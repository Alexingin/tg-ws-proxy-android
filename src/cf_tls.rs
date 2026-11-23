//! Выбор TLS (443) или обычного HTTP (80) для Cloudflare — порт
//! proxy/cf_websocket.py оригинала (1.12.0).
//!
//! У разных провайдеров ломается разное: где-то режут TLS к Cloudflare,
//! где-то — обычный HTTP. Поэтому:
//!  - сначала пробуем тот режим, который чаще срабатывал (на старте — TLS);
//!  - если подключение зависло (таймаут) или его сбросили, сразу пробуем
//!    другой режим, а зависший на 30 секунд откладываем для этого домена;
//!  - HTTP/2 для медиа включается, только если TLS сейчас «в почёте».
//!
//! Отличие от оригинала: кроме таймаута переключаемся и на сброс
//! соединения (RST) — российские ТСПУ часто рвут TLS именно так.

use once_cell::sync::Lazy;
use parking_lot::Mutex;
use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

use crate::config::DISABLE_SECURE;
use crate::ws::WsError;

pub const CF_TIMEOUT_COOLDOWN: Duration = Duration::from_secs(30);

/// Значение `None` — «пробная попытка уже идёт» (в оригинале math.inf):
/// параллельные подключения этот режим пропускают.
static TIMEOUT_UNTIL: Lazy<Mutex<HashMap<(String, bool), Option<Instant>>>> =
    Lazy::new(|| Mutex::new(HashMap::new()));
static TLS_OK: AtomicU64 = AtomicU64::new(0);
static PLAIN_OK: AtomicU64 = AtomicU64::new(0);

pub fn reset() {
    TIMEOUT_UNTIL.lock().clear();
    TLS_OK.store(0, Ordering::Relaxed);
    PLAIN_OK.store(0, Ordering::Relaxed);
}

pub fn secure_allowed() -> bool {
    !DISABLE_SECURE.load(Ordering::Relaxed)
}

/// TLS срабатывал не реже обычного HTTP.
pub fn prefers_tls() -> bool {
    secure_allowed() && TLS_OK.load(Ordering::Relaxed) >= PLAIN_OK.load(Ordering::Relaxed)
}

/// Порядок режимов для очередного подключения.
pub fn modes() -> Vec<bool> {
    if !secure_allowed() {
        vec![false]
    } else if prefers_tls() {
        vec![true, false]
    } else {
        vec![false, true]
    }
}

pub fn record_success(tls: bool) {
    if tls {
        TLS_OK.fetch_add(1, Ordering::Relaxed);
    } else {
        PLAIN_OK.fetch_add(1, Ordering::Relaxed);
    }
}

pub fn tls_in_cooldown(name: &str) -> bool {
    in_cooldown(name, true)
}

pub fn in_cooldown(name: &str, tls: bool) -> bool {
    let map = TIMEOUT_UNTIL.lock();
    match map.get(&(name.to_string(), tls)) {
        Some(None) => true,
        Some(Some(until)) => Instant::now() < *until,
        None => false,
    }
}

pub fn cooldown_state() -> (u64, u64, usize) {
    (
        TLS_OK.load(Ordering::Relaxed),
        PLAIN_OK.load(Ordering::Relaxed),
        TIMEOUT_UNTIL.lock().len(),
    )
}

/// Ошибка, после которой стоит попробовать другой режим (TLS ↔ HTTP).
pub fn should_switch_mode(err: &WsError) -> bool {
    match err {
        WsError::Timeout => true,
        WsError::Io(e) => matches!(
            e.kind(),
            std::io::ErrorKind::TimedOut
                | std::io::ErrorKind::ConnectionReset
                | std::io::ErrorKind::ConnectionAborted
                | std::io::ErrorKind::UnexpectedEof
        ),
        _ => false,
    }
}

/// Попытка подключения в одном режиме к одному домену.
/// Если режим «остывает» после таймаута — `begin` вернёт None.
pub struct Attempt {
    key: (String, bool),
    prev: Option<Instant>,
    had_prev: bool,
    done: bool,
}

pub fn begin(name: &str, tls: bool) -> Option<Attempt> {
    let key = (name.to_string(), tls);
    let mut map = TIMEOUT_UNTIL.lock();
    let (prev, had_prev) = match map.get(&key) {
        Some(None) => return None,
        Some(Some(until)) if Instant::now() < *until => return None,
        Some(Some(until)) => (Some(*until), true),
        None => (None, false),
    };
    if had_prev {
        // Остывание кончилось: эта попытка — пробная, остальные пусть ждут.
        map.insert(key.clone(), None);
    }
    Some(Attempt { key, prev, had_prev, done: false })
}

impl Attempt {
    pub fn tls(&self) -> bool {
        self.key.1
    }

    pub fn succeeded(mut self) {
        TIMEOUT_UNTIL.lock().remove(&self.key);
        record_success(self.key.1);
        self.done = true;
    }

    /// Подключение не удалось. Возвращает true, если режим отложен.
    pub fn failed(mut self, err: &WsError) -> bool {
        self.done = true;
        let mut map = TIMEOUT_UNTIL.lock();
        if should_switch_mode(err) {
            let now = Instant::now();
            map.retain(|_, until| match until {
                Some(u) => *u + CF_TIMEOUT_COOLDOWN > now,
                None => true,
            });
            map.insert(self.key.clone(), Some(now + CF_TIMEOUT_COOLDOWN));
            true
        } else {
            map.remove(&self.key);
            false
        }
    }
}

impl Drop for Attempt {
    fn drop(&mut self) {
        if self.done {
            return;
        }
        // Попытку отменили (клиент ушёл, прокси остановили) — вернуть как было.
        let mut map = TIMEOUT_UNTIL.lock();
        if self.had_prev {
            if let Some(None) = map.get(&self.key) {
                map.insert(self.key.clone(), self.prev);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn timeout() -> WsError {
        WsError::Timeout
    }

    #[test]
    fn timeout_puts_mode_on_cooldown_and_other_mode_stays() {
        let d = "cooldown-test.example";
        let a = begin(d, true).expect("first attempt");
        assert!(a.failed(&timeout()));
        assert!(in_cooldown(d, true));
        assert!(begin(d, true).is_none());
        assert!(!in_cooldown(d, false));
        let b = begin(d, false).expect("plain allowed");
        b.succeeded();
        assert!(!in_cooldown(d, false));
    }

    #[test]
    fn non_timeout_error_does_not_cooldown() {
        let d = "http-error.example";
        let a = begin(d, true).unwrap();
        let err = WsError::Other("http 403".into());
        assert!(!a.failed(&err));
        assert!(!in_cooldown(d, true));
    }

    #[test]
    fn dropped_probe_restores_expired_entry() {
        let d = "probe-drop.example";
        let past = Instant::now() - Duration::from_secs(1);
        TIMEOUT_UNTIL.lock().insert((d.to_string(), true), Some(past));
        {
            let probe = begin(d, true).expect("expired cooldown allows a probe");
            // Пока идёт пробная попытка, другие её не повторяют.
            assert!(begin(d, true).is_none());
            drop(probe);
        }
        assert!(begin(d, true).is_some());
    }

    #[test]
    fn reset_errors_switch_mode() {
        let e = WsError::Io(std::io::Error::from(std::io::ErrorKind::ConnectionReset));
        assert!(should_switch_mode(&e));
        let e = WsError::Io(std::io::Error::from(std::io::ErrorKind::PermissionDenied));
        assert!(!should_switch_mode(&e));
    }
}
