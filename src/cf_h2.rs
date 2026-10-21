//! Медиа через Cloudflare по HTTP/2 — порт proxy/cf_h2.py (+ h2_transport.py)
//! из Flowseal/tg-ws-proxy.
//!
//! Как это работает. Для медиа-соединения прокси не туннелирует поток Telegram
//! целиком, а снимает с него обфускацию, режет на отдельные MTProto-пакеты и
//! отправляет каждый как `POST https://kwsN.<cf-домен>/api` (HTTP-транспорт
//! MTProto). Ответ — тело ответа. Все такие соединения («каналы») к одному
//! хосту идут по одному HTTP/2-подключению («дорожке», lane) — меньше
//! TLS-рукопожатий и фоновых соединений.
//!
//! HTTP-транспорт отвечает только на запросы, поэтому, когда сервер «должен»
//! что-то прислать без запроса, канал повторяет (replay) последний пакет —
//! сервер отбрасывает дубликат по msg_id и отдаёт накопившиеся ответы.
//! Логика повторов перенесена из оригинала почти 1-в-1.

use crate::balancer::BALANCER;
use crate::config::*;
use crate::crypto::TrackedStream;
use crate::{ldebug, linfo, lwarn};
use bytes::Bytes;
use once_cell::sync::Lazy;
use parking_lot::Mutex;
use std::collections::{HashMap, HashSet, VecDeque};
use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Weak};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::Notify;
use tokio_util::sync::CancellationToken;

// --- лимиты и тайминги (как в оригинале) -----------------------------------
pub const MAX_PACKET: usize = 4 * 1024 * 1024;
const MAX_PLAIN_PADDING: usize = 256;
const MAX_CHANNEL_REQUESTS: usize = 8;
const MAX_CHANNEL_BYTES: usize = 8 * 1024 * 1024;
const MAX_LANE_REQUESTS: usize = 64;
const MAX_LANE_BYTES: usize = 32 * 1024 * 1024;
const MAX_LANE_REPLY_BYTES: usize = 32 * 1024 * 1024;
const DOMAIN_COOLDOWN: f64 = 30.0;
const REQUEST_TIMEOUT: Duration = Duration::from_secs(65);
const CONNECT_TIMEOUT: Duration = Duration::from_secs(8);
const SETUP_TIMEOUT: Duration = Duration::from_secs(8);
const REPLAY_IDLE_SECONDS: f64 = 1.0;
const REPLAY_REQUEST_SECONDS: f64 = 3.0;
const REPLAY_CHECK: Duration = Duration::from_millis(250);
const REPLAY_MAX_AGE: f64 = 30.0;
const REPLAY_HISTORY_BYTES: usize = 64 * 1024;
const REPLAY_HISTORY_PACKETS: usize = 16;
const MAX_CHANNEL_REPLAYS: usize = 2;
const REPLAY_SLOT_SECONDS: f64 = 30.0;
const REPLAY_RETRY_SECONDS: f64 = 2.0;
const REPLAY_MAX_ATTEMPTS: u32 = 3;
const REPLY_QUEUE_MAX: usize = 16;
const STREAM_RECEIVE_WINDOW: u32 = 256 * 1024;
const CONNECTION_RECEIVE_WINDOW: u32 = 4 * 1024 * 1024;
const UPLOAD_CHUNK: usize = 64 * 1024;
// Мобильное дополнение: на сетях, где TLS до CF режется, не пытаемся
// поднимать H2 на каждое медиа-соединение — backoff до 10 минут.
const SETUP_BACKOFF_MAX: f64 = 600.0;

/// Включено пользователем (настройка «Медиа через CF по HTTP/2»).
pub static CF_H2_MEDIA: AtomicBool = AtomicBool::new(false);

pub fn h2_enabled() -> bool {
    CF_H2_MEDIA.load(Ordering::Relaxed) && CFPROXY_ENABLED.load(Ordering::Relaxed)
}

// --- ошибки ----------------------------------------------------------------

#[derive(Debug, Clone)]
pub enum H2Error {
    /// Ошибка MTProto-транспорта (-404, -429, ...) — её нужно передать клиенту.
    Transport(i32, String),
    Closed,
    Timeout(String),
    Http(String),
    Buffer(String),
    /// Переполнен общий буфер ответов дорожки (не вина домена).
    ReplyFull,
    Invalid(String),
    /// Локальный клиент (Telegram) закрыл соединение.
    Native(String),
}

impl std::fmt::Display for H2Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            H2Error::Transport(c, s) => write!(f, "transport error {} ({})", c, s),
            H2Error::Closed => write!(f, "H2 channel closed"),
            H2Error::Timeout(s) => write!(f, "timeout: {}", s),
            H2Error::Http(s) => write!(f, "http: {}", s),
            H2Error::Buffer(s) => write!(f, "buffer: {}", s),
            H2Error::ReplyFull => write!(f, "H2 lane response buffers exceeded bound"),
            H2Error::Invalid(s) => write!(f, "invalid: {}", s),
            H2Error::Native(s) => write!(f, "native: {}", s),
        }
    }
}

fn map_reqwest(e: reqwest::Error) -> H2Error {
    if e.is_timeout() {
        H2Error::Timeout(e.to_string())
    } else {
        H2Error::Http(e.to_string())
    }
}

// ---------------------------------------------------------------------------
// MTProto-кадрирование: _read_packet / _encode_reply
// ---------------------------------------------------------------------------

#[derive(Debug)]
pub enum PacketError {
    Io(std::io::Error),
    Invalid(String),
}

async fn read_plain<R: AsyncReadExt + Unpin>(
    r: &mut R,
    dec: &mut TrackedStream,
    n: usize,
) -> Result<Vec<u8>, PacketError> {
    let mut b = vec![0u8; n];
    r.read_exact(&mut b).await.map_err(PacketError::Io)?;
    dec.xor(&mut b);
    Ok(b)
}

/// Читает один MTProto-пакет из обфусцированного потока клиента.
/// Возвращает (тело без транспортного заголовка и паддинга, флаг quick-ack).
pub async fn read_packet<R: AsyncReadExt + Unpin>(
    r: &mut R,
    dec: &mut TrackedStream,
    proto: u32,
) -> Result<(Vec<u8>, bool), PacketError> {
    let (quick, length) = if proto == PROTO_ABRIDGED_INT {
        let first = read_plain(r, dec, 1).await?[0];
        let quick = first & 0x80 != 0;
        let mut words = (first & 0x7f) as usize;
        if words == 0x7f {
            let b = read_plain(r, dec, 3).await?;
            words = b[0] as usize | (b[1] as usize) << 8 | (b[2] as usize) << 16;
        }
        (quick, words * 4)
    } else {
        let b = read_plain(r, dec, 4).await?;
        let value = u32::from_le_bytes([b[0], b[1], b[2], b[3]]);
        (value & 0x8000_0000 != 0, (value & 0x7fff_ffff) as usize)
    };
    let secure = proto == PROTO_PADDED_INTERMEDIATE_INT;
    let limit = MAX_PACKET + if secure { MAX_PLAIN_PADDING } else { 0 };
    if !(24..=limit).contains(&length) {
        return Err(PacketError::Invalid(format!(
            "native packet length outside supported range: {}",
            length
        )));
    }
    let mut body = read_plain(r, dec, length).await?;
    if secure {
        let (packet_length, max_padding) = if body[..8] == [0u8; 8] {
            let l = u32::from_le_bytes([body[16], body[17], body[18], body[19]]) as usize;
            (20usize.saturating_add(l), MAX_PLAIN_PADDING)
        } else {
            (24 + ((length - 24) / 16) * 16, 15)
        };
        if !(24..=length).contains(&packet_length) || length - packet_length > max_padding {
            return Err(PacketError::Invalid(format!(
                "invalid padded native packet: frame={} packet={} limit={}",
                length, packet_length, max_padding
            )));
        }
        body.truncate(packet_length);
    }
    if body.len() % 4 != 0 || body.len() > MAX_PACKET {
        return Err(PacketError::Invalid(
            "invalid native packet alignment or size".to_string(),
        ));
    }
    Ok((body, quick))
}

/// Оборачивает ответ сервера в транспортный кадр клиента (до шифрования).
pub fn encode_reply(body: &[u8], proto: u32) -> Result<Vec<u8>, H2Error> {
    if body.is_empty() || body.len() % 4 != 0 || body.len() > MAX_PACKET {
        return Err(H2Error::Invalid(format!(
            "invalid HTTP MTProto response length: {}",
            body.len()
        )));
    }
    if proto == PROTO_ABRIDGED_INT {
        let words = body.len() / 4;
        let mut out = Vec::with_capacity(body.len() + 4);
        if words < 0x7f {
            out.push(words as u8);
        } else {
            out.push(0x7f);
            out.extend_from_slice(&(words as u32).to_le_bytes()[..3]);
        }
        out.extend_from_slice(body);
        return Ok(out);
    }
    let padding: Vec<u8> = if proto == PROTO_PADDED_INTERMEDIATE_INT {
        let n = (rand::random::<u8>() % 4) as usize;
        (0..n).map(|_| rand::random::<u8>()).collect()
    } else {
        Vec::new()
    };
    let mut out = Vec::with_capacity(4 + body.len() + padding.len());
    out.extend_from_slice(&((body.len() + padding.len()) as u32).to_le_bytes());
    out.extend_from_slice(body);
    out.extend_from_slice(&padding);
    Ok(out)
}

// ---------------------------------------------------------------------------
// Lane — одно HTTP/2-подключение к хосту kwsN.<домен> (_HttpLane + H2Transport)
// ---------------------------------------------------------------------------

#[derive(Default)]
struct LaneState {
    inflight: usize,
    queued_bytes: usize,
    reply_buffer_bytes: usize,
    failed_until: f64,
    closed: bool,
    requests: u64,
    responses: u64,
    errors: u64,
}

pub struct Lane {
    id: u64,
    host: String,
    url: String,
    resolve: Option<SocketAddr>,
    client: parking_lot::RwLock<reqwest::Client>,
    st: Mutex<LaneState>,
    cap: Notify,
    channels: Mutex<Vec<Weak<Channel>>>,
}

fn build_client(host: &str, resolve: Option<SocketAddr>) -> Result<reqwest::Client, H2Error> {
    let mut b = reqwest::Client::builder()
        .use_rustls_tls()
        .http2_prior_knowledge()
        .http2_initial_stream_window_size(STREAM_RECEIVE_WINDOW)
        .http2_initial_connection_window_size(CONNECTION_RECEIVE_WINDOW)
        .connect_timeout(CONNECT_TIMEOUT)
        .read_timeout(REQUEST_TIMEOUT)
        // Простаивающее подключение закрывается — не держим радио в фоне.
        .pool_idle_timeout(Duration::from_secs(60))
        .pool_max_idle_per_host(1)
        .tcp_nodelay(true)
        .no_proxy();
    if let Some(addr) = resolve {
        b = b.resolve(host, addr);
    }
    b.build().map_err(|e| H2Error::Http(e.to_string()))
}

impl Lane {
    fn new(id: u64, host: String, resolve: Option<SocketAddr>) -> Result<Arc<Lane>, H2Error> {
        let client = build_client(&host, resolve)?;
        Ok(Arc::new(Lane {
            id,
            url: format!("https://{}/api", host),
            host,
            resolve,
            client: parking_lot::RwLock::new(client),
            st: Mutex::new(LaneState::default()),
            cap: Notify::new(),
            channels: Mutex::new(Vec::new()),
        }))
    }

    #[cfg(test)]
    fn with_client(id: u64, host: &str, url: &str, client: reqwest::Client) -> Arc<Lane> {
        Arc::new(Lane {
            id,
            host: host.to_string(),
            url: url.to_string(),
            resolve: None,
            client: parking_lot::RwLock::new(client),
            st: Mutex::new(LaneState::default()),
            cap: Notify::new(),
            channels: Mutex::new(Vec::new()),
        })
    }

    fn is_closed(&self) -> bool {
        self.st.lock().closed
    }

    fn failed_until(&self) -> f64 {
        self.st.lock().failed_until
    }

    fn has_capacity(&self, len: usize) -> bool {
        let st = self.st.lock();
        st.inflight < MAX_LANE_REQUESTS && st.queued_bytes + len <= MAX_LANE_BYTES
    }

    fn live_channels(&self) -> Vec<Arc<Channel>> {
        let mut v = self.channels.lock();
        v.retain(|w| w.strong_count() > 0);
        v.iter().filter_map(|w| w.upgrade()).collect()
    }

    /// Пересоздать HTTP/2-подключение (h2_transport: fail() при зависшем пути).
    fn reset_connection(&self) {
        if let Ok(c) = build_client(&self.host, self.resolve) {
            *self.client.write() = c;
            ldebug!("H2 lane={} connection reset host={}", self.id, self.host);
        }
    }

    async fn preflight(&self) -> Result<(), H2Error> {
        let started = now_monotonic();
        let client = self.client.read().clone();
        let resp = client.head(&self.url).send().await.map_err(map_reqwest)?;
        if resp.version() != reqwest::Version::HTTP_2 {
            return Err(H2Error::Invalid(format!(
                "CF /api preflight negotiated {:?}",
                resp.version()
            )));
        }
        let code = resp.status().as_u16();
        if !((200..300).contains(&code) || code == 405 || code == 501) {
            return Err(H2Error::Http(format!(
                "CF /api preflight HTTP {} cf_ray={}",
                code,
                header_str(&resp, "cf-ray")
            )));
        }
        ldebug!(
            "H2 lane={} ready host={} status={} ms={:.0}",
            self.id,
            self.host,
            code,
            (now_monotonic() - started) * 1000.0
        );
        Ok(())
    }

    async fn reserve(&self, len: usize, wait: bool) -> Result<bool, H2Error> {
        let deadline = tokio::time::Instant::now() + REQUEST_TIMEOUT;
        loop {
            let notified = self.cap.notified();
            tokio::pin!(notified);
            notified.as_mut().enable();
            {
                let mut st = self.st.lock();
                if st.closed {
                    return Err(H2Error::Closed);
                }
                if st.inflight < MAX_LANE_REQUESTS && st.queued_bytes + len <= MAX_LANE_BYTES {
                    st.inflight += 1;
                    st.queued_bytes += len;
                    return Ok(true);
                }
                if !wait {
                    return Ok(false);
                }
            }
            if tokio::time::timeout_at(deadline, notified).await.is_err() {
                return Err(H2Error::Timeout("H2 lane capacity".to_string()));
            }
        }
    }

    fn release(&self, len: usize) {
        {
            let mut st = self.st.lock();
            st.inflight = st.inflight.saturating_sub(1);
            st.queued_bytes = st.queued_bytes.saturating_sub(len);
        }
        self.cap.notify_waiters();
    }

    /// Один POST /api. Проверки ответа — как в _HttpLane._post.
    async fn post(&self, body: Bytes, ch: &Arc<Channel>, req: u64) -> Result<Bytes, H2Error> {
        self.st.lock().requests += 1;
        STATS.h2_requests.fetch_add(1, Ordering::Relaxed);
        let res = self.post_inner(body, ch, req).await;
        match &res {
            Ok(_) => self.st.lock().responses += 1,
            Err(H2Error::Transport(..)) => self.st.lock().errors += 1,
            Err(H2Error::ReplyFull) => {}
            Err(e) => {
                let only_request = {
                    let mut st = self.st.lock();
                    st.errors += 1;
                    st.failed_until = now_monotonic() + DOMAIN_COOLDOWN;
                    st.inflight <= 1
                };
                // Подключение может остаться «живым», хотя путь уже не
                // доставляет данные: пересоздаём, если это был последний запрос.
                if matches!(e, H2Error::Timeout(_)) && only_request {
                    self.reset_connection();
                }
            }
        }
        res
    }

    async fn post_inner(&self, body: Bytes, ch: &Arc<Channel>, req: u64) -> Result<Bytes, H2Error> {
        let client = self.client.read().clone();
        let len = body.len();
        let mut rb = client
            .post(&self.url)
            .header(reqwest::header::CONTENT_TYPE, "application/octet-stream")
            .header(reqwest::header::ACCEPT_ENCODING, "identity");
        if len <= UPLOAD_CHUNK {
            ch.mark_sent(req);
            rb = rb.body(body);
        } else {
            // Большой upload: «отправлено» отмечаем, когда HTTP/2 забрал
            // последний кусок (аналог http2.send_request_body.complete).
            let weak = Arc::downgrade(ch);
            let chunks: Vec<Result<Bytes, std::io::Error>> = (0..len)
                .step_by(UPLOAD_CHUNK)
                .map(|o| Ok(body.slice(o..(o + UPLOAD_CHUNK).min(len))))
                .collect();
            let total = chunks.len();
            let stream = futures_util::stream::iter(chunks.into_iter().enumerate().map(
                move |(i, c)| {
                    if i + 1 == total {
                        if let Some(ch) = weak.upgrade() {
                            ch.mark_sent(req);
                        }
                    }
                    c
                },
            ));
            rb = rb
                .header(reqwest::header::CONTENT_LENGTH, len)
                .body(reqwest::Body::wrap_stream(stream));
        }
        let mut resp = rb.send().await.map_err(map_reqwest)?;

        let _receiving = ch.start_receiving(req);
        if resp.version() != reqwest::Version::HTTP_2 {
            return Err(H2Error::Invalid(format!("CF /api downgraded to {:?}", resp.version())));
        }
        let code = resp.status().as_u16();
        if matches!(code, 403 | 404 | 429 | 444) {
            return Err(H2Error::Transport(
                -(code as i32),
                format!("HTTP {} cf_ray={}", code, header_str(&resp, "cf-ray")),
            ));
        }
        if code != 200 {
            return Err(H2Error::Http(format!(
                "CF /api HTTP {} cf_ray={}",
                code,
                header_str(&resp, "cf-ray")
            )));
        }
        if header_str(&resp, "content-type").to_ascii_lowercase().contains("text/html") {
            return Err(H2Error::Invalid("CF /api returned HTML instead of MTProto".to_string()));
        }
        let declared = resp.content_length();
        if let Some(d) = declared {
            if d as usize > MAX_PACKET {
                return Err(H2Error::Buffer(
                    "H2 response Content-Length exceeds native packet bound".to_string(),
                ));
            }
        }
        let identity = {
            let ce = header_str(&resp, "content-encoding");
            ce.is_empty() || ce == "identity"
        };

        let mut guard = ReplyBufferGuard { lane: self, bytes: 0 };
        let mut content: Vec<u8> = Vec::with_capacity(declared.unwrap_or(0) as usize);
        while let Some(chunk) = resp.chunk().await.map_err(map_reqwest)? {
            if content.len() + chunk.len() > MAX_PACKET {
                return Err(H2Error::Buffer("H2 response exceeds native packet bound".to_string()));
            }
            {
                let mut st = self.st.lock();
                if st.reply_buffer_bytes + chunk.len() > MAX_LANE_REPLY_BYTES {
                    return Err(H2Error::ReplyFull);
                }
                st.reply_buffer_bytes += chunk.len();
            }
            guard.bytes += chunk.len();
            content.extend_from_slice(&chunk);
            ch.progress();
        }
        drop(guard);
        if let Some(d) = declared {
            if identity && content.len() as u64 != d {
                return Err(H2Error::Invalid("incomplete H2 response body".to_string()));
            }
        }
        if !content.is_empty() && content.len() % 4 != 0 {
            return Err(H2Error::Invalid(
                "CF /api response is not an aligned MTProto packet".to_string(),
            ));
        }
        if content.len() == 4 {
            let code = i32::from_le_bytes([content[0], content[1], content[2], content[3]]);
            if code < 0 {
                return Err(H2Error::Transport(code, "HTTP 200 payload".to_string()));
            }
        }
        Ok(Bytes::from(content))
    }

    fn close(&self) {
        self.st.lock().closed = true;
        self.cap.notify_waiters();
        for ch in self.live_channels() {
            ch.close();
        }
    }
}

/// Значение заголовка ответа (пустая строка, если его нет).
fn header_str(resp: &reqwest::Response, name: &str) -> String {
    resp.headers()
        .get(name)
        .and_then(|v| v.to_str().ok())
        .map(|s| s.chars().take(64).collect())
        .unwrap_or_default()
}

struct ReplyBufferGuard<'a> {
    lane: &'a Lane,
    bytes: usize,
}

impl Drop for ReplyBufferGuard<'_> {
    fn drop(&mut self) {
        if self.bytes > 0 {
            let mut st = self.lane.st.lock();
            st.reply_buffer_bytes = st.reply_buffer_bytes.saturating_sub(self.bytes);
        }
    }
}

// ---------------------------------------------------------------------------
// Channel — одно соединение Telegram поверх дорожки (_HttpChannel)
// ---------------------------------------------------------------------------

struct ReplayPacket {
    seq: u64,
    sent_at: f64,
    body: Bytes,
    attempts: u32,
    last_attempt_at: f64,
    /// Запрос-повтор этого пакета, если он сейчас в полёте.
    pending: Option<u64>,
    /// Исходные (не повторные) запросы с этим телом.
    originals: HashSet<u64>,
    retired: bool,
    reply_id: Option<Vec<u8>>,
}

impl ReplayPacket {
    fn replayed(&self) -> bool {
        self.last_attempt_at > 0.0 || self.attempts > 0
    }
}

struct Req {
    len: usize,
    abort: Option<tokio::task::AbortHandle>,
    packet: Option<u64>,
}

struct ChState {
    closed: bool,
    close_done: bool,
    transport_error: Option<i32>,
    fail: Option<H2Error>,
    queue: VecDeque<Bytes>,
    reply_bytes: usize,
    pending: HashMap<u64, Req>,
    pending_bytes: usize,
    sent_since: HashMap<u64, f64>,
    receiving: HashSet<u64>,
    replay_pending: HashSet<u64>,
    history: Vec<ReplayPacket>,
    replay_key: Option<[u8; 8]>,
    delivering_since: Option<f64>,
    last_progress: f64,
    requests: u64,
    replay_requests: u64,
    replay_rotations: u64,
    capacity_rotations: u64,
    up: u64,
    down: u64,
    upload_wait_since: Option<f64>,
    upload_wait_phase: &'static str,
    upload_wait_bytes: usize,
    next_req: u64,
}

impl ChState {
    fn has_capacity(&self, len: usize) -> bool {
        self.pending.len() < MAX_CHANNEL_REQUESTS && self.pending_bytes + len <= MAX_CHANNEL_BYTES
    }

    fn native_backpressure(&self) -> bool {
        self.reply_bytes > 0 || self.delivering_since.is_some()
    }

    fn wake_needed(&self) -> bool {
        !self.closed && self.pending.is_empty() && !self.native_backpressure()
    }

    fn overdue_original(&self, e: &ReplayPacket, now: f64) -> bool {
        e.retired
            || e.originals.iter().any(|t| {
                self.sent_since
                    .get(t)
                    .map(|s| !self.receiving.contains(t) && now - s >= REPLAY_REQUEST_SECONDS)
                    .unwrap_or(false)
            })
    }

    fn replay_limit(&self, idx: usize) -> u32 {
        let e = &self.history[idx];
        if !e.originals.is_empty() || e.retired || idx + 1 == self.history.len() {
            REPLAY_MAX_ATTEMPTS
        } else {
            0
        }
    }

    /// Почему повтор пакета сейчас невозможен (None — можно повторять).
    fn replay_blocker(&self, idx: usize, now: f64) -> Option<&'static str> {
        let e = &self.history[idx];
        let age = now - e.sent_at;
        if !(0.0..=REPLAY_MAX_AGE).contains(&age) {
            return Some("expired");
        }
        if e.attempts >= self.replay_limit(idx) {
            return Some("budget-used");
        }
        if self.native_backpressure() {
            return Some("native-backpressure");
        }
        if e.originals.iter().any(|t| self.receiving.contains(t)) {
            return Some("original-body");
        }
        if let Some(p) = e.pending {
            if self.receiving.contains(&p) {
                return Some("replay-body");
            }
        }
        if e.replayed() && now - e.last_attempt_at < REPLAY_RETRY_SECONDS {
            return Some("backoff-or-progress");
        }
        if self.overdue_original(e, now) {
            return None;
        }
        if idx + 1 != self.history.len() || self.pending.keys().any(|t| Some(*t) != e.pending) {
            return Some("receiver-active");
        }
        if e.replayed() && now - self.last_progress < REPLAY_IDLE_SECONDS {
            return Some("backoff-or-progress");
        }
        None
    }

    fn find_packet(&self, body: &[u8]) -> Option<usize> {
        self.history.iter().position(|e| e.body.as_ref() == body)
    }

    fn packet_idx(&self, seq: u64) -> Option<usize> {
        self.history.iter().position(|e| e.seq == seq)
    }

    fn remember_packet(&mut self, body: &Bytes, now: f64) -> Option<u64> {
        let mut key = [0u8; 8];
        key.copy_from_slice(&body[..8]);
        if key == [0u8; 8] {
            return None; // незашифрованные (auth) пакеты не повторяем
        }
        if self.replay_key != Some(key) {
            self.history.clear();
            self.replay_key = Some(key);
        }
        if body.len() > REPLAY_HISTORY_BYTES {
            return None;
        }
        if let Some(i) = self.find_packet(body) {
            return Some(self.history[i].seq);
        }
        let seq = self.requests;
        self.history.push(ReplayPacket {
            seq,
            sent_at: now,
            body: body.clone(),
            attempts: 0,
            last_attempt_at: 0.0,
            pending: None,
            originals: HashSet::new(),
            retired: false,
            reply_id: None,
        });
        Some(seq)
    }

    fn trim_history(&mut self, now: f64) {
        let mut retained: usize = self.history.iter().map(|e| e.body.len()).sum();
        while !self.history.is_empty()
            && (self.history.len() > REPLAY_HISTORY_PACKETS || retained > REPLAY_HISTORY_BYTES)
        {
            let victim = self
                .history
                .iter()
                .position(|e| {
                    e.originals.is_empty()
                        && !(e.retired
                            && e.attempts < REPLAY_MAX_ATTEMPTS
                            && now - e.sent_at <= REPLAY_MAX_AGE)
                })
                .unwrap_or(0);
            retained -= self.history[victim].body.len();
            self.history.remove(victim);
        }
    }

    /// Запрос, который можно снять, чтобы освободить место (_capacity_candidate).
    fn capacity_candidate(&self, now: f64) -> Option<(u64, Option<u64>)> {
        let mut items: Vec<(u64, f64)> = self.sent_since.iter().map(|(k, v)| (*k, *v)).collect();
        items.sort_by(|a, b| {
            let ka = (!self.replay_pending.contains(&a.0), a.1);
            let kb = (!self.replay_pending.contains(&b.0), b.1);
            ka.partial_cmp(&kb).unwrap_or(std::cmp::Ordering::Equal)
        });
        for (req, sent) in items {
            if !self.pending.contains_key(&req)
                || self.receiving.contains(&req)
                || now - sent < REPLAY_REQUEST_SECONDS
            {
                continue;
            }
            if self.replay_pending.contains(&req) {
                return Some((req, None));
            }
            if let Some(e) = self.history.iter().find(|e| e.originals.contains(&req)) {
                if now - e.sent_at <= REPLAY_MAX_AGE {
                    return Some((req, Some(e.seq)));
                }
            }
        }
        None
    }
}

pub struct Channel {
    id: u64,
    label: String,
    lane: Arc<Lane>,
    st: Mutex<ChState>,
    changed: Notify,
    capacity: Notify,
    recovery: Notify,
    send_lock: tokio::sync::Mutex<()>,
}

/// Снимает отметку «идёт приём тела ответа».
struct ReceivingGuard {
    ch: Arc<Channel>,
    req: u64,
}

impl Drop for ReceivingGuard {
    fn drop(&mut self) {
        self.ch.st.lock().receiving.remove(&self.req);
    }
}

/// Завершает запрос при любом выходе из задачи, в т.ч. при её отмене.
struct FinishGuard {
    ch: Arc<Channel>,
    req: u64,
}

impl Drop for FinishGuard {
    fn drop(&mut self) {
        self.ch.finish_request(self.req);
    }
}

/// Сбрасывает признак ожидания отправки (upload_wait_*).
struct UploadWaitGuard<'a> {
    ch: &'a Channel,
}

impl Drop for UploadWaitGuard<'_> {
    fn drop(&mut self) {
        let mut st = self.ch.st.lock();
        st.upload_wait_since = None;
        st.upload_wait_phase = "-";
        st.upload_wait_bytes = 0;
    }
}

impl Channel {
    fn new(lane: Arc<Lane>, id: u64, label: String) -> Arc<Channel> {
        let now = now_monotonic();
        let ch = Arc::new(Channel {
            id,
            label,
            lane: lane.clone(),
            st: Mutex::new(ChState {
                closed: false,
                close_done: false,
                transport_error: None,
                fail: None,
                queue: VecDeque::new(),
                reply_bytes: 0,
                pending: HashMap::new(),
                pending_bytes: 0,
                sent_since: HashMap::new(),
                receiving: HashSet::new(),
                replay_pending: HashSet::new(),
                history: Vec::new(),
                replay_key: None,
                delivering_since: None,
                last_progress: now,
                requests: 0,
                replay_requests: 0,
                replay_rotations: 0,
                capacity_rotations: 0,
                up: 0,
                down: 0,
                upload_wait_since: None,
                upload_wait_phase: "-",
                upload_wait_bytes: 0,
                next_req: 1,
            }),
            changed: Notify::new(),
            capacity: Notify::new(),
            recovery: Notify::new(),
            send_lock: tokio::sync::Mutex::new(()),
        });
        lane.channels.lock().push(Arc::downgrade(&ch));
        ch
    }

    fn is_closed(&self) -> bool {
        self.st.lock().closed
    }

    fn mark_sent(&self, req: u64) {
        let mut st = self.st.lock();
        if st.pending.contains_key(&req) {
            st.sent_since.insert(req, now_monotonic());
        }
    }

    fn progress(&self) {
        self.st.lock().last_progress = now_monotonic();
    }

    fn start_receiving(self: &Arc<Self>, req: u64) -> ReceivingGuard {
        {
            let mut st = self.st.lock();
            st.receiving.insert(req);
            st.last_progress = now_monotonic();
        }
        ReceivingGuard { ch: self.clone(), req }
    }

    fn wake_if_needed(&self, st: &ChState) {
        if st.wake_needed() {
            self.recovery.notify_one();
        }
    }

    /// _HttpChannel._fail: закрыть канал и выдать ошибку получателю.
    fn fail_locked(&self, st: &mut ChState, err: H2Error) {
        if st.closed {
            return;
        }
        if let H2Error::Transport(code, _) = &err {
            st.transport_error = Some(*code);
        }
        st.closed = true;
        st.queue.clear();
        st.reply_bytes = 0;
        st.fail = Some(err);
        self.recovery.notify_one();
        self.changed.notify_waiters();
        self.capacity.notify_waiters();
    }

    fn fail(&self, err: H2Error) {
        let mut st = self.st.lock();
        self.fail_locked(&mut st, err);
    }

    /// Ждать, пока cond(state) не станет истинным, но не дольше timeout.
    async fn wait_capacity(&self, len: usize) -> Result<(), H2Error> {
        let deadline = tokio::time::Instant::now() + REQUEST_TIMEOUT;
        loop {
            let notified = self.capacity.notified();
            tokio::pin!(notified);
            notified.as_mut().enable();
            {
                let st = self.st.lock();
                if st.closed || st.has_capacity(len) {
                    return Ok(());
                }
            }
            if tokio::time::timeout_at(deadline, notified).await.is_err() {
                return Err(H2Error::Timeout("H2 channel capacity".to_string()));
            }
        }
    }

    /// Отправить пакет клиента (или повтор). Ok(false) — повтор не нужен/невозможен.
    async fn send(self: &Arc<Self>, body: Bytes, quick: bool, replay: bool) -> Result<bool, H2Error> {
        let _ = quick; // quick-ack в HTTP-транспорте не поддерживается
        if replay {
            let _lock = match self.send_lock.try_lock() {
                Ok(g) => g,
                Err(_) => return Ok(false),
            };
            return self.send_inner(body, true).await;
        }
        {
            let mut st = self.st.lock();
            st.upload_wait_since = Some(now_monotonic());
            st.upload_wait_phase = "send-lock";
            st.upload_wait_bytes = body.len();
        }
        let _wait = UploadWaitGuard { ch: self };
        let _lock = self.send_lock.lock().await;
        self.send_inner(body, false).await
    }

    async fn send_inner(self: &Arc<Self>, body: Bytes, replay: bool) -> Result<bool, H2Error> {
        let len = body.len();
        if replay {
            if !self.st.lock().has_capacity(len) {
                return Ok(false);
            }
        } else {
            self.st.lock().upload_wait_phase = "channel-capacity";
            self.wait_capacity(len).await?;
        }
        if self.is_closed() {
            return Err(H2Error::Closed);
        }
        if !replay {
            self.st.lock().upload_wait_phase = "lane-capacity";
        }
        if !self.lane.reserve(len, !replay).await? {
            return Ok(false);
        }

        let req;
        let packet_seq;
        {
            let mut st = self.st.lock();
            if st.closed {
                drop(st);
                self.lane.release(len);
                return Err(H2Error::Closed);
            }
            let now = now_monotonic();
            let replay_idx = if replay { st.find_packet(&body) } else { None };
            if replay {
                let ok = match replay_idx {
                    Some(i) => st.history[i].pending.is_none() && st.replay_blocker(i, now).is_none(),
                    None => false,
                };
                if !ok {
                    drop(st);
                    self.lane.release(len);
                    return Ok(false);
                }
            }
            st.pending_bytes += len;
            st.requests += 1;
            if replay {
                st.replay_requests += 1;
            }
            st.up += len as u64;
            STATS.bytes_up.fetch_add(len as i64, Ordering::Relaxed);
            let native_seq = if replay { None } else { st.remember_packet(&body, now) };
            packet_seq = replay_idx.map(|i| st.history[i].seq).or(native_seq);
            req = st.next_req;
            st.next_req += 1;
            st.pending.insert(
                req,
                Req {
                    len,
                    abort: None,
                    packet: packet_seq,
                },
            );
            if let Some(seq) = native_seq {
                if let Some(i) = st.packet_idx(seq) {
                    st.history[i].originals.insert(req);
                }
                st.trim_history(now);
            }
            if let Some(i) = replay_idx {
                st.replay_pending.insert(req);
                let p = &mut st.history[i];
                p.attempts += 1;
                p.last_attempt_at = now;
                p.pending = Some(req);
            }
        }

        let ch = self.clone();
        let handle = tokio::spawn(async move {
            ch.run_request(req, body, packet_seq).await;
        });
        if let Some(r) = self.st.lock().pending.get_mut(&req) {
            r.abort = Some(handle.abort_handle());
        }
        Ok(true)
    }

    async fn run_request(self: Arc<Self>, req: u64, body: Bytes, packet_seq: Option<u64>) {
        let _finish = FinishGuard { ch: self.clone(), req };
        let res = self.lane.post(body.clone(), &self, req).await;
        match res {
            Ok(reply) => {
                let mut st = self.st.lock();
                st.last_progress = now_monotonic();
                if !reply.is_empty() && !st.closed {
                    if let Some(seq) = packet_seq {
                        if let Some(i) = st.packet_idx(seq) {
                            let id = reply[..reply.len().min(24)].to_vec();
                            if st.history[i].reply_id.as_deref() != Some(id.as_slice()) {
                                st.history[i].reply_id = Some(id);
                                st.history[i].attempts = 0;
                            }
                        }
                    }
                    if st.queue.len() >= REPLY_QUEUE_MAX
                        || st.reply_bytes + reply.len() > MAX_CHANNEL_BYTES
                    {
                        self.fail_locked(
                            &mut st,
                            H2Error::Buffer("H2 client response queue exceeded bound".to_string()),
                        );
                    } else {
                        st.reply_bytes += reply.len();
                        st.queue.push_back(reply);
                        self.changed.notify_waiters();
                    }
                }
            }
            Err(e) => {
                STATS.h2_errors.fetch_add(1, Ordering::Relaxed);
                if !self.is_closed() {
                    match &e {
                        H2Error::Transport(..) => lwarn!(
                            "[{}] H2 lane={} channel={} host={} MTProto transport error={} bytes={}; reporting to client",
                            self.label, self.lane.id, self.id, self.lane.host, e, body.len()
                        ),
                        _ => lwarn!(
                            "[{}] H2 lane={} channel={} request failed: {}; closing native channel",
                            self.label, self.lane.id, self.id, e
                        ),
                    }
                }
                self.fail(e);
            }
        }
    }

    /// _finish_request: освободить место запроса. Идемпотентно.
    fn finish_request(&self, req: u64) {
        let len;
        {
            let mut st = self.st.lock();
            let r = match st.pending.remove(&req) {
                Some(r) => r,
                None => return,
            };
            len = r.len;
            st.pending_bytes = st.pending_bytes.saturating_sub(len);
            st.sent_since.remove(&req);
            st.replay_pending.remove(&req);
            st.receiving.remove(&req);
            let idx = match r.packet.and_then(|s| st.packet_idx(s)) {
                Some(i) => Some(i),
                None => st
                    .history
                    .iter()
                    .position(|e| e.originals.contains(&req) || e.pending == Some(req)),
            };
            if let Some(i) = idx {
                let p = &mut st.history[i];
                p.originals.remove(&req);
                if p.pending == Some(req) {
                    p.pending = None;
                }
            }
        }
        self.lane.release(len);
        self.capacity.notify_waiters();
        let st = self.st.lock();
        self.wake_if_needed(&st);
    }

    /// Отменить запрос в полёте (task.cancel() + gather в оригинале).
    fn cancel_request(&self, req: u64) {
        let abort = self.st.lock().pending.get(&req).and_then(|r| r.abort.clone());
        if let Some(a) = abort {
            a.abort();
        }
        self.finish_request(req);
    }

    /// _make_upload_room: если отправка ждёт места — снять самый старый
    /// «зависший» запрос (его пакет потом будет повторён).
    fn make_upload_room(self: &Arc<Self>, now: f64) {
        let (phase, bytes) = {
            let st = self.st.lock();
            if st.closed || st.upload_wait_since.is_none() {
                return;
            }
            (st.upload_wait_phase, st.upload_wait_bytes)
        };
        let channels: Vec<Arc<Channel>> = match phase {
            "channel-capacity" => {
                if self.st.lock().has_capacity(bytes) {
                    return;
                }
                vec![self.clone()]
            }
            "lane-capacity" => {
                if self.lane.has_capacity(bytes) {
                    return;
                }
                let mut v: Vec<(f64, Arc<Channel>)> = self
                    .lane
                    .live_channels()
                    .into_iter()
                    .map(|c| {
                        let m = c
                            .st
                            .lock()
                            .sent_since
                            .values()
                            .cloned()
                            .fold(now, f64::min);
                        (m, c)
                    })
                    .collect();
                v.sort_by(|a, b| a.0.partial_cmp(&b.0).unwrap_or(std::cmp::Ordering::Equal));
                v.into_iter().map(|(_, c)| c).collect()
            }
            _ => return,
        };
        for ch in channels {
            let cand = {
                let mut st = ch.st.lock();
                let c = st.capacity_candidate(now);
                if let Some((req, seq)) = c {
                    st.sent_since.remove(&req);
                    if let Some(i) = seq.and_then(|s| st.packet_idx(s)) {
                        st.history[i].retired = true;
                    }
                    st.capacity_rotations += 1;
                }
                c
            };
            if let Some((req, _)) = cand {
                ldebug!(
                    "H2 CAPACITY lane={} waiting_channel={} release_channel={} reason={}",
                    self.lane.id, self.id, ch.id, phase
                );
                ch.cancel_request(req);
                return;
            }
        }
    }

    /// _recover: фоновый цикл повторов.
    async fn recover(self: Arc<Self>) {
        loop {
            if self.is_closed() {
                return;
            }
            tokio::select! {
                _ = self.recovery.notified() => {}
                _ = tokio::time::sleep(REPLAY_CHECK) => {}
            }
            let now = now_monotonic();
            self.make_upload_room(now);

            let mut to_cancel: Option<u64> = None;
            let mut chosen: Option<Bytes> = None;
            {
                let st = self.st.lock();
                if st.closed {
                    return;
                }
                if st.native_backpressure() {
                    continue;
                }
                let mut order: Vec<usize> = (0..st.history.len()).collect();
                order.sort_by_key(|&i| {
                    let e = &st.history[i];
                    let overdue = st.overdue_original(e, now);
                    (!overdue, if overdue { e.seq as i64 } else { -(e.seq as i64) })
                });
                for i in order {
                    if st.replay_blocker(i, now).is_some() {
                        continue;
                    }
                    let mut replace = st.history[i].pending;
                    if replace.is_none() && st.replay_pending.len() >= MAX_CHANNEL_REPLAYS {
                        replace = st
                            .pending
                            .keys()
                            .find(|t| st.replay_pending.contains(t) && !st.receiving.contains(t))
                            .copied();
                        if replace.is_none() {
                            continue;
                        }
                    }
                    if let Some(r) = replace {
                        let fresh = st
                            .sent_since
                            .get(&r)
                            .map(|s| now - s < REPLAY_SLOT_SECONDS)
                            .unwrap_or(true);
                        if st.receiving.contains(&r) || fresh {
                            continue;
                        }
                        to_cancel = Some(r);
                    }
                    chosen = Some(st.history[i].body.clone());
                    break;
                }
            }
            if let Some(r) = to_cancel {
                self.cancel_request(r);
                self.st.lock().replay_rotations += 1;
            }
            if let Some(body) = chosen {
                if self.send(body, false, true).await.is_err() {
                    return;
                }
            }
        }
    }

    /// Следующий ответ для клиента.
    async fn receive(&self) -> Result<Bytes, H2Error> {
        loop {
            let notified = self.changed.notified();
            tokio::pin!(notified);
            notified.as_mut().enable();
            {
                let mut st = self.st.lock();
                if let Some(b) = st.queue.pop_front() {
                    st.reply_bytes = st.reply_bytes.saturating_sub(b.len());
                    self.wake_if_needed(&st);
                    return Ok(b);
                }
                if let Some(e) = &st.fail {
                    return Err(e.clone());
                }
            }
            notified.await;
        }
    }

    fn close(&self) {
        let reqs: Vec<u64> = {
            let mut st = self.st.lock();
            if st.close_done {
                return;
            }
            st.close_done = true;
            self.fail_locked(&mut st, H2Error::Closed);
            st.pending.keys().copied().collect()
        };
        for r in reqs {
            self.cancel_request(r);
        }
        let (requests, replays, rotations, up, down) = {
            let mut st = self.st.lock();
            st.replay_pending.clear();
            st.history.clear();
            st.sent_since.clear();
            (st.requests, st.replay_requests, st.replay_rotations + st.capacity_rotations, st.up, st.down)
        };
        let me = self as *const Channel;
        self.lane
            .channels
            .lock()
            .retain(|w| w.strong_count() > 0 && !std::ptr::eq(w.as_ptr(), me));
        ldebug!(
            "[{}] H2 channel={} closed lane={} requests={} replays={} rotations={} up={} down={}",
            self.label, self.id, self.lane.id, requests, replays, rotations, up, down
        );
    }
}

// ---------------------------------------------------------------------------
// CfH2Pool — дорожки по хостам, выбор домена, backoff
// ---------------------------------------------------------------------------

#[derive(Default)]
struct PoolState {
    lanes: HashMap<String, Arc<Lane>>,
    host_locks: HashMap<String, Arc<tokio::sync::Mutex<()>>>,
    failed_until: HashMap<String, f64>,
    /// dc -> (повторять не раньше, число неудач подряд)
    setup_retry: HashMap<i32, (f64, u32)>,
}

pub struct CfH2Pool {
    st: Mutex<PoolState>,
    next_lane: AtomicU64,
    next_channel: AtomicU64,
}

pub static CF_H2_POOL: Lazy<CfH2Pool> = Lazy::new(|| CfH2Pool {
    st: Mutex::new(PoolState::default()),
    next_lane: AtomicU64::new(0),
    next_channel: AtomicU64::new(0),
});

async fn resolve_host(host: &str) -> Option<SocketAddr> {
    if let Ok(mut it) = tokio::net::lookup_host((host, 443)).await {
        if it.next().is_some() {
            return None; // системный DNS работает — reqwest разрешит сам
        }
    }
    let ip = crate::cfproxy::resolve_doh(host).await?;
    let ip: std::net::IpAddr = ip.parse().ok()?;
    Some(SocketAddr::new(ip, 443))
}

impl CfH2Pool {
    pub async fn open(&self, dc: i32, label: &str) -> Option<Arc<Channel>> {
        if !h2_enabled() {
            return None;
        }
        let now = now_monotonic();
        if let Some((after, _)) = self.st.lock().setup_retry.get(&dc) {
            if now < *after {
                return None;
            }
        }
        let res = tokio::time::timeout(SETUP_TIMEOUT, self.open_inner(dc, label)).await;
        let ch = match res {
            Ok(c) => c,
            Err(_) => {
                STATS.h2_errors.fetch_add(1, Ordering::Relaxed);
                None
            }
        };
        let mut st = self.st.lock();
        if ch.is_some() {
            st.setup_retry.remove(&dc);
        } else {
            let failures = st.setup_retry.get(&dc).map(|v| v.1).unwrap_or(0) + 1;
            let delay = (DOMAIN_COOLDOWN * 2f64.powi((failures - 1).min(5) as i32)).min(SETUP_BACKOFF_MAX);
            st.setup_retry.insert(dc, (now_monotonic() + delay, failures));
            lwarn!(
                "[{}] H2 DC{} unavailable; using WS for {:.0}s",
                label, dc, delay
            );
        }
        ch
    }

    async fn open_inner(&self, dc: i32, label: &str) -> Option<Arc<Channel>> {
        if !DC_DEFAULT_IPS.contains_key(&dc) {
            lwarn!("[{}] H2 unsupported DC{} -> existing WS route", label, dc);
            return None;
        }
        let domains = BALANCER.read().get_domains_for_dc(dc);
        for base in domains {
            let host = format!("kws{}.{}", dc, base);
            let lock = self
                .st
                .lock()
                .host_locks
                .entry(host.clone())
                .or_insert_with(|| Arc::new(tokio::sync::Mutex::new(())))
                .clone();
            let _g = lock.lock().await;

            let now = now_monotonic();
            let (existing, host_failed) = {
                let st = self.st.lock();
                (
                    st.lanes.get(&host).cloned(),
                    st.failed_until.get(&host).copied().unwrap_or(0.0),
                )
            };
            let lane_failed = existing.as_ref().map(|l| l.failed_until()).unwrap_or(0.0);
            if now < host_failed.max(lane_failed) {
                continue;
            }
            let lane = match existing.filter(|l| !l.is_closed()) {
                Some(l) => l,
                None => {
                    let id = self.next_lane.fetch_add(1, Ordering::Relaxed) + 1;
                    let resolve = resolve_host(&host).await;
                    let lane = match Lane::new(id, host.clone(), resolve) {
                        Ok(l) => l,
                        Err(e) => {
                            lwarn!("[{}] H2 lane={} build failed host={}: {}", label, id, host, e);
                            continue;
                        }
                    };
                    if let Err(e) = lane.preflight().await {
                        STATS.h2_errors.fetch_add(1, Ordering::Relaxed);
                        self.st
                            .lock()
                            .failed_until
                            .insert(host.clone(), now_monotonic() + DOMAIN_COOLDOWN);
                        lwarn!("[{}] H2 lane={} preflight failed host={}: {}", label, id, host, e);
                        lane.close();
                        continue;
                    }
                    self.st.lock().lanes.insert(host.clone(), lane.clone());
                    lane
                }
            };
            let cid = self.next_channel.fetch_add(1, Ordering::Relaxed) + 1;
            let ch = Channel::new(lane.clone(), cid, label.to_string());
            BALANCER.write().update_domain_for_dc(dc, &base);
            linfo!(
                "[{}] ROUTE DC{} media -> H2 lane={} channel={} host={} channels={}",
                label,
                dc,
                lane.id,
                cid,
                host,
                lane.live_channels().len()
            );
            return Some(ch);
        }
        ldebug!("[{}] H2 DC{} unavailable; using WS", label, dc);
        None
    }

    /// Закрыть все дорожки (остановка прокси / смена сети).
    pub fn reset(&self) {
        let lanes: Vec<Arc<Lane>> = {
            let mut st = self.st.lock();
            st.failed_until.clear();
            st.setup_retry.clear();
            st.host_locks.clear();
            st.lanes.drain().map(|(_, l)| l).collect()
        };
        for l in lanes {
            l.close();
        }
    }
}

// ---------------------------------------------------------------------------
// bridge_h2 — мост между клиентом Telegram и каналом
// ---------------------------------------------------------------------------

pub async fn bridge_h2<R, W>(
    mut reader: R,
    mut writer: W,
    ch: Arc<Channel>,
    mut clt_dec: TrackedStream,
    mut clt_enc: TrackedStream,
    proto: u32,
    cancel: CancellationToken,
) where
    R: AsyncReadExt + Unpin + Send + 'static,
    W: AsyncWriteExt + Unpin + Send + 'static,
{
    STATS.connections_h2.fetch_add(1, Ordering::Relaxed);
    let recover = tokio::spawn(ch.clone().recover());

    let result: Result<(), H2Error> = {
        let upload = async {
            loop {
                match read_packet(&mut reader, &mut clt_dec, proto).await {
                    Ok((body, quick)) => {
                        ch.send(Bytes::from(body), quick, false).await?;
                    }
                    Err(PacketError::Io(e)) => return Err(H2Error::Native(e.to_string())),
                    Err(PacketError::Invalid(s)) => return Err(H2Error::Invalid(s)),
                }
            }
        };
        let download = async {
            loop {
                let body = ch.receive().await?;
                if ch.is_closed() {
                    return Err(H2Error::Native(
                        "H2 channel closed before native response".to_string(),
                    ));
                }
                ch.st.lock().delivering_since = Some(now_monotonic());
                let mut frame = encode_reply(&body, proto)?;
                clt_enc.xor(&mut frame);
                let w = writer.write_all(&frame).await;
                {
                    let mut st = ch.st.lock();
                    st.delivering_since = None;
                    st.down += body.len() as u64;
                    st.last_progress = now_monotonic();
                    ch.wake_if_needed(&st);
                }
                w.map_err(|e| H2Error::Native(e.to_string()))?;
                STATS.bytes_down.fetch_add(body.len() as i64, Ordering::Relaxed);
            }
        };
        tokio::select! {
            r = upload => r,
            r = download => r,
            _ = cancel.cancelled() => Err(H2Error::Closed),
        }
    };
    recover.abort();

    let transport_error = ch.st.lock().transport_error;
    if let Some(code) = transport_error {
        // Клиент должен получить код ошибки транспорта (-404 и т.п.), а не EOF.
        if let Ok(mut frame) = encode_reply(&code.to_le_bytes(), proto) {
            clt_enc.xor(&mut frame);
            let _ = writer.write_all(&frame).await;
            STATS.bytes_down.fetch_add(4, Ordering::Relaxed);
        }
    } else if let Err(e) = result {
        match e {
            H2Error::Native(s) => ldebug!("[{}] H2 channel={} native closed: {}", ch.label, ch.id, s),
            H2Error::Closed => {}
            other => {
                if !ch.is_closed() {
                    lwarn!("[{}] H2 channel={} bridge ended: {}", ch.label, ch.id, other);
                }
            }
        }
    }
    let _ = writer.shutdown().await;
    ch.close();
}

#[cfg(test)]
mod tests {
    use super::*;

    fn stream() -> TrackedStream {
        TrackedStream::new(&[7u8; 32], &[9u8; 16])
    }

    async fn roundtrip(proto: u32, body: Vec<u8>) -> Vec<u8> {
        let frame = encode_reply(&body, proto).unwrap();
        let mut enc = stream();
        let mut wire = frame.clone();
        enc.xor(&mut wire);
        let mut dec = stream();
        let mut cur = std::io::Cursor::new(wire);
        let (got, quick) = read_packet(&mut cur, &mut dec, proto).await.unwrap();
        assert!(!quick);
        got
    }

    #[tokio::test]
    async fn abridged_roundtrip() {
        let small: Vec<u8> = (0..64u8).collect();
        assert_eq!(roundtrip(PROTO_ABRIDGED_INT, small.clone()).await, small);
        let big = vec![0x5au8; 4 * 0x90];
        assert_eq!(roundtrip(PROTO_ABRIDGED_INT, big.clone()).await, big);
    }

    #[tokio::test]
    async fn intermediate_roundtrip() {
        let body: Vec<u8> = (0..128u8).collect();
        assert_eq!(roundtrip(PROTO_INTERMEDIATE_INT, body.clone()).await, body);
    }

    #[tokio::test]
    async fn padded_roundtrip_encrypted_message() {
        // Зашифрованное сообщение: auth_key_id != 0, длина 24 + 16*k.
        let mut body = vec![1u8; 24 + 32];
        body[0] = 0xAA;
        for _ in 0..20 {
            assert_eq!(roundtrip(PROTO_PADDED_INTERMEDIATE_INT, body.clone()).await, body);
        }
    }

    #[tokio::test]
    async fn padded_unencrypted_message_strips_padding() {
        // auth_key_id = 0, msg_id, length=8 -> пакет 28 байт, дополним до 32.
        let mut body = vec![0u8; 28];
        body[16..20].copy_from_slice(&8u32.to_le_bytes());
        let mut framed = Vec::new();
        framed.extend_from_slice(&(32u32).to_le_bytes());
        framed.extend_from_slice(&body);
        framed.extend_from_slice(&[0xEE; 4]);
        let mut enc = stream();
        enc.xor(&mut framed);
        let mut dec = stream();
        let mut cur = std::io::Cursor::new(framed);
        let (got, _) = read_packet(&mut cur, &mut dec, PROTO_PADDED_INTERMEDIATE_INT)
            .await
            .unwrap();
        assert_eq!(got, body);
    }

    #[tokio::test]
    async fn rejects_short_packet() {
        let mut framed = (8u32).to_le_bytes().to_vec();
        framed.extend_from_slice(&[0u8; 8]);
        let mut enc = stream();
        enc.xor(&mut framed);
        let mut dec = stream();
        let mut cur = std::io::Cursor::new(framed);
        assert!(read_packet(&mut cur, &mut dec, PROTO_INTERMEDIATE_INT).await.is_err());
    }

    // --- интеграционный тест на локальном HTTP/2-сервере ---------------

    use http_body_util::{BodyExt, Full};
    use hyper::{Request, Response};
    use std::sync::atomic::AtomicUsize;

    /// Сервер: POST /api отвечает эхом; первый ответ задерживается на delay_first.
    async fn spawn_server(delay_first: Duration) -> (u16, Arc<AtomicUsize>) {
        let _ = rustls::crypto::ring::default_provider().install_default();
        let cert = rcgen::generate_simple_self_signed(vec!["localhost".to_string()]).unwrap();
        let key = rustls_pki_types::PrivateKeyDer::Pkcs8(
            rustls_pki_types::PrivatePkcs8KeyDer::from(cert.key_pair.serialize_der()),
        );
        let mut cfg = rustls::ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(vec![cert.cert.der().clone()], key)
            .unwrap();
        cfg.alpn_protocols = vec![b"h2".to_vec()];
        let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(cfg));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let posts = Arc::new(AtomicUsize::new(0));
        let posts_srv = posts.clone();
        tokio::spawn(async move {
            loop {
                let (tcp, _) = listener.accept().await.unwrap();
                let acceptor = acceptor.clone();
                let posts = posts_srv.clone();
                tokio::spawn(async move {
                    let tls = acceptor.accept(tcp).await.unwrap();
                    let svc = hyper::service::service_fn(move |req: Request<hyper::body::Incoming>| {
                        let posts = posts.clone();
                        async move {
                            if req.method() == hyper::Method::HEAD {
                                return Ok::<_, std::convert::Infallible>(
                                    Response::builder().status(405).body(Full::new(Bytes::new())).unwrap(),
                                );
                            }
                            let n = posts.fetch_add(1, Ordering::SeqCst);
                            let body = req.into_body().collect().await.unwrap().to_bytes();
                            if n == 0 && !delay_first.is_zero() {
                                tokio::time::sleep(delay_first).await;
                            }
                            Ok(Response::builder()
                                .status(200)
                                .header("content-type", "application/octet-stream")
                                .body(Full::new(body))
                                .unwrap())
                        }
                    });
                    let _ = hyper::server::conn::http2::Builder::new(hyper_util::rt::TokioExecutor::new())
                        .serve_connection(hyper_util::rt::TokioIo::new(tls), svc)
                        .await;
                });
            }
        });
        (port, posts)
    }

    fn test_lane(port: u16) -> Arc<Lane> {
        let client = reqwest::Client::builder()
            .use_rustls_tls()
            .danger_accept_invalid_certs(true)
            .http2_prior_knowledge()
            .no_proxy()
            .build()
            .unwrap();
        Lane::with_client(1, "localhost", &format!("https://localhost:{}/api", port), client)
    }

    /// Клиентская сторона: шифрует пакеты как Telegram и расшифровывает ответы.
    async fn exchange(port: u16, packets: Vec<Vec<u8>>, wait: Duration) -> (Vec<Vec<u8>>, f64) {
        let want: Vec<Vec<u8>> = Vec::new();
        exchange_until(port, packets, &want, wait).await
    }

    /// Если want не пуст — читаем, пока не получим все пакеты из want;
    /// иначе — пока не получим packets.len() ответов.
    async fn exchange_until(
        port: u16,
        packets: Vec<Vec<u8>>,
        want: &[Vec<u8>],
        wait: Duration,
    ) -> (Vec<Vec<u8>>, f64) {
        let lane = test_lane(port);
        lane.preflight().await.unwrap();
        let ch = Channel::new(lane.clone(), 1, "test".to_string());
        let (client_side, proxy_side) = tokio::io::duplex(1 << 20);
        let (pr, pw) = tokio::io::split(proxy_side);
        let up_key = ([3u8; 32], [4u8; 16]);
        let down_key = ([5u8; 32], [6u8; 16]);
        let cancel = CancellationToken::new();
        let bridge = tokio::spawn(bridge_h2(
            pr,
            pw,
            ch,
            TrackedStream::new(&up_key.0, &up_key.1),
            TrackedStream::new(&down_key.0, &down_key.1),
            PROTO_INTERMEDIATE_INT,
            cancel.clone(),
        ));
        let (mut cr, mut cw) = tokio::io::split(client_side);
        let mut enc = TrackedStream::new(&up_key.0, &up_key.1);
        let started = now_monotonic();
        for p in &packets {
            let mut f = encode_reply(p, PROTO_INTERMEDIATE_INT).unwrap();
            enc.xor(&mut f);
            cw.write_all(&f).await.unwrap();
        }
        let mut dec = TrackedStream::new(&down_key.0, &down_key.1);
        let mut got = Vec::new();
        let deadline = tokio::time::Instant::now() + wait;
        let done = |got: &Vec<Vec<u8>>| {
            if want.is_empty() {
                got.len() >= packets.len()
            } else {
                want.iter().all(|w| got.contains(w))
            }
        };
        while !done(&got) {
            match tokio::time::timeout_at(deadline, read_packet(&mut cr, &mut dec, PROTO_INTERMEDIATE_INT)).await {
                Ok(Ok((b, _))) => got.push(b),
                _ => break,
            }
        }
        let elapsed = now_monotonic() - started;
        cancel.cancel();
        let _ = bridge.await;
        assert!(lane.st.lock().inflight == 0, "lane slots leaked");
        (got, elapsed)
    }

    /// Читает ответы, пока не соберёт все различные (дубли от «опроса» отбрасываются).
    async fn exchange_distinct(port: u16, packets: Vec<Vec<u8>>, wait: Duration) -> (Vec<Vec<u8>>, f64) {
        let started = now_monotonic();
        let mut want: Vec<Vec<u8>> = packets.clone();
        want.sort();
        want.dedup();
        let _ = started;
        let (mut got, el) = exchange_until(port, packets, &want, wait).await;
        got.sort();
        got.dedup();
        (got, el)
    }

    fn mtproto_like(tag: u8, len: usize) -> Vec<u8> {
        let mut b = vec![tag; len];
        b[0] = 0xA5; // auth_key_id != 0 — пакет запоминается для повторов
        b
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn h2_echo_roundtrip() {
        let (port, posts) = spawn_server(Duration::ZERO).await;
        let packets = vec![mtproto_like(1, 64), mtproto_like(2, 128), mtproto_like(3, 200_000)];
        let (got, _) = exchange_distinct(port, packets.clone(), Duration::from_secs(10)).await;
        // Запросы независимы, ответы приходят в порядке готовности (как в оригинале).
        // Когда канал простаивает, последний пакет повторяется как «опрос» —
        // эхо-сервер отвечает на него ещё раз, Telegram же отбрасывает дубль по msg_id.
        let mut want = packets.clone();
        want.sort();
        assert_eq!(got, want);
        assert!(posts.load(Ordering::SeqCst) >= 3);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn h2_replay_when_reply_is_late() {
        // Первый ответ сервер задерживает на 8с; через ~3с канал должен
        // повторить пакет и получить ответ на повтор.
        let (port, posts) = spawn_server(Duration::from_secs(8)).await;
        let packets = vec![mtproto_like(7, 96)];
        let (got, elapsed) = exchange(port, packets.clone(), Duration::from_secs(7)).await;
        assert_eq!(got.first(), packets.first());
        assert!(elapsed < 6.0, "replay did not happen in time: {:.1}s", elapsed);
        assert!(posts.load(Ordering::SeqCst) >= 2);
    }

    #[test]
    fn transport_error_frame() {
        let f = encode_reply(&(-404i32).to_le_bytes(), PROTO_INTERMEDIATE_INT).unwrap();
        assert_eq!(&f[..4], &4u32.to_le_bytes());
        assert_eq!(&f[4..], &(-404i32).to_le_bytes());
    }

    fn state_with_history(n: usize) -> ChState {
        let now = 100.0;
        let mut st = ChState {
            closed: false,
            close_done: false,
            transport_error: None,
            fail: None,
            queue: VecDeque::new(),
            reply_bytes: 0,
            pending: HashMap::new(),
            pending_bytes: 0,
            sent_since: HashMap::new(),
            receiving: HashSet::new(),
            replay_pending: HashSet::new(),
            history: Vec::new(),
            replay_key: None,
            delivering_since: None,
            last_progress: now - 5.0,
            requests: 0,
            replay_requests: 0,
            replay_rotations: 0,
            capacity_rotations: 0,
            up: 0,
            down: 0,
            upload_wait_since: None,
            upload_wait_phase: "-",
            upload_wait_bytes: 0,
            next_req: 1,
        };
        for i in 0..n {
            st.requests += 1;
            let mut b = vec![0x11u8; 32];
            b[8] = i as u8;
            st.remember_packet(&Bytes::from(b), now - 10.0);
        }
        st
    }

    #[test]
    fn last_packet_is_replayable_when_idle() {
        let st = state_with_history(3);
        let last = st.history.len() - 1;
        assert_eq!(st.replay_blocker(last, 100.0), None);
        // Не последний и без исходных запросов — бюджет повторов 0.
        assert_eq!(st.replay_blocker(0, 100.0), Some("budget-used"));
    }

    #[test]
    fn replay_blocked_by_backpressure_and_age() {
        let mut st = state_with_history(1);
        st.reply_bytes = 10;
        assert_eq!(st.replay_blocker(0, 100.0), Some("native-backpressure"));
        st.reply_bytes = 0;
        assert_eq!(st.replay_blocker(0, 200.0), Some("expired"));
    }

    #[test]
    fn auth_key_change_resets_history_and_trim_limits() {
        let mut st = state_with_history(REPLAY_HISTORY_PACKETS + 5);
        st.trim_history(100.0);
        assert!(st.history.len() <= REPLAY_HISTORY_PACKETS);
        let mut other = vec![0x22u8; 32];
        other[0] = 0x33;
        st.requests += 1;
        st.remember_packet(&Bytes::from(other), 100.0);
        assert_eq!(st.history.len(), 1);
    }
}
