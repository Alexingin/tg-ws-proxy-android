//! Лаборатория соединений.
//!
//! Прогоняет набор проверок с телефона на текущей сети и собирает отчёт:
//!  - маршруты до Telegram: прямой TCP, прямой WebSocket (обычный и с
//!    подменой SNI), прокси-домены Cloudflare по TLS и по HTTP, CF worker.
//!    Проверка настоящая: шлём MTProto-запрос req_pq_multi и ждём resPQ, а
//!    потом «поток» — ~250 запросов подряд (около 22 КБ ответов), чтобы
//!    поймать обрыв после 16 КБ;
//!  - мини-приложения: telegram.org, t.me и типичные хостинги — напрямую и
//!    через CF worker (worker открывает TCP к любому хосту на порт 443,
//!    TLS остаётся сквозным);
//!  - DNS: системный против DoH и UDP-DNS разных резолверов;
//!  - UDP для звонков: STUN и серия STUN-запросов.
//!
//! Используется только в отдельной сборке «Лаборатория» (пакет .lab).
//! Основное приложение эти функции не вызывает.

use crate::config::*;
use crate::crypto::{new_aes_ctr, TrackedStream};
use crate::ws::{ws_connect_full_opts, RawWebSocket, WsError};
use byteorder::{ByteOrder, LittleEndian};
use once_cell::sync::Lazy;
use parking_lot::Mutex;
use rand::RngCore;
use serde::{Deserialize, Serialize};
use std::ffi::{CStr, CString};
use std::future::Future;
use std::os::raw::{c_char, c_int};
use std::pin::Pin;
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::{TcpStream, UdpSocket};
use tokio_util::sync::CancellationToken;

const PROBE_TIMEOUT: Duration = Duration::from_secs(25);
const PARALLEL: usize = 6;
const CONNECT_TIMEOUT: f64 = 6.0;
const RTT_TIMEOUT: Duration = Duration::from_secs(6);
const FLOW_REQUESTS: usize = 250;
const FLOW_BATCH: usize = 25;
const FLOW_IDLE: Duration = Duration::from_secs(6);
const HTTP_IDLE: Duration = Duration::from_secs(8);
const HTTP_MAX_BYTES: usize = 300 * 1024;
const DIRECT_WS_IP: &str = "149.154.167.220";

#[derive(Serialize, Clone, Debug)]
pub struct ProbeResult {
    pub group: String,
    pub id: String,
    pub title: String,
    pub ok: bool,
    pub ms: u64,
    pub detail: String,
}

#[derive(Deserialize, Default, Clone)]
#[serde(default)]
pub struct LabConfig {
    /// CF worker домены через запятую или с новой строки.
    pub worker_domains: String,
    /// Свой CF-домен (если есть) — проверяется первым.
    pub cf_domain: String,
    pub cache_dir: String,
    /// Отдаётся обратно в отчёт как есть (сеть, оператор, версия).
    pub meta: serde_json::Value,
}

#[derive(Serialize, Default)]
struct LabState {
    running: bool,
    total: usize,
    done: usize,
    started_unix: u64,
    duration_ms: u64,
    results: Vec<ProbeResult>,
    summary: Vec<String>,
    meta: serde_json::Value,
}

static STATE: Lazy<Mutex<LabState>> = Lazy::new(|| Mutex::new(LabState::default()));
static CANCEL: Lazy<Mutex<Option<CancellationToken>>> = Lazy::new(|| Mutex::new(None));

type Outcome = (bool, String);
type ProbeFut = Pin<Box<dyn Future<Output = Outcome> + Send>>;

struct Probe {
    group: &'static str,
    id: String,
    title: String,
    fut: ProbeFut,
}

fn probe(group: &'static str, id: impl Into<String>, title: impl Into<String>, fut: impl Future<Output = Outcome> + Send + 'static) -> Probe {
    Probe {
        group,
        id: id.into(),
        title: title.into(),
        fut: Box::pin(fut),
    }
}

// ---------------------------------------------------------------------------
// Экспорт для Kotlin (JNA)
// ---------------------------------------------------------------------------

/// Запустить проверку. 0 — запущена, 1 — уже идёт, -1 — неверный конфиг.
///
/// # Safety
/// `c_config` — валидная C-строка (JSON) или null.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn LabStart(c_config: *const c_char) -> c_int {
    let raw = if c_config.is_null() {
        String::new()
    } else {
        CStr::from_ptr(c_config).to_string_lossy().into_owned()
    };
    let cfg: LabConfig = if raw.trim().is_empty() {
        LabConfig::default()
    } else {
        match serde_json::from_str(&raw) {
            Ok(c) => c,
            Err(_) => return -1,
        }
    };
    {
        let mut st = STATE.lock();
        if st.running {
            return 1;
        }
        *st = LabState {
            running: true,
            started_unix: now_unix(),
            meta: cfg.meta.clone(),
            ..Default::default()
        };
    }
    let token = CancellationToken::new();
    *CANCEL.lock() = Some(token.clone());
    std::thread::spawn(move || {
        let started = Instant::now();
        let rt = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(3)
            .enable_all()
            .build();
        if let Ok(rt) = rt {
            rt.block_on(run_lab(cfg, token));
            rt.shutdown_timeout(Duration::from_secs(2));
        }
        let mut st = STATE.lock();
        st.summary = summarize(&st.results);
        st.duration_ms = started.elapsed().as_millis() as u64;
        st.running = false;
    });
    0
}

/// Текущее состояние (JSON). Строку освободить через FreeString.
#[unsafe(no_mangle)]
pub extern "C" fn LabPoll() -> *mut c_char {
    let json = {
        let st = STATE.lock();
        serde_json::to_string(&*st).unwrap_or_else(|_| "{}".to_string())
    };
    CString::new(json).unwrap_or_default().into_raw()
}

#[unsafe(no_mangle)]
pub extern "C" fn LabCancel() {
    if let Some(t) = CANCEL.lock().as_ref() {
        t.cancel();
    }
}

fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

fn push_result(r: ProbeResult) {
    let mut st = STATE.lock();
    st.done += 1;
    st.results.push(r);
}

fn add_total(n: usize) {
    STATE.lock().total += n;
}

// ---------------------------------------------------------------------------
// План проверок
// ---------------------------------------------------------------------------

fn split_domains(s: &str) -> Vec<String> {
    let mut out = Vec::new();
    for part in s.split(|c: char| c == ',' || c == '\n' || c == ' ' || c == ';') {
        let d = part
            .trim()
            .trim_start_matches("https://")
            .trim_start_matches("http://")
            .trim_end_matches('/')
            .to_lowercase();
        if !d.is_empty() && !out.contains(&d) {
            out.push(d);
        }
    }
    out
}

async fn run_probes(probes: Vec<Probe>, cancel: &CancellationToken) {
    add_total(probes.len());
    let sem = Arc::new(tokio::sync::Semaphore::new(PARALLEL));
    let mut set = tokio::task::JoinSet::new();
    for p in probes {
        let sem = sem.clone();
        let cancel = cancel.clone();
        set.spawn(async move {
            let _permit = sem.acquire_owned().await.ok();
            let start = Instant::now();
            let (ok, detail) = tokio::select! {
                _ = cancel.cancelled() => (false, "отменено".to_string()),
                r = tokio::time::timeout(PROBE_TIMEOUT, p.fut) => match r {
                    Ok(v) => v,
                    Err(_) => (false, format!("не уложилось в {} с", PROBE_TIMEOUT.as_secs())),
                },
            };
            push_result(ProbeResult {
                group: p.group.to_string(),
                id: p.id,
                title: p.title,
                ok,
                ms: start.elapsed().as_millis() as u64,
                detail,
            });
        });
    }
    while set.join_next().await.is_some() {}
}

async fn run_lab(cfg: LabConfig, cancel: CancellationToken) {
    let workers = split_domains(&cfg.worker_domains);

    // Этап 1: список CF-доменов (нужен для остальных проверок).
    let cf_domains = prepare_cf_domains(&cfg).await;
    if cancel.is_cancelled() {
        return;
    }

    let mut probes: Vec<Probe> = Vec::new();

    // --- Telegram: основные DC (2 и 4) — полная матрица ---
    for dc in [2, 4] {
        let ip = DC_DEFAULT_IPS.get(&dc).copied().unwrap_or("").to_string();
        let ipc = ip.clone();
        probes.push(probe(
            "telegram",
            format!("dc{dc}.tcp443"),
            format!("DC{dc} · прямой TCP {ip}:443 (MTProto)"),
            async move { mtproto_probe(open_tcp(&ipc, 443), dc, true).await },
        ));
        for port in [80u16, 5222] {
            let ipc = ip.clone();
            probes.push(probe(
                "telegram",
                format!("dc{dc}.tcp{port}"),
                format!("DC{dc} · прямой TCP {ip}:{port} (MTProto)"),
                async move { mtproto_probe(open_tcp(&ipc, port), dc, false).await },
            ));
        }
        probes.push(probe(
            "telegram",
            format!("dc{dc}.ws"),
            format!("DC{dc} · прямой WebSocket kws{dc}.web.telegram.org"),
            async move {
                let domain = format!("kws{dc}.web.telegram.org");
                mtproto_probe(open_ws(DIRECT_WS_IP, &domain, WS_PATH, None, true), dc, true).await
            },
        ));
        probes.push(probe(
            "telegram",
            format!("dc{dc}.ws_front"),
            format!("DC{dc} · прямой WebSocket с подменой SNI ({FRONTING_SNI})"),
            async move {
                let domain = format!("kws{dc}.web.telegram.org");
                mtproto_probe(open_ws(DIRECT_WS_IP, &domain, WS_PATH, Some(FRONTING_SNI), true), dc, false).await
            },
        ));
        for (i, base) in cf_domains.iter().take(3).enumerate() {
            for tls in [true, false] {
                let domain = format!("kws{dc}.{base}");
                let flow = i == 0;
                probes.push(probe(
                    "telegram",
                    format!("dc{dc}.cf{i}.{}", mode_id(tls)),
                    format!("DC{dc} · Cloudflare {} ({})", mask_domain(base), mode_name(tls)),
                    async move { mtproto_probe(open_cf(&domain, tls), dc, flow).await },
                ));
            }
        }
        for w in workers.iter() {
            for tls in [true, false] {
                let w = w.clone();
                let ipc = ip.clone();
                probes.push(probe(
                    "telegram",
                    format!("dc{dc}.worker.{}", mode_id(tls)),
                    format!("DC{dc} · CF worker {} ({})", mask_domain(&w), mode_name(tls)),
                    async move {
                        let path = format!("/apiws?dst={}&dc={}", ipc, dc);
                        mtproto_probe(open_ws(&w, &w, &path, None, tls), dc, true).await
                    },
                ));
            }
        }
    }

    // --- Telegram: остальные DC — короче ---
    for dc in [1, 3, 5] {
        probes.push(probe(
            "telegram",
            format!("dc{dc}.ws"),
            format!("DC{dc} · прямой WebSocket kws{dc}.web.telegram.org"),
            async move {
                let domain = format!("kws{dc}.web.telegram.org");
                mtproto_probe(open_ws(DIRECT_WS_IP, &domain, WS_PATH, None, true), dc, false).await
            },
        ));
        if let Some(base) = cf_domains.first() {
            for tls in [true, false] {
                let domain = format!("kws{dc}.{base}");
                probes.push(probe(
                    "telegram",
                    format!("dc{dc}.cf0.{}", mode_id(tls)),
                    format!("DC{dc} · Cloudflare {} ({})", mask_domain(base), mode_name(tls)),
                    async move { mtproto_probe(open_cf(&domain, tls), dc, false).await },
                ));
            }
        }
    }

    // --- Мини-приложения ---
    let hosts: [(&str, &str, &str, bool); 6] = [
        ("telegram.org", "/js/telegram-web-app.js", "скрипт мини-приложений", true),
        ("t.me", "/", "t.me", true),
        ("web.telegram.org", "/k/", "веб-версия Telegram", true),
        ("vercel.com", "/", "хостинг Vercel", true),
        ("pages.github.com", "/", "GitHub Pages", true),
        ("speed.cloudflare.com", "/__down?bytes=100000", "Cloudflare, 100 КБ", false),
    ];
    for (host, path, label, via_worker) in hosts {
        probes.push(probe(
            "miniapps",
            format!("{host}.direct"),
            format!("{label} — напрямую ({host})"),
            async move { http_probe_direct(host, path).await },
        ));
        if via_worker {
            for w in workers.iter().take(1) {
                let w = w.clone();
                probes.push(probe(
                    "miniapps",
                    format!("{host}.worker"),
                    format!("{label} — через CF worker"),
                    async move { http_probe_worker(&w, host, path).await },
                ));
            }
        }
    }

    // --- DNS ---
    for host in ["telegram.org", "t.me", "web.telegram.org", "kws2.web.telegram.org"] {
        probes.push(probe(
            "dns",
            format!("dns.{host}"),
            format!("{host}: системный DNS и DoH"),
            async move { dns_compare(host).await },
        ));
    }
    for (server, name) in [
        ("1.1.1.1:53", "Cloudflare 1.1.1.1"),
        ("8.8.8.8:53", "Google 8.8.8.8"),
        ("77.88.8.8:53", "Яндекс 77.88.8.8"),
    ] {
        probes.push(probe(
            "dns",
            format!("udpdns.{server}"),
            format!("UDP DNS {name}: telegram.org"),
            async move { udp_dns_probe(server, "telegram.org").await },
        ));
    }

    // --- UDP / звонки ---
    for (server, name) in [
        ("stun.l.google.com:19302", "STUN Google"),
        ("stun.cloudflare.com:3478", "STUN Cloudflare"),
    ] {
        probes.push(probe(
            "udp",
            format!("stun.{server}"),
            name.to_string(),
            async move { stun_probe(server).await },
        ));
    }
    probes.push(probe(
        "udp",
        "stun.burst",
        "Серия из 50 STUN-запросов (Google)",
        async move { stun_burst("stun.l.google.com:19302", 50).await },
    ));

    run_probes(probes, &cancel).await;
}

fn mode_id(tls: bool) -> &'static str {
    if tls {
        "tls"
    } else {
        "http"
    }
}

fn mode_name(tls: bool) -> &'static str {
    if tls {
        "TLS:443"
    } else {
        "HTTP:80"
    }
}

/// Домены воркеров и CF в отчёте сокращаем: отчёт отправляют другим людям.
fn mask_domain(d: &str) -> String {
    let parts: Vec<&str> = d.split('.').collect();
    if parts.len() <= 2 {
        return d.to_string();
    }
    let first = parts[0];
    let short = if first.len() > 4 {
        format!("{}…", &first[..first.char_indices().nth(3).map(|(i, _)| i).unwrap_or(first.len())])
    } else {
        first.to_string()
    };
    format!("{}.{}", short, parts[1..].join("."))
}

async fn prepare_cf_domains(cfg: &LabConfig) -> Vec<String> {
    {
        let mut c = CFPROXY.write();
        c.cache_dir = cfg.cache_dir.clone();
        c.user_domain = crate::cfproxy::normalize_cf_domain(&cfg.cf_domain);
    }
    crate::cfproxy::init_cfproxy_domains();
    add_total(1);
    let start = Instant::now();
    let refreshed = tokio::time::timeout(
        Duration::from_secs(15),
        crate::cfproxy::try_refresh_cfproxy_domains(),
    )
    .await
    .unwrap_or(false);
    let domains = CFPROXY.read().domains.clone();
    push_result(ProbeResult {
        group: "telegram".into(),
        id: "cf.list".into(),
        title: "Список прокси-доменов Cloudflare".into(),
        ok: !domains.is_empty(),
        ms: start.elapsed().as_millis() as u64,
        detail: format!(
            "{} шт.; {}",
            domains.len(),
            if refreshed {
                "список обновлён"
            } else {
                "обновить не удалось — встроенный/кеш"
            }
        ),
    });
    domains
}

// ---------------------------------------------------------------------------
// Транспорт для MTProto-проверок
// ---------------------------------------------------------------------------

enum Pipe {
    Tcp(TcpStream),
    Ws(RawWebSocket),
}

impl Pipe {
    async fn send(&mut self, data: &[u8]) -> Result<(), String> {
        match self {
            Pipe::Tcp(s) => s.write_all(data).await.map_err(|e| e.to_string()),
            Pipe::Ws(w) => w.send(data).await.map_err(|e| e.compact()),
        }
    }

    /// Следующая порция байт. Ok(None) — тишина дольше `idle`.
    async fn recv(&mut self, idle: Duration) -> Result<Option<Vec<u8>>, String> {
        match self {
            Pipe::Tcp(s) => {
                let mut buf = vec![0u8; 16384];
                match tokio::time::timeout(idle, s.read(&mut buf)).await {
                    Err(_) => Ok(None),
                    Ok(Ok(0)) => Err("соединение закрыто".into()),
                    Ok(Ok(n)) => {
                        buf.truncate(n);
                        Ok(Some(buf))
                    }
                    Ok(Err(e)) => Err(e.to_string()),
                }
            }
            Pipe::Ws(w) => match w.recv_with_timeout(idle).await {
                Ok(d) => Ok(Some(d)),
                Err(WsError::Timeout) => Ok(None),
                Err(e) => Err(format!("соединение закрыто ({})", e.compact())),
            },
        }
    }

    async fn close(self) {
        match self {
            Pipe::Tcp(mut s) => {
                let _ = s.shutdown().await;
            }
            Pipe::Ws(w) => w.close().await,
        }
    }
}

type PipeFut = Pin<Box<dyn Future<Output = Result<(Pipe, String), String>> + Send>>;

fn open_tcp(ip: &str, port: u16) -> PipeFut {
    let addr = format!("{ip}:{port}");
    Box::pin(async move {
        match tokio::time::timeout(Duration::from_secs_f64(CONNECT_TIMEOUT), TcpStream::connect(&addr)).await {
            Ok(Ok(s)) => {
                let _ = s.set_nodelay(true);
                Ok((Pipe::Tcp(s), String::new()))
            }
            Ok(Err(e)) => Err(format!("TCP: {}", e)),
            Err(_) => Err("TCP: таймаут подключения".into()),
        }
    })
}

fn open_ws(dial: &str, domain: &str, path: &str, sni: Option<&'static str>, tls: bool) -> PipeFut {
    let (dial, domain, path) = (dial.to_string(), domain.to_string(), path.to_string());
    Box::pin(async move {
        match ws_connect_full_opts(&dial, &domain, &path, CONNECT_TIMEOUT, sni, Some(tls)).await {
            Ok(ws) => Ok((Pipe::Ws(ws), String::new())),
            Err(e) => Err(format!("WebSocket: {}", describe_ws_error(&e))),
        }
    })
}

fn open_cf(domain: &str, tls: bool) -> PipeFut {
    let domain = domain.to_string();
    Box::pin(async move {
        let (ws, ip, err) = crate::cfproxy::cf_connect_domain(&domain, WS_PATH, CONNECT_TIMEOUT, tls).await;
        match (ws, err) {
            (Some(ws), _) => Ok((
                Pipe::Ws(ws),
                if ip.is_empty() {
                    String::new()
                } else {
                    format!("через DoH-адрес {ip}")
                },
            )),
            (None, Some(e)) => Err(format!("WebSocket: {}", describe_ws_error(&e))),
            (None, None) => Err("WebSocket: нет соединения".into()),
        }
    })
}

fn describe_ws_error(e: &WsError) -> String {
    match e {
        WsError::Handshake(h) => format!("ответ HTTP {}", h.status_code),
        WsError::Timeout => "таймаут".into(),
        WsError::Io(io) => match io.kind() {
            std::io::ErrorKind::ConnectionReset => "соединение сброшено (RST)".into(),
            std::io::ErrorKind::ConnectionRefused => "в подключении отказано".into(),
            std::io::ErrorKind::TimedOut => "таймаут".into(),
            std::io::ErrorKind::UnexpectedEof => "соединение оборвано".into(),
            _ => io.to_string(),
        },
        other => other.compact(),
    }
}

// ---------------------------------------------------------------------------
// MTProto: obfuscated2 + intermediate, req_pq_multi → resPQ
// ---------------------------------------------------------------------------

const REQ_PQ_MULTI: u32 = 0xbe7e8ef1;
const RES_PQ: u32 = 0x05162463;
const PROTO_TAG_INTERMEDIATE: [u8; 4] = [0xee, 0xee, 0xee, 0xee];

struct Mtp {
    enc: TrackedStream,
    dec: TrackedStream,
    rx: Vec<u8>,
    last_msg_id: u64,
    first_chunk: bool,
}

impl Mtp {
    /// 64 байта инициализации (как relay_init в proxy.rs) и шифры.
    fn new(dc: i32) -> (Vec<u8>, Mtp) {
        let mut init = [0u8; 64];
        loop {
            rand::thread_rng().fill_bytes(&mut init);
            if init[0] == RESERVED_FIRST_BYTE || is_reserved_start(&init[..4]) {
                continue;
            }
            if init[4..8] == [0, 0, 0, 0] {
                continue;
            }
            break;
        }
        let mut rev = [0u8; 48];
        for i in 0..48 {
            rev[i] = init[8 + 47 - i];
        }
        let mut enc = new_aes_ctr(&init[8..40], &init[40..56]);
        let dec = new_aes_ctr(&rev[..32], &rev[32..]);
        let mut tail = [0u8; 8];
        tail[..4].copy_from_slice(&PROTO_TAG_INTERMEDIATE);
        LittleEndian::write_i16(&mut tail[4..6], dc as i16);
        rand::thread_rng().fill_bytes(&mut tail[6..8]);
        let mut encrypted = init;
        enc.xor(&mut encrypted);
        for i in 0..8 {
            let ks = encrypted[56 + i] ^ init[56 + i];
            init[56 + i] = tail[i] ^ ks;
        }
        (
            init.to_vec(),
            Mtp {
                enc,
                dec,
                rx: Vec::new(),
                last_msg_id: 0,
                first_chunk: true,
            },
        )
    }

    fn next_msg_id(&mut self) -> u64 {
        let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default();
        let mut id = (now.as_secs() << 32) | ((now.subsec_nanos() as u64) << 2 & 0xffff_fffc);
        id &= !3;
        if id <= self.last_msg_id {
            id = self.last_msg_id + 4;
        }
        self.last_msg_id = id;
        id
    }

    /// Зашифрованные кадры с `count` запросами req_pq_multi.
    fn req_pq_frames(&mut self, count: usize) -> Vec<u8> {
        let mut out = Vec::with_capacity(count * 44);
        for _ in 0..count {
            let mut frame = [0u8; 44];
            LittleEndian::write_u32(&mut frame[0..4], 40);
            // auth_key_id = 0 (байты 4..12 уже нули)
            let id = self.next_msg_id();
            LittleEndian::write_u64(&mut frame[12..20], id);
            LittleEndian::write_u32(&mut frame[20..24], 20);
            LittleEndian::write_u32(&mut frame[24..28], REQ_PQ_MULTI);
            rand::thread_rng().fill_bytes(&mut frame[28..44]);
            out.extend_from_slice(&frame);
        }
        self.enc.xor(&mut out);
        out
    }

    /// Разбирает принятое. Возвращает (ответов resPQ, код ошибки если был).
    fn feed(&mut self, mut data: Vec<u8>) -> Result<usize, String> {
        // Первые байты открытым текстом «HTTP/» — ответил не Telegram
        // (заглушка провайдера, прозрачный прокси, страница блокировки).
        if self.first_chunk {
            self.first_chunk = false;
            if data.starts_with(b"HTTP/") {
                let line = String::from_utf8_lossy(&data[..data.len().min(40)])
                    .lines()
                    .next()
                    .unwrap_or("")
                    .to_string();
                return Err(format!("ответил не Telegram: «{line}»"));
            }
        }
        self.dec.xor(&mut data);
        self.rx.extend_from_slice(&data);
        let mut got = 0;
        loop {
            if self.rx.len() < 4 {
                break;
            }
            let len = LittleEndian::read_u32(&self.rx[0..4]) as usize;
            if len == 0 || len > 1 << 20 {
                return Err(format!("ответ не похож на Telegram (длина кадра {len})"));
            }
            if self.rx.len() < 4 + len {
                break;
            }
            let pkt: Vec<u8> = self.rx.drain(..4 + len).skip(4).collect();
            if len == 4 {
                let code = LittleEndian::read_i32(&pkt[0..4]);
                return Err(format!("сервер ответил ошибкой {code}"));
            }
            if pkt.len() >= 24 && LittleEndian::read_u32(&pkt[20..24]) == RES_PQ {
                got += 1;
            }
        }
        Ok(got)
    }
}

async fn mtproto_probe(open: PipeFut, dc: i32, flow: bool) -> Outcome {
    let t0 = Instant::now();
    let (mut pipe, note) = match open.await {
        Ok(v) => v,
        Err(e) => return (false, e),
    };
    let connect_ms = t0.elapsed().as_millis();
    let (init, mut mtp) = Mtp::new(dc);
    let first = mtp.req_pq_frames(1);
    let mut payload = init;
    payload.extend_from_slice(&first);
    let t1 = Instant::now();
    if let Err(e) = pipe.send(&payload).await {
        pipe.close().await;
        return (false, format!("подключение {connect_ms} мс, отправка не удалась: {e}"));
    }
    // Ждём первый resPQ.
    let deadline = Instant::now() + RTT_TIMEOUT;
    let mut got = 0;
    while got == 0 {
        let left = deadline.saturating_duration_since(Instant::now());
        if left.is_zero() {
            pipe.close().await;
            return (false, format!("подключение {connect_ms} мс, но Telegram не ответил за {} с", RTT_TIMEOUT.as_secs()));
        }
        match pipe.recv(left).await {
            Ok(Some(d)) => match mtp.feed(d) {
                Ok(n) => got += n,
                Err(e) => {
                    pipe.close().await;
                    return (false, format!("подключение {connect_ms} мс; {e}"));
                }
            },
            Ok(None) => continue,
            Err(e) => {
                pipe.close().await;
                return (false, format!("подключение {connect_ms} мс; {e} до ответа"));
            }
        }
    }
    let rtt = t1.elapsed().as_millis();
    let mut detail = format!("подключение {connect_ms} мс, ответ Telegram {rtt} мс");
    if !note.is_empty() {
        detail.push_str(&format!(" ({note})"));
    }
    if !flow {
        pipe.close().await;
        return (true, detail);
    }

    // Поток: ~250 запросов, ~22 КБ ответов — ловим обрыв после 16 КБ.
    let flow_start = Instant::now();
    let mut answered = 0usize;
    let mut sent = 0usize;
    let mut err: Option<String> = None;
    while sent < FLOW_REQUESTS {
        let n = FLOW_BATCH.min(FLOW_REQUESTS - sent);
        let frames = mtp.req_pq_frames(n);
        if let Err(e) = pipe.send(&frames).await {
            err = Some(format!("отправка оборвалась: {e}"));
            break;
        }
        sent += n;
        // Не даём очереди расти: ждём, пока ответы догонят.
        while answered + FLOW_BATCH * 2 < sent {
            match pipe.recv(FLOW_IDLE).await {
                Ok(Some(d)) => match mtp.feed(d) {
                    Ok(k) => answered += k,
                    Err(e) => {
                        err = Some(e);
                        break;
                    }
                },
                Ok(None) => {
                    err = Some(format!("данные перестали приходить ({} с тишины)", FLOW_IDLE.as_secs()));
                    break;
                }
                Err(e) => {
                    err = Some(e);
                    break;
                }
            }
        }
        if err.is_some() {
            break;
        }
    }
    while err.is_none() && answered < sent {
        match pipe.recv(FLOW_IDLE).await {
            Ok(Some(d)) => match mtp.feed(d) {
                Ok(k) => answered += k,
                Err(e) => err = Some(e),
            },
            Ok(None) => err = Some(format!("данные перестали приходить ({} с тишины)", FLOW_IDLE.as_secs())),
            Err(e) => err = Some(e),
        }
    }
    pipe.close().await;
    // Ответ resPQ в кадре — около 88 байт.
    let kb = (answered * 88) as f64 / 1024.0;
    let total_kb = (FLOW_REQUESTS * 88) as f64 / 1024.0;
    match err {
        None => {
            detail.push_str(&format!(
                "; поток {:.1} КБ за {} мс — без обрыва",
                kb,
                flow_start.elapsed().as_millis()
            ));
            (true, detail)
        }
        Some(e) => {
            detail.push_str(&format!(
                "; ПОТОК ОБОРВАЛСЯ на {:.1} из {:.1} КБ: {e}",
                kb, total_kb
            ));
            (false, detail)
        }
    }
}

// ---------------------------------------------------------------------------
// HTTPS для мини-приложений
// ---------------------------------------------------------------------------

async fn http_probe_direct(host: &'static str, path: &'static str) -> Outcome {
    let t0 = Instant::now();
    let tcp = match tokio::time::timeout(Duration::from_secs(8), TcpStream::connect((host, 443))).await {
        Ok(Ok(s)) => s,
        Ok(Err(e)) => return (false, format!("TCP: {e}")),
        Err(_) => return (false, "TCP: таймаут подключения".into()),
    };
    let ip = tcp.peer_addr().map(|a| a.ip().to_string()).unwrap_or_default();
    let connect_ms = t0.elapsed().as_millis();
    let (ok, detail) = https_get(tcp, host, path).await;
    (ok, format!("{ip}, TCP {connect_ms} мс; {detail}"))
}

async fn http_probe_worker(worker: &str, host: &'static str, path: &'static str) -> Outcome {
    let t0 = Instant::now();
    let ws_path = format!("/apiws?dst={host}&dc=0");
    let mut last_err = String::new();
    for tls in [true, false] {
        match ws_connect_full_opts(worker, worker, &ws_path, CONNECT_TIMEOUT, None, Some(tls)).await {
            Ok(ws) => {
                let connect_ms = t0.elapsed().as_millis();
                let (stream, ws) = ws_duplex(ws);
                let (ok, detail) = https_get(stream, host, path).await;
                ws.close().await;
                return (ok, format!("worker {} за {connect_ms} мс; {detail}", mode_name(tls)));
            }
            Err(e) => {
                last_err = format!("worker {}: {}", mode_name(tls), describe_ws_error(&e));
            }
        }
    }
    (false, last_err)
}

/// WebSocket как обычный поток байт (для TLS поверх worker).
fn ws_duplex(ws: RawWebSocket) -> (tokio::io::DuplexStream, Arc<RawWebSocket>) {
    let (ours, theirs) = tokio::io::duplex(256 * 1024);
    let ws = Arc::new(ws);
    let (mut rd, mut wr) = tokio::io::split(theirs);
    let up = ws.clone();
    tokio::spawn(async move {
        let mut buf = vec![0u8; 16384];
        loop {
            match rd.read(&mut buf).await {
                Ok(0) | Err(_) => break,
                Ok(n) => {
                    if up.send(&buf[..n]).await.is_err() {
                        break;
                    }
                }
            }
        }
    });
    let down = ws.clone();
    tokio::spawn(async move {
        loop {
            match down.recv_with_timeout(Duration::from_secs(30)).await {
                Ok(d) => {
                    if wr.write_all(&d).await.is_err() {
                        break;
                    }
                }
                Err(_) => break,
            }
        }
        let _ = wr.shutdown().await;
    });
    (ours, ws)
}

async fn https_get<S>(stream: S, host: &str, path: &str) -> Outcome
where
    S: AsyncRead + AsyncWrite + Unpin + Send,
{
    let t0 = Instant::now();
    let connector = tokio_rustls::TlsConnector::from(crate::ws::tls_client_config());
    let name = match rustls_pki_types::ServerName::try_from(host.to_string()) {
        Ok(n) => n,
        Err(_) => return (false, "неверное имя".into()),
    };
    let mut tls = match tokio::time::timeout(Duration::from_secs(8), connector.connect(name, stream)).await {
        Ok(Ok(t)) => t,
        Ok(Err(e)) => {
            let what = match e.kind() {
                std::io::ErrorKind::ConnectionReset => "сброшен (RST)".to_string(),
                std::io::ErrorKind::UnexpectedEof => "оборван".to_string(),
                _ => e.to_string(),
            };
            return (false, format!("TLS {what}"));
        }
        Err(_) => return (false, "TLS: таймаут рукопожатия".into()),
    };
    let tls_ms = t0.elapsed().as_millis();
    let req = format!(
        "GET {path} HTTP/1.1\r\nHost: {host}\r\nUser-Agent: Mozilla/5.0 (Linux; Android 14) TgWsProxyLab\r\nAccept: */*\r\nAccept-Encoding: identity\r\nConnection: close\r\n\r\n"
    );
    if let Err(e) = tls.write_all(req.as_bytes()).await {
        return (false, format!("TLS {tls_ms} мс; запрос не ушёл: {e}"));
    }
    let mut data: Vec<u8> = Vec::new();
    let mut buf = vec![0u8; 16384];
    let mut stalled = false;
    let mut eof = false;
    loop {
        match tokio::time::timeout(HTTP_IDLE, tls.read(&mut buf)).await {
            Err(_) => {
                stalled = true;
                break;
            }
            Ok(Ok(0)) => {
                eof = true;
                break;
            }
            Ok(Ok(n)) => {
                data.extend_from_slice(&buf[..n]);
                if data.len() >= HTTP_MAX_BYTES {
                    eof = true;
                    break;
                }
            }
            Ok(Err(e)) => {
                // Многие серверы закрывают TLS без close_notify — это норма.
                if e.kind() == std::io::ErrorKind::UnexpectedEof && !data.is_empty() {
                    eof = true;
                } else if data.is_empty() {
                    return (false, format!("TLS {tls_ms} мс; ответа нет: {e}"));
                } else {
                    stalled = true;
                }
                break;
            }
        }
    }
    let total_ms = t0.elapsed().as_millis();
    let header_end = data.windows(4).position(|w| w == b"\r\n\r\n").map(|p| p + 4);
    let status = std::str::from_utf8(&data[..data.len().min(64)])
        .ok()
        .and_then(|s| s.split_whitespace().nth(1))
        .and_then(|s| s.parse::<u16>().ok())
        .unwrap_or(0);
    let body = header_end.map(|h| data.len() - h).unwrap_or(0);
    let content_len = header_end.and_then(|h| {
        let head = String::from_utf8_lossy(&data[..h]).to_lowercase();
        head.lines()
            .find_map(|l| l.strip_prefix("content-length:").map(|v| v.trim().to_string()))
            .and_then(|v| v.parse::<usize>().ok())
    });
    let kb = body as f64 / 1024.0;
    if status == 0 {
        return (
            false,
            format!("TLS {tls_ms} мс; HTTP-ответа нет (получено {} Б)", data.len()),
        );
    }
    let complete = match content_len {
        Some(cl) => body >= cl,
        None => eof,
    };
    if stalled && !complete {
        return (
            false,
            format!(
                "TLS {tls_ms} мс; HTTP {status}, ОБРЫВ после {:.1} КБ{} (нет данных {} с)",
                kb,
                content_len.map(|c| format!(" из {:.1}", c as f64 / 1024.0)).unwrap_or_default(),
                HTTP_IDLE.as_secs()
            ),
        );
    }
    let ok = (200..400).contains(&status);
    (
        ok,
        format!("TLS {tls_ms} мс; HTTP {status}, {:.1} КБ за {total_ms} мс", kb),
    )
}

// ---------------------------------------------------------------------------
// DNS
// ---------------------------------------------------------------------------

async fn dns_compare(host: &'static str) -> Outcome {
    let sys = tokio::time::timeout(
        Duration::from_secs(6),
        tokio::net::lookup_host((host, 443)),
    )
    .await;
    let sys_ips: Vec<String> = match sys {
        Ok(Ok(it)) => {
            let mut v: Vec<String> = it.map(|a| a.ip().to_string()).collect();
            v.dedup();
            v
        }
        Ok(Err(e)) => vec![format!("ошибка: {e}")],
        Err(_) => vec!["таймаут".to_string()],
    };
    let doh = tokio::time::timeout(Duration::from_secs(8), crate::cfproxy::resolve_doh(host))
        .await
        .ok()
        .flatten()
        .unwrap_or_default();
    let sys_ok = sys_ips.iter().any(|s| s.parse::<std::net::IpAddr>().is_ok());
    let detail = format!(
        "система: {}; DoH: {}",
        sys_ips.join(", "),
        if doh.is_empty() { "нет ответа" } else { &doh }
    );
    let mismatch = sys_ok && !doh.is_empty() && !sys_ips.contains(&doh);
    if mismatch {
        return (true, format!("{detail} — адреса различаются"));
    }
    (sys_ok || !doh.is_empty(), detail)
}

fn dns_query(host: &str, id: u16) -> Vec<u8> {
    let mut q = Vec::with_capacity(32);
    q.extend_from_slice(&id.to_be_bytes());
    q.extend_from_slice(&[0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0]);
    for label in host.split('.') {
        q.push(label.len() as u8);
        q.extend_from_slice(label.as_bytes());
    }
    q.push(0);
    q.extend_from_slice(&[0, 1, 0, 1]);
    q
}

fn skip_name(p: &[u8], mut i: usize) -> Option<usize> {
    loop {
        let l = *p.get(i)? as usize;
        if l == 0 {
            return Some(i + 1);
        }
        if l & 0xC0 == 0xC0 {
            return Some(i + 2);
        }
        i += 1 + l;
    }
}

fn parse_dns_a(p: &[u8]) -> Option<Vec<String>> {
    if p.len() < 12 {
        return None;
    }
    let qd = u16::from_be_bytes([p[4], p[5]]) as usize;
    let an = u16::from_be_bytes([p[6], p[7]]) as usize;
    let mut i = 12;
    for _ in 0..qd {
        i = skip_name(p, i)? + 4;
    }
    let mut ips = Vec::new();
    for _ in 0..an {
        i = skip_name(p, i)?;
        let typ = u16::from_be_bytes([*p.get(i)?, *p.get(i + 1)?]);
        let rdlen = u16::from_be_bytes([*p.get(i + 8)?, *p.get(i + 9)?]) as usize;
        let rd = p.get(i + 10..i + 10 + rdlen)?;
        if typ == 1 && rdlen == 4 {
            ips.push(format!("{}.{}.{}.{}", rd[0], rd[1], rd[2], rd[3]));
        }
        i += 10 + rdlen;
    }
    Some(ips)
}

async fn udp_dns_probe(server: &'static str, host: &'static str) -> Outcome {
    let sock = match UdpSocket::bind("0.0.0.0:0").await {
        Ok(s) => s,
        Err(e) => return (false, e.to_string()),
    };
    let id: u16 = rand::random();
    let q = dns_query(host, id);
    let t0 = Instant::now();
    for _ in 0..2 {
        if let Err(e) = sock.send_to(&q, server).await {
            return (false, format!("отправка: {e}"));
        }
        let mut buf = vec![0u8; 1500];
        match tokio::time::timeout(Duration::from_secs(3), sock.recv_from(&mut buf)).await {
            Ok(Ok((n, _))) => {
                let ips = parse_dns_a(&buf[..n]).unwrap_or_default();
                return (
                    true,
                    format!(
                        "ответ за {} мс: {}",
                        t0.elapsed().as_millis(),
                        if ips.is_empty() { "без A-записей".to_string() } else { ips.join(", ") }
                    ),
                );
            }
            Ok(Err(e)) => return (false, e.to_string()),
            Err(_) => continue,
        }
    }
    (false, "UDP-ответа нет (2 попытки по 3 с)".into())
}

// ---------------------------------------------------------------------------
// STUN (UDP для звонков)
// ---------------------------------------------------------------------------

const STUN_MAGIC: u32 = 0x2112A442;

fn stun_request() -> ([u8; 20], [u8; 12]) {
    let mut req = [0u8; 20];
    req[0..2].copy_from_slice(&0x0001u16.to_be_bytes());
    req[4..8].copy_from_slice(&STUN_MAGIC.to_be_bytes());
    let mut tid = [0u8; 12];
    rand::thread_rng().fill_bytes(&mut tid);
    req[8..20].copy_from_slice(&tid);
    (req, tid)
}

/// Внешний адрес из XOR-MAPPED-ADDRESS.
fn stun_mapped(resp: &[u8]) -> Option<String> {
    if resp.len() < 20 || u16::from_be_bytes([resp[0], resp[1]]) != 0x0101 {
        return None;
    }
    let mut i = 20;
    while i + 4 <= resp.len() {
        let typ = u16::from_be_bytes([resp[i], resp[i + 1]]);
        let len = u16::from_be_bytes([resp[i + 2], resp[i + 3]]) as usize;
        let v = resp.get(i + 4..i + 4 + len)?;
        if typ == 0x0020 && len >= 8 && v[1] == 1 {
            let port = u16::from_be_bytes([v[2], v[3]]) ^ (STUN_MAGIC >> 16) as u16;
            let m = STUN_MAGIC.to_be_bytes();
            return Some(format!(
                "{}.{}.{}.{}:{}",
                v[4] ^ m[0],
                v[5] ^ m[1],
                v[6] ^ m[2],
                v[7] ^ m[3],
                port
            ));
        }
        i += 4 + ((len + 3) & !3);
    }
    Some("адрес не указан".into())
}

async fn stun_probe(server: &'static str) -> Outcome {
    let sock = match UdpSocket::bind("0.0.0.0:0").await {
        Ok(s) => s,
        Err(e) => return (false, e.to_string()),
    };
    let t0 = Instant::now();
    for _ in 0..3 {
        let (req, tid) = stun_request();
        if let Err(e) = sock.send_to(&req, server).await {
            return (false, format!("отправка: {e}"));
        }
        let mut buf = vec![0u8; 1500];
        match tokio::time::timeout(Duration::from_secs(2), sock.recv_from(&mut buf)).await {
            Ok(Ok((n, _))) if n >= 20 && buf[8..20] == tid => {
                let mapped = stun_mapped(&buf[..n]).unwrap_or_else(|| "?".into());
                return (
                    true,
                    format!("ответ за {} мс, внешний адрес {}", t0.elapsed().as_millis(), mapped),
                );
            }
            Ok(Ok(_)) => continue,
            Ok(Err(e)) => return (false, e.to_string()),
            Err(_) => continue,
        }
    }
    (false, "UDP-ответа нет (3 попытки по 2 с)".into())
}

async fn stun_burst(server: &'static str, count: usize) -> Outcome {
    let sock = match UdpSocket::bind("0.0.0.0:0").await {
        Ok(s) => Arc::new(s),
        Err(e) => return (false, e.to_string()),
    };
    let target = match tokio::net::lookup_host(server).await.ok().and_then(|mut i| i.next()) {
        Some(a) => a,
        None => return (false, "не удалось найти адрес сервера".into()),
    };
    let tids: Arc<Mutex<std::collections::HashSet<[u8; 12]>>> = Arc::new(Mutex::new(Default::default()));
    let got = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let first_lost = Arc::new(Mutex::new(None::<usize>));
    let rx_sock = sock.clone();
    let rx_tids = tids.clone();
    let rx_got = got.clone();
    let reader = tokio::spawn(async move {
        let mut buf = vec![0u8; 1500];
        loop {
            match tokio::time::timeout(Duration::from_secs(3), rx_sock.recv_from(&mut buf)).await {
                Ok(Ok((n, _))) if n >= 20 => {
                    let mut tid = [0u8; 12];
                    tid.copy_from_slice(&buf[8..20]);
                    if rx_tids.lock().remove(&tid) {
                        rx_got.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                    }
                }
                Ok(Ok(_)) => continue,
                _ => break,
            }
        }
    });
    let mut order: Vec<[u8; 12]> = Vec::with_capacity(count);
    for _ in 0..count {
        let (req, tid) = stun_request();
        tids.lock().insert(tid);
        order.push(tid);
        let _ = sock.send_to(&req, target).await;
        tokio::time::sleep(Duration::from_millis(60)).await;
    }
    let _ = reader.await;
    let n = got.load(std::sync::atomic::Ordering::Relaxed);
    {
        let left = tids.lock();
        let lost_at = order.iter().position(|t| left.contains(t));
        *first_lost.lock() = lost_at;
    }
    let lost_at = *first_lost.lock();
    let detail = match lost_at {
        None => format!("ответы на все {count}"),
        Some(i) => format!("ответов {n} из {count}; первый потерянный — №{}", i + 1),
    };
    (n * 10 >= count * 8, detail)
}

// ---------------------------------------------------------------------------
// Выводы
// ---------------------------------------------------------------------------

fn summarize(results: &[ProbeResult]) -> Vec<String> {
    let mut out = Vec::new();
    let find = |pred: &dyn Fn(&ProbeResult) -> bool| -> Vec<&ProbeResult> {
        results.iter().filter(|r| pred(r)).collect()
    };
    let ratio = |v: &[&ProbeResult]| -> (usize, usize) { (v.iter().filter(|r| r.ok).count(), v.len()) };
    let curtain = |v: &[&ProbeResult]| v.iter().any(|r| r.detail.contains("ОБОРВАЛСЯ") || r.detail.contains("ОБРЫВ"));

    let direct_ws = find(&|r| r.id.ends_with(".ws"));
    let tcp443 = find(&|r| r.id.ends_with(".tcp443"));
    let front = find(&|r| r.id.ends_with(".ws_front"));
    let cf_tls = find(&|r| r.id.contains(".cf") && r.id.ends_with(".tls"));
    let cf_http = find(&|r| r.id.contains(".cf") && r.id.ends_with(".http"));
    let w_tls = find(&|r| r.id.contains(".worker.tls"));
    let w_http = find(&|r| r.id.contains(".worker.http"));

    let line = |name: &str, v: &[&ProbeResult]| -> Option<String> {
        if v.is_empty() {
            return None;
        }
        let (ok, n) = ratio(v);
        let mark = if ok == n {
            "✓"
        } else if ok == 0 {
            "✗"
        } else {
            "~"
        };
        let mut s = format!("{mark} {name}: {ok} из {n}");
        if curtain(v) {
            s.push_str(" — есть обрыв потока");
        }
        Some(s)
    };
    for l in [
        line("Прямой WebSocket к Telegram", &direct_ws),
        line("Прямой TCP к Telegram (443)", &tcp443),
        line("WebSocket с подменой SNI", &front),
        line("Cloudflare по TLS:443", &cf_tls),
        line("Cloudflare по HTTP:80", &cf_http),
        line("CF worker по TLS:443", &w_tls),
        line("CF worker по HTTP:80", &w_http),
    ]
    .into_iter()
    .flatten()
    {
        out.push(l);
    }

    let (cft, cftn) = ratio(&cf_tls);
    let (cfh, cfhn) = ratio(&cf_http);
    if cftn > 0 && cfhn > 0 {
        if cft > cfh {
            out.push("→ Cloudflare: лучше TLS — прокси 1.3.1 выберет его сам.".into());
        } else if cfh > cft {
            out.push("→ Cloudflare: TLS режут, работает HTTP:80 — прокси 1.3.1 переключится сам, H2 для медиа здесь не заработает.".into());
        }
    }

    let tg_direct = find(&|r| r.id == "telegram.org.direct");
    let tg_worker = find(&|r| r.id == "telegram.org.worker");
    match (tg_direct.first(), tg_worker.first()) {
        (Some(d), Some(w)) if !d.ok && w.ok => out.push(
            "→ Мини-приложения: telegram.org напрямую недоступен, а через worker открывается — туннель для мини-приложений поможет.".into(),
        ),
        (Some(d), Some(w)) if !d.ok && !w.ok => out.push(
            "→ Мини-приложения: telegram.org недоступен ни напрямую, ни через worker.".into(),
        ),
        (Some(d), None) if !d.ok => out.push(
            "→ Мини-приложения: telegram.org напрямую недоступен. Укажи CF worker, чтобы проверить обход.".into(),
        ),
        (Some(d), _) if d.ok => out.push("✓ telegram.org открывается напрямую.".into()),
        _ => {}
    }
    let cf_speed = find(&|r| r.id == "speed.cloudflare.com.direct");
    if let Some(r) = cf_speed.first() {
        if !r.ok && r.detail.contains("ОБРЫВ") {
            out.push("→ Сайты на Cloudflare здесь режут после ~16 КБ.".into());
        }
    }

    let stun = find(&|r| r.group == "udp" && r.id != "stun.burst");
    let (st_ok, st_n) = ratio(&stun);
    if st_n > 0 {
        if st_ok == 0 {
            out.push("✗ UDP (STUN) не проходит вообще — звонкам нужен туннель.".into());
        } else if let Some(b) = find(&|r| r.id == "stun.burst").first() {
            if !b.ok {
                out.push(format!("~ UDP проходит, но серия теряется: {}", b.detail));
            } else {
                out.push("✓ UDP (STUN) проходит.".into());
            }
        }
    }
    let dns_diff = find(&|r| r.group == "dns" && r.detail.contains("различаются"));
    if !dns_diff.is_empty() {
        out.push(format!(
            "~ DNS: системный и DoH дают разные адреса для {} шт. (не всегда подмена — у CDN адреса меняются)",
            dns_diff.len()
        ));
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mtp_init_has_protocol_tag_after_decrypt() {
        let (init, _) = Mtp::new(2);
        let mut enc = new_aes_ctr(&init[8..40], &init[40..56]);
        let mut copy = init.clone();
        enc.xor(&mut copy);
        assert_eq!(&copy[56..60], &PROTO_TAG_INTERMEDIATE);
        assert_eq!(LittleEndian::read_i16(&copy[60..62]), 2);
    }

    #[test]
    fn req_pq_frames_have_expected_layout() {
        let (init, mut m) = Mtp::new(4);
        let frames = m.req_pq_frames(2);
        assert_eq!(frames.len(), 88);
        // Расшифровываем тем же потоком, что увидит сервер.
        let mut srv = new_aes_ctr(&init[8..40], &init[40..56]);
        let mut all = init.clone();
        all.extend_from_slice(&frames);
        srv.xor(&mut all);
        let f = &all[64..];
        assert_eq!(LittleEndian::read_u32(&f[0..4]), 40);
        assert_eq!(LittleEndian::read_u64(&f[4..12]), 0);
        assert_eq!(LittleEndian::read_u32(&f[24..28]), REQ_PQ_MULTI);
        let id1 = LittleEndian::read_u64(&f[12..20]);
        let id2 = LittleEndian::read_u64(&f[44 + 12..44 + 20]);
        assert!(id2 > id1 && id1 % 4 == 0 && id2 % 4 == 0);
    }

    #[test]
    fn feed_counts_respq_and_errors() {
        let (init, mut m) = Mtp::new(2);
        // «Сервер» шифрует ответ ключом, обратным клиентскому.
        let mut rev = [0u8; 48];
        for i in 0..48 {
            rev[i] = init[8 + 47 - i];
        }
        let mut srv_enc = new_aes_ctr(&rev[..32], &rev[32..]);
        let mut pkt = vec![0u8; 4 + 84];
        LittleEndian::write_u32(&mut pkt[0..4], 84);
        LittleEndian::write_u32(&mut pkt[4 + 20..4 + 24], RES_PQ);
        let mut two = pkt.clone();
        two.extend_from_slice(&pkt);
        srv_enc.xor(&mut two);
        assert_eq!(m.feed(two[..50].to_vec()).unwrap(), 0);
        assert_eq!(m.feed(two[50..].to_vec()).unwrap(), 2);
        let mut err = vec![0u8; 8];
        LittleEndian::write_u32(&mut err[0..4], 4);
        LittleEndian::write_i32(&mut err[4..8], -404);
        srv_enc.xor(&mut err);
        assert!(m.feed(err).unwrap_err().contains("-404"));
    }

    #[test]
    fn dns_roundtrip_parse() {
        let q = dns_query("telegram.org", 0x1234);
        // Ответ: заголовок с 1 вопросом и 1 ответом (сжатое имя).
        let mut r = q.clone();
        r[2] = 0x81;
        r[3] = 0x80;
        r[7] = 1;
        r.extend_from_slice(&[0xC0, 0x0C, 0, 1, 0, 1, 0, 0, 0, 60, 0, 4, 149, 154, 167, 99]);
        assert_eq!(parse_dns_a(&r).unwrap(), vec!["149.154.167.99".to_string()]);
    }

    #[test]
    fn stun_xor_mapped_address() {
        let mut resp = vec![0u8; 32];
        resp[0..2].copy_from_slice(&0x0101u16.to_be_bytes());
        resp[2..4].copy_from_slice(&12u16.to_be_bytes());
        resp[4..8].copy_from_slice(&STUN_MAGIC.to_be_bytes());
        resp[20..22].copy_from_slice(&0x0020u16.to_be_bytes());
        resp[22..24].copy_from_slice(&8u16.to_be_bytes());
        resp[25] = 1;
        let port = 40000u16 ^ (STUN_MAGIC >> 16) as u16;
        resp[26..28].copy_from_slice(&port.to_be_bytes());
        let m = STUN_MAGIC.to_be_bytes();
        let ip = [93u8, 184, 216, 34];
        for i in 0..4 {
            resp[28 + i] = ip[i] ^ m[i];
        }
        assert_eq!(stun_mapped(&resp).unwrap(), "93.184.216.34:40000");
    }

    #[test]
    fn domains_are_split_and_masked() {
        assert_eq!(
            split_domains("https://a.b.workers.dev/, c.d.workers.dev\nA.B.WORKERS.DEV"),
            vec!["a.b.workers.dev".to_string(), "c.d.workers.dev".to_string()]
        );
        assert_eq!(mask_domain("random-123.user.workers.dev"), "ran….user.workers.dev");
        assert_eq!(mask_domain("example.com"), "example.com");
    }

    #[tokio::test]
    async fn https_get_detects_stall_against_local_server() {
        // Локальный TCP-сервер, который не говорит TLS: проверка должна
        // честно провалиться, а не зависнуть.
        let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = l.local_addr().unwrap();
        tokio::spawn(async move {
            if let Ok((mut s, _)) = l.accept().await {
                let _ = s.write_all(b"not tls at all").await;
                tokio::time::sleep(Duration::from_millis(200)).await;
            }
        });
        let s = TcpStream::connect(addr).await.unwrap();
        let (ok, detail) = https_get(s, "example.com", "/").await;
        assert!(!ok, "{detail}");
    }
}

#[cfg(test)]
mod live {
    use super::*;

    /// Живая проверка против настоящего Telegram: cargo test --lib live -- --ignored
    #[tokio::test]
    #[ignore]
    async fn live_mtproto_tcp() {
        let (ok, d) = mtproto_probe(open_tcp("149.154.167.51", 443), 2, true).await;
        println!("tcp443: ok={ok} {d}");
        let (ok2, d2) = mtproto_probe(
            open_ws(DIRECT_WS_IP, "kws2.web.telegram.org", WS_PATH, None, true),
            2,
            true,
        )
        .await;
        println!("ws: ok={ok2} {d2}");
        let (ok3, d3) = http_probe_direct("telegram.org", "/js/telegram-web-app.js").await;
        println!("http: ok={ok3} {d3}");
        let (ok4, d4) = stun_probe("stun.l.google.com:19302").await;
        println!("stun: ok={ok4} {d4}");
    }
}
