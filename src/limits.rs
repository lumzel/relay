// lumzel:remote-link#relay-limits lumzel:remote-link-03#m-limits lumzel:remote-link-03#a-limits
//! Abuse limits for an anonymous Relay: per-IP concurrent WebSocket cap, per-route
//! token-bucket rate backpressure + hard byte total cap across `/control` and `/data`,
//! and post-`hello` handshake timeout when the Host side sends no frame.

use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use axum::extract::{ConnectInfo, FromRequestParts};
use axum::http::request::Parts;
use axum::http::HeaderMap;
use tokio::sync::Notify;
use tokio::time::Instant;

pub const DEFAULT_MAX_CONNS_PER_IP: usize = 32;
pub const DEFAULT_ROUTE_BYTES_PER_SEC: u64 = 2 * 1024 * 1024;
pub const DEFAULT_ROUTE_BYTES_TOTAL: u64 = 512 * 1024 * 1024;
pub const DEFAULT_HANDSHAKE_TIMEOUT_MS: u64 = 10_000;
pub const DEFAULT_PRE_HELLO_TIMEOUT_MS: u64 = 5_000;
pub const DEFAULT_IDLE_TIMEOUT_MS: u64 = 90_000;
pub const DEFAULT_HTTP_REQ_PER_SEC: u32 = 30;
pub const DEFAULT_HTTP_MAX_CONNS_PER_IP: usize = 64;
const MAX_HTTP_TRACKED_IPS: usize = 65_536;

#[derive(Debug, Clone)]
pub struct LimitsConfig {
    pub max_conns_per_ip: usize,
    pub route_bytes_per_sec: u64,
    pub route_bytes_total: u64,
    pub handshake_timeout: Duration,
    pub pre_hello_timeout: Duration,
    pub idle_timeout: Duration,
    pub http_req_per_sec: u32,
    pub http_max_conns_per_ip: usize,
    pub trusted_proxies: Vec<IpAddr>,
}

impl Default for LimitsConfig {
    fn default() -> Self {
        Self {
            max_conns_per_ip: DEFAULT_MAX_CONNS_PER_IP,
            route_bytes_per_sec: DEFAULT_ROUTE_BYTES_PER_SEC,
            route_bytes_total: DEFAULT_ROUTE_BYTES_TOTAL,
            handshake_timeout: Duration::from_millis(DEFAULT_HANDSHAKE_TIMEOUT_MS),
            pre_hello_timeout: Duration::from_millis(DEFAULT_PRE_HELLO_TIMEOUT_MS),
            idle_timeout: Duration::from_millis(DEFAULT_IDLE_TIMEOUT_MS),
            http_req_per_sec: DEFAULT_HTTP_REQ_PER_SEC,
            http_max_conns_per_ip: DEFAULT_HTTP_MAX_CONNS_PER_IP,
            trusted_proxies: Vec::new(),
        }
    }
}

impl LimitsConfig {
    pub fn from_env() -> Self {
        let mut cfg = Self::default();
        if let Ok(v) = std::env::var("RELAY_MAX_CONNS_PER_IP") {
            if let Ok(parsed) = v.parse::<usize>() {
                cfg.max_conns_per_ip = parsed;
            }
        }
        if let Ok(v) = std::env::var("RELAY_ROUTE_BYTES_PER_SEC") {
            if let Ok(parsed) = v.parse::<u64>() {
                cfg.route_bytes_per_sec = parsed;
            }
        }
        if let Ok(v) = std::env::var("RELAY_ROUTE_BYTES_TOTAL") {
            if let Ok(parsed) = v.parse::<u64>() {
                cfg.route_bytes_total = parsed;
            }
        }
        if let Ok(v) = std::env::var("RELAY_HANDSHAKE_TIMEOUT_MS") {
            if let Ok(parsed) = v.parse::<u64>() {
                cfg.handshake_timeout = Duration::from_millis(parsed);
            }
        }
        if let Ok(v) = std::env::var("RELAY_PRE_HELLO_TIMEOUT_MS") {
            if let Ok(parsed) = v.parse::<u64>() {
                cfg.pre_hello_timeout = Duration::from_millis(parsed);
            }
        }
        if let Ok(v) = std::env::var("RELAY_IDLE_TIMEOUT_MS") {
            if let Ok(parsed) = v.parse::<u64>() {
                cfg.idle_timeout = Duration::from_millis(parsed);
            }
        }
        if let Ok(v) = std::env::var("RELAY_HTTP_REQ_PER_SEC") {
            if let Ok(parsed) = v.parse::<u32>() {
                cfg.http_req_per_sec = parsed;
            }
        }
        if let Ok(v) = std::env::var("RELAY_HTTP_MAX_CONNS_PER_IP") {
            if let Ok(parsed) = v.parse::<usize>() {
                cfg.http_max_conns_per_ip = parsed;
            }
        }
        if let Ok(v) = std::env::var("RELAY_TRUSTED_PROXY") {
            cfg.trusted_proxies = v
                .split(',')
                .filter_map(|item| item.trim().parse::<IpAddr>().ok())
                .map(canonical_ip)
                .collect();
        }
        cfg
    }
}

#[derive(Debug, Clone, Copy)]
pub(crate) struct PeerAddr(pub Option<IpAddr>);

impl<S: Send + Sync> FromRequestParts<S> for PeerAddr {
    type Rejection = std::convert::Infallible;

    async fn from_request_parts(parts: &mut Parts, _state: &S) -> Result<Self, Self::Rejection> {
        let ip = parts
            .extensions
            .get::<ConnectInfo<SocketAddr>>()
            .map(|ci| ci.0.ip());
        Ok(PeerAddr(ip))
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ChargeOutcome {
    Allow,
    Backpressure(Duration),
    ExceededTotal,
}

struct RouteQuota {
    bytes_total: u64,
    tokens: f64,
    last_refill: Instant,
    active_conns: usize,
}

struct HttpIpBucket {
    tokens: f64,
    last_refill: Instant,
    active: usize,
}

#[derive(Default)]
struct LimitsInner {
    ip_conns: HashMap<IpAddr, usize>,
    http_ips: HashMap<IpAddr, HttpIpBucket>,
    routes: HashMap<(String, String), RouteQuota>,
}

pub(crate) struct Limits {
    config: LimitsConfig,
    inner: Mutex<LimitsInner>,
}

impl Limits {
    pub(crate) fn new(config: LimitsConfig) -> Arc<Self> {
        Arc::new(Self {
            config,
            inner: Mutex::new(LimitsInner::default()),
        })
    }

    pub(crate) fn handshake_timeout(&self) -> Duration {
        self.config.handshake_timeout
    }

    pub(crate) fn pre_hello_timeout(&self) -> Duration {
        self.config.pre_hello_timeout
    }

    pub(crate) fn idle_timeout(&self) -> Duration {
        self.config.idle_timeout
    }

    pub(crate) fn resolve_client_ip(&self, peer: Option<IpAddr>, headers: &HeaderMap) -> IpAddr {
        let tcp_ip = peer
            .map(canonical_ip)
            .unwrap_or(IpAddr::V4(Ipv4Addr::UNSPECIFIED));
        let is_trusted = |ip: IpAddr| {
            let ip = canonical_ip(ip);
            self.config
                .trusted_proxies
                .iter()
                .any(|proxy| canonical_ip(*proxy) == ip)
        };
        if !is_trusted(tcp_ip) {
            return tcp_ip;
        }
        if let Some(xff) = headers.get("x-forwarded-for").and_then(|v| v.to_str().ok()) {
            let mut last_valid = None;
            for part in xff.rsplit(',') {
                let Ok(parsed) = part.trim().parse::<IpAddr>() else {
                    break;
                };
                let ip = canonical_ip(parsed);
                last_valid = Some(ip);
                if !is_trusted(ip) {
                    return ip;
                }
            }
            if let Some(ip) = last_valid {
                return ip;
            }
        }
        tcp_ip
    }

    pub(crate) fn try_acquire_ip(
        self: &Arc<Self>,
        peer: Option<IpAddr>,
        headers: &HeaderMap,
    ) -> Option<SharedIpPermit> {
        if self.config.max_conns_per_ip == 0 {
            return None;
        }
        let ip = self.resolve_client_ip(peer, headers);
        let mut inner = self
            .inner
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let count = inner.ip_conns.entry(ip).or_insert(0);
        if *count >= self.config.max_conns_per_ip {
            if *count == 0 {
                inner.ip_conns.remove(&ip);
            }
            return None;
        }
        *count += 1;
        Some(SharedIpPermit::new(IpPermit {
            limits: Arc::clone(self),
            ip,
        }))
    }

    pub(crate) fn try_acquire_http(
        self: &Arc<Self>,
        peer: Option<IpAddr>,
        headers: &HeaderMap,
    ) -> Option<HttpPermit> {
        if self.config.http_max_conns_per_ip == 0 {
            return None;
        }
        let ip = self.resolve_client_ip(peer, headers);
        let now = Instant::now();
        let mut inner = self
            .inner
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());

        if inner.http_ips.len() > 4096 {
            inner.http_ips.retain(|_, b| {
                b.active > 0 || now.duration_since(b.last_refill) < Duration::from_secs(60)
            });
        }
        if !inner.http_ips.contains_key(&ip) && inner.http_ips.len() >= MAX_HTTP_TRACKED_IPS {
            return None;
        }

        let rate = self.config.http_req_per_sec as f64;
        let burst = (rate * 2.0).max(10.0);
        let bucket = inner.http_ips.entry(ip).or_insert_with(|| HttpIpBucket {
            tokens: burst,
            last_refill: now,
            active: 0,
        });

        if bucket.active >= self.config.http_max_conns_per_ip {
            return None;
        }

        if self.config.http_req_per_sec > 0 {
            let elapsed = now.duration_since(bucket.last_refill).as_secs_f64();
            bucket.last_refill = now;
            bucket.tokens = (bucket.tokens + elapsed * rate).min(burst);
            if bucket.tokens < 1.0 {
                return None;
            }
            bucket.tokens -= 1.0;
        }

        bucket.active += 1;
        Some(HttpPermit {
            limits: Arc::clone(self),
            ip,
        })
    }

    pub(crate) fn attach_route(self: &Arc<Self>, host: &str, sid: &str) -> RouteLimitGuard {
        let key = (host.to_owned(), sid.to_owned());
        let burst = burst_bytes(self.config.route_bytes_per_sec);
        {
            let mut inner = self
                .inner
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            let quota = inner
                .routes
                .entry(key.clone())
                .or_insert_with(|| RouteQuota {
                    bytes_total: 0,
                    tokens: burst,
                    last_refill: Instant::now(),
                    active_conns: 0,
                });
            quota.active_conns += 1;
        }
        RouteLimitGuard {
            limits: Arc::clone(self),
            key,
        }
    }

    pub(crate) fn charge_route(&self, host: &str, sid: &str, len: usize) -> ChargeOutcome {
        let key = (host.to_owned(), sid.to_owned());
        let mut inner = self
            .inner
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let burst = burst_bytes(self.config.route_bytes_per_sec);
        let now = Instant::now();
        let quota = inner.routes.entry(key).or_insert_with(|| RouteQuota {
            bytes_total: 0,
            tokens: burst,
            last_refill: now,
            active_conns: 0,
        });

        quota.bytes_total = quota.bytes_total.saturating_add(len as u64);
        if quota.bytes_total > self.config.route_bytes_total {
            return ChargeOutcome::ExceededTotal;
        }

        if self.config.route_bytes_per_sec == 0 {
            return ChargeOutcome::Allow;
        }

        let rate = self.config.route_bytes_per_sec as f64;
        let elapsed = now.duration_since(quota.last_refill).as_secs_f64();
        quota.last_refill = now;
        quota.tokens = (quota.tokens + elapsed * rate).min(burst);
        quota.tokens -= len as f64;

        if quota.tokens < 0.0 {
            let wait_secs = (-quota.tokens) / rate;
            ChargeOutcome::Backpressure(Duration::from_secs_f64(wait_secs))
        } else {
            ChargeOutcome::Allow
        }
    }

    fn release_ip(&self, ip: IpAddr) {
        let mut inner = self
            .inner
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if let Some(count) = inner.ip_conns.get_mut(&ip) {
            *count = count.saturating_sub(1);
            if *count == 0 {
                inner.ip_conns.remove(&ip);
            }
        }
    }

    fn release_http_ip(&self, ip: IpAddr) {
        let mut inner = self
            .inner
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if let Some(bucket) = inner.http_ips.get_mut(&ip) {
            bucket.active = bucket.active.saturating_sub(1);
        }
    }

    fn detach_route(&self, key: &(String, String)) {
        let mut inner = self
            .inner
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if let Some(quota) = inner.routes.get_mut(key) {
            quota.active_conns = quota.active_conns.saturating_sub(1);
            if quota.active_conns == 0 {
                inner.routes.remove(key);
            }
        }
    }
}

pub(crate) struct IpPermit {
    limits: Arc<Limits>,
    ip: IpAddr,
}

impl Drop for IpPermit {
    fn drop(&mut self) {
        self.limits.release_ip(self.ip);
    }
}

pub(crate) struct HttpPermit {
    limits: Arc<Limits>,
    ip: IpAddr,
}

impl Drop for HttpPermit {
    fn drop(&mut self) {
        self.limits.release_http_ip(self.ip);
    }
}

#[derive(Clone)]
pub(crate) struct SharedIpPermit(Arc<Mutex<Option<IpPermit>>>);

impl SharedIpPermit {
    fn new(permit: IpPermit) -> Self {
        Self(Arc::new(Mutex::new(Some(permit))))
    }

    pub(crate) fn release(&self) {
        let _ = self
            .0
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .take();
    }
}

pub(crate) struct RouteLimitGuard {
    limits: Arc<Limits>,
    key: (String, String),
}

impl Drop for RouteLimitGuard {
    fn drop(&mut self) {
        self.limits.detach_route(&self.key);
    }
}

#[derive(Default)]
pub(crate) struct HandshakeWatch {
    satisfied: AtomicBool,
    notify: Notify,
}

impl HandshakeWatch {
    pub(crate) fn new() -> Arc<Self> {
        Arc::new(Self::default())
    }

    pub(crate) fn satisfy(&self) {
        if !self.satisfied.swap(true, Ordering::Release) {
            self.notify.notify_waiters();
        }
    }

    pub(crate) fn is_satisfied(&self) -> bool {
        self.satisfied.load(Ordering::Acquire)
    }

    pub(crate) fn notified(&self) -> tokio::sync::futures::Notified<'_> {
        self.notify.notified()
    }
}

fn burst_bytes(rate: u64) -> f64 {
    ((rate as f64) * 0.05).max(1.0)
}

fn canonical_ip(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V6(v6) => v6
            .to_ipv4_mapped()
            .map(IpAddr::V4)
            .unwrap_or(IpAddr::V6(v6)),
        v4 => v4,
    }
}
