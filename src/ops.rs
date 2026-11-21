// lumzel:mobile-companion#relay-ops lumzel:remote-link#relay-limits lumzel:remote-link#r-drain
//! Process liveness, admission, and drain.

use std::net::SocketAddr;

use axum::extract::{Request, State};
use axum::http::{header, HeaderMap, StatusCode};
use axum::middleware;
use axum::response::IntoResponse;
use axum::routing::{get, post};
use axum::{Json, Router};
use rand::rngs::OsRng;
use rand::RngCore;
use serde_json::json;
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;
use tokio::net::TcpListener;

use crate::auth;
use crate::control;
use crate::data;
use crate::inbox::{self, InboxRegistry};
use crate::limits::{Limits, LimitsConfig, PeerAddr};
use crate::push::{self, PushError, Sender};
use crate::routes::{Plane, RouteTable};

#[derive(Clone)]
pub struct AppState {
    table: std::sync::Arc<std::sync::Mutex<RouteTable>>,
    inbox: std::sync::Arc<std::sync::Mutex<InboxRegistry>>,
    limits: std::sync::Arc<Limits>,
    password_hash: Option<std::sync::Arc<[u8; 32]>>,
    ops_token: Option<std::sync::Arc<str>>,
    push_token: Option<std::sync::Arc<str>>,
    push: Sender,
    openai_apps_challenge: Option<std::sync::Arc<str>>,
    public_url: Option<std::sync::Arc<str>>,
    stun_public_addrs: std::sync::Arc<Vec<String>>,
    stun_cn_addrs: std::sync::Arc<Vec<String>>,
    stun_local_ports: std::sync::Arc<Vec<u16>>,
    dcr_secret: std::sync::Arc<[u8; 32]>,
    short_codes: std::sync::Arc<std::sync::Mutex<crate::shortcode::ShortCodes>>,
}

impl std::fmt::Debug for AppState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AppState")
            .field("password_protected", &self.password_hash.is_some())
            .field("ops_token_set", &self.ops_token.is_some())
            .field("push_token_set", &self.push_token.is_some())
            .field("public_url", &self.public_url)
            .field("stun_public_addrs", &self.stun_public_addrs)
            .field("stun_cn_addrs", &self.stun_cn_addrs)
            .finish()
    }
}

pub fn parse_stun_list(raw: &str) -> Vec<String> {
    raw.split(',')
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(ToOwned::to_owned)
        .collect()
}

impl AppState {
    pub fn new(node_id: impl Into<String>, max_conns: usize) -> Self {
        let mut dcr_secret = [0u8; 32];
        OsRng.fill_bytes(&mut dcr_secret);
        Self {
            table: std::sync::Arc::new(std::sync::Mutex::new(RouteTable::new(node_id, max_conns))),
            inbox: std::sync::Arc::new(std::sync::Mutex::new(InboxRegistry::default())),
            limits: Limits::new(LimitsConfig::default()),
            password_hash: None,
            ops_token: None,
            push_token: None,
            push: Sender::unavailable(),
            openai_apps_challenge: None,
            public_url: None,
            stun_public_addrs: std::sync::Arc::new(Vec::new()),
            stun_cn_addrs: std::sync::Arc::new(Vec::new()),
            stun_local_ports: std::sync::Arc::new(Vec::new()),
            dcr_secret: std::sync::Arc::new(dcr_secret),
            short_codes: Default::default(),
        }
    }

    // lumzel:remote-link-03#a-limits
    pub fn from_env() -> Self {
        let node = std::env::var("RELAY_NODE_ID").unwrap_or_else(|_| "local".into());
        let max = match std::env::var("RELAY_MAX_CONNS") {
            Ok(value) => value.parse::<usize>().unwrap_or(1024),
            Err(_) => 1024,
        };
        let mut state = Self::new(node, max).with_limits(LimitsConfig::from_env());
        if let Some(password) = auth::password_from_env() {
            state = state.with_password(password);
        }
        if let Ok(token) = std::env::var("RELAY_OPS_TOKEN") {
            if !token.is_empty() {
                state.ops_token = Some(std::sync::Arc::from(token));
            }
        }
        state.push_token = match std::env::var("RELAY_PUSH_TOKEN") {
            Ok(token) if !token.is_empty() => Some(std::sync::Arc::from(token)),
            _ => state.ops_token.clone(),
        };
        if state.push_token.is_some() {
            state.push = Sender::from_env();
        }
        if let Ok(challenge) = std::env::var("RELAY_OPENAI_APPS_CHALLENGE") {
            if !challenge.is_empty() {
                state.openai_apps_challenge = Some(std::sync::Arc::from(challenge));
            }
        }
        if let Ok(public_url) = std::env::var("RELAY_PUBLIC_URL") {
            let trimmed = public_url.trim().trim_end_matches('/');
            if !trimmed.is_empty() {
                state.public_url = Some(std::sync::Arc::from(trimmed));
            }
        }
        if let Ok(secret) = std::env::var("RELAY_DCR_SECRET") {
            if !secret.is_empty() {
                let digest: [u8; 32] = Sha256::digest(secret.as_bytes()).into();
                state.dcr_secret = std::sync::Arc::new(digest);
            }
        }
        if let Ok(raw) = std::env::var("RELAY_STUN_PUBLIC_ADDRS") {
            let addrs = parse_stun_list(&raw);
            if !addrs.is_empty() {
                state = state.with_stun_public_addrs(addrs);
            }
        }
        if let Ok(raw) = std::env::var("RELAY_STUN_CN_ADDRS") {
            let addrs = parse_stun_list(&raw);
            if !addrs.is_empty() {
                state = state.with_stun_cn_addrs(addrs);
            }
        }
        state
    }

    pub fn with_password(mut self, password: impl AsRef<str>) -> Self {
        let raw = password.as_ref();
        self.password_hash = if raw.is_empty() {
            None
        } else {
            Some(std::sync::Arc::new(auth::hash_password(raw)))
        };
        self
    }

    pub fn is_password_protected(&self) -> bool {
        self.password_hash.is_some()
    }

    pub(crate) fn password_hash(&self) -> Option<&[u8; 32]> {
        self.password_hash.as_deref()
    }

    pub fn with_openai_apps_challenge(mut self, token: impl Into<String>) -> Self {
        let token = token.into();
        self.openai_apps_challenge = if token.is_empty() {
            None
        } else {
            Some(std::sync::Arc::from(token))
        };
        self
    }

    pub fn with_public_url(mut self, url: impl Into<String>) -> Self {
        let trimmed = url.into().trim().trim_end_matches('/').to_owned();
        self.public_url = if trimmed.is_empty() {
            None
        } else {
            Some(std::sync::Arc::from(trimmed))
        };
        self
    }

    pub fn with_stun_public_addrs(mut self, addrs: Vec<String>) -> Self {
        self.stun_public_addrs = std::sync::Arc::new(addrs);
        self
    }

    pub fn with_stun_cn_addrs(mut self, addrs: Vec<String>) -> Self {
        self.stun_cn_addrs = std::sync::Arc::new(addrs);
        self
    }

    pub fn with_stun_local_ports(mut self, ports: Vec<u16>) -> Self {
        self.stun_local_ports = std::sync::Arc::new(ports);
        self
    }

    /// Order advertised STUN addresses by `CF-IPCountry`: `CN` requests get
    /// `stun_cn_addrs` first with `stun_public_addrs` as fallback, and other
    /// requests get `stun_public_addrs` first with `stun_cn_addrs` as fallback.
    /// Falls back to the request `Host` with `stun_local_ports` when no explicit
    /// STUN addresses are configured.
    pub fn stun_addrs_for_headers(&self, headers: &HeaderMap) -> Vec<String> {
        let is_cn = headers
            .get("cf-ipcountry")
            .and_then(|v| v.to_str().ok())
            .is_some_and(|v| v.trim().eq_ignore_ascii_case("CN"));
        let (primary, fallback) = if is_cn {
            (&self.stun_cn_addrs, &self.stun_public_addrs)
        } else {
            (&self.stun_public_addrs, &self.stun_cn_addrs)
        };
        let mut out = Vec::with_capacity(primary.len() + fallback.len());
        for addr in primary.iter().chain(fallback.iter()) {
            if !out.contains(addr) {
                out.push(addr.clone());
            }
        }
        if out.is_empty() && !self.stun_local_ports.is_empty() {
            if let Some(host) = headers
                .get(header::HOST)
                .and_then(|v| v.to_str().ok())
                .and_then(|raw| raw.parse::<axum::http::uri::Authority>().ok())
                .map(|auth| auth.host().to_owned())
            {
                let formatted_host = if host.contains(':') {
                    format!("[{host}]")
                } else {
                    host
                };
                for &port in self.stun_local_ports.iter() {
                    out.push(format!("{formatted_host}:{port}"));
                }
            }
        }
        out
    }

    pub(crate) fn openai_apps_challenge(&self) -> Option<&str> {
        self.openai_apps_challenge.as_deref()
    }

    pub(crate) fn public_url(&self) -> Option<&str> {
        self.public_url.as_deref()
    }

    pub(crate) fn dcr_secret(&self) -> &[u8; 32] {
        &self.dcr_secret
    }

    pub fn with_limits(mut self, config: LimitsConfig) -> Self {
        self.limits = Limits::new(config);
        self
    }

    pub fn with_ops_token(mut self, token: impl Into<String>) -> Self {
        let token = token.into();
        self.ops_token = if token.is_empty() {
            None
        } else {
            Some(std::sync::Arc::from(token))
        };
        self
    }

    pub fn with_push_token(mut self, token: impl Into<String>) -> Self {
        let token = token.into();
        self.push_token = if token.is_empty() {
            None
        } else {
            Some(std::sync::Arc::from(token))
        };
        self
    }

    pub fn with_push_sender(mut self, sender: Sender) -> Self {
        self.push = sender;
        self
    }

    pub fn push_log(&self) -> String {
        self.push.recorded()
    }

    pub(crate) fn short_codes(&self) -> std::sync::MutexGuard<'_, crate::shortcode::ShortCodes> {
        self.short_codes
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    pub(crate) fn lock(&self) -> std::sync::MutexGuard<'_, RouteTable> {
        self.table
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    pub(crate) fn inbox_lock(&self) -> std::sync::MutexGuard<'_, InboxRegistry> {
        self.inbox
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    pub(crate) fn limits(&self) -> &std::sync::Arc<Limits> {
        &self.limits
    }

    pub fn connection_count(&self, host: &str, sid: &str, plane: Plane) -> usize {
        self.lock().connection_count(host, sid, plane)
    }

    pub fn route_count(&self) -> usize {
        self.lock().route_count()
    }

    pub fn owner_count(&self) -> usize {
        self.lock().owner_count()
    }

    pub fn punch_addr(&self, host: &str, sid: &str) -> Option<String> {
        self.lock().punch_addr(host, sid)
    }

    pub(crate) fn bot_host_status(&self, host: &str) -> crate::inbox::BotHostStatus {
        self.inbox_lock().bot_host_status(host)
    }

    pub(crate) fn dispatch_http(
        &self,
        host: &str,
        method: String,
        path: String,
        query: String,
        headers: std::collections::HashMap<String, String>,
        body: String,
    ) -> Result<
        (u64, tokio::sync::oneshot::Receiver<inbox::ProxiedHttpRes>),
        inbox::HttpDispatchError,
    > {
        self.inbox_lock()
            .send_http_req(host, method, path, query, headers, body)
    }

    pub(crate) fn cancel_http(&self, id: u64) {
        self.inbox_lock().cancel_http_req(id);
    }
}

pub fn router(state: AppState) -> Router {
    let protected = Router::new()
        .route("/push/wake", post(push_wake))
        .route("/host", get(inbox::ws))
        .route("/control", get(control::ws))
        .route("/data", get(data::ws))
        .merge(crate::bot::router())
        .merge(crate::shortcode::router())
        .fallback(|| async { StatusCode::NOT_FOUND })
        .layer(middleware::from_fn_with_state(
            state.clone(),
            auth::require_password,
        ));

    Router::new()
        .route("/health", get(health))
        .route("/healthz", get(health))
        .route("/ready", get(ready))
        .route("/drain", post(drain))
        .merge(protected)
        .with_state(state)
}

pub async fn serve(listener: TcpListener, state: AppState) -> std::io::Result<()> {
    axum::serve(
        listener,
        router(state).into_make_service_with_connect_info::<SocketAddr>(),
    )
    .await
}

// Process liveness and optional region-aware STUN advertisement.
async fn health(State(state): State<AppState>, headers: HeaderMap) -> Json<serde_json::Value> {
    let stun_addrs = state.stun_addrs_for_headers(&headers);
    if stun_addrs.is_empty() {
        Json(json!({"ok": true}))
    } else {
        Json(json!({"ok": true, "stun_addrs": stun_addrs}))
    }
}

async fn ready(State(state): State<AppState>) -> impl IntoResponse {
    if state.lock().ready() {
        (StatusCode::OK, Json(json!({"ok": true})))
    } else {
        (StatusCode::SERVICE_UNAVAILABLE, Json(json!({"ok": false})))
    }
}

fn bearer_matches(headers: &HeaderMap, expected: &str) -> bool {
    let Some(raw) = headers
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
    else {
        return false;
    };
    let Some(provided) = raw.strip_prefix("Bearer ") else {
        return false;
    };
    let got_digest = Sha256::digest(provided.as_bytes());
    let want_digest = Sha256::digest(expected.as_bytes());
    bool::from(got_digest.as_slice().ct_eq(want_digest.as_slice()))
}

// lumzel:remote-link#r-drain lumzel:remote-link-03#m-drain lumzel:remote-link-03#a-drain
async fn drain(State(state): State<AppState>, headers: HeaderMap) -> StatusCode {
    let Some(expected) = state.ops_token.as_deref() else {
        return StatusCode::NOT_FOUND;
    };
    if !bearer_matches(&headers, expected) {
        return StatusCode::UNAUTHORIZED;
    }
    state.lock().drain();
    StatusCode::NO_CONTENT
}

async fn push_wake(State(state): State<AppState>, peer: PeerAddr, req: Request) -> StatusCode {
    if let Some(expected) = state.push_token.as_deref() {
        if !bearer_matches(req.headers(), expected) {
            return StatusCode::UNAUTHORIZED;
        }
    }
    if state
        .limits()
        .try_acquire_http(peer.0, req.headers())
        .is_none()
    {
        return StatusCode::TOO_MANY_REQUESTS;
    }
    let Ok(body) = axum::body::to_bytes(req.into_body(), push::MAX_WAKE_PAYLOAD + 1).await else {
        return StatusCode::BAD_REQUEST;
    };
    match push::accept(&state.push, &body) {
        Ok(()) => StatusCode::NO_CONTENT,
        Err(PushError::Unavailable) => StatusCode::NOT_FOUND,
        Err(PushError::BadPayload) => StatusCode::BAD_REQUEST,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::HeaderValue;

    #[test]
    fn stun_addrs_prioritize_cf_country_with_deduped_fallback() {
        let state = AppState::new("n", 8)
            .with_stun_public_addrs(vec![
                "global1.example.com:3478".into(),
                "shared.example.com:3478".into(),
            ])
            .with_stun_cn_addrs(vec![
                "cn1.example.com:3478".into(),
                "shared.example.com:3478".into(),
            ]);

        let empty_headers = HeaderMap::new();
        assert_eq!(
            state.stun_addrs_for_headers(&empty_headers),
            vec![
                "global1.example.com:3478",
                "shared.example.com:3478",
                "cn1.example.com:3478",
            ]
        );

        let mut cn_headers = HeaderMap::new();
        cn_headers.insert("CF-IPCountry", HeaderValue::from_static("cn"));
        assert_eq!(
            state.stun_addrs_for_headers(&cn_headers),
            vec![
                "cn1.example.com:3478",
                "shared.example.com:3478",
                "global1.example.com:3478",
            ]
        );

        let mut us_headers = HeaderMap::new();
        us_headers.insert("CF-IPCountry", HeaderValue::from_static("US"));
        assert_eq!(
            state.stun_addrs_for_headers(&us_headers),
            vec![
                "global1.example.com:3478",
                "shared.example.com:3478",
                "cn1.example.com:3478",
            ]
        );
    }

    #[test]
    fn stun_addrs_empty_when_unconfigured() {
        let state = AppState::new("n", 8);
        assert!(state.stun_addrs_for_headers(&HeaderMap::new()).is_empty());
    }

    #[test]
    fn stun_addrs_fall_back_to_request_host_with_local_ports() {
        let state = AppState::new("n", 8).with_stun_local_ports(vec![3478, 3479]);
        let mut headers = HeaderMap::new();
        headers.insert(
            header::HOST,
            HeaderValue::from_static("relay.example.com:8080"),
        );
        assert_eq!(
            state.stun_addrs_for_headers(&headers),
            vec!["relay.example.com:3478", "relay.example.com:3479"]
        );
    }
}
