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
            .finish()
    }
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

// Process liveness only.
async fn health() -> Json<serde_json::Value> {
    Json(json!({"ok": true}))
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
