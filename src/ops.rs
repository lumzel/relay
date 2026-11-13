// lumzel:mobile-companion#relay-ops lumzel:remote-link#relay-limits lumzel:remote-link#r-drain
//! Process liveness, admission, and drain.

use std::net::SocketAddr;

use axum::extract::State;
use axum::http::{header, HeaderMap, StatusCode};
use axum::response::IntoResponse;
use axum::routing::{get, post};
use axum::{Json, Router};
use serde_json::json;
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;
use tokio::net::TcpListener;

use crate::control;
use crate::data;
use crate::inbox::{self, InboxRegistry};
use crate::limits::{Limits, LimitsConfig};
use crate::push::{self, PushError, Sender};
use crate::routes::{Plane, RouteTable};

#[derive(Clone)]
pub struct AppState {
    table: std::sync::Arc<std::sync::Mutex<RouteTable>>,
    inbox: std::sync::Arc<std::sync::Mutex<InboxRegistry>>,
    limits: std::sync::Arc<Limits>,
    ops_token: Option<std::sync::Arc<str>>,
    push: Sender,
}

impl AppState {
    pub fn new(node_id: impl Into<String>, max_conns: usize) -> Self {
        Self {
            table: std::sync::Arc::new(std::sync::Mutex::new(RouteTable::new(node_id, max_conns))),
            inbox: std::sync::Arc::new(std::sync::Mutex::new(InboxRegistry::default())),
            limits: Limits::new(LimitsConfig::default()),
            ops_token: None,
            push: Sender::unavailable(),
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
        if let Ok(token) = std::env::var("RELAY_OPS_TOKEN") {
            if !token.is_empty() {
                state.ops_token = Some(std::sync::Arc::from(token));
            }
        }
        state.push = Sender::from_env();
        state
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

    pub fn with_push_sender(mut self, sender: Sender) -> Self {
        self.push = sender;
        self
    }

    pub fn push_log(&self) -> String {
        self.push.recorded()
    }

    pub(crate) fn lock(&self) -> std::sync::MutexGuard<'_, RouteTable> {
        self.table.lock().expect("route table")
    }

    pub(crate) fn inbox_lock(&self) -> std::sync::MutexGuard<'_, InboxRegistry> {
        self.inbox.lock().expect("inbox registry")
    }

    pub(crate) fn limits(&self) -> &std::sync::Arc<Limits> {
        &self.limits
    }

    pub fn connection_count(&self, host: &str, sid: &str, plane: Plane) -> usize {
        self.lock().connection_count(host, sid, plane)
    }

    pub fn punch_addr(&self, host: &str, sid: &str) -> Option<String> {
        self.lock().punch_addr(host, sid)
    }

    pub(crate) fn is_bot_enabled(&self, host: &str) -> bool {
        self.inbox_lock().is_bot_enabled(host)
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
    Router::new()
        .route("/health", get(health))
        .route("/ready", get(ready))
        .route("/drain", post(drain))
        .route("/push/wake", post(push_wake))
        .route("/host", get(inbox::ws))
        .route("/control", get(control::ws))
        .route("/data", get(data::ws))
        .merge(crate::bot::router())
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

// lumzel:remote-link#r-drain lumzel:remote-link-03#m-drain lumzel:remote-link-03#a-drain
async fn drain(State(state): State<AppState>, headers: HeaderMap) -> StatusCode {
    let Some(expected) = state.ops_token.as_deref() else {
        return StatusCode::NOT_FOUND;
    };
    let Some(raw) = headers
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
    else {
        return StatusCode::UNAUTHORIZED;
    };
    let Some(provided) = raw.strip_prefix("Bearer ") else {
        return StatusCode::UNAUTHORIZED;
    };
    let got_digest = Sha256::digest(provided.as_bytes());
    let want_digest = Sha256::digest(expected.as_bytes());
    if !bool::from(got_digest.as_slice().ct_eq(want_digest.as_slice())) {
        return StatusCode::UNAUTHORIZED;
    }
    state.lock().drain();
    StatusCode::NO_CONTENT
}

async fn push_wake(State(state): State<AppState>, body: axum::body::Bytes) -> StatusCode {
    match push::accept(&state.push, &body) {
        Ok(()) => StatusCode::NO_CONTENT,
        Err(PushError::Unavailable) => StatusCode::NOT_FOUND,
        Err(PushError::BadPayload) => StatusCode::BAD_REQUEST,
    }
}
