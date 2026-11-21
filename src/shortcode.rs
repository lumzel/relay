// lumzel:remote-link#invite
//! Short pairing codes. A Host parks its `lumzel://pair?v=2&…` invite under an 8-character
//! code (`XXXX-XXXX`) for five minutes; a Peer swaps the code for the invite exactly once.
//! The invite carries no secret the Host's pinned key does not already guard: the Peer
//! checks the Host key, and both ends compare the 6-digit SAS before anything is granted.

use std::collections::HashMap;
use std::net::IpAddr;
use std::time::{Duration, Instant};

use axum::extract::{DefaultBodyLimit, Path, State};
use axum::http::{HeaderMap, StatusCode};
use axum::routing::put;
use axum::{Json, Router};
use serde_json::{json, Value};

use crate::limits::PeerAddr;
use crate::ops::AppState;

pub const SHORT_CODE_TTL: Duration = Duration::from_secs(300);
const MAX_ENTRIES: usize = 4096;
const MAX_INVITE_LEN: usize = 1024;
const MAX_BODY_BYTES: usize = 4096;
const INVITE_PREFIX: &str = "lumzel://pair?v=2&";
/// Unknown-code lookups one client IP may fail per minute before receiving 429,
/// isolating brute-force callers so one noisy IP cannot block other users' valid codes.
const MISS_BUDGET_PER_IP_PER_MIN: u32 = 30;
const MAX_MISS_TRACKED_IPS: usize = 16_384;
const MISS_WINDOW: Duration = Duration::from_secs(60);
const ALPHABET: &str = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789";

#[derive(Default)]
pub(crate) struct ShortCodes {
    entries: HashMap<String, (String, Instant)>,
    ip_misses: HashMap<IpAddr, (Instant, u32)>,
}

pub(crate) enum PutError {
    Conflict,
    Full,
}

impl ShortCodes {
    fn prune(&mut self, now: Instant) {
        self.entries.retain(|_, (_, exp)| *exp > now);
    }

    fn prune_ip_misses(&mut self, now: Instant) {
        if self.ip_misses.len() > 2048 {
            self.ip_misses
                .retain(|_, (win, _)| now.duration_since(*win) < MISS_WINDOW);
        }
    }

    fn put(&mut self, code: String, invite: String, now: Instant) -> Result<(), PutError> {
        self.prune(now);
        if self.entries.contains_key(&code) {
            return Err(PutError::Conflict);
        }
        if self.entries.len() >= MAX_ENTRIES {
            return Err(PutError::Full);
        }
        self.entries.insert(code, (invite, now + SHORT_CODE_TTL));
        Ok(())
    }

    /// `Err(())` when `client_ip` exceeded its unknown-code budget; `Ok(None)` is a plain miss.
    fn take(&mut self, code: &str, client_ip: IpAddr, now: Instant) -> Result<Option<String>, ()> {
        self.prune_ip_misses(now);
        if let Some((win, misses)) = self.ip_misses.get_mut(&client_ip) {
            if now.duration_since(*win) >= MISS_WINDOW {
                *win = now;
                *misses = 0;
            } else if *misses >= MISS_BUDGET_PER_IP_PER_MIN {
                return Err(());
            }
        }
        self.prune(now);
        match self.entries.remove(code) {
            Some((invite, _)) => Ok(Some(invite)),
            None => {
                if !self.ip_misses.contains_key(&client_ip)
                    && self.ip_misses.len() >= MAX_MISS_TRACKED_IPS
                {
                    return Err(());
                }
                let entry = self.ip_misses.entry(client_ip).or_insert((now, 0));
                if now.duration_since(entry.0) >= MISS_WINDOW {
                    entry.0 = now;
                    entry.1 = 1;
                } else {
                    entry.1 += 1;
                }
                Ok(None)
            }
        }
    }
}

/// Canonical form `XXXX-XXXX`, or `None` when `raw` is not a short code.
pub fn normalize(raw: &str) -> Option<String> {
    let flat: String = raw
        .chars()
        .filter(|c| !c.is_whitespace() && *c != '-')
        .map(|c| c.to_ascii_uppercase())
        .collect();
    if flat.len() != 8 || !flat.chars().all(|c| ALPHABET.contains(c)) {
        return None;
    }
    Some(format!("{}-{}", &flat[..4], &flat[4..]))
}

pub(crate) fn router() -> Router<AppState> {
    Router::new()
        .route("/pair-code/{code}", put(register).get(resolve))
        .layer(DefaultBodyLimit::max(MAX_BODY_BYTES))
}

async fn register(
    State(state): State<AppState>,
    peer: PeerAddr,
    headers: HeaderMap,
    Path(code): Path<String>,
    Json(body): Json<Value>,
) -> StatusCode {
    let Some(_permit) = state.limits().try_acquire_http(peer.0, &headers) else {
        return StatusCode::TOO_MANY_REQUESTS;
    };
    let Some(code) = normalize(&code) else {
        return StatusCode::BAD_REQUEST;
    };
    let Some(invite) = body.get("invite").and_then(Value::as_str) else {
        return StatusCode::BAD_REQUEST;
    };
    if invite.len() > MAX_INVITE_LEN || !invite.starts_with(INVITE_PREFIX) {
        return StatusCode::BAD_REQUEST;
    };
    match state
        .short_codes()
        .put(code, invite.to_owned(), Instant::now())
    {
        Ok(()) => StatusCode::NO_CONTENT,
        Err(PutError::Conflict) => StatusCode::CONFLICT,
        Err(PutError::Full) => StatusCode::SERVICE_UNAVAILABLE,
    }
}

async fn resolve(
    State(state): State<AppState>,
    peer: PeerAddr,
    headers: HeaderMap,
    Path(code): Path<String>,
) -> (StatusCode, Json<Value>) {
    let Some(_permit) = state.limits().try_acquire_http(peer.0, &headers) else {
        return (StatusCode::TOO_MANY_REQUESTS, Json(json!({})));
    };
    let Some(code) = normalize(&code) else {
        return (StatusCode::BAD_REQUEST, Json(json!({})));
    };
    let client_ip = state.limits().resolve_client_ip(peer.0, &headers);
    match state.short_codes().take(&code, client_ip, Instant::now()) {
        Ok(Some(invite)) => (StatusCode::OK, Json(json!({ "invite": invite }))),
        Ok(None) => (StatusCode::NOT_FOUND, Json(json!({}))),
        Err(()) => (StatusCode::TOO_MANY_REQUESTS, Json(json!({}))),
    }
}
