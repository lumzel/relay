// lumzel:remote-link#relay-inbox lumzel:remote-link#r-host lumzel:remote-link#p-register lumzel:remote-link#p-notify lumzel:remote-link-03#m-inbox lumzel:remote-link-03#a-challenge lumzel:remote-link-03#a-register lumzel:remote-link-03#a-waiting
//! `/host` inbox WebSocket. A Host proves possession of the X25519 private key behind
//! its `host_id` once here, stays connected to receive `waiting` notifications when
//! peers arrive, and gets a single-use 30s ticket per notification to claim the Host
//! slot on `/control` or `/data`.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use axum::extract::ws::{CloseFrame, Message, WebSocket};
use axum::extract::{State, WebSocketUpgrade};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use futures_util::{SinkExt, StreamExt};
use lumzel_frame::proof::{self, Challenge};
use lumzel_frame::{host_id, PublicKey, StaticSecret};
use rand::rngs::OsRng;
use rand::RngCore;
use serde_json::{json, Value};
use tokio::sync::{mpsc, Notify};
use tokio::time::Instant;

use crate::limits::{PeerAddr, SharedIpPermit};
use crate::ops::AppState;
use crate::routes::Plane;

const REGISTER_TIMEOUT: Duration = Duration::from_secs(5);
const TICKET_TTL: Duration = Duration::from_secs(30);
const MAX_TICKETS: usize = 4096;

#[derive(Debug)]
pub(crate) enum HttpDispatchError {
    NotFound,
    Unavailable,
}

#[derive(Debug, Clone)]
pub(crate) struct ProxiedHttpRes {
    pub id: u64,
    pub status: u16,
    pub headers: HashMap<String, String>,
    pub body: String,
}

struct HostEntry {
    seq: u64,
    bot: bool,
    tx: mpsc::UnboundedSender<String>,
    evict: Arc<Notify>,
}

struct TicketEntry {
    host: String,
    sid: String,
    plane: Plane,
    expires_at: Instant,
}

#[derive(Default)]
pub(crate) struct InboxRegistry {
    next_seq: u64,
    next_http_id: u64,
    hosts: HashMap<String, HostEntry>,
    tickets: HashMap<String, TicketEntry>,
    pending_http: HashMap<u64, tokio::sync::oneshot::Sender<ProxiedHttpRes>>,
}

impl InboxRegistry {
    pub(crate) fn is_registered(&self, host: &str) -> bool {
        self.hosts.contains_key(host)
    }

    pub(crate) fn is_bot_enabled(&self, host: &str) -> bool {
        self.hosts.get(host).is_some_and(|h| h.bot)
    }

    pub(crate) fn register(
        &mut self,
        host: String,
        bot: bool,
        tx: mpsc::UnboundedSender<String>,
        evict: Arc<Notify>,
    ) -> u64 {
        self.next_seq = self.next_seq.saturating_add(1);
        let seq = self.next_seq;
        if let Some(previous) = self.hosts.insert(
            host,
            HostEntry {
                seq,
                bot,
                tx,
                evict,
            },
        ) {
            previous.evict.notify_one();
        }
        seq
    }

    pub(crate) fn send_http_req(
        &mut self,
        host: &str,
        method: String,
        path: String,
        query: String,
        headers: HashMap<String, String>,
        body: String,
    ) -> Result<(u64, tokio::sync::oneshot::Receiver<ProxiedHttpRes>), HttpDispatchError> {
        let entry = self.hosts.get(host).ok_or(HttpDispatchError::NotFound)?;
        if !entry.bot {
            return Err(HttpDispatchError::NotFound);
        }
        self.next_http_id = self.next_http_id.saturating_add(1);
        let id = self.next_http_id;
        let (tx, rx) = tokio::sync::oneshot::channel();
        self.pending_http.insert(id, tx);

        let payload = json!({
            "t": "http",
            "id": id,
            "method": method,
            "path": path,
            "query": query,
            "headers": headers,
            "body": body,
        })
        .to_string();

        if entry.tx.send(payload).is_err() {
            self.pending_http.remove(&id);
            return Err(HttpDispatchError::Unavailable);
        }

        Ok((id, rx))
    }

    pub(crate) fn resolve_http_res(&mut self, res: ProxiedHttpRes) {
        if let Some(tx) = self.pending_http.remove(&res.id) {
            let _ = tx.send(res);
        }
    }

    pub(crate) fn cancel_http_req(&mut self, id: u64) {
        self.pending_http.remove(&id);
    }

    pub(crate) fn unregister(&mut self, host: &str, seq: u64) {
        if self.hosts.get(host).is_some_and(|entry| entry.seq == seq) {
            self.hosts.remove(host);
            self.pending_http.clear();
        }
    }

    pub(crate) fn notify_waiting(&mut self, host: &str, sid: &str, plane: Plane) -> bool {
        let now = Instant::now();
        self.prune_expired(now);
        if !self.hosts.contains_key(host) {
            return false;
        }
        if self.tickets.len() >= MAX_TICKETS {
            if let Some(oldest) = self
                .tickets
                .iter()
                .min_by_key(|(_, entry)| entry.expires_at)
                .map(|(k, _)| k.clone())
            {
                self.tickets.remove(&oldest);
            }
        }
        let mut raw = [0u8; 16];
        OsRng.fill_bytes(&mut raw);
        let ticket = B64.encode(raw);
        let payload = json!({
            "t": "waiting",
            "sid": sid,
            "plane": plane.as_str(),
            "ticket": ticket,
        })
        .to_string();
        let sent = self
            .hosts
            .get(host)
            .is_some_and(|entry| entry.tx.send(payload).is_ok());
        if sent {
            self.tickets.insert(
                ticket,
                TicketEntry {
                    host: host.to_owned(),
                    sid: sid.to_owned(),
                    plane,
                    expires_at: now + TICKET_TTL,
                },
            );
        }
        sent
    }

    pub(crate) fn consume_ticket(
        &mut self,
        ticket: &str,
        host: &str,
        sid: &str,
        plane: Plane,
    ) -> bool {
        let now = Instant::now();
        self.prune_expired(now);
        let valid = self.tickets.get(ticket).is_some_and(|entry| {
            entry.expires_at > now && entry.host == host && entry.sid == sid && entry.plane == plane
        });
        if !valid {
            return false;
        }
        self.tickets.remove(ticket);
        true
    }

    fn prune_expired(&mut self, now: Instant) {
        self.tickets.retain(|_, entry| entry.expires_at > now);
    }
}

pub async fn ws(
    ws: WebSocketUpgrade,
    State(state): State<AppState>,
    peer: PeerAddr,
    headers: HeaderMap,
) -> Response {
    if state.lock().reserve().is_err() {
        return StatusCode::SERVICE_UNAVAILABLE.into_response();
    }
    let Some(ip_permit) = state.limits().try_acquire_ip(peer.0, &headers) else {
        state.lock().unreserve();
        return StatusCode::TOO_MANY_REQUESTS.into_response();
    };
    let failed = state.clone();
    let failed_ip = ip_permit.clone();
    ws.on_failed_upgrade(move |_| {
        failed_ip.release();
        failed.lock().unreserve();
    })
    .on_upgrade(move |socket| run_inbox(socket, state, ip_permit))
}

struct InboxGuard {
    state: AppState,
    ip_permit: SharedIpPermit,
    registered: Option<(String, u64)>,
}

impl Drop for InboxGuard {
    fn drop(&mut self) {
        if let Some((host, seq)) = self.registered.take() {
            self.state.inbox_lock().unregister(&host, seq);
        }
        self.ip_permit.release();
        self.state.lock().unreserve();
    }
}

async fn run_inbox(mut socket: WebSocket, state: AppState, ip_permit: SharedIpPermit) {
    let mut guard = InboxGuard {
        state: state.clone(),
        ip_permit,
        registered: None,
    };

    let (relay_secret, challenge) = proof::challenge();
    let challenge_msg = json!({
        "t": "challenge",
        "key": B64.encode(challenge.key.to_bytes()),
        "nonce": B64.encode(challenge.nonce),
    })
    .to_string();

    if socket
        .send(Message::Text(challenge_msg.into()))
        .await
        .is_err()
    {
        return;
    }

    let register_text =
        match tokio::time::timeout(REGISTER_TIMEOUT, recv_register(&mut socket)).await {
            Ok(Some(Ok(text))) => text,
            Ok(Some(Err(()))) => {
                close_with(&mut socket, 4401, "unauthorized").await;
                return;
            }
            Ok(None) => return,
            Err(_) => {
                let _ = socket.send(Message::Close(None)).await;
                let _ = socket.close().await;
                return;
            }
        };

    let Ok((registered_host, bot)) = verify_register(&register_text, &relay_secret, &challenge)
    else {
        close_with(&mut socket, 4401, "unauthorized").await;
        return;
    };

    let (tx, mut rx) = mpsc::unbounded_channel::<String>();
    let evict = Arc::new(Notify::new());
    let seq = state
        .inbox_lock()
        .register(registered_host.clone(), bot, tx, Arc::clone(&evict));
    guard.registered = Some((registered_host.clone(), seq));

    let ack = json!({
        "t": "registered",
        "host": registered_host,
    })
    .to_string();
    if socket.send(Message::Text(ack.into())).await.is_err() {
        return;
    }

    loop {
        tokio::select! {
            biased;
            _ = evict.notified() => {
                let _ = socket.send(Message::Close(None)).await;
                let _ = socket.close().await;
                break;
            }
            outbound = rx.recv() => {
                match outbound {
                    Some(text) => {
                        if socket.send(Message::Text(text.into())).await.is_err() {
                            break;
                        }
                    }
                    None => break,
                }
            }
            incoming = socket.next() => {
                match incoming {
                    Some(Ok(Message::Text(text))) => {
                        if let Ok(val) = serde_json::from_str::<Value>(&text) {
                            if val.get("t").and_then(Value::as_str) == Some("http_res") {
                                if let (Some(id), Some(status)) = (
                                    val.get("id").and_then(Value::as_u64),
                                    val.get("status").and_then(Value::as_u64),
                                ) {
                                    let mut headers = HashMap::new();
                                    if let Some(obj) = val.get("headers").and_then(Value::as_object) {
                                        for (k, v) in obj {
                                            if let Some(s) = v.as_str() {
                                                headers.insert(k.to_ascii_lowercase(), s.to_owned());
                                            }
                                        }
                                    }
                                    let body = val.get("body").and_then(Value::as_str).unwrap_or("").to_owned();
                                    state.inbox_lock().resolve_http_res(ProxiedHttpRes {
                                        id,
                                        status: status as u16,
                                        headers,
                                        body,
                                    });
                                }
                            }
                        }
                    }
                    Some(Ok(Message::Ping(payload))) => {
                        if socket.send(Message::Pong(payload)).await.is_err() {
                            break;
                        }
                    }
                    Some(Ok(Message::Pong(_))) => {}
                    _ => break,
                }
            }
        }
    }
}

async fn recv_register(socket: &mut WebSocket) -> Option<Result<String, ()>> {
    while let Some(next) = socket.next().await {
        match next {
            Ok(Message::Text(text)) => return Some(Ok(text.to_string())),
            Ok(Message::Ping(payload)) => {
                if socket.send(Message::Pong(payload)).await.is_err() {
                    return None;
                }
            }
            Ok(Message::Pong(_)) => {}
            Ok(Message::Binary(_)) => return Some(Err(())),
            Ok(Message::Close(_)) | Err(_) => return None,
        }
    }
    None
}

fn verify_register(
    text: &str,
    relay_secret: &StaticSecret,
    challenge: &Challenge,
) -> Result<(String, bool), ()> {
    let value: Value = serde_json::from_str(text).map_err(|_| ())?;
    if value.get("t").and_then(Value::as_str) != Some("register") {
        return Err(());
    }
    let pub_b64 = value.get("host_pub").and_then(Value::as_str).ok_or(())?;
    let proof_b64 = value.get("proof").and_then(Value::as_str).ok_or(())?;

    let pub_bytes = B64.decode(pub_b64).map_err(|_| ())?;
    let host_pub = PublicKey::from_bytes(&pub_bytes).map_err(|_| ())?;

    let proof_vec = B64.decode(proof_b64).map_err(|_| ())?;
    let proof_bytes: [u8; 32] = proof_vec.try_into().map_err(|_| ())?;

    if !proof::verify(relay_secret, challenge, &host_pub, &proof_bytes) {
        return Err(());
    }

    let derived = host_id(&host_pub);
    if let Some(claimed) = value.get("host").or_else(|| value.get("host_id")) {
        if claimed.as_str() != Some(derived.as_str()) {
            return Err(());
        }
    }
    let bot = value.get("bot").and_then(Value::as_bool).unwrap_or(false);
    Ok((derived, bot))
}

async fn close_with(socket: &mut WebSocket, code: u16, reason: &'static str) {
    let _ = socket
        .send(Message::Close(Some(CloseFrame {
            code,
            reason: reason.into(),
        })))
        .await;
    let _ = socket.close().await;
}
