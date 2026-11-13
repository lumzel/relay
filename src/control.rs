// lumzel:mobile-companion#relay-fwd lumzel:remote-link#relay-pair lumzel:remote-link#r-control lumzel:remote-link-03#m-claim lumzel:remote-link-03#a-hello
//! Control plane. `link_hello` is checked and forwarded in the clear: it names a route
//! and holds no key. Later bytes must be a v2 lumzel-frame, either a handshake message
//! (n = 0) or a sealed record. This process forwards both and decrypts neither.

use std::future::pending;
use std::pin::Pin;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use axum::extract::ws::{CloseFrame, Message, WebSocket};
use axum::extract::{State, WebSocketUpgrade};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use futures_util::{SinkExt, StreamExt};
use tokio::sync::{watch, Notify};
use tokio::time::Sleep;

use crate::handshake;
use crate::limits::{ChargeOutcome, HandshakeWatch, PeerAddr, RouteLimitGuard, SharedIpPermit};
use crate::ops::AppState;
use crate::punch;
use crate::routes::{ConnId, Outbound, Plane, RouteError, Side};

pub async fn ws(
    ws: WebSocketUpgrade,
    State(state): State<AppState>,
    peer: PeerAddr,
    headers: HeaderMap,
) -> Response {
    accept(ws, state, Plane::Control, peer, headers)
}

pub(crate) fn accept(
    ws: WebSocketUpgrade,
    state: AppState,
    plane: Plane,
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
    let task = state;
    ws.on_failed_upgrade(move |_| {
        failed_ip.release();
        failed.lock().unreserve();
    })
    .on_upgrade(move |socket| run_socket(socket, task, plane, ip_permit))
}

struct Admission {
    state: AppState,
    ip_permit: SharedIpPermit,
    id: Arc<AtomicU64>,
}

impl Drop for Admission {
    fn drop(&mut self) {
        let id = self.id.swap(0, Ordering::SeqCst);
        let mut table = self.state.lock();
        if let Some(conn) = ConnId::from_raw(id) {
            table.release(conn);
        }
        self.ip_permit.release();
        table.unreserve();
    }
}

pub(crate) async fn run_socket(
    socket: WebSocket,
    state: AppState,
    plane: Plane,
    ip_permit: SharedIpPermit,
) {
    let node_id = state.lock().node_id().to_owned();
    let id_slot = Arc::new(AtomicU64::new(0));
    let notify_slot: Arc<Mutex<Option<Arc<Notify>>>> = Arc::new(Mutex::new(None));
    let wake = Arc::new(Notify::new());
    let (writer_done_tx, mut writer_done_rx) = watch::channel(false);
    let _admission = Admission {
        state: state.clone(),
        ip_permit,
        id: Arc::clone(&id_slot),
    };
    let (mut sink, mut stream) = socket.split();
    let (local_tx, mut local_rx) = tokio::sync::mpsc::unbounded_channel::<Message>();

    let writer = {
        let state = state.clone();
        let id_slot = Arc::clone(&id_slot);
        let notify_slot = Arc::clone(&notify_slot);
        let wake = Arc::clone(&wake);
        async move {
            loop {
                if let Some(id) = ConnId::from_raw(id_slot.load(Ordering::SeqCst)) {
                    let batch = state.lock().take_outbound(id);
                    match batch {
                        None => {
                            let _ = sink.send(Message::Close(None)).await;
                            let _ = sink.close().await;
                            let _ = writer_done_tx.send(true);
                            return;
                        }
                        Some(items) if !items.is_empty() => {
                            for item in items {
                                if sink.send(outbound_message(item)).await.is_err() {
                                    let _ = writer_done_tx.send(true);
                                    return;
                                }
                            }
                            continue;
                        }
                        Some(_) => {}
                    }
                }
                let route_notify = notify_slot.lock().expect("notify").clone();
                tokio::select! {
                    biased;
                    incoming = local_rx.recv() => {
                        match incoming {
                            Some(msg) => {
                                let is_close = matches!(msg, Message::Close(_));
                                if sink.send(msg).await.is_err() || is_close {
                                    let _ = sink.close().await;
                                    let _ = writer_done_tx.send(true);
                                    return;
                                }
                            }
                            None => {
                                let _ = sink.send(Message::Close(None)).await;
                                let _ = sink.close().await;
                                let _ = writer_done_tx.send(true);
                                return;
                            }
                        }
                    }
                    _ = wait_notify(route_notify) => {}
                    _ = wake.notified() => {}
                }
            }
        }
    };

    let reader = async move {
        let mut bound: Option<(String, String)> = None;
        let mut _route_guard: Option<RouteLimitGuard> = None;
        let mut handshake_state: Option<(Pin<Box<Sleep>>, Arc<HandshakeWatch>)> = None;
        loop {
            let next = tokio::select! {
                biased;
                _ = writer_done_rx.changed() => break,
                timed_out = poll_handshake(&mut handshake_state) => {
                    if timed_out {
                        break;
                    }
                    continue;
                }
                item = stream.next() => item,
            };
            let Some(next) = next else {
                break;
            };
            let msg = match next {
                Ok(msg) => msg,
                Err(_) => break,
            };
            match msg {
                Message::Binary(bytes) => {
                    let Some((host, sid)) = bound.clone() else {
                        break;
                    };
                    let bytes = bytes.to_vec();
                    let header = match lumzel_frame::parse_header(&bytes) {
                        Ok(header) => header,
                        Err(_) => break,
                    };
                    let encrypted =
                        matches!(lumzel_frame::ciphertext_len(&bytes), Ok(len) if len >= 16);
                    if !encrypted || header.host != host || header.sid != sid {
                        break;
                    }
                    match state.limits().charge_route(&host, &sid, bytes.len()) {
                        ChargeOutcome::Allow => {}
                        ChargeOutcome::Backpressure(wait) => {
                            tokio::select! {
                                _ = writer_done_rx.changed() => break,
                                _ = tokio::time::sleep(wait) => {}
                            }
                        }
                        ChargeOutcome::ExceededTotal => {
                            state.lock().close_route(&host, &sid);
                            break;
                        }
                    }
                    let Some(id) = ConnId::from_raw(id_slot.load(Ordering::SeqCst)) else {
                        break;
                    };
                    let forward_res = {
                        let mut table = state.lock();
                        table.satisfy_handshake(id);
                        table.forward(id, &bytes)
                    };
                    match forward_res {
                        Ok(()) | Err(RouteError::NoPeer) | Err(RouteError::Busy) => {}
                        Err(_) => break,
                    }
                }
                Message::Text(text) => {
                    let text = text.to_string();
                    if bound.is_none() {
                        let hello = match handshake::check_hello(&text) {
                            Ok(hello) => hello,
                            Err(()) => break,
                        };
                        let side = if let Some(ticket) = hello.ticket.as_deref() {
                            if !state.inbox_lock().consume_ticket(
                                ticket,
                                &hello.host,
                                &hello.sid,
                                plane,
                            ) {
                                break;
                            }
                            Side::Host
                        } else {
                            if !state.inbox_lock().is_registered(&hello.host) {
                                let _ = local_tx.send(Message::Close(Some(CloseFrame {
                                    code: 4404,
                                    reason: "host offline".into(),
                                })));
                                break;
                            }
                            Side::Peer
                        };
                        let forwarded = hello.sanitized_text(&text);
                        let (reject, need_waiting, peer_watch) = {
                            let mut table = state.lock();
                            let host_absent = side == Side::Peer
                                && !table.has_host(&hello.host, &hello.sid, plane);
                            match table.claim(&node_id, &hello.host, &hello.sid, plane, side) {
                                Ok((id, notify)) => {
                                    let watch = if side == Side::Peer {
                                        table.start_peer_handshake(id)
                                    } else {
                                        None
                                    };
                                    let _ = table.forward_text(id, &forwarded);
                                    notify_slot.lock().expect("notify").replace(notify);
                                    id_slot.store(id.raw(), Ordering::SeqCst);
                                    (false, host_absent, watch)
                                }
                                Err(_) => (true, false, None),
                            }
                        };
                        if reject {
                            break;
                        }
                        if need_waiting
                            && !state
                                .inbox_lock()
                                .notify_waiting(&hello.host, &hello.sid, plane)
                        {
                            let _ = local_tx.send(Message::Close(Some(CloseFrame {
                                code: 4404,
                                reason: "host offline".into(),
                            })));
                            break;
                        }
                        _route_guard = Some(state.limits().attach_route(&hello.host, &hello.sid));
                        if let Some(watch) = peer_watch {
                            let dur = state.limits().handshake_timeout();
                            handshake_state = Some((Box::pin(tokio::time::sleep(dur)), watch));
                        }
                        wake.notify_one();
                        bound = Some((hello.host, hello.sid));
                        continue;
                    }
                    if plane != Plane::Control {
                        break;
                    }
                    let punch = match punch::parse_punch(&text) {
                        Ok(punch) => punch,
                        Err(_) => break,
                    };
                    if let Some((ref host, ref sid)) = bound {
                        match state.limits().charge_route(host, sid, text.len()) {
                            ChargeOutcome::Allow => {}
                            ChargeOutcome::Backpressure(wait) => {
                                tokio::select! {
                                    _ = writer_done_rx.changed() => break,
                                    _ = tokio::time::sleep(wait) => {}
                                }
                            }
                            ChargeOutcome::ExceededTotal => {
                                state.lock().close_route(host, sid);
                                break;
                            }
                        }
                    }
                    let Some(id) = ConnId::from_raw(id_slot.load(Ordering::SeqCst)) else {
                        break;
                    };
                    match state.lock().forward_punch(id, &text, &punch.addr) {
                        Ok(()) | Err(RouteError::NoPeer) | Err(RouteError::Busy) => {}
                        Err(_) => break,
                    }
                }
                Message::Ping(payload) => {
                    if local_tx.send(Message::Pong(payload)).is_err() {
                        break;
                    }
                }
                Message::Pong(_) => {}
                Message::Close(_) => break,
            }
        }
        drop(local_tx);
        wake.notify_one();
    };

    tokio::join!(reader, writer);
}

async fn poll_handshake(state: &mut Option<(Pin<Box<Sleep>>, Arc<HandshakeWatch>)>) -> bool {
    let timed_out = {
        let Some((sleep, watch)) = state.as_mut() else {
            return pending::<bool>().await;
        };
        if watch.is_satisfied() {
            false
        } else {
            let notified = watch.notified();
            if watch.is_satisfied() {
                false
            } else {
                tokio::select! {
                    _ = notified => false,
                    _ = sleep.as_mut() => !watch.is_satisfied(),
                }
            }
        }
    };
    *state = None;
    timed_out
}

fn outbound_message(item: Outbound) -> Message {
    match item {
        Outbound::Binary(bytes) => Message::binary(bytes),
        Outbound::Text(text) => Message::text(text),
    }
}

async fn wait_notify(notify: Option<Arc<Notify>>) {
    match notify {
        Some(notify) => notify.notified().await,
        None => pending::<()>().await,
    }
}
