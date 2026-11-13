// lumzel:remote-link-03#dw-6 lumzel:remote-link-03#dw-7
use std::net::SocketAddr;
use std::time::Duration;

use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use futures_util::{SinkExt, StreamExt};
use lumzel_frame::proof::{respond, Challenge};
use lumzel_frame::{host_id, Identity, PublicKey};
use lumzel_relay::{AppState, Plane, RouteError, RouteTable, Side};
use serde_json::{json, Value};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::timeout;
use tokio_tungstenite::tungstenite::client::IntoClientRequest;
use tokio_tungstenite::tungstenite::Message;
use tokio_tungstenite::WebSocketStream;

type Ws = WebSocketStream<TcpStream>;

/// The v2 peer hello: the route it wants, and no key.
fn link_hello(host: &str, sid: &str) -> String {
    serde_json::json!({
        "type": "link_hello",
        "v": 2,
        "host": host,
        "sid": sid,
    })
    .to_string()
}

fn host_link_hello(host: &str, sid: &str, ticket: &str) -> String {
    serde_json::json!({
        "type": "link_hello",
        "v": 2,
        "host": host,
        "sid": sid,
        "ticket": ticket,
    })
    .to_string()
}

// The relay never sees a key, so the two direction keys of a test session are fixed.
const KEY_A: [u8; 32] = [0x11; 32];
const KEY_B: [u8; 32] = [0x22; 32];

/// The two ends of one session: each seals under the key the other opens with.
fn session_pair(sid: &str) -> (lumzel_frame::Session, lumzel_frame::Session) {
    (
        lumzel_frame::Session::from_keys(KEY_A, KEY_B, sid).unwrap(),
        lumzel_frame::Session::from_keys(KEY_B, KEY_A, sid).unwrap(),
    )
}

fn session_frame(host: &str, sid: &str, plaintext: &[u8]) -> Vec<u8> {
    let (mut ours, _) = session_pair(sid);
    ours.seal(host, plaintext).unwrap()
}

async fn read_json(ws: &mut Ws) -> Value {
    match timeout(Duration::from_secs(2), ws.next()).await {
        Ok(Some(Ok(Message::Text(text)))) => serde_json::from_str(text.as_str()).unwrap(),
        other => panic!("expected text json, got {other:?}"),
    }
}

fn parse_challenge(msg: &Value) -> Challenge {
    assert_eq!(msg["t"], "challenge");
    let key_b = B64.decode(msg["key"].as_str().unwrap()).unwrap();
    let nonce_b = B64.decode(msg["nonce"].as_str().unwrap()).unwrap();
    Challenge {
        key: PublicKey::from_bytes(&key_b).unwrap(),
        nonce: nonce_b.try_into().unwrap(),
    }
}

async fn register_host(addr: SocketAddr, identity: &Identity) -> (Ws, String) {
    let mut ws = ws_connect(addr, "/host").await;
    let ch = parse_challenge(&read_json(&mut ws).await);
    let proof = respond(identity.static_secret(), &ch).unwrap();
    ws.send(Message::text(
        json!({
            "t": "register",
            "host_pub": B64.encode(identity.public_key().to_bytes()),
            "proof": B64.encode(proof),
        })
        .to_string(),
    ))
    .await
    .unwrap();
    let reply = read_json(&mut ws).await;
    assert_eq!(reply["t"], "registered");
    let expected = host_id(&identity.public_key());
    assert_eq!(reply["host"].as_str().unwrap(), expected);
    (ws, expected)
}

/// Both ends on `/control` for one route (Peer `a`, Host `b`), with initial hellos read off both.
async fn admitted_pair(
    addr: SocketAddr,
    state: &AppState,
    inbox: &mut Ws,
    host: &str,
    sid: &str,
) -> (Ws, Ws) {
    let mut a = ws_connect(addr, "/control").await;
    a.send(Message::text(link_hello(host, sid))).await.unwrap();
    wait_conns(state, host, sid, Plane::Control, 1).await;

    let waiting = read_json(inbox).await;
    assert_eq!(waiting["t"], "waiting");
    assert_eq!(waiting["sid"], sid);
    let ticket = waiting["ticket"].as_str().unwrap();

    let mut b = ws_connect(addr, "/control").await;
    b.send(Message::text(host_link_hello(host, sid, ticket)))
        .await
        .unwrap();
    wait_conns(state, host, sid, Plane::Control, 2).await;

    match timeout(Duration::from_secs(2), a.next()).await {
        Ok(Some(Ok(Message::Text(_)))) => {}
        other => panic!("expected host hello at peer, got {other:?}"),
    }
    match timeout(Duration::from_secs(2), b.next()).await {
        Ok(Some(Ok(Message::Text(_)))) => {}
        other => panic!("expected buffered peer hello at host, got {other:?}"),
    }
    (a, b)
}

async fn spawn() -> (SocketAddr, AppState) {
    spawn_with_state(AppState::new("local", 1024)).await
}

async fn spawn_with_state(state: AppState) -> (SocketAddr, AppState) {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let background = state.clone();
    tokio::spawn(async move {
        lumzel_relay::serve(listener, background).await.unwrap();
    });
    (addr, state)
}

async fn http(addr: SocketAddr, method: &str, path: &str) -> (u16, String) {
    http_auth(addr, method, path, None).await
}

async fn http_auth(
    addr: SocketAddr,
    method: &str,
    path: &str,
    auth_header: Option<&str>,
) -> (u16, String) {
    let mut stream = TcpStream::connect(addr).await.unwrap();
    let auth_line = match auth_header {
        Some(v) => format!("Authorization: {v}\r\n"),
        None => String::new(),
    };
    let req = format!(
        "{method} {path} HTTP/1.1\r\nHost: {addr}\r\n{auth_line}Connection: close\r\nContent-Length: 0\r\n\r\n"
    );
    stream.write_all(req.as_bytes()).await.unwrap();
    let mut buf = Vec::new();
    let _ = timeout(Duration::from_secs(2), stream.read_to_end(&mut buf)).await;
    let text = String::from_utf8_lossy(&buf).into_owned();
    let status = text.split_whitespace().nth(1).unwrap().parse().unwrap();
    let body = text.split("\r\n\r\n").nth(1).unwrap_or("").to_owned();
    (status, body)
}

async fn ws_connect(addr: SocketAddr, path: &str) -> Ws {
    let tcp = TcpStream::connect(addr).await.unwrap();
    let req = format!("ws://{addr}{path}").into_client_request().unwrap();
    let (socket, _) = tokio_tungstenite::client_async(req, tcp).await.unwrap();
    socket
}

async fn upgrade_status(addr: SocketAddr, path: &str) -> u16 {
    let mut stream = TcpStream::connect(addr).await.unwrap();
    let req = format!(
        "GET {path} HTTP/1.1\r\nHost: {addr}\r\nConnection: Upgrade\r\nUpgrade: websocket\r\nSec-WebSocket-Version: 13\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n\r\n"
    );
    stream.write_all(req.as_bytes()).await.unwrap();
    let mut buf = [0u8; 256];
    let n = timeout(Duration::from_secs(2), stream.read(&mut buf))
        .await
        .unwrap()
        .unwrap();
    let text = String::from_utf8_lossy(&buf[..n]);
    text.split_whitespace().nth(1).unwrap().parse().unwrap()
}

async fn wait_conns(state: &AppState, host: &str, sid: &str, plane: Plane, want: usize) {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(2);
    loop {
        if state.connection_count(host, sid, plane) >= want {
            return;
        }
        if tokio::time::Instant::now() > deadline {
            panic!("timed out waiting for {want} {plane:?} conns on {sid}");
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
}

async fn expect_closed(ws: &mut Ws) {
    match timeout(Duration::from_secs(2), ws.next()).await {
        Ok(Some(Ok(Message::Close(_)))) | Ok(Some(Err(_))) | Ok(None) => {}
        Ok(Some(Ok(other))) => panic!("expected close, got {other:?}"),
        Err(_) => panic!("timed out waiting for close"),
    }
}

async fn expect_silent(ws: &mut Ws) {
    let msg = timeout(Duration::from_millis(250), ws.next()).await;
    assert!(msg.is_err(), "unexpected forward: {msg:?}");
}

#[tokio::test]
async fn health_and_ready() {
    let (addr, _) = spawn().await;
    let (status, body) = http(addr, "GET", "/health").await;
    assert_eq!(status, 200);
    let value: serde_json::Value = serde_json::from_str(body.trim()).unwrap();
    assert_eq!(value["ok"], true);
    let (status, body) = http(addr, "GET", "/ready").await;
    assert_eq!(status, 200);
    let value: serde_json::Value = serde_json::from_str(body.trim()).unwrap();
    assert_eq!(value["ok"], true);
}

#[tokio::test]
async fn control_frame_is_forwarded_unchanged() {
    let (addr, state) = spawn().await;
    let host_identity = Identity::generate();
    let (mut inbox, host) = register_host(addr, &host_identity).await;
    let sid = "sid-a";
    let (mut a, mut b) = admitted_pair(addr, &state, &mut inbox, &host, sid).await;
    let (mut ours, mut theirs) = session_pair(sid);
    let payload = ours.seal(&host, b"payload").unwrap();
    a.send(Message::binary(payload.clone())).await.unwrap();
    match timeout(Duration::from_secs(2), b.next()).await {
        Ok(Some(Ok(Message::Binary(got)))) => {
            assert_eq!(&got[..], payload.as_slice());
            // Unchanged means the other end can still open it.
            assert_eq!(theirs.open(&got).unwrap().plaintext, b"payload");
        }
        other => panic!("expected payload, got {other:?}"),
    }
}

#[tokio::test]
async fn garbage_binary_closes_and_is_not_forwarded() {
    let (addr, state) = spawn().await;
    let host_identity = Identity::generate();
    let (mut inbox, host) = register_host(addr, &host_identity).await;
    let sid = "sid-g";
    let (mut a, mut b) = admitted_pair(addr, &state, &mut inbox, &host, sid).await;
    a.send(Message::binary(b"this is not a lumzel frame".to_vec()))
        .await
        .unwrap();
    expect_closed(&mut a).await;
    expect_silent(&mut b).await;
}

#[tokio::test]
async fn third_control_socket_is_rejected() {
    let (addr, state) = spawn().await;
    let host_identity = Identity::generate();
    let (mut inbox, host) = register_host(addr, &host_identity).await;
    let sid = "sid-t";
    let (mut a, mut b) = admitted_pair(addr, &state, &mut inbox, &host, sid).await;

    // A second Peer socket on the same side is rejected as Busy.
    let mut c = ws_connect(addr, "/control").await;
    c.send(Message::text(link_hello(&host, sid))).await.unwrap();
    expect_closed(&mut c).await;
    expect_silent(&mut a).await;
    expect_silent(&mut b).await;
}

// lumzel:remote-link-03#dw-6
#[tokio::test]
async fn drain_rejects_ready_and_upgrade() {
    // 1. Without RELAY_OPS_TOKEN configured, /drain is disabled and returns 404.
    let (unconfigured_addr, _) = spawn().await;
    let (status, _) = http(unconfigured_addr, "POST", "/drain").await;
    assert_eq!(status, 404);
    let (status, _) = http_auth(
        unconfigured_addr,
        "POST",
        "/drain",
        Some("Bearer any-token"),
    )
    .await;
    assert_eq!(status, 404);
    let (status, _) = http(unconfigured_addr, "GET", "/ready").await;
    assert_eq!(status, 200);

    // 2. With RELAY_OPS_TOKEN configured, missing/wrong token returns 401; matching Bearer returns 204.
    let (addr, _) =
        spawn_with_state(AppState::new("local", 1024).with_ops_token("ops-secret-token")).await;

    let (status, _) = http(addr, "POST", "/drain").await;
    assert_eq!(status, 401);
    let (status, _) = http_auth(addr, "POST", "/drain", Some("Bearer wrong-token")).await;
    assert_eq!(status, 401);
    let (status, _) = http_auth(addr, "POST", "/drain", Some("Basic ops-secret-token")).await;
    assert_eq!(status, 401);
    let (status, _) = http(addr, "GET", "/ready").await;
    assert_eq!(status, 200);

    let (status, _) = http_auth(addr, "POST", "/drain", Some("Bearer ops-secret-token")).await;
    assert_eq!(status, 204);
    let (status, _) = http(addr, "GET", "/ready").await;
    assert_eq!(status, 503);
    let (status, body) = http(addr, "GET", "/health").await;
    assert_eq!(status, 200);
    let value: serde_json::Value = serde_json::from_str(body.trim()).unwrap();
    assert_eq!(value["ok"], true);
    assert_eq!(upgrade_status(addr, "/host").await, 503);
    assert_eq!(upgrade_status(addr, "/control").await, 503);
    assert_eq!(upgrade_status(addr, "/data").await, 503);
}

#[test]
fn data_queue_cap_does_not_block_control() {
    let mut table = RouteTable::new("local", 1024);
    let (a, _) = table
        .claim("local", "h", "s", Plane::Data, Side::Host)
        .unwrap();
    let (b, _) = table
        .claim("local", "h", "s", Plane::Data, Side::Peer)
        .unwrap();
    let frame = b"frame";
    for _ in 0..32 {
        table.forward(a, frame).unwrap();
    }
    assert_eq!(table.outbound_len(b), Some(32));
    assert!(matches!(table.forward(a, frame), Err(RouteError::Busy)));
    assert_eq!(table.outbound_len(b), Some(32));
    let (c, _) = table
        .claim("local", "h", "s", Plane::Control, Side::Host)
        .unwrap();
    let (_d, _) = table
        .claim("local", "h", "s", Plane::Control, Side::Peer)
        .unwrap();
    table.forward(c, frame).unwrap();
}

#[test]
fn sid_sticks_to_the_node_that_claimed_it() {
    let a = RouteTable::new("A", 1024);
    let mut b = RouteTable::with_meta("B", 1024, a.meta());
    let mut a = a;
    a.claim("A", "host", "sid", Plane::Control, Side::Host)
        .unwrap();
    assert!(matches!(
        a.claim("A", "host", "sid", Plane::Control, Side::Host),
        Err(RouteError::Busy)
    ));
    a.claim("A", "host", "sid", Plane::Control, Side::Peer)
        .unwrap();
    assert!(matches!(
        a.claim("A", "host", "sid", Plane::Control, Side::Peer),
        Err(RouteError::Busy)
    ));
    assert!(matches!(
        b.claim("B", "host", "sid", Plane::Control, Side::Peer),
        Err(RouteError::OwnedBy { node }) if node == "A"
    ));
    assert!(matches!(
        a.claim("A", "", "sid", Plane::Control, Side::Peer),
        Err(RouteError::BadId)
    ));
    assert!(matches!(
        a.claim("A", "host", &"s".repeat(257), Plane::Control, Side::Peer),
        Err(RouteError::BadId)
    ));
    assert!(a
        .claim(
            "A",
            &"h".repeat(256),
            &"s".repeat(256),
            Plane::Data,
            Side::Host
        )
        .is_ok());
}

#[test]
fn drain_keeps_existing_forward_and_refuses_admit() {
    let mut table = RouteTable::new("local", 1);
    let (a, _) = table
        .claim("local", "h", "s", Plane::Data, Side::Host)
        .unwrap();
    let (b, _) = table
        .claim("local", "h", "s", Plane::Data, Side::Peer)
        .unwrap();
    table.reserve().unwrap();
    assert!(!table.ready());
    table.drain();
    assert!(matches!(table.admit(), Err(RouteError::Draining)));
    table.forward(a, b"still").unwrap();
    assert_eq!(table.outbound_len(b), Some(1));
    assert!(matches!(
        table.claim("local", "h", "other", Plane::Control, Side::Peer),
        Err(RouteError::Draining)
    ));
}

// lumzel:remote-link-02#m-relay
#[tokio::test]
async fn link_hello_v2_is_admitted_and_v1_e2ee_hello_is_closed() {
    let (addr, state) = spawn().await;
    let host_identity = Identity::generate();
    let (mut inbox, host) = register_host(addr, &host_identity).await;

    // Both hellos are written out: these are the wire shapes, not what a helper builds.
    let v2_peer = format!(r#"{{"type":"link_hello","v":2,"host":"{host}","sid":"sid-v"}}"#);
    let mut a = ws_connect(addr, "/control").await;
    let mut b = ws_connect(addr, "/control").await;
    a.send(Message::text(v2_peer.clone())).await.unwrap();
    wait_conns(&state, &host, "sid-v", Plane::Control, 1).await;
    let waiting_msg = read_json(&mut inbox).await;
    let ticket = waiting_msg["ticket"].as_str().unwrap();
    let v2_host = format!(
        r#"{{"type":"link_hello","v":2,"host":"{host}","sid":"sid-v","ticket":"{ticket}"}}"#
    );
    b.send(Message::text(v2_host)).await.unwrap();
    wait_conns(&state, &host, "sid-v", Plane::Control, 2).await;
    match timeout(Duration::from_secs(2), a.next()).await {
        Ok(Some(Ok(Message::Text(got)))) => {
            let parsed: Value = serde_json::from_str(got.as_str()).unwrap();
            assert_eq!(parsed["type"], "link_hello");
            assert_eq!(parsed["v"], 2);
            assert_eq!(parsed["host"], host);
            assert_eq!(parsed["sid"], "sid-v");
            assert!(parsed.get("ticket").is_none());
        }
        other => panic!("expected sanitized host hello, got {other:?}"),
    }

    // The v1 hello, with a well-formed 32-byte key, for a route whose other end is
    // already waiting: refused for its shape, not for a full route or a bad key.
    let waiting = format!(r#"{{"type":"link_hello","v":2,"host":"{host}","sid":"sid-w"}}"#);
    let v1 = format!(
        r#"{{"type":"e2ee_hello","key":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=","host":"{host}","sid":"sid-w"}}"#
    );
    let mut c = ws_connect(addr, "/control").await;
    let mut d = ws_connect(addr, "/control").await;
    c.send(Message::text(waiting)).await.unwrap();
    wait_conns(&state, &host, "sid-w", Plane::Control, 1).await;
    let _ = read_json(&mut inbox).await;
    d.send(Message::text(v1)).await.unwrap();
    expect_closed(&mut d).await;
    expect_silent(&mut c).await;
    assert_eq!(state.connection_count(&host, "sid-w", Plane::Control), 1);
}

// lumzel:remote-link-02#m-relay
#[tokio::test]
async fn handshake_frame_is_forwarded_unchanged() {
    let (addr, state) = spawn().await;
    let host_identity = Identity::generate();
    let (mut inbox, host) = register_host(addr, &host_identity).await;
    let sid = "hs-sid";
    let (mut a, mut b) = admitted_pair(addr, &state, &mut inbox, &host, sid).await;

    // A Noise message is opaque here; 48 bytes is the size of an IK reply.
    let first: Vec<u8> = (0u8..48).collect();
    let second: Vec<u8> = (100u8..148).collect();
    // The v2 header, byte by byte: magic, version 2, u16-BE length (32) + host_id,
    // u16-BE length + sid, u64-BE n = 0. The message follows in the clear.
    assert_eq!(host.len(), 32);
    let header: Vec<u8> = [
        b"LUMZEL".as_slice(),
        &[2],
        &[0, 32],
        host.as_bytes(),
        &[0, 6],
        b"hs-sid",
        &[0, 0, 0, 0, 0, 0, 0, 0],
    ]
    .concat();

    a.send(Message::binary(
        lumzel_frame::handshake_frame(&host, sid, &first).unwrap(),
    ))
    .await
    .unwrap();
    match timeout(Duration::from_secs(2), b.next()).await {
        Ok(Some(Ok(Message::Binary(got)))) => {
            assert_eq!(&got[..], [header.as_slice(), &first].concat());
        }
        other => panic!("expected handshake frame, got {other:?}"),
    }

    // And the answer, the other way.
    b.send(Message::binary(
        lumzel_frame::handshake_frame(&host, sid, &second).unwrap(),
    ))
    .await
    .unwrap();
    match timeout(Duration::from_secs(2), a.next()).await {
        Ok(Some(Ok(Message::Binary(got)))) => {
            assert_eq!(&got[..], [header.as_slice(), &second].concat());
        }
        other => panic!("expected handshake frame, got {other:?}"),
    }
}

// lumzel:remote-link-02#m-relay
#[tokio::test]
async fn v1_frame_closes_and_is_not_forwarded() {
    let (addr, state) = spawn().await;
    let host_identity = Identity::generate();
    let (mut inbox, host) = register_host(addr, &host_identity).await;
    let (mut a, mut b) = admitted_pair(addr, &state, &mut inbox, &host, "v1-sid").await;

    assert_eq!(host.len(), 32);
    // magic, version, u16-BE length + host, u16-BE length + sid, u64-BE n = 1, 32 bytes.
    let frame = |version: u8| -> Vec<u8> {
        [
            b"LUMZEL".as_slice(),
            &[version],
            &[0, 32],
            host.as_bytes(),
            &[0, 6],
            b"v1-sid",
            &[0, 0, 0, 0, 0, 0, 0, 1],
            &[0xab; 32],
        ]
        .concat()
    };

    // The same bytes as version 2 pass, so the version byte is what closes the socket.
    a.send(Message::binary(frame(2))).await.unwrap();
    match timeout(Duration::from_secs(2), b.next()).await {
        Ok(Some(Ok(Message::Binary(got)))) => assert_eq!(&got[..], frame(2)),
        other => panic!("expected v2 frame, got {other:?}"),
    }

    a.send(Message::binary(frame(1))).await.unwrap();
    expect_closed(&mut a).await;
    expect_silent(&mut b).await;
}

#[tokio::test]
async fn header_without_ciphertext_is_not_forwarded() {
    let (addr, state) = spawn().await;
    let host_identity = Identity::generate();
    let (mut inbox, host) = register_host(addr, &host_identity).await;
    let sid = "sid-c";
    let (mut a, mut b) = admitted_pair(addr, &state, &mut inbox, &host, sid).await;
    let mut frame = session_frame(&host, sid, b"secret");
    frame.truncate(frame.len() - 16);
    a.send(Message::binary(frame)).await.unwrap();
    expect_closed(&mut a).await;
    expect_silent(&mut b).await;
}
