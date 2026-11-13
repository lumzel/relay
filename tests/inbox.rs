use std::net::SocketAddr;
use std::time::Duration;

use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use futures_util::{SinkExt, StreamExt};
use lumzel_frame::proof::{respond, Challenge};
use lumzel_frame::{host_id, Identity, PublicKey, Session};
use lumzel_relay::{AppState, Plane};
use serde_json::{json, Value};
use tokio::net::TcpStream;
use tokio::time::timeout;
use tokio_tungstenite::tungstenite::client::IntoClientRequest;
use tokio_tungstenite::tungstenite::Message;
use tokio_tungstenite::WebSocketStream;

type Ws = WebSocketStream<TcpStream>;

async fn spawn() -> (SocketAddr, AppState) {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let state = AppState::new("local", 1024);
    let background = state.clone();
    tokio::spawn(async move {
        lumzel_relay::serve(listener, background).await.unwrap();
    });
    (addr, state)
}

async fn ws_connect(addr: SocketAddr, path: &str) -> Ws {
    let tcp = TcpStream::connect(addr).await.unwrap();
    let req = format!("ws://{addr}{path}").into_client_request().unwrap();
    let (socket, _) = tokio_tungstenite::client_async(req, tcp).await.unwrap();
    socket
}

async fn read_json(ws: &mut Ws) -> Value {
    match timeout(Duration::from_secs(2), ws.next()).await {
        Ok(Some(Ok(Message::Text(text)))) => serde_json::from_str(text.as_str()).unwrap(),
        other => panic!("expected text json, got {other:?}"),
    }
}

async fn expect_close_code(ws: &mut Ws, want_code: u16) {
    loop {
        match timeout(Duration::from_secs(2), ws.next()).await {
            Ok(Some(Ok(Message::Close(Some(frame))))) => {
                assert_eq!(u16::from(frame.code), want_code, "close frame: {frame:?}");
                return;
            }
            Ok(Some(Ok(Message::Ping(_) | Message::Pong(_)))) => continue,
            other => panic!("expected close {want_code}, got {other:?}"),
        }
    }
}

async fn expect_closed(ws: &mut Ws) {
    loop {
        match timeout(Duration::from_secs(2), ws.next()).await {
            Ok(Some(Ok(Message::Close(_)))) | Ok(Some(Err(_))) | Ok(None) => return,
            Ok(Some(Ok(Message::Ping(_) | Message::Pong(_)))) => continue,
            Ok(Some(Ok(other))) => panic!("expected close, got {other:?}"),
            Err(_) => panic!("timed out waiting for close"),
        }
    }
}

fn parse_challenge(msg: &Value) -> Challenge {
    assert_eq!(msg["t"], "challenge");
    let key_b = B64.decode(msg["key"].as_str().unwrap()).unwrap();
    let nonce_b = B64.decode(msg["nonce"].as_str().unwrap()).unwrap();
    assert_eq!(key_b.len(), 32);
    assert_eq!(nonce_b.len(), 32);
    Challenge {
        key: PublicKey::from_bytes(&key_b).unwrap(),
        nonce: nonce_b.try_into().unwrap(),
    }
}

async fn register_host(addr: SocketAddr, host: &Identity) -> (Ws, String) {
    let mut ws = ws_connect(addr, "/host").await;
    let ch = parse_challenge(&read_json(&mut ws).await);
    let proof = respond(host.static_secret(), &ch).unwrap();
    let reg = json!({
        "t": "register",
        "host_pub": B64.encode(host.public_key().to_bytes()),
        "proof": B64.encode(proof),
    });
    ws.send(Message::text(reg.to_string())).await.unwrap();
    let reply = read_json(&mut ws).await;
    assert_eq!(reply["t"], "registered");
    let expected = host_id(&host.public_key());
    assert_eq!(reply["host"].as_str().unwrap(), expected);
    (ws, expected)
}

fn peer_hello(host: &str, sid: &str) -> String {
    json!({
        "type": "link_hello",
        "v": 2,
        "host": host,
        "sid": sid,
    })
    .to_string()
}

fn host_hello(host: &str, sid: &str, ticket: &str) -> String {
    json!({
        "type": "link_hello",
        "v": 2,
        "host": host,
        "sid": sid,
        "ticket": ticket,
    })
    .to_string()
}

// lumzel:remote-link-03#dw-1
#[tokio::test]
async fn valid_proof_registers_and_impostor_proof_or_host_mismatch_closes_4401() {
    let (addr, _state) = spawn().await;
    let real_host = Identity::generate();
    let impostor = Identity::generate();
    let victim_id = host_id(&real_host.public_key());

    // 1. Wrong proof for victim's public key -> 4401.
    {
        let mut ws = ws_connect(addr, "/host").await;
        let ch = parse_challenge(&read_json(&mut ws).await);
        let wrong_proof = respond(impostor.static_secret(), &ch).unwrap();
        ws.send(Message::text(
            json!({
                "t": "register",
                "host_pub": B64.encode(real_host.public_key().to_bytes()),
                "proof": B64.encode(wrong_proof),
            })
            .to_string(),
        ))
        .await
        .unwrap();
        expect_close_code(&mut ws, 4401).await;
    }

    // 2. Claiming victim's host_id alongside impostor's own public key & proof -> 4401.
    {
        let mut ws = ws_connect(addr, "/host").await;
        let ch = parse_challenge(&read_json(&mut ws).await);
        let imp_proof = respond(impostor.static_secret(), &ch).unwrap();
        ws.send(Message::text(
            json!({
                "t": "register",
                "host": victim_id,
                "host_pub": B64.encode(impostor.public_key().to_bytes()),
                "proof": B64.encode(imp_proof),
            })
            .to_string(),
        ))
        .await
        .unwrap();
        expect_close_code(&mut ws, 4401).await;
    }

    // 3. Low-order public key -> 4401.
    {
        let mut ws = ws_connect(addr, "/host").await;
        let _ch = parse_challenge(&read_json(&mut ws).await);
        ws.send(Message::text(
            json!({
                "t": "register",
                "host_pub": B64.encode([0u8; 32]),
                "proof": B64.encode([0u8; 32]),
            })
            .to_string(),
        ))
        .await
        .unwrap();
        expect_close_code(&mut ws, 4401).await;
    }

    // 4. Real Host registers cleanly.
    let (_inbox, registered_id) = register_host(addr, &real_host).await;
    assert_eq!(registered_id, victim_id);
}

#[tokio::test]
async fn silent_host_socket_is_closed_after_five_seconds() {
    tokio::time::pause();
    let (addr, _state) = spawn().await;
    let mut ws = ws_connect(addr, "/host").await;
    let first = ws.next().await.expect("challenge frame").unwrap();
    let Message::Text(ch_text) = first else {
        panic!("expected challenge text, got {first:?}");
    };
    let _ch = parse_challenge(&serde_json::from_str(ch_text.as_str()).unwrap());

    tokio::time::advance(Duration::from_millis(4900)).await;
    for _ in 0..10 {
        tokio::task::yield_now().await;
    }
    assert!(
        futures_util::FutureExt::now_or_never(ws.next()).is_none(),
        "closed before 5s"
    );

    tokio::time::advance(Duration::from_millis(200)).await;
    tokio::time::resume();
    expect_closed(&mut ws).await;
}

#[tokio::test]
async fn reregistering_same_host_id_replaces_old_inbox_socket() {
    let (addr, _state) = spawn().await;
    let host = Identity::generate();

    let (mut old_inbox, id1) = register_host(addr, &host).await;
    let (mut new_inbox, id2) = register_host(addr, &host).await;
    assert_eq!(id1, id2);

    // Old socket is closed when replaced.
    expect_closed(&mut old_inbox).await;
    drop(old_inbox);
    tokio::time::sleep(Duration::from_millis(30)).await;

    // New socket still owns the registration and receives waiting notifications.
    let mut peer = ws_connect(addr, "/control").await;
    peer.send(Message::text(peer_hello(&id2, "sid-replace")))
        .await
        .unwrap();
    let waiting = read_json(&mut new_inbox).await;
    assert_eq!(waiting["t"], "waiting");
    assert_eq!(waiting["sid"], "sid-replace");
    assert_eq!(waiting["plane"], "control");
}

// lumzel:remote-link-03#dw-3
#[tokio::test]
async fn unregistered_host_immediately_closes_peer_with_4404_and_creates_no_route() {
    let (addr, state) = spawn().await;
    let host = Identity::generate();
    let hid = host_id(&host.public_key());

    // Host has never registered: peer gets 4404 immediately, no route created.
    let mut peer = ws_connect(addr, "/control").await;
    peer.send(Message::text(peer_hello(&hid, "sid-offline")))
        .await
        .unwrap();
    expect_close_code(&mut peer, 4404).await;
    assert_eq!(
        state.connection_count(&hid, "sid-offline", Plane::Control),
        0
    );

    // Register, then disconnect /host: peer again gets 4404 immediately.
    let (inbox, _) = register_host(addr, &host).await;
    drop(inbox);
    for _ in 0..50 {
        let mut probe = ws_connect(addr, "/data").await;
        probe
            .send(Message::text(peer_hello(&hid, "sid-after-drop")))
            .await
            .unwrap();
        if let Ok(Some(Ok(Message::Close(Some(cf))))) =
            timeout(Duration::from_millis(200), probe.next()).await
        {
            if u16::from(cf.code) == 4404 {
                assert_eq!(
                    state.connection_count(&hid, "sid-after-drop", Plane::Data),
                    0
                );
                return;
            }
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    panic!("peer did not get 4404 after /host disconnected");
}

// lumzel:remote-link-03#dw-1 lumzel:remote-link-03#dw-2
#[tokio::test]
async fn peer_triggers_waiting_and_ticket_is_single_use_bound_and_expires() {
    let (addr, state) = spawn().await;
    let host = Identity::generate();
    let (mut inbox, hid) = register_host(addr, &host).await;

    // Forged ticket cannot claim Host slot on any route.
    let mut impostor = ws_connect(addr, "/control").await;
    impostor
        .send(Message::text(host_hello(
            &hid,
            "sid-1",
            &B64.encode([0xaa; 16]),
        )))
        .await
        .unwrap();
    expect_closed(&mut impostor).await;
    assert_eq!(state.connection_count(&hid, "sid-1", Plane::Control), 0);

    // Peer joins sid-1 on /control -> Host gets waiting notification with 16-byte ticket.
    let mut peer = ws_connect(addr, "/control").await;
    peer.send(Message::text(peer_hello(&hid, "sid-1")))
        .await
        .unwrap();
    let waiting = read_json(&mut inbox).await;
    assert_eq!(waiting["t"], "waiting");
    assert_eq!(waiting["sid"], "sid-1");
    assert_eq!(waiting["plane"], "control");
    let ticket = waiting["ticket"].as_str().unwrap().to_owned();
    assert_eq!(B64.decode(&ticket).unwrap().len(), 16);

    // Ticket bound to (hid, "sid-1", Control): using it on another sid or /data fails
    // without letting an attacker claim those routes.
    let mut wrong_sid = ws_connect(addr, "/control").await;
    wrong_sid
        .send(Message::text(host_hello(&hid, "sid-2", &ticket)))
        .await
        .unwrap();
    expect_closed(&mut wrong_sid).await;

    let mut wrong_plane = ws_connect(addr, "/data").await;
    wrong_plane
        .send(Message::text(host_hello(&hid, "sid-1", &ticket)))
        .await
        .unwrap();
    expect_closed(&mut wrong_plane).await;

    // Issue a fresh waiting ticket on sid-2 to verify valid Host join, forwarding,
    // single-use enforcement, and Host-disconnect closing Peer.
    let mut peer2 = ws_connect(addr, "/control").await;
    peer2
        .send(Message::text(peer_hello(&hid, "sid-2")))
        .await
        .unwrap();
    let w2 = read_json(&mut inbox).await;
    let ticket2 = w2["ticket"].as_str().unwrap().to_owned();

    let mut host_conn = ws_connect(addr, "/control").await;
    host_conn
        .send(Message::text(host_hello(&hid, "sid-2", &ticket2)))
        .await
        .unwrap();

    // Peer receives link_hello (without leaking ticket), Host receives buffered peer hello,
    // and both ends exchange frames.
    let peer_got_hello = read_json(&mut peer2).await;
    assert_eq!(peer_got_hello["type"], "link_hello");
    assert!(peer_got_hello.get("ticket").is_none());
    let host_got_hello = read_json(&mut host_conn).await;
    assert_eq!(host_got_hello["type"], "link_hello");

    let mut s_peer = Session::from_keys([1u8; 32], [2u8; 32], "sid-2").unwrap();
    let mut s_host = Session::from_keys([2u8; 32], [1u8; 32], "sid-2").unwrap();
    let frame = s_peer.seal(&hid, b"hello-host").unwrap();
    peer2.send(Message::binary(frame)).await.unwrap();
    match timeout(Duration::from_secs(2), host_conn.next()).await {
        Ok(Some(Ok(Message::Binary(bytes)))) => {
            assert_eq!(s_host.open(&bytes).unwrap().plaintext, b"hello-host");
        }
        other => panic!("expected frame at host, got {other:?}"),
    }

    // Reusing ticket2 is rejected.
    let mut replay_ticket = ws_connect(addr, "/control").await;
    replay_ticket
        .send(Message::text(host_hello(&hid, "sid-2", &ticket2)))
        .await
        .unwrap();
    expect_closed(&mut replay_ticket).await;

    // Disconnecting Host side simultaneously disconnects Peer side on that route.
    drop(host_conn);
    expect_closed(&mut peer2).await;

    // Expired ticket (> 30s) is rejected.
    let mut peer3 = ws_connect(addr, "/control").await;
    peer3
        .send(Message::text(peer_hello(&hid, "sid-exp")))
        .await
        .unwrap();
    let w3 = read_json(&mut inbox).await;
    let ticket3 = w3["ticket"].as_str().unwrap().to_owned();

    tokio::time::pause();
    tokio::time::advance(Duration::from_secs(31)).await;
    tokio::time::resume();
    let mut late_host = ws_connect(addr, "/control").await;
    late_host
        .send(Message::text(host_hello(&hid, "sid-exp", &ticket3)))
        .await
        .unwrap();
    expect_closed(&mut late_host).await;
}
