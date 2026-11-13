// lumzel:remote-link-03#dw-7
use std::net::SocketAddr;
use std::time::Duration;

use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use futures_util::{SinkExt, StreamExt};
use lumzel_frame::proof::{respond, Challenge};
use lumzel_frame::{host_id, Identity, PublicKey};
use lumzel_relay::{parse_punch, AppState, Plane};
use serde_json::{json, Value};
use tokio::net::TcpStream;
use tokio::time::timeout;
use tokio_tungstenite::tungstenite::client::IntoClientRequest;
use tokio_tungstenite::tungstenite::Message;
use tokio_tungstenite::WebSocketStream;

type Ws = WebSocketStream<TcpStream>;

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

async fn admitted_pair(
    addr: SocketAddr,
    state: &AppState,
    inbox: &mut Ws,
    host: &str,
    sid: &str,
    plane: Plane,
) -> (Ws, Ws) {
    let path = match plane {
        Plane::Control => "/control",
        Plane::Data => "/data",
    };
    let mut a = ws_connect(addr, path).await;
    a.send(Message::text(link_hello(host, sid))).await.unwrap();
    wait_conns(state, host, sid, plane, 1).await;

    let waiting = read_json(inbox).await;
    let ticket = waiting["ticket"].as_str().unwrap();

    let mut b = ws_connect(addr, path).await;
    b.send(Message::text(host_link_hello(host, sid, ticket)))
        .await
        .unwrap();
    wait_conns(state, host, sid, plane, 2).await;

    let _ = read_json(&mut a).await;
    let _ = read_json(&mut b).await;
    (a, b)
}

async fn wait_conns(state: &AppState, host: &str, sid: &str, plane: Plane, want: usize) {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(2);
    loop {
        if state.connection_count(host, sid, plane) >= want {
            return;
        }
        if tokio::time::Instant::now() > deadline {
            panic!("timed out waiting for {want} conns");
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

#[test]
fn literal_ip_port_only() {
    assert_eq!(
        parse_punch(r#"{"t":"punch","addr":"127.0.0.1:1"}"#)
            .unwrap()
            .addr,
        "127.0.0.1:1"
    );
    assert_eq!(
        parse_punch(r#"{"t":"punch","addr":"[::1]:65535"}"#)
            .unwrap()
            .addr,
        "[::1]:65535"
    );
    assert!(parse_punch(r#"{"t":"punch","addr":"example.com:80"}"#).is_err());
    assert!(parse_punch(r#"{"t":"punch","addr":"http://127.0.0.1:80"}"#).is_err());
    assert!(parse_punch(r#"{"t":"punch","addr":"127.0.0.1:0"}"#).is_err());
    assert!(parse_punch(r#"{"t":"punch","addr":"127.0.0.1:65536"}"#).is_err());
}

#[tokio::test]
async fn punch_text_is_forwarded_and_stored() {
    let (addr, state) = spawn().await;
    let host_identity = Identity::generate();
    let (mut inbox, host) = register_host(addr, &host_identity).await;
    let sid = "sid-p";
    let (mut a, mut b) = admitted_pair(addr, &state, &mut inbox, &host, sid, Plane::Control).await;
    let text = r#"{"t":"punch","addr":"203.0.113.8:4242"}"#;
    a.send(Message::text(text)).await.unwrap();
    match timeout(Duration::from_secs(2), b.next()).await {
        Ok(Some(Ok(Message::Text(got)))) => assert_eq!(got.as_str(), text),
        other => panic!("expected punch text, got {other:?}"),
    }
    assert_eq!(
        state.punch_addr(&host, sid).as_deref(),
        Some("203.0.113.8:4242")
    );
}

#[tokio::test]
async fn hostname_punch_is_rejected() {
    let (addr, state) = spawn().await;
    let host_identity = Identity::generate();
    let (mut inbox, host) = register_host(addr, &host_identity).await;
    let sid = "sid-h";
    let (mut a, mut b) = admitted_pair(addr, &state, &mut inbox, &host, sid, Plane::Control).await;
    a.send(Message::text(r#"{"t":"punch","addr":"example.com:80"}"#))
        .await
        .unwrap();
    expect_closed(&mut a).await;
    expect_silent(&mut b).await;
    assert_eq!(state.punch_addr(&host, sid), None);
}

#[tokio::test]
async fn data_plane_rejects_text() {
    let (addr, state) = spawn().await;
    let host_identity = Identity::generate();
    let (mut inbox, host) = register_host(addr, &host_identity).await;
    let sid = "sid-d";
    let (mut a, mut b) = admitted_pair(addr, &state, &mut inbox, &host, sid, Plane::Data).await;
    a.send(Message::text(r#"{"t":"punch","addr":"203.0.113.8:4242"}"#))
        .await
        .unwrap();
    expect_closed(&mut a).await;
    expect_silent(&mut b).await;
}
