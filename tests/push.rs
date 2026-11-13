use std::net::SocketAddr;
use std::time::Duration;

use lumzel_relay::{AppState, Sender};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::timeout;

async fn spawn(state: AppState) -> (SocketAddr, AppState) {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let background = state.clone();
    tokio::spawn(async move {
        lumzel_relay::serve(listener, background).await.unwrap();
    });
    (addr, state)
}

async fn post(addr: SocketAddr, path: &str, body: &str) -> u16 {
    let mut stream = TcpStream::connect(addr).await.unwrap();
    let req = format!(
        "POST {path} HTTP/1.1\r\nHost: {addr}\r\nConnection: close\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{body}",
        body.len()
    );
    stream.write_all(req.as_bytes()).await.unwrap();
    let mut buf = Vec::new();
    let _ = timeout(Duration::from_secs(2), stream.read_to_end(&mut buf)).await;
    let text = String::from_utf8_lossy(&buf);
    text.split_whitespace().nth(1).unwrap().parse().unwrap()
}

#[tokio::test]
async fn no_keys_returns_404_and_stores_nothing() {
    let (addr, state) = spawn(AppState::new("local", 1024)).await;
    let status = post(addr, "/push/wake", r#"{"host_id":"h","count":1}"#).await;
    assert_eq!(status, 404);
    assert!(state.push_log().is_empty());
}

#[tokio::test]
async fn fake_key_records_host_id_and_count() {
    let state =
        AppState::new("local", 1024).with_push_sender(Sender::with_fake_key("not-a-credential"));
    let (addr, state) = spawn(state).await;
    let status = post(addr, "/push/wake", r#"{"host_id":"host-push","count":42}"#).await;
    assert_eq!(status, 204);
    let log = state.push_log();
    assert!(log.contains("host-push"));
    assert!(log.contains("42"));
    assert!(!log.contains("diff"));
    assert!(!log.contains('/'));
}

#[tokio::test]
async fn extra_field_is_rejected() {
    let state =
        AppState::new("local", 1024).with_push_sender(Sender::with_fake_key("not-a-credential"));
    let (addr, state) = spawn(state).await;
    let status = post(
        addr,
        "/push/wake",
        r#"{"host_id":"h","count":1,"body":"secret"}"#,
    )
    .await;
    assert_eq!(status, 400);
    assert!(state.push_log().is_empty());
}
