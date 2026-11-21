// lumzel:remote-link#invite
use std::net::SocketAddr;

use lumzel_relay::AppState;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

const INVITE: &str =
    "lumzel://pair?v=2&relay=wss%3A%2F%2Fr.example&host=AAAA&code=00112233445566778899aabbccddeeff";

async fn spawn() -> SocketAddr {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        lumzel_relay::serve(listener, AppState::new("local", 64))
            .await
            .unwrap();
    });
    addr
}

/// One raw HTTP/1.1 exchange: returns the status code and the body.
async fn http(addr: SocketAddr, method: &str, path: &str, body: Option<&str>) -> (u16, String) {
    let mut tcp = TcpStream::connect(addr).await.unwrap();
    let body = body.unwrap_or("");
    let req = format!(
        "{method} {path} HTTP/1.1\r\nhost: x\r\nconnection: close\r\ncontent-type: application/json\r\ncontent-length: {}\r\n\r\n{body}",
        body.len()
    );
    tcp.write_all(req.as_bytes()).await.unwrap();
    let mut raw = String::new();
    tcp.read_to_string(&mut raw).await.unwrap();
    let status = raw.split_whitespace().nth(1).unwrap().parse().unwrap();
    let body = raw.split("\r\n\r\n").nth(1).unwrap_or("").to_owned();
    (status, body)
}

fn put_body() -> String {
    serde_json::json!({ "invite": INVITE }).to_string()
}

#[tokio::test]
async fn short_code_resolves_once_then_is_gone() {
    let addr = spawn().await;
    let (status, _) = http(addr, "PUT", "/pair-code/ABCD-2345", Some(&put_body())).await;
    assert_eq!(status, 204);

    // Case, dashes and spaces do not matter to the Peer.
    let (status, body) = http(addr, "GET", "/pair-code/abcd2345", None).await;
    assert_eq!(status, 200);
    let json: serde_json::Value = serde_json::from_str(&body).unwrap();
    assert_eq!(json["invite"], INVITE);

    let (status, _) = http(addr, "GET", "/pair-code/ABCD-2345", None).await;
    assert_eq!(status, 404, "a short code is single-use");
}

#[tokio::test]
async fn short_code_rejects_bad_input_and_duplicates() {
    let addr = spawn().await;
    let (status, _) = http(addr, "PUT", "/pair-code/ABCD-2345", Some(&put_body())).await;
    assert_eq!(status, 204);
    let (status, _) = http(addr, "PUT", "/pair-code/ABCD-2345", Some(&put_body())).await;
    assert_eq!(status, 409, "a live code is never overwritten");

    let (status, _) = http(addr, "PUT", "/pair-code/ABC", Some(&put_body())).await;
    assert_eq!(status, 400, "wrong length");
    let (status, _) = http(addr, "PUT", "/pair-code/ABCD-0O1I", Some(&put_body())).await;
    assert_eq!(status, 400, "characters outside the alphabet");
    let bad = serde_json::json!({ "invite": "https://example.com/phish" }).to_string();
    let (status, _) = http(addr, "PUT", "/pair-code/WXYZ-2345", Some(&bad)).await;
    assert_eq!(status, 400, "only v=2 pair invites are stored");
    let (status, _) = http(addr, "GET", "/pair-code/WXYZ-2345", None).await;
    assert_eq!(status, 404);
}

#[test]
fn normalize_accepts_loose_input() {
    assert_eq!(
        lumzel_relay::shortcode::normalize(" abcd 2345 ").as_deref(),
        Some("ABCD-2345")
    );
    assert_eq!(lumzel_relay::shortcode::normalize("ABCD-234"), None);
    assert_eq!(lumzel_relay::shortcode::normalize("ABCD-234I"), None);
}

#[tokio::test]
async fn short_code_miss_budget_is_isolated_per_ip() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let state = AppState::new("local", 64).with_limits(lumzel_relay::LimitsConfig {
        http_req_per_sec: 0,
        trusted_proxies: vec!["127.0.0.1".parse().unwrap()],
        ..lumzel_relay::LimitsConfig::default()
    });
    tokio::spawn(async move {
        lumzel_relay::serve(listener, state).await.unwrap();
    });

    async fn http_xff(
        addr: SocketAddr,
        method: &str,
        path: &str,
        xff: &str,
        body: Option<&str>,
    ) -> (u16, String) {
        let mut tcp = TcpStream::connect(addr).await.unwrap();
        let body = body.unwrap_or("");
        let req = format!(
            "{method} {path} HTTP/1.1\r\nhost: x\r\nx-forwarded-for: {xff}\r\nconnection: close\r\ncontent-type: application/json\r\ncontent-length: {}\r\n\r\n{body}",
            body.len()
        );
        tcp.write_all(req.as_bytes()).await.unwrap();
        let mut raw = String::new();
        tcp.read_to_string(&mut raw).await.unwrap();
        let status = raw.split_whitespace().nth(1).unwrap().parse().unwrap();
        let body = raw.split("\r\n\r\n").nth(1).unwrap_or("").to_owned();
        (status, body)
    }

    // Legitimate Host registers a valid short code.
    let (status, _) = http_xff(
        addr,
        "PUT",
        "/pair-code/BCDE-2345",
        "198.51.100.1",
        Some(&put_body()),
    )
    .await;
    assert_eq!(status, 204);

    // Attacker IP exhausts its per-IP miss budget.
    let mut attacker_throttled = false;
    for _ in 0..35 {
        let (st, _) = http_xff(addr, "GET", "/pair-code/ZZZZ-9999", "203.0.113.99", None).await;
        if st == 429 {
            attacker_throttled = true;
            break;
        }
    }
    assert!(
        attacker_throttled,
        "attacker IP must hit 429 on repeated misses"
    );

    // Legitimate Peer on another IP can still resolve its valid code without DoS!
    let (st, body) = http_xff(addr, "GET", "/pair-code/BCDE-2345", "198.51.100.2", None).await;
    assert_eq!(st, 200);
    let json: serde_json::Value = serde_json::from_str(&body).unwrap();
    assert_eq!(json["invite"], INVITE);
}
