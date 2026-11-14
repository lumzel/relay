// lumzel:remote-link#relay-mcp lumzel:remote-link-08#m-bot lumzel:remote-link-08#a-mcp lumzel:remote-link-08#a-oauth test:relay/tests/bot.rs
use std::collections::HashMap;
use std::net::SocketAddr;
use std::time::Duration;

use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use futures_util::{SinkExt, StreamExt};
use lumzel_frame::proof::{respond, Challenge};
use lumzel_frame::{host_id, Identity, PublicKey};
use lumzel_relay::AppState;
use serde_json::{json, Value};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
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

fn parse_challenge(msg: &Value) -> Challenge {
    assert_eq!(msg["t"], "challenge");
    let key_b = B64.decode(msg["key"].as_str().unwrap()).unwrap();
    let nonce_b = B64.decode(msg["nonce"].as_str().unwrap()).unwrap();
    Challenge {
        key: PublicKey::from_bytes(&key_b).unwrap(),
        nonce: nonce_b.try_into().unwrap(),
    }
}

async fn register_host(addr: SocketAddr, host: &Identity, bot: bool) -> (Ws, String) {
    let mut ws = ws_connect(addr, "/host").await;
    let ch = parse_challenge(&read_json(&mut ws).await);
    let proof = respond(host.static_secret(), &ch).unwrap();
    let reg = json!({
        "t": "register",
        "host_pub": B64.encode(host.public_key().to_bytes()),
        "proof": B64.encode(proof),
        "bot": bot,
    });
    ws.send(Message::text(reg.to_string())).await.unwrap();
    let reply = read_json(&mut ws).await;
    assert_eq!(reply["t"], "registered");
    let expected = host_id(&host.public_key());
    assert_eq!(reply["host"].as_str().unwrap(), expected);
    (ws, expected)
}

async fn send_http(
    addr: SocketAddr,
    method: &str,
    path: &str,
    headers: &[(&str, &str)],
    body: &[u8],
) -> (u16, HashMap<String, String>, Vec<u8>) {
    let mut stream = TcpStream::connect(addr).await.unwrap();
    let mut req = format!(
        "{method} {path} HTTP/1.1\r\nHost: {addr}\r\nContent-Length: {}\r\nConnection: close\r\n",
        body.len()
    );
    for (k, v) in headers {
        req.push_str(&format!("{k}: {v}\r\n"));
    }
    req.push_str("\r\n");
    let _ = stream.write_all(req.as_bytes()).await;
    if !body.is_empty() {
        let _ = stream.write_all(body).await;
    }
    let _ = stream.flush().await;

    let mut response_bytes = Vec::new();
    let mut buf = [0u8; 4096];
    loop {
        match stream.read(&mut buf).await {
            Ok(0) => break,
            Ok(n) => response_bytes.extend_from_slice(&buf[..n]),
            Err(_) => break,
        }
    }

    parse_http_response(&response_bytes)
}

fn parse_http_response(raw: &[u8]) -> (u16, HashMap<String, String>, Vec<u8>) {
    let text = String::from_utf8_lossy(raw);
    let header_end = text.find("\r\n\r\n").unwrap_or(raw.len());
    let header_part = &text[..header_end];
    let body_part = if header_end + 4 <= raw.len() {
        raw[header_end + 4..].to_vec()
    } else {
        Vec::new()
    };

    let mut lines = header_part.lines();
    let status_line = lines.next().unwrap_or("");
    let status_code = status_line
        .split_whitespace()
        .nth(1)
        .and_then(|s| s.parse::<u16>().ok())
        .unwrap_or(0);

    let mut headers = HashMap::new();
    for line in lines {
        if let Some((k, v)) = line.split_once(':') {
            headers.insert(k.trim().to_ascii_lowercase(), v.trim().to_string());
        }
    }

    (status_code, headers, body_part)
}

#[tokio::test]
async fn unregistered_or_bot_disabled_returns_404_and_unknown_paths_return_404() {
    let (addr, _) = spawn().await;
    let host_identity = Identity::generate();
    let hid = host_id(&host_identity.public_key());

    // 1. Unregistered host -> 404
    let (status, _, _) = send_http(addr, "POST", &format!("/mcp/{hid}"), &[], b"{}").await;
    assert_eq!(status, 404);

    // 2. Host registered with bot: false -> 404
    let (_inbox, _) = register_host(addr, &host_identity, false).await;
    let (status, _, _) = send_http(addr, "POST", &format!("/mcp/{hid}"), &[], b"{}").await;
    assert_eq!(status, 404);

    // 3. Register host with bot: true
    let (_inbox_bot, _) = register_host(addr, &host_identity, true).await;

    // Method not allowed / unknown paths -> 404
    let (status, _, _) = send_http(addr, "GET", &format!("/mcp/{hid}"), &[], b"").await;
    assert_eq!(status, 404);

    let (status, _, _) = send_http(addr, "POST", &format!("/mcp/{hid}/unknown"), &[], b"{}").await;
    assert_eq!(status, 404);

    let (status, _, _) =
        send_http(addr, "POST", &format!("/mcp/{hid}/authorize"), &[], b"{}").await;
    assert_eq!(status, 404);

    let (status, _, _) = send_http(
        addr,
        "GET",
        &format!("/.well-known/unknown/mcp/{hid}"),
        &[],
        b"",
    )
    .await;
    assert_eq!(status, 404);
}

#[tokio::test]
async fn http_request_proxied_to_host_and_response_headers_filtered() {
    let (addr, _) = spawn().await;
    let host_identity = Identity::generate();
    let (mut inbox, hid) = register_host(addr, &host_identity, true).await;

    // Spawn client HTTP request
    let target_hid = hid.clone();
    let client_task = tokio::spawn(async move {
        send_http(
            addr,
            "POST",
            &format!("/mcp/{target_hid}"),
            &[
                ("Authorization", "Bearer test_token"),
                ("Content-Type", "application/json"),
                ("Accept", "application/json"),
                ("X-Custom-Header", "should_be_stripped"),
            ],
            br#"{"jsonrpc":"2.0","method":"tools/list"}"#,
        )
        .await
    });

    // Mock host receives "http" WS message
    let msg = read_json(&mut inbox).await;
    assert_eq!(msg["t"], "http");
    let req_id = msg["id"].as_u64().unwrap();
    assert_eq!(msg["method"], "POST");
    assert_eq!(msg["path"], format!("/mcp/{hid}"));

    // Check header filtering on request: X-Custom-Header must be stripped
    let headers = msg["headers"].as_object().unwrap();
    assert_eq!(headers.get("authorization").unwrap(), "Bearer test_token");
    assert_eq!(headers.get("content-type").unwrap(), "application/json");
    assert_eq!(headers.get("accept").unwrap(), "application/json");
    assert!(headers.get("x-custom-header").is_none());

    // Host responds with http_res
    let reply_body = B64.encode(br#"{"jsonrpc":"2.0","result":{"tools":[]}}"#);
    let reply = json!({
        "t": "http_res",
        "id": req_id,
        "status": 200,
        "headers": {
            "Content-Type": "application/json",
            "Cache-Control": "no-store",
            "X-Secret-Host-Header": "should_be_stripped_on_reply"
        },
        "body": reply_body,
    });
    inbox.send(Message::text(reply.to_string())).await.unwrap();

    // Client receives response
    let (status, res_headers, body) = client_task.await.unwrap();
    assert_eq!(status, 200);
    assert_eq!(res_headers.get("content-type").unwrap(), "application/json");
    assert_eq!(res_headers.get("cache-control").unwrap(), "no-store");
    assert!(!res_headers.contains_key("x-secret-host-header"));

    let body_str = String::from_utf8(body).unwrap();
    assert_eq!(body_str, r#"{"jsonrpc":"2.0","result":{"tools":[]}}"#);
}

#[tokio::test]
async fn body_exceeding_1mib_returns_413() {
    let (addr, _) = spawn().await;
    let host_identity = Identity::generate();
    let (_inbox, hid) = register_host(addr, &host_identity, true).await;

    let oversized = vec![b'a'; 1024 * 1024 + 1];
    let (status, _, _) = send_http(addr, "POST", &format!("/mcp/{hid}"), &[], &oversized).await;
    assert_eq!(status, 413);
}

#[tokio::test]
async fn host_disconnect_returns_504() {
    let (addr, _) = spawn().await;
    let host_identity = Identity::generate();
    let (mut inbox, hid) = register_host(addr, &host_identity, true).await;

    let client_task =
        tokio::spawn(
            async move { send_http(addr, "POST", &format!("/mcp/{hid}"), &[], b"{}").await },
        );

    let _msg = read_json(&mut inbox).await;
    // Host closes without responding
    let _ = inbox.close(None).await;

    let (status, _, _) = client_task.await.unwrap();
    assert_eq!(status, 504);
}

#[tokio::test]
async fn authorize_page_renders_template_with_html_escaped_host_name() {
    let (addr, _) = spawn().await;
    let host_identity = Identity::generate();
    let (mut inbox, hid) = register_host(addr, &host_identity, true).await;

    let target_hid = hid.clone();
    let client_task = tokio::spawn(async move {
        send_http(
            addr,
            "GET",
            &format!("/mcp/{target_hid}/authorize?client_id=chatgpt"),
            &[],
            b"",
        )
        .await
    });

    let msg = read_json(&mut inbox).await;
    assert_eq!(msg["t"], "http");
    let req_id = msg["id"].as_u64().unwrap();
    assert_eq!(msg["method"], "GET");
    assert_eq!(msg["path"], format!("/mcp/{hid}/authorize"));
    assert_eq!(msg["query"], "client_id=chatgpt");

    // Host responds with JSON containing malicious HTML in host_name
    let auth_data = json!({
        "request": "req-123",
        "host_name": "<script>alert('pwn')</script>",
        "user_code": "849201"
    });
    let reply_body = B64.encode(auth_data.to_string().as_bytes());
    let reply = json!({
        "t": "http_res",
        "id": req_id,
        "status": 200,
        "headers": {
            "Content-Type": "application/json"
        },
        "body": reply_body,
    });
    inbox.send(Message::text(reply.to_string())).await.unwrap();

    let (status, res_headers, body) = client_task.await.unwrap();
    assert_eq!(status, 200);
    assert_eq!(
        res_headers.get("content-type").unwrap(),
        "text/html; charset=utf-8"
    );

    let html = String::from_utf8(body).unwrap();
    // Must contain escaped HTML
    assert!(html.contains("&lt;script&gt;alert(&#x27;pwn&#x27;)&lt;/script&gt;"));
    // Must NOT contain raw script tag
    assert!(!html.contains("<script>alert"));
    // Must contain verification code
    assert!(html.contains("849201"));
    // Must contain status poll script
    assert!(html.contains("/mcp/"));
    assert!(html.contains("/authorize/status"));
}

#[tokio::test]
async fn cross_host_http_res_spoofing_is_rejected_and_isolated() {
    let (addr, _) = spawn().await;
    let host_a = Identity::generate();
    let host_b = Identity::generate();
    let (mut inbox_a, hid_a) = register_host(addr, &host_a, true).await;
    let (mut inbox_b, _hid_b) = register_host(addr, &host_b, true).await;

    let target_hid = hid_a.clone();
    let client_task = tokio::spawn(async move {
        send_http(addr, "POST", &format!("/mcp/{target_hid}"), &[], b"{}").await
    });

    let msg = read_json(&mut inbox_a).await;
    let req_id = msg["id"].as_u64().unwrap();

    // Host B attempts to hijack Host A's pending HTTP request id.
    let spoofed = json!({
        "t": "http_res",
        "id": req_id,
        "status": 200,
        "headers": { "Content-Type": "application/json" },
        "body": B64.encode(br#"{"hijacked":true}"#),
    });
    inbox_b
        .send(Message::text(spoofed.to_string()))
        .await
        .unwrap();
    tokio::time::sleep(Duration::from_millis(30)).await;

    // Even disconnecting Host B must not cancel or drop Host A's pending request.
    let _ = inbox_b.close(None).await;
    tokio::time::sleep(Duration::from_millis(30)).await;
    assert!(!client_task.is_finished());

    // Host A answers legitimately.
    let genuine = json!({
        "t": "http_res",
        "id": req_id,
        "status": 200,
        "headers": { "Content-Type": "application/json" },
        "body": B64.encode(br#"{"ok":true}"#),
    });
    inbox_a
        .send(Message::text(genuine.to_string()))
        .await
        .unwrap();

    let (status, _, body) = client_task.await.unwrap();
    assert_eq!(status, 200);
    assert_eq!(String::from_utf8(body).unwrap(), r#"{"ok":true}"#);
}

#[tokio::test]
async fn authorize_template_escapes_js_breakout_and_sets_security_headers() {
    let (addr, _) = spawn().await;
    let host_identity = Identity::generate();
    let (mut inbox, hid) = register_host(addr, &host_identity, true).await;

    let target_hid = hid.clone();
    let client_task = tokio::spawn(async move {
        send_http(
            addr,
            "GET",
            &format!("/mcp/{target_hid}/authorize?client_id=chatgpt"),
            &[],
            b"",
        )
        .await
    });

    let msg = read_json(&mut inbox).await;
    let req_id = msg["id"].as_u64().unwrap();

    let auth_data = json!({
        "request": "req\";</script><script>alert(1)//",
        "host_name": "<img src=x onerror=alert(1)>",
        "user_code": "849201"
    });
    let reply = json!({
        "t": "http_res",
        "id": req_id,
        "status": 200,
        "headers": { "Content-Type": "application/json" },
        "body": B64.encode(auth_data.to_string().as_bytes()),
    });
    inbox.send(Message::text(reply.to_string())).await.unwrap();

    let (status, res_headers, body) = client_task.await.unwrap();
    assert_eq!(status, 200);
    let csp = res_headers.get("content-security-policy").unwrap();
    assert!(csp.contains("default-src 'none'"), "{csp}");
    assert!(csp.contains("script-src 'nonce-"), "{csp}");
    assert!(csp.contains("frame-ancestors 'none'"), "{csp}");
    assert_eq!(res_headers.get("x-frame-options").unwrap(), "DENY");
    assert_eq!(
        res_headers.get("x-content-type-options").unwrap(),
        "nosniff"
    );
    assert_eq!(res_headers.get("referrer-policy").unwrap(), "no-referrer");
    assert_eq!(res_headers.get("cache-control").unwrap(), "no-store");

    let html = String::from_utf8(body).unwrap();
    assert!(!html.contains("</script><script>alert(1)"), "{html}");
    assert!(html.contains("\\u003c\\/script\\u003e"), "{html}");
    assert!(html.contains("encodeURIComponent(hostId)"));
    assert!(html.contains("isSafeRedirect("));
}

#[tokio::test]
async fn authorize_invalid_json_unsafe_content_type_and_bad_base64_are_blocked() {
    let (addr, _) = spawn().await;
    let host_identity = Identity::generate();
    let (mut inbox, hid) = register_host(addr, &host_identity, true).await;

    // 1. /authorize returning non-JSON HTML must return 502, never passthrough raw HTML.
    let target_hid = hid.clone();
    let t1 = tokio::spawn(async move {
        send_http(
            addr,
            "GET",
            &format!("/mcp/{target_hid}/authorize"),
            &[],
            b"",
        )
        .await
    });
    let msg = read_json(&mut inbox).await;
    inbox
        .send(Message::text(
            json!({
                "t": "http_res",
                "id": msg["id"],
                "status": 200,
                "headers": { "Content-Type": "text/html" },
                "body": B64.encode(b"<script>alert(1)</script>"),
            })
            .to_string(),
        ))
        .await
        .unwrap();
    let (status, _, _) = t1.await.unwrap();
    assert_eq!(status, 502);

    // 2. Normal MCP endpoint strips unsafe text/html Content-Type and sets nosniff + X-Frame-Options.
    let target_hid = hid.clone();
    let t2 = tokio::spawn(async move {
        send_http(addr, "POST", &format!("/mcp/{target_hid}"), &[], b"{}").await
    });
    let msg = read_json(&mut inbox).await;
    inbox
        .send(Message::text(
            json!({
                "t": "http_res",
                "id": msg["id"],
                "status": 200,
                "headers": { "Content-Type": "text/html; charset=utf-8" },
                "body": B64.encode(b"ok"),
            })
            .to_string(),
        ))
        .await
        .unwrap();
    let (status, headers, _) = t2.await.unwrap();
    assert_eq!(status, 200);
    assert_eq!(
        headers.get("content-type").map(String::as_str),
        Some("application/octet-stream")
    );
    assert_eq!(headers.get("x-content-type-options").unwrap(), "nosniff");
    assert_eq!(headers.get("x-frame-options").unwrap(), "DENY");

    // 3. Invalid base64 body from Host returns 502 instead of silent empty 200.
    let target_hid = hid.clone();
    let t3 = tokio::spawn(async move {
        send_http(addr, "POST", &format!("/mcp/{target_hid}"), &[], b"{}").await
    });
    let msg = read_json(&mut inbox).await;
    inbox
        .send(Message::text(
            json!({
                "t": "http_res",
                "id": msg["id"],
                "status": 200,
                "headers": { "Content-Type": "application/json" },
                "body": "!!!not-valid-base64!!!",
            })
            .to_string(),
        ))
        .await
        .unwrap();
    let (status, _, _) = t3.await.unwrap();
    assert_eq!(status, 502);
}

#[tokio::test]
async fn http_rate_limit_and_drain_block_bot_endpoints() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let state = AppState::new("local", 1024)
        .with_ops_token("drain-secret")
        .with_limits(lumzel_relay::LimitsConfig {
            http_req_per_sec: 1,
            ..lumzel_relay::LimitsConfig::default()
        });
    let bg = state.clone();
    tokio::spawn(async move {
        lumzel_relay::serve(listener, bg).await.unwrap();
    });

    let host_identity = Identity::generate();
    let (_inbox, hid) = register_host(addr, &host_identity, true).await;

    // Burst is max(rate * 2, 10) = 10; rapid requests beyond burst must receive 429.
    let mut saw_429 = false;
    for _ in 0..16 {
        let (status, _, _) = send_http(
            addr,
            "GET",
            "/.well-known/oauth-protected-resource/mcp/other-host",
            &[],
            b"",
        )
        .await;
        if status == 429 {
            saw_429 = true;
            break;
        }
    }
    assert!(saw_429, "expected 429 from per-IP HTTP rate limiter");

    // Draining returns 503 on Bot HTTP endpoints.
    let (drain_status, _, _) = send_http(
        addr,
        "POST",
        "/drain",
        &[("Authorization", "Bearer drain-secret")],
        b"",
    )
    .await;
    assert_eq!(drain_status, 204);
    let (status, _, _) = send_http(addr, "POST", &format!("/mcp/{hid}"), &[], b"{}").await;
    assert_eq!(status, 503);
}
