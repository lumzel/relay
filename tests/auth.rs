use std::collections::HashMap;
use std::net::SocketAddr;
use std::process::Command;
use std::time::Duration;

use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use futures_util::{SinkExt, StreamExt};
use lumzel_frame::proof::{respond, Challenge};
use lumzel_frame::{host_id, Identity, PublicKey, Session};
use lumzel_relay::{AppState, LimitsConfig, Sender};
use serde_json::{json, Value};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::timeout;
use tokio_tungstenite::tungstenite::client::IntoClientRequest;
use tokio_tungstenite::tungstenite::Message;
use tokio_tungstenite::WebSocketStream;

type Ws = WebSocketStream<TcpStream>;

const SECRET: &str = "priv-relay-s3cr3t+key/2026!";
const INVITE: &str =
    "lumzel://pair?v=2&relay=wss%3A%2F%2Fr.example&host=AAAA&code=00112233445566778899aabbccddeeff";

async fn spawn_state(state: AppState) -> (SocketAddr, AppState) {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let bg = state.clone();
    tokio::spawn(async move {
        lumzel_relay::serve(listener, bg).await.unwrap();
    });
    (addr, state)
}

async fn send_http(
    addr: SocketAddr,
    method: &str,
    path: &str,
    headers: &[(&str, &str)],
    body: &[u8],
) -> (u16, HashMap<String, String>, String) {
    let mut stream = TcpStream::connect(addr).await.unwrap();
    let mut req = format!(
        "{method} {path} HTTP/1.1\r\nHost: {addr}\r\nContent-Length: {}\r\nConnection: close\r\n",
        body.len()
    );
    for (k, v) in headers {
        req.push_str(&format!("{k}: {v}\r\n"));
    }
    req.push_str("\r\n");
    stream.write_all(req.as_bytes()).await.unwrap();
    if !body.is_empty() {
        stream.write_all(body).await.unwrap();
    }
    let mut buf = Vec::new();
    let _ = timeout(Duration::from_secs(2), stream.read_to_end(&mut buf)).await;
    let raw = String::from_utf8_lossy(&buf).into_owned();
    let (head, resp_body) = raw.split_once("\r\n\r\n").unwrap_or((&raw, ""));
    let mut lines = head.lines();
    let status = lines
        .next()
        .unwrap_or("")
        .split_whitespace()
        .nth(1)
        .unwrap()
        .parse::<u16>()
        .unwrap();
    let mut hdrs = HashMap::new();
    for line in lines {
        if let Some((k, v)) = line.split_once(':') {
            hdrs.insert(k.trim().to_ascii_lowercase(), v.trim().to_owned());
        }
    }
    (status, hdrs, resp_body.to_owned())
}

async fn ws_upgrade_status(
    addr: SocketAddr,
    path: &str,
    headers: &[(&str, &str)],
) -> (u16, String) {
    let mut stream = TcpStream::connect(addr).await.unwrap();
    let mut req = format!(
        "GET {path} HTTP/1.1\r\nHost: {addr}\r\nConnection: Upgrade\r\nUpgrade: websocket\r\nSec-WebSocket-Version: 13\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n"
    );
    for (k, v) in headers {
        req.push_str(&format!("{k}: {v}\r\n"));
    }
    req.push_str("\r\n");
    stream.write_all(req.as_bytes()).await.unwrap();
    let mut buf = [0u8; 1024];
    let n = timeout(Duration::from_secs(2), stream.read(&mut buf))
        .await
        .unwrap()
        .unwrap();
    let text = String::from_utf8_lossy(&buf[..n]).into_owned();
    let status = text.split_whitespace().nth(1).unwrap().parse().unwrap();
    (status, text)
}

async fn ws_connect_with_headers(addr: SocketAddr, path: &str, headers: &[(&str, &str)]) -> Ws {
    let tcp = TcpStream::connect(addr).await.unwrap();
    let mut req = format!("ws://{addr}{path}").into_client_request().unwrap();
    for (k, v) in headers {
        let name: tokio_tungstenite::tungstenite::http::HeaderName = k.parse().unwrap();
        req.headers_mut().insert(name, v.parse().unwrap());
    }
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

async fn complete_host_register(mut ws: Ws, identity: &Identity, bot: bool) -> (Ws, String) {
    let ch = parse_challenge(&read_json(&mut ws).await);
    let proof = respond(identity.static_secret(), &ch).unwrap();
    ws.send(Message::text(
        json!({
            "t": "register",
            "host_pub": B64.encode(identity.public_key().to_bytes()),
            "proof": B64.encode(proof),
            "bot": bot,
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

#[tokio::test]
async fn public_mode_without_password_remains_open_and_compatible() {
    // Both default AppState and empty-string with_password("") stay in open mode.
    let state = AppState::new("local", 128).with_password("");
    assert!(!state.is_password_protected());
    let (addr, _) = spawn_state(state).await;

    let (st, _, _) = send_http(addr, "GET", "/health", &[], b"").await;
    assert_eq!(st, 200);
    let (st, _, _) = send_http(addr, "GET", "/ready", &[], b"").await;
    assert_eq!(st, 200);

    // Unauthenticated WebSocket & HTTP endpoints work identically to before.
    let host_id_key = Identity::generate();
    let ws = ws_connect_with_headers(addr, "/host", &[]).await;
    let (_inbox, _) = complete_host_register(ws, &host_id_key, false).await;

    let put_body = json!({ "invite": INVITE }).to_string();
    let (st, _, _) = send_http(
        addr,
        "PUT",
        "/pair-code/ABCD-2345",
        &[("Content-Type", "application/json")],
        put_body.as_bytes(),
    )
    .await;
    assert_eq!(st, 204);

    let (st, _, body) = send_http(addr, "GET", "/pair-code/ABCD-2345", &[], b"").await;
    assert_eq!(st, 200);
    let val: Value = serde_json::from_str(&body).unwrap();
    assert_eq!(val["invite"], INVITE);

    // Unknown paths return 404 (not 401) in public mode.
    let (st, _, _) = send_http(addr, "GET", "/unknown-route", &[], b"").await;
    assert_eq!(st, 404);
}

#[tokio::test]
async fn protected_mode_rejects_unauthenticated_and_wrong_credentials_with_401() {
    let state = AppState::new("local", 128)
        .with_password(SECRET)
        .with_push_sender(Sender::with_fake_key("fake"))
        .with_openai_apps_challenge("challenge-xyz")
        .with_limits(LimitsConfig {
            http_req_per_sec: 0,
            ..LimitsConfig::default()
        });
    assert!(state.is_password_protected());
    let (addr, state) = spawn_state(state).await;

    // Health and readiness probes stay public for container orchestrators.
    for probe in ["/health", "/healthz", "/ready"] {
        let (st, _, _) = send_http(addr, "GET", probe, &[], b"").await;
        assert_eq!(st, 200, "probe {probe} should remain 200");
    }

    // Every WebSocket endpoint rejects missing or wrong credentials BEFORE upgrade (401, not 101).
    for ws_path in ["/host", "/control", "/data", "/pair/room-1"] {
        let (st, raw) = ws_upgrade_status(addr, ws_path, &[]).await;
        assert_eq!(st, 401, "unauthenticated WS {ws_path} must return 401");
        assert!(!raw.contains(SECRET));

        let (st, raw) =
            ws_upgrade_status(addr, ws_path, &[("Authorization", "Bearer wrong-password")]).await;
        assert_eq!(st, 401, "wrong Bearer WS {ws_path} must return 401");
        assert!(!raw.contains(SECRET));

        let (st, raw) = ws_upgrade_status(
            addr,
            ws_path,
            &[("X-Relay-Password", "priv-relay-s3cr3t+key/2026")],
        )
        .await;
        assert_eq!(
            st, 401,
            "near-miss X-Relay-Password on {ws_path} must return 401"
        );
        assert!(!raw.contains(SECRET));

        let (st, raw) = ws_upgrade_status(addr, &format!("{ws_path}?token=wrong"), &[]).await;
        assert_eq!(st, 401, "wrong ?token on {ws_path} must return 401");
        assert!(!raw.contains(SECRET));
    }

    // Every protected HTTP endpoint rejects missing or wrong credentials with 401.
    let put_body = json!({ "invite": INVITE }).to_string();
    let http_cases: &[(&str, &str, &[u8])] = &[
        ("PUT", "/pair-code/ABCD-2345", put_body.as_bytes()),
        ("GET", "/pair-code/ABCD-2345", b""),
        ("POST", "/mcp", b"{}"),
        ("POST", "/mcp/somehost", b"{}"),
        ("POST", "/oauth/register", b"{}"),
        ("GET", "/oauth/authorize", b""),
        ("POST", "/oauth/token", b""),
        ("GET", "/.well-known/oauth-protected-resource", b""),
        ("GET", "/.well-known/openai-apps-challenge", b""),
        ("POST", "/push/wake", br#"{"host_id":"h","count":1}"#),
        ("GET", "/bot/probe", b""),
    ];

    for &(method, path, body) in http_cases {
        let (st, hdrs, resp) = send_http(
            addr,
            method,
            path,
            &[("Content-Type", "application/json")],
            body,
        )
        .await;
        assert_eq!(st, 401, "unauthenticated {method} {path} must return 401");
        assert!(hdrs.contains_key("www-authenticate"));
        assert!(!resp.contains(SECRET));

        let (st, _, resp) = send_http(
            addr,
            method,
            &format!("{path}?password=wrong"),
            &[
                ("Content-Type", "application/json"),
                ("X-Relay-Password", "also-wrong"),
            ],
            body,
        )
        .await;
        assert_eq!(st, 401, "wrong password on {method} {path} must return 401");
        assert!(!resp.contains(SECRET));
    }

    // Debug output of AppState must never leak the password.
    let dbg = format!("{state:?}");
    assert!(!dbg.contains(SECRET));
}

#[tokio::test]
async fn protected_mode_accepts_headers_and_query_params_and_strips_secrets_upstream() {
    let state = AppState::new("local", 128).with_password(SECRET);
    let (addr, _state) = spawn_state(state).await;

    // URL-encoded form of SECRET ("priv-relay-s3cr3t+key/2026!") AND raw '+' form both work.
    let encoded_secret = "priv-relay-s3cr3t%2Bkey%2F2026%21";

    // 1. Pair short-code PUT via Authorization: Bearer, GET via ?password= query param.
    let put_body = json!({ "invite": INVITE }).to_string();
    let (st, _, resp) = send_http(
        addr,
        "PUT",
        "/pair-code/WXYZ-6789",
        &[
            ("Content-Type", "application/json"),
            ("Authorization", &format!("Bearer {SECRET}")),
        ],
        put_body.as_bytes(),
    )
    .await;
    assert_eq!(st, 204);
    assert!(!resp.contains(SECRET));

    let (st, _, resp) = send_http(
        addr,
        "GET",
        &format!("/pair-code/WXYZ-6789?password={encoded_secret}"),
        &[],
        b"",
    )
    .await;
    assert_eq!(st, 200);
    let val: Value = serde_json::from_str(&resp).unwrap();
    assert_eq!(val["invite"], INVITE);
    assert!(!resp.contains(SECRET));

    // 2. Host connects to /host via X-Relay-Password, Peer connects to /control via ?token= (including raw '+'),
    //    Host joins /control via Authorization: Bearer (case-insensitive 'bearer'), and E2EE frames flow!
    let host_identity = Identity::generate();
    let inbox_ws = ws_connect_with_headers(addr, "/host", &[("X-Relay-Password", SECRET)]).await;
    let (mut inbox, hid) = complete_host_register(inbox_ws, &host_identity, true).await;

    let mut peer_ctrl =
        ws_connect_with_headers(addr, &format!("/control?token={SECRET}"), &[]).await;
    peer_ctrl
        .send(Message::text(
            json!({ "type": "link_hello", "v": 2, "host": hid, "sid": "sid-priv" }).to_string(),
        ))
        .await
        .unwrap();

    let waiting = read_json(&mut inbox).await;
    assert_eq!(waiting["t"], "waiting");
    let ticket = waiting["ticket"].as_str().unwrap();

    let mut host_ctrl = ws_connect_with_headers(
        addr,
        "/control",
        &[("Authorization", &format!("bearer {SECRET}"))],
    )
    .await;
    host_ctrl
        .send(Message::text(
            json!({
                "type": "link_hello",
                "v": 2,
                "host": hid,
                "sid": "sid-priv",
                "ticket": ticket,
            })
            .to_string(),
        ))
        .await
        .unwrap();

    let _ = read_json(&mut peer_ctrl).await;
    let _ = read_json(&mut host_ctrl).await;

    let mut s_peer = Session::from_keys([0x11; 32], [0x22; 32], "sid-priv").unwrap();
    let mut s_host = Session::from_keys([0x22; 32], [0x11; 32], "sid-priv").unwrap();
    let sealed = s_peer.seal(&hid, b"private-relay-ok").unwrap();
    peer_ctrl.send(Message::binary(sealed)).await.unwrap();
    match timeout(Duration::from_secs(2), host_ctrl.next()).await {
        Ok(Some(Ok(Message::Binary(got)))) => {
            assert_eq!(s_host.open(&got).unwrap().plaintext, b"private-relay-ok");
        }
        other => panic!("expected binary frame at host, got {other:?}"),
    }

    // Verify /data WebSocket also works with X-Relay-Token and ?relay_password= aliases.
    let mut peer_data =
        ws_connect_with_headers(addr, &format!("/data?relay_password={encoded_secret}"), &[]).await;
    peer_data
        .send(Message::text(
            json!({ "type": "link_hello", "v": 2, "host": hid, "sid": "sid-priv" }).to_string(),
        ))
        .await
        .unwrap();
    let waiting_data = read_json(&mut inbox).await;
    assert_eq!(waiting_data["plane"], "data");
    let data_ticket = waiting_data["ticket"].as_str().unwrap();
    let mut host_data = ws_connect_with_headers(addr, "/data", &[("X-Relay-Token", SECRET)]).await;
    host_data
        .send(Message::text(
            json!({
                "type": "link_hello",
                "v": 2,
                "host": hid,
                "sid": "sid-priv",
                "ticket": data_ticket,
            })
            .to_string(),
        ))
        .await
        .unwrap();
    let _ = read_json(&mut peer_data).await;
    let _ = read_json(&mut host_data).await;

    // 3. Bot MCP request carrying BOTH Bot Bearer token AND Relay password (via ?token= and X-Relay-Password)
    //    succeeds AND strips all Relay credentials before forwarding to Host!
    let bot_tok = format!("lzm_{hid}.bot_access_123");
    let bot_task = tokio::spawn({
        let bot_tok = bot_tok.clone();
        async move {
            send_http(
                addr,
                "POST",
                &format!("/mcp?token={encoded_secret}&keep=1"),
                &[
                    ("Authorization", &format!("Bearer {bot_tok}")),
                    ("X-Relay-Password", SECRET),
                    ("Content-Type", "application/json"),
                ],
                br#"{"jsonrpc":"2.0","id":1,"method":"tools/list"}"#,
            )
            .await
        }
    });

    let proxied = read_json(&mut inbox).await;
    assert_eq!(proxied["t"], "http");
    let proxied_str = proxied.to_string();
    assert!(
        !proxied_str.contains(SECRET) && !proxied_str.contains("priv-relay-s3cr3t"),
        "Relay secret leaked into proxied Host payload: {proxied_str}"
    );
    assert_eq!(proxied["query"], "keep=1");
    assert_eq!(
        proxied["headers"]["authorization"],
        format!("Bearer {bot_tok}")
    );
    assert!(proxied["headers"].get("x-relay-password").is_none());

    inbox
        .send(Message::text(
            json!({
                "t": "http_res",
                "id": proxied["id"],
                "status": 200,
                "headers": { "Content-Type": "application/json" },
                "body": B64.encode(br#"{"ok":true}"#),
            })
            .to_string(),
        ))
        .await
        .unwrap();

    let (st, _, resp_body) = bot_task.await.unwrap();
    assert_eq!(st, 200);
    assert_eq!(resp_body, r#"{"ok":true}"#);

    // 4. Even if caller used Authorization: Bearer <RELAY_SECRET> on /mcp/{hid},
    //    Relay strips that Authorization header so the Relay password never leaks to Host.
    let direct_task = tokio::spawn({
        let hid = hid.clone();
        async move {
            send_http(
                addr,
                "POST",
                &format!("/mcp/{hid}"),
                &[
                    ("Authorization", &format!("Bearer {SECRET}")),
                    ("Content-Type", "application/json"),
                ],
                b"{}",
            )
            .await
        }
    });
    let proxied2 = read_json(&mut inbox).await;
    assert!(
        proxied2["headers"].get("authorization").is_none(),
        "Relay password in Authorization header must not be forwarded to Host"
    );
    inbox
        .send(Message::text(
            json!({
                "t": "http_res",
                "id": proxied2["id"],
                "status": 401,
                "headers": { "Content-Type": "application/json" },
                "body": B64.encode(br#"{"error":"missing_bot_token"}"#),
            })
            .to_string(),
        ))
        .await
        .unwrap();
    let (st2, _, _) = direct_task.await.unwrap();
    assert_eq!(st2, 401);

    // 5. /oauth/authorize HTML host-select page does not echo Relay password into HTML body.
    let (st_html, _, html_body) = send_http(
        addr,
        "GET",
        &format!("/oauth/authorize?client_id=test&token={encoded_secret}"),
        &[],
        b"",
    )
    .await;
    assert_eq!(st_html, 200);
    assert!(!html_body.contains(SECRET));
    assert!(!html_body.contains("priv-relay-s3cr3t"));
}

#[tokio::test]
async fn binary_cli_and_env_password_never_leak_secret_in_logs() {
    let bin = env!("CARGO_BIN_EXE_lumzel-relay");

    // 1. Bind failure with LUMZEL_RELAY_PASSWORD set logs bind error without leaking password.
    let occupied = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let occupied_addr = occupied.local_addr().unwrap();

    let out = Command::new(bin)
        .env("RELAY_BIND", occupied_addr.to_string())
        .env("LUMZEL_RELAY_PASSWORD", SECRET)
        .output()
        .unwrap();
    assert!(!out.status.success());
    let stderr = String::from_utf8_lossy(&out.stderr);
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(!stderr.contains(SECRET), "stderr leaked secret: {stderr}");
    assert!(!stdout.contains(SECRET), "stdout leaked secret: {stdout}");

    // 2. --help exits 0 and documents --password without leaking env password.
    let help = Command::new(bin)
        .arg("--help")
        .env("LUMZEL_RELAY_PASSWORD", SECRET)
        .output()
        .unwrap();
    assert!(help.status.success());
    let help_out = String::from_utf8_lossy(&help.stdout);
    assert!(help_out.contains("--password"));
    assert!(!help_out.contains(SECRET));
}
