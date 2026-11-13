// lumzel:remote-link-03#dw-4 lumzel:remote-link-03#dw-5
use std::net::{IpAddr, SocketAddr};
use std::time::{Duration, Instant};

use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use futures_util::{SinkExt, StreamExt};
use lumzel_frame::proof::{respond, Challenge};
use lumzel_frame::{handshake_frame, host_id, Identity, PublicKey, Session};
use lumzel_relay::{AppState, LimitsConfig, Plane};
use serde_json::{json, Value};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::timeout;
use tokio_tungstenite::tungstenite::client::IntoClientRequest;
use tokio_tungstenite::tungstenite::Message;
use tokio_tungstenite::WebSocketStream;

type Ws = WebSocketStream<TcpStream>;

async fn spawn_with(limits: LimitsConfig) -> (SocketAddr, AppState) {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let state = AppState::new("local", 1024).with_limits(limits);
    let background = state.clone();
    tokio::spawn(async move {
        lumzel_relay::serve(listener, background).await.unwrap();
    });
    (addr, state)
}

async fn ws_connect(addr: SocketAddr, path: &str) -> Ws {
    ws_connect_xff(addr, path, None).await
}

async fn ws_connect_xff(addr: SocketAddr, path: &str, xff: Option<&str>) -> Ws {
    let tcp = TcpStream::connect(addr).await.unwrap();
    let mut req = format!("ws://{addr}{path}").into_client_request().unwrap();
    if let Some(xff_val) = xff {
        req.headers_mut()
            .insert("x-forwarded-for", xff_val.parse().unwrap());
    }
    let (socket, _) = tokio_tungstenite::client_async(req, tcp).await.unwrap();
    socket
}

async fn upgrade_status_xff(addr: SocketAddr, path: &str, xff: Option<&str>) -> u16 {
    let mut stream = TcpStream::connect(addr).await.unwrap();
    let xff_line = match xff {
        Some(v) => format!("X-Forwarded-For: {v}\r\n"),
        None => String::new(),
    };
    let req = format!(
        "GET {path} HTTP/1.1\r\nHost: {addr}\r\n{xff_line}Connection: Upgrade\r\nUpgrade: websocket\r\nSec-WebSocket-Version: 13\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n\r\n"
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

async fn read_json(ws: &mut Ws) -> Value {
    match timeout(Duration::from_secs(2), ws.next()).await {
        Ok(Some(Ok(Message::Text(text)))) => serde_json::from_str(text.as_str()).unwrap(),
        other => panic!("expected text json, got {other:?}"),
    }
}

async fn expect_closed(ws: &mut Ws) {
    loop {
        match timeout(Duration::from_secs(2), ws.next()).await {
            Ok(Some(Ok(Message::Close(_)))) | Ok(Some(Err(_))) | Ok(None) => return,
            Ok(Some(Ok(Message::Ping(_) | Message::Pong(_)))) => continue,
            Ok(Some(Ok(Message::Binary(_) | Message::Text(_)))) => continue,
            Ok(Some(Ok(other))) => panic!("unexpected ws item before close: {other:?}"),
            Err(_) => panic!("timed out waiting for close"),
        }
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

async fn register_host(addr: SocketAddr, host: &Identity) -> (Ws, String) {
    let mut ws = ws_connect(addr, "/host").await;
    let ch = parse_challenge(&read_json(&mut ws).await);
    let proof = respond(host.static_secret(), &ch).unwrap();
    ws.send(Message::text(
        json!({
            "t": "register",
            "host_pub": B64.encode(host.public_key().to_bytes()),
            "proof": B64.encode(proof),
        })
        .to_string(),
    ))
    .await
    .unwrap();
    let reply = read_json(&mut ws).await;
    assert_eq!(reply["t"], "registered");
    (ws, reply["host"].as_str().unwrap().to_owned())
}

async fn pair_plane(
    addr: SocketAddr,
    inbox: &mut Ws,
    hid: &str,
    sid: &str,
    plane: Plane,
) -> (Ws, Ws) {
    let path = match plane {
        Plane::Control => "/control",
        Plane::Data => "/data",
    };
    let mut peer = ws_connect(addr, path).await;
    peer.send(Message::text(
        json!({ "type": "link_hello", "v": 2, "host": hid, "sid": sid }).to_string(),
    ))
    .await
    .unwrap();
    let waiting = read_json(inbox).await;
    assert_eq!(waiting["t"], "waiting");
    assert_eq!(waiting["sid"], sid);
    assert_eq!(waiting["plane"], plane.as_str());
    let ticket = waiting["ticket"].as_str().unwrap();

    let mut host_ws = ws_connect(addr, path).await;
    host_ws
        .send(Message::text(
            json!({
                "type": "link_hello",
                "v": 2,
                "host": hid,
                "sid": sid,
                "ticket": ticket,
            })
            .to_string(),
        ))
        .await
        .unwrap();

    // Drain both link_hello messages.
    let _ = read_json(&mut peer).await;
    let _ = read_json(&mut host_ws).await;
    (peer, host_ws)
}

#[tokio::test]
async fn same_ip_exceeding_max_conns_gets_429_and_releases_on_disconnect() {
    let (addr, _state) = spawn_with(LimitsConfig {
        max_conns_per_ip: 2,
        ..LimitsConfig::default()
    })
    .await;

    let c1 = ws_connect(addr, "/host").await;
    let c2 = ws_connect(addr, "/control").await;

    assert_eq!(upgrade_status_xff(addr, "/control", None).await, 429);
    assert_eq!(upgrade_status_xff(addr, "/data", None).await, 429);
    assert_eq!(upgrade_status_xff(addr, "/host", None).await, 429);

    drop(c1);
    let mut freed = false;
    for _ in 0..50 {
        if upgrade_status_xff(addr, "/control", None).await == 101 {
            freed = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    assert!(freed, "IP slot was not released after socket disconnect");
    drop(c2);
}

#[tokio::test]
async fn trusted_proxy_honors_xff_while_untrusted_peer_ignores_spoofed_xff() {
    // 1. Without RELAY_TRUSTED_PROXY, X-Forwarded-For is ignored so spoofing cannot bypass per-IP cap.
    let (untrusted_addr, _) = spawn_with(LimitsConfig {
        max_conns_per_ip: 1,
        trusted_proxies: Vec::new(),
        ..LimitsConfig::default()
    })
    .await;
    let _u1 = ws_connect_xff(untrusted_addr, "/control", Some("198.51.100.1")).await;
    assert_eq!(
        upgrade_status_xff(untrusted_addr, "/control", Some("198.51.100.2")).await,
        429
    );

    // 2. With 127.0.0.1 in trusted_proxies, leftmost X-Forwarded-For IP is used.
    let (trusted_addr, _) = spawn_with(LimitsConfig {
        max_conns_per_ip: 1,
        trusted_proxies: vec!["127.0.0.1".parse::<IpAddr>().unwrap()],
        ..LimitsConfig::default()
    })
    .await;
    let _t1 = ws_connect_xff(trusted_addr, "/control", Some("198.51.100.10, 10.0.0.1")).await;
    assert_eq!(
        upgrade_status_xff(trusted_addr, "/control", Some("198.51.100.10")).await,
        429
    );
    let _t2 = ws_connect_xff(trusted_addr, "/control", Some("198.51.100.11")).await;
}

#[tokio::test]
async fn over_rate_route_is_throttled_by_backpressure_without_dropping_frames() {
    let (addr, _state) = spawn_with(LimitsConfig {
        route_bytes_per_sec: 40_000,
        ..LimitsConfig::default()
    })
    .await;

    let host = Identity::generate();
    let (mut inbox, hid) = register_host(addr, &host).await;
    let (mut peer_ctrl, mut host_ctrl) =
        pair_plane(addr, &mut inbox, &hid, "sid-rate", Plane::Control).await;
    let (mut peer_data, mut host_data) =
        pair_plane(addr, &mut inbox, &hid, "sid-rate", Plane::Data).await;

    // Host sends one handshake frame on each plane so handshake deadline is satisfied.
    host_ctrl
        .send(Message::binary(
            handshake_frame(&hid, "sid-rate", &[0u8; 32]).unwrap(),
        ))
        .await
        .unwrap();
    let _ = peer_ctrl.next().await.unwrap().unwrap();
    host_data
        .send(Message::binary(
            handshake_frame(&hid, "sid-rate", &[0u8; 32]).unwrap(),
        ))
        .await
        .unwrap();
    let _ = peer_data.next().await.unwrap().unwrap();

    let mut ctrl_sender = Session::from_keys([0x11; 32], [0x22; 32], "sid-rate").unwrap();
    let mut ctrl_receiver = Session::from_keys([0x22; 32], [0x11; 32], "sid-rate").unwrap();
    let mut data_sender = Session::from_keys([0x33; 32], [0x44; 32], "sid-rate").unwrap();
    let mut data_receiver = Session::from_keys([0x44; 32], [0x33; 32], "sid-rate").unwrap();

    // Send 8 frames x ~2,500B (~20,500B combined across /control and /data on the same route).
    // At 40,000 B/s with a small burst, this must take ~400ms+ and drop 0 frames.
    let start = Instant::now();
    for i in 0u8..4 {
        let pt = vec![i; 2_500];
        peer_ctrl
            .send(Message::binary(ctrl_sender.seal(&hid, &pt).unwrap()))
            .await
            .unwrap();
        peer_data
            .send(Message::binary(data_sender.seal(&hid, &pt).unwrap()))
            .await
            .unwrap();
    }

    for i in 0u8..4 {
        let want = vec![i; 2_500];
        let Some(Ok(Message::Binary(c_frame))) = timeout(Duration::from_secs(3), host_ctrl.next())
            .await
            .unwrap()
        else {
            panic!("missing control frame {i}");
        };
        assert_eq!(ctrl_receiver.open(&c_frame).unwrap().plaintext, want);

        let Some(Ok(Message::Binary(d_frame))) = timeout(Duration::from_secs(3), host_data.next())
            .await
            .unwrap()
        else {
            panic!("missing data frame {i}");
        };
        assert_eq!(data_receiver.open(&d_frame).unwrap().plaintext, want);
    }
    let elapsed = start.elapsed();
    assert!(
        elapsed >= Duration::from_millis(350),
        "route was not throttled near rate cap: elapsed {elapsed:?}"
    );
}

#[tokio::test]
async fn exceeding_route_bytes_total_disconnects_route() {
    let (addr, state) = spawn_with(LimitsConfig {
        route_bytes_total: 2_000,
        ..LimitsConfig::default()
    })
    .await;

    let host = Identity::generate();
    let (mut inbox, hid) = register_host(addr, &host).await;
    let (mut peer_ctrl, mut host_ctrl) =
        pair_plane(addr, &mut inbox, &hid, "sid-total", Plane::Control).await;
    let (mut peer_data, mut host_data) =
        pair_plane(addr, &mut inbox, &hid, "sid-total", Plane::Data).await;

    let mut ctrl_sender = Session::from_keys([0x11; 32], [0x22; 32], "sid-total").unwrap();
    let mut ctrl_receiver = Session::from_keys([0x22; 32], [0x11; 32], "sid-total").unwrap();
    let mut data_sender = Session::from_keys([0x33; 32], [0x44; 32], "sid-total").unwrap();

    // First 600B on /control fits under the 2,000B shared cap.
    let f1 = ctrl_sender.seal(&hid, &[0xaa; 600]).unwrap();
    peer_ctrl.send(Message::binary(f1)).await.unwrap();
    match timeout(Duration::from_secs(2), host_ctrl.next()).await {
        Ok(Some(Ok(Message::Binary(got)))) => {
            assert_eq!(ctrl_receiver.open(&got).unwrap().plaintext.len(), 600);
        }
        other => panic!("expected first frame under total cap, got {other:?}"),
    }

    // Sending 1,600B on /data pushes combined route total (/control + /data) past 2,000B -> disconnects route.
    let f2 = data_sender.seal(&hid, &[0xbb; 1_600]).unwrap();
    let _ = peer_data.send(Message::binary(f2)).await;

    expect_closed(&mut peer_data).await;
    expect_closed(&mut host_data).await;
    expect_closed(&mut peer_ctrl).await;
    expect_closed(&mut host_ctrl).await;

    for _ in 0..50 {
        if state.connection_count(&hid, "sid-total", Plane::Control) == 0
            && state.connection_count(&hid, "sid-total", Plane::Data) == 0
        {
            return;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    panic!("route slots were not released after exceeding route_bytes_total");
}

#[tokio::test]
async fn handshake_timeout_closes_peer_when_host_sends_no_frame_and_frees_slot() {
    let (addr, state) = spawn_with(LimitsConfig {
        handshake_timeout: Duration::from_millis(150),
        ..LimitsConfig::default()
    })
    .await;

    let host = Identity::generate();
    let (mut inbox, hid) = register_host(addr, &host).await;
    assert_eq!(hid, host_id(&host.public_key()));

    // 1. Peer sends hello, Host never sends a frame -> Peer closed after ~150ms, slot freed.
    let mut stalled_peer = ws_connect(addr, "/control").await;
    stalled_peer
        .send(Message::text(
            json!({ "type": "link_hello", "v": 2, "host": hid, "sid": "sid-hs" }).to_string(),
        ))
        .await
        .unwrap();
    let _unused_waiting = read_json(&mut inbox).await;

    expect_closed(&mut stalled_peer).await;
    for _ in 0..50 {
        if state.connection_count(&hid, "sid-hs", Plane::Control) == 0 {
            break;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    assert_eq!(state.connection_count(&hid, "sid-hs", Plane::Control), 0);

    // 2. Slot is free: a new Peer joins the same sid, Host responds with a handshake frame in time,
    //    and the connection stays alive well past handshake_timeout (300ms > 150ms).
    let (mut active_peer, mut active_host) =
        pair_plane(addr, &mut inbox, &hid, "sid-hs", Plane::Control).await;
    let hs = handshake_frame(&hid, "sid-hs", &[0x42; 48]).unwrap();
    active_host.send(Message::binary(hs.clone())).await.unwrap();
    match timeout(Duration::from_secs(2), active_peer.next()).await {
        Ok(Some(Ok(Message::Binary(got)))) => assert_eq!(&got[..], hs.as_slice()),
        other => panic!("expected handshake frame at peer, got {other:?}"),
    }

    tokio::time::sleep(Duration::from_millis(260)).await;
    assert_eq!(state.connection_count(&hid, "sid-hs", Plane::Control), 2);
}
