// lumzel:remote-link-06#dw-5 lumzel:remote-link-06#a-stun
use std::net::SocketAddr;
use std::time::Duration;

use lumzel_frame::stun::{binding_request, parse_xor_mapped};
use lumzel_relay::stun::{parse_bind_addrs, StunServer};
use tokio::net::UdpSocket;
use tokio::time::timeout;

#[tokio::test]
async fn relay_stun_answers_on_both_ports_with_mapped_address() {
    let addrs: Vec<SocketAddr> = vec![
        "127.0.0.1:0".parse().unwrap(),
        "127.0.0.1:0".parse().unwrap(),
    ];
    let server = StunServer::start(&addrs, 100).await.unwrap();
    assert_eq!(server.addrs.len(), 2);
    assert_ne!(server.addrs[0].port(), server.addrs[1].port());

    let client = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let client_addr = client.local_addr().unwrap();

    // Query port 1
    let tx1 = [1u8, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12];
    client
        .send_to(&binding_request(tx1), server.addrs[0])
        .await
        .unwrap();

    let mut buf = [0u8; 1024];
    let (n, from) = timeout(Duration::from_millis(500), client.recv_from(&mut buf))
        .await
        .expect("port 1 should reply")
        .unwrap();
    assert_eq!(from, server.addrs[0]);
    let (mapped_ip, mapped_port) = parse_xor_mapped(&buf[..n], tx1).unwrap();
    assert_eq!(mapped_ip, client_addr.ip());
    assert_eq!(mapped_port, client_addr.port());

    // Query port 2 with same client socket (same local port)
    let tx2 = [2u8, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13];
    client
        .send_to(&binding_request(tx2), server.addrs[1])
        .await
        .unwrap();

    let (n2, from2) = timeout(Duration::from_millis(500), client.recv_from(&mut buf))
        .await
        .expect("port 2 should reply")
        .unwrap();
    assert_eq!(from2, server.addrs[1]);
    let (mapped_ip2, mapped_port2) = parse_xor_mapped(&buf[..n2], tx2).unwrap();
    assert_eq!(mapped_ip2, client_addr.ip());
    assert_eq!(mapped_port2, client_addr.port());

    server.stop();
}

#[tokio::test]
async fn relay_stun_rate_limits_per_ip() {
    let addrs: Vec<SocketAddr> = vec!["127.0.0.1:0".parse().unwrap()];
    // Rate limit of 3 per second
    let server = StunServer::start(&addrs, 3).await.unwrap();

    let client = UdpSocket::bind("127.0.0.1:0").await.unwrap();

    let mut buf = [0u8; 1024];
    for i in 0..3 {
        let tx = [i as u8; 12];
        client
            .send_to(&binding_request(tx), server.addrs[0])
            .await
            .unwrap();
        let res = timeout(Duration::from_millis(300), client.recv_from(&mut buf)).await;
        assert!(res.is_ok(), "request {i} within limit should succeed");
    }

    // 4th request exceeds rate limit, dropped silently
    let tx4 = [99u8; 12];
    client
        .send_to(&binding_request(tx4), server.addrs[0])
        .await
        .unwrap();
    let res4 = timeout(Duration::from_millis(200), client.recv_from(&mut buf)).await;
    assert!(res4.is_err(), "request exceeding limit should be dropped");

    server.stop();
}

#[test]
fn relay_stun_parse_bind_addrs() {
    let empty = parse_bind_addrs("");
    assert!(empty.is_empty());

    let single = parse_bind_addrs("127.0.0.1:3478");
    assert_eq!(single.len(), 1);
    assert_eq!(single[0], "127.0.0.1:3478".parse().unwrap());

    let two = parse_bind_addrs("0.0.0.0:3478, 0.0.0.0:3479");
    assert_eq!(two.len(), 2);
    assert_eq!(two[0], "0.0.0.0:3478".parse().unwrap());
    assert_eq!(two[1], "0.0.0.0:3479".parse().unwrap());
}
