// lumzel:remote-link#relay-stun lumzel:remote-link-06#m-stun lumzel:remote-link-06#a-stun
//! RFC 5389 STUN server listening on UDP.
//! Answers Binding Requests with XOR-MAPPED-ADDRESS using `lumzel_frame::stun`.
//! Supports multiple bind sockets (typically 2 ports to allow NAT type detection)
//! and enforces per-IP rate limiting.

use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use lumzel_frame::stun::binding_success;
use tokio::net::UdpSocket;
use tokio::sync::watch;

const MAGIC: u32 = 0x2112_A442;
const BINDING_REQUEST: u16 = 0x0001;
const HEADER_LEN: usize = 20;
const MAX_TRACKED_IPS: usize = 65_536;
pub const DEFAULT_RATE_LIMIT: u32 = 50;

#[derive(Clone)]
pub struct RateLimiter {
    limit_per_sec: u32,
    records: Arc<Mutex<HashMap<IpAddr, (Instant, u32)>>>,
}

impl RateLimiter {
    pub fn new(limit_per_sec: u32) -> Self {
        Self {
            limit_per_sec,
            records: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    pub fn check_and_inc(&self, ip: IpAddr) -> bool {
        let mut map = match self.records.lock() {
            Ok(g) => g,
            Err(p) => p.into_inner(),
        };
        let now = Instant::now();
        if map.len() > 4096 {
            map.retain(|_, (ts, _)| now.duration_since(*ts) < Duration::from_secs(2));
        }
        if !map.contains_key(&ip) && map.len() >= MAX_TRACKED_IPS {
            return false;
        }
        let entry = map.entry(ip).or_insert((now, 0));
        if now.duration_since(entry.0) >= Duration::from_secs(1) {
            entry.0 = now;
            entry.1 = 1;
            true
        } else if entry.1 < self.limit_per_sec {
            entry.1 += 1;
            true
        } else {
            false
        }
    }
}

pub fn parse_bind_addrs(env_val: &str) -> Vec<SocketAddr> {
    env_val
        .split(',')
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .filter_map(|s| s.parse().ok())
        .collect()
}

pub async fn serve_socket(
    socket: Arc<UdpSocket>,
    limiter: RateLimiter,
    mut stop_rx: watch::Receiver<bool>,
) {
    let mut buf = [0u8; 1024];
    loop {
        tokio::select! {
            _ = stop_rx.changed() => {
                if *stop_rx.borrow() {
                    break;
                }
            }
            res = socket.recv_from(&mut buf) => {
                let (len, peer) = match res {
                    Ok(pair) => pair,
                    Err(_) => continue,
                };
                if len < HEADER_LEN {
                    continue;
                }
                let msg_type = u16::from_be_bytes([buf[0], buf[1]]);
                let msg_len = u16::from_be_bytes([buf[2], buf[3]]) as usize;
                let cookie = u32::from_be_bytes([buf[4], buf[5], buf[6], buf[7]]);
                if msg_type != BINDING_REQUEST || cookie != MAGIC || len < HEADER_LEN + msg_len {
                    continue;
                }
                if !limiter.check_and_inc(peer.ip()) {
                    continue;
                }
                let mut tx_id = [0u8; 12];
                tx_id.copy_from_slice(&buf[8..HEADER_LEN]);
                let reply = binding_success(tx_id, peer);
                let _ = socket.send_to(&reply, peer).await;
            }
        }
    }
}

pub struct StunServer {
    pub addrs: Vec<SocketAddr>,
    _stop: watch::Sender<bool>,
}

impl StunServer {
    pub async fn start(addrs: &[SocketAddr], limit_per_sec: u32) -> std::io::Result<Self> {
        let (stop_tx, _) = watch::channel(false);
        let limiter = RateLimiter::new(limit_per_sec);
        let mut bound_addrs = Vec::new();

        for addr in addrs {
            let socket = UdpSocket::bind(addr).await?;
            let local = socket.local_addr()?;
            bound_addrs.push(local);
            let socket_arc = Arc::new(socket);
            let stop_rx = stop_tx.subscribe();
            let limiter_clone = limiter.clone();
            tokio::spawn(serve_socket(socket_arc, limiter_clone, stop_rx));
        }

        Ok(Self {
            addrs: bound_addrs,
            _stop: stop_tx,
        })
    }

    pub fn stop(&self) {
        let _ = self._stop.send(true);
    }
}
