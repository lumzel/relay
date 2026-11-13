// lumzel:mobile-companion#t-punch
//! Minimal RFC 5389 Binding request and XOR-MAPPED-ADDRESS.
//! The magic cookie is `0x2112A442`. IPv4 is XORed with the cookie.
//! IPv6 is XORed with the cookie followed by the 96-bit transaction id.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

const MAGIC: u32 = 0x2112_A442;
const BINDING_REQUEST: u16 = 0x0001;
const BINDING_SUCCESS: u16 = 0x0101;
const XOR_MAPPED_ADDRESS: u16 = 0x0020;
const FAMILY_IPV4: u8 = 0x01;
const FAMILY_IPV6: u8 = 0x02;
const HEADER_LEN: usize = 20;

/// A Binding message was truncated, had the wrong cookie or transaction id, or no XOR-MAPPED-ADDRESS.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Error;

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("bad stun")
    }
}

impl std::error::Error for Error {}

pub type Result<T> = std::result::Result<T, Error>;

/// Binding request. No attributes. `tx_id` is copied into bytes 8..20.
pub fn binding_request(tx_id: [u8; 12]) -> Vec<u8> {
    header(BINDING_REQUEST, 0, tx_id).to_vec()
}

/// Binding success with one XOR-MAPPED-ADDRESS for `addr`. Test servers use this as the reply.
pub fn binding_success(tx_id: [u8; 12], addr: SocketAddr) -> Vec<u8> {
    let value = encode_xor(addr, &tx_id);
    let mut out = header(BINDING_SUCCESS, (4 + value.len()) as u16, tx_id).to_vec();
    out.extend_from_slice(&XOR_MAPPED_ADDRESS.to_be_bytes());
    out.extend_from_slice(&(value.len() as u16).to_be_bytes());
    out.extend_from_slice(&value);
    out
}

/// Read `(ip, port)` from a Binding success. The transaction id must match `tx_id`.
pub fn parse_xor_mapped(response: &[u8], tx_id: [u8; 12]) -> Result<(IpAddr, u16)> {
    if response.len() < HEADER_LEN {
        return Err(Error);
    }
    let msg_type = u16::from_be_bytes([response[0], response[1]]);
    let msg_len = u16::from_be_bytes([response[2], response[3]]) as usize;
    let cookie = u32::from_be_bytes([response[4], response[5], response[6], response[7]]);
    if msg_type != BINDING_SUCCESS || cookie != MAGIC || response[8..HEADER_LEN] != tx_id {
        return Err(Error);
    }
    let end = HEADER_LEN.checked_add(msg_len).ok_or(Error)?;
    if response.len() < end {
        return Err(Error);
    }
    let mut i = HEADER_LEN;
    while i + 4 <= end {
        let attr = u16::from_be_bytes([response[i], response[i + 1]]);
        let len = u16::from_be_bytes([response[i + 2], response[i + 3]]) as usize;
        let value_at = i + 4;
        if value_at + len > end {
            return Err(Error);
        }
        if attr == XOR_MAPPED_ADDRESS {
            return decode_xor(&response[value_at..value_at + len], &tx_id);
        }
        let padded = (len + 3) & !3;
        i = value_at + padded;
    }
    Err(Error)
}

fn header(msg_type: u16, length: u16, tx_id: [u8; 12]) -> [u8; HEADER_LEN] {
    let mut out = [0u8; HEADER_LEN];
    out[0..2].copy_from_slice(&msg_type.to_be_bytes());
    out[2..4].copy_from_slice(&length.to_be_bytes());
    out[4..8].copy_from_slice(&MAGIC.to_be_bytes());
    out[8..].copy_from_slice(&tx_id);
    out
}

fn encode_xor(addr: SocketAddr, tx_id: &[u8; 12]) -> Vec<u8> {
    match addr.ip() {
        IpAddr::V4(ip) => {
            let mut value = [0u8; 8];
            value[1] = FAMILY_IPV4;
            value[2..4].copy_from_slice(&(addr.port() ^ xor_port()).to_be_bytes());
            let xaddr = u32::from(ip) ^ MAGIC;
            value[4..8].copy_from_slice(&xaddr.to_be_bytes());
            value.to_vec()
        }
        IpAddr::V6(ip) => {
            let mut value = [0u8; 20];
            value[1] = FAMILY_IPV6;
            value[2..4].copy_from_slice(&(addr.port() ^ xor_port()).to_be_bytes());
            let mut xaddr = ip.octets();
            xor_ipv6(&mut xaddr, tx_id);
            value[4..].copy_from_slice(&xaddr);
            value.to_vec()
        }
    }
}

fn decode_xor(value: &[u8], tx_id: &[u8; 12]) -> Result<(IpAddr, u16)> {
    if value.len() < 4 {
        return Err(Error);
    }
    let family = value[1];
    let port = u16::from_be_bytes([value[2], value[3]]) ^ xor_port();
    match family {
        FAMILY_IPV4 if value.len() == 8 => {
            let raw = u32::from_be_bytes([value[4], value[5], value[6], value[7]]);
            Ok((IpAddr::V4(Ipv4Addr::from(raw ^ MAGIC)), port))
        }
        FAMILY_IPV6 if value.len() == 20 => {
            let mut octets = [0u8; 16];
            octets.copy_from_slice(&value[4..20]);
            xor_ipv6(&mut octets, tx_id);
            Ok((IpAddr::V6(Ipv6Addr::from(octets)), port))
        }
        _ => Err(Error),
    }
}

fn xor_port() -> u16 {
    (MAGIC >> 16) as u16
}

fn xor_ipv6(octets: &mut [u8; 16], tx_id: &[u8; 12]) {
    let mut mask = [0u8; 16];
    mask[..4].copy_from_slice(&MAGIC.to_be_bytes());
    mask[4..].copy_from_slice(tx_id);
    for (byte, mask_byte) in octets.iter_mut().zip(mask) {
        *byte ^= mask_byte;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn request_is_a_header() {
        let tx = [7u8; 12];
        let pkt = binding_request(tx);
        assert_eq!(pkt.len(), 20);
        assert_eq!(&pkt[0..2], &BINDING_REQUEST.to_be_bytes());
        assert_eq!(&pkt[2..4], &[0, 0]);
        assert_eq!(&pkt[4..8], &MAGIC.to_be_bytes());
        assert_eq!(&pkt[8..], &tx);
    }

    #[test]
    fn xor_mapped_v4_and_v6_roundtrip() {
        let tx = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12];
        let v4: SocketAddr = "203.0.113.9:443".parse().unwrap();
        let v6: SocketAddr = "[2001:db8::1]:2000".parse().unwrap();
        for addr in [v4, v6] {
            let pkt = binding_success(tx, addr);
            let (ip, port) = parse_xor_mapped(&pkt, tx).unwrap();
            assert_eq!(SocketAddr::new(ip, port), addr);
            assert!(parse_xor_mapped(&pkt, [0u8; 12]).is_err());
        }
        let raw = binding_success(tx, v4);
        assert_ne!(&raw[28..32], &Ipv4Addr::new(203, 0, 113, 9).octets());
    }

    #[test]
    fn skips_a_padded_attribute_before_the_mapped_address() {
        let tx = [9u8; 12];
        let addr: SocketAddr = "198.51.100.20:54321".parse().unwrap();
        let mut msg = binding_success(tx, addr);
        let old_len = u16::from_be_bytes([msg[2], msg[3]]);
        msg[2..4].copy_from_slice(&(old_len + 8).to_be_bytes());
        let mut out = msg[..HEADER_LEN].to_vec();
        out.extend_from_slice(&[0x80, 0x22, 0x00, 0x01, b'a', 0, 0, 0]);
        out.extend_from_slice(&msg[HEADER_LEN..]);
        let (ip, port) = parse_xor_mapped(&out, tx).unwrap();
        assert_eq!(SocketAddr::new(ip, port), addr);
        assert!(parse_xor_mapped(&binding_request(tx), tx).is_err());
    }
}
