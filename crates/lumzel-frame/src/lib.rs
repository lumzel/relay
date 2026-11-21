// lumzel:mobile-companion#crate-frame lumzel:remote-link-02#m-frame
//! v2 wire frame shared by both ends of a Host link.
//! The header (magic, version, host, sid, sequence) is readable without a key.
//! A transport frame (n >= 1) carries ChaCha20-Poly1305 ciphertext under the keys of
//! one handshake. A handshake frame (n = 0) carries one Noise message. This crate
//! does not run the handshake: `lumzel-link` does, and hands the keys to `Session`.

use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{ChaCha20Poly1305, Nonce};
use rand::rngs::OsRng;
use sha2::{Digest, Sha256};
use x25519_dalek::PublicKey as DalekPublic;
use x25519_dalek::StaticSecret as DalekSecret;

pub mod proof;
pub mod stun;

const MAGIC: &[u8; 6] = b"LUMZEL";
const VERSION: u8 = 2;
const MIN_ID: usize = 1;
const MAX_ID: usize = 256;
const TAG_LEN: usize = 16;

/// Library error. Display text never includes keys or plaintext.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("truncated frame")]
    Truncated,
    #[error("bad magic")]
    BadMagic,
    #[error("unsupported version")]
    BadVersion,
    #[error("host length out of range")]
    BadHostLen,
    #[error("sid length out of range")]
    BadSidLen,
    #[error("host is not utf-8")]
    BadUtf8Host,
    #[error("sid is not utf-8")]
    BadUtf8Sid,
    #[error("ciphertext truncated")]
    TruncatedCiphertext,
    #[error("replay or reordered sequence")]
    Replay,
    #[error("aead rejected the frame")]
    Aead,
    #[error("sid does not match this session")]
    SidMismatch,
    #[error("send sequence exhausted")]
    SequenceExhausted,
    #[error("a handshake frame carries no ciphertext")]
    Handshake,
    #[error("key must be 32 bytes")]
    BadKeyLength,
    #[error("non-contributory public key")]
    LowOrderKey,
}

pub type Result<T> = std::result::Result<T, Error>;

/// Static X25519 secret. `Debug` redacts the scalar.
pub struct StaticSecret {
    pub(crate) inner: DalekSecret,
}

impl std::fmt::Debug for StaticSecret {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("StaticSecret([redacted])")
    }
}

impl StaticSecret {
    pub fn generate() -> Self {
        let rng = OsRng;
        Self {
            inner: DalekSecret::random_from_rng(rng),
        }
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        let bytes: [u8; 32] = bytes.try_into().map_err(|_| Error::BadKeyLength)?;
        Ok(Self {
            inner: DalekSecret::from(bytes),
        })
    }

    pub fn to_bytes(&self) -> [u8; 32] {
        self.inner.to_bytes()
    }

    pub fn public_key(&self) -> PublicKey {
        PublicKey {
            inner: DalekPublic::from(&self.inner),
        }
    }
}

/// X25519 public key. `Debug` redacts the point.
#[derive(Clone, PartialEq, Eq)]
pub struct PublicKey {
    pub(crate) inner: DalekPublic,
}

impl std::fmt::Debug for PublicKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("PublicKey([redacted])")
    }
}

impl PublicKey {
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        let bytes: [u8; 32] = bytes.try_into().map_err(|_| Error::BadKeyLength)?;
        Ok(Self {
            inner: DalekPublic::from(bytes),
        })
    }

    pub fn to_bytes(&self) -> [u8; 32] {
        self.inner.to_bytes()
    }

    /// True for the few points that make every Diffie-Hellman result the same. A peer
    /// holding one as its "public key" proves nothing in a handshake, so refuse it.
    pub fn is_low_order(&self) -> bool {
        // Any clamped scalar clears the cofactor, so one fixed scalar finds them all.
        !DalekSecret::from([0x42u8; 32])
            .diffie_hellman(&self.inner)
            .was_contributory()
    }
}

/// One endpoint's static key pair.
pub struct Identity {
    secret: StaticSecret,
}

impl std::fmt::Debug for Identity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Identity([redacted])")
    }
}

impl Identity {
    pub fn generate() -> Self {
        Self {
            secret: StaticSecret::generate(),
        }
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        Ok(Self {
            secret: StaticSecret::from_bytes(bytes)?,
        })
    }

    pub fn to_bytes(&self) -> [u8; 32] {
        self.secret.to_bytes()
    }

    pub fn static_secret(&self) -> &StaticSecret {
        &self.secret
    }

    pub fn public_key(&self) -> PublicKey {
        self.secret.public_key()
    }
}

const HOST_ID_BYTES: usize = 20;
const BASE32: &[u8; 32] = b"abcdefghijklmnopqrstuvwxyz234567";

// lumzel:remote-link-02#m-hostid lumzel:remote-link-03#a-register
/// The id a Host is routed by: the first 20 bytes of SHA-256 over its static public
/// key, in lowercase base32. 32 characters, so it fits a URL path and a DNS label, and
/// nobody can claim it without the key it was computed from.
pub fn host_id(host_pub: &PublicKey) -> String {
    let digest = Sha256::digest(host_pub.to_bytes());
    let mut out = String::with_capacity(HOST_ID_BYTES * 8 / 5);
    let (mut buffer, mut bits) = (0u32, 0u32);
    for byte in &digest[..HOST_ID_BYTES] {
        buffer = (buffer << 8) | u32::from(*byte);
        bits += 8;
        while bits >= 5 {
            bits -= 5;
            out.push(BASE32[((buffer >> bits) & 0x1f) as usize] as char);
        }
    }
    out
}

/// Header a Relay can read without the session key. No plaintext.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Header {
    pub v: u8,
    pub host: String,
    pub sid: String,
    pub n: u64,
}

impl Header {
    /// n = 0 marks a handshake frame. A transport frame never uses it.
    pub fn is_handshake(&self) -> bool {
        self.n == 0
    }
}

/// Bytes recovered from a frame. `Debug` omits plaintext.
pub struct Opened {
    pub host: String,
    pub sid: String,
    pub n: u64,
    pub plaintext: Vec<u8>,
}

impl std::fmt::Debug for Opened {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Opened")
            .field("host", &self.host)
            .field("sid", &self.sid)
            .field("n", &self.n)
            .field("plaintext_len", &self.plaintext.len())
            .finish()
    }
}

// lumzel:remote-link#ar-caps
/// Which end of a handshake this is. The initiator dials and sends the first message;
/// the responder answers. A Host is the responder to every peer that dials it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Role {
    Initiator,
    Responder,
}

// lumzel:mobile-companion#crate-frame lumzel:remote-link-02#m-frame
/// One connection's transport keys. Send and receive sequence counters are independent
/// and start at zero: the keys are new for every handshake, so the counters are too.
/// Keys are omitted from `Debug`.
pub struct Session {
    send_key: [u8; 32],
    recv_key: [u8; 32],
    sid: String,
    send_n: u64,
    recv_n: u64,
}

impl std::fmt::Debug for Session {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Session")
            .field("sid", &self.sid)
            .field("send_n", &self.send_n)
            .field("recv_n", &self.recv_n)
            .finish()
    }
}

impl Session {
    /// A session over the two direction keys one handshake produced. This end seals
    /// under `send_key` and opens under `recv_key`; the other end holds them swapped.
    /// The keys must come from a fresh handshake: a pair that was used before repeats nonces.
    pub fn from_keys(send_key: [u8; 32], recv_key: [u8; 32], sid: &str) -> Result<Self> {
        check_id(sid.as_bytes(), Error::BadSidLen)?;
        Ok(Self {
            send_key,
            recv_key,
            sid: sid.to_owned(),
            send_n: 0,
            recv_n: 0,
        })
    }

    pub fn sid(&self) -> &str {
        &self.sid
    }

    /// Frames sealed so far.
    pub fn sent(&self) -> u64 {
        self.send_n
    }

    /// The sequence number of the last frame opened.
    pub fn received(&self) -> u64 {
        self.recv_n
    }

    /// Seal `plaintext` for `host`. The first frame on this session uses n = 1.
    pub fn seal(&mut self, host: &str, plaintext: &[u8]) -> Result<Vec<u8>> {
        check_id(host.as_bytes(), Error::BadHostLen)?;
        let n = self.send_n.checked_add(1).ok_or(Error::SequenceExhausted)?;
        let header = header_bytes(host, &self.sid, n)?;
        let ct = self
            .cipher(&self.send_key)?
            .encrypt(
                Nonce::from_slice(&nonce_for(n)),
                Payload {
                    msg: plaintext,
                    aad: &header,
                },
            )
            .map_err(|_| Error::Aead)?;
        self.send_n = n;
        let mut frame = header;
        frame.extend_from_slice(&ct);
        Ok(frame)
    }

    /// Open a frame. Rejects n == 0 and any n <= the last accepted n.
    pub fn open(&mut self, frame: &[u8]) -> Result<Opened> {
        let (header, header_len) = split_header(frame)?;
        let ct = &frame[header_len..];
        if ct.len() < TAG_LEN {
            return Err(Error::TruncatedCiphertext);
        }
        if header.sid != self.sid {
            return Err(Error::SidMismatch);
        }
        if header.n == 0 || header.n <= self.recv_n {
            return Err(Error::Replay);
        }
        let plaintext = self
            .cipher(&self.recv_key)?
            .decrypt(
                Nonce::from_slice(&nonce_for(header.n)),
                Payload {
                    msg: ct,
                    aad: &frame[..header_len],
                },
            )
            .map_err(|_| Error::Aead)?;
        self.recv_n = header.n;
        Ok(Opened {
            host: header.host,
            sid: header.sid,
            n: header.n,
            plaintext,
        })
    }

    fn cipher(&self, key: &[u8; 32]) -> Result<ChaCha20Poly1305> {
        ChaCha20Poly1305::new_from_slice(key).map_err(|_| Error::Aead)
    }
}

/// Read v, host, sid, and n. Does not take a key and does not return plaintext.
pub fn parse_header(frame: &[u8]) -> Result<Header> {
    Ok(split_header(frame)?.0)
}

/// Byte length of what follows the header: ciphertext with its 16-byte AEAD tag, or a
/// Noise message. Fewer than 16 bytes here is neither.
pub fn ciphertext_len(frame: &[u8]) -> Result<usize> {
    let (_, header_len) = split_header(frame)?;
    Ok(frame.len() - header_len)
}

// lumzel:remote-link-02#a-hs-frame
/// Wrap one Noise message in a handshake frame: the usual header with n = 0, then the
/// message. A Relay routes it like any frame; `Session::open` refuses it.
pub fn handshake_frame(host: &str, sid: &str, message: &[u8]) -> Result<Vec<u8>> {
    let mut frame = header_bytes(host, sid, 0)?;
    frame.extend_from_slice(message);
    Ok(frame)
}

/// The Noise message of a handshake frame, with its header. A transport frame is an error.
pub fn handshake_message(frame: &[u8]) -> Result<(Header, &[u8])> {
    let (header, header_len) = split_header(frame)?;
    if !header.is_handshake() {
        return Err(Error::Handshake);
    }
    Ok((header, &frame[header_len..]))
}

fn check_id(bytes: &[u8], err: Error) -> Result<()> {
    if bytes.is_empty() || bytes.len() > MAX_ID {
        Err(err)
    } else {
        Ok(())
    }
}

fn header_bytes(host: &str, sid: &str, n: u64) -> Result<Vec<u8>> {
    let host_b = host.as_bytes();
    let sid_b = sid.as_bytes();
    check_id(host_b, Error::BadHostLen)?;
    check_id(sid_b, Error::BadSidLen)?;
    let mut out = Vec::with_capacity(MAGIC.len() + 1 + 2 + host_b.len() + 2 + sid_b.len() + 8);
    out.extend_from_slice(MAGIC);
    out.push(VERSION);
    out.extend_from_slice(&(host_b.len() as u16).to_be_bytes());
    out.extend_from_slice(host_b);
    out.extend_from_slice(&(sid_b.len() as u16).to_be_bytes());
    out.extend_from_slice(sid_b);
    out.extend_from_slice(&n.to_be_bytes());
    Ok(out)
}

fn split_header(frame: &[u8]) -> Result<(Header, usize)> {
    if frame.len() < MAGIC.len() {
        return Err(Error::Truncated);
    }
    if &frame[..MAGIC.len()] != MAGIC {
        return Err(Error::BadMagic);
    }
    let v = *frame.get(MAGIC.len()).ok_or(Error::Truncated)?;
    if v != VERSION {
        return Err(Error::BadVersion);
    }
    let mut i = MAGIC.len() + 1;
    let host_len = read_u16(frame, i)? as usize;
    i += 2;
    if !(MIN_ID..=MAX_ID).contains(&host_len) {
        return Err(Error::BadHostLen);
    }
    let host_b = frame.get(i..i + host_len).ok_or(Error::Truncated)?;
    i += host_len;
    let host = std::str::from_utf8(host_b)
        .map_err(|_| Error::BadUtf8Host)?
        .to_owned();

    let sid_len = read_u16(frame, i)? as usize;
    i += 2;
    if !(MIN_ID..=MAX_ID).contains(&sid_len) {
        return Err(Error::BadSidLen);
    }
    let sid_b = frame.get(i..i + sid_len).ok_or(Error::Truncated)?;
    i += sid_len;
    let sid = std::str::from_utf8(sid_b)
        .map_err(|_| Error::BadUtf8Sid)?
        .to_owned();

    let n_b = frame.get(i..i + 8).ok_or(Error::Truncated)?;
    let mut n_bytes = [0u8; 8];
    n_bytes.copy_from_slice(n_b);
    let n = u64::from_be_bytes(n_bytes);
    i += 8;
    Ok((Header { v, host, sid, n }, i))
}

fn read_u16(frame: &[u8], i: usize) -> Result<u16> {
    let b = frame.get(i..i + 2).ok_or(Error::Truncated)?;
    Ok(u16::from_be_bytes([b[0], b[1]]))
}

/// Nonce is 4 zero bytes followed by n as a big-endian u64.
fn nonce_for(n: u64) -> [u8; 12] {
    let mut nonce = [0u8; 12];
    nonce[4..].copy_from_slice(&n.to_be_bytes());
    nonce
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key(seed: u8) -> [u8; 32] {
        let mut key = [seed; 32];
        key[0] ^= 0x5a;
        key
    }

    /// Two ends over the same pair of direction keys, as a handshake would leave them.
    fn pair(sid: &str) -> (Session, Session) {
        let send = Session::from_keys(key(1), key(2), sid).unwrap();
        let recv = Session::from_keys(key(2), key(1), sid).unwrap();
        (send, recv)
    }

    #[test]
    fn both_directions_share_n() {
        let (mut host, mut phone) = pair("sid");
        let from_host = host.seal("h", b"same").unwrap();
        let from_phone = phone.seal("h", b"same").unwrap();
        assert_eq!(parse_header(&from_host).unwrap().n, 1);
        assert_eq!(
            parse_header(&from_phone).unwrap(),
            parse_header(&from_host).unwrap()
        );
        assert_ne!(from_host, from_phone);
        assert_eq!(phone.open(&from_host).unwrap().plaintext, b"same");
        assert_eq!(host.open(&from_phone).unwrap().plaintext, b"same");
        assert_eq!((host.sent(), host.received()), (1, 1));
    }

    #[test]
    fn roundtrip() {
        let a = Identity::generate();
        let restored = Identity::from_bytes(&a.to_bytes()).unwrap();
        assert_eq!(a.public_key().to_bytes(), restored.public_key().to_bytes());

        let (mut send, mut recv) = pair("sid-1");
        let frame = send.seal("host-1", b"hello").unwrap();
        assert_eq!(&frame[..MAGIC.len()], b"LUMZEL");
        assert_eq!(frame[MAGIC.len()], 2);
        let opened = recv.open(&frame).unwrap();
        assert_eq!(opened.plaintext, b"hello");
        assert_eq!(opened.host, "host-1");
        assert_eq!(opened.sid, "sid-1");
        assert_eq!(opened.n, 1);
        let again = send.seal("host-1", b"next").unwrap();
        let opened = recv.open(&again).unwrap();
        assert_eq!(opened.n, 2);
        assert_eq!(opened.plaintext, b"next");
    }

    #[test]
    fn low_order_points_are_told_apart_from_real_keys() {
        assert!(PublicKey::from_bytes(&[0u8; 32]).unwrap().is_low_order());
        let mut one = [0u8; 32];
        one[0] = 1;
        assert!(PublicKey::from_bytes(&one).unwrap().is_low_order());
        // A point of order 8, from RFC 7748's list of values to reject.
        let order8: [u8; 32] = [
            0xe0, 0xeb, 0x7a, 0x7c, 0x3b, 0x41, 0xb8, 0xae, 0x16, 0x56, 0xe3, 0xfa, 0xf1, 0x9f,
            0xc4, 0x6a, 0xda, 0x09, 0x8d, 0xeb, 0x9c, 0x32, 0xb1, 0xfd, 0x86, 0x62, 0x05, 0x16,
            0x5f, 0x49, 0xb8, 0x00,
        ];
        assert!(PublicKey::from_bytes(&order8).unwrap().is_low_order());
        assert!(!Identity::generate().public_key().is_low_order());
    }

    #[test]
    fn a_v1_frame_is_refused_at_the_header() {
        let v1 = craft_v(1, b"h", b"s", 1, &[0u8; 16]);
        assert!(matches!(parse_header(&v1), Err(Error::BadVersion)));
        assert!(matches!(ciphertext_len(&v1), Err(Error::BadVersion)));
        let (_, mut recv) = pair("s");
        assert!(matches!(recv.open(&v1), Err(Error::BadVersion)));
    }

    #[test]
    fn relay_header_ignores_ciphertext() {
        let (mut send, mut recv) = pair("chan");
        let mut frame = send.seal("host", b"body").unwrap();
        let header = parse_header(&frame).unwrap();
        assert_eq!(header.v, 2);
        assert_eq!(header.host, "host");
        assert_eq!(header.sid, "chan");
        assert_eq!(header.n, 1);
        assert!(!header.is_handshake());
        let last = frame.len() - 1;
        frame[last] ^= 0xff;
        let header = parse_header(&frame).unwrap();
        assert_eq!(header.n, 1);
        assert!(recv.open(&frame).is_err());
        frame[last] ^= 0xff;
        let opened = recv.open(&frame).unwrap();
        assert_eq!(opened.plaintext, b"body");
    }

    #[test]
    fn replay_and_backwards() {
        let (mut send, mut recv) = pair("s");
        let first = send.seal("h", b"one").unwrap();
        let second = send.seal("h", b"two").unwrap();
        assert_eq!(recv.open(&first).unwrap().n, 1);
        assert!(recv.open(&first).is_err());
        assert_eq!(recv.open(&second).unwrap().plaintext, b"two");
        assert!(recv.open(&first).is_err());
        let zero = craft(b"h", b"s", 0, &[0u8; 16]);
        assert!(recv.open(&zero).is_err());
    }

    #[test]
    fn a_handshake_frame_carries_a_message_and_never_opens_as_transport() {
        let message = [7u8; 48];
        let frame = handshake_frame("host", "sid", &message).unwrap();
        let header = parse_header(&frame).unwrap();
        assert!(header.is_handshake());
        assert_eq!((header.host.as_str(), header.sid.as_str()), ("host", "sid"));
        // A Relay's "at least 16 bytes after the header" check lets it through.
        assert_eq!(ciphertext_len(&frame).unwrap(), 48);
        let (header, body) = handshake_message(&frame).unwrap();
        assert_eq!(header.n, 0);
        assert_eq!(body, message);

        let (mut send, mut recv) = pair("sid");
        assert!(matches!(recv.open(&frame), Err(Error::Replay)));
        let transport = send.seal("host", b"x").unwrap();
        assert!(matches!(
            handshake_message(&transport),
            Err(Error::Handshake)
        ));
    }

    #[test]
    fn wrong_key() {
        let mut send = Session::from_keys(key(1), key(2), "s").unwrap();
        let mut recv = Session::from_keys(key(2), key(3), "s").unwrap();
        let frame = send.seal("h", b"nope").unwrap();
        assert!(matches!(recv.open(&frame), Err(Error::Aead)));
        // A frame that failed does not move the counter: the real one still opens.
        let mut right = Session::from_keys(key(2), key(1), "s").unwrap();
        assert_eq!(right.open(&frame).unwrap().plaintext, b"nope");
    }

    #[test]
    fn replay_fixture_20k() {
        let (mut send, mut recv) = pair("gap");
        let started = std::time::Instant::now();
        let mut frames = Vec::with_capacity(20_000);
        for i in 0..20_000u32 {
            frames.push(send.seal("h", &i.to_be_bytes()).unwrap());
        }
        for (i, frame) in frames.iter().enumerate() {
            let opened = recv.open(frame).unwrap();
            assert_eq!(opened.n, (i as u64) + 1);
            assert_eq!(opened.plaintext, (i as u32).to_be_bytes());
            assert_eq!(opened.host, "h");
            assert_eq!(opened.sid, "gap");
        }
        let max_secs = if cfg!(debug_assertions) { 10 } else { 2 };
        assert!(
            started.elapsed().as_secs() < max_secs,
            "20k replay took {:?}",
            started.elapsed()
        );
    }

    #[test]
    fn rejects_id_lengths() {
        let (mut send, _) = pair("s");
        assert!(matches!(send.seal("", b"x"), Err(Error::BadHostLen)));
        assert!(matches!(
            send.seal(&"a".repeat(257), b"x"),
            Err(Error::BadHostLen)
        ));
        let ok = send.seal("a", b"x").unwrap();
        assert_eq!(parse_header(&ok).unwrap().n, 1);
        assert!(send.seal(&"a".repeat(256), b"y").is_ok());

        assert!(matches!(
            Session::from_keys(key(1), key(2), ""),
            Err(Error::BadSidLen)
        ));
        assert!(matches!(
            Session::from_keys(key(1), key(2), &"b".repeat(257)),
            Err(Error::BadSidLen)
        ));
        assert!(Session::from_keys(key(1), key(2), "b").is_ok());
        assert!(Session::from_keys(key(1), key(2), &"b".repeat(256)).is_ok());

        assert!(matches!(
            parse_header(&craft(b"", b"s", 1, &[])),
            Err(Error::BadHostLen)
        ));
        assert!(matches!(
            parse_header(&craft(&vec![b'a'; 257], b"s", 1, &[])),
            Err(Error::BadHostLen)
        ));
        assert!(matches!(
            parse_header(&craft(b"h", b"", 1, &[])),
            Err(Error::BadSidLen)
        ));
        assert!(matches!(
            parse_header(&craft(b"h", &vec![b'b'; 257], 1, &[])),
            Err(Error::BadSidLen)
        ));
    }

    fn craft(host: &[u8], sid: &[u8], n: u64, ct: &[u8]) -> Vec<u8> {
        craft_v(2, host, sid, n, ct)
    }

    fn craft_v(v: u8, host: &[u8], sid: &[u8], n: u64, ct: &[u8]) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(b"LUMZEL");
        out.push(v);
        out.extend_from_slice(&(host.len() as u16).to_be_bytes());
        out.extend_from_slice(host);
        out.extend_from_slice(&(sid.len() as u16).to_be_bytes());
        out.extend_from_slice(sid);
        out.extend_from_slice(&n.to_be_bytes());
        out.extend_from_slice(ct);
        out
    }
}
