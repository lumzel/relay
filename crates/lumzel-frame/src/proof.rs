// lumzel:remote-link-03#m-proof lumzel:remote-link-03#a-proof
//! Diffie-Hellman challenge-response proof of holding a Host's X25519 static secret.
//! Both `lumzel-link` (the Host) and `lumzel-relay` (the verifier) share these routines.

use rand::rngs::OsRng;
use rand::RngCore;
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;

use crate::{Error, PublicKey, Result, StaticSecret};

const PROOF_INFO: &[u8] = b"lumzel-host-proof/1";

/// A fresh Relay challenge: an ephemeral X25519 public key and a 32-byte nonce.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Challenge {
    pub key: PublicKey,
    pub nonce: [u8; 32],
}

// lumzel:remote-link-03#a-proof
/// Generate a fresh ephemeral X25519 key pair and 32-byte random nonce for one `/host` session.
pub fn challenge() -> (StaticSecret, Challenge) {
    let secret = StaticSecret::generate();
    let key = secret.public_key();
    let mut nonce = [0u8; 32];
    OsRng.fill_bytes(&mut nonce);
    (secret, Challenge { key, nonce })
}

// lumzel:remote-link-03#a-proof
/// Compute the Host's 32-byte proof for `challenge`. Refuses low-order challenge keys.
pub fn respond(host_secret: &StaticSecret, challenge: &Challenge) -> Result<[u8; 32]> {
    let shared = host_secret.inner.diffie_hellman(&challenge.key.inner);
    if !shared.was_contributory() {
        return Err(Error::LowOrderKey);
    }
    Ok(hkdf_sha256(shared.as_bytes(), &challenge.nonce, PROOF_INFO))
}

// lumzel:remote-link-03#a-proof
/// Verify `proof` in constant time against `host_pub` and the Relay's ephemeral secret.
/// Refuses low-order public keys.
pub fn verify(
    relay_secret: &StaticSecret,
    challenge: &Challenge,
    host_pub: &PublicKey,
    proof: &[u8; 32],
) -> bool {
    let shared = relay_secret.inner.diffie_hellman(&host_pub.inner);
    if !shared.was_contributory() {
        return false;
    }
    let expected = hkdf_sha256(shared.as_bytes(), &challenge.nonce, PROOF_INFO);
    bool::from(expected.ct_eq(proof))
}

/// RFC 5869 HKDF-SHA256 expanding to 32 bytes (`L = HashLen`).
fn hkdf_sha256(ikm: &[u8], salt: &[u8], info: &[u8]) -> [u8; 32] {
    let effective_salt = if salt.is_empty() { &[0u8; 32] } else { salt };
    let prk = hmac_sha256(effective_salt, &[ikm]);
    hmac_sha256(&prk, &[info, &[0x01]])
}

/// RFC 2104 HMAC-SHA256.
fn hmac_sha256(key: &[u8], parts: &[&[u8]]) -> [u8; 32] {
    let mut key_block = [0u8; 64];
    if key.len() > 64 {
        let hashed = Sha256::digest(key);
        key_block[..32].copy_from_slice(&hashed);
    } else {
        key_block[..key.len()].copy_from_slice(key);
    }
    let mut ipad = [0x36u8; 64];
    let mut opad = [0x5cu8; 64];
    for i in 0..64 {
        ipad[i] ^= key_block[i];
        opad[i] ^= key_block[i];
    }
    let mut inner = Sha256::new();
    inner.update(ipad);
    for part in parts {
        inner.update(part);
    }
    let inner_digest = inner.finalize();

    let mut outer = Sha256::new();
    outer.update(opad);
    outer.update(inner_digest);
    outer.finalize().into()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Identity;

    #[test]
    fn hkdf_matches_rfc5869_sha256_test_case_1() {
        // RFC 5869 Appendix A.1 Test Case 1 (first 32 octets of OKM = T(1)).
        let ikm = [0x0bu8; 22];
        let salt: [u8; 13] = [
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c,
        ];
        let info: [u8; 10] = [0xf0, 0xf1, 0xf2, 0xf3, 0xf4, 0xf5, 0xf6, 0xf7, 0xf8, 0xf9];
        let expected: [u8; 32] = [
            0x3c, 0xb2, 0x5f, 0x25, 0xfa, 0xac, 0xd5, 0x7a, 0x90, 0x43, 0x4f, 0x64, 0xd0, 0x36,
            0x2f, 0x2a, 0x2d, 0x2d, 0x0a, 0x90, 0xcf, 0x1a, 0x5a, 0x4c, 0x5d, 0xb0, 0x2d, 0x56,
            0xec, 0xc4, 0xc5, 0xbf,
        ];
        assert_eq!(hkdf_sha256(&ikm, &salt, &info), expected);
    }

    #[test]
    fn respond_and_verify_roundtrip_and_reject_wrong_secret() {
        let host = Identity::generate();
        let impostor = Identity::generate();
        let (relay_secret, ch) = challenge();

        let proof = respond(host.static_secret(), &ch).unwrap();
        assert!(verify(&relay_secret, &ch, &host.public_key(), &proof));

        // Same proof presented for a different public key fails.
        assert!(!verify(&relay_secret, &ch, &impostor.public_key(), &proof));

        // Proof computed with another private key fails against the real Host's public key.
        let wrong_proof = respond(impostor.static_secret(), &ch).unwrap();
        assert_ne!(proof, wrong_proof);
        assert!(!verify(
            &relay_secret,
            &ch,
            &host.public_key(),
            &wrong_proof
        ));

        // Tampering a single bit in the proof fails verification.
        let mut tampered = proof;
        tampered[31] ^= 0x01;
        assert!(!verify(&relay_secret, &ch, &host.public_key(), &tampered));
    }

    #[test]
    fn different_nonces_produce_different_proofs() {
        let host = Identity::generate();
        let (relay_secret, ch_a) = challenge();
        let (_, ch_b_fresh) = challenge();
        assert_ne!(ch_a.nonce, ch_b_fresh.nonce);

        let mut ch_b = ch_a.clone();
        ch_b.nonce[0] ^= 0xff;

        let proof_a = respond(host.static_secret(), &ch_a).unwrap();
        let proof_b = respond(host.static_secret(), &ch_b).unwrap();
        assert_ne!(proof_a, proof_b);

        // Proof bound to ch_a does not pass under ch_b even with the same Relay key.
        assert!(!verify(&relay_secret, &ch_b, &host.public_key(), &proof_a));
        assert!(verify(&relay_secret, &ch_b, &host.public_key(), &proof_b));
    }

    #[test]
    fn low_order_public_keys_are_rejected_on_both_ends() {
        let host = Identity::generate();
        let (relay_secret, ch) = challenge();
        let valid_proof = respond(host.static_secret(), &ch).unwrap();

        // RFC 7748 order-8 point and all-zero point.
        let order8: [u8; 32] = [
            0xe0, 0xeb, 0x7a, 0x7c, 0x3b, 0x41, 0xb8, 0xae, 0x16, 0x56, 0xe3, 0xfa, 0xf1, 0x9f,
            0xc4, 0x6a, 0xda, 0x09, 0x8d, 0xeb, 0x9c, 0x32, 0xb1, 0xfd, 0x86, 0x62, 0x05, 0x16,
            0x5f, 0x49, 0xb8, 0x00,
        ];
        for bad in [[0u8; 32], order8] {
            let low_pub = PublicKey::from_bytes(&bad).unwrap();
            let bad_challenge = Challenge {
                key: low_pub.clone(),
                nonce: ch.nonce,
            };
            assert!(matches!(
                respond(host.static_secret(), &bad_challenge),
                Err(Error::LowOrderKey)
            ));
            assert!(!verify(&relay_secret, &ch, &low_pub, &[0u8; 32]));
            assert!(!verify(&relay_secret, &ch, &low_pub, &valid_proof));
        }
    }
}
