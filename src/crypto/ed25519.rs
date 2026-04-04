/*
 * fialka-core — Cross-platform cryptographic core for Fialka
 * Copyright (C) 2024-2026 DevBot667 — GPL-3.0
 */

//! Ed25519 key generation, signing, and verification.
//!
//! Byte-for-byte compatible with BouncyCastle Ed25519 usage in:
//!   Android: CryptoManager.kt — Ed25519PrivateKeyParameters, Ed25519Signer
//!
//! Key encoding:
//!   - Private key raw = 32-byte seed (same as BouncyCastle .encoded)
//!   - Public key raw  = 32-byte compressed point (same as BouncyCastle .encoded)
//!
//! Signature: 64 bytes, deterministic (RFC 8032 §5.1.6).

use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};

/// An Ed25519 key pair derived from a 32-byte seed.
pub struct Ed25519KeyPair {
    signing_key: SigningKey,
}

impl Ed25519KeyPair {
    /// Create from a 32-byte Ed25519 seed.
    /// Matches: `Ed25519PrivateKeyParameters(seed, 0)` in BouncyCastle.
    pub fn from_seed(seed: &[u8; 32]) -> Self {
        Self {
            signing_key: SigningKey::from_bytes(seed),
        }
    }

    /// Raw 32-byte Ed25519 public key.
    /// Matches: `ed25519Private.generatePublicKey().encoded` in BouncyCastle.
    pub fn public_key_bytes(&self) -> [u8; 32] {
        self.signing_key.verifying_key().to_bytes()
    }

    /// Sign arbitrary data. Returns 64-byte signature.
    /// Matches: `Ed25519Signer.generateSignature(data)` in BouncyCastle.
    pub fn sign(&self, data: &[u8]) -> [u8; 64] {
        self.signing_key.sign(data).to_bytes()
    }
}

/// Verify an Ed25519 signature.
/// Matches: `Ed25519Signer.verifySignature(data, signature)` in BouncyCastle.
pub fn verify(public_key_bytes: &[u8; 32], data: &[u8], signature_bytes: &[u8; 64]) -> bool {
    let Ok(vk) = VerifyingKey::from_bytes(public_key_bytes) else {
        return false;
    };
    let sig = Signature::from_bytes(signature_bytes);
    vk.verify(data, &sig).is_ok()
}

/// Build the signed data blob for a Fialka message signature.
/// Matches: `CryptoManager.buildSignedData(ciphertextBase64, conversationId, createdAt)`.
///
/// Format: ciphertext_utf8 || conversationId_utf8 || createdAt_big_endian_8_bytes
pub fn build_signed_data(
    ciphertext_base64: &str,
    conversation_id: &str,
    created_at_millis: i64,
) -> Vec<u8> {
    let ct_bytes   = ciphertext_base64.as_bytes();
    let conv_bytes = conversation_id.as_bytes();
    let ts_bytes   = created_at_millis.to_be_bytes();
    let mut out = Vec::with_capacity(ct_bytes.len() + conv_bytes.len() + 8);
    out.extend_from_slice(ct_bytes);
    out.extend_from_slice(conv_bytes);
    out.extend_from_slice(&ts_bytes);
    out
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    const SEED: [u8; 32] = [
        0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,
        0x08,0x09,0x0a,0x0b,0x0c,0x0d,0x0e,0x0f,
        0x10,0x11,0x12,0x13,0x14,0x15,0x16,0x17,
        0x18,0x19,0x1a,0x1b,0x1c,0x1d,0x1e,0x1f,
    ];

    /// Ed25519 public key derivation is deterministic.
    #[test]
    fn test_pubkey_deterministic() {
        let kp1 = Ed25519KeyPair::from_seed(&SEED);
        let kp2 = Ed25519KeyPair::from_seed(&SEED);
        assert_eq!(kp1.public_key_bytes(), kp2.public_key_bytes());
    }

    /// Public key changes when seed changes.
    #[test]
    fn test_pubkey_seed_sensitivity() {
        let mut other_seed = SEED;
        other_seed[0] ^= 0x01;
        let kp1 = Ed25519KeyPair::from_seed(&SEED);
        let kp2 = Ed25519KeyPair::from_seed(&other_seed);
        assert_ne!(kp1.public_key_bytes(), kp2.public_key_bytes());
    }

    /// Standard Ed25519 test vector — RFC 8032 §6.1 Test Vector 1.
    /// seed = 9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60
    /// pub  = d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a
    /// msg  = (empty)
    /// sig  = e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e06522490155...
    /// Note: seed last two bytes are 7f60 (not 3d55 — that was a typo).
    #[test]
    fn test_sign_rfc8032_vector1() {
        let seed_hex = "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60";
        let expected_pub = "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a";
        let expected_sig_prefix = "e5564300c360ac729086e2cc806e828a";

        let seed_bytes: [u8; 32] = hex::decode(seed_hex).unwrap().try_into().unwrap();
        let kp  = Ed25519KeyPair::from_seed(&seed_bytes);
        let pub_bytes = kp.public_key_bytes();
        assert_eq!(hex::encode(pub_bytes), expected_pub, "pubkey mismatch");

        let sig = kp.sign(b"");
        assert!(hex::encode(sig).starts_with(expected_sig_prefix), "sig prefix mismatch");
    }

    /// Sign → Verify roundtrip with arbitrary message.
    #[test]
    fn test_sign_verify_roundtrip() {
        let kp  = Ed25519KeyPair::from_seed(&SEED);
        let msg = b"Fialka secure message test";
        let sig = kp.sign(msg);
        let pub_bytes = kp.public_key_bytes();
        assert!(verify(&pub_bytes, msg, &sig), "valid signature must verify");
    }

    /// Tampered message must fail verification.
    #[test]
    fn test_verify_wrong_message() {
        let kp  = Ed25519KeyPair::from_seed(&SEED);
        let sig = kp.sign(b"hello");
        let pub_bytes = kp.public_key_bytes();
        assert!(!verify(&pub_bytes, b"HELLO", &sig), "wrong message must not verify");
    }

    /// Wrong public key must fail verification.
    #[test]
    fn test_verify_wrong_pubkey() {
        let kp1 = Ed25519KeyPair::from_seed(&SEED);
        let mut other_seed = SEED;
        other_seed[31] ^= 0xFF;
        let kp2 = Ed25519KeyPair::from_seed(&other_seed);
        let sig = kp1.sign(b"data");
        assert!(!verify(&kp2.public_key_bytes(), b"data", &sig));
    }

    /// Signature is deterministic (RFC 8032 §5.1.6).
    #[test]
    fn test_sign_deterministic() {
        let kp = Ed25519KeyPair::from_seed(&SEED);
        let msg = b"determinism check";
        assert_eq!(kp.sign(msg), kp.sign(msg));
    }

    /// build_signed_data timestamp bytes are big-endian.
    #[test]
    fn test_build_signed_data_be_timestamp() {
        let ts_millis: i64 = 0x0102030405060708;
        let data = build_signed_data("ct", "conv", ts_millis);
        // Last 8 bytes = big-endian timestamp
        assert_eq!(&data[data.len()-8..], &[0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08]);
    }
}
