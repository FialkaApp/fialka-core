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
    let ct_bytes = ciphertext_base64.as_bytes();
    let conv_bytes = conversation_id.as_bytes();
    let ts_bytes = created_at_millis.to_be_bytes(); // big-endian 8 bytes
    let mut out = Vec::with_capacity(ct_bytes.len() + conv_bytes.len() + 8);
    out.extend_from_slice(ct_bytes);
    out.extend_from_slice(conv_bytes);
    out.extend_from_slice(&ts_bytes);
    out
}
