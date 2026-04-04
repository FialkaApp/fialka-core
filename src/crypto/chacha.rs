/*
 * fialka-core — Cross-platform cryptographic core for Fialka
 * Copyright (C) 2024-2026 DevBot667 — GPL-3.0
 */

//! ChaCha20-Poly1305 authenticated encryption.
//!
//! Byte-for-byte compatible with Android:
//!   CryptoManager.encryptChaCha() / CryptoManager.decryptChaCha()
//!   BouncyCastle ChaCha20Poly1305, 12-byte nonce, 16-byte Poly1305 tag
//!
//! Padding: identical to AES-GCM (same bucket sizes + 2-byte length header).

use chacha20poly1305::{aead::Aead, ChaCha20Poly1305, KeyInit, Nonce, Key};
use rand::RngCore;
use rand::rngs::OsRng;

/// Padding buckets — same as AES-GCM module.
const PADDING_BUCKETS: &[usize] = &[256, 1024, 4096, 16384];
const NONCE_LEN: usize = 12;

/// Result of a ChaCha20-Poly1305 encryption.
pub struct ChaChaEncrypted {
    /// Ciphertext with 16-byte Poly1305 tag appended.
    pub ciphertext: Vec<u8>,
    /// 12-byte random nonce.
    pub nonce: [u8; NONCE_LEN],
}

/// Encrypt a UTF-8 plaintext string with ChaCha20-Poly1305.
/// Matches `CryptoManager.encryptChaCha(plaintext, key)`.
pub fn encrypt(plaintext: &str, key_bytes: &[u8; 32]) -> Result<ChaChaEncrypted, chacha20poly1305::Error> {
    let plaintext_bytes = plaintext.as_bytes();
    let padded = pad_plaintext(plaintext_bytes);

    let mut nonce_bytes = [0u8; NONCE_LEN];
    OsRng.fill_bytes(&mut nonce_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);

    let key = Key::from_slice(key_bytes);
    let cipher = ChaCha20Poly1305::new(key);
    let ciphertext = cipher.encrypt(nonce, padded.as_ref())?;

    Ok(ChaChaEncrypted { ciphertext, nonce: nonce_bytes })
}

/// Decrypt ChaCha20-Poly1305 ciphertext back to a UTF-8 string.
/// Matches `CryptoManager.decryptChaCha(encryptedData, key)`.
pub fn decrypt(ciphertext: &[u8], nonce_bytes: &[u8; NONCE_LEN], key_bytes: &[u8; 32]) -> Result<String, String> {
    let nonce = Nonce::from_slice(nonce_bytes);
    let key = Key::from_slice(key_bytes);
    let cipher = ChaCha20Poly1305::new(key);

    let padded = cipher.decrypt(nonce, ciphertext)
        .map_err(|_| "ChaCha20-Poly1305 decryption failed".to_string())?;

    let unpadded = unpad_plaintext(&padded)
        .map_err(|e| format!("Unpad failed: {e}"))?;

    String::from_utf8(unpadded).map_err(|e| format!("UTF-8 decode failed: {e}"))
}

// ── Padding helpers (identical to aesgcm.rs) ─────────────────────────────────

fn pad_plaintext(plaintext: &[u8]) -> Vec<u8> {
    let payload_size = 2 + plaintext.len();
    let bucket = PADDING_BUCKETS.iter().copied().find(|&b| b >= payload_size)
        .unwrap_or(payload_size);

    let mut padded = vec![0u8; bucket];
    padded[0] = ((plaintext.len() >> 8) & 0xFF) as u8;
    padded[1] = (plaintext.len() & 0xFF) as u8;
    padded[2..2 + plaintext.len()].copy_from_slice(plaintext);
    if bucket > payload_size {
        OsRng.fill_bytes(&mut padded[payload_size..]);
    }
    padded
}

fn unpad_plaintext(padded: &[u8]) -> Result<Vec<u8>, &'static str> {
    if padded.len() < 2 {
        return Err("Padded data too short");
    }
    let real_len = ((padded[0] as usize) << 8) | (padded[1] as usize);
    if real_len > padded.len() - 2 {
        return Err("Invalid padding header: real_len out of range");
    }
    Ok(padded[2..2 + real_len].to_vec())
}
