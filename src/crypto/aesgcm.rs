/*
 * fialka-core — Cross-platform cryptographic core for Fialka
 * Copyright (C) 2024-2026 DevBot667 — GPL-3.0
 */

//! AES-256-GCM authenticated encryption with content-size padding.
//!
//! Byte-for-byte compatible with Android:
//!   CryptoManager.encrypt() / CryptoManager.decrypt()
//!   Transformation: AES/GCM/NoPadding, 128-bit tag, 12-byte IV
//!
//! Padding buckets: [256, 1024, 4096, 16384]
//! Format: [2 bytes big-endian real length][UTF-8 plaintext][random padding to bucket boundary]

use aes_gcm::{aead::Aead, Aes256Gcm, Key, KeyInit, Nonce};
use rand::RngCore;
use rand::rngs::OsRng;
use zeroize::Zeroizing;

/// Padding buckets matching CryptoManager.PADDING_BUCKETS.
const PADDING_BUCKETS: &[usize] = &[256, 1024, 4096, 16384];

const GCM_IV_LEN: usize = 12;

/// Result of an AES-256-GCM encryption.
pub struct AesEncrypted {
    /// Ciphertext with 16-byte GCM tag appended (matches Java AES/GCM/NoPadding output).
    pub ciphertext: Vec<u8>,
    /// 12-byte random IV (matches CryptoManager.EncryptedData.iv Base64).
    pub iv: [u8; GCM_IV_LEN],
}

/// Encrypt a UTF-8 plaintext string with AES-256-GCM.
/// Matches `CryptoManager.encrypt(plaintext, key)`.
pub fn encrypt(plaintext: &str, key_bytes: &[u8; 32]) -> Result<AesEncrypted, aes_gcm::Error> {
    let plaintext_bytes = plaintext.as_bytes();
    let padded = pad_plaintext(plaintext_bytes);

    let mut iv = [0u8; GCM_IV_LEN];
    OsRng.fill_bytes(&mut iv);
    let nonce = Nonce::from_slice(&iv);

    let key = Key::<Aes256Gcm>::from_slice(key_bytes);
    let cipher = Aes256Gcm::new(key);
    let ciphertext = cipher.encrypt(nonce, padded.as_ref())?;

    Ok(AesEncrypted { ciphertext, iv })
}

/// Decrypt AES-256-GCM ciphertext back to a UTF-8 string.
/// Matches `CryptoManager.decrypt(encryptedData, key)`.
pub fn decrypt(ciphertext: &[u8], iv: &[u8; GCM_IV_LEN], key_bytes: &[u8; 32]) -> Result<String, String> {
    let nonce = Nonce::from_slice(iv);
    let key = Key::<Aes256Gcm>::from_slice(key_bytes);
    let cipher = Aes256Gcm::new(key);

    let padded = cipher.decrypt(nonce, ciphertext)
        .map_err(|_| "AES-GCM decryption failed".to_string())?;

    let unpadded = unpad_plaintext(&padded)
        .map_err(|e| format!("Unpad failed: {e}"))?;

    String::from_utf8(unpadded).map_err(|e| format!("UTF-8 decode failed: {e}"))
}

/// Encrypt raw file bytes with a fresh random AES-256-GCM key.
/// Matches `CryptoManager.encryptFile(fileBytes)`.
/// Returns (ciphertext_with_tag, key_32_bytes, iv_12_bytes).
pub fn encrypt_file(file_bytes: &[u8]) -> Result<(Vec<u8>, Zeroizing<[u8; 32]>, [u8; GCM_IV_LEN]), aes_gcm::Error> {
    let mut key_bytes = Zeroizing::new([0u8; 32]);
    OsRng.fill_bytes(key_bytes.as_mut());
    let mut iv = [0u8; GCM_IV_LEN];
    OsRng.fill_bytes(&mut iv);

    let nonce = Nonce::from_slice(&iv);
    let key = Key::<Aes256Gcm>::from_slice(key_bytes.as_ref());
    let cipher = Aes256Gcm::new(key);
    let ciphertext = cipher.encrypt(nonce, file_bytes)?;

    Ok((ciphertext, key_bytes, iv))
}

/// Decrypt file bytes. Matches `CryptoManager.decryptFile(bytes, key, iv)`.
pub fn decrypt_file(ciphertext: &[u8], key_bytes: &[u8; 32], iv: &[u8; GCM_IV_LEN]) -> Result<Vec<u8>, aes_gcm::Error> {
    let nonce = Nonce::from_slice(iv);
    let key = Key::<Aes256Gcm>::from_slice(key_bytes);
    let cipher = Aes256Gcm::new(key);
    cipher.decrypt(nonce, ciphertext)
}

// ── Padding helpers ──────────────────────────────────────────────────────────

/// Pad plaintext into fixed-size buckets.
/// Matches `CryptoManager.padPlaintext()`:
///   payloadSize = 2 + plaintext.size
///   bucket = first(BUCKETS where bucket >= payloadSize) or payloadSize
///   output: [real_len_hi][real_len_lo][plaintext_bytes][random_pad...]
fn pad_plaintext(plaintext: &[u8]) -> Vec<u8> {
    let payload_size = 2 + plaintext.len();
    let bucket = PADDING_BUCKETS.iter().copied().find(|&b| b >= payload_size)
        .unwrap_or(payload_size);

    let mut padded = vec![0u8; bucket];
    // 2-byte big-endian real length header
    padded[0] = ((plaintext.len() >> 8) & 0xFF) as u8;
    padded[1] = (plaintext.len() & 0xFF) as u8;
    // Plaintext
    padded[2..2 + plaintext.len()].copy_from_slice(plaintext);
    // Random padding (non-zero bytes to avoid patterns, like the Kotlin code)
    if bucket > payload_size {
        OsRng.fill_bytes(&mut padded[payload_size..]);
    }
    padded
}

/// Strip padding to recover original bytes.
/// Matches `CryptoManager.unpadPlaintext()`.
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
