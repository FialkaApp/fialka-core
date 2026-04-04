/*
 * fialka-core — Cross-platform cryptographic core for Fialka
 * Copyright (C) 2024-2026 DevBot667 — GPL-3.0
 */

//! HMAC-SHA256 and HKDF-SHA256 — byte-for-byte compatible with:
//!   Android: CryptoManager.hmacSha256() / CryptoManager.hkdfSha256()
//!   Android: DoubleRatchet.hmacSha256() / DoubleRatchet.hkdfExpand()

use hmac::{Hmac, Mac};
use sha2::Sha256;
use zeroize::Zeroize;

type HmacSha256 = Hmac<Sha256>;

/// HMAC-SHA256.
/// Matches CryptoManager.hmacSha256(key, data) and DoubleRatchet.hmacSha256().
pub fn hmac_sha256(key: &[u8], data: &[u8]) -> [u8; 32] {
    let mut mac = HmacSha256::new_from_slice(key)
        .expect("HMAC-SHA256 accepts any key size");
    mac.update(data);
    mac.finalize().into_bytes().into()
}

/// HKDF-SHA256 with configurable output length (RFC 5869).
///
/// Matches `CryptoManager.hkdfSha256(ikm, salt, info, length)` exactly:
///   Extract: PRK = HMAC-SHA256(salt, IKM)
///   Expand:  T(i) = HMAC-SHA256(PRK, T(i-1) || info || i)
///
/// Used for ML-KEM and ML-DSA deterministic seed derivation.
pub fn hkdf_sha256(ikm: &[u8], salt: &[u8], info: &[u8], length: usize) -> Vec<u8> {
    assert!(length >= 1, "HKDF output length must be >= 1");
    assert!(length <= 255 * 32, "HKDF output length must be <= 8160");

    // Extract
    let mut prk = hmac_sha256(salt, ikm);

    // Expand: T(1) || T(2) || ... (Kotlin: i in 1..n, byteArrayOf(i.toByte()))
    let n = (length + 31) / 32;
    let mut okm: Vec<u8> = Vec::with_capacity(n * 32);
    let mut prev: Vec<u8> = Vec::new();
    for i in 1..=(n as u8) {
        // input = prev || info || i
        let mut input = Vec::with_capacity(prev.len() + info.len() + 1);
        input.extend_from_slice(&prev);
        input.extend_from_slice(info);
        input.push(i);
        let t = hmac_sha256(&prk, &input);
        okm.extend_from_slice(&t);
        prev = t.to_vec();
    }
    prk.zeroize();
    okm.truncate(length);
    okm
}

/// Zero-salt HKDF single-block expand.
///
/// Identical to both:
///   - `CryptoManager.hkdfExtractExpand(ikm, info)`  (used for inbox encryption)
///   - `DoubleRatchet.hkdfExpand(ikm, info)`          (used for ratchet init + SPQR)
///
/// Both Kotlin functions are byte-for-byte identical:
///   PRK = HMAC-SHA256(zeros_32, IKM)
///   OKM = HMAC-SHA256(PRK, info || 0x01)
pub fn hkdf_zero_salt(ikm: &[u8], info: &[u8]) -> [u8; 32] {
    let mut prk = hmac_sha256(&[0u8; 32], ikm);
    let mut expand_input = Vec::with_capacity(info.len() + 1);
    expand_input.extend_from_slice(info);
    expand_input.push(0x01);
    let result = hmac_sha256(&prk, &expand_input);
    prk.zeroize();
    result
}
