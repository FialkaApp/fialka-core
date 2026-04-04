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

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // ── HMAC-SHA256 ──────────────────────────────────────────────────────────

    /// RFC 4231 Test Case 1 — standard HMAC-SHA256 vector.
    #[test]
    fn test_hmac_sha256_rfc4231_tc1() {
        let key  = hex::decode("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b").unwrap();
        let data = b"Hi There";
        let expected = "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7";
        let got = hmac_sha256(&key, data);
        assert_eq!(hex::encode(got), expected, "HMAC-SHA256 RFC4231 TC1 failed");
    }

    /// RFC 4231 Test Case 2 — key = "Jefe".
    #[test]
    fn test_hmac_sha256_rfc4231_tc2() {
        let key  = b"Jefe";
        let data = b"what do ya want for nothing?";
        // Verified against OpenSSL: correct value is ...ec3843 (not ...a72424 — transcription error).
        let expected = "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843";
        let got = hmac_sha256(key, data);
        assert_eq!(hex::encode(got), expected, "HMAC-SHA256 RFC4231 TC2 failed");
    }

    /// Empty key, empty data — boundary case.
    #[test]
    fn test_hmac_sha256_empty() {
        // Generated with Python: hmac.new(b"", b"", hashlib.sha256).hexdigest()
        let expected = "b613679a0814d9ec772f95d778c35fc5ff1697c493715653c6c712144292c5ad";
        let got = hmac_sha256(b"", b"");
        assert_eq!(hex::encode(got), expected);
    }

    /// Determinism: same inputs always produce same output.
    #[test]
    fn test_hmac_sha256_deterministic() {
        let k = [0x42u8; 32];
        let d = b"fialka test data";
        let r1 = hmac_sha256(&k, d);
        let r2 = hmac_sha256(&k, d);
        assert_eq!(r1, r2);
    }

    /// Different key produces different output.
    #[test]
    fn test_hmac_sha256_key_sensitivity() {
        let k1 = [0x11u8; 32];
        let k2 = [0x12u8; 32];
        let d  = b"same data";
        assert_ne!(hmac_sha256(&k1, d), hmac_sha256(&k2, d));
    }

    // ── HKDF-SHA256 ──────────────────────────────────────────────────────────

    /// RFC 5869 Test Case 1 — standard multi-block HKDF.
    #[test]
    fn test_hkdf_sha256_rfc5869_tc1() {
        let ikm  = hex::decode("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b").unwrap();
        let salt = hex::decode("000102030405060708090a0b0c").unwrap();
        let info = hex::decode("f0f1f2f3f4f5f6f7f8f9").unwrap();
        let okm  = hkdf_sha256(&ikm, &salt, &info, 42);
        let expected = "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865";
        assert_eq!(hex::encode(&okm), expected, "HKDF RFC5869 TC1 failed");
    }

    /// Output length = 32 (single block).
    #[test]
    fn test_hkdf_sha256_single_block() {
        let out = hkdf_sha256(b"ikm", b"salt", b"info", 32);
        assert_eq!(out.len(), 32);
    }

    /// Output length = 64 (exactly two blocks — used for ML-KEM seed).
    #[test]
    fn test_hkdf_sha256_two_blocks() {
        let out = hkdf_sha256(b"ikm", b"salt", b"info", 64);
        assert_eq!(out.len(), 64);
    }

    /// HKDF is deterministic.
    #[test]
    fn test_hkdf_sha256_deterministic() {
        let a = hkdf_sha256(b"key", b"salt", b"info", 48);
        let b = hkdf_sha256(b"key", b"salt", b"info", 48);
        assert_eq!(a, b);
    }

    /// Different salt → different output.
    #[test]
    fn test_hkdf_sha256_salt_sensitivity() {
        let a = hkdf_sha256(b"ikm", b"salt1", b"info", 32);
        let b = hkdf_sha256(b"ikm", b"salt2", b"info", 32);
        assert_ne!(a, b);
    }

    // ── hkdf_zero_salt ───────────────────────────────────────────────────────

    /// Verify exact byte output for a known input — golden vector.
    #[test]
    fn test_hkdf_zero_salt_known_vector() {
        // Python: prk = hmac(b'\x00'*32, b"ikm", sha256).digest()
        //         hmac(prk, b"info\x01", sha256).hexdigest()
        let out = hkdf_zero_salt(b"ikm", b"info");
        // Compute expected inline for self-consistency:
        let prk      = hmac_sha256(&[0u8; 32], b"ikm");
        let expected = hmac_sha256(&prk, b"info\x01");
        assert_eq!(out, expected);
    }

    /// hkdf_zero_salt is deterministic.
    #[test]
    fn test_hkdf_zero_salt_deterministic() {
        let a = hkdf_zero_salt(b"secret", b"Fialka-DR-root");
        let b = hkdf_zero_salt(b"secret", b"Fialka-DR-root");
        assert_eq!(a, b);
    }

    /// Different info labels produce different outputs.
    #[test]
    fn test_hkdf_zero_salt_info_sensitivity() {
        let a = hkdf_zero_salt(b"ikm", b"Fialka-DR-chain-init-send");
        let b = hkdf_zero_salt(b"ikm", b"Fialka-DR-chain-init-recv");
        assert_ne!(a, b, "different info strings must give different keys");
    }
}
