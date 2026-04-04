/*
 * fialka-core — Cross-platform cryptographic core for Fialka
 * Copyright (C) 2024-2026 DevBot667 — GPL-3.0
 */

//! ML-DSA-44 digital signature (NIST FIPS 204).
//!
//! Deterministic key generation matches Android determinism:
//!   BouncyCastle MLDSAKeyPairGenerator reads exactly 32 bytes (ξ) from SecureRandom.
//!   Both follow FIPS 204 ML-DSA.KeyGen(ξ) → same keys.
//!
//! Key sizes (ML-DSA-44):
//!   Signing key (private):    2560 bytes
//!   Verifying key (public):   1312 bytes
//!   Signature:                2420 bytes

use ml_dsa::{KeyGen, MlDsa44};
use ml_dsa::signature::{Signer as DsaSigner, Verifier as DsaVerifier};
use super::fixed_rng::FixedRng;

/// Signing key (private) size in bytes.
pub const SK_SIZE: usize = 2560;
/// Verifying key (public) size in bytes.
pub const VK_SIZE: usize = 1312;
/// Signature size in bytes.
pub const SIG_SIZE: usize = 2420;

/// Deterministic ML-DSA-44 key generation from a 32-byte seed (ξ).
/// Returns (signing_key_bytes, verifying_key_bytes).
pub fn keygen_from_seed(seed_32: &[u8; 32]) -> ([u8; SK_SIZE], [u8; VK_SIZE]) {
    let mut rng = FixedRng::new(seed_32.as_ref());
    let kp = MlDsa44::key_gen(&mut rng);

    let sk_bytes: [u8; SK_SIZE] = kp.signing_key().encode().as_slice().try_into()
        .expect("ML-DSA-44 signing key must be 2560 bytes");
    let vk_bytes: [u8; VK_SIZE] = kp.verifying_key().encode().as_slice().try_into()
        .expect("ML-DSA-44 verifying key must be 1312 bytes");

    (sk_bytes, vk_bytes)
}

/// Sign data with ML-DSA-44 from raw signing key bytes.
/// Matches `CryptoManager.signHandshakeMlDsa44(data)`.
/// Returns 2420-byte signature.
pub fn sign(sk_bytes: &[u8; SK_SIZE], data: &[u8]) -> Result<[u8; SIG_SIZE], String> {
    let sk = ml_dsa::SigningKey::<MlDsa44>::decode(sk_bytes.into());
    let sig: ml_dsa::Signature<MlDsa44> = DsaSigner::sign(&sk, data);
    let sig_bytes: [u8; SIG_SIZE] = sig.encode().as_slice().try_into()
        .expect("ML-DSA-44 signature must be 2420 bytes");
    Ok(sig_bytes)
}

/// Verify an ML-DSA-44 signature from raw key bytes.
/// Matches `CryptoManager.verifyHandshakeMlDsa44(pubKey, data, signature)`.
pub fn verify(vk_bytes: &[u8; VK_SIZE], data: &[u8], sig_bytes: &[u8; SIG_SIZE]) -> bool {
    let vk = ml_dsa::VerifyingKey::<MlDsa44>::decode(vk_bytes.into());
    let Some(sig) = ml_dsa::Signature::<MlDsa44>::decode(sig_bytes.into()) else {
        return false;
    };
    <ml_dsa::VerifyingKey<MlDsa44> as DsaVerifier<ml_dsa::Signature<MlDsa44>>>::verify(
        &vk, data, &sig
    ).is_ok()
}
