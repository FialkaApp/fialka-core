/*
 * fialka-core — Cross-platform cryptographic core for Fialka
 * Copyright (C) 2024-2026 DevBot667 — GPL-3.0
 */

//! ML-KEM-1024 key encapsulation mechanism (NIST FIPS 203).
//!
//! Deterministic key generation matches Android determinism:
//!   BouncyCastle MLKEMKeyPairGenerator reads exactly 64 bytes from SecureRandom:
//!     d (32 bytes) = seed[0..31]
//!     z (32 bytes) = seed[32..63]
//!   Both follow FIPS 203 ML-KEM.KeyGen_internal(d, z) → same keys.
//!
//! Key sizes (ML-KEM-1024):
//!   Encapsulation key (public):    1568 bytes
//!   Decapsulation key (private):   3168 bytes
//!   Ciphertext:                    1568 bytes
//!   Shared secret:                   32 bytes

use ml_kem::{EncodedSizeUser, KemCore, MlKem1024, MlKem1024Params};
use ml_kem::kem::{DecapsulationKey, Encapsulate, EncapsulationKey};
use rand::rngs::OsRng;
use super::fixed_rng::FixedRng;

/// Deterministic ML-KEM-1024 key generation from a 64-byte seed.
/// Returns (decapsulation_key_bytes, encapsulation_key_bytes) as Vec<u8>.
/// dk = 3168 bytes, ek = 1568 bytes (FIPS 203 standard encoding).
pub fn keygen_from_seed(seed_64: &[u8]) -> (Vec<u8>, Vec<u8>) {
    assert_eq!(seed_64.len(), 64, "ML-KEM seed must be 64 bytes (d=32 + z=32)");
    let mut rng = FixedRng::new(seed_64);
    let (dk, ek) = MlKem1024::generate(&mut rng);
    let ek_bytes = ek.as_bytes().as_slice().to_vec();
    let dk_bytes = dk.as_bytes().as_slice().to_vec();
    (dk_bytes, ek_bytes)
}

/// ML-KEM-1024 encapsulation (initiator side).
/// Returns (ciphertext_bytes, shared_secret_32_bytes).
pub fn encapsulate(ek_bytes: &[u8]) -> Result<(Vec<u8>, [u8; 32]), String> {
    type EkEncoded = ml_kem::Encoded<EncapsulationKey<MlKem1024Params>>;

    let encoded = EkEncoded::try_from(ek_bytes)
        .map_err(|_| format!("ML-KEM ek size mismatch: got {} bytes, expected 1568", ek_bytes.len()))?;
    let ek = EncapsulationKey::<MlKem1024Params>::from_bytes(&encoded);

    let (ct, ss) = ek.encapsulate(&mut OsRng)
        .map_err(|_| "ML-KEM encapsulation failed".to_string())?;

    let ct_bytes = ct.as_slice().to_vec();
    let ss_bytes: [u8; 32] = ss.as_slice().try_into()
        .map_err(|_| "ML-KEM shared secret must be 32 bytes".to_string())?;

    Ok((ct_bytes, ss_bytes))
}

/// ML-KEM-1024 decapsulation (recipient side).
/// Returns shared_secret_32_bytes.
pub fn decapsulate(dk_bytes: &[u8], ct_bytes: &[u8]) -> Result<[u8; 32], String> {
    use ml_kem::kem::Decapsulate;

    type DkEncoded = ml_kem::Encoded<DecapsulationKey<MlKem1024Params>>;
    type CtEncoded = ml_kem::Ciphertext<MlKem1024>;

    let dk_encoded = DkEncoded::try_from(dk_bytes)
        .map_err(|_| format!("ML-KEM dk size mismatch: got {} bytes, expected 3168", dk_bytes.len()))?;
    let dk = DecapsulationKey::<MlKem1024Params>::from_bytes(&dk_encoded);

    let ct_encoded = CtEncoded::try_from(ct_bytes)
        .map_err(|_| format!("ML-KEM ct size mismatch: got {} bytes, expected 1568", ct_bytes.len()))?;

    let ss = dk.decapsulate(&ct_encoded)
        .map_err(|_| "ML-KEM decapsulation failed".to_string())?;

    ss.as_slice().try_into()
        .map_err(|_| "ML-KEM shared secret must be 32 bytes".to_string())
}
