/*
 * fialka-core — Cross-platform cryptographic core for Fialka
 * Copyright (C) 2024-2026 DevBot667 — GPL-3.0
 */

//! Identity derivation: 1 seed (32 bytes) → all key pairs + .onion address + Account ID.
//!
//! Byte-for-byte compatible with `CryptoManager.deriveAndStoreAllKeys()` on Android.
//!
//! Derivation chain:
//!   Ed25519 keypair  = Ed25519PrivateKeyParameters(seed)
//!   X25519 keypair   = SHA-512(seed)[0..31] as scalar (birational)
//!   ML-KEM-1024      = HKDF-SHA256(seed, salt="fialka-ml-kem",    info="identity-keypair", 64)
//!   ML-DSA-44        = HKDF-SHA256(seed, salt="fialka-ml-dsa-44", info="identity-keypair", 32)
//!   Account ID       = SHA3-256(Ed25519 pubkey) → Base58
//!   .onion address   = base32(ed25519_pub || sha3_checksum[0..1] || 0x03).lowercase() + ".onion"

use sha3::{Sha3_256, Digest as Sha3Digest};
use zeroize::Zeroizing;

use crate::crypto::kdf::hkdf_sha256;
use crate::crypto::ed25519::Ed25519KeyPair;
use crate::crypto::x25519::X25519KeyPair;
use crate::crypto::mlkem;
use crate::crypto::mldsa;

/// All keys derived from a single Ed25519 seed.
/// Corresponds to the stored keys in `CryptoManager`.
pub struct FialkaIdentity {
    /// Raw 32-byte Ed25519 seed (the master secret — this IS the BIP-39 mnemonic).
    pub seed: Zeroizing<[u8; 32]>,

    /// Ed25519 signing keypair.
    /// private raw = seed (32 bytes) — same as BouncyCastle encoded
    /// public  raw = 32-byte compressed Edwards point
    pub ed25519_pub: [u8; 32],

    /// X25519 DH keypair (derived from seed via birational map).
    /// private raw = SHA-512(seed)[0..31] (clamped during DH)
    /// public  raw = 32-byte u-coordinate
    pub x25519_pub: [u8; 32],
    pub x25519_priv: Zeroizing<[u8; 32]>,

    /// ML-KEM-1024 key pair (FIPS 203 — post-quantum KEM for PQXDH).
    /// Both keys are FIPS 203 standard encoding.
    pub mlkem_ek: Vec<u8>,   // encapsulation key (public) — 1568 bytes
    pub mlkem_dk: Zeroizing<Vec<u8>>,     // decapsulation key (private) — 3168 bytes

    /// ML-DSA-44 key pair (FIPS 204 — post-quantum signing for handshake auth).
    pub mldsa_vk: [u8; mldsa::VK_SIZE],  // verifying key (public) — 1312 bytes
    pub mldsa_sk: Zeroizing<Vec<u8>>,    // signing key (private) — 2560 bytes

    /// SHA3-256(Ed25519 pubkey) → Base58. Stable user identifier.
    pub account_id: String,
}

impl FialkaIdentity {
    /// Derive all keys from a 32-byte Ed25519 seed.
    /// Matches `CryptoManager.deriveAndStoreAllKeys(seed)`.
    pub fn derive_from_seed(seed: &[u8; 32]) -> Self {
        // ── 1. Ed25519 signing keypair ──
        let ed_keypair = Ed25519KeyPair::from_seed(seed);
        let ed25519_pub = ed_keypair.public_key_bytes();

        // ── 2. X25519 DH keypair ──
        let x25519 = X25519KeyPair::from_ed25519_seed(seed);

        // ── 3. ML-KEM-1024 deterministic from HKDF(seed) ──
        // HKDF-SHA256(ikm=seed, salt="fialka-ml-kem", info="identity-keypair", 64 bytes)
        let mlkem_seed = hkdf_sha256(
            seed,
            b"fialka-ml-kem",
            b"identity-keypair",
            64,
        );
        let (mlkem_dk_bytes, mlkem_ek_bytes) = mlkem::keygen_from_seed(&mlkem_seed);
        let mlkem_dk = Zeroizing::new(mlkem_dk_bytes.to_vec());

        // ── 4. ML-DSA-44 deterministic from HKDF(seed) ──
        // HKDF-SHA256(ikm=seed, salt="fialka-ml-dsa-44", info="identity-keypair", 32 bytes)
        let mldsa_seed_vec = hkdf_sha256(
            seed,
            b"fialka-ml-dsa-44",
            b"identity-keypair",
            32,
        );
        let mldsa_seed: [u8; 32] = mldsa_seed_vec.try_into()
            .expect("HKDF with length=32 must give 32 bytes");
        let (mldsa_sk_bytes, mldsa_vk_bytes) = mldsa::keygen_from_seed(&mldsa_seed);
        let mldsa_sk = Zeroizing::new(mldsa_sk_bytes.to_vec());

        // ── 5. Account ID: SHA3-256(Ed25519 pubkey 32 bytes) → Base58 ──
        let account_id = derive_account_id(&ed25519_pub);

        FialkaIdentity {
            seed: Zeroizing::new(*seed),
            ed25519_pub,
            x25519_pub: x25519.public_raw,
            x25519_priv: x25519.private_raw,
            mlkem_ek: mlkem_ek_bytes,
            mlkem_dk,
            mldsa_vk: mldsa_vk_bytes,
            mldsa_sk,
            account_id,
        }
    }

    /// Tor v3 .onion address derived from our Ed25519 public key.
    /// Matches `CryptoManager.getOnionAddress()`.
    pub fn onion_address(&self) -> String {
        compute_onion_from_ed25519(&self.ed25519_pub)
    }
}

/// Compute a Tor v3 .onion address from any Ed25519 public key.
///
/// Matches `CryptoManager.computeOnionFromEd25519(ed25519PubBytes)`:
///   checksum = SHA3-256(".onion checksum" || pubkey || 0x03)[0..1]
///   address  = base32(pubkey || checksum || 0x03).lowercase() + ".onion"
pub fn compute_onion_from_ed25519(ed25519_pub_bytes: &[u8; 32]) -> String {
    const VERSION: u8 = 0x03;

    // SHA3-256(".onion checksum" || pubkey || version)
    let mut hasher = Sha3_256::new();
    hasher.update(b".onion checksum");
    hasher.update(ed25519_pub_bytes);
    hasher.update([VERSION]);
    let hash = hasher.finalize();
    let checksum = &hash[..2];

    // address_bytes = pubkey(32) || checksum(2) || version(1) = 35 bytes
    let mut address_bytes = [0u8; 35];
    address_bytes[..32].copy_from_slice(ed25519_pub_bytes);
    address_bytes[32..34].copy_from_slice(checksum);
    address_bytes[34] = VERSION;

    // Base32 encode (RFC 4648, no padding) then lowercase + ".onion"
    base32_encode(&address_bytes).to_lowercase() + ".onion"
}

/// Account ID: SHA3-256(Ed25519 pubkey 32 bytes) → Base58.
/// Matches `CryptoManager.deriveAccountId(ed25519PubBytes)`.
pub fn derive_account_id(ed25519_pub_bytes: &[u8; 32]) -> String {
    let mut hasher = Sha3_256::new();
    hasher.update(ed25519_pub_bytes);
    let hash = hasher.finalize();
    bs58::encode(hash.as_slice()).into_string()
}

// ── Base32 encoding (RFC 4648, no padding) ───────────────────────────────────
// Matches `CryptoManager.base32Encode()` exactly.

const BASE32_ALPHABET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

fn base32_encode(data: &[u8]) -> String {
    let mut result = String::new();
    let mut buffer: u32 = 0;
    let mut bits_left: u32 = 0;

    for &byte in data {
        buffer = (buffer << 8) | (byte as u32);
        bits_left += 8;
        while bits_left >= 5 {
            bits_left -= 5;
            result.push(BASE32_ALPHABET[((buffer >> bits_left) & 0x1F) as usize] as char);
        }
    }
    if bits_left > 0 {
        result.push(BASE32_ALPHABET[((buffer << (5 - bits_left)) & 0x1F) as usize] as char);
    }
    result
}
