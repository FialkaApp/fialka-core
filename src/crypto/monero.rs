/*
 * fialka-core — Monero (XMR) cryptography module
 * Copyright (C) 2024-2026 DevBot667 — GPL-3.0
 */

//! Monero key derivation, address generation, and subaddress computation.
//!
//! # Security model
//!
//! - `spend_priv` is derived internally and **NEVER** crosses the JNI boundary.
//! - `view_priv` is returned only when explicitly requested (donation transparency use-case):
//!   the caller deliberately publishes it so the community can audit incoming donations with a
//!   watch-only wallet (e.g. Feather Wallet), while spend authority stays offline.
//! - All private scalars are wrapped in `Zeroizing<>` and dropped via zeroize on scope exit.
//!
//! # Key derivation
//!
//! ```text
//! seed (32 bytes, random)
//!   └─ spend_scalar = sc_reduce32(keccak256(seed))
//!       ├─ spend_pub = spend_scalar * G
//!       └─ view_scalar = sc_reduce32(keccak256(spend_scalar.bytes()))
//!           └─ view_pub = view_scalar * G
//! ```
//!
//! # Subaddress formula (Monero protocol)
//!
//! ```text
//! account, index ∈ ℕ
//! h      = H_s("SubAddr\x00" || view_priv || account_LE32 || index_LE32)   [keccak256 → scalar]
//! D      = spend_pub_point + h * G          (sub-spend public key)
//! C      = view_priv * D                    (sub-view  public key)
//! addr   = Monero_Base58( 0x2a || D || C || keccak256(0x2a||D||C)[0..4] )
//! ```

use sha3::{Keccak256, Digest};
use sha2::Sha256;
use zeroize::Zeroizing;
use rand::rngs::OsRng;
use rand::RngCore;
use curve25519_dalek::Scalar;
use curve25519_dalek::constants::ED25519_BASEPOINT_TABLE;
use curve25519_dalek::edwards::{CompressedEdwardsY, EdwardsPoint};

// ── Constants ─────────────────────────────────────────────────────────────────

/// Monero mainnet standard address network prefix (decimal 18).
const MAINNET_ADDR_PREFIX: u8 = 18;

/// Monero mainnet subaddress network prefix (decimal 42).
const MAINNET_SUBADDR_PREFIX: u8 = 42;

/// Base58 alphabet used by Monero (identical to Bitcoin's).
const BASE58_ALPHABET: &[u8; 58] =
    b"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

/// Number of base58 characters required to encode n input bytes (n = 0..=8).
const ENCODED_BLOCK_SIZES: [usize; 9] = [0, 2, 3, 5, 6, 7, 9, 10, 11];

/// Input block size (bytes) for Monero's chunked base58.
const BLOCK_SIZE: usize = 8;

// ── Key generation ────────────────────────────────────────────────────────────

/// Generate 32 bytes of cryptographically secure random entropy.
///
/// This is the **raw wallet seed** — independent from Fialka's identity seed.
/// Store in `EncryptedSharedPreferences` under a key distinct from `KEY_ED25519_SEED`.
pub fn generate_wallet_seed() -> Zeroizing<[u8; 32]> {
    let mut seed = Zeroizing::new([0u8; 32]);
    OsRng.fill_bytes(seed.as_mut());
    seed
}

// ── Key derivation ────────────────────────────────────────────────────────────

/// Derive Monero keys from a 32-byte wallet seed.
///
/// Returns `(spend_pub[32], view_pub[32], view_priv[32])`.
/// The **spend_priv** scalar is computed internally and deliberately **not** returned.
pub fn derive_keys_from_seed(seed: &[u8; 32]) -> ([u8; 32], [u8; 32], Zeroizing<[u8; 32]>) {
    // spend_scalar = sc_reduce32( keccak256(seed) )
    let spend_hash: [u8; 32] = Keccak256::digest(&seed[..]).into();
    let spend_scalar = Zeroizing::new(Scalar::from_bytes_mod_order(spend_hash));

    // view_scalar = sc_reduce32( keccak256(spend_scalar.as_bytes()) )
    let view_hash: [u8; 32] = Keccak256::digest(spend_scalar.as_bytes()).into();
    let view_scalar = Zeroizing::new(Scalar::from_bytes_mod_order(view_hash));

    // Public keys = scalar * G  (constant-time basepoint multiplication)
    let spend_pub = (ED25519_BASEPOINT_TABLE * &*spend_scalar).compress().to_bytes();
    let view_pub  = (ED25519_BASEPOINT_TABLE * &*view_scalar).compress().to_bytes();

    let mut view_priv_out = Zeroizing::new([0u8; 32]);
    view_priv_out.copy_from_slice(view_scalar.as_bytes());

    // spend_scalar and view_scalar are Zeroized on drop here.
    (spend_pub, view_pub, view_priv_out)
}

// ── Monero address encoding ───────────────────────────────────────────────────

/// Encode a single block of 1–8 bytes to Monero base58 characters.
///
/// Monero encodes in fixed 8-byte blocks: each block becomes 11 chars.
/// The last (partial) block uses fewer chars per `ENCODED_BLOCK_SIZES`.
fn encode_block(block: &[u8]) -> Vec<u8> {
    debug_assert!(!block.is_empty() && block.len() <= BLOCK_SIZE);
    let out_len = ENCODED_BLOCK_SIZES[block.len()];

    // Interpret the block as a big-endian integer.
    let mut num: u128 = 0;
    for &b in block {
        num = num * 256 + (b as u128);
    }

    // Convert to base58, right-anchored.
    let mut encoded = vec![b'1'; out_len]; // '1' encodes zero in base58
    let mut i = out_len;
    while num > 0 {
        i -= 1;
        encoded[i] = BASE58_ALPHABET[(num % 58) as usize];
        num /= 58;
    }
    encoded
}

/// Encode arbitrary bytes using Monero's chunked base58 scheme.
fn monero_base58_encode(data: &[u8]) -> String {
    let full_blocks = data.len() / BLOCK_SIZE;
    let remainder   = data.len() % BLOCK_SIZE;

    let capacity = full_blocks * 11 + if remainder > 0 { ENCODED_BLOCK_SIZES[remainder] } else { 0 };
    let mut result: Vec<u8> = Vec::with_capacity(capacity);

    for i in 0..full_blocks {
        result.extend_from_slice(&encode_block(&data[i * BLOCK_SIZE..(i + 1) * BLOCK_SIZE]));
    }
    if remainder > 0 {
        result.extend_from_slice(&encode_block(&data[full_blocks * BLOCK_SIZE..]));
    }

    // Safety: BASE58_ALPHABET is pure ASCII, encode_block only picks from it.
    unsafe { String::from_utf8_unchecked(result) }
}

/// Build a Monero address string from raw pubkey bytes and a network prefix.
///
/// Layout: `prefix(1) || spend_pub(32) || view_pub(32) || keccak256_checksum(4)`
/// = 69 bytes → 95 base58 chars.
fn build_address(prefix: u8, spend_pub: &[u8; 32], view_pub: &[u8; 32]) -> String {
    let mut payload: Vec<u8> = Vec::with_capacity(69);
    payload.push(prefix);
    payload.extend_from_slice(spend_pub);
    payload.extend_from_slice(view_pub);

    // First 4 bytes of Keccak256(payload) as checksum.
    let checksum: [u8; 32] = Keccak256::digest(&payload).into();
    payload.extend_from_slice(&checksum[..4]);

    monero_base58_encode(&payload)
}

// ── Public address API ────────────────────────────────────────────────────────

/// Return the Monero mainnet primary address for `(spend_pub, view_pub)`.
///
/// Starts with `"4"` on mainnet.  Always 95 characters.
pub fn primary_address(spend_pub: &[u8; 32], view_pub: &[u8; 32]) -> String {
    build_address(MAINNET_ADDR_PREFIX, spend_pub, view_pub)
}

/// Derive a Monero subaddress at position `(account, index)`.
///
/// Does NOT require `spend_priv` — only `spend_pub` and `view_priv`.
/// This makes it safe to use with a watch-only setup (donations page).
///
/// # Errors
///
/// Returns `Err` if `spend_pub_bytes` is not a valid compressed Edwards point.
pub fn subaddress(
    spend_pub_bytes: &[u8; 32],
    view_priv_bytes: &[u8; 32],
    account: u32,
    index: u32,
) -> Result<String, &'static str> {
    // Decompress spend public key to an Edwards point.
    let spend_pub_point = CompressedEdwardsY(*spend_pub_bytes)
        .decompress()
        .ok_or("xmr: invalid spend_pub_bytes (not a compressed Edwards point)")?;

    let view_scalar = Zeroizing::new(Scalar::from_bytes_mod_order(*view_priv_bytes));

    // h = H_s("SubAddr\x00" || view_priv || account_LE32 || index_LE32)
    let mut hash_input: Vec<u8> = Vec::with_capacity(48);
    hash_input.extend_from_slice(b"SubAddr\x00");
    hash_input.extend_from_slice(view_priv_bytes);
    hash_input.extend_from_slice(&account.to_le_bytes());
    hash_input.extend_from_slice(&index.to_le_bytes());

    let h_bytes: [u8; 32] = Keccak256::digest(&hash_input).into();
    let h_scalar = Scalar::from_bytes_mod_order(h_bytes);

    // D = spend_pub + h * G
    let h_times_g: EdwardsPoint = ED25519_BASEPOINT_TABLE * &h_scalar;
    let sub_spend_pub_point: EdwardsPoint = spend_pub_point + h_times_g;
    let sub_spend_pub = sub_spend_pub_point.compress().to_bytes();

    // C = view_priv * D
    let sub_view_pub_point: EdwardsPoint = &*view_scalar * &sub_spend_pub_point;
    let sub_view_pub = sub_view_pub_point.compress().to_bytes();

    Ok(build_address(MAINNET_SUBADDR_PREFIX, &sub_spend_pub, &sub_view_pub))
}

/// Derive a **deterministic donation subaddress** for a given Fialka `account_id`.
///
/// Index = first 4 bytes of `SHA-256(account_id)` interpreted as a little-endian `u32`.
/// Account is always `0`.
///
/// This means every Fialka user sees a unique donation address, all converging to the same
/// wallet (controlled by the project), and the community can audit incoming totals via the
/// public `view_priv` embedded in the APK — while the `spend_priv` stays offline.
pub fn derive_donation_subaddress(
    spend_pub: &[u8; 32],
    view_priv: &[u8; 32],
    account_id_bytes: &[u8],
) -> Result<String, &'static str> {
    let hash: [u8; 32] = Sha256::digest(account_id_bytes).into();
    let index = u32::from_le_bytes([hash[0], hash[1], hash[2], hash[3]]);
    subaddress(spend_pub, view_priv, 0, index)
}

// ── Unit tests ────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    /// Zero seed — deterministic, useful for test vectors.
    const ZERO_SEED: [u8; 32] = [0u8; 32];

    #[test]
    fn test_primary_address_length() {
        let (spend_pub, view_pub, _view_priv) = derive_keys_from_seed(&ZERO_SEED);
        let addr = primary_address(&spend_pub, &view_pub);
        // Monero mainnet primary address is always 95 chars.
        assert_eq!(addr.len(), 95, "Primary address must be 95 chars, got {}", addr.len());
        assert!(addr.starts_with('4'), "Mainnet address must start with '4'");
    }

    #[test]
    fn test_subaddress_length() {
        let (spend_pub, _view_pub, view_priv) = derive_keys_from_seed(&ZERO_SEED);
        let addr = subaddress(&spend_pub, &view_priv, 0, 1).unwrap();
        // Monero subaddress is always 95 chars.
        assert_eq!(addr.len(), 95, "Subaddress must be 95 chars, got {}", addr.len());
        assert!(addr.starts_with('8'), "Mainnet subaddress must start with '8'");
    }

    #[test]
    fn test_primary_address_differs_from_subaddress() {
        let (spend_pub, view_pub, view_priv) = derive_keys_from_seed(&ZERO_SEED);
        let primary = primary_address(&spend_pub, &view_pub);
        let sub     = subaddress(&spend_pub, &view_priv, 0, 1).unwrap();
        assert_ne!(primary, sub);
    }

    #[test]
    fn test_donation_subaddress_deterministic() {
        let (spend_pub, _view_pub, view_priv) = derive_keys_from_seed(&ZERO_SEED);
        let account_id = b"FialkaTestAccountId123";
        let a1 = derive_donation_subaddress(&spend_pub, &view_priv, account_id).unwrap();
        let a2 = derive_donation_subaddress(&spend_pub, &view_priv, account_id).unwrap();
        assert_eq!(a1, a2, "Donation subaddress must be deterministic");
    }

    #[test]
    fn test_donation_subaddresses_unique_per_user() {
        let (spend_pub, _view_pub, view_priv) = derive_keys_from_seed(&ZERO_SEED);
        let a1 = derive_donation_subaddress(&spend_pub, &view_priv, b"user-A").unwrap();
        let a2 = derive_donation_subaddress(&spend_pub, &view_priv, b"user-B").unwrap();
        assert_ne!(a1, a2, "Different users must get different donation addresses");
    }

    #[test]
    fn test_generate_wallet_seed_not_zero() {
        let seed = generate_wallet_seed();
        // Astronomically unlikely to be all zeros.
        assert_ne!(&seed[..], &[0u8; 32]);
    }

    #[test]
    fn test_keys_derived_from_seed_are_deterministic() {
        let (sp1, vp1, vpriv1) = derive_keys_from_seed(&ZERO_SEED);
        let (sp2, vp2, vpriv2) = derive_keys_from_seed(&ZERO_SEED);
        assert_eq!(sp1, sp2);
        assert_eq!(vp1, vp2);
        assert_eq!(&vpriv1[..], &vpriv2[..]);
    }
}
