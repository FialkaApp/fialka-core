/*
 * fialka-core — Cross-platform cryptographic core for Fialka
 * Copyright (C) 2024-2026 DevBot667 — GPL-3.0
 */

//! X25519 ECDH key exchange.
//!
//! Byte-for-byte compatible with Android:
//!   CryptoManager.kt — X25519 JCA KeyFactory / KeyAgreement
//!
//! Identity X25519 derivation from Ed25519 seed (birational map):
//!   x25519_private_raw = SHA-512(ed25519_seed)[0..31]
//!   The JCA and x25519-dalek both clamp the scalar internally.
//!
//! Ephemeral X25519: purely random, JCA `KeyPairGenerator("X25519")`.

use sha2::{Digest, Sha512};
use x25519_dalek::{PublicKey, StaticSecret};
use zeroize::Zeroizing;
use ed25519_dalek::VerifyingKey as Ed25519VerifyingKey;

/// Raw bytes of an X25519 key pair (32-byte private + 32-byte public).
pub struct X25519KeyPair {
    /// Raw 32-byte private scalar (before clamping — clamping applied internally during DH).
    pub private_raw: Zeroizing<[u8; 32]>,
    /// Raw 32-byte X25519 public key (u-coordinate, little-endian).
    pub public_raw: [u8; 32],
}

impl X25519KeyPair {
    /// Derive X25519 key pair from Ed25519 seed (birational map).
    ///
    /// Matches `CryptoManager.deriveAndStoreAllKeys()`:
    ///   x25519_private = SHA-512(seed)[0..31]   (no manual clamping — JCA clamps internally)
    ///   x25519_public  = x25519_private * base_point
    pub fn from_ed25519_seed(seed: &[u8; 32]) -> Self {
        let sha512 = Sha512::digest(&seed[..]);
        let mut private_raw = Zeroizing::new([0u8; 32]);
        private_raw.copy_from_slice(&sha512[..32]);

        // StaticSecret clamps the scalar internally (same as JCA X25519 provider)
        let secret = StaticSecret::from(*private_raw);
        let public = PublicKey::from(&secret);

        Self {
            private_raw,
            public_raw: public.to_bytes(),
        }
    }

    /// Generate a random ephemeral X25519 key pair.
    /// Matches `CryptoManager.generateEphemeralKeyPair()`.
    pub fn random() -> Self {
        use rand_core::OsRng;
        let secret = StaticSecret::random_from_rng(OsRng);
        let public = PublicKey::from(&secret);
        let private_raw = Zeroizing::new(*secret.as_bytes());
        Self { private_raw, public_raw: public.to_bytes() }
    }
}

/// X25519 Diffie-Hellman.
/// Matches `CryptoManager.performEphemeralKeyAgreement(localPriv, remotePub)`.
pub fn diffie_hellman(local_private_raw: &[u8; 32], remote_public_raw: &[u8; 32]) -> Zeroizing<[u8; 32]> {
    let secret     = StaticSecret::from(*local_private_raw);
    let remote_pub = PublicKey::from(*remote_public_raw);
    let shared     = secret.diffie_hellman(&remote_pub);
    Zeroizing::new(shared.to_bytes())
}

/// Convert an Ed25519 public key to its X25519 equivalent (birational map).
pub fn ed25519_pub_to_x25519(ed25519_pub_bytes: &[u8; 32]) -> Option<[u8; 32]> {
    let vk = Ed25519VerifyingKey::from_bytes(ed25519_pub_bytes).ok()?;
    Some(vk.to_montgomery().to_bytes())
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

    /// Public key derivation from seed is deterministic.
    #[test]
    fn test_from_seed_deterministic() {
        let kp1 = X25519KeyPair::from_ed25519_seed(&SEED);
        let kp2 = X25519KeyPair::from_ed25519_seed(&SEED);
        assert_eq!(kp1.public_raw, kp2.public_raw);
        assert_eq!(*kp1.private_raw, *kp2.private_raw);
    }

    /// Different seed → different keys.
    #[test]
    fn test_from_seed_sensitivity() {
        let mut other_seed = SEED;
        other_seed[0] ^= 0x01;
        let kp1 = X25519KeyPair::from_ed25519_seed(&SEED);
        let kp2 = X25519KeyPair::from_ed25519_seed(&other_seed);
        assert_ne!(kp1.public_raw, kp2.public_raw);
    }

    /// DH is commutative: DH(a_priv, b_pub) == DH(b_priv, a_pub).
    #[test]
    fn test_dh_commutative() {
        let kp_a = X25519KeyPair::from_ed25519_seed(&SEED);
        let mut seed_b = SEED;
        seed_b[0] = 0xFF;
        let kp_b = X25519KeyPair::from_ed25519_seed(&seed_b);

        let ss_a = diffie_hellman(&kp_a.private_raw, &kp_b.public_raw);
        let ss_b = diffie_hellman(&kp_b.private_raw, &kp_a.public_raw);
        assert_eq!(*ss_a, *ss_b, "DH must be commutative (Alice == Bob)");
    }

    /// DH shared secret length = 32 bytes.
    #[test]
    fn test_dh_output_len() {
        let kp_a = X25519KeyPair::random();
        let kp_b = X25519KeyPair::random();
        let ss = diffie_hellman(&kp_a.private_raw, &kp_b.public_raw);
        assert_eq!(ss.len(), 32);
    }

    /// DH with wrong key produces different result.
    #[test]
    fn test_dh_wrong_key_different_secret() {
        let kp_a = X25519KeyPair::from_ed25519_seed(&SEED);
        let kp_b = X25519KeyPair::random();
        let kp_c = X25519KeyPair::random();
        // DH(a, b) ≠ DH(a, c) with overwhelmingly high probability
        let ss_ab = diffie_hellman(&kp_a.private_raw, &kp_b.public_raw);
        let ss_ac = diffie_hellman(&kp_a.private_raw, &kp_c.public_raw);
        assert_ne!(*ss_ab, *ss_ac);
    }

    /// Private key is derived from SHA-512(seed)[0..31] (birational map).
    #[test]
    fn test_private_from_sha512_seed() {
        use sha2::{Sha512, Digest};
        let kp = X25519KeyPair::from_ed25519_seed(&SEED);
        let sha512 = Sha512::digest(&SEED[..]);
        assert_eq!(*kp.private_raw, sha512[..32], "private raw must be SHA-512(seed)[0..31]");
    }

    /// Random keypairs differ from each other.
    #[test]
    fn test_random_keypairs_distinct() {
        let kp1 = X25519KeyPair::random();
        let kp2 = X25519KeyPair::random();
        assert_ne!(kp1.public_raw, kp2.public_raw);
    }

    /// ed25519_pub_to_x25519 returns Some for a valid key.
    #[test]
    fn test_ed25519_pub_to_x25519_valid() {
        use crate::crypto::ed25519::Ed25519KeyPair;
        let ed_kp = Ed25519KeyPair::from_seed(&SEED);
        let result = ed25519_pub_to_x25519(&ed_kp.public_key_bytes());
        assert!(result.is_some());
    }
}
