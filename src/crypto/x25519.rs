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
    /// Raw 32-byte private scalar (before clamping — clamping is applied internally during DH).
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
        Self {
            private_raw,
            public_raw: public.to_bytes(),
        }
    }
}

/// X25519 Diffie-Hellman.
/// Matches `CryptoManager.performEphemeralKeyAgreement(localPriv, remotePub)`.
///
/// Both keys are raw 32-byte arrays (no PKCS8/X.509 wrappers — those are Java-specific).
pub fn diffie_hellman(local_private_raw: &[u8; 32], remote_public_raw: &[u8; 32]) -> Zeroizing<[u8; 32]> {
    let secret = StaticSecret::from(*local_private_raw);
    let remote_pub = PublicKey::from(*remote_public_raw);
    let shared = secret.diffie_hellman(&remote_pub);
    Zeroizing::new(shared.to_bytes())
}

/// Convert an Ed25519 public key to its X25519 equivalent (birational map).
///
/// Matches `CryptoManager.ed25519PublicKeyToX25519Raw(ed25519PubBytes)`:
///   u = (1 + y) / (1 - y)  mod  p   (p = 2^255 - 19)
///
/// Uses `ed25519-dalek`'s `VerifyingKey::to_montgomery()` which implements
/// the same math as the Kotlin BigInteger code.
pub fn ed25519_pub_to_x25519(ed25519_pub_bytes: &[u8; 32]) -> Option<[u8; 32]> {
    let vk = Ed25519VerifyingKey::from_bytes(ed25519_pub_bytes).ok()?;
    Some(vk.to_montgomery().to_bytes())
}
