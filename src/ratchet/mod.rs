/*
 * fialka-core — Cross-platform cryptographic core for Fialka
 * Copyright (C) 2024-2026 DevBot667 — GPL-3.0
 */

//! Full Double Ratchet — byte-for-byte compatible with `DoubleRatchet.kt` on Android.
//!
//! DH Ratchet step (matches `DoubleRatchet.dhRatchetStep()`):
//!   1. DH exchange: dh_secret = X25519(local_private, remote_public)
//!   2. KDF_RK:      PRK       = HMAC-SHA256(root_key, dh_secret)
//!                   new_root  = HMAC-SHA256(PRK, "Fialka-DR-root-ratchet\u0001")
//!                   new_chain = HMAC-SHA256(PRK, "Fialka-DR-chain-ratchet\u0002")
//!
//! Symmetric chain step (matches `DoubleRatchet.advanceChain()`):
//!   message_key = HMAC-SHA256(chain_key, 0x01)
//!   chain_key'  = HMAC-SHA256(chain_key, 0x02)
//!
//! SPQR — PQ ratchet (matches `DoubleRatchet.pqRatchetStep()`):
//!   new_root = hkdf_zero_salt(root_key || pq_secret, "Fialka-SPQR-pq-ratchet")
//!
//! All label strings match the Kotlin constants exactly (including the
//! \u0001 and \u0002 embedded in the DH ratchet labels).

use zeroize::Zeroizing;
use crate::crypto::kdf::{hmac_sha256, hkdf_zero_salt};
use crate::crypto::x25519::diffie_hellman;

/// How many sent messages between ML-KEM re-encapsulations.
/// Matches `DoubleRatchet.PQ_RATCHET_INTERVAL`.
pub const PQ_RATCHET_INTERVAL: u32 = 10;

// ── Ratchet initialization ────────────────────────────────────────────────────

/// Initial ratchet state — derived from the PQXDH shared secret.
pub struct InitialRatchetState {
    pub root_key: Zeroizing<[u8; 32]>,
    pub send_chain_key: Zeroizing<[u8; 32]>,
    pub recv_chain_key: Zeroizing<[u8; 32]>,
    /// Newly generated ephemeral X25519 private key (for DH ratchet).
    pub local_dh_private: Zeroizing<[u8; 32]>,
    /// Newly generated ephemeral X25519 public key (to be sent to the peer).
    pub local_dh_public: [u8; 32],
}

/// Initialize as the PQXDH initiator.
/// Matches `DoubleRatchet.initializeAsInitiator(identitySharedSecret)`.
pub fn init_as_initiator(identity_shared_secret: &[u8]) -> InitialRatchetState {
    let root_key = hkdf_zero_salt(identity_shared_secret, b"Fialka-DR-root");
    let send_chain = hkdf_zero_salt(&root_key, b"Fialka-DR-chain-init-send");
    let recv_chain = hkdf_zero_salt(&root_key, b"Fialka-DR-chain-init-recv");

    let ephemeral = crate::crypto::x25519::X25519KeyPair::random();

    InitialRatchetState {
        root_key: Zeroizing::new(root_key),
        send_chain_key: Zeroizing::new(send_chain),
        recv_chain_key: Zeroizing::new(recv_chain),
        local_dh_private: ephemeral.private_raw,
        local_dh_public: ephemeral.public_raw,
    }
}

/// Initialize as the PQXDH responder (chains are swapped vs initiator).
/// Matches `DoubleRatchet.initializeAsResponder(identitySharedSecret)`.
pub fn init_as_responder(identity_shared_secret: &[u8]) -> InitialRatchetState {
    let root_key = hkdf_zero_salt(identity_shared_secret, b"Fialka-DR-root");
    // Swapped: responder's recv = initiator's send, responder's send = initiator's recv
    let recv_chain = hkdf_zero_salt(&root_key, b"Fialka-DR-chain-init-send");
    let send_chain = hkdf_zero_salt(&root_key, b"Fialka-DR-chain-init-recv");

    let ephemeral = crate::crypto::x25519::X25519KeyPair::random();

    InitialRatchetState {
        root_key: Zeroizing::new(root_key),
        send_chain_key: Zeroizing::new(send_chain),
        recv_chain_key: Zeroizing::new(recv_chain),
        local_dh_private: ephemeral.private_raw,
        local_dh_public: ephemeral.public_raw,
    }
}

// ── DH Ratchet step ───────────────────────────────────────────────────────────

/// Result of a DH ratchet step.
pub struct DhRatchetResult {
    pub new_root_key: Zeroizing<[u8; 32]>,
    pub new_chain_key: Zeroizing<[u8; 32]>,
}

/// Perform one DH ratchet step.
/// Matches `DoubleRatchet.dhRatchetStep(rootKey, localPrivate, remotePub)`.
///
/// KDF_RK (Signal spec §2.2):
///   PRK       = HMAC-SHA256(salt=root_key, IKM=dh_secret)
///   new_root  = HMAC-SHA256(PRK, "Fialka-DR-root-ratchet\u0001")
///   new_chain = HMAC-SHA256(PRK, "Fialka-DR-chain-ratchet\u0002")
pub fn dh_ratchet_step(
    root_key: &[u8; 32],
    local_dh_private: &[u8; 32],
    remote_dh_public: &[u8; 32],
) -> DhRatchetResult {
    let dh_secret = diffie_hellman(local_dh_private, remote_dh_public);

    // HKDF-Extract: salt = root_key, IKM = dh_secret
    let mut prk = hmac_sha256(root_key, dh_secret.as_ref());

    // Kotlin: "Fialka-DR-root-ratchet\u0001" = bytes + 0x01 at end
    let new_root = hmac_sha256(&prk, b"Fialka-DR-root-ratchet\x01");
    // Kotlin: "Fialka-DR-chain-ratchet\u0002" = bytes + 0x02 at end
    let new_chain = hmac_sha256(&prk, b"Fialka-DR-chain-ratchet\x02");

    prk.zeroize();

    DhRatchetResult {
        new_root_key: Zeroizing::new(new_root),
        new_chain_key: Zeroizing::new(new_chain),
    }
}

// ── Symmetric chain step ──────────────────────────────────────────────────────

/// Advance a chain key and derive a message key.
/// Matches `DoubleRatchet.advanceChain(chainKey)`.
///
///   message_key = HMAC-SHA256(chain_key, 0x01)
///   chain_key'  = HMAC-SHA256(chain_key, 0x02)
///
/// Returns (new_chain_key, message_key_32_bytes).
pub fn advance_chain(chain_key: &[u8; 32]) -> (Zeroizing<[u8; 32]>, Zeroizing<[u8; 32]>) {
    let message_key = hmac_sha256(chain_key, &[0x01]);
    let new_chain_key = hmac_sha256(chain_key, &[0x02]);
    (Zeroizing::new(new_chain_key), Zeroizing::new(message_key))
}

// ── SPQR — Post-quantum ratchet step ─────────────────────────────────────────

/// Mix a fresh ML-KEM shared secret into the root key (SPQR).
/// Matches `DoubleRatchet.pqRatchetStep(rootKey, pqSharedSecret)`.
///
/// new_root = hkdf_zero_salt(root_key || pq_secret, "Fialka-SPQR-pq-ratchet")
pub fn pq_ratchet_step(root_key: &[u8; 32], pq_shared_secret: &[u8; 32]) -> Zeroizing<[u8; 32]> {
    let mut combined = [0u8; 64];
    combined[..32].copy_from_slice(root_key);
    combined[32..].copy_from_slice(pq_shared_secret);

    let new_root = hkdf_zero_salt(&combined, b"Fialka-SPQR-pq-ratchet");
    combined.zeroize();
    Zeroizing::new(new_root)
}

// ── PQXDH combined key derivation ────────────────────────────────────────────

/// Derive the PQXDH root key by combining X25519 and ML-KEM shared secrets.
/// Matches `CryptoManager.deriveRootKeyPQXDH(ssClassic, ssPQ)`.
///
/// Uses `deriveSymmetricKey(ssClassic || ssPQ)` which is:
///   HMAC-SHA256(zeros_32, combined)  → PRK
///   HMAC-SHA256(PRK, "Fialka-v2-message-key" || 0x01) → 32-byte key
pub fn derive_pqxdh_root_key(ss_classic: &[u8; 32], ss_pq: &[u8; 32]) -> Zeroizing<[u8; 32]> {
    let mut combined = [0u8; 64];
    combined[..32].copy_from_slice(ss_classic);
    combined[32..].copy_from_slice(ss_pq);

    // deriveSymmetricKey() in Kotlin = hkdfExtractExpand(combined, HKDF_INFO)
    // where HKDF_INFO = "Fialka-v2-message-key"
    let root = hkdf_zero_salt(&combined, b"Fialka-v2-message-key");
    combined.zeroize();
    Zeroizing::new(root)
}

// ── Zeroize ──────────────────────────────────────────────────────────────────

use zeroize::Zeroize;
