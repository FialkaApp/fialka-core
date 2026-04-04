/*
 * fialka-core — Cross-platform cryptographic core for Fialka
 * Copyright (C) 2024-2026 DevBot667 — GPL-3.0
 */

//! Persistent Double Ratchet session state.
//!
//! `RatchetState` holds everything needed to encrypt the next outgoing message
//! and to decrypt incoming messages (including out-of-order ones via skipped keys).
//!
//! Serialization: the struct derives serde Serialize/Deserialize so it can be
//! persisted to the local SQLite database (as a JSON blob or MessagePack blob).
//!
//! Skipped message keys: the Signal spec requires storing message keys for
//! messages that arrived out of order.  We keep a bounded map keyed by
//! (dh_pub_hex, msg_index) → 32-byte message key (hex).
//! The bound MAX_SKIP prevents memory exhaustion from a malicious peer.

use std::collections::HashMap;
use zeroize::{Zeroize, Zeroizing};

/// Maximum number of skipped message keys to store.
/// Matches Android `ConversationManager.MAX_SKIP`.
pub const MAX_SKIP: usize = 100;

/// Key for the skipped-message-key map: (remote DH public key hex, message index).
pub type SkipKey = (String, u32);

/// Persistent Double Ratchet session state.
///
/// Both sides start from an `InitialRatchetState` (produced by `ratchet::init_as_*`).
/// After that, this struct is updated on every send/receive and persisted to the DB.
#[derive(Clone)]
pub struct RatchetState {
    // ── Root key ──────────────────────────────────────────────────────────────
    /// Current root key (32 bytes, zeroized on drop).
    pub root_key: Zeroizing<[u8; 32]>,

    // ── Sending chain ─────────────────────────────────────────────────────────
    /// Current sending chain key (32 bytes).
    pub send_chain_key: Zeroizing<[u8; 32]>,
    /// Number of messages sent in the current sending chain.
    pub send_count: u32,

    // ── Receiving chain ───────────────────────────────────────────────────────
    /// Current receiving chain key (32 bytes).
    pub recv_chain_key: Zeroizing<[u8; 32]>,
    /// Number of messages received in the current receiving chain.
    pub recv_count: u32,

    // ── DH ratchet keypairs ───────────────────────────────────────────────────
    /// Our current ephemeral X25519 private key (32 bytes).
    pub local_dh_private: Zeroizing<[u8; 32]>,
    /// Our current ephemeral X25519 public key (32 bytes — sent to peer).
    pub local_dh_public: [u8; 32],
    /// The remote peer's latest ephemeral X25519 public key (32 bytes).
    /// `None` until the first message from the peer arrives.
    pub remote_dh_public: Option<[u8; 32]>,

    // ── Previous chain length ─────────────────────────────────────────────────
    /// Number of messages in the *previous* sending chain (PN in the Signal spec).
    /// Sent in the message header so the peer can advance past skipped messages.
    pub prev_send_count: u32,

    // ── PQ ratchet ────────────────────────────────────────────────────────────
    /// Number of messages sent since the last ML-KEM re-encapsulation.
    pub pq_send_counter: u32,

    // ── Skipped message keys ──────────────────────────────────────────────────
    /// Keys for messages that arrived out of order.
    /// key   = (remote_dh_pub_hex, message_index)
    /// value = 32-byte message key (hex string)
    pub skipped_keys: HashMap<SkipKey, String>,
}

impl RatchetState {
    /// Create a new ratchet state from the result of `ratchet::init_as_initiator/responder`.
    pub fn new(
        root_key: [u8; 32],
        send_chain_key: [u8; 32],
        recv_chain_key: [u8; 32],
        local_dh_private: [u8; 32],
        local_dh_public: [u8; 32],
    ) -> Self {
        Self {
            root_key: Zeroizing::new(root_key),
            send_chain_key: Zeroizing::new(send_chain_key),
            send_count: 0,
            recv_chain_key: Zeroizing::new(recv_chain_key),
            recv_count: 0,
            local_dh_private: Zeroizing::new(local_dh_private),
            local_dh_public,
            remote_dh_public: None,
            prev_send_count: 0,
            pq_send_counter: 0,
            skipped_keys: HashMap::new(),
        }
    }

    // ── Send ──────────────────────────────────────────────────────────────────

    /// Advance the send chain and return the next message key.
    ///
    /// Also returns `send_count` *before* the advance (i.e. the index of this
    /// message) so the header can carry `(local_dh_public, msg_index, prev_send_count)`.
    pub fn next_send_key(&mut self) -> (u32, Zeroizing<[u8; 32]>) {
        use crate::crypto::kdf::hmac_sha256;
        let msg_index = self.send_count;
        let mk = Zeroizing::new(hmac_sha256(self.send_chain_key.as_ref(), &[0x01]));
        let new_ck = hmac_sha256(self.send_chain_key.as_ref(), &[0x02]);
        *self.send_chain_key = new_ck;
        self.send_count += 1;
        self.pq_send_counter += 1;
        (msg_index, mk)
    }

    // ── Receive ───────────────────────────────────────────────────────────────

    /// Try to consume a skipped message key (out-of-order delivery).
    ///
    /// Returns `Some(key_32)` if found and removes it from the map.
    pub fn consume_skipped_key(
        &mut self,
        remote_dh_pub: &[u8; 32],
        msg_index: u32,
    ) -> Option<Zeroizing<[u8; 32]>> {
        let k = (hex::encode(remote_dh_pub), msg_index);
        let hex_key = self.skipped_keys.remove(&k)?;
        let bytes = hex::decode(&hex_key).ok()?;
        if bytes.len() != 32 { return None; }
        let mut arr = [0u8; 32];
        arr.copy_from_slice(&bytes);
        Some(Zeroizing::new(arr))
    }

    /// Advance the recv chain, storing skipped keys, until `target_index`.
    ///
    /// Returns `Err` if we would exceed MAX_SKIP.
    pub fn skip_recv_until(
        &mut self,
        remote_dh_pub: &[u8; 32],
        target_index: u32,
    ) -> Result<(), &'static str> {
        if target_index.saturating_sub(self.recv_count) as usize > MAX_SKIP {
            return Err("too many skipped messages — session compromised or replay");
        }
        use crate::crypto::kdf::hmac_sha256;
        while self.recv_count < target_index {
            if self.skipped_keys.len() >= MAX_SKIP {
                return Err("skipped key store full");
            }
            let mk = hmac_sha256(self.recv_chain_key.as_ref(), &[0x01]);
            let new_ck = hmac_sha256(self.recv_chain_key.as_ref(), &[0x02]);
            *self.recv_chain_key = new_ck;
            let k = (hex::encode(remote_dh_pub), self.recv_count);
            self.skipped_keys.insert(k, hex::encode(mk));
            self.recv_count += 1;
        }
        Ok(())
    }

    /// Advance the recv chain by one and return the message key for `recv_count`.
    pub fn next_recv_key(&mut self) -> (u32, Zeroizing<[u8; 32]>) {
        use crate::crypto::kdf::hmac_sha256;
        let msg_index = self.recv_count;
        let mk = Zeroizing::new(hmac_sha256(self.recv_chain_key.as_ref(), &[0x01]));
        let new_ck = hmac_sha256(self.recv_chain_key.as_ref(), &[0x02]);
        *self.recv_chain_key = new_ck;
        self.recv_count += 1;
        (msg_index, mk)
    }

    // ── DH Ratchet step ───────────────────────────────────────────────────────

    /// Perform a DH ratchet step when a new remote DH public key is received.
    ///
    /// Steps:
    ///   1. Store skipped recv keys for the old remote DH key
    ///   2. DH ratchet step → new root key + new recv chain key
    ///   3. Generate a new local ephemeral keypair
    ///   4. DH ratchet step again → new root key + new send chain key
    ///   5. Reset counters
    pub fn dh_ratchet(
        &mut self,
        new_remote_dh_pub: [u8; 32],
        remote_msg_prev_count: u32,
    ) -> Result<(), &'static str> {
        use crate::ratchet::{dh_ratchet_step};
        use crate::crypto::x25519::X25519KeyPair;

        // 1. Skip remaining recv keys for the old remote DH key (PN from header)
        if let Some(old_remote) = self.remote_dh_public {
            self.skip_recv_until(&old_remote, remote_msg_prev_count)?;
        }

        // 2. Update remote DH public key
        self.remote_dh_public = Some(new_remote_dh_pub);
        self.prev_send_count = self.send_count;
        self.send_count = 0;
        self.recv_count = 0;

        // 3. Recv chain ratchet step: DH(our_current_priv, new_remote_pub)
        let recv_result = dh_ratchet_step(
            &self.root_key,
            &self.local_dh_private,
            &new_remote_dh_pub,
        );
        *self.root_key = *recv_result.new_root_key;
        *self.recv_chain_key = *recv_result.new_chain_key;

        // 4. Generate new local ephemeral keypair
        let new_ephemeral = X25519KeyPair::random();
        *self.local_dh_private = *new_ephemeral.private_raw;
        self.local_dh_public = new_ephemeral.public_raw;

        // 5. Send chain ratchet step: DH(our_new_priv, new_remote_pub)
        let send_result = dh_ratchet_step(
            &self.root_key,
            &self.local_dh_private,
            &new_remote_dh_pub,
        );
        *self.root_key = *send_result.new_root_key;
        *self.send_chain_key = *send_result.new_chain_key;

        Ok(())
    }

    // ── PQ ratchet ────────────────────────────────────────────────────────────

    /// Apply a SPQR PQ ratchet step (called every PQ_RATCHET_INTERVAL sends).
    pub fn apply_pq_ratchet(&mut self, pq_shared_secret: &[u8; 32]) {
        let new_root = crate::ratchet::pq_ratchet_step(&self.root_key, pq_shared_secret);
        *self.root_key = *new_root;
        self.pq_send_counter = 0;
    }

    /// Returns true if a PQ ratchet step is due.
    pub fn pq_ratchet_due(&self) -> bool {
        self.pq_send_counter >= crate::ratchet::PQ_RATCHET_INTERVAL
    }
}

// Zeroize all key material on drop.
impl Drop for RatchetState {
    fn drop(&mut self) {
        // Zeroizing fields handle themselves; clear the skipped keys map too.
        for (_, v) in self.skipped_keys.drain() {
            let mut s = v;
            s.zeroize();
        }
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ratchet::{init_as_initiator, init_as_responder, PQ_RATCHET_INTERVAL};

    fn make_shared_secret() -> [u8; 32] {
        [0xAB; 32]
    }

    fn make_state_pair() -> (RatchetState, RatchetState) {
        let ss = make_shared_secret();
        let alice_init = init_as_initiator(&ss);
        let bob_init = init_as_responder(&ss);

        let alice = RatchetState::new(
            *alice_init.root_key,
            *alice_init.send_chain_key,
            *alice_init.recv_chain_key,
            *alice_init.local_dh_private,
            alice_init.local_dh_public,
        );
        let bob = RatchetState::new(
            *bob_init.root_key,
            *bob_init.send_chain_key,
            *bob_init.recv_chain_key,
            *bob_init.local_dh_private,
            bob_init.local_dh_public,
        );
        (alice, bob)
    }

    #[test]
    fn test_send_count_increments() {
        let (mut alice, _) = make_state_pair();
        let (idx0, _mk0) = alice.next_send_key();
        let (idx1, _mk1) = alice.next_send_key();
        assert_eq!(idx0, 0);
        assert_eq!(idx1, 1);
        assert_eq!(alice.send_count, 2);
    }

    #[test]
    fn test_send_keys_distinct() {
        let (mut alice, _) = make_state_pair();
        let (_i0, mk0) = alice.next_send_key();
        let (_i1, mk1) = alice.next_send_key();
        let (_i2, mk2) = alice.next_send_key();
        // All three message keys must be distinct
        assert_ne!(*mk0, *mk1);
        assert_ne!(*mk1, *mk2);
        assert_ne!(*mk0, *mk2);
    }

    #[test]
    fn test_symmetric_chain_alice_sends_bob_receives() {
        // Alice and Bob share the same initial state from the same shared secret.
        // Alice's send chain = Bob's recv chain (initiator convention).
        let ss = make_shared_secret();
        let alice_init = init_as_initiator(&ss);
        let bob_init   = init_as_responder(&ss);

        let mut alice = RatchetState::new(
            *alice_init.root_key,
            *alice_init.send_chain_key,
            *alice_init.recv_chain_key,
            *alice_init.local_dh_private,
            alice_init.local_dh_public,
        );
        let mut bob = RatchetState::new(
            *bob_init.root_key,
            *bob_init.send_chain_key,
            *bob_init.recv_chain_key,
            *bob_init.local_dh_private,
            bob_init.local_dh_public,
        );

        // Send 5 messages Alice → Bob
        for _ in 0..5 {
            let (_i, alice_mk) = alice.next_send_key();
            let (_j, bob_mk)   = bob.next_recv_key();
            assert_eq!(*alice_mk, *bob_mk,
                "Alice's send key must equal Bob's recv key for the same message index");
        }
    }

    #[test]
    fn test_skip_recv_until_stores_keys() {
        let (mut alice, mut bob) = make_state_pair();
        let remote_pub = alice.local_dh_public;

        // Generate 3 send keys for Alice
        let (_i0, mk0) = alice.next_send_key();
        let (_i1, mk1) = alice.next_send_key();
        let (_i2, mk2) = alice.next_send_key();

        // Bob skips to index 2 (stores keys for 0 and 1)
        bob.skip_recv_until(&remote_pub, 2).unwrap();
        assert_eq!(bob.skipped_keys.len(), 2);

        // Bob now consumes key for index 0
        let recovered0 = bob.consume_skipped_key(&remote_pub, 0).unwrap();
        assert_eq!(*recovered0, *mk0);

        // Bob consumes key for index 1
        let recovered1 = bob.consume_skipped_key(&remote_pub, 1).unwrap();
        assert_eq!(*recovered1, *mk1);

        // Bob receives message 2 in order
        let (_j2, bob_mk2) = bob.next_recv_key();
        assert_eq!(*bob_mk2, *mk2);

        assert!(bob.skipped_keys.is_empty());
    }

    #[test]
    fn test_skip_recv_exceeds_max_skip() {
        let (_, mut bob) = make_state_pair();
        let remote_pub = [0x42u8; 32];
        // Try to skip MAX_SKIP + 1 — must fail
        let result = bob.skip_recv_until(&remote_pub, (MAX_SKIP + 1) as u32);
        assert!(result.is_err());
    }

    #[test]
    fn test_pq_ratchet_due_flag() {
        let (mut alice, _) = make_state_pair();
        for _ in 0..PQ_RATCHET_INTERVAL {
            assert!(!alice.pq_ratchet_due());
            alice.next_send_key();
        }
        assert!(alice.pq_ratchet_due());
    }

    #[test]
    fn test_apply_pq_ratchet_changes_root() {
        let (mut alice, _) = make_state_pair();
        let old_root = *alice.root_key;
        let pq_secret = [0x55u8; 32];
        alice.apply_pq_ratchet(&pq_secret);
        assert_ne!(*alice.root_key, old_root);
        assert_eq!(alice.pq_send_counter, 0);
    }
}
