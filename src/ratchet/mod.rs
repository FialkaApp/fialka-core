//! Double Ratchet + PQXDH key agreement and message encryption.
//!
//! Must be byte-for-byte compatible with:
//!   Android: DoubleRatchet.kt (BouncyCastle impl)
//!   Desktop: DoubleRatchet.cs (BouncyCastle impl)
//!
//! PQXDH initial key agreement combines:
//!   - X25519 ECDH (classical forward secrecy)
//!   - ML-KEM-1024 encapsulation (post-quantum forward secrecy)
//!   → Combined via HKDF-SHA512
//!
//! Double Ratchet chain:
//!   - Root Chain Key (RCK) — ratchets on every DH step
//!   - Sending Chain Key (SCK) — ratchets on every sent message
//!   - Receiving Chain Key (RCK) — ratchets on every received message
//!   - Message keys: AES-256-GCM (or ChaCha20-Poly1305)
//!
//! TODO: implement RatchetState, pqxdh_init_sender(), pqxdh_init_receiver(),
//!       ratchet_encrypt(), ratchet_decrypt()

// Placeholder — implement in Phase 2
