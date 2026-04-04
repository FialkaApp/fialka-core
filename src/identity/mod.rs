//! Identity derivation: seed → all key pairs + .onion v3 address.
//!
//! Mirrors logic currently in:
//!   Android: CryptoManager.kt  → deriveKeysFromSeed()
//!   Desktop: CryptoManager.cs  → DeriveKeysFromSeed()
//!
//! Seed: 24 BIP-39 words → 32-byte entropy
//! Derived keys (all via HKDF-SHA512 with domain-separated labels):
//!   - Ed25519 identity keypair  (signing + .onion address)
//!   - X25519 pre-key            (classic DH for PQXDH)
//!   - ML-KEM-1024 keypair       (post-quantum KEM for PQXDH)
//!   - ML-DSA-44 keypair         (post-quantum signing)
//!
//! .onion v3 derivation:
//!   public_key || checksum || version (0x03) → base32 → .onion
//!
//! TODO: implement FialkaIdentity struct + derive_from_seed()

// Placeholder — implement in Phase 1
