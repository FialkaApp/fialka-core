// Cross-platform integration tests for fialka-core.
//
// Goal: byte-for-byte compatibility between Rust (this lib), Android (Kotlin/JNI),
// and Desktop (C#/P/Invoke).
//
// Test vectors will be generated from the current Android implementation
// and used to validate the Rust implementation produces identical outputs.
//
// TODO (Phase 1+): add test vectors for:
//   - seed → identity keys (Ed25519, X25519, ML-KEM, ML-DSA)
//   - seed → .onion address
//   - AES-256-GCM encrypt/decrypt roundtrip
//   - ChaCha20-Poly1305 encrypt/decrypt roundtrip
//   - HKDF-SHA256 / HKDF-SHA512 known-answer test
//   - PQXDH handshake (sender + receiver produce same shared secret)
//   - Double Ratchet: 10-message exchange, skip-ahead, out-of-order
