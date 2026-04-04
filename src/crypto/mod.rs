//! Cryptographic primitives for Fialka.
//!
//! Replaces BouncyCastle on Android (JNI) and Desktop (.NET P/Invoke).
//!
//! Modules (to be implemented):
//! - `ed25519`   — Ed25519 key generation, signing, verification
//! - `x25519`    — X25519 ECDH key exchange
//! - `mlkem`     — ML-KEM-1024 encapsulation / decapsulation (NIST FIPS 203)
//! - `mldsa`     — ML-DSA-44 signing / verification (NIST FIPS 204)
//! - `aesgcm`    — AES-256-GCM authenticated encryption
//! - `chacha`    — ChaCha20-Poly1305 authenticated encryption
//! - `kdf`       — HKDF-SHA256 / HKDF-SHA512

pub mod ed25519;
pub mod x25519;
pub mod mlkem;
pub mod mldsa;
pub mod aesgcm;
pub mod chacha;
pub mod kdf;
