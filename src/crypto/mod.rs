/*
 * fialka-core — Cross-platform cryptographic core for Fialka
 * Copyright (C) 2024-2026 DevBot667 — GPL-3.0
 */

//! Cryptographic primitives for Fialka.
//!
//! Replaces BouncyCastle on Android (JNI) and Desktop (.NET P/Invoke).
//!
//! Modules:
//! - `fixed_rng`  — Deterministic RNG for ML-KEM / ML-DSA seed-based keygen
//! - `kdf`        — HMAC-SHA256 + HKDF-SHA256
//! - `ed25519`    — Ed25519 key generation, signing, verification
//! - `x25519`     — X25519 ECDH key exchange
//! - `mlkem`      — ML-KEM-1024 (FIPS 203)
//! - `mldsa`      — ML-DSA-44   (FIPS 204)
//! - `aesgcm`     — AES-256-GCM authenticated encryption
//! - `chacha`     — ChaCha20-Poly1305 authenticated encryption

pub mod fixed_rng;
pub mod kdf;
pub mod ed25519;
pub mod x25519;
pub mod mlkem;
pub mod mldsa;
pub mod aesgcm;
pub mod chacha;
