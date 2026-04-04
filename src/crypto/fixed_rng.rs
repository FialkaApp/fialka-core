/*
 * fialka-core — Cross-platform cryptographic core for Fialka
 * Copyright (C) 2024-2026 DevBot667 — GPL-3.0
 */

//! Deterministic RNG that feeds pre-computed seed bytes.
//! Used for ML-KEM and ML-DSA deterministic key generation — mirrors
//! `CryptoManager.FixedSecureRandom` in the Android code.

use rand_core::{CryptoRng, RngCore, Error};

/// A `CryptoRng` backed by a fixed byte slice.
/// Panics if more bytes are requested than available — same as the Kotlin version.
pub struct FixedRng<'a> {
    data: &'a [u8],
    offset: usize,
}

impl<'a> FixedRng<'a> {
    pub fn new(data: &'a [u8]) -> Self {
        Self { data, offset: 0 }
    }
}

impl RngCore for FixedRng<'_> {
    fn next_u32(&mut self) -> u32 {
        let mut buf = [0u8; 4];
        self.fill_bytes(&mut buf);
        u32::from_be_bytes(buf)
    }

    fn next_u64(&mut self) -> u64 {
        let mut buf = [0u8; 8];
        self.fill_bytes(&mut buf);
        u64::from_be_bytes(buf)
    }

    fn fill_bytes(&mut self, dest: &mut [u8]) {
        let available = self.data.len() - self.offset;
        assert!(
            dest.len() <= available,
            "FixedRng exhausted: need {} but only {} bytes remain",
            dest.len(),
            available
        );
        dest.copy_from_slice(&self.data[self.offset..self.offset + dest.len()]);
        self.offset += dest.len();
    }

    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), Error> {
        self.fill_bytes(dest);
        Ok(())
    }
}

// Mark as cryptographically secure (it is, when seeded with HKDF-derived bytes).
impl CryptoRng for FixedRng<'_> {}
