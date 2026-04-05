/*
 * fialka-core — Cross-platform cryptographic core for Fialka
 * Copyright (C) 2024-2026 DevBot667 — GPL-3.0
 */

pub mod crypto;
pub mod identity;
pub mod protocol;
pub mod ratchet;
pub mod ffi;

#[cfg(not(target_os = "android"))]
#[path = "ffi/desktop.rs"]
pub mod ffi_desktop;
