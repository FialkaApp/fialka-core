/*
 * fialka-core — Cross-platform cryptographic core for Fialka
 * Copyright (C) 2024-2026 DevBot667 — GPL-3.0
 */

//! Android JNI bridge.
//!
//! Kotlin side:
//!   object FialkaNative {
//!       init { System.loadLibrary("fialka_core") }
//!       external fun hmacSha256(key: ByteArray, data: ByteArray): ByteArray
//!       // …
//!   }
//!
//! All functions follow:
//!   • Inputs  → individual JByteArray parameters; jint/jlong for primitives
//!   • Output  → single JByteArray (multi-value results concatenated with known offsets)
//!   • Errors  → throw RuntimeException, return null array
//!
//! Wire formats (Kotlin splits by fixed offsets):
//!   encryptAes / encryptChaCha  → iv/nonce(12) || ciphertext
//!   decryptAes / decryptChaCha  → UTF-8 plaintext bytes
//!   encryptFile                 → key(32) || iv(12) || ciphertext
//!   x25519GenerateEphemeral     → priv(32) || pub(32)
//!   mlkemKeygenFromSeed         → ek(1568) || dk(3168)
//!   mlkemEncaps                 → ct(1568) || ss(32)
//!   mldsaKeygenFromSeed         → vk(1312) || sk(2560)
//!   identityDerive              → ed_pub(32) || x25519_pub(32) || x25519_priv(32)
//!                                  || mlkem_ek(1568) || mlkem_dk(3168)
//!                                  || mldsa_vk(1312) || mldsa_sk(2560)
//!   ratchetInitAsInitiator/Responder → root(32)||send_chain(32)||recv_chain(32)
//!                                       ||dh_priv(32)||dh_pub(32)
//!   ratchetDhStep               → new_root(32) || new_chain(32)
//!   ratchetAdvanceChain         → new_chain(32) || msg_key(32)
//!   ed25519Verify / mldsaVerify → [1] = valid, [0] = invalid

#![cfg(target_os = "android")]

use jni::JNIEnv;
use jni::objects::{JByteArray, JObject};
use jni::sys::{jint, jlong};
use std::ptr;

use crate::crypto::{kdf, aesgcm, chacha};
use crate::crypto::ed25519::{self as ed25519_mod, Ed25519KeyPair};
use crate::crypto::x25519 as x25519_mod;
use crate::crypto::{mlkem, mldsa};
use crate::identity::{FialkaIdentity, compute_onion_from_ed25519, derive_account_id};
use crate::ratchet;

// ── Internal helpers ──────────────────────────────────────────────────────────

#[inline]
fn get_bytes<'l>(env: &mut JNIEnv<'l>, arr: &JByteArray<'l>) -> Result<Vec<u8>, String> {
    env.convert_byte_array(arr).map_err(|e| e.to_string())
}

#[inline]
fn out_bytes<'l>(env: &mut JNIEnv<'l>, data: &[u8]) -> JByteArray<'l> {
    env.byte_array_from_slice(data)
        .unwrap_or_else(|_| unsafe { JByteArray::from_raw(ptr::null_mut()) })
}

#[inline]
fn to32(v: &[u8]) -> Result<[u8; 32], String> {
    v.try_into().map_err(|_| format!("Expected 32 bytes, got {}", v.len()))
}
#[inline]
fn to64(v: &[u8]) -> Result<[u8; 64], String> {
    v.try_into().map_err(|_| format!("Expected 64 bytes, got {}", v.len()))
}

macro_rules! throw_ret {
    ($env:expr, $msg:expr) => {{
        let _ = $env.throw_new("java/lang/RuntimeException", $msg);
        return unsafe { JByteArray::from_raw(ptr::null_mut()) };
    }};
}

macro_rules! ok {
    ($env:expr, $res:expr) => {
        match $res {
            Ok(v) => v,
            Err(e) => throw_ret!($env, &format!("{e}")),
        }
    };
}

// ─────────────────────────────────────────────────────────────────────────────
// 1. HMAC-SHA256
// ─────────────────────────────────────────────────────────────────────────────

/// `FialkaNative.hmacSha256(key: ByteArray, data: ByteArray): ByteArray` → [32]
#[no_mangle]
pub extern "system" fn Java_com_fialkaapp_fialka_crypto_FialkaNative_hmacSha256<'l>(
    mut env: JNIEnv<'l>, _this: JObject<'l>,
    key:  JByteArray<'l>,
    data: JByteArray<'l>,
) -> JByteArray<'l> {
    let key  = ok!(env, get_bytes(&mut env, &key));
    let data = ok!(env, get_bytes(&mut env, &data));
    out_bytes(&mut env, &kdf::hmac_sha256(&key, &data))
}

// ─────────────────────────────────────────────────────────────────────────────
// 2. HKDF-SHA256
// ─────────────────────────────────────────────────────────────────────────────

/// `FialkaNative.hkdfSha256(ikm, salt, info, length: Int): ByteArray`
#[no_mangle]
pub extern "system" fn Java_com_fialkaapp_fialka_crypto_FialkaNative_hkdfSha256<'l>(
    mut env: JNIEnv<'l>, _this: JObject<'l>,
    ikm:    JByteArray<'l>,
    salt:   JByteArray<'l>,
    info:   JByteArray<'l>,
    length: jint,
) -> JByteArray<'l> {
    let ikm  = ok!(env, get_bytes(&mut env, &ikm));
    let salt = ok!(env, get_bytes(&mut env, &salt));
    let info = ok!(env, get_bytes(&mut env, &info));
    if length <= 0 { throw_ret!(env, "HKDF length must be > 0"); }
    out_bytes(&mut env, &kdf::hkdf_sha256(&ikm, &salt, &info, length as usize))
}

// ─────────────────────────────────────────────────────────────────────────────
// 3. HKDF zero-salt single-block expand
// ─────────────────────────────────────────────────────────────────────────────

/// `FialkaNative.hkdfZeroSalt(ikm, info): ByteArray` → [32]
#[no_mangle]
pub extern "system" fn Java_com_fialkaapp_fialka_crypto_FialkaNative_hkdfZeroSalt<'l>(
    mut env: JNIEnv<'l>, _this: JObject<'l>,
    ikm:  JByteArray<'l>,
    info: JByteArray<'l>,
) -> JByteArray<'l> {
    let ikm  = ok!(env, get_bytes(&mut env, &ikm));
    let info = ok!(env, get_bytes(&mut env, &info));
    out_bytes(&mut env, &kdf::hkdf_zero_salt(&ikm, &info))
}

// ─────────────────────────────────────────────────────────────────────────────
// 4. AES-256-GCM encrypt  (bucket padding — matches CryptoManager.encrypt)
// ─────────────────────────────────────────────────────────────────────────────

/// `FialkaNative.encryptAes(plaintext: ByteArray /*UTF-8*/, key: ByteArray): ByteArray`
/// Returns: iv(12) || ciphertext
#[no_mangle]
pub extern "system" fn Java_com_fialkaapp_fialka_crypto_FialkaNative_encryptAes<'l>(
    mut env: JNIEnv<'l>, _this: JObject<'l>,
    plaintext: JByteArray<'l>,
    key:       JByteArray<'l>,
) -> JByteArray<'l> {
    let pt_bytes  = ok!(env, get_bytes(&mut env, &plaintext));
    let key_bytes = ok!(env, get_bytes(&mut env, &key));
    let key32  = ok!(env, to32(&key_bytes));
    let pt_str = ok!(env, std::str::from_utf8(&pt_bytes).map_err(|e| e.to_string()));
    let enc = ok!(env, aesgcm::encrypt(pt_str, &key32).map_err(|_| "AES-GCM encrypt failed".to_string()));
    let mut out = Vec::with_capacity(12 + enc.ciphertext.len());
    out.extend_from_slice(&enc.iv);
    out.extend_from_slice(&enc.ciphertext);
    out_bytes(&mut env, &out)
}

// ─────────────────────────────────────────────────────────────────────────────
// 5. AES-256-GCM decrypt
// ─────────────────────────────────────────────────────────────────────────────

/// `FialkaNative.decryptAes(iv: ByteArray /*12*/, ct: ByteArray, key: ByteArray): ByteArray /*UTF-8*/`
#[no_mangle]
pub extern "system" fn Java_com_fialkaapp_fialka_crypto_FialkaNative_decryptAes<'l>(
    mut env: JNIEnv<'l>, _this: JObject<'l>,
    iv:  JByteArray<'l>,
    ct:  JByteArray<'l>,
    key: JByteArray<'l>,
) -> JByteArray<'l> {
    let iv_bytes  = ok!(env, get_bytes(&mut env, &iv));
    let ct_bytes  = ok!(env, get_bytes(&mut env, &ct));
    let key_bytes = ok!(env, get_bytes(&mut env, &key));
    let iv12:  [u8; 12] = ok!(env, iv_bytes.as_slice().try_into()
        .map_err(|_| format!("IV must be 12 bytes, got {}", iv_bytes.len())));
    let key32: [u8; 32] = ok!(env, to32(&key_bytes));
    let plaintext = ok!(env, aesgcm::decrypt(&ct_bytes, &iv12, &key32));
    out_bytes(&mut env, plaintext.as_bytes())
}

// ─────────────────────────────────────────────────────────────────────────────
// 6. ChaCha20-Poly1305 encrypt
// ─────────────────────────────────────────────────────────────────────────────

/// `FialkaNative.encryptChaCha(plaintext: ByteArray /*UTF-8*/, key: ByteArray): ByteArray`
/// Returns: nonce(12) || ciphertext
#[no_mangle]
pub extern "system" fn Java_com_fialkaapp_fialka_crypto_FialkaNative_encryptChaCha<'l>(
    mut env: JNIEnv<'l>, _this: JObject<'l>,
    plaintext: JByteArray<'l>,
    key:       JByteArray<'l>,
) -> JByteArray<'l> {
    let pt_bytes  = ok!(env, get_bytes(&mut env, &plaintext));
    let key_bytes = ok!(env, get_bytes(&mut env, &key));
    let key32  = ok!(env, to32(&key_bytes));
    let pt_str = ok!(env, std::str::from_utf8(&pt_bytes).map_err(|e| e.to_string()));
    let enc = ok!(env, chacha::encrypt(pt_str, &key32).map_err(|_| "ChaCha20 encrypt failed".to_string()));
    let mut out = Vec::with_capacity(12 + enc.ciphertext.len());
    out.extend_from_slice(&enc.nonce);
    out.extend_from_slice(&enc.ciphertext);
    out_bytes(&mut env, &out)
}

// ─────────────────────────────────────────────────────────────────────────────
// 7. ChaCha20-Poly1305 decrypt
// ─────────────────────────────────────────────────────────────────────────────

/// `FialkaNative.decryptChaCha(nonce: ByteArray /*12*/, ct: ByteArray, key: ByteArray): ByteArray`
#[no_mangle]
pub extern "system" fn Java_com_fialkaapp_fialka_crypto_FialkaNative_decryptChaCha<'l>(
    mut env: JNIEnv<'l>, _this: JObject<'l>,
    nonce: JByteArray<'l>,
    ct:    JByteArray<'l>,
    key:   JByteArray<'l>,
) -> JByteArray<'l> {
    let nonce_bytes = ok!(env, get_bytes(&mut env, &nonce));
    let ct_bytes    = ok!(env, get_bytes(&mut env, &ct));
    let key_bytes   = ok!(env, get_bytes(&mut env, &key));
    let nonce12: [u8; 12] = ok!(env, nonce_bytes.as_slice().try_into()
        .map_err(|_| format!("Nonce must be 12 bytes, got {}", nonce_bytes.len())));
    let key32 = ok!(env, to32(&key_bytes));
    let plaintext = ok!(env, chacha::decrypt(&ct_bytes, &nonce12, &key32));
    out_bytes(&mut env, plaintext.as_bytes())
}

// ─────────────────────────────────────────────────────────────────────────────
// 8. File encryption
// ─────────────────────────────────────────────────────────────────────────────

/// `FialkaNative.encryptFile(fileBytes: ByteArray): ByteArray`
/// Returns: key(32) || iv(12) || ciphertext
#[no_mangle]
pub extern "system" fn Java_com_fialkaapp_fialka_crypto_FialkaNative_encryptFile<'l>(
    mut env: JNIEnv<'l>, _this: JObject<'l>,
    file_bytes: JByteArray<'l>,
) -> JByteArray<'l> {
    let data = ok!(env, get_bytes(&mut env, &file_bytes));
    let (ct, key, iv) = ok!(env, aesgcm::encrypt_file(&data)
        .map_err(|_| "File encrypt failed".to_string()));
    let mut out = Vec::with_capacity(32 + 12 + ct.len());
    out.extend_from_slice(key.as_ref());
    out.extend_from_slice(&iv);
    out.extend_from_slice(&ct);
    out_bytes(&mut env, &out)
}

// ─────────────────────────────────────────────────────────────────────────────
// 9. File decryption
// ─────────────────────────────────────────────────────────────────────────────

/// `FialkaNative.decryptFile(ct: ByteArray, key: ByteArray /*32*/, iv: ByteArray /*12*/): ByteArray`
#[no_mangle]
pub extern "system" fn Java_com_fialkaapp_fialka_crypto_FialkaNative_decryptFile<'l>(
    mut env: JNIEnv<'l>, _this: JObject<'l>,
    ct:  JByteArray<'l>,
    key: JByteArray<'l>,
    iv:  JByteArray<'l>,
) -> JByteArray<'l> {
    let ct_bytes  = ok!(env, get_bytes(&mut env, &ct));
    let key_bytes = ok!(env, get_bytes(&mut env, &key));
    let iv_bytes  = ok!(env, get_bytes(&mut env, &iv));
    let key32: [u8; 32] = ok!(env, to32(&key_bytes));
    let iv12:  [u8; 12] = ok!(env, iv_bytes.as_slice().try_into()
        .map_err(|_| format!("IV must be 12 bytes, got {}", iv_bytes.len())));
    let plain = ok!(env, aesgcm::decrypt_file(&ct_bytes, &key32, &iv12)
        .map_err(|_| "File decrypt failed".to_string()));
    out_bytes(&mut env, &plain)
}

// ─────────────────────────────────────────────────────────────────────────────
// 10. Ed25519 sign
// ─────────────────────────────────────────────────────────────────────────────

/// `FialkaNative.ed25519Sign(seed: ByteArray /*32*/, data: ByteArray): ByteArray` → sig[64]
#[no_mangle]
pub extern "system" fn Java_com_fialkaapp_fialka_crypto_FialkaNative_ed25519Sign<'l>(
    mut env: JNIEnv<'l>, _this: JObject<'l>,
    seed: JByteArray<'l>,
    data: JByteArray<'l>,
) -> JByteArray<'l> {
    let seed_bytes = ok!(env, get_bytes(&mut env, &seed));
    let data_bytes = ok!(env, get_bytes(&mut env, &data));
    let seed32 = ok!(env, to32(&seed_bytes));
    let sig = Ed25519KeyPair::from_seed(&seed32).sign(&data_bytes);
    out_bytes(&mut env, &sig)
}

// ─────────────────────────────────────────────────────────────────────────────
// 11. Ed25519 verify
// ─────────────────────────────────────────────────────────────────────────────

/// `FialkaNative.ed25519Verify(pub32: ByteArray, data: ByteArray, sig: ByteArray /*64*/): ByteArray`
/// Returns: [1] = valid, [0] = invalid
#[no_mangle]
pub extern "system" fn Java_com_fialkaapp_fialka_crypto_FialkaNative_ed25519Verify<'l>(
    mut env: JNIEnv<'l>, _this: JObject<'l>,
    pub_key:   JByteArray<'l>,
    data:      JByteArray<'l>,
    signature: JByteArray<'l>,
) -> JByteArray<'l> {
    let pub_bytes  = ok!(env, get_bytes(&mut env, &pub_key));
    let data_bytes = ok!(env, get_bytes(&mut env, &data));
    let sig_bytes  = ok!(env, get_bytes(&mut env, &signature));
    let pub32 = ok!(env, to32(&pub_bytes));
    let sig64 = ok!(env, to64(&sig_bytes));
    let valid = ed25519_mod::verify(&pub32, &data_bytes, &sig64);
    out_bytes(&mut env, &[valid as u8])
}

// ─────────────────────────────────────────────────────────────────────────────
// 12. Ed25519 build signed data blob
// ─────────────────────────────────────────────────────────────────────────────

/// `FialkaNative.ed25519BuildSignedData(ctUtf8: ByteArray, convIdUtf8: ByteArray, tsMs: Long): ByteArray`
#[no_mangle]
pub extern "system" fn Java_com_fialkaapp_fialka_crypto_FialkaNative_ed25519BuildSignedData<'l>(
    mut env: JNIEnv<'l>, _this: JObject<'l>,
    ct_utf8:   JByteArray<'l>,
    conv_utf8: JByteArray<'l>,
    ts_ms:     jlong,
) -> JByteArray<'l> {
    let ct_bytes   = ok!(env, get_bytes(&mut env, &ct_utf8));
    let conv_bytes = ok!(env, get_bytes(&mut env, &conv_utf8));
    let ct_str   = ok!(env, std::str::from_utf8(&ct_bytes).map_err(|e| e.to_string()));
    let conv_str = ok!(env, std::str::from_utf8(&conv_bytes).map_err(|e| e.to_string()));
    let blob = ed25519_mod::build_signed_data(ct_str, conv_str, ts_ms as i64);
    out_bytes(&mut env, &blob)
}

// ─────────────────────────────────────────────────────────────────────────────
// 13. X25519 generate ephemeral key pair
// ─────────────────────────────────────────────────────────────────────────────

/// `FialkaNative.x25519GenerateEphemeral(): ByteArray`
/// Returns: priv(32) || pub(32)
#[no_mangle]
pub extern "system" fn Java_com_fialkaapp_fialka_crypto_FialkaNative_x25519GenerateEphemeral<'l>(
    mut env: JNIEnv<'l>, _this: JObject<'l>,
) -> JByteArray<'l> {
    let kp = x25519_mod::X25519KeyPair::random();
    let mut out = [0u8; 64];
    out[..32].copy_from_slice(kp.private_raw.as_ref());
    out[32..].copy_from_slice(&kp.public_raw);
    out_bytes(&mut env, &out)
}

// ─────────────────────────────────────────────────────────────────────────────
// 14. X25519 Diffie-Hellman
// ─────────────────────────────────────────────────────────────────────────────

/// `FialkaNative.x25519Dh(localPriv: ByteArray /*32*/, remotePub: ByteArray /*32*/): ByteArray` → [32]
#[no_mangle]
pub extern "system" fn Java_com_fialkaapp_fialka_crypto_FialkaNative_x25519Dh<'l>(
    mut env: JNIEnv<'l>, _this: JObject<'l>,
    local_priv: JByteArray<'l>,
    remote_pub: JByteArray<'l>,
) -> JByteArray<'l> {
    let priv_bytes = ok!(env, get_bytes(&mut env, &local_priv));
    let pub_bytes  = ok!(env, get_bytes(&mut env, &remote_pub));
    let priv32 = ok!(env, to32(&priv_bytes));
    let pub32  = ok!(env, to32(&pub_bytes));
    let secret = x25519_mod::diffie_hellman(&priv32, &pub32);
    out_bytes(&mut env, secret.as_ref())
}

// ─────────────────────────────────────────────────────────────────────────────
// 15. Ed25519 public key → X25519 raw (birational map)
// ─────────────────────────────────────────────────────────────────────────────

/// `FialkaNative.ed25519ToX25519Raw(edPub: ByteArray /*32*/): ByteArray` → [32]
#[no_mangle]
pub extern "system" fn Java_com_fialkaapp_fialka_crypto_FialkaNative_ed25519ToX25519Raw<'l>(
    mut env: JNIEnv<'l>, _this: JObject<'l>,
    ed_pub: JByteArray<'l>,
) -> JByteArray<'l> {
    let ed_bytes = ok!(env, get_bytes(&mut env, &ed_pub));
    let ed32 = ok!(env, to32(&ed_bytes));
    let x25519_pub = ok!(env, x25519_mod::ed25519_pub_to_x25519(&ed32)
        .ok_or_else(|| "Invalid Ed25519 public key for birational conversion".to_string()));
    out_bytes(&mut env, &x25519_pub)
}

// ─────────────────────────────────────────────────────────────────────────────
// 16. Identity derive (seed → all key pairs as flat bundle)
// ─────────────────────────────────────────────────────────────────────────────

/// `FialkaNative.identityDerive(seed: ByteArray /*32*/): ByteArray`
/// Returns flat bundle (8704 bytes):
///   ed_pub(32) || x25519_pub(32) || x25519_priv(32)
///   || mlkem_ek(1568) || mlkem_dk(3168)
///   || mldsa_vk(1312) || mldsa_sk(2560)
#[no_mangle]
pub extern "system" fn Java_com_fialkaapp_fialka_crypto_FialkaNative_identityDerive<'l>(
    mut env: JNIEnv<'l>, _this: JObject<'l>,
    seed: JByteArray<'l>,
) -> JByteArray<'l> {
    let seed_bytes = ok!(env, get_bytes(&mut env, &seed));
    let seed32 = ok!(env, to32(&seed_bytes));
    let id = FialkaIdentity::derive_from_seed(&seed32);
    // 32+32+32+1568+3168+1312+2560 = 8704 bytes
    let mut out = Vec::with_capacity(8704);
    out.extend_from_slice(&id.ed25519_pub);
    out.extend_from_slice(&id.x25519_pub);
    out.extend_from_slice(id.x25519_priv.as_ref());
    out.extend_from_slice(&id.mlkem_ek);
    out.extend_from_slice(&id.mlkem_dk);
    out.extend_from_slice(&id.mldsa_vk);
    out.extend_from_slice(&id.mldsa_sk);
    out_bytes(&mut env, &out)
}

// ─────────────────────────────────────────────────────────────────────────────
// 17. Compute Tor v3 .onion address
// ─────────────────────────────────────────────────────────────────────────────

/// `FialkaNative.computeOnion(edPub: ByteArray /*32*/): ByteArray` → UTF-8 ".onion" string bytes
#[no_mangle]
pub extern "system" fn Java_com_fialkaapp_fialka_crypto_FialkaNative_computeOnion<'l>(
    mut env: JNIEnv<'l>, _this: JObject<'l>,
    ed_pub: JByteArray<'l>,
) -> JByteArray<'l> {
    let ed_bytes = ok!(env, get_bytes(&mut env, &ed_pub));
    let ed32 = ok!(env, to32(&ed_bytes));
    out_bytes(&mut env, compute_onion_from_ed25519(&ed32).as_bytes())
}

// ─────────────────────────────────────────────────────────────────────────────
// 18. Derive account ID (SHA3-256 → Base58)
// ─────────────────────────────────────────────────────────────────────────────

/// `FialkaNative.deriveAccountId(edPub: ByteArray /*32*/): ByteArray` → UTF-8 Base58 bytes
#[no_mangle]
pub extern "system" fn Java_com_fialkaapp_fialka_crypto_FialkaNative_deriveAccountId<'l>(
    mut env: JNIEnv<'l>, _this: JObject<'l>,
    ed_pub: JByteArray<'l>,
) -> JByteArray<'l> {
    let ed_bytes = ok!(env, get_bytes(&mut env, &ed_pub));
    let ed32 = ok!(env, to32(&ed_bytes));
    out_bytes(&mut env, derive_account_id(&ed32).as_bytes())
}

// ─────────────────────────────────────────────────────────────────────────────
// 19. ML-KEM-1024 key generation from 64-byte seed
// ─────────────────────────────────────────────────────────────────────────────

/// `FialkaNative.mlkemKeygenFromSeed(seed64: ByteArray): ByteArray`
/// Returns: ek(1568) || dk(3168) = 4736 bytes
#[no_mangle]
pub extern "system" fn Java_com_fialkaapp_fialka_crypto_FialkaNative_mlkemKeygenFromSeed<'l>(
    mut env: JNIEnv<'l>, _this: JObject<'l>,
    seed: JByteArray<'l>,
) -> JByteArray<'l> {
    let seed_bytes = ok!(env, get_bytes(&mut env, &seed));
    let (dk, ek) = mlkem::keygen_from_seed(&seed_bytes);
    let mut out = Vec::with_capacity(ek.len() + dk.len());
    out.extend_from_slice(&ek); // public first
    out.extend_from_slice(&dk);
    out_bytes(&mut env, &out)
}

// ─────────────────────────────────────────────────────────────────────────────
// 20. ML-KEM-1024 encapsulate
// ─────────────────────────────────────────────────────────────────────────────

/// `FialkaNative.mlkemEncaps(ek: ByteArray /*1568*/): ByteArray`
/// Returns: ct(1568) || ss(32) = 1600 bytes
#[no_mangle]
pub extern "system" fn Java_com_fialkaapp_fialka_crypto_FialkaNative_mlkemEncaps<'l>(
    mut env: JNIEnv<'l>, _this: JObject<'l>,
    ek: JByteArray<'l>,
) -> JByteArray<'l> {
    let ek_bytes = ok!(env, get_bytes(&mut env, &ek));
    let (ct, ss) = ok!(env, mlkem::encapsulate(&ek_bytes));
    let mut out = Vec::with_capacity(ct.len() + 32);
    out.extend_from_slice(&ct);
    out.extend_from_slice(&ss);
    out_bytes(&mut env, &out)
}

// ─────────────────────────────────────────────────────────────────────────────
// 21. ML-KEM-1024 decapsulate
// ─────────────────────────────────────────────────────────────────────────────

/// `FialkaNative.mlkemDecaps(dk: ByteArray /*3168*/, ct: ByteArray /*1568*/): ByteArray` → ss[32]
#[no_mangle]
pub extern "system" fn Java_com_fialkaapp_fialka_crypto_FialkaNative_mlkemDecaps<'l>(
    mut env: JNIEnv<'l>, _this: JObject<'l>,
    dk: JByteArray<'l>,
    ct: JByteArray<'l>,
) -> JByteArray<'l> {
    let dk_bytes = ok!(env, get_bytes(&mut env, &dk));
    let ct_bytes = ok!(env, get_bytes(&mut env, &ct));
    let ss = ok!(env, mlkem::decapsulate(&dk_bytes, &ct_bytes));
    out_bytes(&mut env, &ss)
}

// ─────────────────────────────────────────────────────────────────────────────
// 22. ML-DSA-44 key generation from 32-byte seed
// ─────────────────────────────────────────────────────────────────────────────

/// `FialkaNative.mldsaKeygenFromSeed(seed32: ByteArray): ByteArray`
/// Returns: vk(1312) || sk(2560) = 3872 bytes
#[no_mangle]
pub extern "system" fn Java_com_fialkaapp_fialka_crypto_FialkaNative_mldsaKeygenFromSeed<'l>(
    mut env: JNIEnv<'l>, _this: JObject<'l>,
    seed: JByteArray<'l>,
) -> JByteArray<'l> {
    let seed_bytes = ok!(env, get_bytes(&mut env, &seed));
    let seed32 = ok!(env, to32(&seed_bytes));
    let (sk, vk) = mldsa::keygen_from_seed(&seed32);
    let mut out = Vec::with_capacity(mldsa::VK_SIZE + mldsa::SK_SIZE);
    out.extend_from_slice(&vk); // public first
    out.extend_from_slice(&sk);
    out_bytes(&mut env, &out)
}

// ─────────────────────────────────────────────────────────────────────────────
// 23. ML-DSA-44 sign
// ─────────────────────────────────────────────────────────────────────────────

/// `FialkaNative.mldsaSign(sk: ByteArray /*2560*/, data: ByteArray): ByteArray` → sig[2420]
#[no_mangle]
pub extern "system" fn Java_com_fialkaapp_fialka_crypto_FialkaNative_mldsaSign<'l>(
    mut env: JNIEnv<'l>, _this: JObject<'l>,
    sk:   JByteArray<'l>,
    data: JByteArray<'l>,
) -> JByteArray<'l> {
    let sk_bytes   = ok!(env, get_bytes(&mut env, &sk));
    let data_bytes = ok!(env, get_bytes(&mut env, &data));
    let sk_arr: [u8; mldsa::SK_SIZE] = ok!(env, sk_bytes.as_slice().try_into()
        .map_err(|_| format!("ML-DSA-44 sk must be {} bytes, got {}", mldsa::SK_SIZE, sk_bytes.len())));
    let sig = ok!(env, mldsa::sign(&sk_arr, &data_bytes));
    out_bytes(&mut env, &sig)
}

// ─────────────────────────────────────────────────────────────────────────────
// 24. ML-DSA-44 verify
// ─────────────────────────────────────────────────────────────────────────────

/// `FialkaNative.mldsaVerify(vk: ByteArray /*1312*/, data: ByteArray, sig: ByteArray /*2420*/): ByteArray`
/// Returns: [1] = valid, [0] = invalid
#[no_mangle]
pub extern "system" fn Java_com_fialkaapp_fialka_crypto_FialkaNative_mldsaVerify<'l>(
    mut env: JNIEnv<'l>, _this: JObject<'l>,
    vk:        JByteArray<'l>,
    data:      JByteArray<'l>,
    signature: JByteArray<'l>,
) -> JByteArray<'l> {
    let vk_bytes   = ok!(env, get_bytes(&mut env, &vk));
    let data_bytes = ok!(env, get_bytes(&mut env, &data));
    let sig_bytes  = ok!(env, get_bytes(&mut env, &signature));
    let vk_arr: [u8; mldsa::VK_SIZE] = ok!(env, vk_bytes.as_slice().try_into()
        .map_err(|_| format!("ML-DSA-44 vk must be {} bytes, got {}", mldsa::VK_SIZE, vk_bytes.len())));
    let sig_arr: [u8; mldsa::SIG_SIZE] = ok!(env, sig_bytes.as_slice().try_into()
        .map_err(|_| format!("ML-DSA-44 sig must be {} bytes, got {}", mldsa::SIG_SIZE, sig_bytes.len())));
    let valid = mldsa::verify(&vk_arr, &data_bytes, &sig_arr);
    out_bytes(&mut env, &[valid as u8])
}

// ─────────────────────────────────────────────────────────────────────────────
// 25. Derive PQXDH root key
// ─────────────────────────────────────────────────────────────────────────────

/// `FialkaNative.deriveRootKeyPqxdh(ssClassic: ByteArray /*32*/, ssPq: ByteArray /*32*/): ByteArray` → [32]
#[no_mangle]
pub extern "system" fn Java_com_fialkaapp_fialka_crypto_FialkaNative_deriveRootKeyPqxdh<'l>(
    mut env: JNIEnv<'l>, _this: JObject<'l>,
    ss_classic: JByteArray<'l>,
    ss_pq:      JByteArray<'l>,
) -> JByteArray<'l> {
    let classic_bytes = ok!(env, get_bytes(&mut env, &ss_classic));
    let pq_bytes      = ok!(env, get_bytes(&mut env, &ss_pq));
    let classic32 = ok!(env, to32(&classic_bytes));
    let pq32      = ok!(env, to32(&pq_bytes));
    let root = ratchet::derive_pqxdh_root_key(&classic32, &pq32);
    out_bytes(&mut env, root.as_ref())
}

// ─────────────────────────────────────────────────────────────────────────────
// 26. Ratchet init — initiator
// ─────────────────────────────────────────────────────────────────────────────

/// `FialkaNative.ratchetInitAsInitiator(identitySecret: ByteArray): ByteArray`
/// Returns: root(32) || send_chain(32) || recv_chain(32) || dh_priv(32) || dh_pub(32) = 160 bytes
#[no_mangle]
pub extern "system" fn Java_com_fialkaapp_fialka_crypto_FialkaNative_ratchetInitAsInitiator<'l>(
    mut env: JNIEnv<'l>, _this: JObject<'l>,
    identity_secret: JByteArray<'l>,
) -> JByteArray<'l> {
    let secret = ok!(env, get_bytes(&mut env, &identity_secret));
    let s = ratchet::init_as_initiator(&secret);
    let mut out = Vec::with_capacity(160);
    out.extend_from_slice(s.root_key.as_ref());
    out.extend_from_slice(s.send_chain_key.as_ref());
    out.extend_from_slice(s.recv_chain_key.as_ref());
    out.extend_from_slice(s.local_dh_private.as_ref());
    out.extend_from_slice(&s.local_dh_public);
    out_bytes(&mut env, &out)
}

// ─────────────────────────────────────────────────────────────────────────────
// 27. Ratchet init — responder
// ─────────────────────────────────────────────────────────────────────────────

/// `FialkaNative.ratchetInitAsResponder(identitySecret: ByteArray): ByteArray`
/// Returns: root(32) || send_chain(32) || recv_chain(32) || dh_priv(32) || dh_pub(32) = 160 bytes
#[no_mangle]
pub extern "system" fn Java_com_fialkaapp_fialka_crypto_FialkaNative_ratchetInitAsResponder<'l>(
    mut env: JNIEnv<'l>, _this: JObject<'l>,
    identity_secret: JByteArray<'l>,
) -> JByteArray<'l> {
    let secret = ok!(env, get_bytes(&mut env, &identity_secret));
    let s = ratchet::init_as_responder(&secret);
    let mut out = Vec::with_capacity(160);
    out.extend_from_slice(s.root_key.as_ref());
    out.extend_from_slice(s.send_chain_key.as_ref());
    out.extend_from_slice(s.recv_chain_key.as_ref());
    out.extend_from_slice(s.local_dh_private.as_ref());
    out.extend_from_slice(&s.local_dh_public);
    out_bytes(&mut env, &out)
}

// ─────────────────────────────────────────────────────────────────────────────
// 28. DH ratchet step
// ─────────────────────────────────────────────────────────────────────────────

/// `FialkaNative.ratchetDhStep(root: ByteArray /*32*/, localPriv: ByteArray /*32*/, remotePub: ByteArray /*32*/): ByteArray`
/// Returns: new_root(32) || new_chain(32) = 64 bytes
#[no_mangle]
pub extern "system" fn Java_com_fialkaapp_fialka_crypto_FialkaNative_ratchetDhStep<'l>(
    mut env: JNIEnv<'l>, _this: JObject<'l>,
    root:       JByteArray<'l>,
    local_priv: JByteArray<'l>,
    remote_pub: JByteArray<'l>,
) -> JByteArray<'l> {
    let root32 = ok!(env, to32(&ok!(env, get_bytes(&mut env, &root))));
    let priv32 = ok!(env, to32(&ok!(env, get_bytes(&mut env, &local_priv))));
    let pub32  = ok!(env, to32(&ok!(env, get_bytes(&mut env, &remote_pub))));
    let r = ratchet::dh_ratchet_step(&root32, &priv32, &pub32);
    let mut out = [0u8; 64];
    out[..32].copy_from_slice(r.new_root_key.as_ref());
    out[32..].copy_from_slice(r.new_chain_key.as_ref());
    out_bytes(&mut env, &out)
}

// ─────────────────────────────────────────────────────────────────────────────
// 29. Symmetric chain advance
// ─────────────────────────────────────────────────────────────────────────────

/// `FialkaNative.ratchetAdvanceChain(chainKey: ByteArray /*32*/): ByteArray`
/// Returns: new_chain(32) || msg_key(32) = 64 bytes
#[no_mangle]
pub extern "system" fn Java_com_fialkaapp_fialka_crypto_FialkaNative_ratchetAdvanceChain<'l>(
    mut env: JNIEnv<'l>, _this: JObject<'l>,
    chain_key: JByteArray<'l>,
) -> JByteArray<'l> {
    let chain32 = ok!(env, to32(&ok!(env, get_bytes(&mut env, &chain_key))));
    let (new_chain, msg_key) = ratchet::advance_chain(&chain32);
    let mut out = [0u8; 64];
    out[..32].copy_from_slice(new_chain.as_ref());
    out[32..].copy_from_slice(msg_key.as_ref());
    out_bytes(&mut env, &out)
}

// ─────────────────────────────────────────────────────────────────────────────
// 30. PQ ratchet step (SPQR)
// ─────────────────────────────────────────────────────────────────────────────

/// `FialkaNative.ratchetPqStep(rootKey: ByteArray /*32*/, pqSs: ByteArray /*32*/): ByteArray` → [32]
#[no_mangle]
pub extern "system" fn Java_com_fialkaapp_fialka_crypto_FialkaNative_ratchetPqStep<'l>(
    mut env: JNIEnv<'l>, _this: JObject<'l>,
    root_key: JByteArray<'l>,
    pq_ss:    JByteArray<'l>,
) -> JByteArray<'l> {
    let root32 = ok!(env, to32(&ok!(env, get_bytes(&mut env, &root_key))));
    let pq32   = ok!(env, to32(&ok!(env, get_bytes(&mut env, &pq_ss))));
    let new_root = ratchet::pq_ratchet_step(&root32, &pq32);
    out_bytes(&mut env, new_root.as_ref())
}

