/*
 * fialka-core — Desktop C-ABI bridge for .NET P/Invoke
 * Copyright (C) 2024-2026 DevBot667 — GPL-3.0
 */

#![cfg(not(target_os = "android"))]

use std::{ptr, slice};

use crate::crypto::{aesgcm, chacha, ed25519, kdf, mldsa, mlkem, x25519};
use crate::crypto::ed25519::Ed25519KeyPair;
use crate::identity::{compute_onion_from_ed25519, derive_account_id, FialkaIdentity};
use crate::ratchet;

#[inline]
fn to32(v: &[u8]) -> Result<[u8; 32], String> {
    v.try_into().map_err(|_| format!("Expected 32 bytes, got {}", v.len()))
}

#[inline]
fn to64(v: &[u8]) -> Result<[u8; 64], String> {
    v.try_into().map_err(|_| format!("Expected 64 bytes, got {}", v.len()))
}

#[inline]
unsafe fn read_slice<'a>(ptr_in: *const u8, len: usize, label: &str) -> Result<&'a [u8], String> {
    if ptr_in.is_null() {
        return Err(format!("{label} pointer is null"));
    }
    Ok(slice::from_raw_parts(ptr_in, len))
}

#[inline]
unsafe fn write_fixed(out_ptr: *mut u8, out_len: usize, data: &[u8], label: &str) -> Result<(), String> {
    if out_ptr.is_null() {
        return Err(format!("{label} output pointer is null"));
    }
    if out_len < data.len() {
        return Err(format!("{label} output buffer too small: need {}, got {}", data.len(), out_len));
    }
    ptr::copy_nonoverlapping(data.as_ptr(), out_ptr, data.len());
    Ok(())
}

#[inline]
unsafe fn write_var(
    out_ptr: *mut u8,
    out_capacity: usize,
    out_len_ptr: *mut usize,
    data: &[u8],
    label: &str,
) -> Result<(), String> {
    if out_len_ptr.is_null() {
        return Err(format!("{label} out_len pointer is null"));
    }
    if out_ptr.is_null() {
        return Err(format!("{label} output pointer is null"));
    }
    if out_capacity < data.len() {
        return Err(format!("{label} output buffer too small: need {}, got {}", data.len(), out_capacity));
    }
    ptr::copy_nonoverlapping(data.as_ptr(), out_ptr, data.len());
    *out_len_ptr = data.len();
    Ok(())
}

// 1) HMAC-SHA256
#[no_mangle]
pub unsafe extern "C" fn fialka_hmac_sha256(
    key_ptr: *const u8,
    key_len: usize,
    data_ptr: *const u8,
    data_len: usize,
    out_ptr: *mut u8,
    out_len: usize,
) -> i32 {
    let key = match read_slice(key_ptr, key_len, "key") { Ok(v) => v, Err(_) => return -1 };
    let data = match read_slice(data_ptr, data_len, "data") { Ok(v) => v, Err(_) => return -1 };
    let mac = kdf::hmac_sha256(key, data);
    if write_fixed(out_ptr, out_len, &mac, "hmac_sha256").is_err() { return -1; }
    0
}

// 2) HKDF-SHA256
#[no_mangle]
pub unsafe extern "C" fn fialka_hkdf_sha256(
    ikm_ptr: *const u8,
    ikm_len: usize,
    salt_ptr: *const u8,
    salt_len: usize,
    info_ptr: *const u8,
    info_len: usize,
    wanted_len: usize,
    out_ptr: *mut u8,
    out_capacity: usize,
) -> i32 {
    let ikm = match read_slice(ikm_ptr, ikm_len, "ikm") { Ok(v) => v, Err(_) => return -1 };
    let salt = match read_slice(salt_ptr, salt_len, "salt") { Ok(v) => v, Err(_) => return -1 };
    let info = match read_slice(info_ptr, info_len, "info") { Ok(v) => v, Err(_) => return -1 };
    if wanted_len == 0 { return -1; }
    let okm = kdf::hkdf_sha256(ikm, salt, info, wanted_len);
    if write_fixed(out_ptr, out_capacity, &okm, "hkdf_sha256").is_err() { return -1; }
    0
}

// 3) HKDF zero salt
#[no_mangle]
pub unsafe extern "C" fn fialka_hkdf_zero_salt(
    ikm_ptr: *const u8,
    ikm_len: usize,
    info_ptr: *const u8,
    info_len: usize,
    out_ptr: *mut u8,
    out_len: usize,
) -> i32 {
    let ikm = match read_slice(ikm_ptr, ikm_len, "ikm") { Ok(v) => v, Err(_) => return -1 };
    let info = match read_slice(info_ptr, info_len, "info") { Ok(v) => v, Err(_) => return -1 };
    let out = kdf::hkdf_zero_salt(ikm, info);
    if write_fixed(out_ptr, out_len, out.as_ref(), "hkdf_zero_salt").is_err() { return -1; }
    0
}

// 4) AES encrypt => iv||ct
#[no_mangle]
pub unsafe extern "C" fn fialka_encrypt_aes(
    plaintext_ptr: *const u8,
    plaintext_len: usize,
    key_ptr: *const u8,
    key_len: usize,
    out_ptr: *mut u8,
    out_capacity: usize,
    out_len_ptr: *mut usize,
) -> i32 {
    let plaintext = match read_slice(plaintext_ptr, plaintext_len, "plaintext") { Ok(v) => v, Err(_) => return -1 };
    let key = match read_slice(key_ptr, key_len, "key") { Ok(v) => v, Err(_) => return -1 };
    let key32 = match to32(key) { Ok(v) => v, Err(_) => return -1 };
    let pt = match std::str::from_utf8(plaintext) { Ok(v) => v, Err(_) => return -1 };
    let enc = match aesgcm::encrypt(pt, &key32) { Ok(v) => v, Err(_) => return -1 };
    let mut out = Vec::with_capacity(12 + enc.ciphertext.len());
    out.extend_from_slice(&enc.iv);
    out.extend_from_slice(&enc.ciphertext);
    if write_var(out_ptr, out_capacity, out_len_ptr, &out, "encrypt_aes").is_err() { return -1; }
    0
}

// 5) AES decrypt <= iv||ct
#[no_mangle]
pub unsafe extern "C" fn fialka_decrypt_aes(
    data_ptr: *const u8,
    data_len: usize,
    key_ptr: *const u8,
    key_len: usize,
    out_ptr: *mut u8,
    out_capacity: usize,
    out_len_ptr: *mut usize,
) -> i32 {
    let data = match read_slice(data_ptr, data_len, "data") { Ok(v) => v, Err(_) => return -1 };
    let key = match read_slice(key_ptr, key_len, "key") { Ok(v) => v, Err(_) => return -1 };
    if data.len() < 12 { return -1; }
    let key32 = match to32(key) { Ok(v) => v, Err(_) => return -1 };
    let iv: [u8; 12] = match data[..12].try_into() { Ok(v) => v, Err(_) => return -1 };
    let ct = &data[12..];
    let pt = match aesgcm::decrypt(ct, &iv, &key32) { Ok(v) => v, Err(_) => return -1 };
    if write_var(out_ptr, out_capacity, out_len_ptr, pt.as_bytes(), "decrypt_aes").is_err() { return -1; }
    0
}

// 6) ChaCha encrypt => nonce||ct
#[no_mangle]
pub unsafe extern "C" fn fialka_encrypt_chacha(
    plaintext_ptr: *const u8,
    plaintext_len: usize,
    key_ptr: *const u8,
    key_len: usize,
    out_ptr: *mut u8,
    out_capacity: usize,
    out_len_ptr: *mut usize,
) -> i32 {
    let plaintext = match read_slice(plaintext_ptr, plaintext_len, "plaintext") { Ok(v) => v, Err(_) => return -1 };
    let key = match read_slice(key_ptr, key_len, "key") { Ok(v) => v, Err(_) => return -1 };
    let key32 = match to32(key) { Ok(v) => v, Err(_) => return -1 };
    let pt = match std::str::from_utf8(plaintext) { Ok(v) => v, Err(_) => return -1 };
    let enc = match chacha::encrypt(pt, &key32) { Ok(v) => v, Err(_) => return -1 };
    let mut out = Vec::with_capacity(12 + enc.ciphertext.len());
    out.extend_from_slice(&enc.nonce);
    out.extend_from_slice(&enc.ciphertext);
    if write_var(out_ptr, out_capacity, out_len_ptr, &out, "encrypt_chacha").is_err() { return -1; }
    0
}

// 7) ChaCha decrypt <= nonce||ct
#[no_mangle]
pub unsafe extern "C" fn fialka_decrypt_chacha(
    data_ptr: *const u8,
    data_len: usize,
    key_ptr: *const u8,
    key_len: usize,
    out_ptr: *mut u8,
    out_capacity: usize,
    out_len_ptr: *mut usize,
) -> i32 {
    let data = match read_slice(data_ptr, data_len, "data") { Ok(v) => v, Err(_) => return -1 };
    let key = match read_slice(key_ptr, key_len, "key") { Ok(v) => v, Err(_) => return -1 };
    if data.len() < 12 { return -1; }
    let key32 = match to32(key) { Ok(v) => v, Err(_) => return -1 };
    let nonce: [u8; 12] = match data[..12].try_into() { Ok(v) => v, Err(_) => return -1 };
    let ct = &data[12..];
    let pt = match chacha::decrypt(ct, &nonce, &key32) { Ok(v) => v, Err(_) => return -1 };
    if write_var(out_ptr, out_capacity, out_len_ptr, pt.as_bytes(), "decrypt_chacha").is_err() { return -1; }
    0
}

// 8) file encrypt => key||iv||ct
#[no_mangle]
pub unsafe extern "C" fn fialka_encrypt_file(
    data_ptr: *const u8,
    data_len: usize,
    out_ptr: *mut u8,
    out_capacity: usize,
    out_len_ptr: *mut usize,
) -> i32 {
    let data = match read_slice(data_ptr, data_len, "file") { Ok(v) => v, Err(_) => return -1 };
    let (ct, key, iv) = match aesgcm::encrypt_file(data) { Ok(v) => v, Err(_) => return -1 };
    let mut out = Vec::with_capacity(32 + 12 + ct.len());
    out.extend_from_slice(key.as_ref());
    out.extend_from_slice(&iv);
    out.extend_from_slice(&ct);
    if write_var(out_ptr, out_capacity, out_len_ptr, &out, "encrypt_file").is_err() { return -1; }
    0
}

// 9) file decrypt
#[no_mangle]
pub unsafe extern "C" fn fialka_decrypt_file(
    ct_ptr: *const u8,
    ct_len: usize,
    key_ptr: *const u8,
    key_len: usize,
    iv_ptr: *const u8,
    iv_len: usize,
    out_ptr: *mut u8,
    out_capacity: usize,
    out_len_ptr: *mut usize,
) -> i32 {
    let ct = match read_slice(ct_ptr, ct_len, "ct") { Ok(v) => v, Err(_) => return -1 };
    let key = match read_slice(key_ptr, key_len, "key") { Ok(v) => v, Err(_) => return -1 };
    let iv = match read_slice(iv_ptr, iv_len, "iv") { Ok(v) => v, Err(_) => return -1 };
    let key32 = match to32(key) { Ok(v) => v, Err(_) => return -1 };
    let iv12: [u8; 12] = match iv.try_into() { Ok(v) => v, Err(_) => return -1 };
    let pt = match aesgcm::decrypt_file(ct, &key32, &iv12) { Ok(v) => v, Err(_) => return -1 };
    if write_var(out_ptr, out_capacity, out_len_ptr, &pt, "decrypt_file").is_err() { return -1; }
    0
}

// 10) Ed25519 sign
#[no_mangle]
pub unsafe extern "C" fn fialka_ed25519_sign(
    seed_ptr: *const u8,
    seed_len: usize,
    data_ptr: *const u8,
    data_len: usize,
    out_ptr: *mut u8,
    out_len: usize,
) -> i32 {
    let seed = match read_slice(seed_ptr, seed_len, "seed") { Ok(v) => v, Err(_) => return -1 };
    let data = match read_slice(data_ptr, data_len, "data") { Ok(v) => v, Err(_) => return -1 };
    let seed32 = match to32(seed) { Ok(v) => v, Err(_) => return -1 };
    let sig = Ed25519KeyPair::from_seed(&seed32).sign(data);
    if write_fixed(out_ptr, out_len, &sig, "ed25519_sign").is_err() { return -1; }
    0
}

// 11) Ed25519 verify (1 valid, 0 invalid, -1 error)
#[no_mangle]
pub unsafe extern "C" fn fialka_ed25519_verify(
    pub_ptr: *const u8,
    pub_len: usize,
    data_ptr: *const u8,
    data_len: usize,
    sig_ptr: *const u8,
    sig_len: usize,
) -> i32 {
    let pub_bytes = match read_slice(pub_ptr, pub_len, "pub") { Ok(v) => v, Err(_) => return -1 };
    let data = match read_slice(data_ptr, data_len, "data") { Ok(v) => v, Err(_) => return -1 };
    let sig = match read_slice(sig_ptr, sig_len, "sig") { Ok(v) => v, Err(_) => return -1 };
    let pub32 = match to32(pub_bytes) { Ok(v) => v, Err(_) => return -1 };
    let sig64 = match to64(sig) { Ok(v) => v, Err(_) => return -1 };
    if ed25519::verify(&pub32, data, &sig64) { 1 } else { 0 }
}

// 12) Build signed data
#[no_mangle]
pub unsafe extern "C" fn fialka_ed25519_build_signed_data(
    ct_ptr: *const u8,
    ct_len: usize,
    conv_ptr: *const u8,
    conv_len: usize,
    ts_ms: i64,
    out_ptr: *mut u8,
    out_capacity: usize,
    out_len_ptr: *mut usize,
) -> i32 {
    let ct = match read_slice(ct_ptr, ct_len, "ct") { Ok(v) => v, Err(_) => return -1 };
    let conv = match read_slice(conv_ptr, conv_len, "conv") { Ok(v) => v, Err(_) => return -1 };
    let ct_s = match std::str::from_utf8(ct) { Ok(v) => v, Err(_) => return -1 };
    let conv_s = match std::str::from_utf8(conv) { Ok(v) => v, Err(_) => return -1 };
    let data = ed25519::build_signed_data(ct_s, conv_s, ts_ms);
    if write_var(out_ptr, out_capacity, out_len_ptr, &data, "ed25519_build_signed_data").is_err() { return -1; }
    0
}

// 13) X25519 generate ephemeral => priv||pub
#[no_mangle]
pub unsafe extern "C" fn fialka_x25519_generate_ephemeral(
    out_ptr: *mut u8,
    out_len: usize,
) -> i32 {
    let kp = x25519::X25519KeyPair::random();
    let mut out = [0u8; 64];
    out[..32].copy_from_slice(kp.private_raw.as_ref());
    out[32..].copy_from_slice(&kp.public_raw);
    if write_fixed(out_ptr, out_len, &out, "x25519_generate_ephemeral").is_err() { return -1; }
    0
}

// 14) X25519 DH
#[no_mangle]
pub unsafe extern "C" fn fialka_x25519_dh(
    priv_ptr: *const u8,
    priv_len: usize,
    pub_ptr: *const u8,
    pub_len: usize,
    out_ptr: *mut u8,
    out_len: usize,
) -> i32 {
    let priv_bytes = match read_slice(priv_ptr, priv_len, "priv") { Ok(v) => v, Err(_) => return -1 };
    let pub_bytes = match read_slice(pub_ptr, pub_len, "pub") { Ok(v) => v, Err(_) => return -1 };
    let priv32 = match to32(priv_bytes) { Ok(v) => v, Err(_) => return -1 };
    let pub32 = match to32(pub_bytes) { Ok(v) => v, Err(_) => return -1 };
    let ss = x25519::diffie_hellman(&priv32, &pub32);
    if write_fixed(out_ptr, out_len, ss.as_ref(), "x25519_dh").is_err() { return -1; }
    0
}

// 15) Ed25519 pub -> X25519 raw
#[no_mangle]
pub unsafe extern "C" fn fialka_ed25519_to_x25519_raw(
    ed_ptr: *const u8,
    ed_len: usize,
    out_ptr: *mut u8,
    out_len: usize,
) -> i32 {
    let ed = match read_slice(ed_ptr, ed_len, "ed_pub") { Ok(v) => v, Err(_) => return -1 };
    let ed32 = match to32(ed) { Ok(v) => v, Err(_) => return -1 };
    let x = match x25519::ed25519_pub_to_x25519(&ed32) { Some(v) => v, None => return -1 };
    if write_fixed(out_ptr, out_len, &x, "ed25519_to_x25519_raw").is_err() { return -1; }
    0
}

// 16) identity derive => 8704 bytes
#[no_mangle]
pub unsafe extern "C" fn fialka_identity_derive(
    seed_ptr: *const u8,
    seed_len: usize,
    out_ptr: *mut u8,
    out_len: usize,
) -> i32 {
    let seed = match read_slice(seed_ptr, seed_len, "seed") { Ok(v) => v, Err(_) => return -1 };
    let seed32 = match to32(seed) { Ok(v) => v, Err(_) => return -1 };
    let id = FialkaIdentity::derive_from_seed(&seed32);
    let mut out = Vec::with_capacity(8704);
    out.extend_from_slice(&id.ed25519_pub);
    out.extend_from_slice(&id.x25519_pub);
    out.extend_from_slice(id.x25519_priv.as_ref());
    out.extend_from_slice(&id.mlkem_ek);
    out.extend_from_slice(&id.mlkem_dk);
    out.extend_from_slice(&id.mldsa_vk);
    out.extend_from_slice(&id.mldsa_sk);
    if write_fixed(out_ptr, out_len, &out, "identity_derive").is_err() { return -1; }
    0
}

// 17) compute onion
#[no_mangle]
pub unsafe extern "C" fn fialka_compute_onion(
    ed_ptr: *const u8,
    ed_len: usize,
    out_ptr: *mut u8,
    out_capacity: usize,
    out_len_ptr: *mut usize,
) -> i32 {
    let ed = match read_slice(ed_ptr, ed_len, "ed_pub") { Ok(v) => v, Err(_) => return -1 };
    let ed32 = match to32(ed) { Ok(v) => v, Err(_) => return -1 };
    let onion = compute_onion_from_ed25519(&ed32);
    if write_var(out_ptr, out_capacity, out_len_ptr, onion.as_bytes(), "compute_onion").is_err() { return -1; }
    0
}

// 18) derive account id
#[no_mangle]
pub unsafe extern "C" fn fialka_derive_account_id(
    ed_ptr: *const u8,
    ed_len: usize,
    out_ptr: *mut u8,
    out_capacity: usize,
    out_len_ptr: *mut usize,
) -> i32 {
    let ed = match read_slice(ed_ptr, ed_len, "ed_pub") { Ok(v) => v, Err(_) => return -1 };
    let ed32 = match to32(ed) { Ok(v) => v, Err(_) => return -1 };
    let account_id = derive_account_id(&ed32);
    if write_var(out_ptr, out_capacity, out_len_ptr, account_id.as_bytes(), "derive_account_id").is_err() { return -1; }
    0
}

// 19) ML-KEM keygen from seed
#[no_mangle]
pub unsafe extern "C" fn fialka_mlkem_keygen_from_seed(
    seed_ptr: *const u8,
    seed_len: usize,
    out_ptr: *mut u8,
    out_len: usize,
) -> i32 {
    let seed = match read_slice(seed_ptr, seed_len, "seed64") { Ok(v) => v, Err(_) => return -1 };
    if seed.len() != 64 { return -1; }
    let (dk, ek) = mlkem::keygen_from_seed(seed);
    let mut out = Vec::with_capacity(ek.len() + dk.len());
    out.extend_from_slice(&ek);
    out.extend_from_slice(&dk);
    if write_fixed(out_ptr, out_len, &out, "mlkem_keygen_from_seed").is_err() { return -1; }
    0
}

// 20) ML-KEM encaps => ct||ss
#[no_mangle]
pub unsafe extern "C" fn fialka_mlkem_encaps(
    ek_ptr: *const u8,
    ek_len: usize,
    out_ptr: *mut u8,
    out_len: usize,
) -> i32 {
    let ek = match read_slice(ek_ptr, ek_len, "ek") { Ok(v) => v, Err(_) => return -1 };
    let (ct, ss) = match mlkem::encapsulate(ek) { Ok(v) => v, Err(_) => return -1 };
    let mut out = Vec::with_capacity(ct.len() + ss.len());
    out.extend_from_slice(&ct);
    out.extend_from_slice(&ss);
    if write_fixed(out_ptr, out_len, &out, "mlkem_encaps").is_err() { return -1; }
    0
}

// 21) ML-KEM decaps => ss
#[no_mangle]
pub unsafe extern "C" fn fialka_mlkem_decaps(
    dk_ptr: *const u8,
    dk_len: usize,
    ct_ptr: *const u8,
    ct_len: usize,
    out_ptr: *mut u8,
    out_len: usize,
) -> i32 {
    let dk = match read_slice(dk_ptr, dk_len, "dk") { Ok(v) => v, Err(_) => return -1 };
    let ct = match read_slice(ct_ptr, ct_len, "ct") { Ok(v) => v, Err(_) => return -1 };
    let ss = match mlkem::decapsulate(dk, ct) { Ok(v) => v, Err(_) => return -1 };
    if write_fixed(out_ptr, out_len, &ss, "mlkem_decaps").is_err() { return -1; }
    0
}

// 22) ML-DSA keygen from seed
#[no_mangle]
pub unsafe extern "C" fn fialka_mldsa_keygen_from_seed(
    seed_ptr: *const u8,
    seed_len: usize,
    out_ptr: *mut u8,
    out_len: usize,
) -> i32 {
    let seed = match read_slice(seed_ptr, seed_len, "seed32") { Ok(v) => v, Err(_) => return -1 };
    let seed32 = match to32(seed) { Ok(v) => v, Err(_) => return -1 };
    let (sk, vk) = mldsa::keygen_from_seed(&seed32);
    let mut out = Vec::with_capacity(mldsa::VK_SIZE + mldsa::SK_SIZE);
    out.extend_from_slice(&vk);
    out.extend_from_slice(&sk);
    if write_fixed(out_ptr, out_len, &out, "mldsa_keygen_from_seed").is_err() { return -1; }
    0
}

// 23) ML-DSA sign
#[no_mangle]
pub unsafe extern "C" fn fialka_mldsa_sign(
    sk_ptr: *const u8,
    sk_len: usize,
    data_ptr: *const u8,
    data_len: usize,
    out_ptr: *mut u8,
    out_len: usize,
) -> i32 {
    let sk = match read_slice(sk_ptr, sk_len, "sk") { Ok(v) => v, Err(_) => return -1 };
    let data = match read_slice(data_ptr, data_len, "data") { Ok(v) => v, Err(_) => return -1 };
    let sk_arr: [u8; mldsa::SK_SIZE] = match sk.try_into() { Ok(v) => v, Err(_) => return -1 };
    let sig = match mldsa::sign(&sk_arr, data) { Ok(v) => v, Err(_) => return -1 };
    if write_fixed(out_ptr, out_len, &sig, "mldsa_sign").is_err() { return -1; }
    0
}

// 24) ML-DSA verify (1/0/-1)
#[no_mangle]
pub unsafe extern "C" fn fialka_mldsa_verify(
    vk_ptr: *const u8,
    vk_len: usize,
    data_ptr: *const u8,
    data_len: usize,
    sig_ptr: *const u8,
    sig_len: usize,
) -> i32 {
    let vk = match read_slice(vk_ptr, vk_len, "vk") { Ok(v) => v, Err(_) => return -1 };
    let data = match read_slice(data_ptr, data_len, "data") { Ok(v) => v, Err(_) => return -1 };
    let sig = match read_slice(sig_ptr, sig_len, "sig") { Ok(v) => v, Err(_) => return -1 };
    let vk_arr: [u8; mldsa::VK_SIZE] = match vk.try_into() { Ok(v) => v, Err(_) => return -1 };
    let sig_arr: [u8; mldsa::SIG_SIZE] = match sig.try_into() { Ok(v) => v, Err(_) => return -1 };
    if mldsa::verify(&vk_arr, data, &sig_arr) { 1 } else { 0 }
}

// 25) derive root key pqxdh
#[no_mangle]
pub unsafe extern "C" fn fialka_derive_root_key_pqxdh(
    ss_classic_ptr: *const u8,
    ss_classic_len: usize,
    ss_pq_ptr: *const u8,
    ss_pq_len: usize,
    out_ptr: *mut u8,
    out_len: usize,
) -> i32 {
    let ss_classic = match read_slice(ss_classic_ptr, ss_classic_len, "ss_classic") { Ok(v) => v, Err(_) => return -1 };
    let ss_pq = match read_slice(ss_pq_ptr, ss_pq_len, "ss_pq") { Ok(v) => v, Err(_) => return -1 };
    let classic32 = match to32(ss_classic) { Ok(v) => v, Err(_) => return -1 };
    let pq32 = match to32(ss_pq) { Ok(v) => v, Err(_) => return -1 };
    let root = ratchet::derive_pqxdh_root_key(&classic32, &pq32);
    if write_fixed(out_ptr, out_len, root.as_ref(), "derive_root_key_pqxdh").is_err() { return -1; }
    0
}

// 26) ratchet init initiator
#[no_mangle]
pub unsafe extern "C" fn fialka_ratchet_init_as_initiator(
    secret_ptr: *const u8,
    secret_len: usize,
    out_ptr: *mut u8,
    out_len: usize,
) -> i32 {
    let secret = match read_slice(secret_ptr, secret_len, "secret") { Ok(v) => v, Err(_) => return -1 };
    let s = ratchet::init_as_initiator(secret);
    let mut out = [0u8; 160];
    out[..32].copy_from_slice(s.root_key.as_ref());
    out[32..64].copy_from_slice(s.send_chain_key.as_ref());
    out[64..96].copy_from_slice(s.recv_chain_key.as_ref());
    out[96..128].copy_from_slice(s.local_dh_private.as_ref());
    out[128..160].copy_from_slice(&s.local_dh_public);
    if write_fixed(out_ptr, out_len, &out, "ratchet_init_as_initiator").is_err() { return -1; }
    0
}

// 27) ratchet init responder
#[no_mangle]
pub unsafe extern "C" fn fialka_ratchet_init_as_responder(
    secret_ptr: *const u8,
    secret_len: usize,
    out_ptr: *mut u8,
    out_len: usize,
) -> i32 {
    let secret = match read_slice(secret_ptr, secret_len, "secret") { Ok(v) => v, Err(_) => return -1 };
    let s = ratchet::init_as_responder(secret);
    let mut out = [0u8; 160];
    out[..32].copy_from_slice(s.root_key.as_ref());
    out[32..64].copy_from_slice(s.send_chain_key.as_ref());
    out[64..96].copy_from_slice(s.recv_chain_key.as_ref());
    out[96..128].copy_from_slice(s.local_dh_private.as_ref());
    out[128..160].copy_from_slice(&s.local_dh_public);
    if write_fixed(out_ptr, out_len, &out, "ratchet_init_as_responder").is_err() { return -1; }
    0
}

// 28) ratchet dh step
#[no_mangle]
pub unsafe extern "C" fn fialka_ratchet_dh_step(
    root_ptr: *const u8,
    root_len: usize,
    local_priv_ptr: *const u8,
    local_priv_len: usize,
    remote_pub_ptr: *const u8,
    remote_pub_len: usize,
    out_ptr: *mut u8,
    out_len: usize,
) -> i32 {
    let root = match read_slice(root_ptr, root_len, "root") { Ok(v) => v, Err(_) => return -1 };
    let local_priv = match read_slice(local_priv_ptr, local_priv_len, "local_priv") { Ok(v) => v, Err(_) => return -1 };
    let remote_pub = match read_slice(remote_pub_ptr, remote_pub_len, "remote_pub") { Ok(v) => v, Err(_) => return -1 };
    let root32 = match to32(root) { Ok(v) => v, Err(_) => return -1 };
    let local32 = match to32(local_priv) { Ok(v) => v, Err(_) => return -1 };
    let remote32 = match to32(remote_pub) { Ok(v) => v, Err(_) => return -1 };
    let r = ratchet::dh_ratchet_step(&root32, &local32, &remote32);
    let mut out = [0u8; 64];
    out[..32].copy_from_slice(r.new_root_key.as_ref());
    out[32..64].copy_from_slice(r.new_chain_key.as_ref());
    if write_fixed(out_ptr, out_len, &out, "ratchet_dh_step").is_err() { return -1; }
    0
}

// 29) ratchet advance chain
#[no_mangle]
pub unsafe extern "C" fn fialka_ratchet_advance_chain(
    chain_ptr: *const u8,
    chain_len: usize,
    out_ptr: *mut u8,
    out_len: usize,
) -> i32 {
    let chain = match read_slice(chain_ptr, chain_len, "chain") { Ok(v) => v, Err(_) => return -1 };
    let chain32 = match to32(chain) { Ok(v) => v, Err(_) => return -1 };
    let (new_chain, msg_key) = ratchet::advance_chain(&chain32);
    let mut out = [0u8; 64];
    out[..32].copy_from_slice(new_chain.as_ref());
    out[32..64].copy_from_slice(msg_key.as_ref());
    if write_fixed(out_ptr, out_len, &out, "ratchet_advance_chain").is_err() { return -1; }
    0
}

// 30) ratchet pq step
#[no_mangle]
pub unsafe extern "C" fn fialka_ratchet_pq_step(
    root_ptr: *const u8,
    root_len: usize,
    pq_ptr: *const u8,
    pq_len: usize,
    out_ptr: *mut u8,
    out_len: usize,
) -> i32 {
    let root = match read_slice(root_ptr, root_len, "root") { Ok(v) => v, Err(_) => return -1 };
    let pq = match read_slice(pq_ptr, pq_len, "pq_ss") { Ok(v) => v, Err(_) => return -1 };
    let root32 = match to32(root) { Ok(v) => v, Err(_) => return -1 };
    let pq32 = match to32(pq) { Ok(v) => v, Err(_) => return -1 };
    let next = ratchet::pq_ratchet_step(&root32, &pq32);
    if write_fixed(out_ptr, out_len, next.as_ref(), "ratchet_pq_step").is_err() { return -1; }
    0
}
