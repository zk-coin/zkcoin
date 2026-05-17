// Copyright (c) 2026 The zkCoin developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

use core::slice;
use sha2::{Digest, Sha256};

const HASH_SIZE: usize = 32;
const PROOF_ENVELOPE_PREIMAGE_PREFIX: &[u8] = b"zkc-proof-envelope-v1";
const PROOF_ENVELOPE_PREIMAGE_PREFIX_V2: &[u8] = b"zkc-proof-envelope-v2";
const PROOF_PUBLIC_INPUT_PREIMAGE_PREFIX: &[u8] = b"zkc-public-input-v1";
const PROOF_ENVELOPE_PREIMAGE_PREFIX_V3: &[u8] = b"zkc-proof-envelope-v3";
const PROOF_BUNDLE_PREFIX_V4: &[u8] = b"zkc-p4";
const PROOF_BUNDLE_PREIMAGE_PREFIX_V4: &[u8] = b"zkc-proof-bundle-v4";
const ORCHARD_PROOF_PAYLOAD_PREFIX_V1: &[u8] = b"zkc-orchard-proof-v1";
const ORCHARD_PROOF_BODY_PREFIX_V1: &[u8] = b"zkc-orchard-body-v1";
const ORCHARD_REAL_PROOF_PREFIX_V1: &[u8] = b"zkc-orchard-real-v1";
const ORCHARD_REAL_VERIFIER_KEY_HASH_PREIMAGE_PREFIX_V1: &[u8] = b"zkc-orchard-real-vk-v1";
const PROOF_BUNDLE_VERSION_V4: u8 = 1;
const PROOF_SYSTEM_ORCHARD: u8 = 1;
const PROOF_BUNDLE_FLAGS_NONE: u8 = 0;
const ORCHARD_PROOF_BODY_MODE_SCAFFOLD: u8 = 0;
const ORCHARD_PROOF_BODY_MODE_REAL: u8 = 1;
pub const ORCHARD_REAL_PROOF_STATUS_MALFORMED: i32 = 0;
pub const ORCHARD_REAL_PROOF_STATUS_VALID: i32 = 1;
pub const ORCHARD_REAL_PROOF_STATUS_INVALID: i32 = -1;
pub const ORCHARD_REAL_PROOF_STATUS_UNSUPPORTED: i32 = -2;
const PROOF_BUNDLE_HEADER_LEN_V4: usize =
    6 + 1 + 1 + 1 + 1 + HASH_SIZE + core::mem::size_of::<u32>();
const ORCHARD_PROOF_PAYLOAD_HEADER_LEN_V1: usize =
    ORCHARD_PROOF_PAYLOAD_PREFIX_V1.len() + 1 + HASH_SIZE + core::mem::size_of::<u32>();
const ORCHARD_PROOF_BODY_HEADER_LEN_V1: usize =
    ORCHARD_PROOF_BODY_PREFIX_V1.len() + 1 + core::mem::size_of::<u32>();
const ORCHARD_REAL_PROOF_HEADER_LEN_V1: usize = ORCHARD_REAL_PROOF_PREFIX_V1.len()
    + 1
    + 1
    + HASH_SIZE
    + HASH_SIZE
    + core::mem::size_of::<u32>();

fn hash256(data: &[u8]) -> [u8; HASH_SIZE] {
    let first = Sha256::digest(data);
    let second = Sha256::digest(first);
    second.into()
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum OrchardRealProofStatus {
    Valid,
    Malformed,
    Invalid,
    Unsupported,
}

impl OrchardRealProofStatus {
    pub fn as_ffi_code(self) -> i32 {
        match self {
            OrchardRealProofStatus::Valid => ORCHARD_REAL_PROOF_STATUS_VALID,
            OrchardRealProofStatus::Malformed => ORCHARD_REAL_PROOF_STATUS_MALFORMED,
            OrchardRealProofStatus::Invalid => ORCHARD_REAL_PROOF_STATUS_INVALID,
            OrchardRealProofStatus::Unsupported => ORCHARD_REAL_PROOF_STATUS_UNSUPPORTED,
        }
    }
}

pub fn expected_proof_payload_v1(
    field_hash: &[u8; HASH_SIZE],
    tx_binding_hash: &[u8; HASH_SIZE],
) -> [u8; HASH_SIZE] {
    let mut preimage =
        Vec::with_capacity(PROOF_ENVELOPE_PREIMAGE_PREFIX.len() + HASH_SIZE + HASH_SIZE);
    preimage.extend_from_slice(PROOF_ENVELOPE_PREIMAGE_PREFIX);
    preimage.extend_from_slice(field_hash);
    preimage.extend_from_slice(tx_binding_hash);
    hash256(&preimage)
}

pub fn expected_proof_payload_v2(
    proof_kind: u8,
    field_hash: &[u8; HASH_SIZE],
    tx_binding_hash: &[u8; HASH_SIZE],
) -> [u8; HASH_SIZE] {
    let mut preimage =
        Vec::with_capacity(PROOF_ENVELOPE_PREIMAGE_PREFIX_V2.len() + 1 + HASH_SIZE + HASH_SIZE);
    preimage.extend_from_slice(PROOF_ENVELOPE_PREIMAGE_PREFIX_V2);
    preimage.push(proof_kind);
    preimage.extend_from_slice(field_hash);
    preimage.extend_from_slice(tx_binding_hash);
    hash256(&preimage)
}

pub fn proof_public_input_hash(
    proof_kind: u8,
    field_hash: &[u8; HASH_SIZE],
    tx_binding_hash: &[u8; HASH_SIZE],
) -> [u8; HASH_SIZE] {
    let mut preimage =
        Vec::with_capacity(PROOF_PUBLIC_INPUT_PREIMAGE_PREFIX.len() + 1 + HASH_SIZE + HASH_SIZE);
    preimage.extend_from_slice(PROOF_PUBLIC_INPUT_PREIMAGE_PREFIX);
    preimage.push(proof_kind);
    preimage.extend_from_slice(field_hash);
    preimage.extend_from_slice(tx_binding_hash);
    hash256(&preimage)
}

pub fn expected_proof_payload_v3(
    proof_kind: u8,
    public_input_hash: &[u8; HASH_SIZE],
) -> [u8; HASH_SIZE] {
    let mut preimage = Vec::with_capacity(PROOF_ENVELOPE_PREIMAGE_PREFIX_V3.len() + 1 + HASH_SIZE);
    preimage.extend_from_slice(PROOF_ENVELOPE_PREIMAGE_PREFIX_V3);
    preimage.push(proof_kind);
    preimage.extend_from_slice(public_input_hash);
    hash256(&preimage)
}

pub fn expected_proof_payload_v4(
    proof_kind: u8,
    public_input_hash: &[u8; HASH_SIZE],
) -> [u8; HASH_SIZE] {
    let mut preimage = Vec::with_capacity(PROOF_BUNDLE_PREIMAGE_PREFIX_V4.len() + 4 + HASH_SIZE);
    preimage.extend_from_slice(PROOF_BUNDLE_PREIMAGE_PREFIX_V4);
    preimage.push(PROOF_BUNDLE_VERSION_V4);
    preimage.push(proof_kind);
    preimage.push(PROOF_SYSTEM_ORCHARD);
    preimage.push(PROOF_BUNDLE_FLAGS_NONE);
    preimage.extend_from_slice(public_input_hash);
    hash256(&preimage)
}

pub fn expected_orchard_real_verifier_key_hash_v1() -> [u8; HASH_SIZE] {
    hash256(ORCHARD_REAL_VERIFIER_KEY_HASH_PREIMAGE_PREFIX_V1)
}

pub fn build_orchard_real_proof_v1(
    proof_kind: u8,
    public_input_hash: &[u8; HASH_SIZE],
    proof_bytes: &[u8],
) -> Vec<u8> {
    let verifier_key_hash = expected_orchard_real_verifier_key_hash_v1();
    let mut proof = Vec::with_capacity(ORCHARD_REAL_PROOF_HEADER_LEN_V1 + proof_bytes.len());
    proof.extend_from_slice(ORCHARD_REAL_PROOF_PREFIX_V1);
    proof.push(PROOF_BUNDLE_FLAGS_NONE);
    proof.push(proof_kind);
    proof.extend_from_slice(public_input_hash);
    proof.extend_from_slice(&verifier_key_hash);
    proof.extend_from_slice(&(proof_bytes.len() as u32).to_le_bytes());
    proof.extend_from_slice(proof_bytes);
    proof
}

pub fn decode_orchard_real_proof_v1<'a>(
    proof: &'a [u8],
    proof_kind: u8,
    public_input_hash: &[u8; HASH_SIZE],
) -> Option<&'a [u8]> {
    if proof.len() < ORCHARD_REAL_PROOF_HEADER_LEN_V1 {
        return None;
    }
    if !proof.starts_with(ORCHARD_REAL_PROOF_PREFIX_V1) {
        return None;
    }

    let flags_offset = ORCHARD_REAL_PROOF_PREFIX_V1.len();
    let kind_offset = flags_offset + 1;
    let public_input_offset = kind_offset + 1;
    let verifier_key_hash_offset = public_input_offset + HASH_SIZE;
    let proof_len_offset = verifier_key_hash_offset + HASH_SIZE;
    let proof_offset = proof_len_offset + core::mem::size_of::<u32>();

    if proof[flags_offset] != PROOF_BUNDLE_FLAGS_NONE {
        return None;
    }
    if proof[kind_offset] != proof_kind {
        return None;
    }
    if &proof[public_input_offset..verifier_key_hash_offset] != public_input_hash {
        return None;
    }
    if proof[verifier_key_hash_offset..proof_len_offset]
        != expected_orchard_real_verifier_key_hash_v1()
    {
        return None;
    }

    let proof_len = u32::from_le_bytes(
        proof[proof_len_offset..proof_offset]
            .try_into()
            .expect("proof length slice has fixed length"),
    ) as usize;
    if proof_len != proof.len() - proof_offset {
        return None;
    }

    Some(&proof[proof_offset..])
}

pub fn is_well_formed_orchard_real_proof_v1(
    proof: &[u8],
    proof_kind: u8,
    public_input_hash: &[u8; HASH_SIZE],
) -> bool {
    decode_orchard_real_proof_v1(proof, proof_kind, public_input_hash).is_some()
}

pub fn verify_orchard_real_proof_v1(
    proof: &[u8],
    proof_kind: u8,
    public_input_hash: &[u8; HASH_SIZE],
) -> bool {
    orchard_real_proof_status_v1(proof, proof_kind, public_input_hash)
        == OrchardRealProofStatus::Valid
}

pub fn orchard_real_proof_status_v1(
    proof: &[u8],
    proof_kind: u8,
    public_input_hash: &[u8; HASH_SIZE],
) -> OrchardRealProofStatus {
    let Some(proof_bytes) = decode_orchard_real_proof_v1(proof, proof_kind, public_input_hash)
    else {
        return OrchardRealProofStatus::Malformed;
    };
    verify_orchard_real_proof_backend_status_v1(proof_bytes, proof_kind, public_input_hash)
}

fn verify_orchard_real_proof_backend_status_v1(
    _proof_bytes: &[u8],
    _proof_kind: u8,
    _public_input_hash: &[u8; HASH_SIZE],
) -> OrchardRealProofStatus {
    OrchardRealProofStatus::Unsupported
}

pub fn build_proof_bundle_v4(proof_kind: u8, public_input_hash: &[u8; HASH_SIZE]) -> Vec<u8> {
    let proof_payload = build_orchard_proof_payload_v1(proof_kind, public_input_hash);
    build_proof_bundle_with_payload_v4(proof_kind, public_input_hash, &proof_payload)
}

pub fn build_proof_bundle_with_payload_v4(
    proof_kind: u8,
    public_input_hash: &[u8; HASH_SIZE],
    proof_payload: &[u8],
) -> Vec<u8> {
    let mut bundle = Vec::with_capacity(PROOF_BUNDLE_HEADER_LEN_V4 + proof_payload.len());
    bundle.extend_from_slice(PROOF_BUNDLE_PREFIX_V4);
    bundle.push(PROOF_BUNDLE_VERSION_V4);
    bundle.push(proof_kind);
    bundle.push(PROOF_SYSTEM_ORCHARD);
    bundle.push(PROOF_BUNDLE_FLAGS_NONE);
    bundle.extend_from_slice(public_input_hash);
    bundle.extend_from_slice(&(proof_payload.len() as u32).to_le_bytes());
    bundle.extend_from_slice(&proof_payload);
    bundle
}

pub fn build_orchard_proof_payload_v1(
    proof_kind: u8,
    public_input_hash: &[u8; HASH_SIZE],
) -> Vec<u8> {
    let proof_body = build_orchard_proof_body_v1(proof_kind, public_input_hash);
    build_orchard_proof_payload_with_body_v1(proof_kind, public_input_hash, &proof_body)
}

pub fn build_orchard_proof_payload_with_body_v1(
    proof_kind: u8,
    public_input_hash: &[u8; HASH_SIZE],
    proof_body: &[u8],
) -> Vec<u8> {
    let mut payload = Vec::with_capacity(ORCHARD_PROOF_PAYLOAD_HEADER_LEN_V1 + proof_body.len());
    payload.extend_from_slice(ORCHARD_PROOF_PAYLOAD_PREFIX_V1);
    payload.push(proof_kind);
    payload.extend_from_slice(public_input_hash);
    payload.extend_from_slice(&(proof_body.len() as u32).to_le_bytes());
    payload.extend_from_slice(&proof_body);
    payload
}

pub fn build_orchard_proof_body_v1(proof_kind: u8, public_input_hash: &[u8; HASH_SIZE]) -> Vec<u8> {
    let scaffold_body = expected_proof_payload_v4(proof_kind, public_input_hash);
    build_orchard_proof_body_with_mode_v1(ORCHARD_PROOF_BODY_MODE_SCAFFOLD, &scaffold_body)
}

pub fn build_orchard_proof_body_with_mode_v1(mode: u8, proof_bytes: &[u8]) -> Vec<u8> {
    let mut proof_body = Vec::with_capacity(ORCHARD_PROOF_BODY_HEADER_LEN_V1 + proof_bytes.len());
    proof_body.extend_from_slice(ORCHARD_PROOF_BODY_PREFIX_V1);
    proof_body.push(mode);
    proof_body.extend_from_slice(&(proof_bytes.len() as u32).to_le_bytes());
    proof_body.extend_from_slice(proof_bytes);
    proof_body
}

pub fn build_orchard_real_proof_body_v1(proof_bytes: &[u8]) -> Vec<u8> {
    build_orchard_proof_body_with_mode_v1(ORCHARD_PROOF_BODY_MODE_REAL, proof_bytes)
}

pub fn build_orchard_real_proof_body_with_context_v1(
    proof_kind: u8,
    public_input_hash: &[u8; HASH_SIZE],
    proof_bytes: &[u8],
) -> Vec<u8> {
    let proof = build_orchard_real_proof_v1(proof_kind, public_input_hash, proof_bytes);
    build_orchard_real_proof_body_v1(&proof)
}

pub fn verify_orchard_proof_payload_v1(
    proof_payload: &[u8],
    proof_kind: u8,
    public_input_hash: &[u8; HASH_SIZE],
) -> bool {
    if proof_payload.len() < ORCHARD_PROOF_PAYLOAD_HEADER_LEN_V1 {
        return false;
    }
    if !proof_payload.starts_with(ORCHARD_PROOF_PAYLOAD_PREFIX_V1) {
        return false;
    }

    let kind_offset = ORCHARD_PROOF_PAYLOAD_PREFIX_V1.len();
    let public_input_offset = kind_offset + 1;
    let proof_len_offset = public_input_offset + HASH_SIZE;
    let proof_offset = proof_len_offset + core::mem::size_of::<u32>();

    if proof_payload[kind_offset] != proof_kind {
        return false;
    }
    if &proof_payload[public_input_offset..proof_len_offset] != public_input_hash {
        return false;
    }

    let proof_len = u32::from_le_bytes(
        proof_payload[proof_len_offset..proof_offset]
            .try_into()
            .expect("proof length slice has fixed length"),
    ) as usize;
    if proof_len != proof_payload.len() - proof_offset {
        return false;
    }

    let proof_body = &proof_payload[proof_offset..];
    verify_orchard_proof_body_v1(proof_body, proof_kind, public_input_hash)
}

pub fn verify_orchard_proof_body_v1(
    proof_body: &[u8],
    proof_kind: u8,
    public_input_hash: &[u8; HASH_SIZE],
) -> bool {
    if proof_body.len() < ORCHARD_PROOF_BODY_HEADER_LEN_V1 {
        return false;
    }
    if !proof_body.starts_with(ORCHARD_PROOF_BODY_PREFIX_V1) {
        return false;
    }

    let mode_offset = ORCHARD_PROOF_BODY_PREFIX_V1.len();
    let body_len_offset = mode_offset + 1;
    let body_offset = body_len_offset + core::mem::size_of::<u32>();
    let body_mode = proof_body[mode_offset];

    let body_len = u32::from_le_bytes(
        proof_body[body_len_offset..body_offset]
            .try_into()
            .expect("body length slice has fixed length"),
    ) as usize;
    if body_len != proof_body.len() - body_offset {
        return false;
    }

    match body_mode {
        ORCHARD_PROOF_BODY_MODE_SCAFFOLD => {
            &proof_body[body_offset..] == expected_proof_payload_v4(proof_kind, public_input_hash)
        }
        ORCHARD_PROOF_BODY_MODE_REAL => {
            verify_orchard_real_proof_v1(&proof_body[body_offset..], proof_kind, public_input_hash)
        }
        _ => false,
    }
}

pub fn verify_proof_payload_v1(
    proof: &[u8],
    field_hash: &[u8; HASH_SIZE],
    tx_binding_hash: &[u8; HASH_SIZE],
) -> bool {
    proof == expected_proof_payload_v1(field_hash, tx_binding_hash)
}

pub fn verify_proof_payload_v2(
    proof: &[u8],
    proof_kind: u8,
    field_hash: &[u8; HASH_SIZE],
    tx_binding_hash: &[u8; HASH_SIZE],
) -> bool {
    proof == expected_proof_payload_v2(proof_kind, field_hash, tx_binding_hash)
}

pub fn verify_proof_payload_v3(
    proof: &[u8],
    proof_kind: u8,
    public_input_hash: &[u8; HASH_SIZE],
) -> bool {
    proof == expected_proof_payload_v3(proof_kind, public_input_hash)
}

pub fn verify_proof_bundle_v4(
    bundle: &[u8],
    proof_kind: u8,
    public_input_hash: &[u8; HASH_SIZE],
) -> bool {
    if bundle.len() < PROOF_BUNDLE_HEADER_LEN_V4 {
        return false;
    }
    if !bundle.starts_with(PROOF_BUNDLE_PREFIX_V4) {
        return false;
    }

    let version_offset = PROOF_BUNDLE_PREFIX_V4.len();
    let kind_offset = version_offset + 1;
    let proof_system_offset = kind_offset + 1;
    let flags_offset = proof_system_offset + 1;
    let public_input_offset = flags_offset + 1;
    let proof_len_offset = public_input_offset + HASH_SIZE;
    let proof_offset = proof_len_offset + core::mem::size_of::<u32>();

    if bundle[version_offset] != PROOF_BUNDLE_VERSION_V4 {
        return false;
    }
    if bundle[kind_offset] != proof_kind {
        return false;
    }
    if bundle[proof_system_offset] != PROOF_SYSTEM_ORCHARD {
        return false;
    }
    if bundle[flags_offset] != PROOF_BUNDLE_FLAGS_NONE {
        return false;
    }
    if &bundle[public_input_offset..proof_len_offset] != public_input_hash {
        return false;
    }

    let proof_len = u32::from_le_bytes(
        bundle[proof_len_offset..proof_offset]
            .try_into()
            .expect("proof length slice has fixed length"),
    ) as usize;
    if proof_len != bundle.len() - proof_offset {
        return false;
    }

    verify_orchard_proof_payload_v1(&bundle[proof_offset..], proof_kind, public_input_hash)
}

unsafe fn read_hash<'a>(ptr: *const u8, len: usize) -> Option<&'a [u8; HASH_SIZE]> {
    if ptr.is_null() || len != HASH_SIZE {
        return None;
    }
    let bytes = slice::from_raw_parts(ptr, len);
    bytes.try_into().ok()
}

#[no_mangle]
pub unsafe extern "C" fn zkc_shielded_verify_proof_v1(
    proof: *const u8,
    proof_len: usize,
    field_hash: *const u8,
    field_hash_len: usize,
    tx_binding_hash: *const u8,
    tx_binding_hash_len: usize,
) -> i32 {
    if proof.is_null() || proof_len != HASH_SIZE {
        return 0;
    }
    let Some(field_hash) = read_hash(field_hash, field_hash_len) else {
        return 0;
    };
    let Some(tx_binding_hash) = read_hash(tx_binding_hash, tx_binding_hash_len) else {
        return 0;
    };

    let proof = slice::from_raw_parts(proof, proof_len);
    i32::from(verify_proof_payload_v1(proof, field_hash, tx_binding_hash))
}

#[no_mangle]
pub unsafe extern "C" fn zkc_shielded_verify_proof_v2(
    proof: *const u8,
    proof_len: usize,
    proof_kind: u8,
    field_hash: *const u8,
    field_hash_len: usize,
    tx_binding_hash: *const u8,
    tx_binding_hash_len: usize,
) -> i32 {
    if proof.is_null() || proof_len != HASH_SIZE {
        return 0;
    }
    let Some(field_hash) = read_hash(field_hash, field_hash_len) else {
        return 0;
    };
    let Some(tx_binding_hash) = read_hash(tx_binding_hash, tx_binding_hash_len) else {
        return 0;
    };

    let proof = slice::from_raw_parts(proof, proof_len);
    i32::from(verify_proof_payload_v2(
        proof,
        proof_kind,
        field_hash,
        tx_binding_hash,
    ))
}

#[no_mangle]
pub unsafe extern "C" fn zkc_shielded_verify_proof_v3(
    proof: *const u8,
    proof_len: usize,
    proof_kind: u8,
    public_input_hash: *const u8,
    public_input_hash_len: usize,
) -> i32 {
    if proof.is_null() || proof_len != HASH_SIZE {
        return 0;
    }
    let Some(public_input_hash) = read_hash(public_input_hash, public_input_hash_len) else {
        return 0;
    };

    let proof = slice::from_raw_parts(proof, proof_len);
    i32::from(verify_proof_payload_v3(
        proof,
        proof_kind,
        public_input_hash,
    ))
}

#[no_mangle]
pub unsafe extern "C" fn zkc_shielded_verify_bundle_v4(
    bundle: *const u8,
    bundle_len: usize,
    proof_kind: u8,
    public_input_hash: *const u8,
    public_input_hash_len: usize,
) -> i32 {
    if bundle.is_null() {
        return 0;
    }
    let Some(public_input_hash) = read_hash(public_input_hash, public_input_hash_len) else {
        return 0;
    };

    let bundle = slice::from_raw_parts(bundle, bundle_len);
    i32::from(verify_proof_bundle_v4(
        bundle,
        proof_kind,
        public_input_hash,
    ))
}

#[no_mangle]
pub unsafe extern "C" fn zkc_shielded_verify_orchard_proof_v1(
    proof_body: *const u8,
    proof_body_len: usize,
    proof_kind: u8,
    public_input_hash: *const u8,
    public_input_hash_len: usize,
) -> i32 {
    if proof_body.is_null() {
        return 0;
    }
    let Some(public_input_hash) = read_hash(public_input_hash, public_input_hash_len) else {
        return 0;
    };

    let proof_body = slice::from_raw_parts(proof_body, proof_body_len);
    i32::from(verify_orchard_proof_body_v1(
        proof_body,
        proof_kind,
        public_input_hash,
    ))
}

#[no_mangle]
pub unsafe extern "C" fn zkc_shielded_verify_orchard_real_proof_v1(
    proof: *const u8,
    proof_len: usize,
    proof_kind: u8,
    public_input_hash: *const u8,
    public_input_hash_len: usize,
) -> i32 {
    if proof.is_null() {
        return 0;
    }
    let Some(public_input_hash) = read_hash(public_input_hash, public_input_hash_len) else {
        return 0;
    };

    let proof = slice::from_raw_parts(proof, proof_len);
    i32::from(verify_orchard_real_proof_v1(
        proof,
        proof_kind,
        public_input_hash,
    ))
}

#[no_mangle]
pub unsafe extern "C" fn zkc_shielded_verify_orchard_real_proof_status_v1(
    proof: *const u8,
    proof_len: usize,
    proof_kind: u8,
    public_input_hash: *const u8,
    public_input_hash_len: usize,
) -> i32 {
    if proof.is_null() {
        return ORCHARD_REAL_PROOF_STATUS_MALFORMED;
    }
    let Some(public_input_hash) = read_hash(public_input_hash, public_input_hash_len) else {
        return ORCHARD_REAL_PROOF_STATUS_MALFORMED;
    };

    let proof = slice::from_raw_parts(proof, proof_len);
    orchard_real_proof_status_v1(proof, proof_kind, public_input_hash).as_ffi_code()
}

#[cfg(test)]
mod tests {
    use super::*;

    const FIELD_HASH: [u8; HASH_SIZE] = [0x11; HASH_SIZE];
    const TX_BINDING_HASH: [u8; HASH_SIZE] = [0x22; HASH_SIZE];
    const EXPECTED_PROOF: [u8; HASH_SIZE] = [
        0x8d, 0x88, 0xec, 0x0b, 0xaa, 0x50, 0x6b, 0x9d, 0x0a, 0xdd, 0x03, 0x36, 0x13, 0x74, 0x4b,
        0x45, 0x1f, 0x87, 0xe0, 0xd1, 0x17, 0xe7, 0x5e, 0xe5, 0xd4, 0x8f, 0x48, 0x89, 0xa0, 0x7e,
        0x59, 0x8c,
    ];
    const EXPECTED_MINT_PROOF_V2: [u8; HASH_SIZE] = [
        0xae, 0x9b, 0x4e, 0x8b, 0x11, 0x17, 0xc7, 0x69, 0x37, 0x62, 0x97, 0x1b, 0x55, 0x55, 0xcf,
        0xd3, 0x80, 0xd6, 0xa8, 0x94, 0xe5, 0xd9, 0x16, 0xf4, 0x4d, 0x2a, 0x99, 0x1c, 0xea, 0xb3,
        0x9d, 0xa1,
    ];
    const EXPECTED_PUBLIC_INPUT_HASH: [u8; HASH_SIZE] = [
        0x90, 0xd5, 0xa8, 0xbb, 0x82, 0x0b, 0x4f, 0x47, 0x4e, 0x1a, 0x44, 0x5f, 0x0b, 0x23, 0x03,
        0x27, 0x18, 0xc0, 0x7e, 0xbc, 0x5b, 0x94, 0xec, 0x51, 0x23, 0x43, 0x63, 0xa0, 0x67, 0x82,
        0x6e, 0x31,
    ];
    const EXPECTED_MINT_PROOF_V3: [u8; HASH_SIZE] = [
        0x46, 0x50, 0x2b, 0x6c, 0x3c, 0xab, 0xfb, 0xe2, 0x17, 0x8f, 0xbb, 0x6e, 0x7c, 0xcb, 0x90,
        0x14, 0x45, 0x91, 0xf8, 0xce, 0x03, 0x16, 0xf9, 0x0b, 0x5c, 0x0e, 0xb6, 0xc1, 0xa6, 0x3f,
        0x5b, 0x3a,
    ];
    const EXPECTED_MINT_PROOF_V4: [u8; HASH_SIZE] = [
        0xe1, 0x60, 0x23, 0x9b, 0x4c, 0x8b, 0xfc, 0x13, 0x7c, 0xac, 0xf2, 0x10, 0xd0, 0xea, 0xc3,
        0xcb, 0xc8, 0xe6, 0xfa, 0xd5, 0xff, 0xaa, 0x06, 0xca, 0xe6, 0x93, 0x1d, 0xb0, 0x34, 0x58,
        0xc4, 0x24,
    ];
    const EXPECTED_ORCHARD_REAL_VK_HASH: [u8; HASH_SIZE] = [
        0x44, 0x98, 0xa4, 0xda, 0xde, 0xe9, 0x35, 0xcc, 0x2a, 0x7a, 0xf6, 0x97, 0xc5, 0x7a, 0xc3,
        0x55, 0x93, 0xbf, 0xff, 0x59, 0x71, 0x7f, 0x1b, 0x74, 0x0f, 0xe2, 0x82, 0xaf, 0xe3, 0xf3,
        0x2c, 0xd3,
    ];

    #[test]
    fn builds_known_payload() {
        assert_eq!(
            expected_proof_payload_v1(&FIELD_HASH, &TX_BINDING_HASH),
            EXPECTED_PROOF
        );
        assert_eq!(
            expected_proof_payload_v2(1, &FIELD_HASH, &TX_BINDING_HASH),
            EXPECTED_MINT_PROOF_V2
        );
        assert_eq!(
            proof_public_input_hash(1, &FIELD_HASH, &TX_BINDING_HASH),
            EXPECTED_PUBLIC_INPUT_HASH
        );
        assert_eq!(
            expected_proof_payload_v3(1, &EXPECTED_PUBLIC_INPUT_HASH),
            EXPECTED_MINT_PROOF_V3
        );
        assert_eq!(
            expected_proof_payload_v4(1, &EXPECTED_PUBLIC_INPUT_HASH),
            EXPECTED_MINT_PROOF_V4
        );
        assert_eq!(
            expected_orchard_real_verifier_key_hash_v1(),
            EXPECTED_ORCHARD_REAL_VK_HASH
        );
        assert_eq!(
            build_orchard_proof_payload_v1(1, &EXPECTED_PUBLIC_INPUT_HASH).len(),
            ORCHARD_PROOF_PAYLOAD_HEADER_LEN_V1 + ORCHARD_PROOF_BODY_HEADER_LEN_V1 + HASH_SIZE
        );
        assert_eq!(
            build_orchard_proof_body_v1(1, &EXPECTED_PUBLIC_INPUT_HASH).len(),
            ORCHARD_PROOF_BODY_HEADER_LEN_V1 + HASH_SIZE
        );
        assert_eq!(
            build_proof_bundle_v4(1, &EXPECTED_PUBLIC_INPUT_HASH).len(),
            PROOF_BUNDLE_HEADER_LEN_V4
                + ORCHARD_PROOF_PAYLOAD_HEADER_LEN_V1
                + ORCHARD_PROOF_BODY_HEADER_LEN_V1
                + HASH_SIZE
        );
        assert_eq!(
            build_orchard_real_proof_v1(1, &EXPECTED_PUBLIC_INPUT_HASH, &[0x42; 192]).len(),
            ORCHARD_REAL_PROOF_HEADER_LEN_V1 + 192
        );
        assert_eq!(
            build_orchard_real_proof_body_with_context_v1(
                1,
                &EXPECTED_PUBLIC_INPUT_HASH,
                &[0x42; 192]
            )
            .len(),
            ORCHARD_PROOF_BODY_HEADER_LEN_V1 + ORCHARD_REAL_PROOF_HEADER_LEN_V1 + 192
        );
    }

    #[test]
    fn rejects_wrong_proof_context_and_lengths() {
        assert!(verify_proof_payload_v1(
            &EXPECTED_PROOF,
            &FIELD_HASH,
            &TX_BINDING_HASH
        ));
        assert!(!verify_proof_payload_v1(
            &EXPECTED_PROOF[..31],
            &FIELD_HASH,
            &TX_BINDING_HASH
        ));
        assert!(verify_proof_payload_v2(
            &EXPECTED_MINT_PROOF_V2,
            1,
            &FIELD_HASH,
            &TX_BINDING_HASH
        ));
        assert!(!verify_proof_payload_v2(
            &EXPECTED_MINT_PROOF_V2,
            2,
            &FIELD_HASH,
            &TX_BINDING_HASH
        ));
        assert!(verify_proof_payload_v3(
            &EXPECTED_MINT_PROOF_V3,
            1,
            &EXPECTED_PUBLIC_INPUT_HASH
        ));
        assert!(!verify_proof_payload_v3(
            &EXPECTED_MINT_PROOF_V3,
            2,
            &EXPECTED_PUBLIC_INPUT_HASH
        ));
        let bundle_v4 = build_proof_bundle_v4(1, &EXPECTED_PUBLIC_INPUT_HASH);
        let orchard_payload_v1 = build_orchard_proof_payload_v1(1, &EXPECTED_PUBLIC_INPUT_HASH);
        let orchard_body_v1 = build_orchard_proof_body_v1(1, &EXPECTED_PUBLIC_INPUT_HASH);
        assert!(verify_orchard_proof_body_v1(
            &orchard_body_v1,
            1,
            &EXPECTED_PUBLIC_INPUT_HASH
        ));
        assert!(!verify_orchard_proof_body_v1(
            &orchard_body_v1,
            2,
            &EXPECTED_PUBLIC_INPUT_HASH
        ));
        assert!(!verify_orchard_proof_body_v1(
            &EXPECTED_MINT_PROOF_V4,
            1,
            &EXPECTED_PUBLIC_INPUT_HASH
        ));
        let real_proof_v1 =
            build_orchard_real_proof_v1(1, &EXPECTED_PUBLIC_INPUT_HASH, &[0x42; 192]);
        assert!(is_well_formed_orchard_real_proof_v1(
            &real_proof_v1,
            1,
            &EXPECTED_PUBLIC_INPUT_HASH
        ));
        assert_eq!(
            decode_orchard_real_proof_v1(&real_proof_v1, 1, &EXPECTED_PUBLIC_INPUT_HASH),
            Some(&[0x42; 192][..])
        );
        assert!(!verify_orchard_real_proof_v1(
            &real_proof_v1,
            1,
            &EXPECTED_PUBLIC_INPUT_HASH
        ));
        assert_eq!(
            orchard_real_proof_status_v1(&real_proof_v1, 1, &EXPECTED_PUBLIC_INPUT_HASH),
            OrchardRealProofStatus::Unsupported
        );
        assert!(!is_well_formed_orchard_real_proof_v1(
            &real_proof_v1,
            2,
            &EXPECTED_PUBLIC_INPUT_HASH
        ));
        assert_eq!(
            orchard_real_proof_status_v1(&real_proof_v1, 2, &EXPECTED_PUBLIC_INPUT_HASH),
            OrchardRealProofStatus::Malformed
        );
        let mut wrong_real_proof_v1 = real_proof_v1.clone();
        wrong_real_proof_v1[ORCHARD_REAL_PROOF_PREFIX_V1.len()] = 0x01;
        assert!(!is_well_formed_orchard_real_proof_v1(
            &wrong_real_proof_v1,
            1,
            &EXPECTED_PUBLIC_INPUT_HASH
        ));
        assert_eq!(
            orchard_real_proof_status_v1(&wrong_real_proof_v1, 1, &EXPECTED_PUBLIC_INPUT_HASH),
            OrchardRealProofStatus::Malformed
        );
        let mut wrong_real_proof_v1 = real_proof_v1.clone();
        let verifier_key_hash_offset = ORCHARD_REAL_PROOF_PREFIX_V1.len() + 1 + 1 + HASH_SIZE;
        wrong_real_proof_v1[verifier_key_hash_offset] ^= 0x01;
        assert!(!is_well_formed_orchard_real_proof_v1(
            &wrong_real_proof_v1,
            1,
            &EXPECTED_PUBLIC_INPUT_HASH
        ));
        let mut wrong_real_proof_v1 = real_proof_v1.clone();
        let proof_len_offset = verifier_key_hash_offset + HASH_SIZE;
        wrong_real_proof_v1[proof_len_offset] ^= 0x01;
        assert!(!is_well_formed_orchard_real_proof_v1(
            &wrong_real_proof_v1,
            1,
            &EXPECTED_PUBLIC_INPUT_HASH
        ));
        let real_body_v1 = build_orchard_real_proof_body_with_context_v1(
            1,
            &EXPECTED_PUBLIC_INPUT_HASH,
            &[0x42; 192],
        );
        let real_payload_v1 =
            build_orchard_proof_payload_with_body_v1(1, &EXPECTED_PUBLIC_INPUT_HASH, &real_body_v1);
        let real_bundle_v4 =
            build_proof_bundle_with_payload_v4(1, &EXPECTED_PUBLIC_INPUT_HASH, &real_payload_v1);
        assert!(!verify_orchard_proof_body_v1(
            &real_body_v1,
            1,
            &EXPECTED_PUBLIC_INPUT_HASH
        ));
        assert!(!verify_orchard_proof_payload_v1(
            &real_payload_v1,
            1,
            &EXPECTED_PUBLIC_INPUT_HASH
        ));
        assert!(!verify_proof_bundle_v4(
            &real_bundle_v4,
            1,
            &EXPECTED_PUBLIC_INPUT_HASH
        ));
        let mut unknown_body_mode = orchard_body_v1.clone();
        unknown_body_mode[ORCHARD_PROOF_BODY_PREFIX_V1.len()] = 0xff;
        assert!(!verify_orchard_proof_body_v1(
            &unknown_body_mode,
            1,
            &EXPECTED_PUBLIC_INPUT_HASH
        ));
        assert!(verify_orchard_proof_payload_v1(
            &orchard_payload_v1,
            1,
            &EXPECTED_PUBLIC_INPUT_HASH
        ));
        assert!(!verify_orchard_proof_payload_v1(
            &orchard_payload_v1,
            2,
            &EXPECTED_PUBLIC_INPUT_HASH
        ));
        assert!(verify_proof_bundle_v4(
            &bundle_v4,
            1,
            &EXPECTED_PUBLIC_INPUT_HASH
        ));
        assert!(!verify_proof_bundle_v4(
            &bundle_v4,
            2,
            &EXPECTED_PUBLIC_INPUT_HASH
        ));

        let mut wrong_field_hash = FIELD_HASH;
        wrong_field_hash[0] ^= 1;
        assert!(!verify_proof_payload_v1(
            &EXPECTED_PROOF,
            &wrong_field_hash,
            &TX_BINDING_HASH
        ));
        assert!(!verify_proof_payload_v2(
            &EXPECTED_MINT_PROOF_V2,
            1,
            &wrong_field_hash,
            &TX_BINDING_HASH
        ));
        let wrong_public_input_hash =
            proof_public_input_hash(1, &wrong_field_hash, &TX_BINDING_HASH);
        assert!(!verify_proof_payload_v3(
            &EXPECTED_MINT_PROOF_V3,
            1,
            &wrong_public_input_hash
        ));
        assert!(!verify_proof_bundle_v4(
            &bundle_v4,
            1,
            &wrong_public_input_hash
        ));

        let mut wrong_bundle = bundle_v4;
        wrong_bundle[0] ^= 1;
        assert!(!verify_proof_bundle_v4(
            &wrong_bundle,
            1,
            &EXPECTED_PUBLIC_INPUT_HASH
        ));

        let mut wrong_payload = orchard_payload_v1;
        wrong_payload[ORCHARD_PROOF_PAYLOAD_PREFIX_V1.len()] ^= 1;
        assert!(!verify_orchard_proof_payload_v1(
            &wrong_payload,
            1,
            &EXPECTED_PUBLIC_INPUT_HASH
        ));
    }

    #[test]
    fn c_abi_matches_safe_api() {
        let ok = unsafe {
            zkc_shielded_verify_proof_v1(
                EXPECTED_PROOF.as_ptr(),
                EXPECTED_PROOF.len(),
                FIELD_HASH.as_ptr(),
                FIELD_HASH.len(),
                TX_BINDING_HASH.as_ptr(),
                TX_BINDING_HASH.len(),
            )
        };
        assert_eq!(ok, 1);

        let bad = unsafe {
            zkc_shielded_verify_proof_v1(
                EXPECTED_PROOF.as_ptr(),
                EXPECTED_PROOF.len() - 1,
                FIELD_HASH.as_ptr(),
                FIELD_HASH.len(),
                TX_BINDING_HASH.as_ptr(),
                TX_BINDING_HASH.len(),
            )
        };
        assert_eq!(bad, 0);

        let null = unsafe {
            zkc_shielded_verify_proof_v1(
                core::ptr::null(),
                EXPECTED_PROOF.len(),
                FIELD_HASH.as_ptr(),
                FIELD_HASH.len(),
                TX_BINDING_HASH.as_ptr(),
                TX_BINDING_HASH.len(),
            )
        };
        assert_eq!(null, 0);

        let ok_v2 = unsafe {
            zkc_shielded_verify_proof_v2(
                EXPECTED_MINT_PROOF_V2.as_ptr(),
                EXPECTED_MINT_PROOF_V2.len(),
                1,
                FIELD_HASH.as_ptr(),
                FIELD_HASH.len(),
                TX_BINDING_HASH.as_ptr(),
                TX_BINDING_HASH.len(),
            )
        };
        assert_eq!(ok_v2, 1);

        let bad_kind_v2 = unsafe {
            zkc_shielded_verify_proof_v2(
                EXPECTED_MINT_PROOF_V2.as_ptr(),
                EXPECTED_MINT_PROOF_V2.len(),
                2,
                FIELD_HASH.as_ptr(),
                FIELD_HASH.len(),
                TX_BINDING_HASH.as_ptr(),
                TX_BINDING_HASH.len(),
            )
        };
        assert_eq!(bad_kind_v2, 0);

        let ok_v3 = unsafe {
            zkc_shielded_verify_proof_v3(
                EXPECTED_MINT_PROOF_V3.as_ptr(),
                EXPECTED_MINT_PROOF_V3.len(),
                1,
                EXPECTED_PUBLIC_INPUT_HASH.as_ptr(),
                EXPECTED_PUBLIC_INPUT_HASH.len(),
            )
        };
        assert_eq!(ok_v3, 1);

        let bad_kind_v3 = unsafe {
            zkc_shielded_verify_proof_v3(
                EXPECTED_MINT_PROOF_V3.as_ptr(),
                EXPECTED_MINT_PROOF_V3.len(),
                2,
                EXPECTED_PUBLIC_INPUT_HASH.as_ptr(),
                EXPECTED_PUBLIC_INPUT_HASH.len(),
            )
        };
        assert_eq!(bad_kind_v3, 0);

        let bundle_v4 = build_proof_bundle_v4(1, &EXPECTED_PUBLIC_INPUT_HASH);
        let ok_v4 = unsafe {
            zkc_shielded_verify_bundle_v4(
                bundle_v4.as_ptr(),
                bundle_v4.len(),
                1,
                EXPECTED_PUBLIC_INPUT_HASH.as_ptr(),
                EXPECTED_PUBLIC_INPUT_HASH.len(),
            )
        };
        assert_eq!(ok_v4, 1);

        let bad_kind_v4 = unsafe {
            zkc_shielded_verify_bundle_v4(
                bundle_v4.as_ptr(),
                bundle_v4.len(),
                2,
                EXPECTED_PUBLIC_INPUT_HASH.as_ptr(),
                EXPECTED_PUBLIC_INPUT_HASH.len(),
            )
        };
        assert_eq!(bad_kind_v4, 0);

        let orchard_body_v1 = build_orchard_proof_body_v1(1, &EXPECTED_PUBLIC_INPUT_HASH);
        let ok_orchard_body_v1 = unsafe {
            zkc_shielded_verify_orchard_proof_v1(
                orchard_body_v1.as_ptr(),
                orchard_body_v1.len(),
                1,
                EXPECTED_PUBLIC_INPUT_HASH.as_ptr(),
                EXPECTED_PUBLIC_INPUT_HASH.len(),
            )
        };
        assert_eq!(ok_orchard_body_v1, 1);

        let bad_kind_orchard_body_v1 = unsafe {
            zkc_shielded_verify_orchard_proof_v1(
                orchard_body_v1.as_ptr(),
                orchard_body_v1.len(),
                2,
                EXPECTED_PUBLIC_INPUT_HASH.as_ptr(),
                EXPECTED_PUBLIC_INPUT_HASH.len(),
            )
        };
        assert_eq!(bad_kind_orchard_body_v1, 0);

        let bad_len_orchard_body_v1 = unsafe {
            zkc_shielded_verify_orchard_proof_v1(
                orchard_body_v1.as_ptr(),
                orchard_body_v1.len() - 1,
                1,
                EXPECTED_PUBLIC_INPUT_HASH.as_ptr(),
                EXPECTED_PUBLIC_INPUT_HASH.len(),
            )
        };
        assert_eq!(bad_len_orchard_body_v1, 0);

        let real_proof_v1 =
            build_orchard_real_proof_v1(1, &EXPECTED_PUBLIC_INPUT_HASH, &[0x42; 192]);
        let unsupported_real_proof_status_v1 = unsafe {
            zkc_shielded_verify_orchard_real_proof_status_v1(
                real_proof_v1.as_ptr(),
                real_proof_v1.len(),
                1,
                EXPECTED_PUBLIC_INPUT_HASH.as_ptr(),
                EXPECTED_PUBLIC_INPUT_HASH.len(),
            )
        };
        assert_eq!(
            unsupported_real_proof_status_v1,
            ORCHARD_REAL_PROOF_STATUS_UNSUPPORTED
        );
        let unsupported_real_proof_v1 = unsafe {
            zkc_shielded_verify_orchard_real_proof_v1(
                real_proof_v1.as_ptr(),
                real_proof_v1.len(),
                1,
                EXPECTED_PUBLIC_INPUT_HASH.as_ptr(),
                EXPECTED_PUBLIC_INPUT_HASH.len(),
            )
        };
        assert_eq!(unsupported_real_proof_v1, 0);

        let malformed_real_proof_status_v1 = unsafe {
            zkc_shielded_verify_orchard_real_proof_status_v1(
                real_proof_v1.as_ptr(),
                real_proof_v1.len(),
                2,
                EXPECTED_PUBLIC_INPUT_HASH.as_ptr(),
                EXPECTED_PUBLIC_INPUT_HASH.len(),
            )
        };
        assert_eq!(
            malformed_real_proof_status_v1,
            ORCHARD_REAL_PROOF_STATUS_MALFORMED
        );

        let real_body_v1 = build_orchard_real_proof_body_with_context_v1(
            1,
            &EXPECTED_PUBLIC_INPUT_HASH,
            &[0x42; 192],
        );
        let unsupported_real_body_v1 = unsafe {
            zkc_shielded_verify_orchard_proof_v1(
                real_body_v1.as_ptr(),
                real_body_v1.len(),
                1,
                EXPECTED_PUBLIC_INPUT_HASH.as_ptr(),
                EXPECTED_PUBLIC_INPUT_HASH.len(),
            )
        };
        assert_eq!(unsupported_real_body_v1, 0);
    }
}
