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

fn hash256(data: &[u8]) -> [u8; HASH_SIZE] {
    let first = Sha256::digest(data);
    let second = Sha256::digest(first);
    second.into()
}

pub fn expected_proof_payload_v1(field_hash: &[u8; HASH_SIZE], tx_binding_hash: &[u8; HASH_SIZE]) -> [u8; HASH_SIZE] {
    let mut preimage = Vec::with_capacity(PROOF_ENVELOPE_PREIMAGE_PREFIX.len() + HASH_SIZE + HASH_SIZE);
    preimage.extend_from_slice(PROOF_ENVELOPE_PREIMAGE_PREFIX);
    preimage.extend_from_slice(field_hash);
    preimage.extend_from_slice(tx_binding_hash);
    hash256(&preimage)
}

pub fn expected_proof_payload_v2(proof_kind: u8, field_hash: &[u8; HASH_SIZE], tx_binding_hash: &[u8; HASH_SIZE]) -> [u8; HASH_SIZE] {
    let mut preimage = Vec::with_capacity(PROOF_ENVELOPE_PREIMAGE_PREFIX_V2.len() + 1 + HASH_SIZE + HASH_SIZE);
    preimage.extend_from_slice(PROOF_ENVELOPE_PREIMAGE_PREFIX_V2);
    preimage.push(proof_kind);
    preimage.extend_from_slice(field_hash);
    preimage.extend_from_slice(tx_binding_hash);
    hash256(&preimage)
}

pub fn proof_public_input_hash(proof_kind: u8, field_hash: &[u8; HASH_SIZE], tx_binding_hash: &[u8; HASH_SIZE]) -> [u8; HASH_SIZE] {
    let mut preimage = Vec::with_capacity(PROOF_PUBLIC_INPUT_PREIMAGE_PREFIX.len() + 1 + HASH_SIZE + HASH_SIZE);
    preimage.extend_from_slice(PROOF_PUBLIC_INPUT_PREIMAGE_PREFIX);
    preimage.push(proof_kind);
    preimage.extend_from_slice(field_hash);
    preimage.extend_from_slice(tx_binding_hash);
    hash256(&preimage)
}

pub fn expected_proof_payload_v3(proof_kind: u8, public_input_hash: &[u8; HASH_SIZE]) -> [u8; HASH_SIZE] {
    let mut preimage = Vec::with_capacity(PROOF_ENVELOPE_PREIMAGE_PREFIX_V3.len() + 1 + HASH_SIZE);
    preimage.extend_from_slice(PROOF_ENVELOPE_PREIMAGE_PREFIX_V3);
    preimage.push(proof_kind);
    preimage.extend_from_slice(public_input_hash);
    hash256(&preimage)
}

pub fn verify_proof_payload_v1(proof: &[u8], field_hash: &[u8; HASH_SIZE], tx_binding_hash: &[u8; HASH_SIZE]) -> bool {
    proof == expected_proof_payload_v1(field_hash, tx_binding_hash)
}

pub fn verify_proof_payload_v2(proof: &[u8], proof_kind: u8, field_hash: &[u8; HASH_SIZE], tx_binding_hash: &[u8; HASH_SIZE]) -> bool {
    proof == expected_proof_payload_v2(proof_kind, field_hash, tx_binding_hash)
}

pub fn verify_proof_payload_v3(proof: &[u8], proof_kind: u8, public_input_hash: &[u8; HASH_SIZE]) -> bool {
    proof == expected_proof_payload_v3(proof_kind, public_input_hash)
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
    i32::from(verify_proof_payload_v2(proof, proof_kind, field_hash, tx_binding_hash))
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
    i32::from(verify_proof_payload_v3(proof, proof_kind, public_input_hash))
}

#[cfg(test)]
mod tests {
    use super::*;

    const FIELD_HASH: [u8; HASH_SIZE] = [0x11; HASH_SIZE];
    const TX_BINDING_HASH: [u8; HASH_SIZE] = [0x22; HASH_SIZE];
    const EXPECTED_PROOF: [u8; HASH_SIZE] = [
        0x8d, 0x88, 0xec, 0x0b, 0xaa, 0x50, 0x6b, 0x9d,
        0x0a, 0xdd, 0x03, 0x36, 0x13, 0x74, 0x4b, 0x45,
        0x1f, 0x87, 0xe0, 0xd1, 0x17, 0xe7, 0x5e, 0xe5,
        0xd4, 0x8f, 0x48, 0x89, 0xa0, 0x7e, 0x59, 0x8c,
    ];
    const EXPECTED_MINT_PROOF_V2: [u8; HASH_SIZE] = [
        0xae, 0x9b, 0x4e, 0x8b, 0x11, 0x17, 0xc7, 0x69,
        0x37, 0x62, 0x97, 0x1b, 0x55, 0x55, 0xcf, 0xd3,
        0x80, 0xd6, 0xa8, 0x94, 0xe5, 0xd9, 0x16, 0xf4,
        0x4d, 0x2a, 0x99, 0x1c, 0xea, 0xb3, 0x9d, 0xa1,
    ];
    const EXPECTED_PUBLIC_INPUT_HASH: [u8; HASH_SIZE] = [
        0x90, 0xd5, 0xa8, 0xbb, 0x82, 0x0b, 0x4f, 0x47,
        0x4e, 0x1a, 0x44, 0x5f, 0x0b, 0x23, 0x03, 0x27,
        0x18, 0xc0, 0x7e, 0xbc, 0x5b, 0x94, 0xec, 0x51,
        0x23, 0x43, 0x63, 0xa0, 0x67, 0x82, 0x6e, 0x31,
    ];
    const EXPECTED_MINT_PROOF_V3: [u8; HASH_SIZE] = [
        0x46, 0x50, 0x2b, 0x6c, 0x3c, 0xab, 0xfb, 0xe2,
        0x17, 0x8f, 0xbb, 0x6e, 0x7c, 0xcb, 0x90, 0x14,
        0x45, 0x91, 0xf8, 0xce, 0x03, 0x16, 0xf9, 0x0b,
        0x5c, 0x0e, 0xb6, 0xc1, 0xa6, 0x3f, 0x5b, 0x3a,
    ];

    #[test]
    fn builds_known_payload() {
        assert_eq!(expected_proof_payload_v1(&FIELD_HASH, &TX_BINDING_HASH), EXPECTED_PROOF);
        assert_eq!(expected_proof_payload_v2(1, &FIELD_HASH, &TX_BINDING_HASH), EXPECTED_MINT_PROOF_V2);
        assert_eq!(proof_public_input_hash(1, &FIELD_HASH, &TX_BINDING_HASH), EXPECTED_PUBLIC_INPUT_HASH);
        assert_eq!(expected_proof_payload_v3(1, &EXPECTED_PUBLIC_INPUT_HASH), EXPECTED_MINT_PROOF_V3);
    }

    #[test]
    fn rejects_wrong_proof_context_and_lengths() {
        assert!(verify_proof_payload_v1(&EXPECTED_PROOF, &FIELD_HASH, &TX_BINDING_HASH));
        assert!(!verify_proof_payload_v1(&EXPECTED_PROOF[..31], &FIELD_HASH, &TX_BINDING_HASH));
        assert!(verify_proof_payload_v2(&EXPECTED_MINT_PROOF_V2, 1, &FIELD_HASH, &TX_BINDING_HASH));
        assert!(!verify_proof_payload_v2(&EXPECTED_MINT_PROOF_V2, 2, &FIELD_HASH, &TX_BINDING_HASH));
        assert!(verify_proof_payload_v3(&EXPECTED_MINT_PROOF_V3, 1, &EXPECTED_PUBLIC_INPUT_HASH));
        assert!(!verify_proof_payload_v3(&EXPECTED_MINT_PROOF_V3, 2, &EXPECTED_PUBLIC_INPUT_HASH));

        let mut wrong_field_hash = FIELD_HASH;
        wrong_field_hash[0] ^= 1;
        assert!(!verify_proof_payload_v1(&EXPECTED_PROOF, &wrong_field_hash, &TX_BINDING_HASH));
        assert!(!verify_proof_payload_v2(&EXPECTED_MINT_PROOF_V2, 1, &wrong_field_hash, &TX_BINDING_HASH));
        let wrong_public_input_hash = proof_public_input_hash(1, &wrong_field_hash, &TX_BINDING_HASH);
        assert!(!verify_proof_payload_v3(&EXPECTED_MINT_PROOF_V3, 1, &wrong_public_input_hash));
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
    }
}
