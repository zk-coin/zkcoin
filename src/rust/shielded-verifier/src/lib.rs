// Copyright (c) 2026 The zkCoin developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

use core::slice;
use sha2::{Digest, Sha256};

const HASH_SIZE: usize = 32;
const PROOF_ENVELOPE_PREIMAGE_PREFIX: &[u8] = b"zkc-proof-envelope-v1";

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

pub fn verify_proof_payload_v1(proof: &[u8], field_hash: &[u8; HASH_SIZE], tx_binding_hash: &[u8; HASH_SIZE]) -> bool {
    proof == expected_proof_payload_v1(field_hash, tx_binding_hash)
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

    #[test]
    fn builds_known_payload() {
        assert_eq!(expected_proof_payload_v1(&FIELD_HASH, &TX_BINDING_HASH), EXPECTED_PROOF);
    }

    #[test]
    fn rejects_wrong_proof_context_and_lengths() {
        assert!(verify_proof_payload_v1(&EXPECTED_PROOF, &FIELD_HASH, &TX_BINDING_HASH));
        assert!(!verify_proof_payload_v1(&EXPECTED_PROOF[..31], &FIELD_HASH, &TX_BINDING_HASH));

        let mut wrong_field_hash = FIELD_HASH;
        wrong_field_hash[0] ^= 1;
        assert!(!verify_proof_payload_v1(&EXPECTED_PROOF, &wrong_field_hash, &TX_BINDING_HASH));
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
    }
}
