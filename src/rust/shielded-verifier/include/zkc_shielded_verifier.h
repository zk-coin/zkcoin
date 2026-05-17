// Copyright (c) 2026 The zkCoin developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef ZKC_SHIELDED_VERIFIER_H
#define ZKC_SHIELDED_VERIFIER_H

#include <stddef.h>
#include <stdint.h>

#define ZKC_ORCHARD_REAL_PROOF_STATUS_MALFORMED 0
#define ZKC_ORCHARD_REAL_PROOF_STATUS_VALID 1
#define ZKC_ORCHARD_REAL_PROOF_STATUS_INVALID -1
#define ZKC_ORCHARD_REAL_PROOF_STATUS_UNSUPPORTED -2
#define ZKC_ORCHARD_PROOF_BODY_MODE_SCAFFOLD 0
#define ZKC_ORCHARD_PROOF_BODY_MODE_REAL 1
#define ZKC_ORCHARD_PROOF_BODY_MODE_UNKNOWN 255
#define ZKC_ORCHARD_REAL_VERIFIER_BACKEND_UNSUPPORTED 0
#define ZKC_ORCHARD_REAL_VERIFIER_BACKEND_ORCHARD_V1 1

#ifdef __cplusplus
extern "C" {
#endif

int zkc_shielded_verify_proof_v1(
    const unsigned char* proof,
    size_t proof_len,
    const unsigned char* field_hash,
    size_t field_hash_len,
    const unsigned char* tx_binding_hash,
    size_t tx_binding_hash_len);

int zkc_shielded_verify_proof_v2(
    const unsigned char* proof,
    size_t proof_len,
    uint8_t proof_kind,
    const unsigned char* field_hash,
    size_t field_hash_len,
    const unsigned char* tx_binding_hash,
    size_t tx_binding_hash_len);

int zkc_shielded_verify_proof_v3(
    const unsigned char* proof,
    size_t proof_len,
    uint8_t proof_kind,
    const unsigned char* public_input_hash,
    size_t public_input_hash_len);

int zkc_shielded_verify_bundle_v4(
    const unsigned char* bundle,
    size_t bundle_len,
    uint8_t proof_kind,
    const unsigned char* public_input_hash,
    size_t public_input_hash_len);

int zkc_shielded_check_bundle_v4(
    const unsigned char* bundle,
    size_t bundle_len,
    uint8_t proof_kind,
    const unsigned char* public_input_hash,
    size_t public_input_hash_len,
    uint8_t* proof_body_mode_out,
    unsigned char* real_request_hash_out,
    size_t real_request_hash_out_len);

int zkc_shielded_check_bundle_v5(
    const unsigned char* bundle,
    size_t bundle_len,
    uint8_t proof_kind,
    const unsigned char* public_input_hash,
    size_t public_input_hash_len,
    uint8_t* proof_body_mode_out,
    unsigned char* real_request_hash_out,
    size_t real_request_hash_out_len,
    unsigned char* real_verifier_input_hash_out,
    size_t real_verifier_input_hash_out_len);

int zkc_shielded_verify_orchard_proof_v1(
    const unsigned char* proof_body,
    size_t proof_body_len,
    uint8_t proof_kind,
    const unsigned char* public_input_hash,
    size_t public_input_hash_len);

int zkc_shielded_verify_orchard_real_proof_v1(
    const unsigned char* proof,
    size_t proof_len,
    uint8_t proof_kind,
    const unsigned char* public_input_hash,
    size_t public_input_hash_len);

int zkc_shielded_verify_orchard_real_proof_status_v1(
    const unsigned char* proof,
    size_t proof_len,
    uint8_t proof_kind,
    const unsigned char* public_input_hash,
    size_t public_input_hash_len);

int zkc_shielded_orchard_real_verifier_backend_v1(void);

int zkc_shielded_orchard_real_verifier_supports_proofs_v1(void);

int zkc_shielded_orchard_real_proof_request_hash_v1(
    const unsigned char* proof,
    size_t proof_len,
    uint8_t proof_kind,
    const unsigned char* public_input_hash,
    size_t public_input_hash_len,
    unsigned char* request_hash_out,
    size_t request_hash_out_len);

int zkc_shielded_orchard_real_verifier_input_hash_v1(
    const unsigned char* proof,
    size_t proof_len,
    uint8_t proof_kind,
    const unsigned char* public_input_hash,
    size_t public_input_hash_len,
    unsigned char* verifier_input_hash_out,
    size_t verifier_input_hash_out_len);

int zkc_shielded_orchard_real_proof_check_v1(
    const unsigned char* proof,
    size_t proof_len,
    uint8_t proof_kind,
    const unsigned char* public_input_hash,
    size_t public_input_hash_len,
    unsigned char* request_hash_out,
    size_t request_hash_out_len);

int zkc_shielded_orchard_real_proof_check_v2(
    const unsigned char* proof,
    size_t proof_len,
    uint8_t proof_kind,
    const unsigned char* public_input_hash,
    size_t public_input_hash_len,
    unsigned char* request_hash_out,
    size_t request_hash_out_len,
    unsigned char* verifier_input_hash_out,
    size_t verifier_input_hash_out_len);

#ifdef __cplusplus
}
#endif

#endif // ZKC_SHIELDED_VERIFIER_H
