// Copyright (c) 2026 The zkCoin developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef ZKC_SHIELDED_VERIFIER_H
#define ZKC_SHIELDED_VERIFIER_H

#include <stddef.h>

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

#ifdef __cplusplus
}
#endif

#endif // ZKC_SHIELDED_VERIFIER_H
