// Copyright (c) 2026 The zkCoin developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <stddef.h>
#include <string.h>

#include "zkc_shielded_verifier.h"

static const unsigned char FIELD_HASH[32] = {
    0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11,
    0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11,
    0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11,
    0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11,
};

static const unsigned char TX_BINDING_HASH[32] = {
    0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22,
    0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22,
    0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22,
    0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22,
};

static const unsigned char EXPECTED_PROOF[32] = {
    0x8d, 0x88, 0xec, 0x0b, 0xaa, 0x50, 0x6b, 0x9d,
    0x0a, 0xdd, 0x03, 0x36, 0x13, 0x74, 0x4b, 0x45,
    0x1f, 0x87, 0xe0, 0xd1, 0x17, 0xe7, 0x5e, 0xe5,
    0xd4, 0x8f, 0x48, 0x89, 0xa0, 0x7e, 0x59, 0x8c,
};

static const unsigned char EXPECTED_MINT_PROOF_V2[32] = {
    0xae, 0x9b, 0x4e, 0x8b, 0x11, 0x17, 0xc7, 0x69,
    0x37, 0x62, 0x97, 0x1b, 0x55, 0x55, 0xcf, 0xd3,
    0x80, 0xd6, 0xa8, 0x94, 0xe5, 0xd9, 0x16, 0xf4,
    0x4d, 0x2a, 0x99, 0x1c, 0xea, 0xb3, 0x9d, 0xa1,
};

int main(void)
{
    if (zkc_shielded_verify_proof_v1(EXPECTED_PROOF, sizeof(EXPECTED_PROOF), FIELD_HASH, sizeof(FIELD_HASH), TX_BINDING_HASH, sizeof(TX_BINDING_HASH)) != 1) {
        return 1;
    }

    unsigned char wrong_proof[32];
    memcpy(wrong_proof, EXPECTED_PROOF, sizeof(wrong_proof));
    wrong_proof[0] ^= 0x01;
    if (zkc_shielded_verify_proof_v1(wrong_proof, sizeof(wrong_proof), FIELD_HASH, sizeof(FIELD_HASH), TX_BINDING_HASH, sizeof(TX_BINDING_HASH)) != 0) {
        return 2;
    }

    if (zkc_shielded_verify_proof_v1(EXPECTED_PROOF, sizeof(EXPECTED_PROOF) - 1, FIELD_HASH, sizeof(FIELD_HASH), TX_BINDING_HASH, sizeof(TX_BINDING_HASH)) != 0) {
        return 3;
    }

    if (zkc_shielded_verify_proof_v1(NULL, sizeof(EXPECTED_PROOF), FIELD_HASH, sizeof(FIELD_HASH), TX_BINDING_HASH, sizeof(TX_BINDING_HASH)) != 0) {
        return 4;
    }

    if (zkc_shielded_verify_proof_v2(EXPECTED_MINT_PROOF_V2, sizeof(EXPECTED_MINT_PROOF_V2), 1, FIELD_HASH, sizeof(FIELD_HASH), TX_BINDING_HASH, sizeof(TX_BINDING_HASH)) != 1) {
        return 5;
    }

    if (zkc_shielded_verify_proof_v2(EXPECTED_MINT_PROOF_V2, sizeof(EXPECTED_MINT_PROOF_V2), 2, FIELD_HASH, sizeof(FIELD_HASH), TX_BINDING_HASH, sizeof(TX_BINDING_HASH)) != 0) {
        return 6;
    }

    return 0;
}
