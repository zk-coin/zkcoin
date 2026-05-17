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

static const unsigned char EXPECTED_PUBLIC_INPUT_HASH[32] = {
    0x90, 0xd5, 0xa8, 0xbb, 0x82, 0x0b, 0x4f, 0x47,
    0x4e, 0x1a, 0x44, 0x5f, 0x0b, 0x23, 0x03, 0x27,
    0x18, 0xc0, 0x7e, 0xbc, 0x5b, 0x94, 0xec, 0x51,
    0x23, 0x43, 0x63, 0xa0, 0x67, 0x82, 0x6e, 0x31,
};

static const unsigned char EXPECTED_MINT_PROOF_V3[32] = {
    0x46, 0x50, 0x2b, 0x6c, 0x3c, 0xab, 0xfb, 0xe2,
    0x17, 0x8f, 0xbb, 0x6e, 0x7c, 0xcb, 0x90, 0x14,
    0x45, 0x91, 0xf8, 0xce, 0x03, 0x16, 0xf9, 0x0b,
    0x5c, 0x0e, 0xb6, 0xc1, 0xa6, 0x3f, 0x5b, 0x3a,
};

static const unsigned char EXPECTED_MINT_PROOF_V4[32] = {
    0xe1, 0x60, 0x23, 0x9b, 0x4c, 0x8b, 0xfc, 0x13,
    0x7c, 0xac, 0xf2, 0x10, 0xd0, 0xea, 0xc3, 0xcb,
    0xc8, 0xe6, 0xfa, 0xd5, 0xff, 0xaa, 0x06, 0xca,
    0xe6, 0x93, 0x1d, 0xb0, 0x34, 0x58, 0xc4, 0x24,
};

int main(void)
{
    unsigned char expected_bundle_v4[78];
    memcpy(expected_bundle_v4, "zkc-p4", 6);
    expected_bundle_v4[6] = 1;
    expected_bundle_v4[7] = 1;
    expected_bundle_v4[8] = 1;
    expected_bundle_v4[9] = 0;
    memcpy(expected_bundle_v4 + 10, EXPECTED_PUBLIC_INPUT_HASH, sizeof(EXPECTED_PUBLIC_INPUT_HASH));
    expected_bundle_v4[42] = 32;
    expected_bundle_v4[43] = 0;
    expected_bundle_v4[44] = 0;
    expected_bundle_v4[45] = 0;
    memcpy(expected_bundle_v4 + 46, EXPECTED_MINT_PROOF_V4, sizeof(EXPECTED_MINT_PROOF_V4));

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

    if (zkc_shielded_verify_proof_v3(EXPECTED_MINT_PROOF_V3, sizeof(EXPECTED_MINT_PROOF_V3), 1, EXPECTED_PUBLIC_INPUT_HASH, sizeof(EXPECTED_PUBLIC_INPUT_HASH)) != 1) {
        return 7;
    }

    if (zkc_shielded_verify_proof_v3(EXPECTED_MINT_PROOF_V3, sizeof(EXPECTED_MINT_PROOF_V3), 2, EXPECTED_PUBLIC_INPUT_HASH, sizeof(EXPECTED_PUBLIC_INPUT_HASH)) != 0) {
        return 8;
    }

    if (zkc_shielded_verify_bundle_v4(expected_bundle_v4, sizeof(expected_bundle_v4), 1, EXPECTED_PUBLIC_INPUT_HASH, sizeof(EXPECTED_PUBLIC_INPUT_HASH)) != 1) {
        return 9;
    }

    if (zkc_shielded_verify_bundle_v4(expected_bundle_v4, sizeof(expected_bundle_v4), 2, EXPECTED_PUBLIC_INPUT_HASH, sizeof(EXPECTED_PUBLIC_INPUT_HASH)) != 0) {
        return 10;
    }

    return 0;
}
