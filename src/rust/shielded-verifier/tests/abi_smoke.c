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

static const unsigned char EXPECTED_ORCHARD_REAL_VK_HASH[32] = {
    0x44, 0x98, 0xa4, 0xda, 0xde, 0xe9, 0x35, 0xcc,
    0x2a, 0x7a, 0xf6, 0x97, 0xc5, 0x7a, 0xc3, 0x55,
    0x93, 0xbf, 0xff, 0x59, 0x71, 0x7f, 0x1b, 0x74,
    0x0f, 0xe2, 0x82, 0xaf, 0xe3, 0xf3, 0x2c, 0xd3,
};

static const unsigned char EXPECTED_ORCHARD_REAL_REQUEST_HASH[32] = {
    0x50, 0xa2, 0x6b, 0x9b, 0xf8, 0x44, 0xa9, 0x3a,
    0x8b, 0x08, 0xeb, 0xd4, 0xf8, 0x1f, 0xab, 0xee,
    0x25, 0xa0, 0x58, 0x91, 0xcd, 0x10, 0xd3, 0xe7,
    0x0a, 0xbd, 0xa9, 0x6d, 0xe2, 0xbf, 0x24, 0x19,
};

static const unsigned char EXPECTED_ORCHARD_REAL_VERIFIER_INPUT_HASH[32] = {
    0x66, 0xb7, 0xae, 0xc4, 0xde, 0xa3, 0x68, 0x22,
    0xc7, 0xe8, 0xef, 0xaf, 0x4b, 0x21, 0xed, 0xd6,
    0x91, 0x5c, 0x31, 0x91, 0x6a, 0xc8, 0x09, 0x27,
    0x91, 0x50, 0x23, 0x6c, 0xf9, 0x4d, 0x5b, 0xc7,
};

int main(void)
{
    unsigned char expected_orchard_body_v1[56];
    memcpy(expected_orchard_body_v1, "zkc-orchard-body-v1", 19);
    expected_orchard_body_v1[19] = 0;
    expected_orchard_body_v1[20] = 32;
    expected_orchard_body_v1[21] = 0;
    expected_orchard_body_v1[22] = 0;
    expected_orchard_body_v1[23] = 0;
    memcpy(expected_orchard_body_v1 + 24, EXPECTED_MINT_PROOF_V4, sizeof(EXPECTED_MINT_PROOF_V4));

    unsigned char real_orchard_proof_v1[153];
    memcpy(real_orchard_proof_v1, "zkc-orchard-real-v1", 19);
    real_orchard_proof_v1[19] = 0;
    real_orchard_proof_v1[20] = 1;
    memcpy(real_orchard_proof_v1 + 21, EXPECTED_PUBLIC_INPUT_HASH, sizeof(EXPECTED_PUBLIC_INPUT_HASH));
    memcpy(real_orchard_proof_v1 + 53, EXPECTED_ORCHARD_REAL_VK_HASH, sizeof(EXPECTED_ORCHARD_REAL_VK_HASH));
    real_orchard_proof_v1[85] = 64;
    real_orchard_proof_v1[86] = 0;
    real_orchard_proof_v1[87] = 0;
    real_orchard_proof_v1[88] = 0;
    memset(real_orchard_proof_v1 + 89, 0x42, 64);

    unsigned char real_orchard_body_v1[177];
    memcpy(real_orchard_body_v1, "zkc-orchard-body-v1", 19);
    real_orchard_body_v1[19] = 1;
    real_orchard_body_v1[20] = 153;
    real_orchard_body_v1[21] = 0;
    real_orchard_body_v1[22] = 0;
    real_orchard_body_v1[23] = 0;
    memcpy(real_orchard_body_v1 + 24, real_orchard_proof_v1, sizeof(real_orchard_proof_v1));

    unsigned char expected_bundle_v4[159];
    memcpy(expected_bundle_v4, "zkc-p4", 6);
    expected_bundle_v4[6] = 1;
    expected_bundle_v4[7] = 1;
    expected_bundle_v4[8] = 1;
    expected_bundle_v4[9] = 0;
    memcpy(expected_bundle_v4 + 10, EXPECTED_PUBLIC_INPUT_HASH, sizeof(EXPECTED_PUBLIC_INPUT_HASH));
    expected_bundle_v4[42] = 113;
    expected_bundle_v4[43] = 0;
    expected_bundle_v4[44] = 0;
    expected_bundle_v4[45] = 0;
    memcpy(expected_bundle_v4 + 46, "zkc-orchard-proof-v1", 20);
    expected_bundle_v4[66] = 1;
    memcpy(expected_bundle_v4 + 67, EXPECTED_PUBLIC_INPUT_HASH, sizeof(EXPECTED_PUBLIC_INPUT_HASH));
    expected_bundle_v4[99] = 56;
    expected_bundle_v4[100] = 0;
    expected_bundle_v4[101] = 0;
    expected_bundle_v4[102] = 0;
    memcpy(expected_bundle_v4 + 103, expected_orchard_body_v1, sizeof(expected_orchard_body_v1));

    unsigned char real_orchard_payload_v1[234];
    memcpy(real_orchard_payload_v1, "zkc-orchard-proof-v1", 20);
    real_orchard_payload_v1[20] = 1;
    memcpy(real_orchard_payload_v1 + 21, EXPECTED_PUBLIC_INPUT_HASH, sizeof(EXPECTED_PUBLIC_INPUT_HASH));
    real_orchard_payload_v1[53] = 177;
    real_orchard_payload_v1[54] = 0;
    real_orchard_payload_v1[55] = 0;
    real_orchard_payload_v1[56] = 0;
    memcpy(real_orchard_payload_v1 + 57, real_orchard_body_v1, sizeof(real_orchard_body_v1));

    unsigned char real_bundle_v4[280];
    memcpy(real_bundle_v4, "zkc-p4", 6);
    real_bundle_v4[6] = 1;
    real_bundle_v4[7] = 1;
    real_bundle_v4[8] = 1;
    real_bundle_v4[9] = 0;
    memcpy(real_bundle_v4 + 10, EXPECTED_PUBLIC_INPUT_HASH, sizeof(EXPECTED_PUBLIC_INPUT_HASH));
    real_bundle_v4[42] = 234;
    real_bundle_v4[43] = 0;
    real_bundle_v4[44] = 0;
    real_bundle_v4[45] = 0;
    memcpy(real_bundle_v4 + 46, real_orchard_payload_v1, sizeof(real_orchard_payload_v1));

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

    if (zkc_shielded_verify_orchard_proof_v1(expected_orchard_body_v1, sizeof(expected_orchard_body_v1), 1, EXPECTED_PUBLIC_INPUT_HASH, sizeof(EXPECTED_PUBLIC_INPUT_HASH)) != 1) {
        return 11;
    }

    if (zkc_shielded_verify_orchard_proof_v1(expected_orchard_body_v1, sizeof(expected_orchard_body_v1), 2, EXPECTED_PUBLIC_INPUT_HASH, sizeof(EXPECTED_PUBLIC_INPUT_HASH)) != 0) {
        return 12;
    }

    if (zkc_shielded_verify_orchard_proof_v1(expected_orchard_body_v1, sizeof(expected_orchard_body_v1) - 1, 1, EXPECTED_PUBLIC_INPUT_HASH, sizeof(EXPECTED_PUBLIC_INPUT_HASH)) != 0) {
        return 13;
    }

    if (zkc_shielded_verify_orchard_real_proof_status_v1(real_orchard_proof_v1, sizeof(real_orchard_proof_v1), 1, EXPECTED_PUBLIC_INPUT_HASH, sizeof(EXPECTED_PUBLIC_INPUT_HASH)) != ZKC_ORCHARD_REAL_PROOF_STATUS_UNSUPPORTED) {
        return 14;
    }

    if (zkc_shielded_verify_orchard_real_proof_status_v1(real_orchard_proof_v1, sizeof(real_orchard_proof_v1), 2, EXPECTED_PUBLIC_INPUT_HASH, sizeof(EXPECTED_PUBLIC_INPUT_HASH)) != ZKC_ORCHARD_REAL_PROOF_STATUS_MALFORMED) {
        return 15;
    }

    if (zkc_shielded_orchard_real_verifier_backend_v1() != ZKC_ORCHARD_REAL_VERIFIER_BACKEND_UNSUPPORTED) {
        return 16;
    }

    if (zkc_shielded_orchard_real_verifier_supports_proofs_v1() != 0) {
        return 17;
    }

    unsigned char request_hash[32];
    if (zkc_shielded_orchard_real_proof_request_hash_v1(real_orchard_proof_v1, sizeof(real_orchard_proof_v1), 1, EXPECTED_PUBLIC_INPUT_HASH, sizeof(EXPECTED_PUBLIC_INPUT_HASH), request_hash, sizeof(request_hash)) != 1) {
        return 18;
    }

    if (memcmp(request_hash, EXPECTED_ORCHARD_REAL_REQUEST_HASH, sizeof(request_hash)) != 0) {
        return 19;
    }

    if (zkc_shielded_orchard_real_proof_request_hash_v1(real_orchard_proof_v1, sizeof(real_orchard_proof_v1), 2, EXPECTED_PUBLIC_INPUT_HASH, sizeof(EXPECTED_PUBLIC_INPUT_HASH), request_hash, sizeof(request_hash)) != 0) {
        return 20;
    }

    if (zkc_shielded_orchard_real_proof_request_hash_v1(real_orchard_proof_v1, sizeof(real_orchard_proof_v1), 1, EXPECTED_PUBLIC_INPUT_HASH, sizeof(EXPECTED_PUBLIC_INPUT_HASH), request_hash, sizeof(request_hash) - 1) != 0) {
        return 21;
    }

    unsigned char verifier_input_hash[32];
    if (zkc_shielded_orchard_real_verifier_input_hash_v1(real_orchard_proof_v1, sizeof(real_orchard_proof_v1), 1, EXPECTED_PUBLIC_INPUT_HASH, sizeof(EXPECTED_PUBLIC_INPUT_HASH), verifier_input_hash, sizeof(verifier_input_hash)) != 1) {
        return 36;
    }

    if (memcmp(verifier_input_hash, EXPECTED_ORCHARD_REAL_VERIFIER_INPUT_HASH, sizeof(verifier_input_hash)) != 0) {
        return 37;
    }

    memset(verifier_input_hash, 0xaa, sizeof(verifier_input_hash));
    if (zkc_shielded_orchard_real_verifier_input_hash_v1(real_orchard_proof_v1, sizeof(real_orchard_proof_v1), 2, EXPECTED_PUBLIC_INPUT_HASH, sizeof(EXPECTED_PUBLIC_INPUT_HASH), verifier_input_hash, sizeof(verifier_input_hash)) != 0) {
        return 38;
    }

    if (memcmp(verifier_input_hash, (unsigned char[32]){0}, sizeof(verifier_input_hash)) != 0) {
        return 39;
    }

    if (zkc_shielded_orchard_real_verifier_input_hash_v1(real_orchard_proof_v1, sizeof(real_orchard_proof_v1), 1, EXPECTED_PUBLIC_INPUT_HASH, sizeof(EXPECTED_PUBLIC_INPUT_HASH), verifier_input_hash, sizeof(verifier_input_hash) - 1) != 0) {
        return 40;
    }

    memset(request_hash, 0xaa, sizeof(request_hash));
    if (zkc_shielded_orchard_real_proof_check_v1(real_orchard_proof_v1, sizeof(real_orchard_proof_v1), 1, EXPECTED_PUBLIC_INPUT_HASH, sizeof(EXPECTED_PUBLIC_INPUT_HASH), request_hash, sizeof(request_hash)) != ZKC_ORCHARD_REAL_PROOF_STATUS_UNSUPPORTED) {
        return 22;
    }

    if (memcmp(request_hash, EXPECTED_ORCHARD_REAL_REQUEST_HASH, sizeof(request_hash)) != 0) {
        return 23;
    }

    if (zkc_shielded_orchard_real_proof_check_v1(real_orchard_proof_v1, sizeof(real_orchard_proof_v1), 2, EXPECTED_PUBLIC_INPUT_HASH, sizeof(EXPECTED_PUBLIC_INPUT_HASH), request_hash, sizeof(request_hash)) != ZKC_ORCHARD_REAL_PROOF_STATUS_MALFORMED) {
        return 24;
    }

    if (memcmp(request_hash, (unsigned char[32]){0}, sizeof(request_hash)) != 0) {
        return 25;
    }

    if (zkc_shielded_verify_orchard_real_proof_v1(real_orchard_proof_v1, sizeof(real_orchard_proof_v1), 1, EXPECTED_PUBLIC_INPUT_HASH, sizeof(EXPECTED_PUBLIC_INPUT_HASH)) != 0) {
        return 26;
    }

    if (zkc_shielded_verify_orchard_proof_v1(real_orchard_body_v1, sizeof(real_orchard_body_v1), 1, EXPECTED_PUBLIC_INPUT_HASH, sizeof(EXPECTED_PUBLIC_INPUT_HASH)) != 0) {
        return 27;
    }

    unsigned char proof_body_mode = ZKC_ORCHARD_PROOF_BODY_MODE_UNKNOWN;
    memset(request_hash, 0xaa, sizeof(request_hash));
    if (zkc_shielded_check_bundle_v4(expected_bundle_v4, sizeof(expected_bundle_v4), 1, EXPECTED_PUBLIC_INPUT_HASH, sizeof(EXPECTED_PUBLIC_INPUT_HASH), &proof_body_mode, request_hash, sizeof(request_hash)) != ZKC_ORCHARD_REAL_PROOF_STATUS_VALID) {
        return 28;
    }

    if (proof_body_mode != ZKC_ORCHARD_PROOF_BODY_MODE_SCAFFOLD) {
        return 29;
    }

    if (memcmp(request_hash, (unsigned char[32]){0}, sizeof(request_hash)) != 0) {
        return 30;
    }

    if (zkc_shielded_check_bundle_v4(real_bundle_v4, sizeof(real_bundle_v4), 1, EXPECTED_PUBLIC_INPUT_HASH, sizeof(EXPECTED_PUBLIC_INPUT_HASH), &proof_body_mode, request_hash, sizeof(request_hash)) != ZKC_ORCHARD_REAL_PROOF_STATUS_UNSUPPORTED) {
        return 31;
    }

    if (proof_body_mode != ZKC_ORCHARD_PROOF_BODY_MODE_REAL) {
        return 32;
    }

    if (memcmp(request_hash, EXPECTED_ORCHARD_REAL_REQUEST_HASH, sizeof(request_hash)) != 0) {
        return 33;
    }

    if (zkc_shielded_check_bundle_v4(real_bundle_v4, sizeof(real_bundle_v4), 2, EXPECTED_PUBLIC_INPUT_HASH, sizeof(EXPECTED_PUBLIC_INPUT_HASH), &proof_body_mode, request_hash, sizeof(request_hash)) != ZKC_ORCHARD_REAL_PROOF_STATUS_MALFORMED) {
        return 34;
    }

    if (proof_body_mode != ZKC_ORCHARD_PROOF_BODY_MODE_UNKNOWN || memcmp(request_hash, (unsigned char[32]){0}, sizeof(request_hash)) != 0) {
        return 35;
    }

    return 0;
}
