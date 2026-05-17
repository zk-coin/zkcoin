// Copyright (c) 2026 The zkCoin developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <consensus/shielded_verifier.h>

#include <algorithm>
#include <string>
#include <vector>

static uint256 FilledHash(unsigned char value)
{
    uint256 hash;
    std::fill(hash.begin(), hash.end(), value);
    return hash;
}

int main()
{
    static const std::vector<unsigned char> EXPECTED_PROOF{
        0x8d, 0x88, 0xec, 0x0b, 0xaa, 0x50, 0x6b, 0x9d,
        0x0a, 0xdd, 0x03, 0x36, 0x13, 0x74, 0x4b, 0x45,
        0x1f, 0x87, 0xe0, 0xd1, 0x17, 0xe7, 0x5e, 0xe5,
        0xd4, 0x8f, 0x48, 0x89, 0xa0, 0x7e, 0x59, 0x8c,
    };
    static const std::vector<unsigned char> EXPECTED_MINT_PROOF_V2{
        0xae, 0x9b, 0x4e, 0x8b, 0x11, 0x17, 0xc7, 0x69,
        0x37, 0x62, 0x97, 0x1b, 0x55, 0x55, 0xcf, 0xd3,
        0x80, 0xd6, 0xa8, 0x94, 0xe5, 0xd9, 0x16, 0xf4,
        0x4d, 0x2a, 0x99, 0x1c, 0xea, 0xb3, 0x9d, 0xa1,
    };
    static const std::vector<unsigned char> EXPECTED_PUBLIC_INPUT_HASH{
        0x90, 0xd5, 0xa8, 0xbb, 0x82, 0x0b, 0x4f, 0x47,
        0x4e, 0x1a, 0x44, 0x5f, 0x0b, 0x23, 0x03, 0x27,
        0x18, 0xc0, 0x7e, 0xbc, 0x5b, 0x94, 0xec, 0x51,
        0x23, 0x43, 0x63, 0xa0, 0x67, 0x82, 0x6e, 0x31,
    };
    static const std::vector<unsigned char> EXPECTED_MINT_PROOF_V3{
        0x46, 0x50, 0x2b, 0x6c, 0x3c, 0xab, 0xfb, 0xe2,
        0x17, 0x8f, 0xbb, 0x6e, 0x7c, 0xcb, 0x90, 0x14,
        0x45, 0x91, 0xf8, 0xce, 0x03, 0x16, 0xf9, 0x0b,
        0x5c, 0x0e, 0xb6, 0xc1, 0xa6, 0x3f, 0x5b, 0x3a,
    };
    static const std::vector<unsigned char> EXPECTED_MINT_PROOF_V4{
        0xe1, 0x60, 0x23, 0x9b, 0x4c, 0x8b, 0xfc, 0x13,
        0x7c, 0xac, 0xf2, 0x10, 0xd0, 0xea, 0xc3, 0xcb,
        0xc8, 0xe6, 0xfa, 0xd5, 0xff, 0xaa, 0x06, 0xca,
        0xe6, 0x93, 0x1d, 0xb0, 0x34, 0x58, 0xc4, 0x24,
    };
    static const std::vector<unsigned char> EXPECTED_ORCHARD_REAL_VK_HASH{
        0x44, 0x98, 0xa4, 0xda, 0xde, 0xe9, 0x35, 0xcc,
        0x2a, 0x7a, 0xf6, 0x97, 0xc5, 0x7a, 0xc3, 0x55,
        0x93, 0xbf, 0xff, 0x59, 0x71, 0x7f, 0x1b, 0x74,
        0x0f, 0xe2, 0x82, 0xaf, 0xe3, 0xf3, 0x2c, 0xd3,
    };
    static const std::vector<unsigned char> EXPECTED_ORCHARD_REAL_REQUEST_HASH{
        0x7c, 0xc5, 0x1e, 0x6b, 0x21, 0xcf, 0x00, 0x8e,
        0x5e, 0x30, 0x1d, 0x9b, 0xce, 0x8b, 0x2d, 0x42,
        0x55, 0xb8, 0x8e, 0x0c, 0xb5, 0xde, 0x0d, 0x2e,
        0xc5, 0xa0, 0x22, 0xdd, 0x91, 0x85, 0x26, 0x30,
    };
    static const std::vector<unsigned char> EXPECTED_ORCHARD_REAL_VERIFIER_INPUT_HASH{
        0x66, 0xb7, 0xae, 0xc4, 0xde, 0xa3, 0x68, 0x22,
        0xc7, 0xe8, 0xef, 0xaf, 0x4b, 0x21, 0xed, 0xd6,
        0x91, 0x5c, 0x31, 0x91, 0x6a, 0xc8, 0x09, 0x27,
        0x91, 0x50, 0x23, 0x6c, 0xf9, 0x4d, 0x5b, 0xc7,
    };

    const uint256 field_hash = FilledHash(0x11);
    const uint256 tx_binding_hash = FilledHash(0x22);
    const auto built_payload = Consensus::ShieldedPool::BuildProofPayloadV1(field_hash, tx_binding_hash);
    if (built_payload != EXPECTED_PROOF) {
        return 1;
    }

    if (!Consensus::ShieldedPool::VerifyProofPayloadV1(EXPECTED_PROOF, field_hash, tx_binding_hash)) {
        return 2;
    }

    const auto built_payload_v2 = Consensus::ShieldedPool::BuildProofPayloadV2(1, field_hash, tx_binding_hash);
    if (built_payload_v2 != EXPECTED_MINT_PROOF_V2) {
        return 3;
    }

    if (!Consensus::ShieldedPool::VerifyProofPayloadV2(EXPECTED_MINT_PROOF_V2, 1, field_hash, tx_binding_hash)) {
        return 4;
    }

    if (Consensus::ShieldedPool::VerifyProofPayloadV2(EXPECTED_MINT_PROOF_V2, 2, field_hash, tx_binding_hash)) {
        return 5;
    }

    const uint256 public_input_hash = Consensus::ShieldedPool::BuildProofPublicInputHash(1, field_hash, tx_binding_hash);
    if (std::vector<unsigned char>(public_input_hash.begin(), public_input_hash.end()) != EXPECTED_PUBLIC_INPUT_HASH) {
        return 6;
    }

    const auto built_payload_v3 = Consensus::ShieldedPool::BuildProofPayloadV3(1, public_input_hash);
    if (built_payload_v3 != EXPECTED_MINT_PROOF_V3) {
        return 7;
    }

    if (!Consensus::ShieldedPool::VerifyProofPayloadV3(EXPECTED_MINT_PROOF_V3, 1, public_input_hash)) {
        return 8;
    }

    if (Consensus::ShieldedPool::VerifyProofPayloadV3(EXPECTED_MINT_PROOF_V3, 2, public_input_hash)) {
        return 9;
    }

    const uint256 built_payload_v4 = Consensus::ShieldedPool::ExpectedProofBundlePayloadHashV4(1, public_input_hash);
    if (std::vector<unsigned char>(built_payload_v4.begin(), built_payload_v4.end()) != EXPECTED_MINT_PROOF_V4) {
        return 10;
    }

    const uint256 real_vk_hash = Consensus::ShieldedPool::ExpectedOrchardRealVerifierKeyHashV1();
    if (std::vector<unsigned char>(real_vk_hash.begin(), real_vk_hash.end()) != EXPECTED_ORCHARD_REAL_VK_HASH) {
        return 11;
    }

    const auto orchard_body_v1 = Consensus::ShieldedPool::BuildOrchardProofBodyV1(1, public_input_hash);
    const auto orchard_payload_v1 = Consensus::ShieldedPool::BuildOrchardProofPayloadV1(1, public_input_hash);
    if (!Consensus::ShieldedPool::VerifyOrchardProofBodyV1(orchard_body_v1, 1, public_input_hash)) {
        return 12;
    }

    if (Consensus::ShieldedPool::VerifyOrchardProofBodyV1(orchard_body_v1, 2, public_input_hash)) {
        return 13;
    }

    if (Consensus::ShieldedPool::VerifyOrchardProofBodyV1(EXPECTED_MINT_PROOF_V4, 1, public_input_hash)) {
        return 14;
    }

    const std::vector<unsigned char> native_proof_bytes(192, 0x42);
    const std::vector<unsigned char> real_proof_bytes =
        Consensus::ShieldedPool::BuildOrchardNativeProofBytesV1(1, public_input_hash, native_proof_bytes);
    const auto real_proof_v1 = Consensus::ShieldedPool::BuildOrchardRealProofV1(1, public_input_hash, real_proof_bytes);
    std::vector<unsigned char> decoded_real_proof_bytes;
    if (!Consensus::ShieldedPool::DecodeOrchardRealProofV1(real_proof_v1, 1, public_input_hash, decoded_real_proof_bytes)) {
        return 15;
    }

    if (decoded_real_proof_bytes != real_proof_bytes) {
        return 16;
    }

    std::vector<unsigned char> decoded_native_proof_bytes;
    if (!Consensus::ShieldedPool::DecodeOrchardNativeProofBytesV1(decoded_real_proof_bytes, 1, public_input_hash, decoded_native_proof_bytes)) {
        return 74;
    }

    if (decoded_native_proof_bytes != native_proof_bytes) {
        return 75;
    }

    if (Consensus::ShieldedPool::VerifyOrchardRealProofV1(real_proof_v1, 1, public_input_hash)) {
        return 17;
    }

    if (Consensus::ShieldedPool::VerifyOrchardRealProofStatusV1(real_proof_v1, 1, public_input_hash) !=
        Consensus::ShieldedPool::SHIELDED_ORCHARD_REAL_PROOF_STATUS_UNSUPPORTED) {
        return 18;
    }

    if (Consensus::ShieldedPool::OrchardRealVerifierBackendV1() !=
        Consensus::ShieldedPool::SHIELDED_ORCHARD_REAL_VERIFIER_BACKEND_UNSUPPORTED) {
        return 19;
    }

    if (Consensus::ShieldedPool::OrchardRealVerifierSupportsProofsV1()) {
        return 20;
    }

    if (std::string(Consensus::ShieldedPool::OrchardRealVerifierBackendName(
            Consensus::ShieldedPool::SHIELDED_ORCHARD_REAL_VERIFIER_BACKEND_UNSUPPORTED)) != "unsupported") {
        return 21;
    }

    if (std::string(Consensus::ShieldedPool::OrchardRealVerifierBackendName(
            Consensus::ShieldedPool::SHIELDED_ORCHARD_REAL_VERIFIER_BACKEND_ORCHARD_V1)) != "orchard-v1") {
        return 22;
    }

    uint256 request_hash;
    if (!Consensus::ShieldedPool::OrchardRealProofRequestHashV1(real_proof_v1, 1, public_input_hash, request_hash)) {
        return 23;
    }

    if (std::vector<unsigned char>(request_hash.begin(), request_hash.end()) != EXPECTED_ORCHARD_REAL_REQUEST_HASH) {
        return 24;
    }

    if (Consensus::ShieldedPool::OrchardRealProofRequestHashV1(real_proof_v1, 2, public_input_hash, request_hash)) {
        return 25;
    }

    std::vector<unsigned char> request_hash_bytes(Consensus::ShieldedPool::SHIELDED_PROOF_HASH_SIZE);
    if (zkc_shielded_orchard_real_proof_request_hash_v1(
            real_proof_v1.data(),
            real_proof_v1.size(),
            1,
            public_input_hash.begin(),
            Consensus::ShieldedPool::SHIELDED_PUBLIC_INPUT_HASH_SIZE,
            request_hash_bytes.data(),
            request_hash_bytes.size()) != 1) {
        return 26;
    }

    if (request_hash_bytes != EXPECTED_ORCHARD_REAL_REQUEST_HASH) {
        return 27;
    }

    if (zkc_shielded_orchard_real_proof_request_hash_v1(
            real_proof_v1.data(),
            real_proof_v1.size(),
            1,
            public_input_hash.begin(),
            Consensus::ShieldedPool::SHIELDED_PUBLIC_INPUT_HASH_SIZE,
            request_hash_bytes.data(),
            request_hash_bytes.size() - 1) != 0) {
        return 28;
    }

    uint256 verifier_input_hash;
    if (!Consensus::ShieldedPool::OrchardRealVerifierInputHashV1(real_proof_v1, 1, public_input_hash, verifier_input_hash)) {
        return 55;
    }

    if (std::vector<unsigned char>(verifier_input_hash.begin(), verifier_input_hash.end()) != EXPECTED_ORCHARD_REAL_VERIFIER_INPUT_HASH) {
        return 56;
    }

    if (Consensus::ShieldedPool::OrchardRealVerifierInputHashV1(real_proof_v1, 2, public_input_hash, verifier_input_hash)) {
        return 57;
    }

    std::vector<unsigned char> verifier_input_hash_bytes(Consensus::ShieldedPool::SHIELDED_PROOF_HASH_SIZE);
    if (zkc_shielded_orchard_real_verifier_input_hash_v1(
            real_proof_v1.data(),
            real_proof_v1.size(),
            1,
            public_input_hash.begin(),
            Consensus::ShieldedPool::SHIELDED_PUBLIC_INPUT_HASH_SIZE,
            verifier_input_hash_bytes.data(),
            verifier_input_hash_bytes.size()) != 1) {
        return 58;
    }

    if (verifier_input_hash_bytes != EXPECTED_ORCHARD_REAL_VERIFIER_INPUT_HASH) {
        return 59;
    }

    std::fill(verifier_input_hash_bytes.begin(), verifier_input_hash_bytes.end(), 0xaa);
    if (zkc_shielded_orchard_real_verifier_input_hash_v1(
            real_proof_v1.data(),
            real_proof_v1.size(),
            2,
            public_input_hash.begin(),
            Consensus::ShieldedPool::SHIELDED_PUBLIC_INPUT_HASH_SIZE,
            verifier_input_hash_bytes.data(),
            verifier_input_hash_bytes.size()) != 0) {
        return 60;
    }

    if (verifier_input_hash_bytes != std::vector<unsigned char>(Consensus::ShieldedPool::SHIELDED_PROOF_HASH_SIZE)) {
        return 61;
    }

    if (zkc_shielded_orchard_real_verifier_input_hash_v1(
            real_proof_v1.data(),
            real_proof_v1.size(),
            1,
            public_input_hash.begin(),
            Consensus::ShieldedPool::SHIELDED_PUBLIC_INPUT_HASH_SIZE,
            verifier_input_hash_bytes.data(),
            verifier_input_hash_bytes.size() - 1) != 0) {
        return 62;
    }

    std::fill(request_hash_bytes.begin(), request_hash_bytes.end(), 0xaa);
    if (Consensus::ShieldedPool::CheckOrchardRealProofV1(real_proof_v1, 1, public_input_hash, request_hash) !=
        Consensus::ShieldedPool::SHIELDED_ORCHARD_REAL_PROOF_STATUS_UNSUPPORTED) {
        return 29;
    }

    if (std::vector<unsigned char>(request_hash.begin(), request_hash.end()) != EXPECTED_ORCHARD_REAL_REQUEST_HASH) {
        return 30;
    }

    if (Consensus::ShieldedPool::CheckOrchardRealProofV2(real_proof_v1, 1, public_input_hash, request_hash, verifier_input_hash) !=
        Consensus::ShieldedPool::SHIELDED_ORCHARD_REAL_PROOF_STATUS_UNSUPPORTED) {
        return 63;
    }

    if (std::vector<unsigned char>(request_hash.begin(), request_hash.end()) != EXPECTED_ORCHARD_REAL_REQUEST_HASH) {
        return 64;
    }

    if (std::vector<unsigned char>(verifier_input_hash.begin(), verifier_input_hash.end()) != EXPECTED_ORCHARD_REAL_VERIFIER_INPUT_HASH) {
        return 65;
    }

    if (Consensus::ShieldedPool::CheckOrchardRealProofV2(real_proof_v1, 2, public_input_hash, request_hash, verifier_input_hash) !=
        Consensus::ShieldedPool::SHIELDED_ORCHARD_REAL_PROOF_STATUS_MALFORMED) {
        return 66;
    }

    if (!request_hash.IsNull() || !verifier_input_hash.IsNull()) {
        return 67;
    }

    std::fill(verifier_input_hash_bytes.begin(), verifier_input_hash_bytes.end(), 0xaa);
    if (zkc_shielded_orchard_real_proof_check_v2(
            real_proof_v1.data(),
            real_proof_v1.size(),
            1,
            public_input_hash.begin(),
            Consensus::ShieldedPool::SHIELDED_PUBLIC_INPUT_HASH_SIZE,
            request_hash_bytes.data(),
            request_hash_bytes.size(),
            verifier_input_hash_bytes.data(),
            verifier_input_hash_bytes.size()) != Consensus::ShieldedPool::SHIELDED_ORCHARD_REAL_PROOF_STATUS_UNSUPPORTED) {
        return 68;
    }

    if (request_hash_bytes != EXPECTED_ORCHARD_REAL_REQUEST_HASH ||
        verifier_input_hash_bytes != EXPECTED_ORCHARD_REAL_VERIFIER_INPUT_HASH) {
        return 69;
    }

    if (zkc_shielded_orchard_real_proof_check_v1(
            real_proof_v1.data(),
            real_proof_v1.size(),
            1,
            public_input_hash.begin(),
            Consensus::ShieldedPool::SHIELDED_PUBLIC_INPUT_HASH_SIZE,
            request_hash_bytes.data(),
            request_hash_bytes.size()) != Consensus::ShieldedPool::SHIELDED_ORCHARD_REAL_PROOF_STATUS_UNSUPPORTED) {
        return 31;
    }

    if (request_hash_bytes != EXPECTED_ORCHARD_REAL_REQUEST_HASH) {
        return 32;
    }

    if (zkc_shielded_orchard_real_proof_check_v1(
            real_proof_v1.data(),
            real_proof_v1.size(),
            2,
            public_input_hash.begin(),
            Consensus::ShieldedPool::SHIELDED_PUBLIC_INPUT_HASH_SIZE,
            request_hash_bytes.data(),
            request_hash_bytes.size()) != Consensus::ShieldedPool::SHIELDED_ORCHARD_REAL_PROOF_STATUS_MALFORMED) {
        return 33;
    }

    if (request_hash_bytes != std::vector<unsigned char>(Consensus::ShieldedPool::SHIELDED_PROOF_HASH_SIZE)) {
        return 34;
    }

    if (Consensus::ShieldedPool::DecodeOrchardRealProofV1(real_proof_v1, 2, public_input_hash, decoded_real_proof_bytes)) {
        return 35;
    }

    if (Consensus::ShieldedPool::VerifyOrchardRealProofStatusV1(real_proof_v1, 2, public_input_hash) !=
        Consensus::ShieldedPool::SHIELDED_ORCHARD_REAL_PROOF_STATUS_MALFORMED) {
        return 36;
    }

    const auto real_orchard_body_v1 = Consensus::ShieldedPool::BuildOrchardRealProofBodyV1(1, public_input_hash, real_proof_bytes);
    const auto real_orchard_payload_v1 = Consensus::ShieldedPool::BuildOrchardProofPayloadV1(1, public_input_hash, real_orchard_body_v1);
    const auto real_bundle_v4 = Consensus::ShieldedPool::BuildProofBundleV4(1, public_input_hash, real_orchard_payload_v1);
    uint8_t decoded_body_mode{0xff};
    if (!Consensus::ShieldedPool::DecodeOrchardProofBodyModeV1(real_orchard_payload_v1, 1, public_input_hash, decoded_body_mode)) {
        return 37;
    }

    if (decoded_body_mode != Consensus::ShieldedPool::SHIELDED_ORCHARD_PROOF_BODY_MODE_REAL) {
        return 38;
    }

    if (Consensus::ShieldedPool::VerifyOrchardProofBodyV1(real_orchard_body_v1, 1, public_input_hash)) {
        return 39;
    }

    if (Consensus::ShieldedPool::VerifyOrchardProofPayloadV1(real_orchard_payload_v1, 1, public_input_hash)) {
        return 40;
    }

    if (Consensus::ShieldedPool::VerifyProofBundleV4(real_bundle_v4, 1, public_input_hash)) {
        return 41;
    }

    if (!Consensus::ShieldedPool::VerifyOrchardProofPayloadV1(orchard_payload_v1, 1, public_input_hash)) {
        return 42;
    }

    if (Consensus::ShieldedPool::VerifyOrchardProofPayloadV1(orchard_payload_v1, 2, public_input_hash)) {
        return 43;
    }

    const auto built_bundle_v4 = Consensus::ShieldedPool::BuildProofBundleV4(1, public_input_hash);
    if (!Consensus::ShieldedPool::VerifyProofBundleV4(built_bundle_v4, 1, public_input_hash)) {
        return 44;
    }

    if (Consensus::ShieldedPool::VerifyProofBundleV4(built_bundle_v4, 2, public_input_hash)) {
        return 45;
    }

    auto wrong_proof = EXPECTED_PROOF;
    wrong_proof[0] ^= 0x01;
    if (Consensus::ShieldedPool::VerifyProofPayloadV1(wrong_proof, field_hash, tx_binding_hash)) {
        return 46;
    }

    uint8_t checked_body_mode{Consensus::ShieldedPool::SHIELDED_ORCHARD_PROOF_BODY_MODE_UNKNOWN};
    uint256 checked_request_hash;
    if (Consensus::ShieldedPool::CheckProofBundleV4(built_bundle_v4, 1, public_input_hash, checked_body_mode, checked_request_hash) !=
        Consensus::ShieldedPool::SHIELDED_ORCHARD_REAL_PROOF_STATUS_VALID) {
        return 47;
    }

    if (checked_body_mode != Consensus::ShieldedPool::SHIELDED_ORCHARD_PROOF_BODY_MODE_SCAFFOLD) {
        return 48;
    }

    if (!checked_request_hash.IsNull()) {
        return 49;
    }

    if (Consensus::ShieldedPool::CheckProofBundleV4(real_bundle_v4, 1, public_input_hash, checked_body_mode, checked_request_hash) !=
        Consensus::ShieldedPool::SHIELDED_ORCHARD_REAL_PROOF_STATUS_UNSUPPORTED) {
        return 50;
    }

    if (checked_body_mode != Consensus::ShieldedPool::SHIELDED_ORCHARD_PROOF_BODY_MODE_REAL) {
        return 51;
    }

    if (std::vector<unsigned char>(checked_request_hash.begin(), checked_request_hash.end()) != EXPECTED_ORCHARD_REAL_REQUEST_HASH) {
        return 52;
    }

    uint256 checked_verifier_input_hash;
    if (Consensus::ShieldedPool::CheckProofBundleV5(real_bundle_v4, 1, public_input_hash, checked_body_mode, checked_request_hash, checked_verifier_input_hash) !=
        Consensus::ShieldedPool::SHIELDED_ORCHARD_REAL_PROOF_STATUS_UNSUPPORTED) {
        return 70;
    }

    if (checked_body_mode != Consensus::ShieldedPool::SHIELDED_ORCHARD_PROOF_BODY_MODE_REAL) {
        return 71;
    }

    if (std::vector<unsigned char>(checked_request_hash.begin(), checked_request_hash.end()) != EXPECTED_ORCHARD_REAL_REQUEST_HASH) {
        return 72;
    }

    if (std::vector<unsigned char>(checked_verifier_input_hash.begin(), checked_verifier_input_hash.end()) != EXPECTED_ORCHARD_REAL_VERIFIER_INPUT_HASH) {
        return 73;
    }

    if (Consensus::ShieldedPool::CheckProofBundleV4(real_bundle_v4, 2, public_input_hash, checked_body_mode, checked_request_hash) !=
        Consensus::ShieldedPool::SHIELDED_ORCHARD_REAL_PROOF_STATUS_MALFORMED) {
        return 53;
    }

    if (checked_body_mode != Consensus::ShieldedPool::SHIELDED_ORCHARD_PROOF_BODY_MODE_UNKNOWN || !checked_request_hash.IsNull()) {
        return 54;
    }

    return 0;
}
