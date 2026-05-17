// Copyright (c) 2026 The zkCoin developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_CONSENSUS_SHIELDED_VERIFIER_H
#define BITCOIN_CONSENSUS_SHIELDED_VERIFIER_H

#include <uint256.h>

#include <cstddef>
#include <cstdint>
#include <vector>

extern "C" int zkc_shielded_verify_proof_v1(
    const unsigned char* proof,
    size_t proof_len,
    const unsigned char* field_hash,
    size_t field_hash_len,
    const unsigned char* tx_binding_hash,
    size_t tx_binding_hash_len);

extern "C" int zkc_shielded_verify_proof_v2(
    const unsigned char* proof,
    size_t proof_len,
    uint8_t proof_kind,
    const unsigned char* field_hash,
    size_t field_hash_len,
    const unsigned char* tx_binding_hash,
    size_t tx_binding_hash_len);

extern "C" int zkc_shielded_verify_proof_v3(
    const unsigned char* proof,
    size_t proof_len,
    uint8_t proof_kind,
    const unsigned char* public_input_hash,
    size_t public_input_hash_len);

extern "C" int zkc_shielded_verify_bundle_v4(
    const unsigned char* bundle,
    size_t bundle_len,
    uint8_t proof_kind,
    const unsigned char* public_input_hash,
    size_t public_input_hash_len);

extern "C" int zkc_shielded_verify_orchard_proof_v1(
    const unsigned char* proof_body,
    size_t proof_body_len,
    uint8_t proof_kind,
    const unsigned char* public_input_hash,
    size_t public_input_hash_len);

namespace Consensus {
namespace ShieldedPool {

static constexpr size_t SHIELDED_PROOF_HASH_SIZE{32};
static constexpr size_t SHIELDED_PUBLIC_INPUT_HASH_SIZE{32};
static constexpr uint8_t SHIELDED_PROOF_BUNDLE_VERSION_V4{1};
static constexpr uint8_t SHIELDED_PROOF_SYSTEM_ORCHARD{1};
static constexpr uint8_t SHIELDED_PROOF_BUNDLE_FLAGS_NONE{0};
static constexpr uint8_t SHIELDED_ORCHARD_PROOF_BODY_MODE_SCAFFOLD{0};
static constexpr uint8_t SHIELDED_ORCHARD_PROOF_BODY_MODE_REAL{1};

uint256 ExpectedProofEnvelopeHash(const uint256& field_hash, const uint256& tx_binding_hash);
std::vector<unsigned char> BuildProofPayloadV1(const uint256& field_hash, const uint256& tx_binding_hash);
bool VerifyProofPayloadV1(const std::vector<unsigned char>& proof, const uint256& field_hash, const uint256& tx_binding_hash);
uint256 ExpectedProofEnvelopeHashV2(uint8_t proof_kind, const uint256& field_hash, const uint256& tx_binding_hash);
std::vector<unsigned char> BuildProofPayloadV2(uint8_t proof_kind, const uint256& field_hash, const uint256& tx_binding_hash);
bool VerifyProofPayloadV2(const std::vector<unsigned char>& proof, uint8_t proof_kind, const uint256& field_hash, const uint256& tx_binding_hash);
uint256 BuildProofPublicInputHash(uint8_t proof_kind, const uint256& field_hash, const uint256& tx_binding_hash);
uint256 ExpectedProofEnvelopeHashV3(uint8_t proof_kind, const uint256& public_input_hash);
std::vector<unsigned char> BuildProofPayloadV3(uint8_t proof_kind, const uint256& public_input_hash);
bool VerifyProofPayloadV3(const std::vector<unsigned char>& proof, uint8_t proof_kind, const uint256& public_input_hash);
uint256 ExpectedProofBundlePayloadHashV4(uint8_t proof_kind, const uint256& public_input_hash);
std::vector<unsigned char> BuildOrchardProofBodyV1(uint8_t proof_body_mode, const std::vector<unsigned char>& proof_bytes);
std::vector<unsigned char> BuildOrchardProofBodyV1(uint8_t proof_kind, const uint256& public_input_hash);
std::vector<unsigned char> BuildOrchardRealProofBodyV1(const std::vector<unsigned char>& proof_bytes);
bool VerifyOrchardProofBodyV1(const std::vector<unsigned char>& proof_body, uint8_t proof_kind, const uint256& public_input_hash);
bool DecodeOrchardProofBodyModeV1(const std::vector<unsigned char>& proof_payload, uint8_t proof_kind, const uint256& public_input_hash, uint8_t& proof_body_mode);
std::vector<unsigned char> BuildOrchardProofPayloadV1(uint8_t proof_kind, const uint256& public_input_hash, const std::vector<unsigned char>& proof_body);
std::vector<unsigned char> BuildOrchardProofPayloadV1(uint8_t proof_kind, const uint256& public_input_hash);
bool VerifyOrchardProofPayloadV1(const std::vector<unsigned char>& proof_payload, uint8_t proof_kind, const uint256& public_input_hash);
std::vector<unsigned char> BuildProofBundleV4(uint8_t proof_kind, const uint256& public_input_hash, const std::vector<unsigned char>& proof_payload);
std::vector<unsigned char> BuildProofBundleV4(uint8_t proof_kind, const uint256& public_input_hash);
bool VerifyProofBundleV4(const std::vector<unsigned char>& bundle, uint8_t proof_kind, const uint256& public_input_hash);

} // namespace ShieldedPool
} // namespace Consensus

#endif // BITCOIN_CONSENSUS_SHIELDED_VERIFIER_H
