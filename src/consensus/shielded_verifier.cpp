// Copyright (c) 2026 The zkCoin developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <consensus/shielded_verifier.h>

#include <hash.h>

#include <algorithm>
#include <vector>

namespace Consensus {
namespace ShieldedPool {

static const std::vector<unsigned char>& ProofEnvelopePreimagePrefixV1()
{
    static const std::vector<unsigned char> prefix{
        'z', 'k', 'c', '-', 'p', 'r', 'o', 'o', 'f', '-', 'e', 'n', 'v', 'e', 'l', 'o', 'p', 'e', '-', 'v', '1'};
    return prefix;
}

static const std::vector<unsigned char>& ProofEnvelopePreimagePrefixV2()
{
    static const std::vector<unsigned char> prefix{
        'z', 'k', 'c', '-', 'p', 'r', 'o', 'o', 'f', '-', 'e', 'n', 'v', 'e', 'l', 'o', 'p', 'e', '-', 'v', '2'};
    return prefix;
}

static const std::vector<unsigned char>& ProofPublicInputPreimagePrefix()
{
    static const std::vector<unsigned char> prefix{
        'z', 'k', 'c', '-', 'p', 'u', 'b', 'l', 'i', 'c', '-', 'i', 'n', 'p', 'u', 't', '-', 'v', '1'};
    return prefix;
}

static const std::vector<unsigned char>& ProofEnvelopePreimagePrefixV3()
{
    static const std::vector<unsigned char> prefix{
        'z', 'k', 'c', '-', 'p', 'r', 'o', 'o', 'f', '-', 'e', 'n', 'v', 'e', 'l', 'o', 'p', 'e', '-', 'v', '3'};
    return prefix;
}

static const std::vector<unsigned char>& ProofBundlePrefixV4()
{
    static const std::vector<unsigned char> prefix{'z', 'k', 'c', '-', 'p', '4'};
    return prefix;
}

static const std::vector<unsigned char>& ProofBundlePreimagePrefixV4()
{
    static const std::vector<unsigned char> prefix{
        'z', 'k', 'c', '-', 'p', 'r', 'o', 'o', 'f', '-', 'b', 'u', 'n', 'd', 'l', 'e', '-', 'v', '4'};
    return prefix;
}

static const std::vector<unsigned char>& OrchardProofPayloadPrefixV1()
{
    static const std::vector<unsigned char> prefix{
        'z', 'k', 'c', '-', 'o', 'r', 'c', 'h', 'a', 'r', 'd', '-', 'p', 'r', 'o', 'o', 'f', '-', 'v', '1'};
    return prefix;
}

static void AppendUint32(std::vector<unsigned char>& payload, uint32_t value)
{
    for (size_t i = 0; i < sizeof(value); ++i) {
        payload.push_back((value >> (8 * i)) & 0xff);
    }
}

uint256 ExpectedProofEnvelopeHash(const uint256& field_hash, const uint256& tx_binding_hash)
{
    std::vector<unsigned char> data = ProofEnvelopePreimagePrefixV1();
    data.insert(data.end(), field_hash.begin(), field_hash.end());
    data.insert(data.end(), tx_binding_hash.begin(), tx_binding_hash.end());
    return Hash(data);
}

uint256 ExpectedProofEnvelopeHashV2(uint8_t proof_kind, const uint256& field_hash, const uint256& tx_binding_hash)
{
    std::vector<unsigned char> data = ProofEnvelopePreimagePrefixV2();
    data.push_back(proof_kind);
    data.insert(data.end(), field_hash.begin(), field_hash.end());
    data.insert(data.end(), tx_binding_hash.begin(), tx_binding_hash.end());
    return Hash(data);
}

uint256 BuildProofPublicInputHash(uint8_t proof_kind, const uint256& field_hash, const uint256& tx_binding_hash)
{
    std::vector<unsigned char> data = ProofPublicInputPreimagePrefix();
    data.push_back(proof_kind);
    data.insert(data.end(), field_hash.begin(), field_hash.end());
    data.insert(data.end(), tx_binding_hash.begin(), tx_binding_hash.end());
    return Hash(data);
}

uint256 ExpectedProofEnvelopeHashV3(uint8_t proof_kind, const uint256& public_input_hash)
{
    std::vector<unsigned char> data = ProofEnvelopePreimagePrefixV3();
    data.push_back(proof_kind);
    data.insert(data.end(), public_input_hash.begin(), public_input_hash.end());
    return Hash(data);
}

std::vector<unsigned char> BuildProofPayloadV1(const uint256& field_hash, const uint256& tx_binding_hash)
{
    const uint256 proof_hash = ExpectedProofEnvelopeHash(field_hash, tx_binding_hash);
    return std::vector<unsigned char>(proof_hash.begin(), proof_hash.end());
}

bool VerifyProofPayloadV1(const std::vector<unsigned char>& proof, const uint256& field_hash, const uint256& tx_binding_hash)
{
    return zkc_shielded_verify_proof_v1(
        proof.data(),
        proof.size(),
        field_hash.begin(),
        SHIELDED_PROOF_HASH_SIZE,
        tx_binding_hash.begin(),
        SHIELDED_PROOF_HASH_SIZE) == 1;
}

std::vector<unsigned char> BuildProofPayloadV2(uint8_t proof_kind, const uint256& field_hash, const uint256& tx_binding_hash)
{
    const uint256 proof_hash = ExpectedProofEnvelopeHashV2(proof_kind, field_hash, tx_binding_hash);
    return std::vector<unsigned char>(proof_hash.begin(), proof_hash.end());
}

bool VerifyProofPayloadV2(const std::vector<unsigned char>& proof, uint8_t proof_kind, const uint256& field_hash, const uint256& tx_binding_hash)
{
    return zkc_shielded_verify_proof_v2(
        proof.data(),
        proof.size(),
        proof_kind,
        field_hash.begin(),
        SHIELDED_PROOF_HASH_SIZE,
        tx_binding_hash.begin(),
        SHIELDED_PROOF_HASH_SIZE) == 1;
}

std::vector<unsigned char> BuildProofPayloadV3(uint8_t proof_kind, const uint256& public_input_hash)
{
    const uint256 proof_hash = ExpectedProofEnvelopeHashV3(proof_kind, public_input_hash);
    return std::vector<unsigned char>(proof_hash.begin(), proof_hash.end());
}

bool VerifyProofPayloadV3(const std::vector<unsigned char>& proof, uint8_t proof_kind, const uint256& public_input_hash)
{
    return zkc_shielded_verify_proof_v3(
        proof.data(),
        proof.size(),
        proof_kind,
        public_input_hash.begin(),
        SHIELDED_PUBLIC_INPUT_HASH_SIZE) == 1;
}

uint256 ExpectedProofBundlePayloadHashV4(uint8_t proof_kind, const uint256& public_input_hash)
{
    std::vector<unsigned char> data = ProofBundlePreimagePrefixV4();
    data.push_back(SHIELDED_PROOF_BUNDLE_VERSION_V4);
    data.push_back(proof_kind);
    data.push_back(SHIELDED_PROOF_SYSTEM_ORCHARD);
    data.push_back(SHIELDED_PROOF_BUNDLE_FLAGS_NONE);
    data.insert(data.end(), public_input_hash.begin(), public_input_hash.end());
    return Hash(data);
}

std::vector<unsigned char> BuildOrchardProofPayloadV1(uint8_t proof_kind, const uint256& public_input_hash)
{
    const uint256 proof_body_hash = ExpectedProofBundlePayloadHashV4(proof_kind, public_input_hash);
    std::vector<unsigned char> proof_payload = OrchardProofPayloadPrefixV1();
    proof_payload.push_back(proof_kind);
    proof_payload.insert(proof_payload.end(), public_input_hash.begin(), public_input_hash.end());
    AppendUint32(proof_payload, SHIELDED_PROOF_HASH_SIZE);
    proof_payload.insert(proof_payload.end(), proof_body_hash.begin(), proof_body_hash.end());
    return proof_payload;
}

bool VerifyOrchardProofPayloadV1(const std::vector<unsigned char>& proof_payload, uint8_t proof_kind, const uint256& public_input_hash)
{
    const auto& prefix = OrchardProofPayloadPrefixV1();
    const size_t kind_offset = prefix.size();
    const size_t public_input_offset = kind_offset + 1;
    const size_t proof_len_offset = public_input_offset + SHIELDED_PUBLIC_INPUT_HASH_SIZE;
    const size_t proof_offset = proof_len_offset + sizeof(uint32_t);
    if (proof_payload.size() < proof_offset) return false;
    if (!std::equal(prefix.begin(), prefix.end(), proof_payload.begin())) return false;
    if (proof_payload[kind_offset] != proof_kind) return false;
    if (!std::equal(public_input_hash.begin(), public_input_hash.end(), proof_payload.begin() + public_input_offset)) return false;

    uint32_t proof_len{0};
    for (size_t i = 0; i < sizeof(proof_len); ++i) {
        proof_len |= uint32_t{proof_payload[proof_len_offset + i]} << (8 * i);
    }
    if (proof_len != proof_payload.size() - proof_offset) return false;

    const uint256 expected_proof_body = ExpectedProofBundlePayloadHashV4(proof_kind, public_input_hash);
    return proof_len == SHIELDED_PROOF_HASH_SIZE &&
           std::equal(expected_proof_body.begin(), expected_proof_body.end(), proof_payload.begin() + proof_offset);
}

std::vector<unsigned char> BuildProofBundleV4(uint8_t proof_kind, const uint256& public_input_hash)
{
    const auto proof_payload = BuildOrchardProofPayloadV1(proof_kind, public_input_hash);
    std::vector<unsigned char> bundle = ProofBundlePrefixV4();
    bundle.push_back(SHIELDED_PROOF_BUNDLE_VERSION_V4);
    bundle.push_back(proof_kind);
    bundle.push_back(SHIELDED_PROOF_SYSTEM_ORCHARD);
    bundle.push_back(SHIELDED_PROOF_BUNDLE_FLAGS_NONE);
    bundle.insert(bundle.end(), public_input_hash.begin(), public_input_hash.end());
    AppendUint32(bundle, static_cast<uint32_t>(proof_payload.size()));
    bundle.insert(bundle.end(), proof_payload.begin(), proof_payload.end());
    return bundle;
}

bool VerifyProofBundleV4(const std::vector<unsigned char>& bundle, uint8_t proof_kind, const uint256& public_input_hash)
{
    return zkc_shielded_verify_bundle_v4(
        bundle.data(),
        bundle.size(),
        proof_kind,
        public_input_hash.begin(),
        SHIELDED_PUBLIC_INPUT_HASH_SIZE) == 1;
}

} // namespace ShieldedPool
} // namespace Consensus

#ifndef ZKC_SHIELDED_VERIFIER_EXTERNAL
extern "C" int zkc_shielded_verify_proof_v1(
    const unsigned char* proof,
    size_t proof_len,
    const unsigned char* field_hash,
    size_t field_hash_len,
    const unsigned char* tx_binding_hash,
    size_t tx_binding_hash_len)
{
    if (proof == nullptr || field_hash == nullptr || tx_binding_hash == nullptr) return 0;
    if (proof_len != Consensus::ShieldedPool::SHIELDED_PROOF_HASH_SIZE) return 0;
    if (field_hash_len != Consensus::ShieldedPool::SHIELDED_PROOF_HASH_SIZE) return 0;
    if (tx_binding_hash_len != Consensus::ShieldedPool::SHIELDED_PROOF_HASH_SIZE) return 0;

    const uint256 field_hash_value(std::vector<unsigned char>(field_hash, field_hash + field_hash_len));
    const uint256 tx_binding_hash_value(std::vector<unsigned char>(tx_binding_hash, tx_binding_hash + tx_binding_hash_len));
    const auto expected = Consensus::ShieldedPool::BuildProofPayloadV1(field_hash_value, tx_binding_hash_value);
    return std::equal(expected.begin(), expected.end(), proof) ? 1 : 0;
}

extern "C" int zkc_shielded_verify_proof_v2(
    const unsigned char* proof,
    size_t proof_len,
    uint8_t proof_kind,
    const unsigned char* field_hash,
    size_t field_hash_len,
    const unsigned char* tx_binding_hash,
    size_t tx_binding_hash_len)
{
    if (proof == nullptr || field_hash == nullptr || tx_binding_hash == nullptr) return 0;
    if (proof_len != Consensus::ShieldedPool::SHIELDED_PROOF_HASH_SIZE) return 0;
    if (field_hash_len != Consensus::ShieldedPool::SHIELDED_PROOF_HASH_SIZE) return 0;
    if (tx_binding_hash_len != Consensus::ShieldedPool::SHIELDED_PROOF_HASH_SIZE) return 0;

    const uint256 field_hash_value(std::vector<unsigned char>(field_hash, field_hash + field_hash_len));
    const uint256 tx_binding_hash_value(std::vector<unsigned char>(tx_binding_hash, tx_binding_hash + tx_binding_hash_len));
    const auto expected = Consensus::ShieldedPool::BuildProofPayloadV2(proof_kind, field_hash_value, tx_binding_hash_value);
    return std::equal(expected.begin(), expected.end(), proof) ? 1 : 0;
}

extern "C" int zkc_shielded_verify_proof_v3(
    const unsigned char* proof,
    size_t proof_len,
    uint8_t proof_kind,
    const unsigned char* public_input_hash,
    size_t public_input_hash_len)
{
    if (proof == nullptr || public_input_hash == nullptr) return 0;
    if (proof_len != Consensus::ShieldedPool::SHIELDED_PROOF_HASH_SIZE) return 0;
    if (public_input_hash_len != Consensus::ShieldedPool::SHIELDED_PUBLIC_INPUT_HASH_SIZE) return 0;

    const uint256 public_input_hash_value(std::vector<unsigned char>(public_input_hash, public_input_hash + public_input_hash_len));
    const auto expected = Consensus::ShieldedPool::BuildProofPayloadV3(proof_kind, public_input_hash_value);
    return std::equal(expected.begin(), expected.end(), proof) ? 1 : 0;
}

extern "C" int zkc_shielded_verify_bundle_v4(
    const unsigned char* bundle,
    size_t bundle_len,
    uint8_t proof_kind,
    const unsigned char* public_input_hash,
    size_t public_input_hash_len)
{
    if (bundle == nullptr || public_input_hash == nullptr) return 0;
    if (public_input_hash_len != Consensus::ShieldedPool::SHIELDED_PUBLIC_INPUT_HASH_SIZE) return 0;

    const uint256 public_input_hash_value(std::vector<unsigned char>(public_input_hash, public_input_hash + public_input_hash_len));
    const auto expected = Consensus::ShieldedPool::BuildProofBundleV4(proof_kind, public_input_hash_value);
    return expected.size() == bundle_len && std::equal(expected.begin(), expected.end(), bundle) ? 1 : 0;
}
#endif // ZKC_SHIELDED_VERIFIER_EXTERNAL
