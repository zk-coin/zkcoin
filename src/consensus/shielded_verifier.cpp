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

static const std::vector<unsigned char>& OrchardProofBodyPrefixV1()
{
    static const std::vector<unsigned char> prefix{
        'z', 'k', 'c', '-', 'o', 'r', 'c', 'h', 'a', 'r', 'd', '-', 'b', 'o', 'd', 'y', '-', 'v', '1'};
    return prefix;
}

static const std::vector<unsigned char>& OrchardRealProofPrefixV1()
{
    static const std::vector<unsigned char> prefix{
        'z', 'k', 'c', '-', 'o', 'r', 'c', 'h', 'a', 'r', 'd', '-', 'r', 'e', 'a', 'l', '-', 'v', '1'};
    return prefix;
}

static const std::vector<unsigned char>& OrchardRealVerifierKeyHashPreimagePrefixV1()
{
    static const std::vector<unsigned char> prefix{
        'z', 'k', 'c', '-', 'o', 'r', 'c', 'h', 'a', 'r', 'd', '-', 'r', 'e', 'a', 'l', '-', 'v', 'k', '-', 'v', '1'};
    return prefix;
}

[[maybe_unused]] static const std::vector<unsigned char>& OrchardRealProofRequestPreimagePrefixV1()
{
    static const std::vector<unsigned char> prefix{
        'z', 'k', 'c', '-', 'o', 'r', 'c', 'h', 'a', 'r', 'd', '-', 'r', 'e', 'a', 'l', '-', 'r', 'e', 'q', 'u', 'e', 's', 't', '-', 'v', '1'};
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

uint256 ExpectedOrchardRealVerifierKeyHashV1()
{
    return Hash(OrchardRealVerifierKeyHashPreimagePrefixV1());
}

std::vector<unsigned char> BuildOrchardRealProofV1(uint8_t proof_kind, const uint256& public_input_hash, const std::vector<unsigned char>& proof_bytes)
{
    const uint256 verifier_key_hash = ExpectedOrchardRealVerifierKeyHashV1();
    std::vector<unsigned char> proof = OrchardRealProofPrefixV1();
    proof.push_back(SHIELDED_PROOF_BUNDLE_FLAGS_NONE);
    proof.push_back(proof_kind);
    proof.insert(proof.end(), public_input_hash.begin(), public_input_hash.end());
    proof.insert(proof.end(), verifier_key_hash.begin(), verifier_key_hash.end());
    AppendUint32(proof, static_cast<uint32_t>(proof_bytes.size()));
    proof.insert(proof.end(), proof_bytes.begin(), proof_bytes.end());
    return proof;
}

bool DecodeOrchardRealProofV1(const std::vector<unsigned char>& proof, uint8_t proof_kind, const uint256& public_input_hash, std::vector<unsigned char>& proof_bytes)
{
    const auto& prefix = OrchardRealProofPrefixV1();
    const size_t flags_offset = prefix.size();
    const size_t kind_offset = flags_offset + 1;
    const size_t public_input_offset = kind_offset + 1;
    const size_t verifier_key_hash_offset = public_input_offset + SHIELDED_PUBLIC_INPUT_HASH_SIZE;
    const size_t proof_len_offset = verifier_key_hash_offset + SHIELDED_PUBLIC_INPUT_HASH_SIZE;
    const size_t proof_offset = proof_len_offset + sizeof(uint32_t);
    if (proof.size() < proof_offset) return false;
    if (!std::equal(prefix.begin(), prefix.end(), proof.begin())) return false;
    if (proof[flags_offset] != SHIELDED_PROOF_BUNDLE_FLAGS_NONE) return false;
    if (proof[kind_offset] != proof_kind) return false;
    if (!std::equal(public_input_hash.begin(), public_input_hash.end(), proof.begin() + public_input_offset)) return false;

    const uint256 verifier_key_hash = ExpectedOrchardRealVerifierKeyHashV1();
    if (!std::equal(verifier_key_hash.begin(), verifier_key_hash.end(), proof.begin() + verifier_key_hash_offset)) return false;

    uint32_t proof_len{0};
    for (size_t i = 0; i < sizeof(proof_len); ++i) {
        proof_len |= uint32_t{proof[proof_len_offset + i]} << (8 * i);
    }
    if (proof_len != proof.size() - proof_offset) return false;

    proof_bytes.assign(proof.begin() + proof_offset, proof.end());
    return true;
}

bool VerifyOrchardRealProofV1(const std::vector<unsigned char>& proof, uint8_t proof_kind, const uint256& public_input_hash)
{
    return zkc_shielded_verify_orchard_real_proof_v1(
        proof.data(),
        proof.size(),
        proof_kind,
        public_input_hash.begin(),
        SHIELDED_PUBLIC_INPUT_HASH_SIZE) == 1;
}

int VerifyOrchardRealProofStatusV1(const std::vector<unsigned char>& proof, uint8_t proof_kind, const uint256& public_input_hash)
{
    return zkc_shielded_verify_orchard_real_proof_status_v1(
        proof.data(),
        proof.size(),
        proof_kind,
        public_input_hash.begin(),
        SHIELDED_PUBLIC_INPUT_HASH_SIZE);
}

bool OrchardRealProofRequestHashV1(const std::vector<unsigned char>& proof, uint8_t proof_kind, const uint256& public_input_hash, uint256& request_hash)
{
    std::vector<unsigned char> request_hash_bytes(SHIELDED_PROOF_HASH_SIZE);
    const int ok = zkc_shielded_orchard_real_proof_request_hash_v1(
        proof.data(),
        proof.size(),
        proof_kind,
        public_input_hash.begin(),
        SHIELDED_PUBLIC_INPUT_HASH_SIZE,
        request_hash_bytes.data(),
        request_hash_bytes.size());
    if (ok != 1) return false;

    std::copy(request_hash_bytes.begin(), request_hash_bytes.end(), request_hash.begin());
    return true;
}

int CheckOrchardRealProofV1(const std::vector<unsigned char>& proof, uint8_t proof_kind, const uint256& public_input_hash, uint256& request_hash)
{
    std::vector<unsigned char> request_hash_bytes(SHIELDED_PROOF_HASH_SIZE);
    const int status = zkc_shielded_orchard_real_proof_check_v1(
        proof.data(),
        proof.size(),
        proof_kind,
        public_input_hash.begin(),
        SHIELDED_PUBLIC_INPUT_HASH_SIZE,
        request_hash_bytes.data(),
        request_hash_bytes.size());
    std::copy(request_hash_bytes.begin(), request_hash_bytes.end(), request_hash.begin());
    return status;
}

int OrchardRealVerifierBackendV1()
{
    return zkc_shielded_orchard_real_verifier_backend_v1();
}

bool OrchardRealVerifierSupportsProofsV1()
{
    return zkc_shielded_orchard_real_verifier_supports_proofs_v1() == 1;
}

const char* OrchardRealVerifierBackendName(int backend)
{
    switch (backend) {
    case SHIELDED_ORCHARD_REAL_VERIFIER_BACKEND_UNSUPPORTED:
        return "unsupported";
    case SHIELDED_ORCHARD_REAL_VERIFIER_BACKEND_ORCHARD_V1:
        return "orchard-v1";
    default:
        return "unknown";
    }
}

bool VerifyOrchardProofBodyV1(const std::vector<unsigned char>& proof_body, uint8_t proof_kind, const uint256& public_input_hash)
{
    return zkc_shielded_verify_orchard_proof_v1(
        proof_body.data(),
        proof_body.size(),
        proof_kind,
        public_input_hash.begin(),
        SHIELDED_PUBLIC_INPUT_HASH_SIZE) == 1;
}

bool DecodeOrchardProofBodyModeV1(const std::vector<unsigned char>& proof_payload, uint8_t proof_kind, const uint256& public_input_hash, uint8_t& proof_body_mode)
{
    const auto& payload_prefix = OrchardProofPayloadPrefixV1();
    const size_t kind_offset = payload_prefix.size();
    const size_t public_input_offset = kind_offset + 1;
    const size_t proof_len_offset = public_input_offset + SHIELDED_PUBLIC_INPUT_HASH_SIZE;
    const size_t proof_offset = proof_len_offset + sizeof(uint32_t);
    if (proof_payload.size() < proof_offset) return false;
    if (!std::equal(payload_prefix.begin(), payload_prefix.end(), proof_payload.begin())) return false;
    if (proof_payload[kind_offset] != proof_kind) return false;
    if (!std::equal(public_input_hash.begin(), public_input_hash.end(), proof_payload.begin() + public_input_offset)) return false;

    uint32_t proof_len{0};
    for (size_t i = 0; i < sizeof(proof_len); ++i) {
        proof_len |= uint32_t{proof_payload[proof_len_offset + i]} << (8 * i);
    }
    if (proof_len != proof_payload.size() - proof_offset) return false;

    const auto& body_prefix = OrchardProofBodyPrefixV1();
    const size_t body_mode_offset = proof_offset + body_prefix.size();
    const size_t body_len_offset = body_mode_offset + 1;
    const size_t body_offset = body_len_offset + sizeof(uint32_t);
    if (proof_payload.size() < body_offset) return false;
    if (!std::equal(body_prefix.begin(), body_prefix.end(), proof_payload.begin() + proof_offset)) return false;

    uint32_t body_len{0};
    for (size_t i = 0; i < sizeof(body_len); ++i) {
        body_len |= uint32_t{proof_payload[body_len_offset + i]} << (8 * i);
    }
    if (body_len != proof_payload.size() - body_offset) return false;

    proof_body_mode = proof_payload[body_mode_offset];
    return true;
}

std::vector<unsigned char> BuildOrchardProofBodyV1(uint8_t proof_kind, const uint256& public_input_hash)
{
    const uint256 scaffold_body = ExpectedProofBundlePayloadHashV4(proof_kind, public_input_hash);
    return BuildOrchardProofBodyV1(
        SHIELDED_ORCHARD_PROOF_BODY_MODE_SCAFFOLD,
        std::vector<unsigned char>(scaffold_body.begin(), scaffold_body.end()));
}

std::vector<unsigned char> BuildOrchardProofBodyV1(uint8_t proof_body_mode, const std::vector<unsigned char>& proof_bytes)
{
    std::vector<unsigned char> proof_body = OrchardProofBodyPrefixV1();
    proof_body.push_back(proof_body_mode);
    AppendUint32(proof_body, static_cast<uint32_t>(proof_bytes.size()));
    proof_body.insert(proof_body.end(), proof_bytes.begin(), proof_bytes.end());
    return proof_body;
}

std::vector<unsigned char> BuildOrchardRealProofBodyV1(const std::vector<unsigned char>& proof_bytes)
{
    return BuildOrchardProofBodyV1(SHIELDED_ORCHARD_PROOF_BODY_MODE_REAL, proof_bytes);
}

std::vector<unsigned char> BuildOrchardRealProofBodyV1(uint8_t proof_kind, const uint256& public_input_hash, const std::vector<unsigned char>& proof_bytes)
{
    return BuildOrchardRealProofBodyV1(BuildOrchardRealProofV1(proof_kind, public_input_hash, proof_bytes));
}

std::vector<unsigned char> BuildOrchardProofPayloadV1(uint8_t proof_kind, const uint256& public_input_hash, const std::vector<unsigned char>& proof_body)
{
    std::vector<unsigned char> proof_payload = OrchardProofPayloadPrefixV1();
    proof_payload.push_back(proof_kind);
    proof_payload.insert(proof_payload.end(), public_input_hash.begin(), public_input_hash.end());
    AppendUint32(proof_payload, static_cast<uint32_t>(proof_body.size()));
    proof_payload.insert(proof_payload.end(), proof_body.begin(), proof_body.end());
    return proof_payload;
}

std::vector<unsigned char> BuildOrchardProofPayloadV1(uint8_t proof_kind, const uint256& public_input_hash)
{
    return BuildOrchardProofPayloadV1(proof_kind, public_input_hash, BuildOrchardProofBodyV1(proof_kind, public_input_hash));
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

    return VerifyOrchardProofBodyV1(
        std::vector<unsigned char>(proof_payload.begin() + proof_offset, proof_payload.end()),
        proof_kind,
        public_input_hash);
}

std::vector<unsigned char> BuildProofBundleV4(uint8_t proof_kind, const uint256& public_input_hash, const std::vector<unsigned char>& proof_payload)
{
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

std::vector<unsigned char> BuildProofBundleV4(uint8_t proof_kind, const uint256& public_input_hash)
{
    return BuildProofBundleV4(proof_kind, public_input_hash, BuildOrchardProofPayloadV1(proof_kind, public_input_hash));
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

int CheckProofBundleV4(const std::vector<unsigned char>& bundle, uint8_t proof_kind, const uint256& public_input_hash, uint8_t& proof_body_mode, uint256& real_request_hash)
{
    std::vector<unsigned char> real_request_hash_bytes(SHIELDED_PROOF_HASH_SIZE);
    proof_body_mode = SHIELDED_ORCHARD_PROOF_BODY_MODE_UNKNOWN;
    const int status = zkc_shielded_check_bundle_v4(
        bundle.data(),
        bundle.size(),
        proof_kind,
        public_input_hash.begin(),
        SHIELDED_PUBLIC_INPUT_HASH_SIZE,
        &proof_body_mode,
        real_request_hash_bytes.data(),
        real_request_hash_bytes.size());
    std::copy(real_request_hash_bytes.begin(), real_request_hash_bytes.end(), real_request_hash.begin());
    return status;
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

extern "C" int zkc_shielded_check_bundle_v4(
    const unsigned char* bundle,
    size_t bundle_len,
    uint8_t proof_kind,
    const unsigned char* public_input_hash,
    size_t public_input_hash_len,
    uint8_t* proof_body_mode_out,
    unsigned char* real_request_hash_out,
    size_t real_request_hash_out_len)
{
    if (proof_body_mode_out == nullptr || real_request_hash_out == nullptr || real_request_hash_out_len != Consensus::ShieldedPool::SHIELDED_PROOF_HASH_SIZE) {
        return Consensus::ShieldedPool::SHIELDED_ORCHARD_REAL_PROOF_STATUS_MALFORMED;
    }
    *proof_body_mode_out = Consensus::ShieldedPool::SHIELDED_ORCHARD_PROOF_BODY_MODE_UNKNOWN;
    std::fill(real_request_hash_out, real_request_hash_out + real_request_hash_out_len, 0);

    if (bundle == nullptr || public_input_hash == nullptr) {
        return Consensus::ShieldedPool::SHIELDED_ORCHARD_REAL_PROOF_STATUS_MALFORMED;
    }
    if (public_input_hash_len != Consensus::ShieldedPool::SHIELDED_PUBLIC_INPUT_HASH_SIZE) {
        return Consensus::ShieldedPool::SHIELDED_ORCHARD_REAL_PROOF_STATUS_MALFORMED;
    }

    const uint256 public_input_hash_value(std::vector<unsigned char>(public_input_hash, public_input_hash + public_input_hash_len));
    const std::vector<unsigned char> bundle_bytes(bundle, bundle + bundle_len);
    const auto& prefix = Consensus::ShieldedPool::ProofBundlePrefixV4();
    const size_t version_offset = prefix.size();
    const size_t kind_offset = version_offset + 1;
    const size_t proof_system_offset = kind_offset + 1;
    const size_t flags_offset = proof_system_offset + 1;
    const size_t public_input_offset = flags_offset + 1;
    const size_t proof_len_offset = public_input_offset + Consensus::ShieldedPool::SHIELDED_PUBLIC_INPUT_HASH_SIZE;
    const size_t proof_offset = proof_len_offset + sizeof(uint32_t);
    if (bundle_bytes.size() < proof_offset) {
        return Consensus::ShieldedPool::SHIELDED_ORCHARD_REAL_PROOF_STATUS_MALFORMED;
    }
    if (!std::equal(prefix.begin(), prefix.end(), bundle_bytes.begin())) {
        return Consensus::ShieldedPool::SHIELDED_ORCHARD_REAL_PROOF_STATUS_MALFORMED;
    }
    if (bundle_bytes[version_offset] != Consensus::ShieldedPool::SHIELDED_PROOF_BUNDLE_VERSION_V4 ||
        bundle_bytes[kind_offset] != proof_kind ||
        bundle_bytes[proof_system_offset] != Consensus::ShieldedPool::SHIELDED_PROOF_SYSTEM_ORCHARD ||
        bundle_bytes[flags_offset] != Consensus::ShieldedPool::SHIELDED_PROOF_BUNDLE_FLAGS_NONE ||
        !std::equal(public_input_hash_value.begin(), public_input_hash_value.end(), bundle_bytes.begin() + public_input_offset)) {
        return Consensus::ShieldedPool::SHIELDED_ORCHARD_REAL_PROOF_STATUS_MALFORMED;
    }

    uint32_t proof_len{0};
    for (size_t i = 0; i < sizeof(proof_len); ++i) {
        proof_len |= uint32_t{bundle_bytes[proof_len_offset + i]} << (8 * i);
    }
    if (proof_len != bundle_bytes.size() - proof_offset) {
        return Consensus::ShieldedPool::SHIELDED_ORCHARD_REAL_PROOF_STATUS_MALFORMED;
    }

    const std::vector<unsigned char> proof_payload(bundle_bytes.begin() + proof_offset, bundle_bytes.end());
    uint8_t proof_body_mode{Consensus::ShieldedPool::SHIELDED_ORCHARD_PROOF_BODY_MODE_UNKNOWN};
    if (!Consensus::ShieldedPool::DecodeOrchardProofBodyModeV1(proof_payload, proof_kind, public_input_hash_value, proof_body_mode)) {
        return Consensus::ShieldedPool::SHIELDED_ORCHARD_REAL_PROOF_STATUS_MALFORMED;
    }
    *proof_body_mode_out = proof_body_mode;

    if (proof_body_mode == Consensus::ShieldedPool::SHIELDED_ORCHARD_PROOF_BODY_MODE_SCAFFOLD) {
        return Consensus::ShieldedPool::VerifyProofBundleV4(bundle_bytes, proof_kind, public_input_hash_value)
            ? Consensus::ShieldedPool::SHIELDED_ORCHARD_REAL_PROOF_STATUS_VALID
            : Consensus::ShieldedPool::SHIELDED_ORCHARD_REAL_PROOF_STATUS_INVALID;
    }
    if (proof_body_mode != Consensus::ShieldedPool::SHIELDED_ORCHARD_PROOF_BODY_MODE_REAL) {
        return Consensus::ShieldedPool::SHIELDED_ORCHARD_REAL_PROOF_STATUS_MALFORMED;
    }

    const size_t payload_proof_offset = Consensus::ShieldedPool::OrchardProofPayloadPrefixV1().size() + 1 + Consensus::ShieldedPool::SHIELDED_PUBLIC_INPUT_HASH_SIZE + sizeof(uint32_t);
    const size_t real_proof_offset = payload_proof_offset + Consensus::ShieldedPool::OrchardProofBodyPrefixV1().size() + 1 + sizeof(uint32_t);
    if (proof_payload.size() < real_proof_offset) {
        return Consensus::ShieldedPool::SHIELDED_ORCHARD_REAL_PROOF_STATUS_MALFORMED;
    }
    return zkc_shielded_orchard_real_proof_check_v1(
        proof_payload.data() + real_proof_offset,
        proof_payload.size() - real_proof_offset,
        proof_kind,
        public_input_hash,
        public_input_hash_len,
        real_request_hash_out,
        real_request_hash_out_len);
}

extern "C" int zkc_shielded_verify_orchard_proof_v1(
    const unsigned char* proof_body,
    size_t proof_body_len,
    uint8_t proof_kind,
    const unsigned char* public_input_hash,
    size_t public_input_hash_len)
{
    if (proof_body == nullptr || public_input_hash == nullptr) return 0;
    if (public_input_hash_len != Consensus::ShieldedPool::SHIELDED_PUBLIC_INPUT_HASH_SIZE) return 0;

    const uint256 public_input_hash_value(std::vector<unsigned char>(public_input_hash, public_input_hash + public_input_hash_len));
    const auto expected = Consensus::ShieldedPool::BuildOrchardProofBodyV1(proof_kind, public_input_hash_value);
    return expected.size() == proof_body_len && std::equal(expected.begin(), expected.end(), proof_body) ? 1 : 0;
}

extern "C" int zkc_shielded_verify_orchard_real_proof_v1(
    const unsigned char* proof,
    size_t proof_len,
    uint8_t proof_kind,
    const unsigned char* public_input_hash,
    size_t public_input_hash_len)
{
    const int status = zkc_shielded_verify_orchard_real_proof_status_v1(
        proof,
        proof_len,
        proof_kind,
        public_input_hash,
        public_input_hash_len);
    return status == Consensus::ShieldedPool::SHIELDED_ORCHARD_REAL_PROOF_STATUS_VALID ? 1 : 0;
}

extern "C" int zkc_shielded_verify_orchard_real_proof_status_v1(
    const unsigned char* proof,
    size_t proof_len,
    uint8_t proof_kind,
    const unsigned char* public_input_hash,
    size_t public_input_hash_len)
{
    if (proof == nullptr || public_input_hash == nullptr) return 0;
    if (public_input_hash_len != Consensus::ShieldedPool::SHIELDED_PUBLIC_INPUT_HASH_SIZE) return 0;

    const uint256 public_input_hash_value(std::vector<unsigned char>(public_input_hash, public_input_hash + public_input_hash_len));
    std::vector<unsigned char> proof_bytes;
    if (!Consensus::ShieldedPool::DecodeOrchardRealProofV1(
            std::vector<unsigned char>(proof, proof + proof_len),
            proof_kind,
            public_input_hash_value,
            proof_bytes)) {
        return Consensus::ShieldedPool::SHIELDED_ORCHARD_REAL_PROOF_STATUS_MALFORMED;
    }

    return Consensus::ShieldedPool::SHIELDED_ORCHARD_REAL_PROOF_STATUS_UNSUPPORTED;
}

extern "C" int zkc_shielded_orchard_real_verifier_backend_v1()
{
    return Consensus::ShieldedPool::SHIELDED_ORCHARD_REAL_VERIFIER_BACKEND_UNSUPPORTED;
}

extern "C" int zkc_shielded_orchard_real_verifier_supports_proofs_v1()
{
    return 0;
}

extern "C" int zkc_shielded_orchard_real_proof_request_hash_v1(
    const unsigned char* proof,
    size_t proof_len,
    uint8_t proof_kind,
    const unsigned char* public_input_hash,
    size_t public_input_hash_len,
    unsigned char* request_hash_out,
    size_t request_hash_out_len)
{
    if (proof == nullptr || public_input_hash == nullptr || request_hash_out == nullptr) return 0;
    if (public_input_hash_len != Consensus::ShieldedPool::SHIELDED_PUBLIC_INPUT_HASH_SIZE) return 0;
    if (request_hash_out_len != Consensus::ShieldedPool::SHIELDED_PROOF_HASH_SIZE) return 0;

    const uint256 public_input_hash_value(std::vector<unsigned char>(public_input_hash, public_input_hash + public_input_hash_len));
    std::vector<unsigned char> proof_bytes;
    if (!Consensus::ShieldedPool::DecodeOrchardRealProofV1(
            std::vector<unsigned char>(proof, proof + proof_len),
            proof_kind,
            public_input_hash_value,
            proof_bytes)) {
        return 0;
    }

    const uint256 verifier_key_hash = Consensus::ShieldedPool::ExpectedOrchardRealVerifierKeyHashV1();
    std::vector<unsigned char> data = Consensus::ShieldedPool::OrchardRealProofRequestPreimagePrefixV1();
    data.push_back(proof_kind);
    data.insert(data.end(), public_input_hash_value.begin(), public_input_hash_value.end());
    data.insert(data.end(), verifier_key_hash.begin(), verifier_key_hash.end());
    Consensus::ShieldedPool::AppendUint32(data, static_cast<uint32_t>(proof_bytes.size()));
    data.insert(data.end(), proof_bytes.begin(), proof_bytes.end());

    const uint256 request_hash = Hash(data);
    std::copy(request_hash.begin(), request_hash.end(), request_hash_out);
    return 1;
}

extern "C" int zkc_shielded_orchard_real_proof_check_v1(
    const unsigned char* proof,
    size_t proof_len,
    uint8_t proof_kind,
    const unsigned char* public_input_hash,
    size_t public_input_hash_len,
    unsigned char* request_hash_out,
    size_t request_hash_out_len)
{
    if (request_hash_out == nullptr || request_hash_out_len != Consensus::ShieldedPool::SHIELDED_PROOF_HASH_SIZE) {
        return Consensus::ShieldedPool::SHIELDED_ORCHARD_REAL_PROOF_STATUS_MALFORMED;
    }
    std::fill(request_hash_out, request_hash_out + request_hash_out_len, 0);

    if (zkc_shielded_orchard_real_proof_request_hash_v1(
            proof,
            proof_len,
            proof_kind,
            public_input_hash,
            public_input_hash_len,
            request_hash_out,
            request_hash_out_len) != 1) {
        return Consensus::ShieldedPool::SHIELDED_ORCHARD_REAL_PROOF_STATUS_MALFORMED;
    }
    return Consensus::ShieldedPool::SHIELDED_ORCHARD_REAL_PROOF_STATUS_UNSUPPORTED;
}
#endif // ZKC_SHIELDED_VERIFIER_EXTERNAL
