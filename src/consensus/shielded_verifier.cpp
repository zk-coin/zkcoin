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
#endif // ZKC_SHIELDED_VERIFIER_EXTERNAL
