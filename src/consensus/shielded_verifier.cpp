// Copyright (c) 2026 The zkCoin developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <consensus/shielded_verifier.h>

#include <hash.h>

#include <algorithm>
#include <vector>

namespace Consensus {
namespace ShieldedPool {

static const std::vector<unsigned char>& ProofEnvelopePreimagePrefix()
{
    static const std::vector<unsigned char> prefix{
        'z', 'k', 'c', '-', 'p', 'r', 'o', 'o', 'f', '-', 'e', 'n', 'v', 'e', 'l', 'o', 'p', 'e', '-', 'v', '1'};
    return prefix;
}

uint256 ExpectedProofEnvelopeHash(const uint256& field_hash, const uint256& tx_binding_hash)
{
    std::vector<unsigned char> data = ProofEnvelopePreimagePrefix();
    data.insert(data.end(), field_hash.begin(), field_hash.end());
    data.insert(data.end(), tx_binding_hash.begin(), tx_binding_hash.end());
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
#endif // ZKC_SHIELDED_VERIFIER_EXTERNAL
