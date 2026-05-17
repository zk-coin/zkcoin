// Copyright (c) 2026 The zkCoin developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_CONSENSUS_SHIELDED_VERIFIER_H
#define BITCOIN_CONSENSUS_SHIELDED_VERIFIER_H

#include <uint256.h>

#include <cstddef>
#include <vector>

extern "C" int zkc_shielded_verify_proof_v1(
    const unsigned char* proof,
    size_t proof_len,
    const unsigned char* field_hash,
    size_t field_hash_len,
    const unsigned char* tx_binding_hash,
    size_t tx_binding_hash_len);

namespace Consensus {
namespace ShieldedPool {

static constexpr size_t SHIELDED_PROOF_HASH_SIZE{32};

uint256 ExpectedProofEnvelopeHash(const uint256& field_hash, const uint256& tx_binding_hash);
std::vector<unsigned char> BuildProofPayloadV1(const uint256& field_hash, const uint256& tx_binding_hash);
bool VerifyProofPayloadV1(const std::vector<unsigned char>& proof, const uint256& field_hash, const uint256& tx_binding_hash);

} // namespace ShieldedPool
} // namespace Consensus

#endif // BITCOIN_CONSENSUS_SHIELDED_VERIFIER_H
