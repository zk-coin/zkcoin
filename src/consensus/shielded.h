// Copyright (c) 2026 The zkCoin developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_CONSENSUS_SHIELDED_H
#define BITCOIN_CONSENSUS_SHIELDED_H

#include <amount.h>
#include <consensus/validation.h>
#include <primitives/transaction.h>
#include <script/script.h>
#include <uint256.h>

#include <algorithm>
#include <cstdint>
#include <vector>

namespace Consensus {
namespace ShieldedPool {

static constexpr uint8_t ACTION_MINT{0x01};
static constexpr uint8_t ACTION_SPEND{0x02};
static constexpr size_t FIELD_SIZE{32};

struct Marker
{
    uint8_t action{0};
    uint256 commitment;
    uint256 nullifier;

    bool HasCommitment() const { return action == ACTION_MINT || action == ACTION_SPEND; }
    bool HasNullifier() const { return action == ACTION_SPEND; }
};

inline const std::vector<unsigned char>& MarkerPrefix()
{
    // Keep the marker short enough for spend payloads to stay standard-relay sized.
    static const std::vector<unsigned char> marker{'z', 'k', 'c', '-', 's', 'h', 'i', 'e', 'l', 'd', '-', 'v', '0'};
    return marker;
}

inline bool ExtractMarkerPayload(const CScript& script, std::vector<unsigned char>& payload)
{
    CScript::const_iterator pc = script.begin();
    opcodetype opcode;
    if (!script.GetOp(pc, opcode) || opcode != OP_RETURN) return false;
    if (!script.GetOp(pc, opcode, payload)) return false;
    if (pc != script.end()) return false;
    const auto& marker = MarkerPrefix();
    return payload.size() >= marker.size() && std::equal(marker.begin(), marker.end(), payload.begin());
}

inline bool IsMarkerPayloadWellFormed(const std::vector<unsigned char>& payload)
{
    const auto& marker = MarkerPrefix();
    if (payload.size() < marker.size() + 1) return false;
    const uint8_t action = payload[marker.size()];
    if (action == ACTION_MINT) {
        return payload.size() == marker.size() + 1 + FIELD_SIZE;
    }
    if (action == ACTION_SPEND) {
        return payload.size() == marker.size() + 1 + FIELD_SIZE + FIELD_SIZE;
    }
    return false;
}

inline uint256 ReadUint256Field(const std::vector<unsigned char>& payload, size_t offset)
{
    return uint256(std::vector<unsigned char>(payload.begin() + offset, payload.begin() + offset + FIELD_SIZE));
}

inline bool DecodeMarkerPayload(const std::vector<unsigned char>& payload, Marker& marker)
{
    if (!IsMarkerPayloadWellFormed(payload)) return false;

    const size_t action_offset = MarkerPrefix().size();
    marker.action = payload[action_offset];
    if (marker.action == ACTION_MINT) {
        marker.commitment = ReadUint256Field(payload, action_offset + 1);
        return true;
    }
    if (marker.action == ACTION_SPEND) {
        marker.nullifier = ReadUint256Field(payload, action_offset + 1);
        marker.commitment = ReadUint256Field(payload, action_offset + 1 + FIELD_SIZE);
        return true;
    }

    return false;
}

inline std::vector<unsigned char> BuildMintPayload(const uint256& commitment)
{
    std::vector<unsigned char> payload = MarkerPrefix();
    payload.push_back(ACTION_MINT);
    payload.insert(payload.end(), commitment.begin(), commitment.end());
    return payload;
}

inline std::vector<unsigned char> BuildSpendPayload(const uint256& nullifier, const uint256& commitment)
{
    std::vector<unsigned char> payload = MarkerPrefix();
    payload.push_back(ACTION_SPEND);
    payload.insert(payload.end(), nullifier.begin(), nullifier.end());
    payload.insert(payload.end(), commitment.begin(), commitment.end());
    return payload;
}

inline bool CheckTransaction(const CTransaction& tx, bool active, TxValidationState& state, std::vector<Marker>* markers_out = nullptr)
{
    size_t marker_outputs{0};
    for (const CTxOut& txout : tx.vout) {
        std::vector<unsigned char> payload;
        if (!ExtractMarkerPayload(txout.scriptPubKey, payload)) continue;

        ++marker_outputs;
        if (!active) {
            return state.Invalid(TxValidationResult::TX_CONSENSUS, "bad-shielded-before-activation");
        }
        if (tx.IsCoinBase()) {
            return state.Invalid(TxValidationResult::TX_CONSENSUS, "bad-shielded-coinbase");
        }
        if (txout.nValue != 0) {
            return state.Invalid(TxValidationResult::TX_CONSENSUS, "bad-shielded-value");
        }
        Marker marker;
        if (!DecodeMarkerPayload(payload, marker)) {
            return state.Invalid(TxValidationResult::TX_CONSENSUS, "bad-shielded-payload");
        }
        if (marker.HasCommitment() && marker.commitment.IsNull()) {
            return state.Invalid(TxValidationResult::TX_CONSENSUS, "bad-shielded-commitment");
        }
        if (marker.HasNullifier() && marker.nullifier.IsNull()) {
            return state.Invalid(TxValidationResult::TX_CONSENSUS, "bad-shielded-nullifier");
        }
        if (markers_out) {
            markers_out->push_back(marker);
        }
    }

    if (marker_outputs > 1) {
        return state.Invalid(TxValidationResult::TX_CONSENSUS, "bad-shielded-duplicate");
    }

    return true;
}

} // namespace ShieldedPool
} // namespace Consensus

#endif // BITCOIN_CONSENSUS_SHIELDED_H
