// Copyright (c) 2026 The zkCoin developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_CONSENSUS_SHIELDED_H
#define BITCOIN_CONSENSUS_SHIELDED_H

#include <amount.h>
#include <consensus/validation.h>
#include <primitives/transaction.h>
#include <script/script.h>

#include <algorithm>
#include <cstdint>
#include <vector>

namespace Consensus {
namespace ShieldedPool {

static constexpr uint8_t ACTION_MINT{0x01};
static constexpr uint8_t ACTION_SPEND{0x02};

inline const std::vector<unsigned char>& MarkerPrefix()
{
    static const std::vector<unsigned char> marker{'z', 'k', 'c', 'o', 'i', 'n', '-', 's', 'h', 'i', 'e', 'l', 'd', 'e', 'd', '-', 'v', '0'};
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
    if (payload.size() != marker.size() + 1) return false;
    const uint8_t action = payload.back();
    return action == ACTION_MINT || action == ACTION_SPEND;
}

inline std::vector<unsigned char> BuildMarkerPayload(uint8_t action)
{
    std::vector<unsigned char> payload = MarkerPrefix();
    payload.push_back(action);
    return payload;
}

inline bool CheckTransaction(const CTransaction& tx, bool active, TxValidationState& state)
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
        if (!IsMarkerPayloadWellFormed(payload)) {
            return state.Invalid(TxValidationResult::TX_CONSENSUS, "bad-shielded-payload");
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
