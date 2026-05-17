// Copyright (c) 2026 The zkCoin developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_CONSENSUS_SHIELDED_H
#define BITCOIN_CONSENSUS_SHIELDED_H

#include <amount.h>
#include <consensus/validation.h>
#include <hash.h>
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
static constexpr size_t VALUE_SIZE{8};
static constexpr size_t PROOF_TAG_SIZE{3};

struct Marker
{
    uint8_t action{0};
    CAmount nValue{0};
    uint256 anchor;
    uint256 commitment;
    uint256 nullifier;
    std::vector<unsigned char> proof_tag;

    bool HasCommitment() const { return action == ACTION_MINT; }
    bool HasNullifier() const { return action == ACTION_SPEND; }
    bool HasAnchor() const { return action == ACTION_SPEND; }
    CAmount ValuePoolDelta() const { return action == ACTION_MINT ? nValue : -nValue; }
};

inline const std::vector<unsigned char>& MarkerPrefix()
{
    // Keep the marker short enough for spend payloads with anchors to stay standard-relay sized.
    static const std::vector<unsigned char> marker{'z', 'k', 'c', '0'};
    return marker;
}

inline const std::vector<unsigned char>& ProofEnvelopePrefix()
{
    static const std::vector<unsigned char> prefix{'z', 'k', 'c', '-', 'p', 'r', 'o', 'o', 'f', '-', 'v', '1'};
    return prefix;
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
        return payload.size() == marker.size() + 1 + VALUE_SIZE + FIELD_SIZE + PROOF_TAG_SIZE;
    }
    if (action == ACTION_SPEND) {
        return payload.size() == marker.size() + 1 + VALUE_SIZE + FIELD_SIZE + FIELD_SIZE + PROOF_TAG_SIZE;
    }
    return false;
}

inline uint64_t ReadUint64Field(const std::vector<unsigned char>& payload, size_t offset)
{
    uint64_t value{0};
    for (size_t i = 0; i < VALUE_SIZE; ++i) {
        value |= uint64_t{payload[offset + i]} << (8 * i);
    }
    return value;
}

inline uint256 ReadUint256Field(const std::vector<unsigned char>& payload, size_t offset)
{
    return uint256(std::vector<unsigned char>(payload.begin() + offset, payload.begin() + offset + FIELD_SIZE));
}

inline void AppendAmount(std::vector<unsigned char>& payload, CAmount amount)
{
    for (size_t i = 0; i < VALUE_SIZE; ++i) {
        payload.push_back((amount >> (8 * i)) & 0xff);
    }
}

inline uint256 AppendCommitmentRoot(const uint256& previous_root, uint64_t position, const uint256& commitment)
{
    std::vector<unsigned char> data{'z', 'k', 'c', '-', 'n', 'o', 't', 'e', '-', 'r', 'o', 'o', 't', '-', 'v', '0'};
    data.insert(data.end(), previous_root.begin(), previous_root.end());
    for (size_t i = 0; i < sizeof(position); ++i) {
        data.push_back((position >> (8 * i)) & 0xff);
    }
    data.insert(data.end(), commitment.begin(), commitment.end());
    return Hash(data);
}

inline std::vector<unsigned char> BuildProofPreimage(const Marker& marker)
{
    std::vector<unsigned char> data{'z', 'k', 'c', '-', 'p', 'r', 'o', 'o', 'f', '-', 'v', '0'};
    data.push_back(marker.action);
    AppendAmount(data, marker.nValue);
    if (marker.action == ACTION_MINT) {
        data.insert(data.end(), marker.commitment.begin(), marker.commitment.end());
    } else if (marker.action == ACTION_SPEND) {
        data.insert(data.end(), marker.nullifier.begin(), marker.nullifier.end());
        data.insert(data.end(), marker.anchor.begin(), marker.anchor.end());
    }
    return data;
}

inline uint256 ExpectedProofHash(const Marker& marker)
{
    return Hash(BuildProofPreimage(marker));
}

inline std::vector<unsigned char> ExpectedProofTag(const Marker& marker)
{
    const uint256 proof_hash = ExpectedProofHash(marker);
    return std::vector<unsigned char>(proof_hash.begin(), proof_hash.begin() + PROOF_TAG_SIZE);
}

inline std::vector<unsigned char> BuildProofEnvelope(const Marker& marker)
{
    const uint256 proof_hash = ExpectedProofHash(marker);
    std::vector<unsigned char> envelope = ProofEnvelopePrefix();
    envelope.insert(envelope.end(), proof_hash.begin(), proof_hash.end());
    return envelope;
}

inline bool HasProofEnvelopePrefix(const std::vector<unsigned char>& stack_item)
{
    const auto& prefix = ProofEnvelopePrefix();
    return stack_item.size() >= prefix.size() && std::equal(prefix.begin(), prefix.end(), stack_item.begin());
}

inline bool DecodeMarkerPayload(const std::vector<unsigned char>& payload, Marker& marker)
{
    if (!IsMarkerPayloadWellFormed(payload)) return false;

    const size_t action_offset = MarkerPrefix().size();
    const size_t value_offset = action_offset + 1;
    const size_t field_offset = value_offset + VALUE_SIZE;
    const uint64_t encoded_value = ReadUint64Field(payload, value_offset);
    if (encoded_value > uint64_t{MAX_MONEY}) return false;

    marker.action = payload[action_offset];
    marker.nValue = static_cast<CAmount>(encoded_value);
    if (marker.action == ACTION_MINT) {
        marker.commitment = ReadUint256Field(payload, field_offset);
        const size_t proof_offset = field_offset + FIELD_SIZE;
        marker.proof_tag.assign(payload.begin() + proof_offset, payload.begin() + proof_offset + PROOF_TAG_SIZE);
        return true;
    }
    if (marker.action == ACTION_SPEND) {
        marker.nullifier = ReadUint256Field(payload, field_offset);
        marker.anchor = ReadUint256Field(payload, field_offset + FIELD_SIZE);
        const size_t proof_offset = field_offset + FIELD_SIZE + FIELD_SIZE;
        marker.proof_tag.assign(payload.begin() + proof_offset, payload.begin() + proof_offset + PROOF_TAG_SIZE);
        return true;
    }

    return false;
}

inline std::vector<unsigned char> BuildMintPayload(const uint256& commitment, CAmount amount)
{
    std::vector<unsigned char> payload = MarkerPrefix();
    payload.push_back(ACTION_MINT);
    AppendAmount(payload, amount);
    payload.insert(payload.end(), commitment.begin(), commitment.end());
    Marker marker;
    marker.action = ACTION_MINT;
    marker.nValue = amount;
    marker.commitment = commitment;
    const auto proof_tag = ExpectedProofTag(marker);
    payload.insert(payload.end(), proof_tag.begin(), proof_tag.end());
    return payload;
}

inline std::vector<unsigned char> BuildSpendPayload(const uint256& nullifier, const uint256& anchor, CAmount amount)
{
    std::vector<unsigned char> payload = MarkerPrefix();
    payload.push_back(ACTION_SPEND);
    AppendAmount(payload, amount);
    payload.insert(payload.end(), nullifier.begin(), nullifier.end());
    payload.insert(payload.end(), anchor.begin(), anchor.end());
    Marker marker;
    marker.action = ACTION_SPEND;
    marker.nValue = amount;
    marker.nullifier = nullifier;
    marker.anchor = anchor;
    const auto proof_tag = ExpectedProofTag(marker);
    payload.insert(payload.end(), proof_tag.begin(), proof_tag.end());
    return payload;
}

inline bool VerifyProofEnvelope(const Marker& marker, const CTransaction& tx)
{
    if (marker.proof_tag != ExpectedProofTag(marker)) return false;

    bool found{false};
    const std::vector<unsigned char> expected = BuildProofEnvelope(marker);
    for (const CTxIn& txin : tx.vin) {
        for (const auto& stack_item : txin.scriptWitness.stack) {
            if (!HasProofEnvelopePrefix(stack_item)) continue;
            if (found) return false;
            found = true;
            if (stack_item != expected) return false;
        }
    }
    return found;
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
        if (!MoneyRange(marker.nValue) || marker.nValue == 0) {
            return state.Invalid(TxValidationResult::TX_CONSENSUS, "bad-shielded-amount");
        }
        if (marker.HasCommitment() && marker.commitment.IsNull()) {
            return state.Invalid(TxValidationResult::TX_CONSENSUS, "bad-shielded-commitment");
        }
        if (marker.HasNullifier() && marker.nullifier.IsNull()) {
            return state.Invalid(TxValidationResult::TX_CONSENSUS, "bad-shielded-nullifier");
        }
        if (marker.HasAnchor() && marker.anchor.IsNull()) {
            return state.Invalid(TxValidationResult::TX_CONSENSUS, "bad-shielded-anchor");
        }
        if (!VerifyProofEnvelope(marker, tx)) {
            return state.Invalid(TxValidationResult::TX_CONSENSUS, "bad-shielded-proof");
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

inline bool GetTransactionValuePoolDelta(const CTransaction& tx, bool active, CAmount& delta, TxValidationState& state)
{
    std::vector<Marker> markers;
    if (!CheckTransaction(tx, active, state, &markers)) return false;

    delta = 0;
    for (const auto& marker : markers) {
        if (marker.action == ACTION_MINT) {
            if (delta > MAX_MONEY - marker.nValue) {
                return state.Invalid(TxValidationResult::TX_CONSENSUS, "bad-shielded-amount");
            }
            delta += marker.nValue;
        } else if (marker.action == ACTION_SPEND) {
            if (delta < -MAX_MONEY + marker.nValue) {
                return state.Invalid(TxValidationResult::TX_CONSENSUS, "bad-shielded-amount");
            }
            delta -= marker.nValue;
        }
    }
    return true;
}

} // namespace ShieldedPool
} // namespace Consensus

#endif // BITCOIN_CONSENSUS_SHIELDED_H
