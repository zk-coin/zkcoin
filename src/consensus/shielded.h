// Copyright (c) 2026 The zkCoin developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_CONSENSUS_SHIELDED_H
#define BITCOIN_CONSENSUS_SHIELDED_H

#include <amount.h>
#include <consensus/shielded_verifier.h>
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

struct ProofEnvelopeCheck
{
    bool found{false};
    int proof_status{SHIELDED_ORCHARD_REAL_PROOF_STATUS_MALFORMED};
    uint8_t proof_body_mode{SHIELDED_ORCHARD_PROOF_BODY_MODE_UNKNOWN};
    uint256 real_request_hash;
    uint256 real_verifier_input_hash;
    uint256 real_native_proof_hash;

    bool IsAccepted(bool allow_scaffold_proofs) const
    {
        return found &&
            proof_status == SHIELDED_ORCHARD_REAL_PROOF_STATUS_VALID &&
            (allow_scaffold_proofs || proof_body_mode != SHIELDED_ORCHARD_PROOF_BODY_MODE_SCAFFOLD);
    }
};

inline const std::vector<unsigned char>& MarkerPrefix()
{
    // Keep the marker short enough for spend payloads with anchors to stay standard-relay sized.
    static const std::vector<unsigned char> marker{'z', 'k', 'c', '0'};
    return marker;
}

inline const std::vector<unsigned char>& ProofEnvelopePrefix()
{
    static const std::vector<unsigned char> prefix{'z', 'k', 'c', '-', 'p', '4'};
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

inline uint256 TransactionBindingHash(const CTransaction& tx)
{
    return SerializeHash(tx, SER_GETHASH, PROTOCOL_VERSION | SERIALIZE_TRANSACTION_NO_WITNESS | SERIALIZE_NO_MWEB);
}

inline uint256 BuildProofPublicInputHash(const Marker& marker, const CTransaction& tx)
{
    return BuildProofPublicInputHash(marker.action, ExpectedProofHash(marker), TransactionBindingHash(tx));
}

inline std::vector<unsigned char> BuildProofEnvelope(const Marker& marker, const CTransaction& tx)
{
    const uint256 public_input_hash = BuildProofPublicInputHash(marker, tx);
    return BuildProofBundleV4(marker.action, public_input_hash);
}

inline std::vector<unsigned char> BuildRealProofEnvelope(const Marker& marker, const CTransaction& tx, const std::vector<unsigned char>& proof_bytes)
{
    const uint256 public_input_hash = BuildProofPublicInputHash(marker, tx);
    const auto proof_body = BuildOrchardRealProofBodyV1(marker.action, public_input_hash, proof_bytes);
    const auto proof_payload = BuildOrchardProofPayloadV1(marker.action, public_input_hash, proof_body);
    return BuildProofBundleV4(marker.action, public_input_hash, proof_payload);
}

inline bool HasProofEnvelopePrefix(const std::vector<unsigned char>& stack_item)
{
    const auto& prefix = ProofEnvelopePrefix();
    return stack_item.size() >= prefix.size() && std::equal(prefix.begin(), prefix.end(), stack_item.begin());
}

inline bool DecodeProofEnvelope(const std::vector<unsigned char>& stack_item, uint8_t& proof_kind, uint256& public_input_hash, std::vector<unsigned char>& proof_payload)
{
    if (!HasProofEnvelopePrefix(stack_item)) return false;
    const size_t version_offset = ProofEnvelopePrefix().size();
    const size_t proof_kind_offset = version_offset + 1;
    const size_t proof_system_offset = proof_kind_offset + 1;
    const size_t flags_offset = proof_system_offset + 1;
    const size_t public_input_offset = flags_offset + 1;
    const size_t proof_len_offset = public_input_offset + SHIELDED_PUBLIC_INPUT_HASH_SIZE;
    const size_t proof_offset = proof_len_offset + sizeof(uint32_t);
    if (stack_item.size() < proof_offset) return false;
    if (stack_item[version_offset] != SHIELDED_PROOF_BUNDLE_VERSION_V4) return false;
    if (stack_item[proof_system_offset] != SHIELDED_PROOF_SYSTEM_ORCHARD) return false;
    if (stack_item[flags_offset] != SHIELDED_PROOF_BUNDLE_FLAGS_NONE) return false;

    uint32_t proof_len{0};
    for (size_t i = 0; i < sizeof(proof_len); ++i) {
        proof_len |= uint32_t{stack_item[proof_len_offset + i]} << (8 * i);
    }
    if (proof_len != stack_item.size() - proof_offset) return false;

    proof_kind = stack_item[proof_kind_offset];
    public_input_hash = uint256(std::vector<unsigned char>(stack_item.begin() + public_input_offset, stack_item.begin() + proof_len_offset));
    proof_payload.assign(stack_item.begin() + proof_offset, stack_item.end());
    return true;
}

inline bool DecodeProofEnvelopeFromWitnessStack(const std::vector<std::vector<unsigned char>>& stack, size_t proof_index, uint8_t& proof_kind, uint256& public_input_hash, std::vector<unsigned char>& proof_payload, std::vector<unsigned char>& bundle, size_t& consumed_last)
{
    consumed_last = proof_index;
    bundle = stack[proof_index];
    if (DecodeProofEnvelope(bundle, proof_kind, public_input_hash, proof_payload)) {
        return true;
    }

    // Real Orchard proofs are too large for a single P2WSH stack element. The
    // proof-carrying spend uses stack chunks followed by the witnessScript; the
    // transaction binding hash excludes witness data, so reassembly is stable.
    if (proof_index + 2 > stack.size()) return false;
    const size_t chunk_end = stack.size() - 1;
    if (proof_index >= chunk_end) return false;

    bundle.clear();
    for (size_t chunk_index = proof_index; chunk_index < chunk_end; ++chunk_index) {
        bundle.insert(bundle.end(), stack[chunk_index].begin(), stack[chunk_index].end());
    }
    if (!DecodeProofEnvelope(bundle, proof_kind, public_input_hash, proof_payload)) {
        consumed_last = proof_index;
        return false;
    }
    consumed_last = chunk_end - 1;
    return true;
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

inline ProofEnvelopeCheck CheckProofEnvelope(const Marker& marker, const CTransaction& tx)
{
    ProofEnvelopeCheck check;
    if (marker.proof_tag != ExpectedProofTag(marker)) return check;

    const uint256 field_hash = ExpectedProofHash(marker);
    const uint256 tx_binding_hash = TransactionBindingHash(tx);
    const uint256 expected_public_input_hash = BuildProofPublicInputHash(marker.action, field_hash, tx_binding_hash);
    for (const CTxIn& txin : tx.vin) {
        const auto& stack = txin.scriptWitness.stack;
        for (size_t stack_index = 0; stack_index < stack.size(); ++stack_index) {
            const auto& stack_item = stack[stack_index];
            if (!HasProofEnvelopePrefix(stack_item)) continue;
            if (check.found) {
                check.proof_status = SHIELDED_ORCHARD_REAL_PROOF_STATUS_MALFORMED;
                check.proof_body_mode = SHIELDED_ORCHARD_PROOF_BODY_MODE_UNKNOWN;
                check.real_request_hash.SetNull();
                check.real_verifier_input_hash.SetNull();
                check.real_native_proof_hash.SetNull();
                return check;
            }
            check.found = true;
            uint8_t proof_kind{0};
            uint256 public_input_hash;
            std::vector<unsigned char> proof_payload;
            std::vector<unsigned char> proof_bundle;
            size_t consumed_last{stack_index};
            if (!DecodeProofEnvelopeFromWitnessStack(stack, stack_index, proof_kind, public_input_hash, proof_payload, proof_bundle, consumed_last)) {
                check.proof_status = SHIELDED_ORCHARD_REAL_PROOF_STATUS_MALFORMED;
                return check;
            }
            if (proof_kind != marker.action || public_input_hash != expected_public_input_hash) {
                check.proof_status = SHIELDED_ORCHARD_REAL_PROOF_STATUS_MALFORMED;
                return check;
            }
            check.proof_status = CheckProofBundleV6(
                proof_bundle,
                marker.action,
                expected_public_input_hash,
                check.proof_body_mode,
                check.real_request_hash,
                check.real_verifier_input_hash,
                check.real_native_proof_hash);
            stack_index = consumed_last;
        }
    }
    return check;
}

inline bool VerifyProofEnvelope(const Marker& marker, const CTransaction& tx, bool allow_scaffold_proofs)
{
    return CheckProofEnvelope(marker, tx).IsAccepted(allow_scaffold_proofs);
}

inline bool CheckTransaction(const CTransaction& tx, bool active, bool allow_scaffold_proofs, TxValidationState& state, std::vector<Marker>* markers_out = nullptr)
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
        if (!VerifyProofEnvelope(marker, tx, allow_scaffold_proofs)) {
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

inline bool GetTransactionValuePoolDelta(const CTransaction& tx, bool active, bool allow_scaffold_proofs, CAmount& delta, TxValidationState& state)
{
    std::vector<Marker> markers;
    if (!CheckTransaction(tx, active, allow_scaffold_proofs, state, &markers)) return false;

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
