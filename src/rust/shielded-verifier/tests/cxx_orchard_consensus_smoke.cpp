// Copyright (c) 2026 The zkCoin developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <consensus/shielded.h>

#include <primitives/transaction.h>
#include <script/script.h>

#include <algorithm>
#include <cctype>
#include <fstream>
#include <map>
#include <stdexcept>
#include <string>
#include <vector>

static std::vector<unsigned char> HexToBytes(const std::string& hex)
{
    if (hex.size() % 2 != 0) {
        throw std::runtime_error("hex string has odd length");
    }

    auto hex_value = [](char c) -> unsigned char {
        if (c >= '0' && c <= '9') return c - '0';
        if (c >= 'a' && c <= 'f') return c - 'a' + 10;
        if (c >= 'A' && c <= 'F') return c - 'A' + 10;
        throw std::runtime_error("invalid hex character");
    };

    std::vector<unsigned char> bytes;
    bytes.reserve(hex.size() / 2);
    for (size_t i = 0; i < hex.size(); i += 2) {
        bytes.push_back((hex_value(hex[i]) << 4) | hex_value(hex[i + 1]));
    }
    return bytes;
}

static uint256 HashFromHex(const std::string& hex)
{
    const auto bytes = HexToBytes(hex);
    if (bytes.size() != Consensus::ShieldedPool::FIELD_SIZE) {
        throw std::runtime_error("field hex is not 32 bytes");
    }
    return uint256(bytes);
}

static std::map<std::string, std::string> ReadVector(const std::string& path)
{
    std::ifstream input(path);
    if (!input) {
        throw std::runtime_error("could not open vector file");
    }

    std::map<std::string, std::string> values;
    std::string line;
    while (std::getline(input, line)) {
        if (line.empty() || line[0] == '#') continue;
        const size_t separator = line.find('=');
        if (separator == std::string::npos) {
            throw std::runtime_error("invalid vector line");
        }
        values.emplace(line.substr(0, separator), line.substr(separator + 1));
    }
    return values;
}

static uint64_t ReadU64(const std::map<std::string, std::string>& values, const std::string& key)
{
    const auto iter = values.find(key);
    if (iter == values.end()) {
        throw std::runtime_error("missing vector integer");
    }
    return std::stoull(iter->second);
}

static std::vector<unsigned char> ReadBytes(const std::map<std::string, std::string>& values, const std::string& key)
{
    const auto iter = values.find(key);
    if (iter == values.end()) {
        throw std::runtime_error("missing vector bytes");
    }
    return HexToBytes(iter->second);
}

static uint256 ReadHash(const std::map<std::string, std::string>& values, const std::string& key)
{
    const auto iter = values.find(key);
    if (iter == values.end()) {
        throw std::runtime_error("missing vector field");
    }
    return HashFromHex(iter->second);
}

static void AppendU32(std::vector<unsigned char>& out, uint32_t value)
{
    for (size_t i = 0; i < sizeof(value); ++i) {
        out.push_back((value >> (8 * i)) & 0xff);
    }
}

static void AppendU64(std::vector<unsigned char>& out, uint64_t value)
{
    for (size_t i = 0; i < sizeof(value); ++i) {
        out.push_back((value >> (8 * i)) & 0xff);
    }
}

static void AppendField(std::vector<unsigned char>& out, const uint256& value)
{
    out.insert(out.end(), value.begin(), value.end());
}

struct OrchardActionVector
{
    uint256 anchor;
    uint256 cv_net;
    uint256 nf_old;
    uint256 rk;
    uint256 cmx;
};

static std::vector<unsigned char> BuildHalo2BundleNativePayload(
    uint8_t action,
    uint32_t marker_action_index,
    uint64_t shielded_value,
    const uint256& tx_binding_hash,
    bool enable_spend,
    bool enable_output,
    const std::vector<OrchardActionVector>& actions,
    const std::vector<unsigned char>& proof)
{
    static const std::vector<unsigned char> prefix{
        'z', 'k', 'c', '-', 'o', 'r', 'c', 'h', 'a', 'r', 'd', '-',
        'h', 'a', 'l', 'o', '2', '-', 'b', 'u', 'n', 'd', 'l', 'e',
        '-', 'v', '1'};

    std::vector<unsigned char> payload;
    payload.reserve(prefix.size() + 1 + 4 + 4 + 8 + 32 + 2 + actions.size() * 160 + 4 + proof.size());
    payload.insert(payload.end(), prefix.begin(), prefix.end());
    payload.push_back(action);
    AppendU32(payload, static_cast<uint32_t>(actions.size()));
    AppendU32(payload, marker_action_index);
    AppendU64(payload, shielded_value);
    AppendField(payload, tx_binding_hash);
    payload.push_back(enable_spend ? 1 : 0);
    payload.push_back(enable_output ? 1 : 0);
    for (const auto& proof_action : actions) {
        AppendField(payload, proof_action.anchor);
        AppendField(payload, proof_action.cv_net);
        AppendField(payload, proof_action.nf_old);
        AppendField(payload, proof_action.rk);
        AppendField(payload, proof_action.cmx);
    }
    AppendU32(payload, static_cast<uint32_t>(proof.size()));
    payload.insert(payload.end(), proof.begin(), proof.end());
    return payload;
}

static CMutableTransaction MutableTransactionWithMarker(const std::vector<unsigned char>& payload)
{
    CMutableTransaction tx;
    tx.vin.resize(1);
    tx.vin[0].prevout = COutPoint(uint256(std::vector<unsigned char>(Consensus::ShieldedPool::FIELD_SIZE, 0x72)), 0);
    tx.vout.emplace_back(0, CScript() << OP_RETURN << payload);
    return tx;
}

int main()
{
    using namespace Consensus::ShieldedPool;

    if (OrchardRealVerifierBackendV1() != SHIELDED_ORCHARD_REAL_VERIFIER_BACKEND_ORCHARD_V1) {
        return 1;
    }
    if (!OrchardRealVerifierSupportsProofsV1()) {
        return 2;
    }

    const auto vector = ReadVector("tests/vectors/orchard_mint_vector.txt");
    const uint64_t shielded_value = ReadU64(vector, "shielded_value");
    if (shielded_value != COIN) {
        return 3;
    }
    const uint32_t marker_action_index = static_cast<uint32_t>(ReadU64(vector, "marker_action_index"));
    if (marker_action_index != 0) {
        return 4;
    }
    const uint64_t action_count = ReadU64(vector, "action_count");
    if (action_count != 2) {
        return 5;
    }

    std::vector<OrchardActionVector> actions;
    actions.reserve(action_count);
    const uint256 anchor = ReadHash(vector, "anchor");
    for (uint64_t i = 0; i < action_count; ++i) {
        const std::string prefix = "action" + std::to_string(i) + ".";
        actions.push_back(OrchardActionVector{
            anchor,
            ReadHash(vector, prefix + "cv_net"),
            ReadHash(vector, prefix + "nf_old"),
            ReadHash(vector, prefix + "rk"),
            ReadHash(vector, prefix + "cmx")});
    }
    const auto proof = ReadBytes(vector, "proof");
    if (proof.size() != 7264) {
        return 6;
    }

    const uint256 marker_commitment = actions[marker_action_index].cmx;
    const auto payload = BuildMintPayload(marker_commitment, COIN);
    Marker marker;
    if (!DecodeMarkerPayload(payload, marker)) {
        return 7;
    }

    CMutableTransaction base_tx = MutableTransactionWithMarker(payload);
    const CTransaction base_context_tx(base_tx);
    const uint256 public_input_hash = BuildProofPublicInputHash(marker, base_context_tx);
    const uint256 tx_binding_hash = TransactionBindingHash(base_context_tx);
    const auto native_payload = BuildHalo2BundleNativePayload(
        marker.action,
        marker_action_index,
        shielded_value,
        tx_binding_hash,
        /*enable_spend=*/false,
        /*enable_output=*/true,
        actions,
        proof);
    const auto native_proof = BuildOrchardNativeProofBytesV1(marker.action, public_input_hash, native_payload);
    const auto real_envelope = BuildRealProofEnvelope(marker, base_context_tx, native_proof);

    uint8_t proof_body_mode{SHIELDED_ORCHARD_PROOF_BODY_MODE_UNKNOWN};
    uint256 real_request_hash;
    uint256 real_verifier_input_hash;
    uint256 real_native_proof_hash;
    if (CheckProofBundleV6(
            real_envelope,
            marker.action,
            public_input_hash,
            proof_body_mode,
            real_request_hash,
            real_verifier_input_hash,
            real_native_proof_hash) != SHIELDED_ORCHARD_REAL_PROOF_STATUS_VALID) {
        return 8;
    }
    if (proof_body_mode != SHIELDED_ORCHARD_PROOF_BODY_MODE_REAL) {
        return 9;
    }
    if (real_request_hash.IsNull() || real_verifier_input_hash.IsNull() || real_native_proof_hash.IsNull()) {
        return 10;
    }

    CMutableTransaction real_tx = MutableTransactionWithMarker(payload);
    real_tx.vin[0].scriptWitness.stack.push_back(real_envelope);
    const auto envelope_check = CheckProofEnvelope(marker, CTransaction(real_tx));
    if (!envelope_check.IsAccepted(/*allow_scaffold_proofs=*/false)) {
        return 11;
    }
    if (envelope_check.proof_body_mode != SHIELDED_ORCHARD_PROOF_BODY_MODE_REAL ||
        envelope_check.real_request_hash != real_request_hash ||
        envelope_check.real_verifier_input_hash != real_verifier_input_hash ||
        envelope_check.real_native_proof_hash != real_native_proof_hash) {
        return 12;
    }

    TxValidationState valid_state;
    if (!CheckTransaction(CTransaction(real_tx), /*active=*/true, /*allow_scaffold_proofs=*/false, valid_state)) {
        return 13;
    }
    CAmount value_pool_delta{0};
    TxValidationState delta_state;
    if (!GetTransactionValuePoolDelta(CTransaction(real_tx), /*active=*/true, /*allow_scaffold_proofs=*/false, value_pool_delta, delta_state)) {
        return 14;
    }
    if (value_pool_delta != COIN) {
        return 15;
    }

    CMutableTransaction scaffold_tx = MutableTransactionWithMarker(payload);
    scaffold_tx.vin[0].scriptWitness.stack.push_back(BuildProofEnvelope(marker, CTransaction(scaffold_tx)));
    TxValidationState scaffold_disabled_state;
    if (CheckTransaction(CTransaction(scaffold_tx), /*active=*/true, /*allow_scaffold_proofs=*/false, scaffold_disabled_state)) {
        return 16;
    }
    if (scaffold_disabled_state.GetRejectReason() != "bad-shielded-proof") {
        return 17;
    }

    auto bad_proof_payload = native_payload;
    bad_proof_payload.back() ^= 0x01;
    const auto bad_native_proof = BuildOrchardNativeProofBytesV1(marker.action, public_input_hash, bad_proof_payload);
    const auto bad_envelope = BuildRealProofEnvelope(marker, base_context_tx, bad_native_proof);
    CMutableTransaction bad_tx = MutableTransactionWithMarker(payload);
    bad_tx.vin[0].scriptWitness.stack.push_back(bad_envelope);
    TxValidationState bad_state;
    if (CheckTransaction(CTransaction(bad_tx), /*active=*/true, /*allow_scaffold_proofs=*/false, bad_state)) {
        return 18;
    }
    if (bad_state.GetRejectReason() != "bad-shielded-proof") {
        return 19;
    }

    const auto wrong_payload = BuildMintPayload(uint256(std::vector<unsigned char>(FIELD_SIZE, 0x33)), COIN);
    Marker wrong_marker;
    if (!DecodeMarkerPayload(wrong_payload, wrong_marker)) {
        return 20;
    }
    CMutableTransaction wrong_tx = MutableTransactionWithMarker(wrong_payload);
    const CTransaction wrong_context_tx(wrong_tx);
    const uint256 wrong_public_input_hash = BuildProofPublicInputHash(wrong_marker, wrong_context_tx);
    const auto wrong_native_payload = BuildHalo2BundleNativePayload(
        wrong_marker.action,
        marker_action_index,
        shielded_value,
        TransactionBindingHash(wrong_context_tx),
        /*enable_spend=*/false,
        /*enable_output=*/true,
        actions,
        proof);
    const auto wrong_native_proof = BuildOrchardNativeProofBytesV1(wrong_marker.action, wrong_public_input_hash, wrong_native_payload);
    wrong_tx.vin[0].scriptWitness.stack.push_back(BuildRealProofEnvelope(wrong_marker, wrong_context_tx, wrong_native_proof));
    TxValidationState wrong_marker_state;
    if (CheckTransaction(CTransaction(wrong_tx), /*active=*/true, /*allow_scaffold_proofs=*/false, wrong_marker_state)) {
        return 21;
    }
    if (wrong_marker_state.GetRejectReason() != "bad-shielded-proof") {
        return 22;
    }

    return 0;
}
