// Copyright (c) 2026 The zkCoin developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <consensus/shielded.h>

#include <primitives/transaction.h>
#include <script/script.h>

#include <string>
#include <vector>

static uint256 Field(unsigned char value)
{
    return uint256(std::vector<unsigned char>(Consensus::ShieldedPool::FIELD_SIZE, value));
}

static CMutableTransaction MutableTransactionWithMarker(const std::vector<unsigned char>& payload)
{
    CMutableTransaction tx;
    tx.vin.resize(1);
    tx.vin[0].prevout = COutPoint(Field(0x52), 0);
    tx.vout.emplace_back(0, CScript() << OP_RETURN << payload);
    return tx;
}

static std::vector<unsigned char> FixtureProofPrefix()
{
    return {'z', 'k', 'c', '-', 'o', 'r', 'c', 'h', 'a', 'r', 'd', '-',
            'f', 'i', 'x', 't', 'u', 'r', 'e', '-', 'p', 'r', 'o', 'o',
            'f', '-', 'v', '1'};
}

static std::vector<unsigned char> BuildFixtureProofBytes(uint8_t proof_kind, const uint256& public_input_hash)
{
    using namespace Consensus::ShieldedPool;

    const auto empty_real_proof = BuildOrchardRealProofV1(proof_kind, public_input_hash, {});
    uint256 verifier_input_hash;
    if (!OrchardRealVerifierInputHashV1(empty_real_proof, proof_kind, public_input_hash, verifier_input_hash)) {
        return {};
    }

    std::vector<unsigned char> proof_bytes = FixtureProofPrefix();
    proof_bytes.insert(proof_bytes.end(), verifier_input_hash.begin(), verifier_input_hash.end());
    return proof_bytes;
}

static std::vector<unsigned char> BuildFixtureProofEnvelope(
    const Consensus::ShieldedPool::Marker& marker,
    const CTransaction& tx,
    uint256& public_input_hash_out)
{
    using namespace Consensus::ShieldedPool;

    public_input_hash_out = BuildProofPublicInputHash(marker, tx);
    const auto proof_bytes = BuildFixtureProofBytes(marker.action, public_input_hash_out);
    return BuildRealProofEnvelope(marker, tx, proof_bytes);
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

    const auto payload = BuildMintPayload(Field(0x21), COIN);
    Marker marker;
    if (!DecodeMarkerPayload(payload, marker)) {
        return 3;
    }

    CMutableTransaction base_tx = MutableTransactionWithMarker(payload);
    uint256 public_input_hash;
    const auto real_envelope = BuildFixtureProofEnvelope(marker, CTransaction(base_tx), public_input_hash);

    uint8_t proof_body_mode{SHIELDED_ORCHARD_PROOF_BODY_MODE_UNKNOWN};
    uint256 real_request_hash;
    uint256 real_verifier_input_hash;
    if (CheckProofBundleV5(
            real_envelope,
            marker.action,
            public_input_hash,
            proof_body_mode,
            real_request_hash,
            real_verifier_input_hash) != SHIELDED_ORCHARD_REAL_PROOF_STATUS_VALID) {
        return 4;
    }
    if (proof_body_mode != SHIELDED_ORCHARD_PROOF_BODY_MODE_REAL) {
        return 5;
    }
    if (real_request_hash.IsNull() || real_verifier_input_hash.IsNull()) {
        return 6;
    }

    CMutableTransaction real_tx = MutableTransactionWithMarker(payload);
    real_tx.vin[0].scriptWitness.stack.push_back(real_envelope);
    TxValidationState real_state;
    if (!CheckTransaction(CTransaction(real_tx), /*active=*/true, /*allow_scaffold_proofs=*/false, real_state)) {
        return 7;
    }

    CAmount mint_delta{0};
    TxValidationState mint_delta_state;
    if (!GetTransactionValuePoolDelta(CTransaction(real_tx), /*active=*/true, /*allow_scaffold_proofs=*/false, mint_delta, mint_delta_state)) {
        return 24;
    }
    if (mint_delta != COIN) {
        return 25;
    }

    CMutableTransaction scaffold_tx = MutableTransactionWithMarker(payload);
    scaffold_tx.vin[0].scriptWitness.stack.push_back(BuildProofEnvelope(marker, CTransaction(scaffold_tx)));
    TxValidationState scaffold_state;
    if (CheckTransaction(CTransaction(scaffold_tx), /*active=*/true, /*allow_scaffold_proofs=*/false, scaffold_state)) {
        return 8;
    }
    if (scaffold_state.GetRejectReason() != "bad-shielded-proof") {
        return 9;
    }

    auto bad_envelope = real_envelope;
    bad_envelope.back() ^= 0x01;
    CMutableTransaction bad_tx = MutableTransactionWithMarker(payload);
    bad_tx.vin[0].scriptWitness.stack.push_back(bad_envelope);
    TxValidationState bad_state;
    if (CheckTransaction(CTransaction(bad_tx), /*active=*/true, /*allow_scaffold_proofs=*/false, bad_state)) {
        return 10;
    }
    if (bad_state.GetRejectReason() != "bad-shielded-proof") {
        return 11;
    }

    const auto spend_payload = BuildSpendPayload(Field(0x31), Field(0x32), COIN);
    Marker spend_marker;
    if (!DecodeMarkerPayload(spend_payload, spend_marker)) {
        return 12;
    }
    if (spend_marker.action != ACTION_SPEND || spend_marker.nullifier.IsNull() || spend_marker.anchor.IsNull()) {
        return 13;
    }

    CMutableTransaction spend_base_tx = MutableTransactionWithMarker(spend_payload);
    uint256 spend_public_input_hash;
    const auto spend_real_envelope = BuildFixtureProofEnvelope(spend_marker, CTransaction(spend_base_tx), spend_public_input_hash);

    proof_body_mode = SHIELDED_ORCHARD_PROOF_BODY_MODE_UNKNOWN;
    real_request_hash.SetNull();
    real_verifier_input_hash.SetNull();
    if (CheckProofBundleV5(
            spend_real_envelope,
            spend_marker.action,
            spend_public_input_hash,
            proof_body_mode,
            real_request_hash,
            real_verifier_input_hash) != SHIELDED_ORCHARD_REAL_PROOF_STATUS_VALID) {
        return 14;
    }
    if (proof_body_mode != SHIELDED_ORCHARD_PROOF_BODY_MODE_REAL) {
        return 15;
    }
    if (real_request_hash.IsNull() || real_verifier_input_hash.IsNull()) {
        return 16;
    }

    CMutableTransaction spend_real_tx = MutableTransactionWithMarker(spend_payload);
    spend_real_tx.vin[0].scriptWitness.stack.push_back(spend_real_envelope);
    TxValidationState spend_real_state;
    if (!CheckTransaction(CTransaction(spend_real_tx), /*active=*/true, /*allow_scaffold_proofs=*/false, spend_real_state)) {
        return 17;
    }

    CAmount spend_delta{0};
    TxValidationState spend_delta_state;
    if (!GetTransactionValuePoolDelta(CTransaction(spend_real_tx), /*active=*/true, /*allow_scaffold_proofs=*/false, spend_delta, spend_delta_state)) {
        return 18;
    }
    if (spend_delta != -COIN) {
        return 19;
    }

    CMutableTransaction spend_scaffold_tx = MutableTransactionWithMarker(spend_payload);
    spend_scaffold_tx.vin[0].scriptWitness.stack.push_back(BuildProofEnvelope(spend_marker, CTransaction(spend_scaffold_tx)));
    TxValidationState spend_scaffold_state;
    if (CheckTransaction(CTransaction(spend_scaffold_tx), /*active=*/true, /*allow_scaffold_proofs=*/false, spend_scaffold_state)) {
        return 20;
    }
    if (spend_scaffold_state.GetRejectReason() != "bad-shielded-proof") {
        return 21;
    }

    auto bad_spend_envelope = spend_real_envelope;
    bad_spend_envelope.back() ^= 0x01;
    CMutableTransaction bad_spend_tx = MutableTransactionWithMarker(spend_payload);
    bad_spend_tx.vin[0].scriptWitness.stack.push_back(bad_spend_envelope);
    TxValidationState bad_spend_state;
    if (CheckTransaction(CTransaction(bad_spend_tx), /*active=*/true, /*allow_scaffold_proofs=*/false, bad_spend_state)) {
        return 22;
    }
    if (bad_spend_state.GetRejectReason() != "bad-shielded-proof") {
        return 23;
    }

    return 0;
}
