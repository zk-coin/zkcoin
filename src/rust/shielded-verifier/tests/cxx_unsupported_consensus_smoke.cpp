// Copyright (c) 2026 The zkCoin developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <consensus/shielded.h>

#include <primitives/transaction.h>
#include <script/script.h>

#include <vector>

static uint256 Field(unsigned char value)
{
    return uint256(std::vector<unsigned char>(Consensus::ShieldedPool::FIELD_SIZE, value));
}

static CMutableTransaction MutableTransactionWithMarker(const std::vector<unsigned char>& payload)
{
    CMutableTransaction tx;
    tx.vin.resize(1);
    tx.vin[0].prevout = COutPoint(Field(0x42), 0);
    tx.vout.emplace_back(0, CScript() << OP_RETURN << payload);
    return tx;
}

static std::vector<unsigned char> BuildNativeProofEnvelope(
    const Consensus::ShieldedPool::Marker& marker,
    const CTransaction& tx,
    const std::vector<unsigned char>& native_proof_bytes,
    uint256& public_input_hash_out)
{
    using namespace Consensus::ShieldedPool;

    public_input_hash_out = BuildProofPublicInputHash(marker, tx);
    const auto proof_bytes = BuildOrchardNativeProofBytesV1(marker.action, public_input_hash_out, native_proof_bytes);
    return BuildRealProofEnvelope(marker, tx, proof_bytes);
}

static int CheckUnsupportedRealProofPath(const std::vector<unsigned char>& payload, CAmount expected_delta, unsigned char native_byte, int base_error)
{
    using namespace Consensus::ShieldedPool;

    Marker marker;
    if (!DecodeMarkerPayload(payload, marker)) {
        return base_error;
    }

    CMutableTransaction base_tx = MutableTransactionWithMarker(payload);
    const std::vector<unsigned char> native_proof_bytes(192, native_byte);
    uint256 public_input_hash;
    const auto real_envelope = BuildNativeProofEnvelope(marker, CTransaction(base_tx), native_proof_bytes, public_input_hash);
    const uint256 expected_native_proof_hash =
        ExpectedOrchardNativeProofHashV1(marker.action, public_input_hash, native_proof_bytes);

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
            real_native_proof_hash) != SHIELDED_ORCHARD_REAL_PROOF_STATUS_UNSUPPORTED) {
        return base_error + 1;
    }
    if (proof_body_mode != SHIELDED_ORCHARD_PROOF_BODY_MODE_REAL) {
        return base_error + 2;
    }
    if (real_request_hash.IsNull() || real_verifier_input_hash.IsNull() || real_native_proof_hash.IsNull()) {
        return base_error + 3;
    }
    if (real_native_proof_hash != expected_native_proof_hash) {
        return base_error + 4;
    }

    CMutableTransaction real_tx = MutableTransactionWithMarker(payload);
    real_tx.vin[0].scriptWitness.stack.push_back(real_envelope);
    const auto real_envelope_check = CheckProofEnvelope(marker, CTransaction(real_tx));
    if (!real_envelope_check.found ||
        real_envelope_check.proof_status != SHIELDED_ORCHARD_REAL_PROOF_STATUS_UNSUPPORTED ||
        real_envelope_check.proof_body_mode != SHIELDED_ORCHARD_PROOF_BODY_MODE_REAL ||
        real_envelope_check.real_request_hash != real_request_hash ||
        real_envelope_check.real_verifier_input_hash != real_verifier_input_hash ||
        real_envelope_check.real_native_proof_hash != real_native_proof_hash) {
        return base_error + 5;
    }
    if (real_envelope_check.IsAccepted(/*allow_scaffold_proofs=*/true) ||
        real_envelope_check.IsAccepted(/*allow_scaffold_proofs=*/false)) {
        return base_error + 6;
    }

    TxValidationState real_state;
    if (CheckTransaction(CTransaction(real_tx), /*active=*/true, /*allow_scaffold_proofs=*/true, real_state)) {
        return base_error + 7;
    }
    if (real_state.GetRejectReason() != "bad-shielded-proof") {
        return base_error + 8;
    }

    CMutableTransaction scaffold_tx = MutableTransactionWithMarker(payload);
    scaffold_tx.vin[0].scriptWitness.stack.push_back(BuildProofEnvelope(marker, CTransaction(scaffold_tx)));
    TxValidationState scaffold_state;
    if (!CheckTransaction(CTransaction(scaffold_tx), /*active=*/true, /*allow_scaffold_proofs=*/true, scaffold_state)) {
        return base_error + 9;
    }

    CAmount delta{0};
    TxValidationState delta_state;
    if (!GetTransactionValuePoolDelta(CTransaction(scaffold_tx), /*active=*/true, /*allow_scaffold_proofs=*/true, delta, delta_state)) {
        return base_error + 10;
    }
    if (delta != expected_delta) {
        return base_error + 11;
    }

    TxValidationState scaffold_disabled_state;
    if (CheckTransaction(CTransaction(scaffold_tx), /*active=*/true, /*allow_scaffold_proofs=*/false, scaffold_disabled_state)) {
        return base_error + 12;
    }
    if (scaffold_disabled_state.GetRejectReason() != "bad-shielded-proof") {
        return base_error + 13;
    }

    return 0;
}

int main()
{
    using namespace Consensus::ShieldedPool;

    if (OrchardRealVerifierBackendV1() != SHIELDED_ORCHARD_REAL_VERIFIER_BACKEND_UNSUPPORTED) {
        return 1;
    }
    if (OrchardRealVerifierSupportsProofsV1()) {
        return 2;
    }

    const int mint_result = CheckUnsupportedRealProofPath(
        BuildMintPayload(Field(0x21), COIN),
        COIN,
        0x42,
        10);
    if (mint_result != 0) {
        return mint_result;
    }

    const int spend_result = CheckUnsupportedRealProofPath(
        BuildSpendPayload(Field(0x31), Field(0x32), COIN),
        -COIN,
        0x43,
        40);
    if (spend_result != 0) {
        return spend_result;
    }

    return 0;
}
