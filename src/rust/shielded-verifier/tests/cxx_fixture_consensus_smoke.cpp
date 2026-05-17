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

    public_input_hash_out = BuildProofPublicInputHash(
        marker.action,
        ExpectedProofHash(marker),
        TransactionBindingHash(tx));
    const auto proof_bytes = BuildFixtureProofBytes(marker.action, public_input_hash_out);
    const auto real_body = BuildOrchardRealProofBodyV1(marker.action, public_input_hash_out, proof_bytes);
    const auto real_payload = BuildOrchardProofPayloadV1(marker.action, public_input_hash_out, real_body);
    return BuildProofBundleV4(marker.action, public_input_hash_out, real_payload);
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

    return 0;
}
