// Copyright (c) 2026 The zkCoin developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <amount.h>
#include <consensus/shielded.h>
#include <consensus/validation.h>
#include <primitives/transaction.h>
#include <script/script.h>
#include <script/standard.h>
#include <test/util/setup_common.h>
#include <uint256.h>

#include <boost/test/unit_test.hpp>

#include <vector>

BOOST_FIXTURE_TEST_SUITE(shielded_tests, BasicTestingSetup)

static uint256 Field(unsigned char value)
{
    return uint256(std::vector<unsigned char>(Consensus::ShieldedPool::FIELD_SIZE, value));
}

static CMutableTransaction MutableTransactionWithMarker(const std::vector<unsigned char>& payload)
{
    uint256 prevout_hash;
    prevout_hash.SetHex("01");

    CMutableTransaction tx;
    tx.vin.resize(1);
    tx.vin[0].prevout = COutPoint(prevout_hash, 0);
    tx.vout.emplace_back(0, CScript() << OP_RETURN << payload);
    return tx;
}

static CTransaction TransactionWithMarker(const std::vector<unsigned char>& payload)
{
    return CTransaction(MutableTransactionWithMarker(payload));
}

static CTransaction TransactionWithProof(const std::vector<unsigned char>& payload, const std::vector<unsigned char>& proof_envelope)
{
    CMutableTransaction tx = MutableTransactionWithMarker(payload);
    tx.vin[0].scriptWitness.stack.push_back(proof_envelope);
    return CTransaction(tx);
}

static CTransaction TransactionWithProof(const std::vector<unsigned char>& payload, const Consensus::ShieldedPool::Marker& marker)
{
    CMutableTransaction tx = MutableTransactionWithMarker(payload);
    tx.vin[0].scriptWitness.stack.push_back(Consensus::ShieldedPool::BuildProofEnvelope(marker, CTransaction(tx)));
    return CTransaction(tx);
}

BOOST_AUTO_TEST_CASE(proof_tag_is_required_for_mint_markers)
{
    using namespace Consensus::ShieldedPool;

    const auto payload = BuildMintPayload(Field(0x01), COIN);
    BOOST_CHECK_EQUAL(payload.size(), MarkerPrefix().size() + 1 + VALUE_SIZE + FIELD_SIZE + PROOF_TAG_SIZE);

    Marker marker;
    BOOST_CHECK(DecodeMarkerPayload(payload, marker));
    BOOST_CHECK_EQUAL(marker.action, ACTION_MINT);
    BOOST_CHECK_EQUAL(marker.nValue, COIN);
    const CTransaction unsigned_tx = TransactionWithMarker(payload);
    BOOST_CHECK_EQUAL(BuildProofEnvelope(marker, unsigned_tx).size(), ProofEnvelopePrefix().size() + 1 + FIELD_SIZE);

    TxValidationState missing_proof_state;
    BOOST_CHECK(!CheckTransaction(unsigned_tx, /*active=*/true, missing_proof_state));
    BOOST_CHECK_EQUAL(missing_proof_state.GetRejectReason(), "bad-shielded-proof");

    TxValidationState valid_state;
    BOOST_CHECK(CheckTransaction(TransactionWithProof(payload, marker), /*active=*/true, valid_state));

    const uint256 field_hash = ExpectedProofHash(marker);
    const uint256 tx_binding_hash = TransactionBindingHash(unsigned_tx);
    const auto proof_payload = BuildProofPayloadV1(field_hash, tx_binding_hash);
    BOOST_CHECK(VerifyProofPayloadV1(proof_payload, field_hash, tx_binding_hash));
    BOOST_CHECK_EQUAL(
        zkc_shielded_verify_proof_v1(
            proof_payload.data(),
            proof_payload.size(),
            field_hash.begin(),
            SHIELDED_PROOF_HASH_SIZE,
            tx_binding_hash.begin(),
            SHIELDED_PROOF_HASH_SIZE),
        1);

    const auto proof_payload_v2 = BuildProofPayloadV2(ACTION_MINT, field_hash, tx_binding_hash);
    BOOST_CHECK(VerifyProofPayloadV2(proof_payload_v2, ACTION_MINT, field_hash, tx_binding_hash));
    BOOST_CHECK(!VerifyProofPayloadV2(proof_payload_v2, ACTION_SPEND, field_hash, tx_binding_hash));
    BOOST_CHECK_EQUAL(
        zkc_shielded_verify_proof_v2(
            proof_payload_v2.data(),
            proof_payload_v2.size(),
            ACTION_MINT,
            field_hash.begin(),
            SHIELDED_PROOF_HASH_SIZE,
            tx_binding_hash.begin(),
            SHIELDED_PROOF_HASH_SIZE),
        1);

    auto short_proof_payload = proof_payload;
    short_proof_payload.pop_back();
    BOOST_CHECK(!VerifyProofPayloadV1(short_proof_payload, field_hash, tx_binding_hash));
    BOOST_CHECK(!VerifyProofPayloadV2(short_proof_payload, ACTION_MINT, field_hash, tx_binding_hash));
    BOOST_CHECK(!VerifyProofPayloadV1(proof_payload, Field(0x04), tx_binding_hash));

    const std::vector<unsigned char> expected_vector{
        0x8d, 0x88, 0xec, 0x0b, 0xaa, 0x50, 0x6b, 0x9d,
        0x0a, 0xdd, 0x03, 0x36, 0x13, 0x74, 0x4b, 0x45,
        0x1f, 0x87, 0xe0, 0xd1, 0x17, 0xe7, 0x5e, 0xe5,
        0xd4, 0x8f, 0x48, 0x89, 0xa0, 0x7e, 0x59, 0x8c};
    const auto vector_payload = BuildProofPayloadV1(Field(0x11), Field(0x22));
    BOOST_CHECK_EQUAL_COLLECTIONS(
        expected_vector.begin(),
        expected_vector.end(),
        vector_payload.begin(),
        vector_payload.end());
    const std::vector<unsigned char> expected_mint_vector_v2{
        0xae, 0x9b, 0x4e, 0x8b, 0x11, 0x17, 0xc7, 0x69,
        0x37, 0x62, 0x97, 0x1b, 0x55, 0x55, 0xcf, 0xd3,
        0x80, 0xd6, 0xa8, 0x94, 0xe5, 0xd9, 0x16, 0xf4,
        0x4d, 0x2a, 0x99, 0x1c, 0xea, 0xb3, 0x9d, 0xa1};
    const auto vector_payload_v2 = BuildProofPayloadV2(ACTION_MINT, Field(0x11), Field(0x22));
    BOOST_CHECK_EQUAL_COLLECTIONS(
        expected_mint_vector_v2.begin(),
        expected_mint_vector_v2.end(),
        vector_payload_v2.begin(),
        vector_payload_v2.end());

    auto tampered_payload = payload;
    tampered_payload.back() ^= 0x01;
    TxValidationState invalid_state;
    BOOST_CHECK(!CheckTransaction(TransactionWithProof(tampered_payload, BuildProofEnvelope(marker, unsigned_tx)), /*active=*/true, invalid_state));
    BOOST_CHECK_EQUAL(invalid_state.GetRejectReason(), "bad-shielded-proof");

    auto tampered_proof = BuildProofEnvelope(marker, unsigned_tx);
    tampered_proof.back() ^= 0x01;
    TxValidationState tampered_proof_state;
    BOOST_CHECK(!CheckTransaction(TransactionWithProof(payload, tampered_proof), /*active=*/true, tampered_proof_state));
    BOOST_CHECK_EQUAL(tampered_proof_state.GetRejectReason(), "bad-shielded-proof");

    auto wrong_kind_proof = BuildProofEnvelope(marker, unsigned_tx);
    wrong_kind_proof[ProofEnvelopePrefix().size()] = ACTION_SPEND;
    TxValidationState wrong_kind_state;
    BOOST_CHECK(!CheckTransaction(TransactionWithProof(payload, wrong_kind_proof), /*active=*/true, wrong_kind_state));
    BOOST_CHECK_EQUAL(wrong_kind_state.GetRejectReason(), "bad-shielded-proof");

    auto duplicate_proof = BuildProofEnvelope(marker, unsigned_tx);
    CMutableTransaction duplicate_proof_tx(TransactionWithProof(payload, duplicate_proof));
    duplicate_proof_tx.vin[0].scriptWitness.stack.push_back(duplicate_proof);
    TxValidationState duplicate_proof_state;
    BOOST_CHECK(!CheckTransaction(CTransaction(duplicate_proof_tx), /*active=*/true, duplicate_proof_state));
    BOOST_CHECK_EQUAL(duplicate_proof_state.GetRejectReason(), "bad-shielded-proof");

    auto wrong_prefix_proof = BuildProofEnvelope(marker, unsigned_tx);
    wrong_prefix_proof[0] ^= 0x01;
    TxValidationState wrong_prefix_state;
    BOOST_CHECK(!CheckTransaction(TransactionWithProof(payload, wrong_prefix_proof), /*active=*/true, wrong_prefix_state));
    BOOST_CHECK_EQUAL(wrong_prefix_state.GetRejectReason(), "bad-shielded-proof");

    CMutableTransaction mutated_tx = MutableTransactionWithMarker(payload);
    const auto original_proof = BuildProofEnvelope(marker, CTransaction(mutated_tx));
    mutated_tx.nLockTime = 1;
    mutated_tx.vin[0].scriptWitness.stack.push_back(original_proof);
    TxValidationState mutated_tx_state;
    BOOST_CHECK(!CheckTransaction(CTransaction(mutated_tx), /*active=*/true, mutated_tx_state));
    BOOST_CHECK_EQUAL(mutated_tx_state.GetRejectReason(), "bad-shielded-proof");
}

BOOST_AUTO_TEST_CASE(spend_markers_stay_standard_relay_sized)
{
    using namespace Consensus::ShieldedPool;

    const auto payload = BuildSpendPayload(Field(0x02), Field(0x03), COIN);
    BOOST_CHECK_EQUAL(payload.size(), 80U);

    const CScript marker_script = CScript() << OP_RETURN << payload;
    BOOST_CHECK_EQUAL(marker_script.size(), MAX_OP_RETURN_RELAY);

    Marker marker;
    BOOST_CHECK(DecodeMarkerPayload(payload, marker));
    BOOST_CHECK_EQUAL(marker.action, ACTION_SPEND);
    BOOST_CHECK_EQUAL(marker.nValue, COIN);
    TxValidationState valid_state;
    BOOST_CHECK(CheckTransaction(TransactionWithProof(payload, marker), /*active=*/true, valid_state));
}

BOOST_AUTO_TEST_SUITE_END()
