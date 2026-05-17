// Copyright (c) 2026 The zkCoin developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <amount.h>
#include <coins.h>
#include <consensus/shielded.h>
#include <consensus/tx_verify.h>
#include <consensus/validation.h>
#include <policy/policy.h>
#include <primitives/transaction.h>
#include <script/script.h>
#include <script/standard.h>
#include <test/util/setup_common.h>
#include <uint256.h>

#include <boost/test/unit_test.hpp>

#include <cassert>
#include <string>
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

static void SetProofBundleLength(std::vector<unsigned char>& bundle)
{
    using namespace Consensus::ShieldedPool;

    const size_t proof_len_offset = ProofEnvelopePrefix().size() + 1 + 1 + 1 + 1 + SHIELDED_PUBLIC_INPUT_HASH_SIZE;
    const size_t proof_offset = proof_len_offset + sizeof(uint32_t);
    BOOST_REQUIRE(bundle.size() >= proof_offset);

    const uint32_t proof_len = bundle.size() - proof_offset;
    for (size_t i = 0; i < sizeof(proof_len); ++i) {
        bundle[proof_len_offset + i] = (proof_len >> (8 * i)) & 0xff;
    }
}

static void AppendUint32Field(std::vector<unsigned char>& payload, uint32_t value)
{
    for (size_t i = 0; i < sizeof(value); ++i) {
        payload.push_back((value >> (8 * i)) & 0xff);
    }
}

static uint256 ExpectedRealProofRequestHash(uint8_t proof_kind, const uint256& public_input_hash, const uint256& verifier_key_hash, const std::vector<unsigned char>& proof_bytes)
{
    std::vector<unsigned char> data{
        'z', 'k', 'c', '-', 'o', 'r', 'c', 'h', 'a', 'r', 'd', '-', 'r', 'e',
        'a', 'l', '-', 'r', 'e', 'q', 'u', 'e', 's', 't', '-', 'v', '1'};
    data.push_back(proof_kind);
    data.insert(data.end(), public_input_hash.begin(), public_input_hash.end());
    data.insert(data.end(), verifier_key_hash.begin(), verifier_key_hash.end());
    AppendUint32Field(data, static_cast<uint32_t>(proof_bytes.size()));
    data.insert(data.end(), proof_bytes.begin(), proof_bytes.end());
    return Hash(data);
}

static uint256 ExpectedRealVerifierInputHash(uint8_t proof_kind, const uint256& public_input_hash, const uint256& verifier_key_hash)
{
    std::vector<unsigned char> data{
        'z', 'k', 'c', '-', 'o', 'r', 'c', 'h', 'a', 'r', 'd', '-', 'r', 'e',
        'a', 'l', '-', 'i', 'n', 'p', 'u', 't', '-', 'v', '1'};
    data.push_back(proof_kind);
    data.insert(data.end(), public_input_hash.begin(), public_input_hash.end());
    data.insert(data.end(), verifier_key_hash.begin(), verifier_key_hash.end());
    return Hash(data);
}

static void AddP2WSHWitnessInput(CMutableTransaction& tx, CCoinsViewCache& coins, const std::vector<unsigned char>& witness_item, uint32_t nonce)
{
    const CScript witness_script = CScript() << OP_TRUE;
    const CScript script_pubkey = GetScriptForDestination(WitnessV0ScriptHash(witness_script));

    CMutableTransaction funding_tx;
    funding_tx.nLockTime = nonce;
    funding_tx.vin.resize(1);
    funding_tx.vin[0].prevout.SetNull();
    funding_tx.vout.emplace_back(COIN, script_pubkey);
    const CTransaction funding(funding_tx);
    AddCoins(coins, funding, 1);

    tx.vin.resize(1);
    tx.vin[0].prevout = COutPoint(funding.GetHash(), 0);
    tx.vin[0].scriptWitness.stack.push_back(witness_item);
    tx.vin[0].scriptWitness.stack.emplace_back(witness_script.begin(), witness_script.end());
}

static COutPoint AddTransparentCoin(CCoinsViewCache& coins, CAmount amount, unsigned char nonce)
{
    CMutableTransaction funding_tx;
    funding_tx.nLockTime = nonce;
    funding_tx.vin.resize(1);
    funding_tx.vin[0].prevout = COutPoint(Field(nonce), 0);
    funding_tx.vout.emplace_back(amount, CScript() << OP_TRUE);
    const CTransaction funding(funding_tx);
    AddCoins(coins, funding, 1);
    return COutPoint(funding.GetHash(), 0);
}

static CTransaction TransactionWithShieldedValueBalance(
    CCoinsViewCache& coins,
    CAmount transparent_input,
    CAmount transparent_output,
    const std::vector<unsigned char>& marker_payload,
    unsigned char nonce)
{
    CMutableTransaction tx;
    tx.vin.resize(1);
    tx.vin[0].prevout = AddTransparentCoin(coins, transparent_input, nonce);
    tx.vout.emplace_back(transparent_output, CScript() << OP_TRUE);
    tx.vout.emplace_back(0, CScript() << OP_RETURN << marker_payload);

    Consensus::ShieldedPool::Marker marker;
    const bool decoded = Consensus::ShieldedPool::DecodeMarkerPayload(marker_payload, marker);
    assert(decoded);
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
    BOOST_CHECK_GT(BuildProofEnvelope(marker, unsigned_tx).size(), MAX_STANDARD_P2WSH_STACK_ITEM_SIZE);

    TxValidationState missing_proof_state;
    BOOST_CHECK(!CheckTransaction(unsigned_tx, /*active=*/true, /*allow_scaffold_proofs=*/true, missing_proof_state));
    BOOST_CHECK_EQUAL(missing_proof_state.GetRejectReason(), "bad-shielded-proof");
    const auto missing_proof_check = CheckProofEnvelope(marker, unsigned_tx);
    BOOST_CHECK(!missing_proof_check.found);
    BOOST_CHECK(!missing_proof_check.IsAccepted(/*allow_scaffold_proofs=*/true));

    const CTransaction scaffold_tx = TransactionWithProof(payload, marker);
    TxValidationState valid_state;
    BOOST_CHECK(CheckTransaction(scaffold_tx, /*active=*/true, /*allow_scaffold_proofs=*/true, valid_state));
    const auto scaffold_check = CheckProofEnvelope(marker, scaffold_tx);
    BOOST_CHECK(scaffold_check.found);
    BOOST_CHECK_EQUAL(scaffold_check.proof_status, SHIELDED_ORCHARD_REAL_PROOF_STATUS_VALID);
    BOOST_CHECK_EQUAL(scaffold_check.proof_body_mode, SHIELDED_ORCHARD_PROOF_BODY_MODE_SCAFFOLD);
    BOOST_CHECK(scaffold_check.real_request_hash.IsNull());
    BOOST_CHECK(scaffold_check.real_verifier_input_hash.IsNull());
    BOOST_CHECK(scaffold_check.IsAccepted(/*allow_scaffold_proofs=*/true));
    BOOST_CHECK(!scaffold_check.IsAccepted(/*allow_scaffold_proofs=*/false));
    TxValidationState scaffold_disabled_state;
    BOOST_CHECK(!CheckTransaction(scaffold_tx, /*active=*/true, /*allow_scaffold_proofs=*/false, scaffold_disabled_state));
    BOOST_CHECK_EQUAL(scaffold_disabled_state.GetRejectReason(), "bad-shielded-proof");

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
    const uint256 public_input_hash = BuildProofPublicInputHash(ACTION_MINT, field_hash, tx_binding_hash);
    const auto proof_payload_v3 = BuildProofPayloadV3(ACTION_MINT, public_input_hash);
    BOOST_CHECK(VerifyProofPayloadV3(proof_payload_v3, ACTION_MINT, public_input_hash));
    BOOST_CHECK(!VerifyProofPayloadV3(proof_payload_v3, ACTION_SPEND, public_input_hash));
    BOOST_CHECK_EQUAL(
        zkc_shielded_verify_proof_v3(
            proof_payload_v3.data(),
            proof_payload_v3.size(),
            ACTION_MINT,
            public_input_hash.begin(),
            SHIELDED_PUBLIC_INPUT_HASH_SIZE),
        1);
    const auto proof_bundle_v4 = BuildProofBundleV4(ACTION_MINT, public_input_hash);
    const auto orchard_payload_v1 = BuildOrchardProofPayloadV1(ACTION_MINT, public_input_hash);
    const auto orchard_body_v1 = BuildOrchardProofBodyV1(ACTION_MINT, public_input_hash);
    const uint256 orchard_proof_body_v1 = ExpectedProofBundlePayloadHashV4(ACTION_MINT, public_input_hash);
    BOOST_CHECK(VerifyOrchardProofBodyV1(
        orchard_body_v1,
        ACTION_MINT,
        public_input_hash));
    BOOST_CHECK(!VerifyOrchardProofBodyV1(
        orchard_body_v1,
        ACTION_SPEND,
        public_input_hash));
    BOOST_CHECK(!VerifyOrchardProofBodyV1(
        std::vector<unsigned char>(orchard_proof_body_v1.begin(), orchard_proof_body_v1.end()),
        ACTION_MINT,
        public_input_hash));
    uint8_t decoded_body_mode{0xff};
    BOOST_CHECK(DecodeOrchardProofBodyModeV1(
        orchard_payload_v1,
        ACTION_MINT,
        public_input_hash,
        decoded_body_mode));
    BOOST_CHECK_EQUAL(decoded_body_mode, SHIELDED_ORCHARD_PROOF_BODY_MODE_SCAFFOLD);
    const std::vector<unsigned char> native_proof_bytes(192, 0x42);
    const std::vector<unsigned char> real_proof_bytes = BuildOrchardNativeProofBytesV1(ACTION_MINT, public_input_hash, native_proof_bytes);
    const uint256 real_verifier_key_hash = ExpectedOrchardRealVerifierKeyHashV1();
    const std::vector<unsigned char> expected_real_verifier_key_hash{
        0x44, 0x98, 0xa4, 0xda, 0xde, 0xe9, 0x35, 0xcc,
        0x2a, 0x7a, 0xf6, 0x97, 0xc5, 0x7a, 0xc3, 0x55,
        0x93, 0xbf, 0xff, 0x59, 0x71, 0x7f, 0x1b, 0x74,
        0x0f, 0xe2, 0x82, 0xaf, 0xe3, 0xf3, 0x2c, 0xd3};
    BOOST_CHECK_EQUAL_COLLECTIONS(
        expected_real_verifier_key_hash.begin(),
        expected_real_verifier_key_hash.end(),
        real_verifier_key_hash.begin(),
        real_verifier_key_hash.end());
    const auto real_proof_v1 = BuildOrchardRealProofV1(ACTION_MINT, public_input_hash, real_proof_bytes);
    std::vector<unsigned char> decoded_real_proof_bytes;
    BOOST_CHECK(DecodeOrchardRealProofV1(real_proof_v1, ACTION_MINT, public_input_hash, decoded_real_proof_bytes));
    BOOST_CHECK_EQUAL_COLLECTIONS(
        real_proof_bytes.begin(),
        real_proof_bytes.end(),
        decoded_real_proof_bytes.begin(),
        decoded_real_proof_bytes.end());
    std::vector<unsigned char> decoded_native_proof_bytes;
    BOOST_CHECK(DecodeOrchardNativeProofBytesV1(decoded_real_proof_bytes, ACTION_MINT, public_input_hash, decoded_native_proof_bytes));
    BOOST_CHECK_EQUAL_COLLECTIONS(
        native_proof_bytes.begin(),
        native_proof_bytes.end(),
        decoded_native_proof_bytes.begin(),
        decoded_native_proof_bytes.end());
    uint256 real_request_hash;
    BOOST_CHECK(OrchardRealProofRequestHashV1(real_proof_v1, ACTION_MINT, public_input_hash, real_request_hash));
    const uint256 expected_real_request_hash = ExpectedRealProofRequestHash(ACTION_MINT, public_input_hash, real_verifier_key_hash, real_proof_bytes);
    BOOST_CHECK_EQUAL_COLLECTIONS(
        expected_real_request_hash.begin(),
        expected_real_request_hash.end(),
        real_request_hash.begin(),
        real_request_hash.end());
    uint256 real_verifier_input_hash;
    BOOST_CHECK(OrchardRealVerifierInputHashV1(real_proof_v1, ACTION_MINT, public_input_hash, real_verifier_input_hash));
    const uint256 expected_real_verifier_input_hash = ExpectedRealVerifierInputHash(ACTION_MINT, public_input_hash, real_verifier_key_hash);
    BOOST_CHECK_EQUAL_COLLECTIONS(
        expected_real_verifier_input_hash.begin(),
        expected_real_verifier_input_hash.end(),
        real_verifier_input_hash.begin(),
        real_verifier_input_hash.end());
    BOOST_CHECK(!OrchardRealVerifierInputHashV1(real_proof_v1, ACTION_SPEND, public_input_hash, real_verifier_input_hash));
    std::vector<unsigned char> real_verifier_input_hash_bytes(SHIELDED_PROOF_HASH_SIZE);
    BOOST_CHECK_EQUAL(
        zkc_shielded_orchard_real_verifier_input_hash_v1(
            real_proof_v1.data(),
            real_proof_v1.size(),
            ACTION_MINT,
            public_input_hash.begin(),
            SHIELDED_PUBLIC_INPUT_HASH_SIZE,
            real_verifier_input_hash_bytes.data(),
            real_verifier_input_hash_bytes.size()),
        1);
    BOOST_CHECK_EQUAL_COLLECTIONS(
        expected_real_verifier_input_hash.begin(),
        expected_real_verifier_input_hash.end(),
        real_verifier_input_hash_bytes.begin(),
        real_verifier_input_hash_bytes.end());
    std::fill(real_verifier_input_hash_bytes.begin(), real_verifier_input_hash_bytes.end(), 0xaa);
    BOOST_CHECK_EQUAL(
        zkc_shielded_orchard_real_verifier_input_hash_v1(
            real_proof_v1.data(),
            real_proof_v1.size(),
            ACTION_SPEND,
            public_input_hash.begin(),
            SHIELDED_PUBLIC_INPUT_HASH_SIZE,
            real_verifier_input_hash_bytes.data(),
            real_verifier_input_hash_bytes.size()),
        0);
    const std::vector<unsigned char> zero_hash(SHIELDED_PROOF_HASH_SIZE);
    BOOST_CHECK_EQUAL_COLLECTIONS(
        zero_hash.begin(),
        zero_hash.end(),
        real_verifier_input_hash_bytes.begin(),
        real_verifier_input_hash_bytes.end());
    uint256 checked_real_request_hash;
    BOOST_CHECK_EQUAL(
        CheckOrchardRealProofV1(real_proof_v1, ACTION_MINT, public_input_hash, checked_real_request_hash),
        SHIELDED_ORCHARD_REAL_PROOF_STATUS_UNSUPPORTED);
    BOOST_CHECK_EQUAL_COLLECTIONS(
        expected_real_request_hash.begin(),
        expected_real_request_hash.end(),
        checked_real_request_hash.begin(),
        checked_real_request_hash.end());
    uint256 checked_real_verifier_input_hash;
    BOOST_CHECK_EQUAL(
        CheckOrchardRealProofV2(real_proof_v1, ACTION_MINT, public_input_hash, checked_real_request_hash, checked_real_verifier_input_hash),
        SHIELDED_ORCHARD_REAL_PROOF_STATUS_UNSUPPORTED);
    BOOST_CHECK_EQUAL_COLLECTIONS(
        expected_real_request_hash.begin(),
        expected_real_request_hash.end(),
        checked_real_request_hash.begin(),
        checked_real_request_hash.end());
    BOOST_CHECK_EQUAL_COLLECTIONS(
        expected_real_verifier_input_hash.begin(),
        expected_real_verifier_input_hash.end(),
        checked_real_verifier_input_hash.begin(),
        checked_real_verifier_input_hash.end());
    BOOST_CHECK_EQUAL(
        CheckOrchardRealProofV1(real_proof_v1, ACTION_SPEND, public_input_hash, checked_real_request_hash),
        SHIELDED_ORCHARD_REAL_PROOF_STATUS_MALFORMED);
    BOOST_CHECK(checked_real_request_hash.IsNull());
    BOOST_CHECK_EQUAL(
        CheckOrchardRealProofV2(real_proof_v1, ACTION_SPEND, public_input_hash, checked_real_request_hash, checked_real_verifier_input_hash),
        SHIELDED_ORCHARD_REAL_PROOF_STATUS_MALFORMED);
    BOOST_CHECK(checked_real_request_hash.IsNull());
    BOOST_CHECK(checked_real_verifier_input_hash.IsNull());
    BOOST_CHECK(!OrchardRealProofRequestHashV1(real_proof_v1, ACTION_SPEND, public_input_hash, real_request_hash));
    BOOST_CHECK(!VerifyOrchardRealProofV1(real_proof_v1, ACTION_MINT, public_input_hash));
    BOOST_CHECK_EQUAL(
        VerifyOrchardRealProofStatusV1(real_proof_v1, ACTION_MINT, public_input_hash),
        SHIELDED_ORCHARD_REAL_PROOF_STATUS_UNSUPPORTED);
    const auto raw_real_proof_v1 = BuildOrchardRealProofV1(ACTION_MINT, public_input_hash, native_proof_bytes);
    const uint256 expected_raw_real_request_hash = ExpectedRealProofRequestHash(ACTION_MINT, public_input_hash, real_verifier_key_hash, native_proof_bytes);
    BOOST_CHECK_EQUAL(
        CheckOrchardRealProofV2(raw_real_proof_v1, ACTION_MINT, public_input_hash, checked_real_request_hash, checked_real_verifier_input_hash),
        SHIELDED_ORCHARD_REAL_PROOF_STATUS_INVALID);
    BOOST_CHECK_EQUAL_COLLECTIONS(
        expected_raw_real_request_hash.begin(),
        expected_raw_real_request_hash.end(),
        checked_real_request_hash.begin(),
        checked_real_request_hash.end());
    BOOST_CHECK_EQUAL_COLLECTIONS(
        expected_real_verifier_input_hash.begin(),
        expected_real_verifier_input_hash.end(),
        checked_real_verifier_input_hash.begin(),
        checked_real_verifier_input_hash.end());
    BOOST_CHECK_EQUAL(
        VerifyOrchardRealProofStatusV1(raw_real_proof_v1, ACTION_MINT, public_input_hash),
        SHIELDED_ORCHARD_REAL_PROOF_STATUS_INVALID);
    auto wrong_native_verifier_key = real_proof_bytes;
    wrong_native_verifier_key[sizeof("zkc-orchard-native-proof-v1") - 1 + 1] ^= 0x01;
    const auto wrong_native_verifier_key_proof_v1 = BuildOrchardRealProofV1(ACTION_MINT, public_input_hash, wrong_native_verifier_key);
    BOOST_CHECK_EQUAL(
        VerifyOrchardRealProofStatusV1(wrong_native_verifier_key_proof_v1, ACTION_MINT, public_input_hash),
        SHIELDED_ORCHARD_REAL_PROOF_STATUS_INVALID);
    std::vector<unsigned char> decoded_wrong_native_verifier_key;
    BOOST_CHECK(DecodeOrchardRealProofV1(wrong_native_verifier_key_proof_v1, ACTION_MINT, public_input_hash, decoded_wrong_native_verifier_key));
    BOOST_CHECK(!DecodeOrchardNativeProofBytesV1(decoded_wrong_native_verifier_key, ACTION_MINT, public_input_hash, decoded_native_proof_bytes));
    BOOST_CHECK(!DecodeOrchardNativeProofBytesV1(native_proof_bytes, ACTION_MINT, public_input_hash, decoded_native_proof_bytes));
    BOOST_CHECK_EQUAL(OrchardRealVerifierBackendV1(), SHIELDED_ORCHARD_REAL_VERIFIER_BACKEND_UNSUPPORTED);
    BOOST_CHECK(!OrchardRealVerifierSupportsProofsV1());
    BOOST_CHECK_EQUAL(
        OrchardRealVerifierBackendName(SHIELDED_ORCHARD_REAL_VERIFIER_BACKEND_UNSUPPORTED),
        std::string("unsupported"));
    BOOST_CHECK_EQUAL(
        OrchardRealVerifierBackendName(SHIELDED_ORCHARD_REAL_VERIFIER_BACKEND_ORCHARD_V1),
        std::string("orchard-v1"));
    BOOST_CHECK_EQUAL(OrchardRealVerifierBackendName(99), std::string("unknown"));
    BOOST_CHECK(!DecodeOrchardRealProofV1(real_proof_v1, ACTION_SPEND, public_input_hash, decoded_real_proof_bytes));
    BOOST_CHECK_EQUAL(
        VerifyOrchardRealProofStatusV1(real_proof_v1, ACTION_SPEND, public_input_hash),
        SHIELDED_ORCHARD_REAL_PROOF_STATUS_MALFORMED);
    auto wrong_real_proof_v1 = real_proof_v1;
    const size_t real_proof_flags_offset = sizeof("zkc-orchard-real-v1") - 1;
    wrong_real_proof_v1[real_proof_flags_offset] = 0x01;
    BOOST_CHECK(!DecodeOrchardRealProofV1(wrong_real_proof_v1, ACTION_MINT, public_input_hash, decoded_real_proof_bytes));
    BOOST_CHECK_EQUAL(
        VerifyOrchardRealProofStatusV1(wrong_real_proof_v1, ACTION_MINT, public_input_hash),
        SHIELDED_ORCHARD_REAL_PROOF_STATUS_MALFORMED);
    wrong_real_proof_v1 = real_proof_v1;
    const size_t real_verifier_key_hash_offset = real_proof_flags_offset + 1 + 1 + SHIELDED_PUBLIC_INPUT_HASH_SIZE;
    wrong_real_proof_v1[real_verifier_key_hash_offset] ^= 0x01;
    BOOST_CHECK(!DecodeOrchardRealProofV1(wrong_real_proof_v1, ACTION_MINT, public_input_hash, decoded_real_proof_bytes));
    const auto real_orchard_body_v1 = BuildOrchardRealProofBodyV1(ACTION_MINT, public_input_hash, real_proof_bytes);
    const auto real_orchard_payload_v1 = BuildOrchardProofPayloadV1(ACTION_MINT, public_input_hash, real_orchard_body_v1);
    const auto real_proof_bundle_v4 = BuildProofBundleV4(ACTION_MINT, public_input_hash, real_orchard_payload_v1);
    const auto real_proof_bundle_from_marker = BuildRealProofEnvelope(marker, unsigned_tx, real_proof_bytes);
    BOOST_CHECK_EQUAL_COLLECTIONS(
        real_proof_bundle_v4.begin(),
        real_proof_bundle_v4.end(),
        real_proof_bundle_from_marker.begin(),
        real_proof_bundle_from_marker.end());
    decoded_body_mode = 0xff;
    BOOST_CHECK(DecodeOrchardProofBodyModeV1(
        real_orchard_payload_v1,
        ACTION_MINT,
        public_input_hash,
        decoded_body_mode));
    BOOST_CHECK_EQUAL(decoded_body_mode, SHIELDED_ORCHARD_PROOF_BODY_MODE_REAL);
    BOOST_CHECK(!VerifyOrchardProofBodyV1(real_orchard_body_v1, ACTION_MINT, public_input_hash));
    BOOST_CHECK(!VerifyOrchardProofPayloadV1(real_orchard_payload_v1, ACTION_MINT, public_input_hash));
    BOOST_CHECK(!VerifyProofBundleV4(real_proof_bundle_v4, ACTION_MINT, public_input_hash));
    uint8_t checked_body_mode{SHIELDED_ORCHARD_PROOF_BODY_MODE_UNKNOWN};
    uint256 checked_bundle_request_hash;
    BOOST_CHECK_EQUAL(
        CheckProofBundleV4(real_proof_bundle_v4, ACTION_MINT, public_input_hash, checked_body_mode, checked_bundle_request_hash),
        SHIELDED_ORCHARD_REAL_PROOF_STATUS_UNSUPPORTED);
    BOOST_CHECK_EQUAL(checked_body_mode, SHIELDED_ORCHARD_PROOF_BODY_MODE_REAL);
    BOOST_CHECK_EQUAL_COLLECTIONS(
        expected_real_request_hash.begin(),
        expected_real_request_hash.end(),
        checked_bundle_request_hash.begin(),
        checked_bundle_request_hash.end());
    uint256 checked_bundle_verifier_input_hash;
    BOOST_CHECK_EQUAL(
        CheckProofBundleV5(real_proof_bundle_v4, ACTION_MINT, public_input_hash, checked_body_mode, checked_bundle_request_hash, checked_bundle_verifier_input_hash),
        SHIELDED_ORCHARD_REAL_PROOF_STATUS_UNSUPPORTED);
    BOOST_CHECK_EQUAL(checked_body_mode, SHIELDED_ORCHARD_PROOF_BODY_MODE_REAL);
    BOOST_CHECK_EQUAL_COLLECTIONS(
        expected_real_request_hash.begin(),
        expected_real_request_hash.end(),
        checked_bundle_request_hash.begin(),
        checked_bundle_request_hash.end());
    BOOST_CHECK_EQUAL_COLLECTIONS(
        expected_real_verifier_input_hash.begin(),
        expected_real_verifier_input_hash.end(),
        checked_bundle_verifier_input_hash.begin(),
        checked_bundle_verifier_input_hash.end());
    const auto real_proof_envelope_check = CheckProofEnvelope(marker, TransactionWithProof(payload, real_proof_bundle_v4));
    BOOST_CHECK(real_proof_envelope_check.found);
    BOOST_CHECK_EQUAL(real_proof_envelope_check.proof_status, SHIELDED_ORCHARD_REAL_PROOF_STATUS_UNSUPPORTED);
    BOOST_CHECK_EQUAL(real_proof_envelope_check.proof_body_mode, SHIELDED_ORCHARD_PROOF_BODY_MODE_REAL);
    BOOST_CHECK_EQUAL_COLLECTIONS(
        expected_real_request_hash.begin(),
        expected_real_request_hash.end(),
        real_proof_envelope_check.real_request_hash.begin(),
        real_proof_envelope_check.real_request_hash.end());
    BOOST_CHECK_EQUAL_COLLECTIONS(
        expected_real_verifier_input_hash.begin(),
        expected_real_verifier_input_hash.end(),
        real_proof_envelope_check.real_verifier_input_hash.begin(),
        real_proof_envelope_check.real_verifier_input_hash.end());
    BOOST_CHECK(!real_proof_envelope_check.IsAccepted(/*allow_scaffold_proofs=*/true));
    BOOST_CHECK(!real_proof_envelope_check.IsAccepted(/*allow_scaffold_proofs=*/false));
    BOOST_CHECK_EQUAL(
        CheckProofBundleV4(real_proof_bundle_v4, ACTION_SPEND, public_input_hash, checked_body_mode, checked_bundle_request_hash),
        SHIELDED_ORCHARD_REAL_PROOF_STATUS_MALFORMED);
    BOOST_CHECK_EQUAL(checked_body_mode, SHIELDED_ORCHARD_PROOF_BODY_MODE_UNKNOWN);
    BOOST_CHECK(checked_bundle_request_hash.IsNull());
    TxValidationState real_proof_tx_state;
    BOOST_CHECK(!CheckTransaction(TransactionWithProof(payload, real_proof_bundle_v4), /*active=*/true, /*allow_scaffold_proofs=*/true, real_proof_tx_state));
    BOOST_CHECK_EQUAL(real_proof_tx_state.GetRejectReason(), "bad-shielded-proof");
    auto unknown_body_mode = orchard_body_v1;
    const size_t body_mode_offset = sizeof("zkc-orchard-body-v1") - 1;
    BOOST_REQUIRE_GT(unknown_body_mode.size(), body_mode_offset);
    unknown_body_mode[body_mode_offset] = 0xff;
    BOOST_CHECK(!VerifyOrchardProofBodyV1(unknown_body_mode, ACTION_MINT, public_input_hash));
    BOOST_CHECK(VerifyOrchardProofPayloadV1(orchard_payload_v1, ACTION_MINT, public_input_hash));
    BOOST_CHECK(!VerifyOrchardProofPayloadV1(orchard_payload_v1, ACTION_SPEND, public_input_hash));
    BOOST_CHECK(VerifyProofBundleV4(proof_bundle_v4, ACTION_MINT, public_input_hash));
    BOOST_CHECK_EQUAL(
        CheckProofBundleV4(proof_bundle_v4, ACTION_MINT, public_input_hash, checked_body_mode, checked_bundle_request_hash),
        SHIELDED_ORCHARD_REAL_PROOF_STATUS_VALID);
    BOOST_CHECK_EQUAL(checked_body_mode, SHIELDED_ORCHARD_PROOF_BODY_MODE_SCAFFOLD);
    BOOST_CHECK(checked_bundle_request_hash.IsNull());
    BOOST_CHECK(!VerifyProofBundleV4(proof_bundle_v4, ACTION_SPEND, public_input_hash));
    uint8_t decoded_proof_kind{0};
    uint256 decoded_public_input_hash;
    std::vector<unsigned char> decoded_orchard_payload;
    BOOST_CHECK(DecodeProofEnvelope(proof_bundle_v4, decoded_proof_kind, decoded_public_input_hash, decoded_orchard_payload));
    BOOST_CHECK_EQUAL(decoded_proof_kind, ACTION_MINT);
    BOOST_CHECK_EQUAL(decoded_public_input_hash.ToString(), public_input_hash.ToString());
    BOOST_CHECK_EQUAL_COLLECTIONS(
        orchard_payload_v1.begin(),
        orchard_payload_v1.end(),
        decoded_orchard_payload.begin(),
        decoded_orchard_payload.end());
    BOOST_CHECK_EQUAL(
        zkc_shielded_verify_bundle_v4(
            proof_bundle_v4.data(),
            proof_bundle_v4.size(),
            ACTION_MINT,
            public_input_hash.begin(),
            SHIELDED_PUBLIC_INPUT_HASH_SIZE),
        1);

    auto short_proof_payload = proof_payload;
    short_proof_payload.pop_back();
    BOOST_CHECK(!VerifyProofPayloadV1(short_proof_payload, field_hash, tx_binding_hash));
    BOOST_CHECK(!VerifyProofPayloadV2(short_proof_payload, ACTION_MINT, field_hash, tx_binding_hash));
    BOOST_CHECK(!VerifyProofPayloadV3(short_proof_payload, ACTION_MINT, public_input_hash));
    BOOST_CHECK(!VerifyProofBundleV4(short_proof_payload, ACTION_MINT, public_input_hash));
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
    const std::vector<unsigned char> expected_public_input_vector{
        0x90, 0xd5, 0xa8, 0xbb, 0x82, 0x0b, 0x4f, 0x47,
        0x4e, 0x1a, 0x44, 0x5f, 0x0b, 0x23, 0x03, 0x27,
        0x18, 0xc0, 0x7e, 0xbc, 0x5b, 0x94, 0xec, 0x51,
        0x23, 0x43, 0x63, 0xa0, 0x67, 0x82, 0x6e, 0x31};
    const uint256 vector_public_input_hash = BuildProofPublicInputHash(ACTION_MINT, Field(0x11), Field(0x22));
    BOOST_CHECK_EQUAL_COLLECTIONS(
        expected_public_input_vector.begin(),
        expected_public_input_vector.end(),
        vector_public_input_hash.begin(),
        vector_public_input_hash.end());
    const std::vector<unsigned char> expected_mint_vector_v3{
        0x46, 0x50, 0x2b, 0x6c, 0x3c, 0xab, 0xfb, 0xe2,
        0x17, 0x8f, 0xbb, 0x6e, 0x7c, 0xcb, 0x90, 0x14,
        0x45, 0x91, 0xf8, 0xce, 0x03, 0x16, 0xf9, 0x0b,
        0x5c, 0x0e, 0xb6, 0xc1, 0xa6, 0x3f, 0x5b, 0x3a};
    const auto vector_payload_v3 = BuildProofPayloadV3(ACTION_MINT, vector_public_input_hash);
    BOOST_CHECK_EQUAL_COLLECTIONS(
        expected_mint_vector_v3.begin(),
        expected_mint_vector_v3.end(),
        vector_payload_v3.begin(),
        vector_payload_v3.end());
    const std::vector<unsigned char> expected_mint_vector_v4{
        0xe1, 0x60, 0x23, 0x9b, 0x4c, 0x8b, 0xfc, 0x13,
        0x7c, 0xac, 0xf2, 0x10, 0xd0, 0xea, 0xc3, 0xcb,
        0xc8, 0xe6, 0xfa, 0xd5, 0xff, 0xaa, 0x06, 0xca,
        0xe6, 0x93, 0x1d, 0xb0, 0x34, 0x58, 0xc4, 0x24};
    const uint256 vector_payload_v4 = ExpectedProofBundlePayloadHashV4(ACTION_MINT, vector_public_input_hash);
    BOOST_CHECK_EQUAL_COLLECTIONS(
        expected_mint_vector_v4.begin(),
        expected_mint_vector_v4.end(),
        vector_payload_v4.begin(),
        vector_payload_v4.end());

    auto tampered_payload = payload;
    tampered_payload.back() ^= 0x01;
    TxValidationState invalid_state;
    BOOST_CHECK(!CheckTransaction(TransactionWithProof(tampered_payload, BuildProofEnvelope(marker, unsigned_tx)), /*active=*/true, /*allow_scaffold_proofs=*/true, invalid_state));
    BOOST_CHECK_EQUAL(invalid_state.GetRejectReason(), "bad-shielded-proof");

    auto tampered_proof = BuildProofEnvelope(marker, unsigned_tx);
    tampered_proof.back() ^= 0x01;
    TxValidationState tampered_proof_state;
    BOOST_CHECK(!CheckTransaction(TransactionWithProof(payload, tampered_proof), /*active=*/true, /*allow_scaffold_proofs=*/true, tampered_proof_state));
    BOOST_CHECK_EQUAL(tampered_proof_state.GetRejectReason(), "bad-shielded-proof");

    auto wrong_kind_proof = BuildProofEnvelope(marker, unsigned_tx);
    wrong_kind_proof[ProofEnvelopePrefix().size() + 1] = ACTION_SPEND;
    TxValidationState wrong_kind_state;
    BOOST_CHECK(!CheckTransaction(TransactionWithProof(payload, wrong_kind_proof), /*active=*/true, /*allow_scaffold_proofs=*/true, wrong_kind_state));
    BOOST_CHECK_EQUAL(wrong_kind_state.GetRejectReason(), "bad-shielded-proof");

    auto wrong_public_input_proof = BuildProofEnvelope(marker, unsigned_tx);
    wrong_public_input_proof[ProofEnvelopePrefix().size() + 4] ^= 0x01;
    TxValidationState wrong_public_input_state;
    BOOST_CHECK(!CheckTransaction(TransactionWithProof(payload, wrong_public_input_proof), /*active=*/true, /*allow_scaffold_proofs=*/true, wrong_public_input_state));
    BOOST_CHECK_EQUAL(wrong_public_input_state.GetRejectReason(), "bad-shielded-proof");

    auto duplicate_proof = BuildProofEnvelope(marker, unsigned_tx);
    CMutableTransaction duplicate_proof_tx(TransactionWithProof(payload, duplicate_proof));
    duplicate_proof_tx.vin[0].scriptWitness.stack.push_back(duplicate_proof);
    const auto duplicate_proof_check = CheckProofEnvelope(marker, CTransaction(duplicate_proof_tx));
    BOOST_CHECK(duplicate_proof_check.found);
    BOOST_CHECK_EQUAL(duplicate_proof_check.proof_status, SHIELDED_ORCHARD_REAL_PROOF_STATUS_MALFORMED);
    BOOST_CHECK_EQUAL(duplicate_proof_check.proof_body_mode, SHIELDED_ORCHARD_PROOF_BODY_MODE_UNKNOWN);
    BOOST_CHECK(duplicate_proof_check.real_request_hash.IsNull());
    BOOST_CHECK(duplicate_proof_check.real_verifier_input_hash.IsNull());
    TxValidationState duplicate_proof_state;
    BOOST_CHECK(!CheckTransaction(CTransaction(duplicate_proof_tx), /*active=*/true, /*allow_scaffold_proofs=*/true, duplicate_proof_state));
    BOOST_CHECK_EQUAL(duplicate_proof_state.GetRejectReason(), "bad-shielded-proof");

    auto wrong_prefix_proof = BuildProofEnvelope(marker, unsigned_tx);
    wrong_prefix_proof[0] ^= 0x01;
    TxValidationState wrong_prefix_state;
    BOOST_CHECK(!CheckTransaction(TransactionWithProof(payload, wrong_prefix_proof), /*active=*/true, /*allow_scaffold_proofs=*/true, wrong_prefix_state));
    BOOST_CHECK_EQUAL(wrong_prefix_state.GetRejectReason(), "bad-shielded-proof");

    CMutableTransaction mutated_tx = MutableTransactionWithMarker(payload);
    const auto original_proof = BuildProofEnvelope(marker, CTransaction(mutated_tx));
    mutated_tx.nLockTime = 1;
    mutated_tx.vin[0].scriptWitness.stack.push_back(original_proof);
    TxValidationState mutated_tx_state;
    BOOST_CHECK(!CheckTransaction(CTransaction(mutated_tx), /*active=*/true, /*allow_scaffold_proofs=*/true, mutated_tx_state));
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
    BOOST_CHECK(CheckTransaction(TransactionWithProof(payload, marker), /*active=*/true, /*allow_scaffold_proofs=*/true, valid_state));
}

BOOST_AUTO_TEST_CASE(shielded_proof_bundle_witness_policy_allows_real_proof_sizes)
{
    using namespace Consensus::ShieldedPool;

    CCoinsView coins_dummy;
    CCoinsViewCache coins(&coins_dummy);

    const auto marker_payload = BuildMintPayload(Field(0x04), COIN);
    Marker marker;
    BOOST_REQUIRE(DecodeMarkerPayload(marker_payload, marker));

    const uint256 public_input_hash = BuildProofPublicInputHash(ACTION_MINT, ExpectedProofHash(marker), Field(0x05));
    auto proof_bundle = BuildProofBundleV4(ACTION_MINT, public_input_hash);
    BOOST_REQUIRE(proof_bundle.size() > MAX_STANDARD_P2WSH_STACK_ITEM_SIZE);
    BOOST_REQUIRE(HasProofEnvelopePrefix(proof_bundle));
    BOOST_REQUIRE(proof_bundle.size() <= MAX_SCRIPT_ELEMENT_SIZE);

    CMutableTransaction non_shielded_tx;
    AddP2WSHWitnessInput(non_shielded_tx, coins, std::vector<unsigned char>(MAX_STANDARD_P2WSH_STACK_ITEM_SIZE + 1, 0x99), 1);
    BOOST_CHECK(!IsWitnessStandard(CTransaction(non_shielded_tx), coins));

    CMutableTransaction shielded_tx;
    shielded_tx.vout.emplace_back(0, CScript() << OP_RETURN << marker_payload);
    AddP2WSHWitnessInput(shielded_tx, coins, proof_bundle, 2);
    BOOST_CHECK(IsWitnessStandard(CTransaction(shielded_tx), coins));

    auto over_limit_bundle = proof_bundle;
    over_limit_bundle.resize(MAX_SCRIPT_ELEMENT_SIZE + 1, 0x42);
    SetProofBundleLength(over_limit_bundle);
    CMutableTransaction over_limit_tx;
    over_limit_tx.vout.emplace_back(0, CScript() << OP_RETURN << marker_payload);
    AddP2WSHWitnessInput(over_limit_tx, coins, over_limit_bundle, 3);
    BOOST_CHECK(!IsWitnessStandard(CTransaction(over_limit_tx), coins));
}

struct ShieldedActiveTestingSetup : public BasicTestingSetup {
    ShieldedActiveTestingSetup()
        : BasicTestingSetup(CBaseChainParams::REGTEST, {"-shieldedheight=1"})
    {
    }
};

BOOST_FIXTURE_TEST_CASE(check_tx_inputs_accounts_shielded_value_balance, ShieldedActiveTestingSetup)
{
    using namespace Consensus::ShieldedPool;

    CCoinsView coins_dummy;
    CCoinsViewCache coins(&coins_dummy);

    CAmount txfee{0};
    TxValidationState valid_mint_state;
    const CTransaction valid_mint = TransactionWithShieldedValueBalance(
        coins,
        5 * COIN,
        4 * COIN,
        BuildMintPayload(Field(0x10), COIN),
        0x10);
    BOOST_CHECK(Consensus::CheckTxInputs(valid_mint, valid_mint_state, coins, /*nSpendHeight=*/1, txfee));
    BOOST_CHECK_EQUAL(txfee, 0);

    txfee = 0;
    TxValidationState underfunded_mint_state;
    const CTransaction underfunded_mint = TransactionWithShieldedValueBalance(
        coins,
        5 * COIN,
        4 * COIN + 1,
        BuildMintPayload(Field(0x11), COIN),
        0x11);
    BOOST_CHECK(!Consensus::CheckTxInputs(underfunded_mint, underfunded_mint_state, coins, /*nSpendHeight=*/1, txfee));
    BOOST_CHECK_EQUAL(underfunded_mint_state.GetRejectReason(), "bad-txns-in-belowout");

    txfee = 0;
    TxValidationState valid_spend_state;
    const CTransaction valid_spend = TransactionWithShieldedValueBalance(
        coins,
        5 * COIN,
        6 * COIN,
        BuildSpendPayload(Field(0x20), Field(0x21), COIN),
        0x12);
    BOOST_CHECK(Consensus::CheckTxInputs(valid_spend, valid_spend_state, coins, /*nSpendHeight=*/1, txfee));
    BOOST_CHECK_EQUAL(txfee, 0);

    txfee = 0;
    TxValidationState overspent_spend_state;
    const CTransaction overspent_spend = TransactionWithShieldedValueBalance(
        coins,
        5 * COIN,
        6 * COIN + 1,
        BuildSpendPayload(Field(0x22), Field(0x23), COIN),
        0x13);
    BOOST_CHECK(!Consensus::CheckTxInputs(overspent_spend, overspent_spend_state, coins, /*nSpendHeight=*/1, txfee));
    BOOST_CHECK_EQUAL(overspent_spend_state.GetRejectReason(), "bad-txns-in-belowout");
}

BOOST_AUTO_TEST_SUITE_END()
