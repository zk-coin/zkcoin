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

static CTransaction TransactionWithMarker(const std::vector<unsigned char>& payload)
{
    uint256 prevout_hash;
    prevout_hash.SetHex("01");

    CMutableTransaction tx;
    tx.vin.resize(1);
    tx.vin[0].prevout = COutPoint(prevout_hash, 0);
    tx.vout.emplace_back(0, CScript() << OP_RETURN << payload);
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
    BOOST_CHECK(VerifyStubbedProof(marker));

    TxValidationState valid_state;
    BOOST_CHECK(CheckTransaction(TransactionWithMarker(payload), /*active=*/true, valid_state));

    auto tampered_payload = payload;
    tampered_payload.back() ^= 0x01;
    TxValidationState invalid_state;
    BOOST_CHECK(!CheckTransaction(TransactionWithMarker(tampered_payload), /*active=*/true, invalid_state));
    BOOST_CHECK_EQUAL(invalid_state.GetRejectReason(), "bad-shielded-proof");
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
    BOOST_CHECK(VerifyStubbedProof(marker));
}

BOOST_AUTO_TEST_SUITE_END()
