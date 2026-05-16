// Copyright (c) 2026 The zkCoin developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <auxpow.h>
#include <chainparams.h>
#include <pow.h>
#include <primitives/block.h>
#include <streams.h>
#include <test/util/setup_common.h>
#include <version.h>

#include <boost/test/unit_test.hpp>

BOOST_FIXTURE_TEST_SUITE(auxpow_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(expected_index_bounds)
{
    BOOST_CHECK_EQUAL(CAuxPow::getExpectedIndex(0, 0x5a4b, 0), 0);
    BOOST_CHECK_EQUAL(CAuxPow::getExpectedIndex(1234, 0x5a4b, 0), 0);

    const int index = CAuxPow::getExpectedIndex(1234, 0x5a4b, 5);
    BOOST_CHECK_GE(index, 0);
    BOOST_CHECK_LT(index, 32);
}

BOOST_AUTO_TEST_CASE(init_auxpow_creates_valid_minimal_proof)
{
    CBlockHeader header;
    header.nVersion = 1;
    header.nTime = 1;
    header.nBits = 0x207fffff;
    header.nNonce = 0;
    header.hashPrevBlock.SetHex("01");
    header.hashMerkleRoot.SetHex("02");

    BOOST_CHECK(!header.IsAuxpow());

    CPureBlockHeader& parent = CAuxPow::initAuxPow(header);
    const Consensus::Params& consensus = Params().GetConsensus();

    BOOST_CHECK(header.IsAuxpow());
    BOOST_REQUIRE(header.auxpow);
    BOOST_CHECK(parent.hashMerkleRoot == header.auxpow->getParentBlock().hashMerkleRoot);
    BOOST_CHECK(header.auxpow->check(header.GetHash(), consensus.auxpow.nChainId, consensus));
    BOOST_CHECK(!header.auxpow->getParentBlockHash().IsNull());
    BOOST_CHECK(!header.auxpow->getParentBlockPoWHash().IsNull());
}

BOOST_AUTO_TEST_CASE(block_proof_of_work_uses_parent_auxpow_header)
{
    CBlockHeader header;
    header.nVersion = 1;
    header.nTime = 1;
    header.nBits = 0x207fffff;
    header.nNonce = 0;
    header.hashPrevBlock.SetHex("05");
    header.hashMerkleRoot.SetHex("06");

    CPureBlockHeader& parent = CAuxPow::initAuxPow(header);
    const auto chainParams = CreateChainParams(*m_node.args, CBaseChainParams::REGTEST);
    const Consensus::Params& consensus = chainParams->GetConsensus();

    while (!CheckProofOfWork(parent.GetPoWHash(), header.nBits, consensus) && parent.nNonce < 100000) {
        ++parent.nNonce;
    }

    BOOST_REQUIRE(CheckProofOfWork(parent.GetPoWHash(), header.nBits, consensus));
    BOOST_CHECK(CheckBlockProofOfWork(header, consensus));
}

BOOST_AUTO_TEST_CASE(auxpow_header_serialization_round_trip)
{
    CBlockHeader header;
    header.nVersion = 1;
    header.nTime = 2;
    header.nBits = 0x207fffff;
    header.nNonce = 3;
    header.hashPrevBlock.SetHex("03");
    header.hashMerkleRoot.SetHex("04");
    CAuxPow::initAuxPow(header);

    CDataStream stream(SER_NETWORK, PROTOCOL_VERSION);
    stream << header;

    CBlockHeader decoded;
    stream >> decoded;

    const Consensus::Params& consensus = Params().GetConsensus();
    BOOST_CHECK(decoded.IsAuxpow());
    BOOST_REQUIRE(decoded.auxpow);
    BOOST_CHECK(decoded.GetHash() == header.GetHash());
    BOOST_CHECK(decoded.auxpow->check(decoded.GetHash(), consensus.auxpow.nChainId, consensus));
}

BOOST_AUTO_TEST_SUITE_END()
