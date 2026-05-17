// Copyright (c) 2026 The zkCoin developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <auxpow.h>
#include <chain.h>
#include <chainparams.h>
#include <pow.h>
#include <primitives/block.h>
#include <streams.h>
#include <test/util/setup_common.h>
#include <version.h>

#include <boost/test/unit_test.hpp>

#include <algorithm>

namespace {
std::vector<unsigned char> BuildAuxPowCommitmentBytes(const uint256& hashAuxBlock, bool includeMergedMiningHeader = false, unsigned int leadingPadding = 0)
{
    std::vector<unsigned char> commitment(leadingPadding, 0);
    if (includeMergedMiningHeader) {
        commitment.insert(commitment.end(), PCH_MERGED_MINING_HEADER, PCH_MERGED_MINING_HEADER + sizeof(PCH_MERGED_MINING_HEADER));
    }

    std::vector<unsigned char> auxBlockHash(hashAuxBlock.begin(), hashAuxBlock.end());
    std::reverse(auxBlockHash.begin(), auxBlockHash.end());
    commitment.insert(commitment.end(), auxBlockHash.begin(), auxBlockHash.end());
    commitment.push_back(1);
    commitment.insert(commitment.end(), 7, 0);
    return commitment;
}

CAuxPow DeserializeAuxPowForParentTx(const CTransactionRef& parentTx, const CPureBlockHeader& parentHeader, int txIndex = 0)
{
    CDataStream stream(SER_NETWORK, PROTOCOL_VERSION);
    const uint256 hashBlock;
    const std::vector<uint256> merkleBranch;
    const std::vector<uint256> chainMerkleBranch;
    const int chainIndex = 0;

    stream << parentTx << hashBlock << merkleBranch << txIndex;
    stream << chainMerkleBranch << chainIndex << parentHeader;

    CAuxPow auxpow;
    stream >> auxpow;
    return auxpow;
}
} // namespace

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
    const Consensus::Params& consensus = Params().GetConsensus();
    header.SetChainId(consensus.auxpow.nChainId);

    BOOST_CHECK(!header.IsAuxpow());

    CPureBlockHeader& parent = CAuxPow::initAuxPow(header);

    BOOST_CHECK(header.IsAuxpow());
    BOOST_REQUIRE(header.auxpow);
    BOOST_CHECK(parent.hashMerkleRoot == header.auxpow->getParentBlock().hashMerkleRoot);
    BOOST_CHECK(header.auxpow->check(header.GetHash(), consensus.auxpow.nChainId, consensus));
    BOOST_CHECK(!header.auxpow->getParentBlockHash().IsNull());
    BOOST_CHECK(!header.auxpow->getParentBlockPoWHash().IsNull());
}

BOOST_AUTO_TEST_CASE(auxpow_rejects_non_coinbase_parent_commitment)
{
    CBlockHeader header;
    header.nVersion = 1;
    header.nTime = 1;
    header.nBits = 0x207fffff;
    header.nNonce = 0;
    header.hashPrevBlock.SetHex("07");
    header.hashMerkleRoot.SetHex("08");
    header.SetAuxpowVersion(true);

    uint256 prevoutHash;
    prevoutHash.SetHex("09");

    CMutableTransaction tx;
    tx.vin.resize(1);
    tx.vin[0].prevout = COutPoint(prevoutHash, 0);
    tx.vin[0].scriptSig = CScript() << BuildAuxPowCommitmentBytes(header.GetHash());
    tx.vout.resize(1);
    tx.vout[0].scriptPubKey = CScript() << OP_TRUE;
    CTransactionRef txRef = MakeTransactionRef(tx);

    CPureBlockHeader parent;
    parent.nVersion = 1;
    parent.nTime = 1;
    parent.nBits = 0x207fffff;
    parent.nNonce = 0;
    parent.hashMerkleRoot = txRef->GetHash();

    CAuxPow auxpow = DeserializeAuxPowForParentTx(txRef, parent);
    const Consensus::Params& consensus = Params().GetConsensus();

    BOOST_CHECK(!txRef->IsCoinBase());
    BOOST_CHECK(!auxpow.check(header.GetHash(), consensus.auxpow.nChainId, consensus));
}

BOOST_AUTO_TEST_CASE(auxpow_rejects_nonzero_parent_tx_index)
{
    CBlockHeader header;
    header.nVersion = 1;
    header.nTime = 1;
    header.nBits = 0x207fffff;
    header.nNonce = 0;
    header.hashPrevBlock.SetHex("0a");
    header.hashMerkleRoot.SetHex("0b");
    header.SetAuxpowVersion(true);

    CMutableTransaction coinbase;
    coinbase.vin.resize(1);
    coinbase.vin[0].prevout.SetNull();
    coinbase.vin[0].scriptSig = CScript() << BuildAuxPowCommitmentBytes(header.GetHash());
    coinbase.vout.resize(1);
    coinbase.vout[0].scriptPubKey = CScript() << OP_TRUE;
    CTransactionRef coinbaseRef = MakeTransactionRef(coinbase);

    CPureBlockHeader parent;
    parent.nVersion = 1;
    parent.nTime = 1;
    parent.nBits = 0x207fffff;
    parent.nNonce = 0;
    parent.hashMerkleRoot = coinbaseRef->GetHash();

    CAuxPow auxpow = DeserializeAuxPowForParentTx(coinbaseRef, parent, 1);
    const Consensus::Params& consensus = Params().GetConsensus();

    BOOST_CHECK(coinbaseRef->IsCoinBase());
    BOOST_CHECK(!auxpow.check(header.GetHash(), consensus.auxpow.nChainId, consensus));
}

BOOST_AUTO_TEST_CASE(auxpow_rejects_parent_with_child_chain_id)
{
    CBlockHeader header;
    header.nVersion = 1;
    header.nTime = 1;
    header.nBits = 0x207fffff;
    header.nNonce = 0;
    header.hashPrevBlock.SetHex("0c");
    header.hashMerkleRoot.SetHex("0d");
    header.SetAuxpowVersion(true);

    CMutableTransaction coinbase;
    coinbase.vin.resize(1);
    coinbase.vin[0].prevout.SetNull();
    coinbase.vin[0].scriptSig = CScript() << BuildAuxPowCommitmentBytes(header.GetHash());
    coinbase.vout.resize(1);
    coinbase.vout[0].scriptPubKey = CScript() << OP_TRUE;
    CTransactionRef coinbaseRef = MakeTransactionRef(coinbase);

    CPureBlockHeader parent;
    parent.nVersion = 1;
    parent.nTime = 1;
    parent.nBits = 0x207fffff;
    parent.nNonce = 0;
    parent.hashMerkleRoot = coinbaseRef->GetHash();

    const Consensus::Params& consensus = Params().GetConsensus();
    CAuxPow auxpow = DeserializeAuxPowForParentTx(coinbaseRef, parent);
    BOOST_CHECK(auxpow.check(header.GetHash(), consensus.auxpow.nChainId, consensus));

    parent.SetChainId(consensus.auxpow.nChainId);
    CAuxPow selfMergedAuxpow = DeserializeAuxPowForParentTx(coinbaseRef, parent);
    BOOST_CHECK(!selfMergedAuxpow.check(header.GetHash(), consensus.auxpow.nChainId, consensus));
}

BOOST_AUTO_TEST_CASE(auxpow_merged_mining_header_allows_late_commitment)
{
    CBlockHeader header;
    header.nVersion = 1;
    header.nTime = 1;
    header.nBits = 0x207fffff;
    header.nNonce = 0;
    header.hashPrevBlock.SetHex("0c");
    header.hashMerkleRoot.SetHex("0d");
    header.SetAuxpowVersion(true);

    CMutableTransaction coinbase;
    coinbase.vin.resize(1);
    coinbase.vin[0].prevout.SetNull();
    coinbase.vout.resize(1);
    coinbase.vout[0].scriptPubKey = CScript() << OP_TRUE;

    CPureBlockHeader parent;
    parent.nVersion = 1;
    parent.nTime = 1;
    parent.nBits = 0x207fffff;
    parent.nNonce = 0;

    const Consensus::Params& consensus = Params().GetConsensus();

    coinbase.vin[0].scriptSig = CScript() << BuildAuxPowCommitmentBytes(header.GetHash(), false, 24);
    CTransactionRef legacyLateCoinbase = MakeTransactionRef(coinbase);
    parent.hashMerkleRoot = legacyLateCoinbase->GetHash();
    CAuxPow legacyLateAuxpow = DeserializeAuxPowForParentTx(legacyLateCoinbase, parent);
    BOOST_CHECK(!legacyLateAuxpow.check(header.GetHash(), consensus.auxpow.nChainId, consensus));

    coinbase.vin[0].scriptSig = CScript() << BuildAuxPowCommitmentBytes(header.GetHash(), true, 24);
    CTransactionRef taggedCoinbase = MakeTransactionRef(coinbase);
    parent.hashMerkleRoot = taggedCoinbase->GetHash();
    CAuxPow taggedAuxpow = DeserializeAuxPowForParentTx(taggedCoinbase, parent);
    BOOST_CHECK(taggedAuxpow.check(header.GetHash(), consensus.auxpow.nChainId, consensus));
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
    const auto chainParams = CreateChainParams(*m_node.args, CBaseChainParams::REGTEST);
    const Consensus::Params& consensus = chainParams->GetConsensus();
    header.SetChainId(consensus.auxpow.nChainId);

    CPureBlockHeader& parent = CAuxPow::initAuxPow(header);

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
    const Consensus::Params& consensus = Params().GetConsensus();
    header.SetChainId(consensus.auxpow.nChainId);
    CAuxPow::initAuxPow(header);

    CDataStream stream(SER_NETWORK, PROTOCOL_VERSION);
    stream << header;

    CBlockHeader decoded;
    stream >> decoded;

    BOOST_CHECK(decoded.IsAuxpow());
    BOOST_REQUIRE(decoded.auxpow);
    BOOST_CHECK(decoded.GetHash() == header.GetHash());
    BOOST_CHECK(decoded.auxpow->check(decoded.GetHash(), consensus.auxpow.nChainId, consensus));
}

BOOST_AUTO_TEST_CASE(auxpow_block_index_preserves_payload)
{
    CBlockHeader header;
    header.nVersion = 1;
    header.nTime = 2;
    header.nBits = 0x207fffff;
    header.nNonce = 3;
    header.hashPrevBlock.SetNull();
    header.hashMerkleRoot.SetHex("0f");
    const Consensus::Params& consensus = Params().GetConsensus();
    header.SetChainId(consensus.auxpow.nChainId);
    CAuxPow::initAuxPow(header);

    CBlockIndex index(header);
    CBlockHeader indexed_header = index.GetBlockHeader();

    BOOST_REQUIRE(indexed_header.IsAuxpow());
    BOOST_REQUIRE(indexed_header.auxpow);

    CDataStream stream(SER_NETWORK, PROTOCOL_VERSION);
    stream << indexed_header;

    CBlockHeader decoded_header;
    stream >> decoded_header;

    BOOST_REQUIRE(decoded_header.auxpow);
    BOOST_CHECK(decoded_header.GetHash() == header.GetHash());
    BOOST_CHECK(decoded_header.auxpow->check(decoded_header.GetHash(), consensus.auxpow.nChainId, consensus));

    CDataStream disk_stream(SER_DISK, PROTOCOL_VERSION);
    CDiskBlockIndex disk_index(&index);
    disk_stream << disk_index;

    CDiskBlockIndex decoded_disk_index;
    disk_stream >> decoded_disk_index;

    BOOST_REQUIRE(decoded_disk_index.auxpow);
}

BOOST_AUTO_TEST_SUITE_END()
