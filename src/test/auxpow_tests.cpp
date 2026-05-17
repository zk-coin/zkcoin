// Copyright (c) 2026 The zkCoin developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <auxpow.h>
#include <chain.h>
#include <chainparams.h>
#include <consensus/merkle.h>
#include <hash.h>
#include <pow.h>
#include <primitives/block.h>
#include <streams.h>
#include <test/util/setup_common.h>
#include <version.h>

#include <boost/test/unit_test.hpp>

#include <algorithm>

namespace {
std::vector<unsigned char> BuildAuxPowCommitmentBytes(
    const uint256& hashAuxBlock,
    bool includeMergedMiningHeader = false,
    unsigned int leadingPadding = 0,
    uint32_t chainSize = 1,
    uint32_t nonce = 0)
{
    std::vector<unsigned char> commitment(leadingPadding, 0);
    if (includeMergedMiningHeader) {
        commitment.insert(commitment.end(), PCH_MERGED_MINING_HEADER, PCH_MERGED_MINING_HEADER + sizeof(PCH_MERGED_MINING_HEADER));
    }

    std::vector<unsigned char> auxBlockHash(hashAuxBlock.begin(), hashAuxBlock.end());
    std::reverse(auxBlockHash.begin(), auxBlockHash.end());
    commitment.insert(commitment.end(), auxBlockHash.begin(), auxBlockHash.end());
    for (int i = 0; i < 4; ++i) {
        commitment.push_back((chainSize >> (8 * i)) & 0xff);
    }
    for (int i = 0; i < 4; ++i) {
        commitment.push_back((nonce >> (8 * i)) & 0xff);
    }
    return commitment;
}

uint256 CalcAuxPowMerkleRootForTest(uint256 hash, const std::vector<uint256>& branch, int index)
{
    for (const uint256& branchHash : branch) {
        if (index & 1) {
            hash = Hash(branchHash, hash);
        } else {
            hash = Hash(hash, branchHash);
        }
        index >>= 1;
    }
    return hash;
}

CAuxPow DeserializeAuxPowForParentTx(
    const CTransactionRef& parentTx,
    const CPureBlockHeader& parentHeader,
    int txIndex = 0,
    std::vector<uint256> merkleBranch = {},
    std::vector<uint256> chainMerkleBranch = {},
    int chainIndex = 0)
{
    CDataStream stream(SER_NETWORK, PROTOCOL_VERSION);
    const uint256 hashBlock;

    stream << parentTx << hashBlock << merkleBranch << txIndex;
    stream << chainMerkleBranch << chainIndex << parentHeader;

    CAuxPow auxpow;
    stream >> auxpow;
    return auxpow;
}

CBlockHeader MakeAuxPowChildHeader(const char* prev_hex, const char* merkle_hex)
{
    CBlockHeader header;
    header.nVersion = 1;
    header.nTime = 1;
    header.nBits = 0x207fffff;
    header.nNonce = 0;
    header.hashPrevBlock.SetHex(prev_hex);
    header.hashMerkleRoot.SetHex(merkle_hex);
    header.SetAuxpowVersion(true);
    return header;
}

CTransactionRef MakeCoinbaseWithCommitment(const std::vector<unsigned char>& commitment)
{
    CMutableTransaction coinbase;
    coinbase.vin.resize(1);
    coinbase.vin[0].prevout.SetNull();
    coinbase.vin[0].scriptSig = CScript() << commitment;
    coinbase.vout.resize(1);
    coinbase.vout[0].scriptPubKey = CScript() << OP_TRUE;
    return MakeTransactionRef(coinbase);
}

bool CheckAuxPowCommitment(const CBlockHeader& header, const std::vector<unsigned char>& commitment, const Consensus::Params& consensus)
{
    CTransactionRef coinbaseRef = MakeCoinbaseWithCommitment(commitment);

    CPureBlockHeader parent;
    parent.nVersion = 1;
    parent.nTime = 1;
    parent.nBits = 0x207fffff;
    parent.nNonce = 0;
    parent.hashMerkleRoot = coinbaseRef->GetHash();

    CAuxPow auxpow = DeserializeAuxPowForParentTx(coinbaseRef, parent);
    return auxpow.check(header.GetHash(), consensus.auxpow.nChainId, consensus);
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

BOOST_AUTO_TEST_CASE(auxpow_rejects_ambiguous_parent_commitments)
{
    const Consensus::Params& consensus = Params().GetConsensus();
    CBlockHeader header = MakeAuxPowChildHeader("10", "11");

    BOOST_CHECK(CheckAuxPowCommitment(header, BuildAuxPowCommitmentBytes(header.GetHash(), false), consensus));
    BOOST_CHECK(CheckAuxPowCommitment(header, BuildAuxPowCommitmentBytes(header.GetHash(), true), consensus));

    std::vector<unsigned char> duplicate_header = BuildAuxPowCommitmentBytes(header.GetHash(), true);
    duplicate_header.insert(duplicate_header.end(), PCH_MERGED_MINING_HEADER, PCH_MERGED_MINING_HEADER + sizeof(PCH_MERGED_MINING_HEADER));
    BOOST_CHECK(!CheckAuxPowCommitment(header, duplicate_header, consensus));

    std::vector<unsigned char> separated_header(PCH_MERGED_MINING_HEADER, PCH_MERGED_MINING_HEADER + sizeof(PCH_MERGED_MINING_HEADER));
    separated_header.push_back(0);
    const std::vector<unsigned char> legacy_commitment = BuildAuxPowCommitmentBytes(header.GetHash(), false);
    separated_header.insert(separated_header.end(), legacy_commitment.begin(), legacy_commitment.end());
    BOOST_CHECK(!CheckAuxPowCommitment(header, separated_header, consensus));

    uint256 wrong_hash;
    wrong_hash.SetHex("12");
    std::vector<unsigned char> wrong_tagged_root = BuildAuxPowCommitmentBytes(wrong_hash, true);
    wrong_tagged_root.insert(wrong_tagged_root.end(), legacy_commitment.begin(), legacy_commitment.end());
    BOOST_CHECK(!CheckAuxPowCommitment(header, wrong_tagged_root, consensus));
}

BOOST_AUTO_TEST_CASE(auxpow_rejects_tampered_parent_merkle_proof)
{
    const Consensus::Params& consensus = Params().GetConsensus();
    CBlockHeader header = MakeAuxPowChildHeader("13", "14");

    CTransactionRef coinbaseRef = MakeCoinbaseWithCommitment(BuildAuxPowCommitmentBytes(header.GetHash(), true));

    uint256 prevoutHash;
    prevoutHash.SetHex("15");
    CMutableTransaction tx;
    tx.vin.resize(1);
    tx.vin[0].prevout = COutPoint(prevoutHash, 0);
    tx.vout.resize(1);
    tx.vout[0].scriptPubKey = CScript() << OP_TRUE;
    CTransactionRef txRef = MakeTransactionRef(tx);

    CBlock parentBlock;
    parentBlock.nVersion = 1;
    parentBlock.nTime = 1;
    parentBlock.nBits = 0x207fffff;
    parentBlock.nNonce = 0;
    parentBlock.vtx = {coinbaseRef, txRef};
    parentBlock.hashMerkleRoot = BlockMerkleRoot(parentBlock);

    std::vector<uint256> merkleBranch{txRef->GetHash()};
    CAuxPow validAuxpow = DeserializeAuxPowForParentTx(coinbaseRef, parentBlock.GetBlockHeader(), 0, merkleBranch);
    BOOST_CHECK(validAuxpow.check(header.GetHash(), consensus.auxpow.nChainId, consensus));

    std::vector<uint256> badMerkleBranch{coinbaseRef->GetHash()};
    CAuxPow badBranchAuxpow = DeserializeAuxPowForParentTx(coinbaseRef, parentBlock.GetBlockHeader(), 0, badMerkleBranch);
    BOOST_CHECK(!badBranchAuxpow.check(header.GetHash(), consensus.auxpow.nChainId, consensus));

    CBlockHeader badParentHeader = parentBlock.GetBlockHeader();
    badParentHeader.hashMerkleRoot.SetHex("16");
    CAuxPow badRootAuxpow = DeserializeAuxPowForParentTx(coinbaseRef, badParentHeader, 0, merkleBranch);
    BOOST_CHECK(!badRootAuxpow.check(header.GetHash(), consensus.auxpow.nChainId, consensus));
}

BOOST_AUTO_TEST_CASE(auxpow_validates_chain_merkle_branch_metadata)
{
    const Consensus::Params& consensus = Params().GetConsensus();
    CBlockHeader header = MakeAuxPowChildHeader("1a", "1b");

    uint256 branchHash;
    branchHash.SetHex("1c");
    const std::vector<uint256> chainMerkleBranch{branchHash};
    const uint32_t nonce = 0;
    const int chainIndex = CAuxPow::getExpectedIndex(nonce, consensus.auxpow.nChainId, chainMerkleBranch.size());
    const uint256 root = CalcAuxPowMerkleRootForTest(header.GetHash(), chainMerkleBranch, chainIndex);

    CTransactionRef coinbaseRef = MakeCoinbaseWithCommitment(BuildAuxPowCommitmentBytes(root, true, 0, 1u << chainMerkleBranch.size(), nonce));
    CPureBlockHeader parent;
    parent.nVersion = 1;
    parent.nTime = 1;
    parent.nBits = 0x207fffff;
    parent.nNonce = 0;
    parent.hashMerkleRoot = coinbaseRef->GetHash();

    CAuxPow validAuxpow = DeserializeAuxPowForParentTx(coinbaseRef, parent, 0, {}, chainMerkleBranch, chainIndex);
    BOOST_CHECK(validAuxpow.check(header.GetHash(), consensus.auxpow.nChainId, consensus));

    CAuxPow wrongIndexAuxpow = DeserializeAuxPowForParentTx(coinbaseRef, parent, 0, {}, chainMerkleBranch, chainIndex ^ 1);
    BOOST_CHECK(!wrongIndexAuxpow.check(header.GetHash(), consensus.auxpow.nChainId, consensus));

    uint32_t wrongNonce = nonce + 1;
    while (CAuxPow::getExpectedIndex(wrongNonce, consensus.auxpow.nChainId, chainMerkleBranch.size()) == chainIndex) {
        ++wrongNonce;
    }
    CTransactionRef wrongNonceCoinbase = MakeCoinbaseWithCommitment(BuildAuxPowCommitmentBytes(root, true, 0, 1u << chainMerkleBranch.size(), wrongNonce));
    parent.hashMerkleRoot = wrongNonceCoinbase->GetHash();
    CAuxPow wrongNonceAuxpow = DeserializeAuxPowForParentTx(wrongNonceCoinbase, parent, 0, {}, chainMerkleBranch, chainIndex);
    BOOST_CHECK(!wrongNonceAuxpow.check(header.GetHash(), consensus.auxpow.nChainId, consensus));

    CTransactionRef wrongSizeCoinbase = MakeCoinbaseWithCommitment(BuildAuxPowCommitmentBytes(root, true, 0, 1, nonce));
    parent.hashMerkleRoot = wrongSizeCoinbase->GetHash();
    CAuxPow wrongSizeAuxpow = DeserializeAuxPowForParentTx(wrongSizeCoinbase, parent, 0, {}, chainMerkleBranch, chainIndex);
    BOOST_CHECK(!wrongSizeAuxpow.check(header.GetHash(), consensus.auxpow.nChainId, consensus));

    std::vector<uint256> maxChainMerkleBranch(30, branchHash);
    const int maxChainIndex = CAuxPow::getExpectedIndex(nonce, consensus.auxpow.nChainId, maxChainMerkleBranch.size());
    const uint256 maxRoot = CalcAuxPowMerkleRootForTest(header.GetHash(), maxChainMerkleBranch, maxChainIndex);
    CTransactionRef maxBranchCoinbase = MakeCoinbaseWithCommitment(BuildAuxPowCommitmentBytes(maxRoot, true, 0, 1u << maxChainMerkleBranch.size(), nonce));
    parent.hashMerkleRoot = maxBranchCoinbase->GetHash();
    CAuxPow maxBranchAuxpow = DeserializeAuxPowForParentTx(maxBranchCoinbase, parent, 0, {}, maxChainMerkleBranch, maxChainIndex);
    BOOST_CHECK(maxBranchAuxpow.check(header.GetHash(), consensus.auxpow.nChainId, consensus));

    std::vector<uint256> tooLongChainMerkleBranch(31, branchHash);
    CAuxPow tooLongBranchAuxpow = DeserializeAuxPowForParentTx(maxBranchCoinbase, parent, 0, {}, tooLongChainMerkleBranch, maxChainIndex);
    BOOST_CHECK(!tooLongBranchAuxpow.check(header.GetHash(), consensus.auxpow.nChainId, consensus));
}

BOOST_AUTO_TEST_CASE(auxpow_rejects_replayed_parent_work_for_mutated_child_header)
{
    CBlockHeader header;
    header.nVersion = 1;
    header.nTime = 1;
    header.nBits = 0x207fffff;
    header.nNonce = 0;
    header.hashPrevBlock.SetHex("17");
    header.hashMerkleRoot.SetHex("18");
    const auto chainParams = CreateChainParams(*m_node.args, CBaseChainParams::REGTEST);
    const Consensus::Params& consensus = chainParams->GetConsensus();
    header.SetChainId(consensus.auxpow.nChainId);

    CPureBlockHeader& parent = CAuxPow::initAuxPow(header);
    while (!CheckProofOfWork(parent.GetPoWHash(), header.nBits, consensus) && parent.nNonce < 100000) {
        ++parent.nNonce;
    }

    BOOST_REQUIRE(header.auxpow);
    BOOST_REQUIRE(CheckBlockProofOfWork(header, consensus));

    header.hashMerkleRoot.SetHex("19");
    BOOST_CHECK(!header.auxpow->check(header.GetHash(), consensus.auxpow.nChainId, consensus));
    BOOST_CHECK(!CheckBlockProofOfWork(header, consensus));
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
