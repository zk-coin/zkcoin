// Copyright (c) 2015-2019 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <chain.h>
#include <chainparams.h>
#include <launchprofile.h>
#include <pow.h>
#include <test/util/setup_common.h>
#include <util/system.h>

#include <boost/test/unit_test.hpp>

BOOST_FIXTURE_TEST_SUITE(pow_tests, BasicTestingSetup)

/* Test calculation of next difficulty target with no constraints applying */
BOOST_AUTO_TEST_CASE(get_next_work)
{
    const auto chainParams = CreateChainParams(*m_node.args, CBaseChainParams::MAIN);
    int64_t nLastRetargetTime = 1358118740; // Block #30240
    CBlockIndex pindexLast;
    pindexLast.nHeight = 280223;
    pindexLast.nTime = 1358378777;  // Block #280223
    pindexLast.nBits = 0x1c0ac141;
    BOOST_CHECK_EQUAL(CalculateNextWorkRequired(&pindexLast, nLastRetargetTime, chainParams->GetConsensus()), 0x1c093f8dU);
}

/* Test the constraint on the upper bound for next work */
BOOST_AUTO_TEST_CASE(get_next_work_pow_limit)
{
    const auto chainParams = CreateChainParams(*m_node.args, CBaseChainParams::MAIN);
    int64_t nLastRetargetTime = 1317972665; // Block #0
    CBlockIndex pindexLast;
    pindexLast.nHeight = 2015;
    pindexLast.nTime = 1318480354;  // Block #2015
    pindexLast.nBits = 0x1e0ffff0;
    BOOST_CHECK_EQUAL(CalculateNextWorkRequired(&pindexLast, nLastRetargetTime, chainParams->GetConsensus()), 0x1e0fffffU);
}

/* Test the constraint on the lower bound for actual time taken */
BOOST_AUTO_TEST_CASE(get_next_work_lower_limit_actual)
{
    const auto chainParams = CreateChainParams(*m_node.args, CBaseChainParams::MAIN);
    int64_t nLastRetargetTime = 1401682934; // Block #66528
    CBlockIndex pindexLast;
    pindexLast.nHeight = 578591;
    pindexLast.nTime = 1401757934;  // Block #578591
    pindexLast.nBits = 0x1b075cf1;
    BOOST_CHECK_EQUAL(CalculateNextWorkRequired(&pindexLast, nLastRetargetTime, chainParams->GetConsensus()), 0x1b01d73cU);
}

/* Test the constraint on the upper bound for actual time taken */
BOOST_AUTO_TEST_CASE(get_next_work_upper_limit_actual)
{
    const auto chainParams = CreateChainParams(*m_node.args, CBaseChainParams::MAIN);
    int64_t nLastRetargetTime = 1463690315; // NOTE: Not an actual block time
    CBlockIndex pindexLast;
    pindexLast.nHeight = 1001951;
    pindexLast.nTime = 1464900315;  // Block #46367
    pindexLast.nBits = 0x1b015318;
    BOOST_CHECK_EQUAL(CalculateNextWorkRequired(&pindexLast, nLastRetargetTime, chainParams->GetConsensus()), 0x1b054c60U);
}

BOOST_AUTO_TEST_CASE(CheckProofOfWork_test_negative_target)
{
    const auto consensus = CreateChainParams(*m_node.args, CBaseChainParams::MAIN)->GetConsensus();
    uint256 hash;
    unsigned int nBits;
    nBits = UintToArith256(consensus.powLimit).GetCompact(true);
    hash.SetHex("0x1");
    BOOST_CHECK(!CheckProofOfWork(hash, nBits, consensus));
}

BOOST_AUTO_TEST_CASE(CheckProofOfWork_test_overflow_target)
{
    const auto consensus = CreateChainParams(*m_node.args, CBaseChainParams::MAIN)->GetConsensus();
    uint256 hash;
    unsigned int nBits = ~0x00800000;
    hash.SetHex("0x1");
    BOOST_CHECK(!CheckProofOfWork(hash, nBits, consensus));
}

BOOST_AUTO_TEST_CASE(CheckProofOfWork_test_too_easy_target)
{
    const auto consensus = CreateChainParams(*m_node.args, CBaseChainParams::MAIN)->GetConsensus();
    uint256 hash;
    unsigned int nBits;
    arith_uint256 nBits_arith = UintToArith256(consensus.powLimit);
    nBits_arith *= 2;
    nBits = nBits_arith.GetCompact();
    hash.SetHex("0x1");
    BOOST_CHECK(!CheckProofOfWork(hash, nBits, consensus));
}

BOOST_AUTO_TEST_CASE(CheckProofOfWork_test_biger_hash_than_target)
{
    const auto consensus = CreateChainParams(*m_node.args, CBaseChainParams::MAIN)->GetConsensus();
    uint256 hash;
    unsigned int nBits;
    arith_uint256 hash_arith = UintToArith256(consensus.powLimit);
    nBits = hash_arith.GetCompact();
    hash_arith *= 2; // hash > nBits
    hash = ArithToUint256(hash_arith);
    BOOST_CHECK(!CheckProofOfWork(hash, nBits, consensus));
}

BOOST_AUTO_TEST_CASE(CheckProofOfWork_test_zero_target)
{
    const auto consensus = CreateChainParams(*m_node.args, CBaseChainParams::MAIN)->GetConsensus();
    uint256 hash;
    unsigned int nBits;
    arith_uint256 hash_arith{0};
    nBits = hash_arith.GetCompact();
    hash = ArithToUint256(hash_arith);
    BOOST_CHECK(!CheckProofOfWork(hash, nBits, consensus));
}

BOOST_AUTO_TEST_CASE(GetBlockProofEquivalentTime_test)
{
    const auto chainParams = CreateChainParams(*m_node.args, CBaseChainParams::MAIN);
    std::vector<CBlockIndex> blocks(10000);
    for (int i = 0; i < 10000; i++) {
        blocks[i].pprev = i ? &blocks[i - 1] : nullptr;
        blocks[i].nHeight = i;
        blocks[i].nTime = 1269211443 + i * chainParams->GetConsensus().nPowTargetSpacing;
        blocks[i].nBits = 0x207fffff; /* target 0x7fffff000... */
        blocks[i].nChainWork = i ? blocks[i - 1].nChainWork + GetBlockProof(blocks[i - 1]) : arith_uint256(0);
    }

    for (int j = 0; j < 1000; j++) {
        CBlockIndex *p1 = &blocks[InsecureRandRange(10000)];
        CBlockIndex *p2 = &blocks[InsecureRandRange(10000)];
        CBlockIndex *p3 = &blocks[InsecureRandRange(10000)];

        int64_t tdiff = GetBlockProofEquivalentTime(*p1, *p2, *p3, chainParams->GetConsensus());
        BOOST_CHECK_EQUAL(tdiff, p1->GetBlockTime() - p2->GetBlockTime());
    }
}

void sanity_check_chainparams(const ArgsManager& args, std::string chainName)
{
    const auto chainParams = CreateChainParams(args, chainName);
    const auto consensus = chainParams->GetConsensus();

    // hash genesis is correct
    BOOST_CHECK_EQUAL(consensus.hashGenesisBlock, chainParams->GenesisBlock().GetHash());

    // target timespan is an even multiple of spacing
    BOOST_CHECK_EQUAL(consensus.nPowTargetTimespan % consensus.nPowTargetSpacing, 0);

    // genesis nBits is positive, doesn't overflow and is lower than powLimit
    arith_uint256 pow_compact;
    bool neg, over;
    pow_compact.SetCompact(chainParams->GenesisBlock().nBits, &neg, &over);
    BOOST_CHECK(!neg && pow_compact != 0);
    BOOST_CHECK(!over);
    BOOST_CHECK(UintToArith256(consensus.powLimit) >= pow_compact);

    // zkCoin launch parameters are explicit but disabled until block X and
    // AuxPoW activation are locked in.
    BOOST_CHECK(!consensus.ltc_snapshot.IsEnabled());
    BOOST_CHECK(consensus.ltc_snapshot.hashBlock.IsNull());
    BOOST_CHECK(consensus.ltc_snapshot.hashUTXORoot.IsNull());
    BOOST_CHECK(!consensus.auxpow.IsEnabled(0));
    BOOST_CHECK_NE(consensus.auxpow.nChainId, 0U);
    BOOST_CHECK_LT(consensus.auxpow.nChainId, 0x8000U);
    BOOST_CHECK(consensus.nMinimumChainWork.IsNull());
    BOOST_CHECK(consensus.defaultAssumeValid.IsNull());

    const auto& checkpoints = chainParams->Checkpoints().mapCheckpoints;
    BOOST_CHECK(checkpoints.empty() ||
        (checkpoints.size() == 1 &&
            checkpoints.begin()->first == 0 &&
            checkpoints.begin()->second == consensus.hashGenesisBlock));

    const auto& tx_data = chainParams->TxData();
    BOOST_CHECK_EQUAL(tx_data.nTime, 0);
    BOOST_CHECK_EQUAL(tx_data.nTxCount, 0);
    BOOST_CHECK_EQUAL(tx_data.dTxRate, 0);

    // check max target * 4*nPowTargetTimespan doesn't overflow -- see pow.cpp:CalculateNextWorkRequired()
    /* Litecoin: we allow overflowing by 1 bit
    if (!consensus.fPowNoRetargeting) {
        arith_uint256 targ_max("0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF");
        targ_max /= consensus.nPowTargetTimespan*4;
        BOOST_CHECK(UintToArith256(consensus.powLimit) < targ_max);
    }
    */
}

BOOST_AUTO_TEST_CASE(ChainParams_MAIN_sanity)
{
    sanity_check_chainparams(*m_node.args, CBaseChainParams::MAIN);
}

BOOST_AUTO_TEST_CASE(ChainParams_REGTEST_sanity)
{
    sanity_check_chainparams(*m_node.args, CBaseChainParams::REGTEST);
}

BOOST_AUTO_TEST_CASE(ChainParams_TESTNET_sanity)
{
    sanity_check_chainparams(*m_node.args, CBaseChainParams::TESTNET);
}

BOOST_AUTO_TEST_CASE(ChainParams_SIGNET_sanity)
{
    sanity_check_chainparams(*m_node.args, CBaseChainParams::SIGNET);
}

static void check_public_launch_profile_fails_closed(const ArgsManager& args, const std::string& chain_name)
{
    const auto chainParams = CreateChainParams(args, chain_name);
    const PublicLaunchProfileStatus status = GetPublicLaunchProfileStatus(*chainParams);
    const PublicNetworkIdentityStatus identity = GetPublicNetworkIdentityStatus(*chainParams);

    BOOST_CHECK(!HasConfiguredPublicLaunchProfile(*chainParams));
    BOOST_CHECK(!status.configured);
    BOOST_CHECK(!status.snapshot_configured);
    BOOST_CHECK(!status.auxpow_active_at_launch);
    BOOST_CHECK(status.chain_id_encodable);
    BOOST_CHECK(status.chain_id_parent_version_safe);
    BOOST_CHECK(status.chain_id_configured);
    BOOST_CHECK(!status.script_rules_active_at_launch);
    BOOST_CHECK(status.shielded_inactive_at_launch);
    BOOST_CHECK(status.chain_history_clean);
    BOOST_CHECK(status.inherited_litecoin_public_identity);
    BOOST_CHECK(!status.public_network_identity_configured);
    BOOST_CHECK(status.public_network_identity.inherited_litecoin_public_identity);
    BOOST_CHECK(!status.public_network_identity.configured);
    BOOST_CHECK(identity.inherited_litecoin_public_identity);
    BOOST_CHECK(!identity.configured);
    BOOST_CHECK(identity.inherited_litecoin_message_start);
    BOOST_CHECK(identity.message_start_shape_valid);
    BOOST_CHECK(identity.inherited_litecoin_default_port);
    BOOST_CHECK(identity.default_port_shape_valid);
    BOOST_CHECK(identity.inherited_litecoin_dns_seed);
    BOOST_CHECK(identity.dns_seeds_shape_valid);
    BOOST_CHECK(identity.fixed_seeds_present);
    BOOST_CHECK(identity.inherited_litecoin_base58_prefixes);
    BOOST_CHECK(identity.base58_prefixes_shape_valid);
    BOOST_CHECK(identity.base58_prefixes_unique);
    BOOST_CHECK(identity.inherited_litecoin_bech32_hrp);
    BOOST_CHECK(identity.bech32_hrp_shape_valid);
    BOOST_CHECK(identity.inherited_litecoin_mweb_hrp);
    BOOST_CHECK(identity.mweb_hrp_shape_valid);
    BOOST_CHECK(identity.hrps_unique);
    BOOST_CHECK(IsInheritedLitecoinPublicNetworkIdentity(*chainParams));
}

BOOST_AUTO_TEST_CASE(ChainParams_PUBLIC_launch_profile_fails_closed_until_constants)
{
    check_public_launch_profile_fails_closed(*m_node.args, CBaseChainParams::MAIN);
    check_public_launch_profile_fails_closed(*m_node.args, CBaseChainParams::TESTNET);
    check_public_launch_profile_fails_closed(*m_node.args, CBaseChainParams::SIGNET);
}

BOOST_AUTO_TEST_CASE(ChainParams_REGTEST_launch_profile_defaults_are_local_only)
{
    const auto chainParams = CreateChainParams(*m_node.args, CBaseChainParams::REGTEST);
    const PublicLaunchProfileStatus status = GetPublicLaunchProfileStatus(*chainParams);

    BOOST_CHECK(!HasConfiguredPublicLaunchProfile(*chainParams));
    BOOST_CHECK(!status.configured);
    BOOST_CHECK(!status.snapshot_configured);
    BOOST_CHECK(!status.auxpow_active_at_launch);
    BOOST_CHECK(status.chain_id_encodable);
    BOOST_CHECK(status.chain_id_parent_version_safe);
    BOOST_CHECK(status.chain_id_configured);
    BOOST_CHECK(status.script_rules_active_at_launch);
    BOOST_CHECK(status.shielded_inactive_at_launch);
    BOOST_CHECK(status.chain_history_clean);
    BOOST_CHECK(!status.inherited_litecoin_public_identity);
    BOOST_CHECK(status.public_network_identity_configured);
    BOOST_CHECK(!status.public_network_identity.inherited_litecoin_public_identity);
    BOOST_CHECK(status.public_network_identity.configured);
    BOOST_CHECK(!status.public_network_identity.inherited_litecoin_message_start);
    BOOST_CHECK(status.public_network_identity.message_start_shape_valid);
    BOOST_CHECK(!status.public_network_identity.inherited_litecoin_default_port);
    BOOST_CHECK(status.public_network_identity.default_port_shape_valid);
    BOOST_CHECK(!status.public_network_identity.inherited_litecoin_dns_seed);
    BOOST_CHECK(status.public_network_identity.dns_seeds_shape_valid);
    BOOST_CHECK(!status.public_network_identity.fixed_seeds_present);
    BOOST_CHECK(!status.public_network_identity.inherited_litecoin_base58_prefixes);
    BOOST_CHECK(status.public_network_identity.base58_prefixes_shape_valid);
    BOOST_CHECK(status.public_network_identity.base58_prefixes_unique);
    BOOST_CHECK(!status.public_network_identity.inherited_litecoin_bech32_hrp);
    BOOST_CHECK(status.public_network_identity.bech32_hrp_shape_valid);
    BOOST_CHECK(!status.public_network_identity.inherited_litecoin_mweb_hrp);
    BOOST_CHECK(status.public_network_identity.mweb_hrp_shape_valid);
    BOOST_CHECK(status.public_network_identity.hrps_unique);
    BOOST_CHECK(!IsInheritedLitecoinPublicNetworkIdentity(*chainParams));
}

BOOST_AUTO_TEST_CASE(ChainParams_PUBLIC_auxpow_chain_id_parent_version_range)
{
    BOOST_CHECK(AuxPowChainIdAvoidsLitecoinParentVersionRange(0));
    BOOST_CHECK(AuxPowChainIdAvoidsLitecoinParentVersionRange(0x1fff));
    BOOST_CHECK(!AuxPowChainIdAvoidsLitecoinParentVersionRange(0x2000));
    BOOST_CHECK(!AuxPowChainIdAvoidsLitecoinParentVersionRange(0x3fff));
    BOOST_CHECK(AuxPowChainIdAvoidsLitecoinParentVersionRange(0x4000));
    BOOST_CHECK(AuxPowChainIdAvoidsLitecoinParentVersionRange(0x5a4b));
}

BOOST_AUTO_TEST_CASE(ChainParams_REGTEST_auxpow_height)
{
    ArgsManager args;
    args.ForceSetArg("-auxpowheight", "7");

    const auto chainParams = CreateChainParams(args, CBaseChainParams::REGTEST);
    const auto consensus = chainParams->GetConsensus();

    BOOST_CHECK(!consensus.auxpow.IsEnabled(6));
    BOOST_CHECK(consensus.auxpow.IsEnabled(7));
}

BOOST_AUTO_TEST_CASE(ChainParams_REGTEST_auxpow_chain_id_args)
{
    ArgsManager args;
    args.ForceSetArg("-auxpowchainid", "4660");
    args.ForceSetArg("-auxpowstrictchainid", "0");

    const auto chainParams = CreateChainParams(args, CBaseChainParams::REGTEST);
    const auto consensus = chainParams->GetConsensus();

    BOOST_CHECK_EQUAL(consensus.auxpow.nChainId, 4660U);
    BOOST_CHECK(!consensus.auxpow.fStrictChainId);
}

BOOST_AUTO_TEST_CASE(ChainParams_REGTEST_ltc_snapshot_args)
{
    const std::string block_hash{"0000000000000000000000000000000000000000000000000000000000000001"};
    const std::string utxo_root{"0000000000000000000000000000000000000000000000000000000000000002"};

    ArgsManager args;
    args.ForceSetArg("-ltcsnapshotheight", "123");
    args.ForceSetArg("-ltcsnapshotblockhash", block_hash);
    args.ForceSetArg("-ltcsnapshotutxoroot", utxo_root);

    const auto chainParams = CreateChainParams(args, CBaseChainParams::REGTEST);
    const auto consensus = chainParams->GetConsensus();

    BOOST_CHECK(consensus.ltc_snapshot.IsEnabled());
    BOOST_CHECK_EQUAL(consensus.ltc_snapshot.nHeight, 123);
    BOOST_CHECK_EQUAL(consensus.ltc_snapshot.hashBlock.ToString(), block_hash);
    BOOST_CHECK_EQUAL(consensus.ltc_snapshot.hashUTXORoot.ToString(), utxo_root);
}

BOOST_AUTO_TEST_CASE(ChainParams_REGTEST_ltc_snapshot_args_reject_partial)
{
    ArgsManager args;
    args.ForceSetArg("-ltcsnapshotheight", "123");

    BOOST_CHECK_THROW(CreateChainParams(args, CBaseChainParams::REGTEST), std::runtime_error);
}

BOOST_AUTO_TEST_SUITE_END()
