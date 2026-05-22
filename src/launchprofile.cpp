// Copyright (c) 2026 The zkCoin developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <launchprofile.h>

#include <chainparams.h>
#include <consensus/params.h>

#include <string>
#include <vector>

bool AuxPowChainIdAvoidsLitecoinParentVersionRange(uint32_t chain_id)
{
    // BIP9 parent versions with top bits 0x20000000 decode as AuxPoW chain ids 0x2000-0x3fff.
    return chain_id < 0x2000 || chain_id > 0x3fff;
}

bool HasLaunchNeutralChainHistory(const CChainParams& chainparams)
{
    const Consensus::Params& consensus = chainparams.GetConsensus();
    const ChainTxData& tx_data = chainparams.TxData();
    const MapCheckpoints& checkpoints = chainparams.Checkpoints().mapCheckpoints;
    const bool checkpoints_launch_neutral = checkpoints.empty() ||
        (checkpoints.size() == 1 &&
            checkpoints.begin()->first == 0 &&
            checkpoints.begin()->second == chainparams.GenesisBlock().GetHash());
    return consensus.nMinimumChainWork.IsNull() &&
        consensus.defaultAssumeValid.IsNull() &&
        checkpoints_launch_neutral &&
        tx_data.nTime == 0 &&
        tx_data.nTxCount == 0 &&
        tx_data.dTxRate == 0;
}

bool IsInheritedLitecoinPublicNetworkIdentity(const CChainParams& chainparams)
{
    const auto& message_start = chainparams.MessageStart();
    const bool litecoin_main_message =
        message_start[0] == 0xfb &&
        message_start[1] == 0xc0 &&
        message_start[2] == 0xb6 &&
        message_start[3] == 0xdb;
    const bool litecoin_testnet_message =
        message_start[0] == 0xfd &&
        message_start[1] == 0xd2 &&
        message_start[2] == 0xc8 &&
        message_start[3] == 0xf1;
    const bool litecoin_main_address =
        chainparams.Bech32HRP() == "ltc" &&
        chainparams.Base58Prefix(CChainParams::PUBKEY_ADDRESS) == std::vector<unsigned char>{48} &&
        chainparams.Base58Prefix(CChainParams::SCRIPT_ADDRESS) == std::vector<unsigned char>{5} &&
        chainparams.Base58Prefix(CChainParams::SECRET_KEY) == std::vector<unsigned char>{176};
    const bool litecoin_testnet_address =
        chainparams.Bech32HRP() == "tltc" &&
        chainparams.Base58Prefix(CChainParams::PUBKEY_ADDRESS) == std::vector<unsigned char>{111} &&
        chainparams.Base58Prefix(CChainParams::SCRIPT_ADDRESS) == std::vector<unsigned char>{196} &&
        chainparams.Base58Prefix(CChainParams::SECRET_KEY) == std::vector<unsigned char>{239};
    const bool litecoin_ports = chainparams.GetDefaultPort() == 9333 || chainparams.GetDefaultPort() == 19335;
    bool litecoin_dns_seed = false;
    for (const std::string& seed : chainparams.DNSSeeds()) {
        litecoin_dns_seed = litecoin_dns_seed ||
            seed == "seed-a.litecoin.loshan.co.uk" ||
            seed == "dnsseed.thrasher.io" ||
            seed == "dnsseed.litecointools.com" ||
            seed == "dnsseed.litecoinpool.org" ||
            seed == "dnsseed-testnet.thrasher.io" ||
            seed == "testnet-seed.litecointools.com" ||
            seed == "seed-b.litecoin.loshan.co.uk";
    }
    return litecoin_main_message ||
        litecoin_testnet_message ||
        litecoin_main_address ||
        litecoin_testnet_address ||
        litecoin_ports ||
        litecoin_dns_seed ||
        !chainparams.FixedSeeds().empty();
}

PublicLaunchProfileStatus GetPublicLaunchProfileStatus(const CChainParams& chainparams)
{
    const Consensus::Params& consensus = chainparams.GetConsensus();
    PublicLaunchProfileStatus status;
    status.snapshot_configured = consensus.ltc_snapshot.IsEnabled() &&
        !consensus.ltc_snapshot.hashBlock.IsNull() &&
        !consensus.ltc_snapshot.hashUTXORoot.IsNull();
    status.auxpow_active_at_launch = consensus.auxpow.IsEnabled(1);
    status.chain_id_encodable = consensus.auxpow.nChainId != 0 &&
        consensus.auxpow.nChainId < 0x8000;
    status.chain_id_parent_version_safe = AuxPowChainIdAvoidsLitecoinParentVersionRange(consensus.auxpow.nChainId);
    status.chain_id_configured = status.chain_id_encodable &&
        status.chain_id_parent_version_safe &&
        consensus.auxpow.fStrictChainId;
    status.shielded_inactive_at_launch = !consensus.shielded_pool.IsEnabled(1);
    status.chain_history_clean = HasLaunchNeutralChainHistory(chainparams);
    status.inherited_litecoin_public_identity = IsInheritedLitecoinPublicNetworkIdentity(chainparams);
    status.public_network_identity_configured = !status.inherited_litecoin_public_identity;
    status.configured = status.snapshot_configured &&
        status.auxpow_active_at_launch &&
        status.chain_id_configured &&
        status.shielded_inactive_at_launch &&
        status.chain_history_clean &&
        status.public_network_identity_configured;
    return status;
}

bool HasConfiguredPublicLaunchProfile(const CChainParams& chainparams)
{
    return GetPublicLaunchProfileStatus(chainparams).configured;
}
