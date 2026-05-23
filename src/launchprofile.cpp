// Copyright (c) 2026 The zkCoin developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <launchprofile.h>

#include <chainparams.h>
#include <consensus/params.h>

#include <cstddef>
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

static bool DeploymentAlwaysActiveAtLaunch(const Consensus::BIP9Deployment& deployment)
{
    return deployment.nStartTime == Consensus::BIP9Deployment::ALWAYS_ACTIVE;
}

bool HasLaunchActiveScriptRules(const CChainParams& chainparams)
{
    if (chainparams.IsMockableChain()) {
        // Regtest launch rehearsals are allowed to mock production constants.
        return true;
    }

    const Consensus::Params& consensus = chainparams.GetConsensus();
    return consensus.BIP16Height <= 1 &&
        consensus.BIP34Height <= 1 &&
        consensus.BIP65Height <= 1 &&
        consensus.BIP66Height <= 1 &&
        consensus.CSVHeight <= 1 &&
        consensus.SegwitHeight <= 1 &&
        DeploymentAlwaysActiveAtLaunch(consensus.vDeployments[Consensus::DEPLOYMENT_TAPROOT]);
}

static bool MatchesMessageStart(
    const CMessageHeader::MessageStartChars& message_start,
    unsigned char a,
    unsigned char b,
    unsigned char c,
    unsigned char d)
{
    return message_start[0] == a &&
        message_start[1] == b &&
        message_start[2] == c &&
        message_start[3] == d;
}

static bool MessageStartShapeValid(const CMessageHeader::MessageStartChars& message_start)
{
    bool all_zero = true;
    bool all_ff = true;
    bool all_printable = true;
    for (const unsigned char byte : message_start) {
        all_zero = all_zero && byte == 0x00;
        all_ff = all_ff && byte == 0xff;
        all_printable = all_printable && byte >= 0x20 && byte <= 0x7e;
    }
    return !all_zero && !all_ff && !all_printable;
}

static bool DefaultPortShapeValid(int port)
{
    return port > 1024 && port <= 65535;
}

static bool ContainsLitecoinSeedMarker(const std::string& seed)
{
    return seed.find("litecoin") != std::string::npos ||
        seed.find("thrasher.io") != std::string::npos ||
        seed.find("koin-project.com") != std::string::npos;
}

static bool HasLitecoinDnsSeed(const CChainParams& chainparams)
{
    for (const std::string& seed : chainparams.DNSSeeds()) {
        if (ContainsLitecoinSeedMarker(seed)) {
            return true;
        }
    }
    return false;
}

static bool ReservedDnsSeedSuffix(const std::string& suffix)
{
    return suffix == "example" ||
        suffix == "invalid" ||
        suffix == "local" ||
        suffix == "localhost" ||
        suffix == "test";
}

static bool DnsSeedShapeValid(const std::string& seed)
{
    if (seed.empty() || seed.size() > 253 ||
        seed.front() == '-' || seed.front() == '.' ||
        seed.back() == '-' || seed.back() == '.') {
        return false;
    }

    std::size_t label_count = 1;
    std::size_t label_length = 0;
    std::size_t final_label_start = 0;
    bool final_label_has_alpha = false;

    for (std::size_t i = 0; i < seed.size(); ++i) {
        const char c = seed[i];
        if ((c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '-') {
            ++label_length;
            if (label_length > 63) {
                return false;
            }
            if (c >= 'a' && c <= 'z') {
                final_label_has_alpha = true;
            }
            continue;
        }
        if (c == '.') {
            if (label_length == 0 ||
                seed[i - 1] == '-' ||
                seed[i + 1] == '-' || seed[i + 1] == '.') {
                return false;
            }
            ++label_count;
            label_length = 0;
            final_label_start = i + 1;
            final_label_has_alpha = false;
            continue;
        }
        return false;
    }

    if (label_count < 2 || !final_label_has_alpha) {
        return false;
    }
    return !ReservedDnsSeedSuffix(seed.substr(final_label_start));
}

static bool DnsSeedsShapeValid(const CChainParams& chainparams)
{
    if (chainparams.DNSSeeds().empty()) {
        return false;
    }
    for (const std::string& seed : chainparams.DNSSeeds()) {
        if (!DnsSeedShapeValid(seed)) {
            return false;
        }
    }
    return true;
}

static bool HasAnyLitecoinBase58Prefix(const CChainParams& chainparams)
{
    return chainparams.Base58Prefix(CChainParams::PUBKEY_ADDRESS) == std::vector<unsigned char>{48} ||
        chainparams.Base58Prefix(CChainParams::PUBKEY_ADDRESS) == std::vector<unsigned char>{111} ||
        chainparams.Base58Prefix(CChainParams::SCRIPT_ADDRESS) == std::vector<unsigned char>{5} ||
        chainparams.Base58Prefix(CChainParams::SCRIPT_ADDRESS) == std::vector<unsigned char>{196} ||
        chainparams.Base58Prefix(CChainParams::SCRIPT_ADDRESS2) == std::vector<unsigned char>{50} ||
        chainparams.Base58Prefix(CChainParams::SCRIPT_ADDRESS2) == std::vector<unsigned char>{58} ||
        chainparams.Base58Prefix(CChainParams::SECRET_KEY) == std::vector<unsigned char>{176} ||
        chainparams.Base58Prefix(CChainParams::SECRET_KEY) == std::vector<unsigned char>{239} ||
        chainparams.Base58Prefix(CChainParams::EXT_PUBLIC_KEY) == std::vector<unsigned char>{0x04, 0x88, 0xB2, 0x1E} ||
        chainparams.Base58Prefix(CChainParams::EXT_PUBLIC_KEY) == std::vector<unsigned char>{0x04, 0x35, 0x87, 0xCF} ||
        chainparams.Base58Prefix(CChainParams::EXT_SECRET_KEY) == std::vector<unsigned char>{0x04, 0x88, 0xAD, 0xE4} ||
        chainparams.Base58Prefix(CChainParams::EXT_SECRET_KEY) == std::vector<unsigned char>{0x04, 0x35, 0x83, 0x94};
}

static std::vector<std::vector<unsigned char>> PublicBase58Prefixes(const CChainParams& chainparams)
{
    return {
        chainparams.Base58Prefix(CChainParams::PUBKEY_ADDRESS),
        chainparams.Base58Prefix(CChainParams::SCRIPT_ADDRESS),
        chainparams.Base58Prefix(CChainParams::SCRIPT_ADDRESS2),
        chainparams.Base58Prefix(CChainParams::SECRET_KEY),
        chainparams.Base58Prefix(CChainParams::EXT_PUBLIC_KEY),
        chainparams.Base58Prefix(CChainParams::EXT_SECRET_KEY),
    };
}

static bool Base58PrefixesShapeValid(const CChainParams& chainparams)
{
    return chainparams.Base58Prefix(CChainParams::PUBKEY_ADDRESS).size() == 1 &&
        chainparams.Base58Prefix(CChainParams::SCRIPT_ADDRESS).size() == 1 &&
        chainparams.Base58Prefix(CChainParams::SCRIPT_ADDRESS2).size() == 1 &&
        chainparams.Base58Prefix(CChainParams::SECRET_KEY).size() == 1 &&
        chainparams.Base58Prefix(CChainParams::EXT_PUBLIC_KEY).size() == 4 &&
        chainparams.Base58Prefix(CChainParams::EXT_SECRET_KEY).size() == 4;
}

static bool Base58PrefixesUnique(const CChainParams& chainparams)
{
    const std::vector<std::vector<unsigned char>> prefixes = PublicBase58Prefixes(chainparams);
    for (std::size_t i = 0; i < prefixes.size(); ++i) {
        for (std::size_t j = i + 1; j < prefixes.size(); ++j) {
            if (prefixes[i] == prefixes[j]) {
                return false;
            }
        }
    }
    return true;
}

static bool HrpShapeValid(const std::string& hrp)
{
    if (hrp.empty()) {
        return false;
    }
    for (const char c : hrp) {
        if (c < 0x21 || c > 0x7e || (c >= 'A' && c <= 'Z')) {
            return false;
        }
    }
    return true;
}

PublicNetworkIdentityStatus GetPublicNetworkIdentityStatus(const CChainParams& chainparams)
{
    PublicNetworkIdentityStatus status;
    if (chainparams.IsMockableChain()) {
        status.message_start_shape_valid = true;
        status.default_port_shape_valid = true;
        status.dns_seeds_shape_valid = true;
        status.base58_prefixes_shape_valid = true;
        status.base58_prefixes_unique = true;
        status.bech32_hrp_shape_valid = true;
        status.mweb_hrp_shape_valid = true;
        status.hrps_unique = true;
        status.configured = true;
        return status;
    }

    const auto& message_start = chainparams.MessageStart();
    status.message_start_shape_valid = MessageStartShapeValid(message_start);
    status.inherited_litecoin_message_start =
        MatchesMessageStart(message_start, 0xfb, 0xc0, 0xb6, 0xdb) ||
        MatchesMessageStart(message_start, 0xfd, 0xd2, 0xc8, 0xf1);
    status.default_port_shape_valid = DefaultPortShapeValid(chainparams.GetDefaultPort());
    status.inherited_litecoin_default_port =
        chainparams.GetDefaultPort() == 9333 ||
        chainparams.GetDefaultPort() == 19335;
    status.dns_seeds_shape_valid = DnsSeedsShapeValid(chainparams);
    status.inherited_litecoin_dns_seed = HasLitecoinDnsSeed(chainparams);
    status.fixed_seeds_present = !chainparams.FixedSeeds().empty();
    status.base58_prefixes_shape_valid = Base58PrefixesShapeValid(chainparams);
    status.base58_prefixes_unique = Base58PrefixesUnique(chainparams);
    status.inherited_litecoin_base58_prefixes = HasAnyLitecoinBase58Prefix(chainparams);
    status.bech32_hrp_shape_valid = HrpShapeValid(chainparams.Bech32HRP());
    status.inherited_litecoin_bech32_hrp =
        chainparams.Bech32HRP() == "ltc" ||
        chainparams.Bech32HRP() == "tltc";
    status.mweb_hrp_shape_valid = HrpShapeValid(chainparams.MWEB_HRP());
    status.inherited_litecoin_mweb_hrp =
        chainparams.MWEB_HRP() == "ltcmweb" ||
        chainparams.MWEB_HRP() == "tmweb";
    status.hrps_unique = chainparams.Bech32HRP() != chainparams.MWEB_HRP();
    status.inherited_litecoin_public_identity =
        status.inherited_litecoin_message_start ||
        status.inherited_litecoin_default_port ||
        status.inherited_litecoin_dns_seed ||
        status.fixed_seeds_present ||
        status.inherited_litecoin_base58_prefixes ||
        status.inherited_litecoin_bech32_hrp ||
        status.inherited_litecoin_mweb_hrp;
    status.configured =
        !status.inherited_litecoin_public_identity &&
        status.message_start_shape_valid &&
        status.default_port_shape_valid &&
        status.dns_seeds_shape_valid &&
        status.base58_prefixes_shape_valid &&
        status.base58_prefixes_unique &&
        status.bech32_hrp_shape_valid &&
        status.mweb_hrp_shape_valid &&
        status.hrps_unique;
    return status;
}

std::vector<std::string> GetPublicNetworkIdentityFailures(const PublicNetworkIdentityStatus& status)
{
    std::vector<std::string> failures;
    if (!status.message_start_shape_valid) {
        failures.emplace_back("P2P message start has an invalid public-network shape");
    }
    if (status.inherited_litecoin_message_start) {
        failures.emplace_back("P2P message start still matches Litecoin");
    }
    if (!status.default_port_shape_valid) {
        failures.emplace_back("default P2P port is missing or reserved");
    }
    if (status.inherited_litecoin_default_port) {
        failures.emplace_back("default P2P port still matches Litecoin");
    }
    if (!status.dns_seeds_shape_valid) {
        failures.emplace_back("DNS seed list is empty or contains malformed hostnames");
    }
    if (status.inherited_litecoin_dns_seed) {
        failures.emplace_back("DNS seed list still references Litecoin infrastructure");
    }
    if (status.fixed_seeds_present) {
        failures.emplace_back("fixed seed list is present and must be regenerated or cleared");
    }
    if (!status.base58_prefixes_shape_valid) {
        failures.emplace_back("Base58 prefixes have invalid public-network lengths");
    }
    if (!status.base58_prefixes_unique) {
        failures.emplace_back("Base58 prefixes contain duplicate byte sequences");
    }
    if (status.inherited_litecoin_base58_prefixes) {
        failures.emplace_back("Base58 prefixes still match Litecoin");
    }
    if (!status.bech32_hrp_shape_valid) {
        failures.emplace_back("Bech32 HRP is empty or malformed");
    }
    if (status.inherited_litecoin_bech32_hrp) {
        failures.emplace_back("Bech32 HRP still matches Litecoin");
    }
    if (!status.mweb_hrp_shape_valid) {
        failures.emplace_back("MWEB HRP is empty or malformed");
    }
    if (status.inherited_litecoin_mweb_hrp) {
        failures.emplace_back("MWEB HRP still matches Litecoin");
    }
    if (!status.hrps_unique) {
        failures.emplace_back("Bech32 and MWEB HRPs must be distinct");
    }
    return failures;
}

bool IsInheritedLitecoinPublicNetworkIdentity(const CChainParams& chainparams)
{
    return GetPublicNetworkIdentityStatus(chainparams).inherited_litecoin_public_identity;
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
    status.chain_id_strict = consensus.auxpow.fStrictChainId;
    status.chain_id_configured = status.chain_id_encodable &&
        status.chain_id_parent_version_safe &&
        consensus.auxpow.fStrictChainId;
    status.script_rules_active_at_launch = HasLaunchActiveScriptRules(chainparams);
    status.shielded_inactive_at_launch = !consensus.shielded_pool.IsEnabled(1);
    status.chain_history_clean = HasLaunchNeutralChainHistory(chainparams);
    status.public_network_identity = GetPublicNetworkIdentityStatus(chainparams);
    status.inherited_litecoin_public_identity = status.public_network_identity.inherited_litecoin_public_identity;
    status.public_network_identity_configured = status.public_network_identity.configured;
    status.configured = status.snapshot_configured &&
        status.auxpow_active_at_launch &&
        status.chain_id_configured &&
        status.script_rules_active_at_launch &&
        status.shielded_inactive_at_launch &&
        status.chain_history_clean &&
        status.public_network_identity_configured;
    return status;
}

std::vector<std::string> GetPublicLaunchProfileFailures(
    const PublicLaunchProfileStatus& status,
    bool snapshot_imported,
    bool at_launch_tip)
{
    std::vector<std::string> failures;
    if (!status.snapshot_configured) {
        failures.emplace_back("snapshot consensus parameters are not configured");
    }
    if (!snapshot_imported) {
        failures.emplace_back("configured snapshot has not been imported");
    }
    if (!status.auxpow_active_at_launch) {
        failures.emplace_back("AuxPoW is not active for the first launch block");
    }
    if (!status.chain_id_encodable || !status.chain_id_strict) {
        failures.emplace_back("AuxPoW chain id is not configured for strict merge mining");
    }
    if (status.chain_id_encodable && !status.chain_id_parent_version_safe) {
        failures.emplace_back("AuxPoW chain id overlaps Litecoin parent versionbits chain-id range");
    }
    if (!status.script_rules_active_at_launch) {
        failures.emplace_back("script validation rules are not active for the first launch block");
    }
    if (!status.shielded_inactive_at_launch) {
        failures.emplace_back("shielded pool is active in the first launch block");
    }
    if (!status.chain_history_clean) {
        failures.emplace_back("inherited Litecoin chain history assumptions are not cleared");
    }
    if (!status.public_network_identity_configured) {
        failures.emplace_back("public network identity is inherited from Litecoin or malformed");
    }
    if (!at_launch_tip) {
        failures.emplace_back("node is not at the genesis launch tip");
    }
    return failures;
}

bool HasConfiguredPublicLaunchProfile(const CChainParams& chainparams)
{
    return GetPublicLaunchProfileStatus(chainparams).configured;
}
