// Copyright (c) 2026 The zkCoin developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_LAUNCHPROFILE_H
#define BITCOIN_LAUNCHPROFILE_H

#include <stdint.h>

class CChainParams;

struct PublicNetworkIdentityStatus {
    bool inherited_litecoin_message_start{false};
    bool inherited_litecoin_default_port{false};
    bool inherited_litecoin_dns_seed{false};
    bool fixed_seeds_present{false};
    bool inherited_litecoin_base58_prefixes{false};
    bool inherited_litecoin_bech32_hrp{false};
    bool inherited_litecoin_mweb_hrp{false};
    bool inherited_litecoin_public_identity{false};
    bool configured{false};
};

struct PublicLaunchProfileStatus {
    bool snapshot_configured{false};
    bool auxpow_active_at_launch{false};
    bool chain_id_encodable{false};
    bool chain_id_parent_version_safe{false};
    bool chain_id_configured{false};
    bool script_rules_active_at_launch{false};
    bool shielded_inactive_at_launch{false};
    bool chain_history_clean{false};
    PublicNetworkIdentityStatus public_network_identity;
    bool inherited_litecoin_public_identity{false};
    bool public_network_identity_configured{false};
    bool configured{false};
};

bool AuxPowChainIdAvoidsLitecoinParentVersionRange(uint32_t chain_id);
bool HasLaunchNeutralChainHistory(const CChainParams& chainparams);
bool HasLaunchActiveScriptRules(const CChainParams& chainparams);
PublicNetworkIdentityStatus GetPublicNetworkIdentityStatus(const CChainParams& chainparams);
bool IsInheritedLitecoinPublicNetworkIdentity(const CChainParams& chainparams);
PublicLaunchProfileStatus GetPublicLaunchProfileStatus(const CChainParams& chainparams);
bool HasConfiguredPublicLaunchProfile(const CChainParams& chainparams);

#endif // BITCOIN_LAUNCHPROFILE_H
