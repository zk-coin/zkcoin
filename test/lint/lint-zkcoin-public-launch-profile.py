#!/usr/bin/env python3
# Copyright (c) 2026 The zkCoin developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Check that public zkCoin launch parameters stay fail-closed."""

from pathlib import Path
import subprocess
import sys


ROOT_DIR = Path(__file__).resolve().parents[2]
CHAINPARAMS = ROOT_DIR / "src" / "chainparams.cpp"
LAUNCHPROFILE = ROOT_DIR / "src" / "launchprofile.cpp"
INIT = ROOT_DIR / "src" / "init.cpp"
POW_TESTS = ROOT_DIR / "src" / "test" / "pow_tests.cpp"
SIGNET_TEST = ROOT_DIR / "test" / "functional" / "feature_signet.py"
LAUNCH_PREFLIGHT = ROOT_DIR / "contrib" / "devtools" / "zkcoin_launch_preflight.sh"
LAUNCH_DOC = ROOT_DIR / "doc" / "zkcoin-merge-mining-snapshot.md"
DNSSEED_POLICY = ROOT_DIR / "doc" / "dnsseed-policy.md"
SEEDS_README = ROOT_DIR / "contrib" / "seeds" / "README.md"
CHAINPARAMS_SEEDS = ROOT_DIR / "src" / "chainparamsseeds.h"
SEEDS_DIR = ROOT_DIR / "contrib" / "seeds"
GENERATE_SEEDS = SEEDS_DIR / "generate-seeds.py"
MAKESEEDS = SEEDS_DIR / "makeseeds.py"
SEED_NODE_FILES = (
    SEEDS_DIR / "nodes_main.txt",
    SEEDS_DIR / "nodes_test.txt",
)


PUBLIC_LAUNCH_FAILURE = (
    "zkCoin public networks are disabled until the production launch profile is hardcoded in chainparams"
)

MAIN_FAIL_CLOSED_MARKERS = (
    ("consensus.BIP34Height = 710000;", "mainnet inherited BIP34 activation height"),
    ("consensus.CSVHeight = 1201536;", "mainnet inherited CSV activation height"),
    ("consensus.SegwitHeight = 1201536;", "mainnet inherited Segwit activation height"),
    ("consensus.ltc_snapshot.nHeight = -1;", "mainnet disabled Litecoin snapshot"),
    ("consensus.auxpow.nStartHeight = -1;", "mainnet disabled AuxPoW"),
    (
        'consensus.auxpow.nChainId = 0x5a4b; // "ZK", encodable in the AuxPoW version field',
        "mainnet placeholder AuxPoW chain id",
    ),
    ("consensus.shielded_pool.nStartHeight = -1;", "mainnet disabled shielded pool"),
    ("consensus.nMinimumChainWork = uint256{};", "mainnet neutral minimum chain work"),
    ("consensus.defaultAssumeValid = uint256{};", "mainnet neutral assumevalid"),
    ("nDefaultPort = 9333;", "mainnet inherited Litecoin port"),
    (
        "// Do not contact inherited Litecoin seed infrastructure before zkCoin-specific seeds exist.",
        "mainnet seed infrastructure disabled",
    ),
    ("vSeeds.clear();", "mainnet DNS seeds cleared"),
    ("vFixedSeeds.clear();", "mainnet fixed seeds cleared"),
    ('bech32_hrp = "ltc";', "mainnet inherited Litecoin bech32 HRP"),
    ('mweb_hrp = "ltcmweb";', "mainnet inherited Litecoin MWEB HRP"),
)

TESTNET_FAIL_CLOSED_MARKERS = (
    ("consensus.BIP34Height = 76;", "testnet inherited BIP34 activation height"),
    ("consensus.CSVHeight = 6048;", "testnet inherited CSV activation height"),
    ("consensus.SegwitHeight = 6048;", "testnet inherited Segwit activation height"),
    ("consensus.ltc_snapshot.nHeight = -1;", "testnet disabled Litecoin snapshot"),
    ("consensus.auxpow.nStartHeight = -1;", "testnet disabled AuxPoW"),
    (
        'consensus.auxpow.nChainId = 0x5a4b; // "ZK", encodable in the AuxPoW version field',
        "testnet placeholder AuxPoW chain id",
    ),
    ("consensus.shielded_pool.nStartHeight = -1;", "testnet disabled shielded pool"),
    ("consensus.nMinimumChainWork = uint256{};", "testnet neutral minimum chain work"),
    ("consensus.defaultAssumeValid = uint256{};", "testnet neutral assumevalid"),
    ("nDefaultPort = 19335;", "testnet inherited Litecoin port"),
    (
        "// Do not contact inherited Litecoin seed infrastructure before zkCoin-specific seeds exist.",
        "testnet seed infrastructure disabled",
    ),
    ("vSeeds.clear();", "testnet DNS seeds cleared"),
    ("vFixedSeeds.clear();", "testnet fixed seeds cleared"),
    ('bech32_hrp = "tltc";', "testnet inherited Litecoin bech32 HRP"),
    ('mweb_hrp = "tmweb";', "testnet inherited Litecoin MWEB HRP"),
)

LAUNCH_PROFILE_MARKERS = (
    ("return consensus.BIP16Height <= 1 &&", "script rules require BIP16 active at launch"),
    ("consensus.BIP34Height <= 1 &&", "script rules require BIP34 active at launch"),
    ("consensus.BIP65Height <= 1 &&", "script rules require BIP65 active at launch"),
    ("consensus.BIP66Height <= 1 &&", "script rules require BIP66 active at launch"),
    ("consensus.CSVHeight <= 1 &&", "script rules require CSV active at launch"),
    ("consensus.SegwitHeight <= 1 &&", "script rules require Segwit active at launch"),
    (
        "DeploymentAlwaysActiveAtLaunch(consensus.vDeployments[Consensus::DEPLOYMENT_TAPROOT]);",
        "script rules require Taproot active at launch",
    ),
    ("status.snapshot_configured = consensus.ltc_snapshot.IsEnabled()", "readiness requires Litecoin snapshot enabled"),
    (
        "status.auxpow_active_at_launch = consensus.auxpow.IsEnabled(1);",
        "readiness requires AuxPoW active for block 1",
    ),
    (
        "status.chain_id_encodable = consensus.auxpow.nChainId != 0",
        "readiness requires non-zero encodable AuxPoW chain id",
    ),
    (
        "status.chain_id_parent_version_safe = AuxPowChainIdAvoidsLitecoinParentVersionRange(consensus.auxpow.nChainId);",
        "readiness rejects Litecoin parent-version chain-id range",
    ),
    ("consensus.auxpow.fStrictChainId;", "readiness requires strict AuxPoW chain id"),
    (
        "status.script_rules_active_at_launch = HasLaunchActiveScriptRules(chainparams);",
        "readiness includes script-rule activation",
    ),
    (
        "status.shielded_inactive_at_launch = !consensus.shielded_pool.IsEnabled(1);",
        "readiness keeps shielded inactive for first launch block",
    ),
    (
        "status.chain_history_clean = HasLaunchNeutralChainHistory(chainparams);",
        "readiness requires neutral inherited chain history",
    ),
    (
        "status.public_network_identity = GetPublicNetworkIdentityStatus(chainparams);",
        "readiness includes public network identity",
    ),
    (
        "status.message_start_shape_valid = MessageStartShapeValid(message_start);",
        "identity readiness validates P2P message-start shape",
    ),
    (
        "status.default_port_shape_valid = DefaultPortShapeValid(chainparams.GetDefaultPort());",
        "identity readiness validates public P2P port shape",
    ),
    (
        "status.dns_seeds_shape_valid = DnsSeedsShapeValid(chainparams);",
        "identity readiness validates DNS seed shape",
    ),
    (
        "status.inherited_litecoin_base58_prefixes = HasAnyLitecoinBase58Prefix(chainparams);",
        "identity readiness rejects partial inherited Base58 prefixes",
    ),
    (
        "status.base58_prefixes_shape_valid = Base58PrefixesShapeValid(chainparams);",
        "identity readiness validates Base58 prefix lengths",
    ),
    (
        "status.base58_prefixes_unique = Base58PrefixesUnique(chainparams);",
        "identity readiness validates Base58 prefix uniqueness",
    ),
    (
        "status.bech32_hrp_shape_valid = HrpShapeValid(chainparams.Bech32HRP());",
        "identity readiness validates Bech32 HRP shape",
    ),
    (
        "status.mweb_hrp_shape_valid = HrpShapeValid(chainparams.MWEB_HRP());",
        "identity readiness validates MWEB HRP shape",
    ),
    (
        "status.hrps_unique = chainparams.Bech32HRP() != chainparams.MWEB_HRP();",
        "identity readiness requires distinct HRPs",
    ),
)


def fail(path, message):
    print("{}: {}".format(path.relative_to(ROOT_DIR), message), file=sys.stderr)
    return 1


def require_text(path, needle, description):
    if needle not in path.read_text(encoding="utf8"):
        return "{} missing {}: {}".format(path.relative_to(ROOT_DIR), description, needle)
    return None


def require_absent_text(path, needle, description):
    if needle in path.read_text(encoding="utf8"):
        return "{} still contains {}: {}".format(
            path.relative_to(ROOT_DIR),
            description,
            needle,
        )
    return None


def seed_data_lines(path):
    return [
        line
        for line in path.read_text(encoding="utf8").splitlines()
        if line.strip() and not line.lstrip().startswith("#")
    ]


def require_no_checked_in_seed_entries(path):
    data_lines = seed_data_lines(path)
    if data_lines:
        return "{} contains checked-in seed entries: {}".format(
            path.relative_to(ROOT_DIR),
            ", ".join(data_lines[:3]),
        )
    return None


def require_generated_fixed_seed_header_current():
    result = subprocess.run(
        [sys.executable, str(GENERATE_SEEDS), str(SEEDS_DIR)],
        check=False,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    if result.returncode != 0:
        return "{} failed: {}".format(
            GENERATE_SEEDS.relative_to(ROOT_DIR),
            result.stderr.strip() or "no stderr",
        )

    actual = CHAINPARAMS_SEEDS.read_text(encoding="utf8")
    if actual != result.stdout:
        return "{} is not generated from checked-in zkCoin seed inputs".format(
            CHAINPARAMS_SEEDS.relative_to(ROOT_DIR)
        )
    return None


def class_block(text, class_name, next_class_name):
    start_marker = "class {} : public CChainParams".format(class_name)
    start = text.find(start_marker)
    if start == -1:
        raise ValueError("missing {}".format(start_marker))
    next_marker = "class {} : public CChainParams".format(next_class_name)
    end = text.find(next_marker, start + len(start_marker))
    if end == -1:
        raise ValueError("missing {}".format(next_marker))
    return text[start:end]


def require_markers(text, markers, path):
    missing = [
        "{}: {}".format(description, marker)
        for marker, description in markers
        if marker not in text
    ]
    if missing:
        return "{} missing launch-profile markers: {}".format(
            path.relative_to(ROOT_DIR),
            "; ".join(missing),
        )
    return None


def require_configured_gate(text):
    start = text.find("status.configured = status.snapshot_configured &&")
    if start == -1:
        return "{} missing configured gate start".format(LAUNCHPROFILE.relative_to(ROOT_DIR))
    end = text.find("return status;", start)
    if end == -1:
        return "{} missing configured gate terminator".format(LAUNCHPROFILE.relative_to(ROOT_DIR))
    gate = text[start:end]
    required_terms = (
        "status.snapshot_configured",
        "status.auxpow_active_at_launch",
        "status.chain_id_configured",
        "status.script_rules_active_at_launch",
        "status.shielded_inactive_at_launch",
        "status.chain_history_clean",
        "status.public_network_identity_configured",
    )
    missing = [term for term in required_terms if term not in gate]
    if missing:
        return "{} configured gate missing terms: {}".format(
            LAUNCHPROFILE.relative_to(ROOT_DIR),
            ", ".join(missing),
        )
    return None


def require_chain_id_configured_gate(text):
    start = text.find("status.chain_id_configured = status.chain_id_encodable &&")
    if start == -1:
        return "{} missing chain-id configured gate start".format(LAUNCHPROFILE.relative_to(ROOT_DIR))
    end = text.find(";", start)
    if end == -1:
        return "{} missing chain-id configured gate terminator".format(LAUNCHPROFILE.relative_to(ROOT_DIR))
    gate = text[start:end]
    required_terms = (
        "status.chain_id_encodable",
        "status.chain_id_parent_version_safe",
        "consensus.auxpow.fStrictChainId",
    )
    missing = [term for term in required_terms if term not in gate]
    if missing:
        return "{} chain-id configured gate missing terms: {}".format(
            LAUNCHPROFILE.relative_to(ROOT_DIR),
            ", ".join(missing),
        )
    return None


def require_public_identity_configured_gate(text):
    start = text.find("status.configured =\n        !status.inherited_litecoin_public_identity &&")
    if start == -1:
        return "{} missing public identity configured gate start".format(LAUNCHPROFILE.relative_to(ROOT_DIR))
    end = text.find("return status;", start)
    if end == -1:
        return "{} missing public identity configured gate terminator".format(LAUNCHPROFILE.relative_to(ROOT_DIR))
    gate = text[start:end]
    required_terms = (
        "!status.inherited_litecoin_public_identity",
        "status.message_start_shape_valid",
        "status.default_port_shape_valid",
        "status.dns_seeds_shape_valid",
        "status.base58_prefixes_shape_valid",
        "status.base58_prefixes_unique",
        "status.bech32_hrp_shape_valid",
        "status.mweb_hrp_shape_valid",
        "status.hrps_unique",
    )
    missing = [term for term in required_terms if term not in gate]
    if missing:
        return "{} public identity configured gate missing terms: {}".format(
            LAUNCHPROFILE.relative_to(ROOT_DIR),
            ", ".join(missing),
        )
    return None


def main():
    chainparams_text = CHAINPARAMS.read_text(encoding="utf8")
    try:
        main_block = class_block(chainparams_text, "CMainParams", "CTestNetParams")
        testnet_block = class_block(chainparams_text, "CTestNetParams", "CRegTestParams")
    except ValueError as exc:
        return fail(CHAINPARAMS, str(exc))

    for text, markers in (
        (main_block, MAIN_FAIL_CLOSED_MARKERS),
        (testnet_block, TESTNET_FAIL_CLOSED_MARKERS),
    ):
        error = require_markers(text, markers, CHAINPARAMS)
        if error:
            return fail(CHAINPARAMS, error)

    chainparams_checks = (
        (
            "zkCoin signet is disabled until dedicated zkCoin signet chainparams are implemented.",
            "signet disabled until dedicated zkCoin chainparams exist",
        ),
        (
            "chainTxData = ChainTxData{\n"
            "            /* nTime    */ 0,\n"
            "            /* nTxCount */ 0,\n"
            "            /* dTxRate  */ 0,\n"
            "        };",
            "public neutral chain transaction data",
        ),
    )
    for needle, description in chainparams_checks:
        error = require_text(CHAINPARAMS, needle, description)
        if error:
            return fail(CHAINPARAMS, error)

    forbidden_chainparams_checks = (
        (
            "return std::unique_ptr<CChainParams>(new CTestNetParams()); // TODO: Support SigNet",
            "inherited testnet signet fallback",
        ),
    )
    for needle, description in forbidden_chainparams_checks:
        error = require_absent_text(CHAINPARAMS, needle, description)
        if error:
            return fail(CHAINPARAMS, error)

    launchprofile_text = LAUNCHPROFILE.read_text(encoding="utf8")
    error = require_markers(launchprofile_text, LAUNCH_PROFILE_MARKERS, LAUNCHPROFILE)
    if error:
        return fail(LAUNCHPROFILE, error)
    error = require_chain_id_configured_gate(launchprofile_text)
    if error:
        return fail(LAUNCHPROFILE, error)
    error = require_configured_gate(launchprofile_text)
    if error:
        return fail(LAUNCHPROFILE, error)
    error = require_public_identity_configured_gate(launchprofile_text)
    if error:
        return fail(LAUNCHPROFILE, error)

    init_checks = (
        ("if (!chainparams.IsMockableChain()) {", "public launch gate outside regtest"),
        (
            "production launch consensus parameters must be hardcoded in chainparams",
            "public launch args rejected outside regtest",
        ),
        (
            "signet reserved until supported",
            "signet base-port help marked reserved",
        ),
        ("if (!HasConfiguredPublicLaunchProfile(chainparams)) {", "public launch readiness gate"),
        (PUBLIC_LAUNCH_FAILURE, "public launch fail-closed error"),
    )
    for needle, description in init_checks:
        error = require_text(INIT, needle, description)
        if error:
            return fail(INIT, error)

    forbidden_init_checks = (
        (
            "CreateChainParams(argsman, CBaseChainParams::SIGNET)",
            "server arg setup creating unsupported signet params",
        ),
        ("Signet derived magic", "signet magic log before signet params exist"),
    )
    for needle, description in forbidden_init_checks:
        error = require_absent_text(INIT, needle, description)
        if error:
            return fail(INIT, error)

    test_checks = (
        (
            "ChainParams_PUBLIC_launch_profile_fails_closed_until_constants",
            "runtime public launch fail-closed unit test",
        ),
        (
            "ChainParams_REGTEST_launch_profile_accepts_complete_rehearsal_args",
            "runtime positive launch-profile rehearsal unit test",
        ),
        (
            "ChainParams_REGTEST_launch_profile_rejects_shielded_active_at_launch",
            "runtime negative shielded launch activation unit test",
        ),
        (
            "ChainParams_PUBLIC_identity_accepts_non_litecoin_non_mockable_values",
            "runtime positive non-mockable public identity unit test",
        ),
        (
            "ChainParams_PUBLIC_identity_rejects_non_mockable_inherited_or_malformed_values",
            "runtime negative non-mockable public identity unit test",
        ),
        (
            "CNonMockablePublicIdentityParams",
            "test-only non-mockable public identity chainparams",
        ),
        ("chainParams.SetFixedSeeds({0x01});", "runtime public identity fixed seed rejection coverage"),
        (
            "check_public_launch_profile_fails_closed(*m_node.args, CBaseChainParams::MAIN);",
            "mainnet fail-closed runtime coverage",
        ),
        (
            "check_public_launch_profile_fails_closed(*m_node.args, CBaseChainParams::TESTNET);",
            "testnet fail-closed runtime coverage",
        ),
        (
            "ChainParams_SIGNET_disabled_until_dedicated_params_exist",
            "signet explicit unsupported unit coverage",
        ),
        ("identity.message_start_shape_valid", "runtime public identity message-start shape coverage"),
        ("identity.base58_prefixes_unique", "runtime public identity Base58 uniqueness coverage"),
        ("status.public_network_identity.hrps_unique", "runtime regtest identity HRP uniqueness coverage"),
    )
    for needle, description in test_checks:
        error = require_text(POW_TESTS, needle, description)
        if error:
            return fail(POW_TESTS, error)

    signet_test_checks = (
        ("SignetUnsupportedTest", "signet unsupported functional test"),
        ("setup_network", "signet test avoids automatic startup"),
        ("assert_start_raises_init_error", "signet startup rejection assertion"),
        ("zkCoin signet is disabled until dedicated", "signet disabled startup error"),
        ("zkCoin signet chainparams are implemented.", "signet disabled startup error"),
    )
    for needle, description in signet_test_checks:
        error = require_text(SIGNET_TEST, needle, description)
        if error:
            return fail(SIGNET_TEST, error)

    preflight_checks = (
        (
            "getblockchaininfo.ltc_snapshot.imported must match launch_readiness.snapshot_imported",
            "preflight cross-checks snapshot import detail",
        ),
        ("snapshot import is still in progress", "preflight rejects in-progress snapshot imports"),
        (
            "getblockchaininfo.auxpow.next_block_active must match launch_readiness.auxpow_active_at_launch at the launch tip",
            "preflight cross-checks AuxPoW next-block activation detail",
        ),
        (
            "getblockchaininfo.auxpow.strict_chain_id must be true when launch_readiness.chain_id_configured is true",
            "preflight cross-checks strict AuxPoW chain-id detail",
        ),
        ("message_start_shape_valid", "preflight requires message-start shape detail"),
        ("dns_seeds_shape_valid", "preflight requires DNS seed shape detail"),
        ("base58_prefixes_unique", "preflight requires Base58 uniqueness detail"),
        ("hrps_unique", "preflight requires HRP uniqueness detail"),
        (
            "getblockchaininfo.auxpow.parent_version_safe must match launch_readiness.chain_id_parent_version_safe",
            "preflight cross-checks AuxPoW parent-version safety detail",
        ),
        (
            "getblockchaininfo.shielded_pool.next_block_active must agree with launch_readiness.shielded_inactive_at_launch at the launch tip",
            "preflight cross-checks shielded launch activation detail",
        ),
    )
    for needle, description in preflight_checks:
        error = require_text(LAUNCH_PREFLIGHT, needle, description)
        if error:
            return fail(LAUNCH_PREFLIGHT, error)

    doc_checks = (
        (
            "Public `main` and `testnet` startup is fail-closed",
            "public launch fail-closed documentation",
        ),
        ("launch profile is hardcoded in `chainparams`", "chainparams launch-profile documentation"),
        ("the Litecoin block-X snapshot", "snapshot readiness documentation"),
        ("strict AuxPoW must activate for the first launch block", "AuxPoW readiness documentation"),
        ("with a parent-version-safe child chain id", "parent-version-safe AuxPoW documentation"),
        (
            "avoid the Litecoin parent versionbits-derived range `0x2000` through `0x3fff`",
            "Litecoin parent versionbits chain-id range documentation",
        ),
        ("launch_readiness.chain_id_parent_version_safe=true", "preflight parent-version-safe readiness documentation"),
        (
            "transactions must remain inactive for the first launch block",
            "shielded launch posture documentation",
        ),
        ("inherited Litecoin public network identity", "identity readiness documentation"),
    )
    for needle, description in doc_checks:
        error = require_text(LAUNCH_DOC, needle, description)
        if error:
            return fail(LAUNCH_DOC, error)

    dnsseed_policy_checks = (
        ("zkCoin DNS seed operators", "zkCoin DNS seed policy title"),
        ("must not be used as zkCoin public-network launch inputs", "inherited seed data rejection"),
        ("functioning zkCoin nodes from the intended zkCoin public network", "zkCoin public node requirement"),
        ("contact the active zkCoin maintainers", "zkCoin maintainer escalation"),
    )
    for needle, description in dnsseed_policy_checks:
        error = require_text(DNSSEED_POLICY, needle, description)
        if error:
            return fail(DNSSEED_POLICY, error)

    seed_readme_checks = (
        ("inherited Litecoin seed data", "inherited seed source rejection"),
        ("fail launch readiness", "fail-closed seed readiness documentation"),
        ("zkCoin-specific seed", "zkCoin seed infrastructure requirement"),
        ("infrastructure exists", "zkCoin seed infrastructure requirement"),
        ("checked-in `nodes_main.txt` and `nodes_test.txt`", "empty seed input documentation"),
        ("Generate crawler output from the intended zkCoin public network", "zkCoin crawler source requirement"),
        ("generate-seeds.py` only from zkCoin node lists", "fixed seed source requirement"),
    )
    for needle, description in seed_readme_checks:
        error = require_text(SEEDS_README, needle, description)
        if error:
            return fail(SEEDS_README, error)

    makeseeds_checks = (
        ('r"^/zkCoinCore:("', "zkCoin-only seed crawler user-agent filter"),
    )
    for needle, description in makeseeds_checks:
        error = require_text(MAKESEEDS, needle, description)
        if error:
            return fail(MAKESEEDS, error)

    forbidden_makeseeds_checks = (
        ("LitecoinCore", "inherited Litecoin crawler user-agent acceptance"),
    )
    for needle, description in forbidden_makeseeds_checks:
        error = require_absent_text(MAKESEEDS, needle, description)
        if error:
            return fail(MAKESEEDS, error)

    for seed_node_file in SEED_NODE_FILES:
        error = require_no_checked_in_seed_entries(seed_node_file)
        if error:
            return fail(seed_node_file, error)

    chainparams_seed_checks = (
        ("List of fixed seed nodes for the zkCoin network", "zkCoin fixed seed header"),
        ("static const uint8_t chainparams_seed_main[] = {\n};", "empty mainnet fixed seed array"),
        ("static const uint8_t chainparams_seed_test[] = {\n};", "empty testnet fixed seed array"),
    )
    for needle, description in chainparams_seed_checks:
        error = require_text(CHAINPARAMS_SEEDS, needle, description)
        if error:
            return fail(CHAINPARAMS_SEEDS, error)

    error = require_generated_fixed_seed_header_current()
    if error:
        return fail(CHAINPARAMS_SEEDS, error)

    return 0


if __name__ == "__main__":
    sys.exit(main())
