#!/usr/bin/env python3
# Copyright (c) 2026 The zkCoin developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Check that public zkCoin launch parameters stay fail-closed."""

import hashlib
import importlib.util
import json
import os
from pathlib import Path
import shlex
import subprocess
import sys
import tempfile


ROOT_DIR = Path(__file__).resolve().parents[2]
CHAINPARAMS = ROOT_DIR / "src" / "chainparams.cpp"
LAUNCHPROFILE = ROOT_DIR / "src" / "launchprofile.cpp"
INIT = ROOT_DIR / "src" / "init.cpp"
POW_TESTS = ROOT_DIR / "src" / "test" / "pow_tests.cpp"
SIGNET_TEST = ROOT_DIR / "test" / "functional" / "feature_signet.py"
LAUNCH_PREFLIGHT = ROOT_DIR / "contrib" / "devtools" / "zkcoin_launch_preflight.sh"
LAUNCH_PREFLIGHT_TEST = ROOT_DIR / "test" / "functional" / "feature_launch_preflight_script.py"
PUBLIC_LAUNCH_MANIFEST = ROOT_DIR / "contrib" / "devtools" / "zkcoin_public_launch_profile_manifest.json"
PUBLIC_LAUNCH_MANIFEST_TOOL = ROOT_DIR / "contrib" / "devtools" / "zkcoin_public_launch_profile.py"
LTC_SNAPSHOT_SCRIPT = ROOT_DIR / "contrib" / "devtools" / "zkcoin_ltc_snapshot.sh"
LTC_SNAPSHOT_SCRIPT_TEST = ROOT_DIR / "test" / "functional" / "feature_ltc_snapshot_script.py"
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
    ("status.chain_id_placeholder", "readiness rejects placeholder public AuxPoW chain id"),
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
        "std::vector<std::string> GetPublicNetworkIdentityFailures",
        "public identity failure reasons are centralized",
    ),
    (
        "std::vector<std::string> GetPublicLaunchProfileFailures",
        "public launch failure reasons are centralized",
    ),
    (
        "snapshot consensus parameters are not configured",
        "public launch missing snapshot failure reason",
    ),
    (
        "public network identity is inherited from Litecoin or malformed",
        "public launch identity failure reason",
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
    ("ReservedDnsSeedSuffix", "runtime identity rejects reserved DNS seed suffixes"),
    ("label_count < 2", "runtime identity rejects single-label DNS seed hostnames"),
    ("label_length > 63", "runtime identity rejects overlong DNS seed labels"),
    ("!final_label_has_alpha", "runtime identity rejects numeric final-label DNS seed hostnames"),
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
    ("MAX_BECH32_HRP_LENGTH", "identity readiness caps Bech32 HRP length"),
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


def require_status_json_schema_version(status_json):
    if status_json.get("schema_version") != 2:
        return "{} --status-json did not report schema_version 2".format(
            PUBLIC_LAUNCH_MANIFEST_TOOL.relative_to(ROOT_DIR)
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


def require_public_launch_manifest_current():
    result = subprocess.run(
        [
            sys.executable,
            str(PUBLIC_LAUNCH_MANIFEST_TOOL),
            "--allow-blocked",
            str(PUBLIC_LAUNCH_MANIFEST),
        ],
        check=False,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    if result.returncode != 0:
        return "{} failed: {}".format(
            PUBLIC_LAUNCH_MANIFEST_TOOL.relative_to(ROOT_DIR),
            result.stderr.strip() or result.stdout.strip() or "no output",
        )

    manifest = json.loads(PUBLIC_LAUNCH_MANIFEST.read_text(encoding="utf8"))
    if manifest.get("version") != 1:
        return "{} version must be 1".format(PUBLIC_LAUNCH_MANIFEST.relative_to(ROOT_DIR))
    if manifest.get("status") != "blocked":
        return "{} must remain blocked until final public launch constants are selected".format(
            PUBLIC_LAUNCH_MANIFEST.relative_to(ROOT_DIR)
        )

    required_blockers = {
        "main.litecoin_snapshot",
        "main.auxpow_chain_id",
        "main.public_network_identity",
        "main.dns_seeds",
        "testnet.litecoin_snapshot",
        "testnet.auxpow_chain_id",
        "testnet.public_network_identity",
        "testnet.dns_seeds",
    }
    blocker_ids = {
        blocker.get("id")
        for blocker in manifest.get("blockers", [])
        if isinstance(blocker, dict)
    }
    missing_blockers = sorted(required_blockers - blocker_ids)
    if missing_blockers:
        return "{} missing blockers: {}".format(
            PUBLIC_LAUNCH_MANIFEST.relative_to(ROOT_DIR),
            ", ".join(missing_blockers),
        )

    for network in ("main", "testnet"):
        profile = manifest.get("networks", {}).get(network, {})
        if profile.get("auxpow", {}).get("start_height") != 1:
            return "{} {} AuxPoW start height must be 1".format(
                PUBLIC_LAUNCH_MANIFEST.relative_to(ROOT_DIR),
                network,
            )
        if profile.get("auxpow", {}).get("forbidden_parent_version_chain_id_range") != [8192, 16383]:
            return "{} {} AuxPoW parent-version forbidden range must be [8192, 16383]".format(
                PUBLIC_LAUNCH_MANIFEST.relative_to(ROOT_DIR),
                network,
            )
        if profile.get("shielded_pool", {}).get("active_at_launch") is not False:
            return "{} {} shielded pool must be inactive at launch".format(
                PUBLIC_LAUNCH_MANIFEST.relative_to(ROOT_DIR),
                network,
            )
        if profile.get("public_network_identity", {}).get("fixed_seeds") != []:
            return "{} {} fixed seeds must remain empty in the launch manifest".format(
                PUBLIC_LAUNCH_MANIFEST.relative_to(ROOT_DIR),
                network,
            )

    output = result.stdout
    for needle in (
        "main.litecoin_snapshot.height",
        "main.litecoin_snapshot.audit.snapshot_hash",
        "main.auxpow.chain_id",
        "main.public_network_identity.dns_seeds",
        "testnet.litecoin_snapshot.height",
        "testnet.litecoin_snapshot.audit.snapshot_hash",
        "testnet.auxpow.chain_id",
        "testnet.public_network_identity.dns_seeds",
    ):
        if needle not in output:
            return "{} did not report blocked field {}".format(
                PUBLIC_LAUNCH_MANIFEST_TOOL.relative_to(ROOT_DIR),
                needle,
            )

    next_action_result = subprocess.run(
        [
            sys.executable,
            str(PUBLIC_LAUNCH_MANIFEST_TOOL),
            "--next-action",
            str(PUBLIC_LAUNCH_MANIFEST),
        ],
        check=False,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    if next_action_result.returncode != 0:
        return "{} --next-action failed for blocked manifest: {}".format(
            PUBLIC_LAUNCH_MANIFEST_TOOL.relative_to(ROOT_DIR),
            next_action_result.stderr.strip() or next_action_result.stdout.strip() or "no output",
        )
    if "next blocker: main.litecoin_snapshot" not in next_action_result.stdout:
        return "{} --next-action did not select the first unresolved blocker".format(
            PUBLIC_LAUNCH_MANIFEST_TOOL.relative_to(ROOT_DIR)
        )
    if "--check-snapshot-audit main <snapshot_audit.json>" not in next_action_result.stdout:
        return "{} --next-action did not print the snapshot audit check command".format(
            PUBLIC_LAUNCH_MANIFEST_TOOL.relative_to(ROOT_DIR)
        )
    if "--set-snapshot-audit main <snapshot_audit.json>" not in next_action_result.stdout:
        return "{} --next-action did not print the snapshot handoff command".format(
            PUBLIC_LAUNCH_MANIFEST_TOOL.relative_to(ROOT_DIR)
        )
    if "--snapshot-audit-template main" not in next_action_result.stdout:
        return "{} --next-action did not print the snapshot audit template command".format(
            PUBLIC_LAUNCH_MANIFEST_TOOL.relative_to(ROOT_DIR)
        )
    if "  - template command: contrib/devtools/zkcoin_public_launch_profile.py --snapshot-audit-template main" not in next_action_result.stdout:
        return "{} --next-action did not print a copyable snapshot template command line".format(
            PUBLIC_LAUNCH_MANIFEST_TOOL.relative_to(ROOT_DIR)
        )
    if "  - check command: contrib/devtools/zkcoin_public_launch_profile.py --check-snapshot-audit main <snapshot_audit.json>" not in next_action_result.stdout:
        return "{} --next-action did not print a copyable snapshot check command line".format(
            PUBLIC_LAUNCH_MANIFEST_TOOL.relative_to(ROOT_DIR)
        )
    if "  - apply command: contrib/devtools/zkcoin_public_launch_profile.py --set-snapshot-audit main <snapshot_audit.json>" not in next_action_result.stdout:
        return "{} --next-action did not print a copyable snapshot apply command line".format(
            PUBLIC_LAUNCH_MANIFEST_TOOL.relative_to(ROOT_DIR)
        )
    if "  - network readiness summary command: contrib/devtools/zkcoin_public_launch_profile.py --network-readiness-summary main" not in next_action_result.stdout:
        return "{} --next-action did not print a copyable network readiness-summary command line".format(
            PUBLIC_LAUNCH_MANIFEST_TOOL.relative_to(ROOT_DIR)
        )
    if "  - blocker type readiness summary command: contrib/devtools/zkcoin_public_launch_profile.py --blocker-type-readiness-summary litecoin_snapshot" not in next_action_result.stdout:
        return "{} --next-action did not print a copyable blocker-type readiness-summary command line".format(
            PUBLIC_LAUNCH_MANIFEST_TOOL.relative_to(ROOT_DIR)
        )
    if "  - blocker readiness summary command: contrib/devtools/zkcoin_public_launch_profile.py --blocker-readiness-summary main.litecoin_snapshot" not in next_action_result.stdout:
        return "{} --next-action did not print a copyable blocker readiness-summary command line".format(
            PUBLIC_LAUNCH_MANIFEST_TOOL.relative_to(ROOT_DIR)
        )
    if "  - later blocker readiness summary commands: main.auxpow_chain_id=contrib/devtools/zkcoin_public_launch_profile.py --blocker-readiness-summary main.auxpow_chain_id" not in next_action_result.stdout:
        return "{} --next-action did not print copyable later blocker readiness-summary command lines".format(
            PUBLIC_LAUNCH_MANIFEST_TOOL.relative_to(ROOT_DIR)
        )
    if "testnet.dns_seeds=contrib/devtools/zkcoin_public_launch_profile.py --blocker-readiness-summary testnet.dns_seeds" not in next_action_result.stdout:
        return "{} --next-action did not print the final later blocker readiness-summary command line".format(
            PUBLIC_LAUNCH_MANIFEST_TOOL.relative_to(ROOT_DIR)
        )

    expected_snapshot_audit_template_fields = [
        "height",
        "block_hash",
        "import_hash",
        "snapshot_hash",
        "coins",
        "base_nchaintx",
        "source_chain",
        "snapshot_file_size",
        "snapshot_file_sha256",
        "snapshot_file",
        "total_amount",
    ]
    snapshot_template_result = subprocess.run(
        [
            sys.executable,
            str(PUBLIC_LAUNCH_MANIFEST_TOOL),
            "--snapshot-audit-template",
            "main",
            str(PUBLIC_LAUNCH_MANIFEST),
        ],
        check=False,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    if snapshot_template_result.returncode != 0:
        return "{} --snapshot-audit-template failed for main: {}".format(
            PUBLIC_LAUNCH_MANIFEST_TOOL.relative_to(ROOT_DIR),
            snapshot_template_result.stderr.strip()
            or snapshot_template_result.stdout.strip()
            or "no output",
        )
    try:
        snapshot_template = json.loads(snapshot_template_result.stdout)
    except json.JSONDecodeError as exc:
        return "{} --snapshot-audit-template did not emit JSON: {}".format(
            PUBLIC_LAUNCH_MANIFEST_TOOL.relative_to(ROOT_DIR),
            exc,
        )
    if list(snapshot_template) != expected_snapshot_audit_template_fields:
        return "{} --snapshot-audit-template did not emit the expected field order".format(
            PUBLIC_LAUNCH_MANIFEST_TOOL.relative_to(ROOT_DIR)
        )
    if snapshot_template.get("source_chain") != "main":
        return "{} --snapshot-audit-template did not prefill main source_chain".format(
            PUBLIC_LAUNCH_MANIFEST_TOOL.relative_to(ROOT_DIR)
        )
    if any(
        value is not None
        for field, value in snapshot_template.items()
        if field != "source_chain"
    ):
        return "{} --snapshot-audit-template guessed production snapshot values".format(
            PUBLIC_LAUNCH_MANIFEST_TOOL.relative_to(ROOT_DIR)
        )

    testnet_snapshot_template_result = subprocess.run(
        [
            sys.executable,
            str(PUBLIC_LAUNCH_MANIFEST_TOOL),
            "--snapshot-audit-template",
            "testnet",
            str(PUBLIC_LAUNCH_MANIFEST),
        ],
        check=False,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    if testnet_snapshot_template_result.returncode != 0:
        return "{} --snapshot-audit-template failed for testnet: {}".format(
            PUBLIC_LAUNCH_MANIFEST_TOOL.relative_to(ROOT_DIR),
            testnet_snapshot_template_result.stderr.strip()
            or testnet_snapshot_template_result.stdout.strip()
            or "no output",
        )
    try:
        testnet_snapshot_template = json.loads(testnet_snapshot_template_result.stdout)
    except json.JSONDecodeError as exc:
        return "{} --snapshot-audit-template testnet output was not JSON: {}".format(
            PUBLIC_LAUNCH_MANIFEST_TOOL.relative_to(ROOT_DIR),
            exc,
        )
    if testnet_snapshot_template.get("source_chain") != "test":
        return "{} --snapshot-audit-template did not prefill testnet source_chain".format(
            PUBLIC_LAUNCH_MANIFEST_TOOL.relative_to(ROOT_DIR)
        )

    action_plan_result = subprocess.run(
        [
            sys.executable,
            str(PUBLIC_LAUNCH_MANIFEST_TOOL),
            "--action-plan",
            str(PUBLIC_LAUNCH_MANIFEST),
        ],
        check=False,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    if action_plan_result.returncode != 0:
        return "{} --action-plan failed for blocked manifest: {}".format(
            PUBLIC_LAUNCH_MANIFEST_TOOL.relative_to(ROOT_DIR),
            action_plan_result.stderr.strip() or action_plan_result.stdout.strip() or "no output",
        )
    for expected in (
        "zkCoin public launch profile action plan:",
        "1. main.litecoin_snapshot",
        "8. testnet.dns_seeds",
        "--snapshot-audit-template main",
        "--check-snapshot-audit main <snapshot_audit.json>",
        "--check-dns-seeds testnet <seed1.hostname>,<seed2.hostname>",
        "     template command: contrib/devtools/zkcoin_public_launch_profile.py --snapshot-audit-template main",
        "     check command: contrib/devtools/zkcoin_public_launch_profile.py --check-snapshot-audit main <snapshot_audit.json>",
        "     apply command: contrib/devtools/zkcoin_public_launch_profile.py --set-snapshot-audit main <snapshot_audit.json>",
        "     readiness summary command: contrib/devtools/zkcoin_public_launch_profile.py --readiness-summary contrib/devtools/zkcoin_public_launch_profile_manifest.json",
        "     network readiness summary command: contrib/devtools/zkcoin_public_launch_profile.py --network-readiness-summary main contrib/devtools/zkcoin_public_launch_profile_manifest.json",
        "     blocker type readiness summary command: contrib/devtools/zkcoin_public_launch_profile.py --blocker-type-readiness-summary litecoin_snapshot contrib/devtools/zkcoin_public_launch_profile_manifest.json",
        "     blocker readiness summary command: contrib/devtools/zkcoin_public_launch_profile.py --blocker-readiness-summary main.litecoin_snapshot contrib/devtools/zkcoin_public_launch_profile_manifest.json",
        "     check command: contrib/devtools/zkcoin_public_launch_profile.py --check-dns-seeds testnet <seed1.hostname>,<seed2.hostname>",
        "     apply command: contrib/devtools/zkcoin_public_launch_profile.py --set-dns-seeds testnet <seed1.hostname>,<seed2.hostname>",
    ):
        if expected not in action_plan_result.stdout:
            return "{} --action-plan did not print {}".format(
                PUBLIC_LAUNCH_MANIFEST_TOOL.relative_to(ROOT_DIR),
                expected,
            )

    readiness_summary_result = subprocess.run(
        [
            sys.executable,
            str(PUBLIC_LAUNCH_MANIFEST_TOOL),
            "--readiness-summary",
            str(PUBLIC_LAUNCH_MANIFEST),
        ],
        check=False,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    if readiness_summary_result.returncode != 0:
        return "{} --readiness-summary failed for blocked manifest: {}".format(
            PUBLIC_LAUNCH_MANIFEST_TOOL.relative_to(ROOT_DIR),
            readiness_summary_result.stderr.strip() or readiness_summary_result.stdout.strip() or "no output",
        )
    for expected in (
        "zkCoin public launch profile readiness summary:",
        "  - status: blocked",
        "  - ready for chainparams: no",
        "  - action plan command: contrib/devtools/zkcoin_public_launch_profile.py --action-plan contrib/devtools/zkcoin_public_launch_profile_manifest.json",
        "  - next action command: contrib/devtools/zkcoin_public_launch_profile.py --next-action contrib/devtools/zkcoin_public_launch_profile_manifest.json",
        "  - readiness summary command: contrib/devtools/zkcoin_public_launch_profile.py --readiness-summary contrib/devtools/zkcoin_public_launch_profile_manifest.json",
        "  - status JSON command: contrib/devtools/zkcoin_public_launch_profile.py --status-json contrib/devtools/zkcoin_public_launch_profile_manifest.json",
        "  - blocked networks: main, testnet",
        "  - ready networks: none",
        "  - blocked networks by blocker type: litecoin_snapshot=main, testnet; auxpow_chain_id=main, testnet; public_network_identity=main, testnet; dns_seeds=main, testnet",
        "  - ready networks by blocker type: litecoin_snapshot=none; auxpow_chain_id=none; public_network_identity=none; dns_seeds=none",
        "  - unresolved blockers: 8",
        "  - unresolved blockers by network: main=4, testnet=4",
        "  - unresolved blockers by blocker type: litecoin_snapshot=2, auxpow_chain_id=2, public_network_identity=2, dns_seeds=2",
        "  - unresolved blockers by network and blocker type: main: litecoin_snapshot=1, auxpow_chain_id=1, public_network_identity=1, dns_seeds=1; testnet: litecoin_snapshot=1, auxpow_chain_id=1, public_network_identity=1, dns_seeds=1",
        "  - blocked fields: 46",
        "  - blocked fields by network: main=23, testnet=23",
        "  - blocked fields by blocker type: litecoin_snapshot=22, auxpow_chain_id=2, public_network_identity=20, dns_seeds=2",
        "  - blocked fields by network and blocker type: main: litecoin_snapshot=11, auxpow_chain_id=1, public_network_identity=10, dns_seeds=1; testnet: litecoin_snapshot=11, auxpow_chain_id=1, public_network_identity=10, dns_seeds=1",
        "  - next blockers by network: main=main.litecoin_snapshot, testnet=testnet.litecoin_snapshot",
        "  - next blockers by network and blocker type: main: litecoin_snapshot=main.litecoin_snapshot, auxpow_chain_id=main.auxpow_chain_id, public_network_identity=main.public_network_identity, dns_seeds=main.dns_seeds; testnet: litecoin_snapshot=testnet.litecoin_snapshot, auxpow_chain_id=testnet.auxpow_chain_id, public_network_identity=testnet.public_network_identity, dns_seeds=testnet.dns_seeds",
        "  - next blocker fields by network: main=11, testnet=11",
        "  - next blocker fields by network and blocker type: main: litecoin_snapshot=11, auxpow_chain_id=1, public_network_identity=10, dns_seeds=1; testnet: litecoin_snapshot=11, auxpow_chain_id=1, public_network_identity=10, dns_seeds=1",
        "  - next blockers by blocker type: litecoin_snapshot=main.litecoin_snapshot, auxpow_chain_id=main.auxpow_chain_id, public_network_identity=main.public_network_identity, dns_seeds=main.dns_seeds",
        "  - next blocker networks by blocker type: litecoin_snapshot=main, auxpow_chain_id=main, public_network_identity=main, dns_seeds=main",
        "  - next blocker fields by blocker type: litecoin_snapshot=11, auxpow_chain_id=1, public_network_identity=10, dns_seeds=1",
        "  - next template commands by network: main=contrib/devtools/zkcoin_public_launch_profile.py --snapshot-audit-template main contrib/devtools/zkcoin_public_launch_profile_manifest.json; testnet=contrib/devtools/zkcoin_public_launch_profile.py --snapshot-audit-template testnet contrib/devtools/zkcoin_public_launch_profile_manifest.json",
        "  - next check commands by network: main=contrib/devtools/zkcoin_public_launch_profile.py --check-snapshot-audit main <snapshot_audit.json> contrib/devtools/zkcoin_public_launch_profile_manifest.json; testnet=contrib/devtools/zkcoin_public_launch_profile.py --check-snapshot-audit testnet <snapshot_audit.json> contrib/devtools/zkcoin_public_launch_profile_manifest.json",
        "  - next apply commands by network: main=contrib/devtools/zkcoin_public_launch_profile.py --set-snapshot-audit main <snapshot_audit.json> --in-place contrib/devtools/zkcoin_public_launch_profile_manifest.json; testnet=contrib/devtools/zkcoin_public_launch_profile.py --set-snapshot-audit testnet <snapshot_audit.json> --in-place contrib/devtools/zkcoin_public_launch_profile_manifest.json",
        "  - next template commands by blocker type: litecoin_snapshot=contrib/devtools/zkcoin_public_launch_profile.py --snapshot-audit-template main contrib/devtools/zkcoin_public_launch_profile_manifest.json; auxpow_chain_id=none; public_network_identity=none; dns_seeds=none",
        "  - next check commands by blocker type: litecoin_snapshot=contrib/devtools/zkcoin_public_launch_profile.py --check-snapshot-audit main <snapshot_audit.json> contrib/devtools/zkcoin_public_launch_profile_manifest.json",
        "auxpow_chain_id=contrib/devtools/zkcoin_public_launch_profile.py --check-auxpow main <chain_id> contrib/devtools/zkcoin_public_launch_profile_manifest.json",
        "  - next apply commands by blocker type: litecoin_snapshot=contrib/devtools/zkcoin_public_launch_profile.py --set-snapshot-audit main <snapshot_audit.json> --in-place contrib/devtools/zkcoin_public_launch_profile_manifest.json",
        "dns_seeds=contrib/devtools/zkcoin_public_launch_profile.py --set-dns-seeds main <seed1.hostname>,<seed2.hostname> --in-place contrib/devtools/zkcoin_public_launch_profile_manifest.json",
        "  - next network readiness summary commands by blocker type: litecoin_snapshot=contrib/devtools/zkcoin_public_launch_profile.py --network-readiness-summary main contrib/devtools/zkcoin_public_launch_profile_manifest.json",
        "dns_seeds=contrib/devtools/zkcoin_public_launch_profile.py --network-readiness-summary main contrib/devtools/zkcoin_public_launch_profile_manifest.json",
        "  - next blocker type readiness summary commands by blocker type: litecoin_snapshot=contrib/devtools/zkcoin_public_launch_profile.py --blocker-type-readiness-summary litecoin_snapshot contrib/devtools/zkcoin_public_launch_profile_manifest.json",
        "dns_seeds=contrib/devtools/zkcoin_public_launch_profile.py --blocker-type-readiness-summary dns_seeds contrib/devtools/zkcoin_public_launch_profile_manifest.json",
        "  - next blocker readiness summary commands by blocker type: litecoin_snapshot=contrib/devtools/zkcoin_public_launch_profile.py --blocker-readiness-summary main.litecoin_snapshot contrib/devtools/zkcoin_public_launch_profile_manifest.json",
        "dns_seeds=contrib/devtools/zkcoin_public_launch_profile.py --blocker-readiness-summary main.dns_seeds contrib/devtools/zkcoin_public_launch_profile_manifest.json",
        "  - next blocker type readiness summary commands by network: main=contrib/devtools/zkcoin_public_launch_profile.py --blocker-type-readiness-summary litecoin_snapshot contrib/devtools/zkcoin_public_launch_profile_manifest.json; testnet=contrib/devtools/zkcoin_public_launch_profile.py --blocker-type-readiness-summary litecoin_snapshot contrib/devtools/zkcoin_public_launch_profile_manifest.json",
        "  - next blocker readiness summary commands by network: main=contrib/devtools/zkcoin_public_launch_profile.py --blocker-readiness-summary main.litecoin_snapshot contrib/devtools/zkcoin_public_launch_profile_manifest.json; testnet=contrib/devtools/zkcoin_public_launch_profile.py --blocker-readiness-summary testnet.litecoin_snapshot contrib/devtools/zkcoin_public_launch_profile_manifest.json",
        "  - network readiness summary commands by network: main=contrib/devtools/zkcoin_public_launch_profile.py --network-readiness-summary main contrib/devtools/zkcoin_public_launch_profile_manifest.json; testnet=contrib/devtools/zkcoin_public_launch_profile.py --network-readiness-summary testnet contrib/devtools/zkcoin_public_launch_profile_manifest.json",
        "  - blocker type readiness summary commands by blocker type: litecoin_snapshot=contrib/devtools/zkcoin_public_launch_profile.py --blocker-type-readiness-summary litecoin_snapshot contrib/devtools/zkcoin_public_launch_profile_manifest.json",
        "  - next blocker: main.litecoin_snapshot",
        "  - next blocker fields: 11",
        "  - blocked field paths:",
        "    - main.litecoin_snapshot.height",
        "    - main.litecoin_snapshot.audit.total_amount",
        "  - template command: contrib/devtools/zkcoin_public_launch_profile.py --snapshot-audit-template main",
        "  - check command: contrib/devtools/zkcoin_public_launch_profile.py --check-snapshot-audit main <snapshot_audit.json>",
        "  - apply command: contrib/devtools/zkcoin_public_launch_profile.py --set-snapshot-audit main <snapshot_audit.json>",
        "  - network readiness summary command: contrib/devtools/zkcoin_public_launch_profile.py --network-readiness-summary main contrib/devtools/zkcoin_public_launch_profile_manifest.json",
        "  - blocker type readiness summary command: contrib/devtools/zkcoin_public_launch_profile.py --blocker-type-readiness-summary litecoin_snapshot contrib/devtools/zkcoin_public_launch_profile_manifest.json",
        "  - blocker readiness summary command: contrib/devtools/zkcoin_public_launch_profile.py --blocker-readiness-summary main.litecoin_snapshot contrib/devtools/zkcoin_public_launch_profile_manifest.json",
        "  - later blockers: main.auxpow_chain_id",
        "  - later blocker readiness summary commands: main.auxpow_chain_id=contrib/devtools/zkcoin_public_launch_profile.py --blocker-readiness-summary main.auxpow_chain_id contrib/devtools/zkcoin_public_launch_profile_manifest.json",
        "testnet.dns_seeds=contrib/devtools/zkcoin_public_launch_profile.py --blocker-readiness-summary testnet.dns_seeds contrib/devtools/zkcoin_public_launch_profile_manifest.json",
    ):
        if expected not in readiness_summary_result.stdout:
            return "{} --readiness-summary did not print {}".format(
                PUBLIC_LAUNCH_MANIFEST_TOOL.relative_to(ROOT_DIR),
                expected,
            )

    network_readiness_result = subprocess.run(
        [
            sys.executable,
            str(PUBLIC_LAUNCH_MANIFEST_TOOL),
            "--network-readiness-summary",
            "main",
            str(PUBLIC_LAUNCH_MANIFEST),
        ],
        check=False,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    if network_readiness_result.returncode != 0:
        return "{} --network-readiness-summary failed for blocked manifest: {}".format(
            PUBLIC_LAUNCH_MANIFEST_TOOL.relative_to(ROOT_DIR),
            network_readiness_result.stderr.strip()
            or network_readiness_result.stdout.strip()
            or "no output",
        )
    for expected in (
        "zkCoin public launch profile network readiness summary:",
        "  - network: main",
        "  - ready for launch profile: no",
        "  - unresolved blockers: 4",
        "  - blocked fields: 23",
        "  - blocked blocker types: litecoin_snapshot, auxpow_chain_id, public_network_identity, dns_seeds",
        "  - ready blocker types: none",
        "  - next blocker: main.litecoin_snapshot",
        "  - next blocker fields: 11",
        "  - blocked field paths:",
        "    - main.litecoin_snapshot.height",
        "    - main.litecoin_snapshot.audit.total_amount",
        "  - template command: contrib/devtools/zkcoin_public_launch_profile.py --snapshot-audit-template main",
        "  - check command: contrib/devtools/zkcoin_public_launch_profile.py --check-snapshot-audit main <snapshot_audit.json>",
        "  - apply command: contrib/devtools/zkcoin_public_launch_profile.py --set-snapshot-audit main <snapshot_audit.json>",
        "  - network readiness summary command: contrib/devtools/zkcoin_public_launch_profile.py --network-readiness-summary main contrib/devtools/zkcoin_public_launch_profile_manifest.json",
        "  - blocker type readiness summary command: contrib/devtools/zkcoin_public_launch_profile.py --blocker-type-readiness-summary litecoin_snapshot contrib/devtools/zkcoin_public_launch_profile_manifest.json",
        "  - blocker readiness summary command: contrib/devtools/zkcoin_public_launch_profile.py --blocker-readiness-summary main.litecoin_snapshot contrib/devtools/zkcoin_public_launch_profile_manifest.json",
        "  - later blockers: main.auxpow_chain_id, main.public_network_identity, main.dns_seeds",
        "  - later blocker readiness summary commands: main.auxpow_chain_id=contrib/devtools/zkcoin_public_launch_profile.py --blocker-readiness-summary main.auxpow_chain_id contrib/devtools/zkcoin_public_launch_profile_manifest.json",
        "main.dns_seeds=contrib/devtools/zkcoin_public_launch_profile.py --blocker-readiness-summary main.dns_seeds contrib/devtools/zkcoin_public_launch_profile_manifest.json",
    ):
        if expected not in network_readiness_result.stdout:
            return "{} --network-readiness-summary did not print {}".format(
                PUBLIC_LAUNCH_MANIFEST_TOOL.relative_to(ROOT_DIR),
                expected,
            )

    blocker_type_readiness_result = subprocess.run(
        [
            sys.executable,
            str(PUBLIC_LAUNCH_MANIFEST_TOOL),
            "--blocker-type-readiness-summary",
            "litecoin_snapshot",
            str(PUBLIC_LAUNCH_MANIFEST),
        ],
        check=False,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    if blocker_type_readiness_result.returncode != 0:
        return "{} --blocker-type-readiness-summary failed for blocked manifest: {}".format(
            PUBLIC_LAUNCH_MANIFEST_TOOL.relative_to(ROOT_DIR),
            blocker_type_readiness_result.stderr.strip()
            or blocker_type_readiness_result.stdout.strip()
            or "no output",
        )
    for expected in (
        "zkCoin public launch profile blocker-type readiness summary:",
        "  - blocker type: litecoin_snapshot",
        "  - ready for launch profile: no",
        "  - unresolved blockers: 2",
        "  - blocked fields: 22",
        "  - blocked networks: main, testnet",
        "  - ready networks: none",
        "  - next blocker: main.litecoin_snapshot",
        "  - next blocker fields: 11",
        "  - blocked field paths:",
        "    - main.litecoin_snapshot.height",
        "    - main.litecoin_snapshot.audit.total_amount",
        "  - template command: contrib/devtools/zkcoin_public_launch_profile.py --snapshot-audit-template main",
        "  - check command: contrib/devtools/zkcoin_public_launch_profile.py --check-snapshot-audit main <snapshot_audit.json>",
        "  - apply command: contrib/devtools/zkcoin_public_launch_profile.py --set-snapshot-audit main <snapshot_audit.json>",
        "  - network readiness summary command: contrib/devtools/zkcoin_public_launch_profile.py --network-readiness-summary main contrib/devtools/zkcoin_public_launch_profile_manifest.json",
        "  - blocker type readiness summary command: contrib/devtools/zkcoin_public_launch_profile.py --blocker-type-readiness-summary litecoin_snapshot contrib/devtools/zkcoin_public_launch_profile_manifest.json",
        "  - blocker readiness summary command: contrib/devtools/zkcoin_public_launch_profile.py --blocker-readiness-summary main.litecoin_snapshot contrib/devtools/zkcoin_public_launch_profile_manifest.json",
        "  - later blockers: testnet.litecoin_snapshot",
        "  - later blocker readiness summary commands: testnet.litecoin_snapshot=contrib/devtools/zkcoin_public_launch_profile.py --blocker-readiness-summary testnet.litecoin_snapshot contrib/devtools/zkcoin_public_launch_profile_manifest.json",
    ):
        if expected not in blocker_type_readiness_result.stdout:
            return "{} --blocker-type-readiness-summary did not print {}".format(
                PUBLIC_LAUNCH_MANIFEST_TOOL.relative_to(ROOT_DIR),
                expected,
            )

    blocker_readiness_result = subprocess.run(
        [
            sys.executable,
            str(PUBLIC_LAUNCH_MANIFEST_TOOL),
            "--blocker-readiness-summary",
            "main.litecoin_snapshot",
            str(PUBLIC_LAUNCH_MANIFEST),
        ],
        check=False,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    if blocker_readiness_result.returncode != 0:
        return "{} --blocker-readiness-summary failed for blocked manifest: {}".format(
            PUBLIC_LAUNCH_MANIFEST_TOOL.relative_to(ROOT_DIR),
            blocker_readiness_result.stderr.strip()
            or blocker_readiness_result.stdout.strip()
            or "no output",
        )
    for expected in (
        "zkCoin public launch profile blocker readiness summary:",
        "  - blocker: main.litecoin_snapshot",
        "  - launch order: 1 of 8",
        "  - network launch order: 1 of 4",
        "  - blocker-type launch order: 1 of 2",
        "  - network: main",
        "  - blocker type: litecoin_snapshot",
        "  - blocked fields: 11",
        "  - action: select and verify the final Litecoin snapshot",
        "  - blocked field paths:",
        "    - main.litecoin_snapshot.height",
        "    - main.litecoin_snapshot.audit.total_amount",
        "  - template command: contrib/devtools/zkcoin_public_launch_profile.py --snapshot-audit-template main",
        "  - check command: contrib/devtools/zkcoin_public_launch_profile.py --check-snapshot-audit main <snapshot_audit.json>",
        "  - apply command: contrib/devtools/zkcoin_public_launch_profile.py --set-snapshot-audit main <snapshot_audit.json>",
        "  - network readiness summary command: contrib/devtools/zkcoin_public_launch_profile.py --network-readiness-summary main contrib/devtools/zkcoin_public_launch_profile_manifest.json",
        "  - blocker type readiness summary command: contrib/devtools/zkcoin_public_launch_profile.py --blocker-type-readiness-summary litecoin_snapshot contrib/devtools/zkcoin_public_launch_profile_manifest.json",
        "  - blocker readiness summary command: contrib/devtools/zkcoin_public_launch_profile.py --blocker-readiness-summary main.litecoin_snapshot contrib/devtools/zkcoin_public_launch_profile_manifest.json",
        "  - later blockers: main.auxpow_chain_id, main.public_network_identity, main.dns_seeds, testnet.litecoin_snapshot",
        "  - later blocker readiness summary commands: main.auxpow_chain_id=contrib/devtools/zkcoin_public_launch_profile.py --blocker-readiness-summary main.auxpow_chain_id contrib/devtools/zkcoin_public_launch_profile_manifest.json",
        "testnet.dns_seeds=contrib/devtools/zkcoin_public_launch_profile.py --blocker-readiness-summary testnet.dns_seeds contrib/devtools/zkcoin_public_launch_profile_manifest.json",
    ):
        if expected not in blocker_readiness_result.stdout:
            return "{} --blocker-readiness-summary did not print {}".format(
                PUBLIC_LAUNCH_MANIFEST_TOOL.relative_to(ROOT_DIR),
                expected,
            )

    terminal_blocker_readiness_result = subprocess.run(
        [
            sys.executable,
            str(PUBLIC_LAUNCH_MANIFEST_TOOL),
            "--blocker-readiness-summary",
            "testnet.dns_seeds",
            str(PUBLIC_LAUNCH_MANIFEST),
        ],
        check=False,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    if terminal_blocker_readiness_result.returncode != 0:
        return "{} --blocker-readiness-summary failed for terminal blocked manifest blocker: {}".format(
            PUBLIC_LAUNCH_MANIFEST_TOOL.relative_to(ROOT_DIR),
            terminal_blocker_readiness_result.stderr.strip()
            or terminal_blocker_readiness_result.stdout.strip()
            or "no output",
        )
    for expected in (
        "  - blocker: testnet.dns_seeds",
        "  - launch order: 8 of 8",
        "  - network launch order: 4 of 4",
        "  - blocker-type launch order: 2 of 2",
        "  - earlier blockers: main.litecoin_snapshot, main.auxpow_chain_id, main.public_network_identity, main.dns_seeds, testnet.litecoin_snapshot, testnet.auxpow_chain_id, testnet.public_network_identity",
        "  - earlier blocker readiness summary commands: main.litecoin_snapshot=contrib/devtools/zkcoin_public_launch_profile.py --blocker-readiness-summary main.litecoin_snapshot contrib/devtools/zkcoin_public_launch_profile_manifest.json",
        "testnet.public_network_identity=contrib/devtools/zkcoin_public_launch_profile.py --blocker-readiness-summary testnet.public_network_identity contrib/devtools/zkcoin_public_launch_profile_manifest.json",
    ):
        if expected not in terminal_blocker_readiness_result.stdout:
            return "{} --blocker-readiness-summary did not print terminal blocker {}".format(
                PUBLIC_LAUNCH_MANIFEST_TOOL.relative_to(ROOT_DIR),
                expected,
            )

    status_json_result = subprocess.run(
        [
            sys.executable,
            str(PUBLIC_LAUNCH_MANIFEST_TOOL),
            "--status-json",
            str(PUBLIC_LAUNCH_MANIFEST),
        ],
        check=False,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    if status_json_result.returncode != 0:
        return "{} --status-json failed for blocked manifest: {}".format(
            PUBLIC_LAUNCH_MANIFEST_TOOL.relative_to(ROOT_DIR),
            status_json_result.stderr.strip() or status_json_result.stdout.strip() or "no output",
        )
    try:
        status_json = json.loads(status_json_result.stdout)
    except json.JSONDecodeError as exc:
        return "{} --status-json did not emit JSON: {}".format(
            PUBLIC_LAUNCH_MANIFEST_TOOL.relative_to(ROOT_DIR),
            exc,
        )
    schema_version_error = require_status_json_schema_version(status_json)
    if schema_version_error:
        return schema_version_error
    if status_json.get("status") != "blocked":
        return "{} --status-json did not report blocked status".format(
            PUBLIC_LAUNCH_MANIFEST_TOOL.relative_to(ROOT_DIR)
        )
    if status_json.get("ready_for_chainparams") is not False:
        return "{} --status-json treated blocked manifest as ready".format(
            PUBLIC_LAUNCH_MANIFEST_TOOL.relative_to(ROOT_DIR)
        )
    if status_json.get("blocked_network_count") != 2 or status_json.get("blocked_networks") != ["main", "testnet"]:
        return "{} --status-json did not summarize blocked networks".format(
            PUBLIC_LAUNCH_MANIFEST_TOOL.relative_to(ROOT_DIR)
        )
    if status_json.get("ready_network_count") != 0 or status_json.get("ready_networks") != []:
        return "{} --status-json reported ready networks for a blocked manifest".format(
            PUBLIC_LAUNCH_MANIFEST_TOOL.relative_to(ROOT_DIR)
        )
    expected_blocker_type_order = [
        "litecoin_snapshot",
        "auxpow_chain_id",
        "public_network_identity",
        "dns_seeds",
    ]
    if (
        status_json.get("blocked_blocker_type_count") != 4
        or status_json.get("blocked_blocker_types") != expected_blocker_type_order
    ):
        return "{} --status-json did not summarize blocked blocker types".format(
            PUBLIC_LAUNCH_MANIFEST_TOOL.relative_to(ROOT_DIR)
        )
    if status_json.get("ready_blocker_type_count") != 0 or status_json.get("ready_blocker_types") != []:
        return "{} --status-json reported ready blocker types for a blocked manifest".format(
            PUBLIC_LAUNCH_MANIFEST_TOOL.relative_to(ROOT_DIR)
        )
    expected_blocker_types_by_network = {
        "main": expected_blocker_type_order,
        "testnet": expected_blocker_type_order,
    }
    empty_blocker_types_by_network = {"main": [], "testnet": []}
    expected_blocker_type_counts_by_network = {"main": 4, "testnet": 4}
    empty_blocker_type_counts_by_network = {"main": 0, "testnet": 0}
    expected_networks_by_blocker_type = {
        blocker_type: ["main", "testnet"]
        for blocker_type in expected_blocker_type_order
    }
    empty_networks_by_blocker_type = {
        blocker_type: []
        for blocker_type in expected_blocker_type_order
    }
    expected_network_counts_by_blocker_type = {
        blocker_type: 2
        for blocker_type in expected_blocker_type_order
    }
    empty_network_counts_by_blocker_type = {
        blocker_type: 0
        for blocker_type in expected_blocker_type_order
    }
    if status_json.get("blocked_blocker_types_by_network") != expected_blocker_types_by_network:
        return "{} --status-json did not summarize blocked blocker types by network".format(
            PUBLIC_LAUNCH_MANIFEST_TOOL.relative_to(ROOT_DIR)
        )
    if status_json.get("blocked_blocker_type_counts_by_network") != expected_blocker_type_counts_by_network:
        return "{} --status-json did not count blocked blocker types by network".format(
            PUBLIC_LAUNCH_MANIFEST_TOOL.relative_to(ROOT_DIR)
        )
    if status_json.get("ready_blocker_types_by_network") != empty_blocker_types_by_network:
        return "{} --status-json reported ready blocker types by network for a blocked manifest".format(
            PUBLIC_LAUNCH_MANIFEST_TOOL.relative_to(ROOT_DIR)
        )
    if status_json.get("ready_blocker_type_counts_by_network") != empty_blocker_type_counts_by_network:
        return "{} --status-json counted ready blocker types by network for a blocked manifest".format(
            PUBLIC_LAUNCH_MANIFEST_TOOL.relative_to(ROOT_DIR)
        )
    if status_json.get("blocked_networks_by_blocker_type") != expected_networks_by_blocker_type:
        return "{} --status-json did not summarize blocked networks by blocker type".format(
            PUBLIC_LAUNCH_MANIFEST_TOOL.relative_to(ROOT_DIR)
        )
    if status_json.get("blocked_network_counts_by_blocker_type") != expected_network_counts_by_blocker_type:
        return "{} --status-json did not count blocked networks by blocker type".format(
            PUBLIC_LAUNCH_MANIFEST_TOOL.relative_to(ROOT_DIR)
        )
    if status_json.get("ready_networks_by_blocker_type") != empty_networks_by_blocker_type:
        return "{} --status-json reported ready networks by blocker type for a blocked manifest".format(
            PUBLIC_LAUNCH_MANIFEST_TOOL.relative_to(ROOT_DIR)
        )
    if status_json.get("ready_network_counts_by_blocker_type") != empty_network_counts_by_blocker_type:
        return "{} --status-json counted ready networks by blocker type for a blocked manifest".format(
            PUBLIC_LAUNCH_MANIFEST_TOOL.relative_to(ROOT_DIR)
        )
    if status_json.get("unresolved_blocker_count") != 8:
        return "{} --status-json did not count unresolved blocker groups".format(
            PUBLIC_LAUNCH_MANIFEST_TOOL.relative_to(ROOT_DIR)
        )
    if status_json.get("unresolved_blocker_counts_by_network") != {"main": 4, "testnet": 4}:
        return "{} --status-json did not count unresolved blockers by network".format(
            PUBLIC_LAUNCH_MANIFEST_TOOL.relative_to(ROOT_DIR)
        )
    if status_json.get("unresolved_blockers_by_network", {}).get("main") != [
        "main.litecoin_snapshot",
        "main.auxpow_chain_id",
        "main.public_network_identity",
        "main.dns_seeds",
    ]:
        return "{} --status-json did not group mainnet blockers by network".format(
            PUBLIC_LAUNCH_MANIFEST_TOOL.relative_to(ROOT_DIR)
        )
    if status_json.get("unresolved_blockers_by_network", {}).get("testnet") != [
        "testnet.litecoin_snapshot",
        "testnet.auxpow_chain_id",
        "testnet.public_network_identity",
        "testnet.dns_seeds",
    ]:
        return "{} --status-json did not group testnet blockers by network".format(
            PUBLIC_LAUNCH_MANIFEST_TOOL.relative_to(ROOT_DIR)
        )
    if status_json.get("action_count") != 8:
        return "{} --status-json did not count action-plan entries".format(
            PUBLIC_LAUNCH_MANIFEST_TOOL.relative_to(ROOT_DIR)
        )
    if status_json.get("action_counts_by_network") != {"main": 4, "testnet": 4}:
        return "{} --status-json did not count action-plan entries by network".format(
            PUBLIC_LAUNCH_MANIFEST_TOOL.relative_to(ROOT_DIR)
        )
    expected_action_counts_by_blocker_type = {
        "litecoin_snapshot": 2,
        "auxpow_chain_id": 2,
        "public_network_identity": 2,
        "dns_seeds": 2,
    }
    expected_blockers_by_blocker_type = {
        "litecoin_snapshot": ["main.litecoin_snapshot", "testnet.litecoin_snapshot"],
        "auxpow_chain_id": ["main.auxpow_chain_id", "testnet.auxpow_chain_id"],
        "public_network_identity": [
            "main.public_network_identity",
            "testnet.public_network_identity",
        ],
        "dns_seeds": ["main.dns_seeds", "testnet.dns_seeds"],
    }
    expected_blocker_counts_by_blocker_type = {
        blocker_type: len(blockers)
        for blocker_type, blockers in expected_blockers_by_blocker_type.items()
    }
    empty_blockers_by_blocker_type = {
        blocker_type: []
        for blocker_type in expected_blockers_by_blocker_type
    }
    empty_blocker_counts_by_blocker_type = {
        blocker_type: 0
        for blocker_type in expected_blockers_by_blocker_type
    }
    expected_blocker_counts_by_network_and_blocker_type = {
        network: {
            blocker_type: 1
            for blocker_type in expected_blockers_by_blocker_type
        }
        for network in ("main", "testnet")
    }
    expected_blockers_by_network_and_blocker_type = {
        "main": {
            "litecoin_snapshot": ["main.litecoin_snapshot"],
            "auxpow_chain_id": ["main.auxpow_chain_id"],
            "public_network_identity": ["main.public_network_identity"],
            "dns_seeds": ["main.dns_seeds"],
        },
        "testnet": {
            "litecoin_snapshot": ["testnet.litecoin_snapshot"],
            "auxpow_chain_id": ["testnet.auxpow_chain_id"],
            "public_network_identity": ["testnet.public_network_identity"],
            "dns_seeds": ["testnet.dns_seeds"],
        },
    }
    expected_blocked_field_group_ids_by_network_and_blocker_type = expected_blockers_by_network_and_blocker_type
    expected_blocked_field_group_counts_by_network_and_blocker_type = {
        network: {
            blocker_type: len(group_ids)
            for blocker_type, group_ids in groups_by_type.items()
        }
        for network, groups_by_type in expected_blocked_field_group_ids_by_network_and_blocker_type.items()
    }
    expected_action_counts_by_network_and_blocker_type = {
        network: {
            blocker_type: len(actions)
            for blocker_type, actions in actions_by_type.items()
        }
        for network, actions_by_type in expected_blockers_by_network_and_blocker_type.items()
    }
    expected_next_action_ids_by_network_and_blocker_type = {
        network: {
            blocker_type: actions[0] if actions else None
            for blocker_type, actions in actions_by_type.items()
        }
        for network, actions_by_type in expected_blockers_by_network_and_blocker_type.items()
    }
    empty_counts_by_network_and_blocker_type = {
        network: {
            blocker_type: 0
            for blocker_type in expected_blockers_by_blocker_type
        }
        for network in ("main", "testnet")
    }
    empty_items_by_network_and_blocker_type = {
        network: {
            blocker_type: []
            for blocker_type in expected_blockers_by_blocker_type
        }
        for network in ("main", "testnet")
    }
    empty_next_by_network_and_blocker_type = {
        network: {
            blocker_type: None
            for blocker_type in expected_blockers_by_blocker_type
        }
        for network in ("main", "testnet")
    }

    def action_ids_by_network_and_blocker_type(groups):
        return {
            network: {
                blocker_type: [
                    action.get("id")
                    for action in groups.get(network, {}).get(blocker_type, [])
                ]
                for blocker_type in expected_blockers_by_blocker_type
            }
            for network in ("main", "testnet")
        }

    def next_action_ids_by_network_and_blocker_type(groups):
        return {
            network: {
                blocker_type: (
                    groups.get(network, {}).get(blocker_type, {}) or {}
                ).get("id")
                for blocker_type in expected_blockers_by_blocker_type
            }
            for network in ("main", "testnet")
        }

    def group_ids_by_network_and_blocker_type(groups):
        return {
            network: {
                blocker_type: [
                    group.get("id")
                    for group in groups.get(network, {}).get(blocker_type, [])
                ]
                for blocker_type in expected_blockers_by_blocker_type
            }
            for network in ("main", "testnet")
        }

    empty_blocker_type_progress = {
        blocker_type: {
            "ready_for_launch_profile": True,
            "unresolved_blocker_count": 0,
            "unresolved_blockers": [],
            "blocked_field_count": 0,
            "blocked_fields": [],
            "next_action": None,
        }
        for blocker_type in expected_blockers_by_blocker_type
    }
    expected_next_blocked_field_group_ids_by_blocker_type = {
        "litecoin_snapshot": "main.litecoin_snapshot",
        "auxpow_chain_id": "main.auxpow_chain_id",
        "public_network_identity": "main.public_network_identity",
        "dns_seeds": "main.dns_seeds",
    }
    if status_json.get("action_counts_by_blocker_type") != expected_action_counts_by_blocker_type:
        return "{} --status-json did not count action-plan entries by blocker type".format(
            PUBLIC_LAUNCH_MANIFEST_TOOL.relative_to(ROOT_DIR)
        )
    action_count_matrix = status_json.get("action_counts_by_network_and_blocker_type")
    if action_count_matrix != expected_action_counts_by_network_and_blocker_type:
        return "{} --status-json did not count action-plan entries by network and blocker type".format(
            PUBLIC_LAUNCH_MANIFEST_TOOL.relative_to(ROOT_DIR)
        )
    action_id_matrix = action_ids_by_network_and_blocker_type(
        status_json.get("actions_by_network_and_blocker_type", {})
    )
    if action_id_matrix != expected_blockers_by_network_and_blocker_type:
        return "{} --status-json did not group action-plan entries by network and blocker type".format(
            PUBLIC_LAUNCH_MANIFEST_TOOL.relative_to(ROOT_DIR)
        )
    next_action_id_matrix = next_action_ids_by_network_and_blocker_type(
        status_json.get("next_actions_by_network_and_blocker_type", {})
    )
    if next_action_id_matrix != expected_next_action_ids_by_network_and_blocker_type:
        return "{} --status-json did not expose next action entries by network and blocker type".format(
            PUBLIC_LAUNCH_MANIFEST_TOOL.relative_to(ROOT_DIR)
        )
    next_commands_by_network_and_blocker_type = status_json.get("next_commands_by_network_and_blocker_type", {})
    if "--check-snapshot-audit main <snapshot_audit.json>" not in next_commands_by_network_and_blocker_type.get("main", {}).get("litecoin_snapshot", {}).get("check_command", ""):
        return "{} --status-json did not expose mainnet snapshot next commands by network and blocker type".format(
            PUBLIC_LAUNCH_MANIFEST_TOOL.relative_to(ROOT_DIR)
        )
    if "--blocker-readiness-summary testnet.dns_seeds" not in next_commands_by_network_and_blocker_type.get("testnet", {}).get("dns_seeds", {}).get("blocker_readiness_summary_command", ""):
        return "{} --status-json did not expose testnet DNS seed next commands by network and blocker type".format(
            PUBLIC_LAUNCH_MANIFEST_TOOL.relative_to(ROOT_DIR)
        )
    if status_json.get("next_blocker_commands_by_network_and_blocker_type") != next_commands_by_network_and_blocker_type:
        return "{} --status-json did not alias matrix next blocker commands".format(
            PUBLIC_LAUNCH_MANIFEST_TOOL.relative_to(ROOT_DIR)
        )
    if status_json.get("unresolved_blockers_by_blocker_type") != expected_blockers_by_blocker_type:
        return "{} --status-json did not group unresolved blockers by blocker type".format(
            PUBLIC_LAUNCH_MANIFEST_TOOL.relative_to(ROOT_DIR)
        )
    if status_json.get("unresolved_blocker_counts_by_blocker_type") != expected_blocker_counts_by_blocker_type:
        return "{} --status-json did not count unresolved blockers by blocker type".format(
            PUBLIC_LAUNCH_MANIFEST_TOOL.relative_to(ROOT_DIR)
        )
    if status_json.get("unresolved_blocker_counts_by_network_and_blocker_type") != expected_blocker_counts_by_network_and_blocker_type:
        return "{} --status-json did not count unresolved blockers by network and blocker type".format(
            PUBLIC_LAUNCH_MANIFEST_TOOL.relative_to(ROOT_DIR)
        )
    if status_json.get("unresolved_blockers_by_network_and_blocker_type") != expected_blockers_by_network_and_blocker_type:
        return "{} --status-json did not group unresolved blockers by network and blocker type".format(
            PUBLIC_LAUNCH_MANIFEST_TOOL.relative_to(ROOT_DIR)
        )
    actions_by_network = status_json.get("actions_by_network", {})
    if [action.get("id") for action in actions_by_network.get("main", [])] != [
        "main.litecoin_snapshot",
        "main.auxpow_chain_id",
        "main.public_network_identity",
        "main.dns_seeds",
    ]:
        return "{} --status-json did not group mainnet action entries by network".format(
            PUBLIC_LAUNCH_MANIFEST_TOOL.relative_to(ROOT_DIR)
        )
    if [action.get("id") for action in actions_by_network.get("testnet", [])] != [
        "testnet.litecoin_snapshot",
        "testnet.auxpow_chain_id",
        "testnet.public_network_identity",
        "testnet.dns_seeds",
    ]:
        return "{} --status-json did not group testnet action entries by network".format(
            PUBLIC_LAUNCH_MANIFEST_TOOL.relative_to(ROOT_DIR)
        )
    actions_by_blocker_type = status_json.get("actions_by_blocker_type", {})
    if [action.get("id") for action in actions_by_blocker_type.get("litecoin_snapshot", [])] != [
        "main.litecoin_snapshot",
        "testnet.litecoin_snapshot",
    ]:
        return "{} --status-json did not group snapshot action entries by blocker type".format(
            PUBLIC_LAUNCH_MANIFEST_TOOL.relative_to(ROOT_DIR)
        )
    if [action.get("id") for action in actions_by_blocker_type.get("dns_seeds", [])] != [
        "main.dns_seeds",
        "testnet.dns_seeds",
    ]:
        return "{} --status-json did not group DNS seed action entries by blocker type".format(
            PUBLIC_LAUNCH_MANIFEST_TOOL.relative_to(ROOT_DIR)
        )
    next_actions_by_blocker_type = status_json.get("next_actions_by_blocker_type", {})
    if {blocker_type: action.get("id") for blocker_type, action in next_actions_by_blocker_type.items()} != {
        "litecoin_snapshot": "main.litecoin_snapshot",
        "auxpow_chain_id": "main.auxpow_chain_id",
        "public_network_identity": "main.public_network_identity",
        "dns_seeds": "main.dns_seeds",
    }:
        return "{} --status-json did not expose next actions by blocker type".format(
            PUBLIC_LAUNCH_MANIFEST_TOOL.relative_to(ROOT_DIR)
        )
    if status_json.get("next_blockers_by_blocker_type") != {
        "litecoin_snapshot": "main.litecoin_snapshot",
        "auxpow_chain_id": "main.auxpow_chain_id",
        "public_network_identity": "main.public_network_identity",
        "dns_seeds": "main.dns_seeds",
    }:
        return "{} --status-json did not expose next blockers by blocker type".format(
            PUBLIC_LAUNCH_MANIFEST_TOOL.relative_to(ROOT_DIR)
        )
    if status_json.get("next_blocker_networks_by_blocker_type") != {
        "litecoin_snapshot": "main",
        "auxpow_chain_id": "main",
        "public_network_identity": "main",
        "dns_seeds": "main",
    }:
        return "{} --status-json did not expose next blocker networks by blocker type".format(
            PUBLIC_LAUNCH_MANIFEST_TOOL.relative_to(ROOT_DIR)
        )
    next_groups_by_blocker_type = status_json.get("next_blocked_field_groups_by_blocker_type", {})
    if {
        blocker_type: group.get("id") if group else None
        for blocker_type, group in next_groups_by_blocker_type.items()
    } != expected_next_blocked_field_group_ids_by_blocker_type:
        return "{} --status-json did not expose next blocker groups by blocker type".format(
            PUBLIC_LAUNCH_MANIFEST_TOOL.relative_to(ROOT_DIR)
        )
    if status_json.get("next_blocker_field_groups_by_blocker_type") != next_groups_by_blocker_type:
        return "{} --status-json did not alias next blocker groups by blocker type".format(
            PUBLIC_LAUNCH_MANIFEST_TOOL.relative_to(ROOT_DIR)
        )
    if status_json.get("next_blocked_field_counts_by_blocker_type") != {
        "litecoin_snapshot": 11,
        "auxpow_chain_id": 1,
        "public_network_identity": 10,
        "dns_seeds": 1,
    }:
        return "{} --status-json did not expose next blocked field counts by blocker type".format(
            PUBLIC_LAUNCH_MANIFEST_TOOL.relative_to(ROOT_DIR)
        )
    if status_json.get("next_blocker_field_counts_by_blocker_type") != status_json.get("next_blocked_field_counts_by_blocker_type"):
        return "{} --status-json did not alias next blocker field counts by blocker type".format(
            PUBLIC_LAUNCH_MANIFEST_TOOL.relative_to(ROOT_DIR)
        )
    next_fields_by_blocker_type = status_json.get("next_blocked_fields_by_blocker_type", {})
    if next_fields_by_blocker_type.get("litecoin_snapshot", [None])[0] != "main.litecoin_snapshot.height":
        return "{} --status-json did not expose snapshot next blocked fields by blocker type".format(
            PUBLIC_LAUNCH_MANIFEST_TOOL.relative_to(ROOT_DIR)
        )
    if next_fields_by_blocker_type.get("dns_seeds") != ["main.public_network_identity.dns_seeds"]:
        return "{} --status-json did not expose DNS seed next blocked fields by blocker type".format(
            PUBLIC_LAUNCH_MANIFEST_TOOL.relative_to(ROOT_DIR)
        )
    if status_json.get("next_blocker_fields_by_blocker_type") != next_fields_by_blocker_type:
        return "{} --status-json did not alias next blocker fields by blocker type".format(
            PUBLIC_LAUNCH_MANIFEST_TOOL.relative_to(ROOT_DIR)
        )
    next_commands_by_blocker_type = status_json.get("next_commands_by_blocker_type", {})
    if "--snapshot-audit-template main" not in next_commands_by_blocker_type.get("litecoin_snapshot", {}).get("template_command", ""):
        return "{} --status-json did not expose snapshot next commands by blocker type".format(
            PUBLIC_LAUNCH_MANIFEST_TOOL.relative_to(ROOT_DIR)
        )
    if "--check-dns-seeds main <seed1.hostname>,<seed2.hostname>" not in next_commands_by_blocker_type.get("dns_seeds", {}).get("check_command", ""):
        return "{} --status-json did not expose DNS seed next commands by blocker type".format(
            PUBLIC_LAUNCH_MANIFEST_TOOL.relative_to(ROOT_DIR)
        )
    if status_json.get("next_blocker_commands_by_blocker_type") != next_commands_by_blocker_type:
        return "{} --status-json did not alias blocker-type next blocker commands".format(
            PUBLIC_LAUNCH_MANIFEST_TOOL.relative_to(ROOT_DIR)
        )
    blocker_type_progress = status_json.get("blocker_type_progress", {})
    snapshot_progress = blocker_type_progress.get("litecoin_snapshot", {})
    if snapshot_progress.get("ready_for_launch_profile") is not False:
        return "{} --status-json treated snapshot workstream as ready".format(
            PUBLIC_LAUNCH_MANIFEST_TOOL.relative_to(ROOT_DIR)
        )
    if snapshot_progress.get("unresolved_blockers") != expected_blockers_by_blocker_type["litecoin_snapshot"]:
        return "{} --status-json did not expose snapshot blocker-type progress blockers".format(
            PUBLIC_LAUNCH_MANIFEST_TOOL.relative_to(ROOT_DIR)
        )
    if snapshot_progress.get("blocked_field_count") != 22:
        return "{} --status-json did not expose snapshot blocker-type progress field count".format(
            PUBLIC_LAUNCH_MANIFEST_TOOL.relative_to(ROOT_DIR)
        )
    if snapshot_progress.get("next_action") != next_actions_by_blocker_type.get("litecoin_snapshot"):
        return "{} --status-json did not expose snapshot blocker-type progress next action".format(
            PUBLIC_LAUNCH_MANIFEST_TOOL.relative_to(ROOT_DIR)
        )
    dns_progress = blocker_type_progress.get("dns_seeds", {})
    if dns_progress.get("blocked_fields") != [
        "main.public_network_identity.dns_seeds",
        "testnet.public_network_identity.dns_seeds",
    ]:
        return "{} --status-json did not expose DNS seed blocker-type progress fields".format(
            PUBLIC_LAUNCH_MANIFEST_TOOL.relative_to(ROOT_DIR)
        )
    if dns_progress.get("next_action") != next_actions_by_blocker_type.get("dns_seeds"):
        return "{} --status-json did not expose DNS seed blocker-type progress next action".format(
            PUBLIC_LAUNCH_MANIFEST_TOOL.relative_to(ROOT_DIR)
        )
    if status_json.get("blocked_field_count") != 46:
        return "{} --status-json did not count field-level blockers".format(
            PUBLIC_LAUNCH_MANIFEST_TOOL.relative_to(ROOT_DIR)
        )
    if status_json.get("blocked_field_counts_by_network") != {"main": 23, "testnet": 23}:
        return "{} --status-json did not count field-level blockers by network".format(
            PUBLIC_LAUNCH_MANIFEST_TOOL.relative_to(ROOT_DIR)
        )
    expected_blocked_fields_by_network = {
        "main": [
            "main.litecoin_snapshot.height",
            "main.litecoin_snapshot.block_hash",
            "main.litecoin_snapshot.import_hash",
            "main.litecoin_snapshot.audit.snapshot_hash",
            "main.litecoin_snapshot.audit.coins",
            "main.litecoin_snapshot.audit.base_nchaintx",
            "main.litecoin_snapshot.audit.source_chain",
            "main.litecoin_snapshot.audit.snapshot_file_size",
            "main.litecoin_snapshot.audit.snapshot_file_sha256",
            "main.litecoin_snapshot.audit.snapshot_file",
            "main.litecoin_snapshot.audit.total_amount",
            "main.auxpow.chain_id",
            "main.public_network_identity.message_start",
            "main.public_network_identity.default_port",
            "main.public_network_identity.dns_seeds",
            "main.public_network_identity.base58_prefixes.pubkey_address",
            "main.public_network_identity.base58_prefixes.script_address",
            "main.public_network_identity.base58_prefixes.script_address2",
            "main.public_network_identity.base58_prefixes.secret_key",
            "main.public_network_identity.base58_prefixes.ext_public_key",
            "main.public_network_identity.base58_prefixes.ext_secret_key",
            "main.public_network_identity.bech32_hrp",
            "main.public_network_identity.mweb_hrp",
        ],
        "testnet": [
            "testnet.litecoin_snapshot.height",
            "testnet.litecoin_snapshot.block_hash",
            "testnet.litecoin_snapshot.import_hash",
            "testnet.litecoin_snapshot.audit.snapshot_hash",
            "testnet.litecoin_snapshot.audit.coins",
            "testnet.litecoin_snapshot.audit.base_nchaintx",
            "testnet.litecoin_snapshot.audit.source_chain",
            "testnet.litecoin_snapshot.audit.snapshot_file_size",
            "testnet.litecoin_snapshot.audit.snapshot_file_sha256",
            "testnet.litecoin_snapshot.audit.snapshot_file",
            "testnet.litecoin_snapshot.audit.total_amount",
            "testnet.auxpow.chain_id",
            "testnet.public_network_identity.message_start",
            "testnet.public_network_identity.default_port",
            "testnet.public_network_identity.dns_seeds",
            "testnet.public_network_identity.base58_prefixes.pubkey_address",
            "testnet.public_network_identity.base58_prefixes.script_address",
            "testnet.public_network_identity.base58_prefixes.script_address2",
            "testnet.public_network_identity.base58_prefixes.secret_key",
            "testnet.public_network_identity.base58_prefixes.ext_public_key",
            "testnet.public_network_identity.base58_prefixes.ext_secret_key",
            "testnet.public_network_identity.bech32_hrp",
            "testnet.public_network_identity.mweb_hrp",
        ],
    }
    if status_json.get("blocked_fields_by_network") != expected_blocked_fields_by_network:
        return "{} --status-json did not group field-level blockers by network".format(
            PUBLIC_LAUNCH_MANIFEST_TOOL.relative_to(ROOT_DIR)
        )
    expected_blocked_field_counts_by_blocker_type = {
        "litecoin_snapshot": 22,
        "auxpow_chain_id": 2,
        "public_network_identity": 20,
        "dns_seeds": 2,
    }
    expected_blocked_field_counts_by_network_and_blocker_type = {
        "main": {
            "litecoin_snapshot": 11,
            "auxpow_chain_id": 1,
            "public_network_identity": 10,
            "dns_seeds": 1,
        },
        "testnet": {
            "litecoin_snapshot": 11,
            "auxpow_chain_id": 1,
            "public_network_identity": 10,
            "dns_seeds": 1,
        },
    }
    expected_blocked_fields_by_network_and_blocker_type = {
        "main": {
            "litecoin_snapshot": [
                "main.litecoin_snapshot.height",
                "main.litecoin_snapshot.block_hash",
                "main.litecoin_snapshot.import_hash",
                "main.litecoin_snapshot.audit.snapshot_hash",
                "main.litecoin_snapshot.audit.coins",
                "main.litecoin_snapshot.audit.base_nchaintx",
                "main.litecoin_snapshot.audit.source_chain",
                "main.litecoin_snapshot.audit.snapshot_file_size",
                "main.litecoin_snapshot.audit.snapshot_file_sha256",
                "main.litecoin_snapshot.audit.snapshot_file",
                "main.litecoin_snapshot.audit.total_amount",
            ],
            "auxpow_chain_id": ["main.auxpow.chain_id"],
            "public_network_identity": [
                "main.public_network_identity.message_start",
                "main.public_network_identity.default_port",
                "main.public_network_identity.base58_prefixes.pubkey_address",
                "main.public_network_identity.base58_prefixes.script_address",
                "main.public_network_identity.base58_prefixes.script_address2",
                "main.public_network_identity.base58_prefixes.secret_key",
                "main.public_network_identity.base58_prefixes.ext_public_key",
                "main.public_network_identity.base58_prefixes.ext_secret_key",
                "main.public_network_identity.bech32_hrp",
                "main.public_network_identity.mweb_hrp",
            ],
            "dns_seeds": ["main.public_network_identity.dns_seeds"],
        },
        "testnet": {
            "litecoin_snapshot": [
                "testnet.litecoin_snapshot.height",
                "testnet.litecoin_snapshot.block_hash",
                "testnet.litecoin_snapshot.import_hash",
                "testnet.litecoin_snapshot.audit.snapshot_hash",
                "testnet.litecoin_snapshot.audit.coins",
                "testnet.litecoin_snapshot.audit.base_nchaintx",
                "testnet.litecoin_snapshot.audit.source_chain",
                "testnet.litecoin_snapshot.audit.snapshot_file_size",
                "testnet.litecoin_snapshot.audit.snapshot_file_sha256",
                "testnet.litecoin_snapshot.audit.snapshot_file",
                "testnet.litecoin_snapshot.audit.total_amount",
            ],
            "auxpow_chain_id": ["testnet.auxpow.chain_id"],
            "public_network_identity": [
                "testnet.public_network_identity.message_start",
                "testnet.public_network_identity.default_port",
                "testnet.public_network_identity.base58_prefixes.pubkey_address",
                "testnet.public_network_identity.base58_prefixes.script_address",
                "testnet.public_network_identity.base58_prefixes.script_address2",
                "testnet.public_network_identity.base58_prefixes.secret_key",
                "testnet.public_network_identity.base58_prefixes.ext_public_key",
                "testnet.public_network_identity.base58_prefixes.ext_secret_key",
                "testnet.public_network_identity.bech32_hrp",
                "testnet.public_network_identity.mweb_hrp",
            ],
            "dns_seeds": ["testnet.public_network_identity.dns_seeds"],
        },
    }
    expected_blocked_field_group_ids_by_network = {
        "main": [
            "main.litecoin_snapshot",
            "main.auxpow_chain_id",
            "main.public_network_identity",
            "main.dns_seeds",
        ],
        "testnet": [
            "testnet.litecoin_snapshot",
            "testnet.auxpow_chain_id",
            "testnet.public_network_identity",
            "testnet.dns_seeds",
        ],
    }
    expected_blocked_field_group_counts_by_network = {"main": 4, "testnet": 4}
    expected_blocked_field_group_ids_by_blocker_type = {
        "litecoin_snapshot": [
            "main.litecoin_snapshot",
            "testnet.litecoin_snapshot",
        ],
        "auxpow_chain_id": [
            "main.auxpow_chain_id",
            "testnet.auxpow_chain_id",
        ],
        "public_network_identity": [
            "main.public_network_identity",
            "testnet.public_network_identity",
        ],
        "dns_seeds": [
            "main.dns_seeds",
            "testnet.dns_seeds",
        ],
    }
    expected_blocked_field_group_counts_by_blocker_type = {
        blocker_type: len(group_ids)
        for blocker_type, group_ids in expected_blocked_field_group_ids_by_blocker_type.items()
    }
    empty_blocked_fields_by_blocker_type = {
        blocker_type: []
        for blocker_type in expected_blocked_field_counts_by_blocker_type
    }
    empty_blocked_field_counts_by_blocker_type = {
        blocker_type: 0
        for blocker_type in expected_blocked_field_counts_by_blocker_type
    }
    empty_blocked_field_groups_by_blocker_type = {
        blocker_type: []
        for blocker_type in expected_blocked_field_group_ids_by_blocker_type
    }
    empty_blocked_field_group_counts_by_blocker_type = {
        blocker_type: 0
        for blocker_type in expected_blocked_field_group_ids_by_blocker_type
    }
    if status_json.get("blocked_field_counts_by_blocker_type") != expected_blocked_field_counts_by_blocker_type:
        return "{} --status-json did not count field-level blockers by blocker type".format(
            PUBLIC_LAUNCH_MANIFEST_TOOL.relative_to(ROOT_DIR)
        )
    if status_json.get("blocked_field_counts_by_network_and_blocker_type") != expected_blocked_field_counts_by_network_and_blocker_type:
        return "{} --status-json did not count field-level blockers by network and blocker type".format(
            PUBLIC_LAUNCH_MANIFEST_TOOL.relative_to(ROOT_DIR)
        )
    if status_json.get("blocked_fields_by_network_and_blocker_type") != expected_blocked_fields_by_network_and_blocker_type:
        return "{} --status-json did not group field-level blockers by network and blocker type".format(
            PUBLIC_LAUNCH_MANIFEST_TOOL.relative_to(ROOT_DIR)
        )
    blocked_fields_by_blocker_type = status_json.get("blocked_fields_by_blocker_type", {})
    if blocked_fields_by_blocker_type.get("litecoin_snapshot", [None])[0] != "main.litecoin_snapshot.height":
        return "{} --status-json did not group snapshot blocked fields by blocker type".format(
            PUBLIC_LAUNCH_MANIFEST_TOOL.relative_to(ROOT_DIR)
        )
    if blocked_fields_by_blocker_type.get("dns_seeds") != [
        "main.public_network_identity.dns_seeds",
        "testnet.public_network_identity.dns_seeds",
    ]:
        return "{} --status-json did not group DNS seed blocked fields by blocker type".format(
            PUBLIC_LAUNCH_MANIFEST_TOOL.relative_to(ROOT_DIR)
        )
    if status_json.get("action_plan_command") != (
        "contrib/devtools/zkcoin_public_launch_profile.py --action-plan "
        "contrib/devtools/zkcoin_public_launch_profile_manifest.json"
    ):
        return "{} --status-json did not expose the action-plan command".format(
            PUBLIC_LAUNCH_MANIFEST_TOOL.relative_to(ROOT_DIR)
        )
    if status_json.get("readiness_summary_command") != (
        "contrib/devtools/zkcoin_public_launch_profile.py --readiness-summary "
        "contrib/devtools/zkcoin_public_launch_profile_manifest.json"
    ):
        return "{} --status-json did not expose the readiness-summary command".format(
            PUBLIC_LAUNCH_MANIFEST_TOOL.relative_to(ROOT_DIR)
        )
    if status_json.get("status_json_command") != (
        "contrib/devtools/zkcoin_public_launch_profile.py --status-json "
        "contrib/devtools/zkcoin_public_launch_profile_manifest.json"
    ):
        return "{} --status-json did not expose the status-json command".format(
            PUBLIC_LAUNCH_MANIFEST_TOOL.relative_to(ROOT_DIR)
        )
    if status_json.get("commands") != {
        "action_plan": (
            "contrib/devtools/zkcoin_public_launch_profile.py --action-plan "
            "contrib/devtools/zkcoin_public_launch_profile_manifest.json"
        ),
        "next_action": (
            "contrib/devtools/zkcoin_public_launch_profile.py --next-action "
            "contrib/devtools/zkcoin_public_launch_profile_manifest.json"
        ),
        "readiness_summary": (
            "contrib/devtools/zkcoin_public_launch_profile.py --readiness-summary "
            "contrib/devtools/zkcoin_public_launch_profile_manifest.json"
        ),
        "status_json": (
            "contrib/devtools/zkcoin_public_launch_profile.py --status-json "
            "contrib/devtools/zkcoin_public_launch_profile_manifest.json"
        ),
    }:
        return "{} --status-json did not expose the command map".format(
            PUBLIC_LAUNCH_MANIFEST_TOOL.relative_to(ROOT_DIR)
        )
    if status_json.get("network_readiness_summary_commands_by_network") != {
        "main": "contrib/devtools/zkcoin_public_launch_profile.py --network-readiness-summary main contrib/devtools/zkcoin_public_launch_profile_manifest.json",
        "testnet": "contrib/devtools/zkcoin_public_launch_profile.py --network-readiness-summary testnet contrib/devtools/zkcoin_public_launch_profile_manifest.json",
    }:
        return "{} --status-json did not expose network readiness-summary commands".format(
            PUBLIC_LAUNCH_MANIFEST_TOOL.relative_to(ROOT_DIR)
        )
    if status_json.get("network_readiness_summary_command_count") != len(
        status_json.get("network_readiness_summary_commands_by_network", {})
    ):
        return "{} --status-json did not count network readiness-summary commands".format(
            PUBLIC_LAUNCH_MANIFEST_TOOL.relative_to(ROOT_DIR)
        )
    if status_json.get("blocker_type_readiness_summary_commands_by_blocker_type") != {
        "litecoin_snapshot": "contrib/devtools/zkcoin_public_launch_profile.py --blocker-type-readiness-summary litecoin_snapshot contrib/devtools/zkcoin_public_launch_profile_manifest.json",
        "auxpow_chain_id": "contrib/devtools/zkcoin_public_launch_profile.py --blocker-type-readiness-summary auxpow_chain_id contrib/devtools/zkcoin_public_launch_profile_manifest.json",
        "public_network_identity": "contrib/devtools/zkcoin_public_launch_profile.py --blocker-type-readiness-summary public_network_identity contrib/devtools/zkcoin_public_launch_profile_manifest.json",
        "dns_seeds": "contrib/devtools/zkcoin_public_launch_profile.py --blocker-type-readiness-summary dns_seeds contrib/devtools/zkcoin_public_launch_profile_manifest.json",
    }:
        return "{} --status-json did not expose blocker-type readiness-summary commands".format(
            PUBLIC_LAUNCH_MANIFEST_TOOL.relative_to(ROOT_DIR)
        )
    if status_json.get("blocker_type_readiness_summary_command_count") != len(
        status_json.get("blocker_type_readiness_summary_commands_by_blocker_type", {})
    ):
        return "{} --status-json did not count blocker-type readiness-summary commands".format(
            PUBLIC_LAUNCH_MANIFEST_TOOL.relative_to(ROOT_DIR)
        )
    if status_json.get("blocker_readiness_summary_commands_by_blocker") != {
        "main.litecoin_snapshot": "contrib/devtools/zkcoin_public_launch_profile.py --blocker-readiness-summary main.litecoin_snapshot contrib/devtools/zkcoin_public_launch_profile_manifest.json",
        "main.auxpow_chain_id": "contrib/devtools/zkcoin_public_launch_profile.py --blocker-readiness-summary main.auxpow_chain_id contrib/devtools/zkcoin_public_launch_profile_manifest.json",
        "main.public_network_identity": "contrib/devtools/zkcoin_public_launch_profile.py --blocker-readiness-summary main.public_network_identity contrib/devtools/zkcoin_public_launch_profile_manifest.json",
        "main.dns_seeds": "contrib/devtools/zkcoin_public_launch_profile.py --blocker-readiness-summary main.dns_seeds contrib/devtools/zkcoin_public_launch_profile_manifest.json",
        "testnet.litecoin_snapshot": "contrib/devtools/zkcoin_public_launch_profile.py --blocker-readiness-summary testnet.litecoin_snapshot contrib/devtools/zkcoin_public_launch_profile_manifest.json",
        "testnet.auxpow_chain_id": "contrib/devtools/zkcoin_public_launch_profile.py --blocker-readiness-summary testnet.auxpow_chain_id contrib/devtools/zkcoin_public_launch_profile_manifest.json",
        "testnet.public_network_identity": "contrib/devtools/zkcoin_public_launch_profile.py --blocker-readiness-summary testnet.public_network_identity contrib/devtools/zkcoin_public_launch_profile_manifest.json",
        "testnet.dns_seeds": "contrib/devtools/zkcoin_public_launch_profile.py --blocker-readiness-summary testnet.dns_seeds contrib/devtools/zkcoin_public_launch_profile_manifest.json",
    }:
        return "{} --status-json did not expose blocker readiness-summary commands".format(
            PUBLIC_LAUNCH_MANIFEST_TOOL.relative_to(ROOT_DIR)
        )
    if status_json.get("blocker_readiness_summary_command_count") != len(
        status_json.get("blocker_readiness_summary_commands_by_blocker", {})
    ):
        return "{} --status-json did not count blocker readiness-summary commands".format(
            PUBLIC_LAUNCH_MANIFEST_TOOL.relative_to(ROOT_DIR)
        )
    if status_json.get("next_action_command") != (
        "contrib/devtools/zkcoin_public_launch_profile.py --next-action "
        "contrib/devtools/zkcoin_public_launch_profile_manifest.json"
    ):
        return "{} --status-json did not expose the next-action command".format(
            PUBLIC_LAUNCH_MANIFEST_TOOL.relative_to(ROOT_DIR)
        )
    next_commands_by_network = status_json.get("next_commands_by_network", {})
    if "--snapshot-audit-template main" not in next_commands_by_network.get("main", {}).get("template_command", ""):
        return "{} --status-json did not expose mainnet next commands".format(
            PUBLIC_LAUNCH_MANIFEST_TOOL.relative_to(ROOT_DIR)
        )
    if "--check-snapshot-audit testnet <snapshot_audit.json>" not in next_commands_by_network.get("testnet", {}).get("check_command", ""):
        return "{} --status-json did not expose testnet next commands".format(
            PUBLIC_LAUNCH_MANIFEST_TOOL.relative_to(ROOT_DIR)
        )
    if "--network-readiness-summary main" not in next_commands_by_network.get("main", {}).get("network_readiness_summary_command", ""):
        return "{} --status-json did not expose mainnet next network readiness command".format(
            PUBLIC_LAUNCH_MANIFEST_TOOL.relative_to(ROOT_DIR)
        )
    if "--blocker-type-readiness-summary litecoin_snapshot" not in next_commands_by_network.get("main", {}).get("blocker_type_readiness_summary_command", ""):
        return "{} --status-json did not expose mainnet next blocker-type readiness command".format(
            PUBLIC_LAUNCH_MANIFEST_TOOL.relative_to(ROOT_DIR)
        )
    if status_json.get("next_blocker_commands_by_network") != next_commands_by_network:
        return "{} --status-json did not alias per-network next blocker commands".format(
            PUBLIC_LAUNCH_MANIFEST_TOOL.relative_to(ROOT_DIR)
        )
    next_fields_by_network = status_json.get("next_blocked_fields_by_network", {})
    if next_fields_by_network.get("main", [None])[0] != "main.litecoin_snapshot.height":
        return "{} --status-json did not expose mainnet next blocked fields".format(
            PUBLIC_LAUNCH_MANIFEST_TOOL.relative_to(ROOT_DIR)
        )
    if next_fields_by_network.get("testnet", [None])[-1] != "testnet.litecoin_snapshot.audit.total_amount":
        return "{} --status-json did not expose testnet next blocked fields".format(
            PUBLIC_LAUNCH_MANIFEST_TOOL.relative_to(ROOT_DIR)
        )
    if status_json.get("next_blocker_fields_by_network") != next_fields_by_network:
        return "{} --status-json did not alias per-network next blocker fields".format(
            PUBLIC_LAUNCH_MANIFEST_TOOL.relative_to(ROOT_DIR)
        )
    if status_json.get("next_blocked_field_counts_by_network") != {"main": 11, "testnet": 11}:
        return "{} --status-json did not count per-network next blocked fields".format(
            PUBLIC_LAUNCH_MANIFEST_TOOL.relative_to(ROOT_DIR)
        )
    if status_json.get("next_blocker_field_counts_by_network") != status_json.get("next_blocked_field_counts_by_network"):
        return "{} --status-json did not alias per-network next blocker field counts".format(
            PUBLIC_LAUNCH_MANIFEST_TOOL.relative_to(ROOT_DIR)
        )
    if status_json.get("next_blockers_by_network") != {
        "main": "main.litecoin_snapshot",
        "testnet": "testnet.litecoin_snapshot",
    }:
        return "{} --status-json did not expose per-network next blockers".format(
            PUBLIC_LAUNCH_MANIFEST_TOOL.relative_to(ROOT_DIR)
        )
    if status_json.get("next_blocker_types_by_network") != {
        "main": "litecoin_snapshot",
        "testnet": "litecoin_snapshot",
    }:
        return "{} --status-json did not expose per-network next blocker types".format(
            PUBLIC_LAUNCH_MANIFEST_TOOL.relative_to(ROOT_DIR)
        )
    next_groups_by_network = status_json.get("next_blocked_field_groups_by_network", {})
    if next_groups_by_network.get("main", {}).get("id") != "main.litecoin_snapshot":
        return "{} --status-json did not expose mainnet next blocker group".format(
            PUBLIC_LAUNCH_MANIFEST_TOOL.relative_to(ROOT_DIR)
        )
    if next_groups_by_network.get("testnet", {}).get("id") != "testnet.litecoin_snapshot":
        return "{} --status-json did not expose testnet next blocker group".format(
            PUBLIC_LAUNCH_MANIFEST_TOOL.relative_to(ROOT_DIR)
        )
    if status_json.get("next_blocker_field_groups_by_network") != next_groups_by_network:
        return "{} --status-json did not alias per-network next blocker groups".format(
            PUBLIC_LAUNCH_MANIFEST_TOOL.relative_to(ROOT_DIR)
        )
    next_group_matrix = status_json.get("next_blocked_field_groups_by_network_and_blocker_type", {})
    next_group_id_matrix = next_action_ids_by_network_and_blocker_type(next_group_matrix)
    if next_group_id_matrix != expected_next_action_ids_by_network_and_blocker_type:
        return "{} --status-json did not expose next blocker groups by network and blocker type".format(
            PUBLIC_LAUNCH_MANIFEST_TOOL.relative_to(ROOT_DIR)
        )
    if status_json.get("next_blocker_field_groups_by_network_and_blocker_type") != next_group_matrix:
        return "{} --status-json did not alias matrix next blocker groups".format(
            PUBLIC_LAUNCH_MANIFEST_TOOL.relative_to(ROOT_DIR)
        )
    if status_json.get("next_blockers_by_network_and_blocker_type") != expected_next_action_ids_by_network_and_blocker_type:
        return "{} --status-json did not expose next blockers by network and blocker type".format(
            PUBLIC_LAUNCH_MANIFEST_TOOL.relative_to(ROOT_DIR)
        )
    next_field_matrix = status_json.get("next_blocked_fields_by_network_and_blocker_type", {})
    if next_field_matrix.get("main", {}).get("litecoin_snapshot", [None])[0] != "main.litecoin_snapshot.height":
        return "{} --status-json did not expose mainnet snapshot next fields by network and blocker type".format(
            PUBLIC_LAUNCH_MANIFEST_TOOL.relative_to(ROOT_DIR)
        )
    if next_field_matrix.get("testnet", {}).get("dns_seeds") != ["testnet.public_network_identity.dns_seeds"]:
        return "{} --status-json did not expose testnet DNS seed next fields by network and blocker type".format(
            PUBLIC_LAUNCH_MANIFEST_TOOL.relative_to(ROOT_DIR)
        )
    if status_json.get("next_blocker_fields_by_network_and_blocker_type") != next_field_matrix:
        return "{} --status-json did not alias next blocker fields by network and blocker type".format(
            PUBLIC_LAUNCH_MANIFEST_TOOL.relative_to(ROOT_DIR)
        )
    if status_json.get("next_blocked_field_counts_by_network_and_blocker_type") != expected_blocked_field_counts_by_network_and_blocker_type:
        return "{} --status-json did not count next fields by network and blocker type".format(
            PUBLIC_LAUNCH_MANIFEST_TOOL.relative_to(ROOT_DIR)
        )
    if status_json.get("next_blocker_field_counts_by_network_and_blocker_type") != status_json.get("next_blocked_field_counts_by_network_and_blocker_type"):
        return "{} --status-json did not alias next blocker field counts by network and blocker type".format(
            PUBLIC_LAUNCH_MANIFEST_TOOL.relative_to(ROOT_DIR)
        )
    blocked_field_groups = status_json.get("blocked_field_groups", [])
    if len(blocked_field_groups) != 8:
        return "{} --status-json did not include every blocker field group".format(
            PUBLIC_LAUNCH_MANIFEST_TOOL.relative_to(ROOT_DIR)
        )
    if status_json.get("blocked_field_group_count") != 8:
        return "{} --status-json did not count blocker field groups".format(
            PUBLIC_LAUNCH_MANIFEST_TOOL.relative_to(ROOT_DIR)
        )
    blocked_field_groups_by_network = status_json.get("blocked_field_groups_by_network", {})
    if {
        network: [group.get("id") for group in groups]
        for network, groups in blocked_field_groups_by_network.items()
    } != expected_blocked_field_group_ids_by_network:
        return "{} --status-json did not group blocker field groups by network".format(
            PUBLIC_LAUNCH_MANIFEST_TOOL.relative_to(ROOT_DIR)
        )
    if status_json.get("blocked_field_group_counts_by_network") != expected_blocked_field_group_counts_by_network:
        return "{} --status-json did not count blocker field groups by network".format(
            PUBLIC_LAUNCH_MANIFEST_TOOL.relative_to(ROOT_DIR)
        )
    blocked_field_groups_by_blocker_type = status_json.get("blocked_field_groups_by_blocker_type", {})
    if {
        blocker_type: [group.get("id") for group in groups]
        for blocker_type, groups in blocked_field_groups_by_blocker_type.items()
    } != expected_blocked_field_group_ids_by_blocker_type:
        return "{} --status-json did not group blocker field groups by blocker type".format(
            PUBLIC_LAUNCH_MANIFEST_TOOL.relative_to(ROOT_DIR)
        )
    if status_json.get("blocked_field_group_counts_by_blocker_type") != expected_blocked_field_group_counts_by_blocker_type:
        return "{} --status-json did not count blocker field groups by blocker type".format(
            PUBLIC_LAUNCH_MANIFEST_TOOL.relative_to(ROOT_DIR)
        )
    blocked_field_group_id_matrix = group_ids_by_network_and_blocker_type(
        status_json.get("blocked_field_groups_by_network_and_blocker_type", {})
    )
    if blocked_field_group_id_matrix != expected_blocked_field_group_ids_by_network_and_blocker_type:
        return "{} --status-json did not group blocker field groups by network and blocker type".format(
            PUBLIC_LAUNCH_MANIFEST_TOOL.relative_to(ROOT_DIR)
        )
    if status_json.get("blocked_field_group_counts_by_network_and_blocker_type") != expected_blocked_field_group_counts_by_network_and_blocker_type:
        return "{} --status-json did not count blocker field groups by network and blocker type".format(
            PUBLIC_LAUNCH_MANIFEST_TOOL.relative_to(ROOT_DIR)
        )
    if blocked_field_groups[0].get("id") != "main.litecoin_snapshot":
        return "{} --status-json did not preserve field group blocker order".format(
            PUBLIC_LAUNCH_MANIFEST_TOOL.relative_to(ROOT_DIR)
        )
    if blocked_field_groups[0].get("step") != 1 or blocked_field_groups[0].get("kind") != "blocker":
        return "{} --status-json did not include first blocker group metadata".format(
            PUBLIC_LAUNCH_MANIFEST_TOOL.relative_to(ROOT_DIR)
        )
    if blocked_field_groups[0].get("network") != "main" or blocked_field_groups[0].get("blocker_type") != "litecoin_snapshot":
        return "{} --status-json did not include first blocker group network metadata".format(
            PUBLIC_LAUNCH_MANIFEST_TOOL.relative_to(ROOT_DIR)
        )
    if (
        blocked_field_groups[0].get("network_step") != 1
        or blocked_field_groups[0].get("network_step_count") != 4
        or blocked_field_groups[0].get("blocker_type_step") != 1
        or blocked_field_groups[0].get("blocker_type_step_count") != 2
    ):
        return "{} --status-json did not include first blocker group scoped order metadata".format(
            PUBLIC_LAUNCH_MANIFEST_TOOL.relative_to(ROOT_DIR)
        )
    if "--check-snapshot-audit main <snapshot_audit.json>" not in blocked_field_groups[0].get("action", ""):
        return "{} --status-json did not include first blocker group action guidance".format(
            PUBLIC_LAUNCH_MANIFEST_TOOL.relative_to(ROOT_DIR)
        )
    if blocked_field_groups[0].get("field_count") != 11:
        return "{} --status-json did not count first blocker fields".format(
            PUBLIC_LAUNCH_MANIFEST_TOOL.relative_to(ROOT_DIR)
        )
    if blocked_field_groups[-1].get("id") != "testnet.dns_seeds" or blocked_field_groups[-1].get("field_count") != 1:
        return "{} --status-json did not include the final DNS seed field group".format(
            PUBLIC_LAUNCH_MANIFEST_TOOL.relative_to(ROOT_DIR)
        )
    if blocked_field_groups[-1].get("network") != "testnet" or blocked_field_groups[-1].get("blocker_type") != "dns_seeds":
        return "{} --status-json did not include final blocker group network metadata".format(
            PUBLIC_LAUNCH_MANIFEST_TOOL.relative_to(ROOT_DIR)
        )
    if (
        blocked_field_groups[-1].get("network_step") != 4
        or blocked_field_groups[-1].get("network_step_count") != 4
        or blocked_field_groups[-1].get("blocker_type_step") != 2
        or blocked_field_groups[-1].get("blocker_type_step_count") != 2
    ):
        return "{} --status-json did not include final blocker group scoped order metadata".format(
            PUBLIC_LAUNCH_MANIFEST_TOOL.relative_to(ROOT_DIR)
        )
    network_progress = status_json.get("network_progress", {})
    main_progress = network_progress.get("main", {})
    if main_progress.get("ready_for_launch_profile") is not False:
        return "{} --status-json treated blocked mainnet profile as ready".format(
            PUBLIC_LAUNCH_MANIFEST_TOOL.relative_to(ROOT_DIR)
        )
    if main_progress.get("unresolved_blocker_count") != 4 or main_progress.get("blocked_field_count") != 23:
        return "{} --status-json did not expose mainnet network progress counts".format(
            PUBLIC_LAUNCH_MANIFEST_TOOL.relative_to(ROOT_DIR)
        )
    if main_progress.get("unresolved_blockers") != status_json.get("unresolved_blockers_by_network", {}).get("main"):
        return "{} --status-json did not expose mainnet network progress blockers".format(
            PUBLIC_LAUNCH_MANIFEST_TOOL.relative_to(ROOT_DIR)
        )
    if main_progress.get("blocked_fields", [None])[0] != "main.litecoin_snapshot.height":
        return "{} --status-json did not expose mainnet network progress fields".format(
            PUBLIC_LAUNCH_MANIFEST_TOOL.relative_to(ROOT_DIR)
        )
    if main_progress.get("next_blocked_field_group") != blocked_field_groups[0]:
        return "{} --status-json did not expose mainnet next blocker progress".format(
            PUBLIC_LAUNCH_MANIFEST_TOOL.relative_to(ROOT_DIR)
        )
    testnet_progress = network_progress.get("testnet", {})
    if testnet_progress.get("ready_for_launch_profile") is not False:
        return "{} --status-json treated blocked testnet profile as ready".format(
            PUBLIC_LAUNCH_MANIFEST_TOOL.relative_to(ROOT_DIR)
        )
    if testnet_progress.get("unresolved_blocker_count") != 4 or testnet_progress.get("blocked_field_count") != 23:
        return "{} --status-json did not expose testnet network progress counts".format(
            PUBLIC_LAUNCH_MANIFEST_TOOL.relative_to(ROOT_DIR)
        )
    if testnet_progress.get("unresolved_blockers") != status_json.get("unresolved_blockers_by_network", {}).get("testnet"):
        return "{} --status-json did not expose testnet network progress blockers".format(
            PUBLIC_LAUNCH_MANIFEST_TOOL.relative_to(ROOT_DIR)
        )
    if testnet_progress.get("blocked_fields", [None])[0] != "testnet.litecoin_snapshot.height":
        return "{} --status-json did not expose testnet network progress fields".format(
            PUBLIC_LAUNCH_MANIFEST_TOOL.relative_to(ROOT_DIR)
        )
    if testnet_progress.get("next_blocked_field_group") != blocked_field_groups[4]:
        return "{} --status-json did not expose testnet next blocker progress".format(
            PUBLIC_LAUNCH_MANIFEST_TOOL.relative_to(ROOT_DIR)
        )
    actions = status_json.get("actions", [])
    if (
        status_json.get("action_ids") != [action.get("id") for action in actions]
        or status_json.get("action_kinds") != [action.get("kind") for action in actions]
        or status_json.get("action_steps") != [action.get("step") for action in actions]
        or status_json.get("action_networks") != [action.get("network") for action in actions]
        or status_json.get("action_blocker_types") != [action.get("blocker_type") for action in actions]
        or status_json.get("action_field_counts") != [action.get("field_count") for action in actions]
    ):
        return "{} --status-json did not expose action list aliases".format(
            PUBLIC_LAUNCH_MANIFEST_TOOL.relative_to(ROOT_DIR)
        )
    expected_later_actions = actions[1:]
    if status_json.get("later_actions") != expected_later_actions:
        return "{} --status-json did not expose later action aliases".format(
            PUBLIC_LAUNCH_MANIFEST_TOOL.relative_to(ROOT_DIR)
        )
    if status_json.get("later_action_count") != len(expected_later_actions):
        return "{} --status-json did not count later action aliases".format(
            PUBLIC_LAUNCH_MANIFEST_TOOL.relative_to(ROOT_DIR)
        )
    if (
        status_json.get("later_action_ids") != [action.get("id") for action in expected_later_actions]
        or status_json.get("later_action_kinds") != [action.get("kind") for action in expected_later_actions]
        or status_json.get("later_action_steps") != [action.get("step") for action in expected_later_actions]
        or status_json.get("later_action_networks") != [action.get("network") for action in expected_later_actions]
        or status_json.get("later_action_blocker_types") != [action.get("blocker_type") for action in expected_later_actions]
        or status_json.get("later_action_field_counts") != [action.get("field_count") for action in expected_later_actions]
    ):
        return "{} --status-json did not expose later action list aliases".format(
            PUBLIC_LAUNCH_MANIFEST_TOOL.relative_to(ROOT_DIR)
        )
    if [action.get("id") for action in status_json.get("later_actions", [])] != status_json.get("later_blockers"):
        return "{} --status-json did not align later actions with later blockers".format(
            PUBLIC_LAUNCH_MANIFEST_TOOL.relative_to(ROOT_DIR)
        )
    command_fields = tuple(status_json.get("command_field_order", []))
    if command_fields != (
        "template_command",
        "check_command",
        "apply_command",
        "readiness_summary_command",
        "network_readiness_summary_command",
        "blocker_type_readiness_summary_command",
        "blocker_readiness_summary_command",
        "command",
    ):
        return "{} --status-json did not expose the command field order".format(
            PUBLIC_LAUNCH_MANIFEST_TOOL.relative_to(ROOT_DIR)
        )
    if status_json.get("command_field_count") != len(command_fields):
        return "{} --status-json did not count command fields".format(
            PUBLIC_LAUNCH_MANIFEST_TOOL.relative_to(ROOT_DIR)
        )
    expected_action_commands = [
        {command_field: action.get(command_field) for command_field in command_fields}
        for action in actions
    ]
    if status_json.get("action_commands") != expected_action_commands:
        return "{} --status-json did not expose action command aliases".format(
            PUBLIC_LAUNCH_MANIFEST_TOOL.relative_to(ROOT_DIR)
        )
    if status_json.get("action_command_count") != len(expected_action_commands):
        return "{} --status-json did not count action command aliases".format(
            PUBLIC_LAUNCH_MANIFEST_TOOL.relative_to(ROOT_DIR)
        )
    expected_later_commands = [
        {command_field: action.get(command_field) for command_field in command_fields}
        for action in expected_later_actions
    ]
    if status_json.get("later_commands") != expected_later_commands:
        return "{} --status-json did not expose later command aliases".format(
            PUBLIC_LAUNCH_MANIFEST_TOOL.relative_to(ROOT_DIR)
        )
    if status_json.get("later_command_count") != len(expected_later_commands):
        return "{} --status-json did not count later command aliases".format(
            PUBLIC_LAUNCH_MANIFEST_TOOL.relative_to(ROOT_DIR)
        )
    expected_later_command_keys = [
        [
            command_field
            for command_field in command_fields
            if action.get(command_field) is not None
        ]
        for action in expected_later_actions
    ]
    if status_json.get("later_command_keys") != expected_later_command_keys:
        return "{} --status-json did not expose later command key aliases".format(
            PUBLIC_LAUNCH_MANIFEST_TOOL.relative_to(ROOT_DIR)
        )
    if status_json.get("later_command_key_counts") != [
        len(command_keys) for command_keys in expected_later_command_keys
    ]:
        return "{} --status-json did not count later command key aliases".format(
            PUBLIC_LAUNCH_MANIFEST_TOOL.relative_to(ROOT_DIR)
        )
    expected_action_command_keys = [
        [
            command_field
            for command_field in command_fields
            if action.get(command_field) is not None
        ]
        for action in actions
    ]
    if status_json.get("action_command_keys") != expected_action_command_keys:
        return "{} --status-json did not expose action command key aliases".format(
            PUBLIC_LAUNCH_MANIFEST_TOOL.relative_to(ROOT_DIR)
        )
    if status_json.get("action_command_key_counts") != [
        len(command_keys) for command_keys in expected_action_command_keys
    ]:
        return "{} --status-json did not count action command key aliases".format(
            PUBLIC_LAUNCH_MANIFEST_TOOL.relative_to(ROOT_DIR)
        )
    expected_action_command_values = [
        [
            action.get(command_field)
            for command_field in command_fields
            if action.get(command_field) is not None
        ]
        for action in actions
    ]
    if status_json.get("action_command_values") != expected_action_command_values:
        return "{} --status-json did not expose action command value aliases".format(
            PUBLIC_LAUNCH_MANIFEST_TOOL.relative_to(ROOT_DIR)
        )
    if status_json.get("action_command_value_counts") != [
        len(command_values) for command_values in expected_action_command_values
    ]:
        return "{} --status-json did not count action command value aliases".format(
            PUBLIC_LAUNCH_MANIFEST_TOOL.relative_to(ROOT_DIR)
        )
    expected_later_command_values = [
        [
            action.get(command_field)
            for command_field in command_fields
            if action.get(command_field) is not None
        ]
        for action in expected_later_actions
    ]
    if status_json.get("later_command_values") != expected_later_command_values:
        return "{} --status-json did not expose later command value aliases".format(
            PUBLIC_LAUNCH_MANIFEST_TOOL.relative_to(ROOT_DIR)
        )
    if status_json.get("later_command_value_counts") != [
        len(command_values) for command_values in expected_later_command_values
    ]:
        return "{} --status-json did not count later command value aliases".format(
            PUBLIC_LAUNCH_MANIFEST_TOOL.relative_to(ROOT_DIR)
        )
    expected_action_command_pairs = [
        [
            {"key": command_field, "value": action.get(command_field)}
            for command_field in command_fields
            if action.get(command_field) is not None
        ]
        for action in actions
    ]
    if status_json.get("action_command_pairs") != expected_action_command_pairs:
        return "{} --status-json did not expose action command pair aliases".format(
            PUBLIC_LAUNCH_MANIFEST_TOOL.relative_to(ROOT_DIR)
        )
    if status_json.get("action_command_pair_counts") != [
        len(command_pairs) for command_pairs in expected_action_command_pairs
    ]:
        return "{} --status-json did not count action command pair aliases".format(
            PUBLIC_LAUNCH_MANIFEST_TOOL.relative_to(ROOT_DIR)
        )
    expected_later_command_pairs = [
        [
            {"key": command_field, "value": action.get(command_field)}
            for command_field in command_fields
            if action.get(command_field) is not None
        ]
        for action in expected_later_actions
    ]
    if status_json.get("later_command_pairs") != expected_later_command_pairs:
        return "{} --status-json did not expose later command pair aliases".format(
            PUBLIC_LAUNCH_MANIFEST_TOOL.relative_to(ROOT_DIR)
        )
    if status_json.get("later_command_pair_counts") != [
        len(command_pairs) for command_pairs in expected_later_command_pairs
    ]:
        return "{} --status-json did not count later command pair aliases".format(
            PUBLIC_LAUNCH_MANIFEST_TOOL.relative_to(ROOT_DIR)
        )
    actions_by_id = {action.get("id"): action for action in actions}
    for group in blocked_field_groups:
        action = actions_by_id.get(group.get("id"), {})
        for command_field in ("template_command", "check_command", "apply_command", "readiness_summary_command", "network_readiness_summary_command", "blocker_type_readiness_summary_command", "blocker_readiness_summary_command"):
            if command_field not in group:
                return "{} --status-json blocker group {} did not include {}".format(
                    PUBLIC_LAUNCH_MANIFEST_TOOL.relative_to(ROOT_DIR),
                    group.get("id"),
                    command_field,
                )
            if group.get(command_field) != action.get(command_field):
                return "{} --status-json blocker group {} did not match action {}".format(
                    PUBLIC_LAUNCH_MANIFEST_TOOL.relative_to(ROOT_DIR),
                    group.get("id"),
                    command_field,
                )
    if status_json.get("next_blocked_field_group") != blocked_field_groups[0]:
        return "{} --status-json did not report the current blocker field group".format(
            PUBLIC_LAUNCH_MANIFEST_TOOL.relative_to(ROOT_DIR)
        )
    if status_json.get("next_blocker_field_group") != status_json.get("next_blocked_field_group"):
        return "{} --status-json did not alias the current blocker field group".format(
            PUBLIC_LAUNCH_MANIFEST_TOOL.relative_to(ROOT_DIR)
        )
    if status_json.get("next_blocker") != "main.litecoin_snapshot":
        return "{} --status-json did not expose the current blocker id".format(
            PUBLIC_LAUNCH_MANIFEST_TOOL.relative_to(ROOT_DIR)
        )
    if status_json.get("next_blocker_network") != "main":
        return "{} --status-json did not expose the current blocker network".format(
            PUBLIC_LAUNCH_MANIFEST_TOOL.relative_to(ROOT_DIR)
        )
    if status_json.get("next_blocker_type") != "litecoin_snapshot":
        return "{} --status-json did not expose the current blocker type".format(
            PUBLIC_LAUNCH_MANIFEST_TOOL.relative_to(ROOT_DIR)
        )
    if (
        status_json.get("next_blocker_step") != blocked_field_groups[0].get("step")
        or status_json.get("next_blocker_network_step") != blocked_field_groups[0].get("network_step")
        or status_json.get("next_blocker_network_step_count") != blocked_field_groups[0].get("network_step_count")
        or status_json.get("next_blocker_type_step") != blocked_field_groups[0].get("blocker_type_step")
        or status_json.get("next_blocker_type_step_count") != blocked_field_groups[0].get("blocker_type_step_count")
    ):
        return "{} --status-json did not expose current blocker scoped order aliases".format(
            PUBLIC_LAUNCH_MANIFEST_TOOL.relative_to(ROOT_DIR)
        )
    if status_json.get("next_blocker_commands") != status_json.get("next_commands"):
        return "{} --status-json did not expose current blocker commands".format(
            PUBLIC_LAUNCH_MANIFEST_TOOL.relative_to(ROOT_DIR)
        )
    if status_json.get("next_blocker_fields") != status_json.get("next_blocked_fields"):
        return "{} --status-json did not expose current blocker fields".format(
            PUBLIC_LAUNCH_MANIFEST_TOOL.relative_to(ROOT_DIR)
        )
    if status_json.get("next_blocker_field_count") != status_json.get("next_blocked_field_count"):
        return "{} --status-json did not expose current blocker field count".format(
            PUBLIC_LAUNCH_MANIFEST_TOOL.relative_to(ROOT_DIR)
        )
    expected_later_blockers = status_json.get("unresolved_blockers", [])[1:]
    if status_json.get("later_blockers") != expected_later_blockers:
        return "{} --status-json did not expose later blocker aliases".format(
            PUBLIC_LAUNCH_MANIFEST_TOOL.relative_to(ROOT_DIR)
        )
    if status_json.get("later_blocker_count") != len(expected_later_blockers):
        return "{} --status-json did not count later blocker aliases".format(
            PUBLIC_LAUNCH_MANIFEST_TOOL.relative_to(ROOT_DIR)
        )
    expected_later_blocker_commands = {
        blocker: status_json.get("blocker_readiness_summary_commands_by_blocker", {}).get(blocker)
        for blocker in expected_later_blockers
    }
    if status_json.get("later_blocker_readiness_summary_commands_by_blocker") != expected_later_blocker_commands:
        return "{} --status-json did not expose later blocker summary command aliases".format(
            PUBLIC_LAUNCH_MANIFEST_TOOL.relative_to(ROOT_DIR)
        )
    if status_json.get("later_blocker_readiness_summary_command_count") != len(expected_later_blocker_commands):
        return "{} --status-json did not count later blocker summary command aliases".format(
            PUBLIC_LAUNCH_MANIFEST_TOOL.relative_to(ROOT_DIR)
        )
    expected_later_blocker_field_groups = blocked_field_groups[1:]
    if status_json.get("later_blocker_field_groups") != expected_later_blocker_field_groups:
        return "{} --status-json did not expose later blocker field group aliases".format(
            PUBLIC_LAUNCH_MANIFEST_TOOL.relative_to(ROOT_DIR)
        )
    if status_json.get("later_blocker_field_group_count") != len(expected_later_blocker_field_groups):
        return "{} --status-json did not count later blocker field group aliases".format(
            PUBLIC_LAUNCH_MANIFEST_TOOL.relative_to(ROOT_DIR)
        )
    expected_later_blocker_fields = [
        field
        for group in expected_later_blocker_field_groups
        for field in group.get("fields", [])
    ]
    if status_json.get("later_blocker_fields") != expected_later_blocker_fields:
        return "{} --status-json did not expose later blocker field aliases".format(
            PUBLIC_LAUNCH_MANIFEST_TOOL.relative_to(ROOT_DIR)
        )
    if status_json.get("later_blocker_field_count") != len(expected_later_blocker_fields):
        return "{} --status-json did not count later blocker field aliases".format(
            PUBLIC_LAUNCH_MANIFEST_TOOL.relative_to(ROOT_DIR)
        )
    if status_json.get("next_blocked_field_count") != 11:
        return "{} --status-json did not count next blocker field-level blockers".format(
            PUBLIC_LAUNCH_MANIFEST_TOOL.relative_to(ROOT_DIR)
        )
    if status_json.get("next_blocked_fields", [None])[0] != "main.litecoin_snapshot.height":
        return "{} --status-json did not preserve next blocker field order".format(
            PUBLIC_LAUNCH_MANIFEST_TOOL.relative_to(ROOT_DIR)
        )
    if status_json.get("next_blocked_fields", [None])[-1] != "main.litecoin_snapshot.audit.total_amount":
        return "{} --status-json did not include the full next blocker field set".format(
            PUBLIC_LAUNCH_MANIFEST_TOOL.relative_to(ROOT_DIR)
        )
    if status_json.get("unresolved_blockers", [None])[0] != "main.litecoin_snapshot":
        return "{} --status-json did not preserve blocker order".format(
            PUBLIC_LAUNCH_MANIFEST_TOOL.relative_to(ROOT_DIR)
        )
    if actions[-1].get("id") != "testnet.dns_seeds":
        return "{} --status-json did not include the full action plan".format(
            PUBLIC_LAUNCH_MANIFEST_TOOL.relative_to(ROOT_DIR)
        )
    if actions[0].get("network") != "main" or actions[0].get("blocker_type") != "litecoin_snapshot":
        return "{} --status-json did not include first action network metadata".format(
            PUBLIC_LAUNCH_MANIFEST_TOOL.relative_to(ROOT_DIR)
        )
    if (
        actions[0].get("network_step") != 1
        or actions[0].get("network_step_count") != 4
        or actions[0].get("blocker_type_step") != 1
        or actions[0].get("blocker_type_step_count") != 2
    ):
        return "{} --status-json did not include first action scoped order metadata".format(
            PUBLIC_LAUNCH_MANIFEST_TOOL.relative_to(ROOT_DIR)
        )
    if actions[0].get("field_count") != blocked_field_groups[0].get("field_count"):
        return "{} --status-json did not include first action blocked field count".format(
            PUBLIC_LAUNCH_MANIFEST_TOOL.relative_to(ROOT_DIR)
        )
    if actions[0].get("fields") != blocked_field_groups[0].get("fields"):
        return "{} --status-json did not include first action blocked fields".format(
            PUBLIC_LAUNCH_MANIFEST_TOOL.relative_to(ROOT_DIR)
        )
    if "--snapshot-audit-template main" not in actions[0].get("template_command", ""):
        return "{} --status-json did not include first action template command".format(
            PUBLIC_LAUNCH_MANIFEST_TOOL.relative_to(ROOT_DIR)
        )
    if "--check-snapshot-audit main <snapshot_audit.json>" not in actions[0].get("check_command", ""):
        return "{} --status-json did not include first action check command".format(
            PUBLIC_LAUNCH_MANIFEST_TOOL.relative_to(ROOT_DIR)
        )
    if "--set-snapshot-audit main <snapshot_audit.json>" not in actions[0].get("apply_command", ""):
        return "{} --status-json did not include first action apply command".format(
            PUBLIC_LAUNCH_MANIFEST_TOOL.relative_to(ROOT_DIR)
        )
    if "--readiness-summary contrib/devtools/zkcoin_public_launch_profile_manifest.json" not in actions[0].get("readiness_summary_command", ""):
        return "{} --status-json did not include first action readiness-summary command".format(
            PUBLIC_LAUNCH_MANIFEST_TOOL.relative_to(ROOT_DIR)
        )
    if "--network-readiness-summary main contrib/devtools/zkcoin_public_launch_profile_manifest.json" not in actions[0].get("network_readiness_summary_command", ""):
        return "{} --status-json did not include first action network readiness-summary command".format(
            PUBLIC_LAUNCH_MANIFEST_TOOL.relative_to(ROOT_DIR)
        )
    if "--blocker-type-readiness-summary litecoin_snapshot contrib/devtools/zkcoin_public_launch_profile_manifest.json" not in actions[0].get("blocker_type_readiness_summary_command", ""):
        return "{} --status-json did not include first action blocker-type readiness-summary command".format(
            PUBLIC_LAUNCH_MANIFEST_TOOL.relative_to(ROOT_DIR)
        )
    if "--blocker-readiness-summary main.litecoin_snapshot contrib/devtools/zkcoin_public_launch_profile_manifest.json" not in actions[0].get("blocker_readiness_summary_command", ""):
        return "{} --status-json did not include first action blocker readiness-summary command".format(
            PUBLIC_LAUNCH_MANIFEST_TOOL.relative_to(ROOT_DIR)
        )
    if actions[-1].get("network") != "testnet" or actions[-1].get("blocker_type") != "dns_seeds":
        return "{} --status-json did not include final action network metadata".format(
            PUBLIC_LAUNCH_MANIFEST_TOOL.relative_to(ROOT_DIR)
        )
    if (
        actions[-1].get("network_step") != 4
        or actions[-1].get("network_step_count") != 4
        or actions[-1].get("blocker_type_step") != 2
        or actions[-1].get("blocker_type_step_count") != 2
    ):
        return "{} --status-json did not include final action scoped order metadata".format(
            PUBLIC_LAUNCH_MANIFEST_TOOL.relative_to(ROOT_DIR)
        )
    for action in actions:
        for command_field in ("template_command", "check_command", "apply_command", "readiness_summary_command", "network_readiness_summary_command", "blocker_type_readiness_summary_command", "blocker_readiness_summary_command"):
            if command_field not in action:
                return "{} --status-json action {} did not include {}".format(
                    PUBLIC_LAUNCH_MANIFEST_TOOL.relative_to(ROOT_DIR),
                    action.get("id"),
                    command_field,
                )
        if action.get("blocker_type") != "litecoin_snapshot" and action.get("template_command") is not None:
            return "{} --status-json action {} did not report null template_command".format(
                PUBLIC_LAUNCH_MANIFEST_TOOL.relative_to(ROOT_DIR),
                action.get("id"),
            )
    if actions[-1].get("field_count") != 1 or actions[-1].get("fields") != ["testnet.public_network_identity.dns_seeds"]:
        return "{} --status-json did not include final action blocked field metadata".format(
            PUBLIC_LAUNCH_MANIFEST_TOOL.relative_to(ROOT_DIR)
        )
    if "--check-dns-seeds testnet <seed1.hostname>,<seed2.hostname>" not in actions[-1].get("check_command", ""):
        return "{} --status-json did not include final action check command".format(
            PUBLIC_LAUNCH_MANIFEST_TOOL.relative_to(ROOT_DIR)
        )
    if "--set-dns-seeds testnet <seed1.hostname>,<seed2.hostname>" not in actions[-1].get("apply_command", ""):
        return "{} --status-json did not include final action apply command".format(
            PUBLIC_LAUNCH_MANIFEST_TOOL.relative_to(ROOT_DIR)
        )
    if "--readiness-summary contrib/devtools/zkcoin_public_launch_profile_manifest.json" not in actions[-1].get("readiness_summary_command", ""):
        return "{} --status-json did not include final action readiness-summary command".format(
            PUBLIC_LAUNCH_MANIFEST_TOOL.relative_to(ROOT_DIR)
        )
    if "--network-readiness-summary testnet contrib/devtools/zkcoin_public_launch_profile_manifest.json" not in actions[-1].get("network_readiness_summary_command", ""):
        return "{} --status-json did not include final action network readiness-summary command".format(
            PUBLIC_LAUNCH_MANIFEST_TOOL.relative_to(ROOT_DIR)
        )
    if "--blocker-type-readiness-summary dns_seeds contrib/devtools/zkcoin_public_launch_profile_manifest.json" not in actions[-1].get("blocker_type_readiness_summary_command", ""):
        return "{} --status-json did not include final action blocker-type readiness-summary command".format(
            PUBLIC_LAUNCH_MANIFEST_TOOL.relative_to(ROOT_DIR)
        )
    if "--blocker-readiness-summary testnet.dns_seeds contrib/devtools/zkcoin_public_launch_profile_manifest.json" not in actions[-1].get("blocker_readiness_summary_command", ""):
        return "{} --status-json did not include final action blocker readiness-summary command".format(
            PUBLIC_LAUNCH_MANIFEST_TOOL.relative_to(ROOT_DIR)
        )
    if status_json.get("next_action") != status_json.get("next"):
        return "{} --status-json did not expose next_action as the current handoff entry".format(
            PUBLIC_LAUNCH_MANIFEST_TOOL.relative_to(ROOT_DIR)
        )
    if (
        status_json.get("next_action_id") != status_json.get("next_action", {}).get("id")
        or status_json.get("next_action_kind") != status_json.get("next_action", {}).get("kind")
        or status_json.get("next_action_step") != status_json.get("next_action", {}).get("step")
        or status_json.get("next_action_network") != status_json.get("next_action", {}).get("network")
        or status_json.get("next_action_blocker_type") != status_json.get("next_action", {}).get("blocker_type")
        or status_json.get("next_action_field_count") != status_json.get("next_action", {}).get("field_count")
    ):
        return "{} --status-json did not expose current next_action aliases".format(
            PUBLIC_LAUNCH_MANIFEST_TOOL.relative_to(ROOT_DIR)
        )
    if status_json.get("next_action", {}).get("id") != "main.litecoin_snapshot":
        return "{} --status-json next_action did not preserve the current blocker id".format(
            PUBLIC_LAUNCH_MANIFEST_TOOL.relative_to(ROOT_DIR)
        )
    if status_json.get("next_action", {}).get("network") != "main":
        return "{} --status-json next_action did not expose the current blocker network".format(
            PUBLIC_LAUNCH_MANIFEST_TOOL.relative_to(ROOT_DIR)
        )
    if status_json.get("next_action", {}).get("blocker_type") != "litecoin_snapshot":
        return "{} --status-json next_action did not expose the current blocker type".format(
            PUBLIC_LAUNCH_MANIFEST_TOOL.relative_to(ROOT_DIR)
        )
    if status_json.get("next_action", {}).get("field_count") != 11:
        return "{} --status-json next_action did not expose the current field count".format(
            PUBLIC_LAUNCH_MANIFEST_TOOL.relative_to(ROOT_DIR)
        )
    if status_json.get("next_action", {}).get("fields") != status_json.get("next_blocked_fields"):
        return "{} --status-json next_action did not expose the current blocked fields".format(
            PUBLIC_LAUNCH_MANIFEST_TOOL.relative_to(ROOT_DIR)
        )
    if status_json.get("next_action", {}).get("check_command") != actions[0].get("check_command"):
        return "{} --status-json next_action did not expose the current check command".format(
            PUBLIC_LAUNCH_MANIFEST_TOOL.relative_to(ROOT_DIR)
        )
    if status_json.get("next_action", {}).get("apply_command") != actions[0].get("apply_command"):
        return "{} --status-json next_action did not expose the current apply command".format(
            PUBLIC_LAUNCH_MANIFEST_TOOL.relative_to(ROOT_DIR)
        )
    if status_json.get("next_action", {}).get("readiness_summary_command") != actions[0].get("readiness_summary_command"):
        return "{} --status-json next_action did not expose the current readiness-summary command".format(
            PUBLIC_LAUNCH_MANIFEST_TOOL.relative_to(ROOT_DIR)
        )
    if status_json.get("next_action", {}).get("network_readiness_summary_command") != actions[0].get("network_readiness_summary_command"):
        return "{} --status-json next_action did not expose the current network readiness-summary command".format(
            PUBLIC_LAUNCH_MANIFEST_TOOL.relative_to(ROOT_DIR)
        )
    if status_json.get("next_action", {}).get("blocker_type_readiness_summary_command") != actions[0].get("blocker_type_readiness_summary_command"):
        return "{} --status-json next_action did not expose the current blocker-type readiness-summary command".format(
            PUBLIC_LAUNCH_MANIFEST_TOOL.relative_to(ROOT_DIR)
        )
    if status_json.get("next_action", {}).get("blocker_readiness_summary_command") != actions[0].get("blocker_readiness_summary_command"):
        return "{} --status-json next_action did not expose the current blocker readiness-summary command".format(
            PUBLIC_LAUNCH_MANIFEST_TOOL.relative_to(ROOT_DIR)
        )
    next_commands = status_json.get("next_commands", {})
    if next_commands.get("template_command") != actions[0].get("template_command"):
        return "{} --status-json next_commands did not expose the current template command".format(
            PUBLIC_LAUNCH_MANIFEST_TOOL.relative_to(ROOT_DIR)
        )
    if next_commands.get("check_command") != actions[0].get("check_command"):
        return "{} --status-json next_commands did not expose the current check command".format(
            PUBLIC_LAUNCH_MANIFEST_TOOL.relative_to(ROOT_DIR)
        )
    if next_commands.get("apply_command") != actions[0].get("apply_command"):
        return "{} --status-json next_commands did not expose the current apply command".format(
            PUBLIC_LAUNCH_MANIFEST_TOOL.relative_to(ROOT_DIR)
        )
    if next_commands.get("readiness_summary_command") != actions[0].get("readiness_summary_command"):
        return "{} --status-json next_commands did not expose the current readiness-summary command".format(
            PUBLIC_LAUNCH_MANIFEST_TOOL.relative_to(ROOT_DIR)
        )
    if next_commands.get("network_readiness_summary_command") != actions[0].get("network_readiness_summary_command"):
        return "{} --status-json next_commands did not expose the current network readiness-summary command".format(
            PUBLIC_LAUNCH_MANIFEST_TOOL.relative_to(ROOT_DIR)
        )
    if next_commands.get("blocker_type_readiness_summary_command") != actions[0].get("blocker_type_readiness_summary_command"):
        return "{} --status-json next_commands did not expose the current blocker-type readiness-summary command".format(
            PUBLIC_LAUNCH_MANIFEST_TOOL.relative_to(ROOT_DIR)
        )
    if next_commands.get("blocker_readiness_summary_command") != actions[0].get("blocker_readiness_summary_command"):
        return "{} --status-json next_commands did not expose the current blocker readiness-summary command".format(
            PUBLIC_LAUNCH_MANIFEST_TOOL.relative_to(ROOT_DIR)
        )
    if next_commands.get("command") is not None:
        return "{} --status-json next_commands reported a blocker command alias".format(
            PUBLIC_LAUNCH_MANIFEST_TOOL.relative_to(ROOT_DIR)
        )
    expected_next_command_keys = [
        command_field
        for command_field in command_fields
        if actions[0].get(command_field) is not None
    ]
    if status_json.get("next_command_keys") != expected_next_command_keys:
        return "{} --status-json did not expose current next command key aliases".format(
            PUBLIC_LAUNCH_MANIFEST_TOOL.relative_to(ROOT_DIR)
        )
    if status_json.get("next_command_key_count") != len(expected_next_command_keys):
        return "{} --status-json did not count current next command key aliases".format(
            PUBLIC_LAUNCH_MANIFEST_TOOL.relative_to(ROOT_DIR)
        )
    expected_next_command_values = [
        actions[0].get(command_field)
        for command_field in command_fields
        if actions[0].get(command_field) is not None
    ]
    if status_json.get("next_command_values") != expected_next_command_values:
        return "{} --status-json did not expose current next command value aliases".format(
            PUBLIC_LAUNCH_MANIFEST_TOOL.relative_to(ROOT_DIR)
        )
    if status_json.get("next_command_value_count") != len(expected_next_command_values):
        return "{} --status-json did not count current next command value aliases".format(
            PUBLIC_LAUNCH_MANIFEST_TOOL.relative_to(ROOT_DIR)
        )
    expected_next_command_pairs = [
        {"key": command_field, "value": actions[0].get(command_field)}
        for command_field in command_fields
        if actions[0].get(command_field) is not None
    ]
    if status_json.get("next_command_pairs") != expected_next_command_pairs:
        return "{} --status-json did not expose current next command pair aliases".format(
            PUBLIC_LAUNCH_MANIFEST_TOOL.relative_to(ROOT_DIR)
        )
    if status_json.get("next_command_pair_count") != len(expected_next_command_pairs):
        return "{} --status-json did not count current next command pair aliases".format(
            PUBLIC_LAUNCH_MANIFEST_TOOL.relative_to(ROOT_DIR)
        )
    if "--check-snapshot-audit main <snapshot_audit.json>" not in status_json.get("next", {}).get("action", ""):
        return "{} --status-json did not include next action guidance".format(
            PUBLIC_LAUNCH_MANIFEST_TOOL.relative_to(ROOT_DIR)
        )
    if "--set-snapshot-audit main <snapshot_audit.json>" not in status_json.get("next_action", {}).get("action", ""):
        return "{} --status-json did not include next_action apply guidance".format(
            PUBLIC_LAUNCH_MANIFEST_TOOL.relative_to(ROOT_DIR)
        )
    if "main.litecoin_snapshot.height" not in status_json.get("blocked_fields", []):
        return "{} --status-json did not include field-level blockers".format(
            PUBLIC_LAUNCH_MANIFEST_TOOL.relative_to(ROOT_DIR)
        )

    with tempfile.TemporaryDirectory(prefix="zkcoin manifest path ") as spaced_manifest_dir:
        spaced_manifest_path = Path(spaced_manifest_dir) / "public launch manifest.json"
        spaced_manifest_path.write_text(PUBLIC_LAUNCH_MANIFEST.read_text(encoding="utf8"), encoding="utf8")
        spaced_next_action_result = subprocess.run(
            [
                sys.executable,
                str(PUBLIC_LAUNCH_MANIFEST_TOOL),
                "--next-action",
                str(spaced_manifest_path),
            ],
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        if spaced_next_action_result.returncode != 0:
            return "{} --next-action failed for a staged manifest path with spaces: {}".format(
                PUBLIC_LAUNCH_MANIFEST_TOOL.relative_to(ROOT_DIR),
                spaced_next_action_result.stderr.strip()
                or spaced_next_action_result.stdout.strip()
                or "no output",
            )
        quoted_manifest_path = shlex.quote(str(spaced_manifest_path))
        if f"--in-place {quoted_manifest_path}" not in spaced_next_action_result.stdout:
            return "{} --next-action did not shell-quote a staged manifest path with spaces".format(
                PUBLIC_LAUNCH_MANIFEST_TOOL.relative_to(ROOT_DIR)
            )
        if f"  - apply command: contrib/devtools/zkcoin_public_launch_profile.py --set-snapshot-audit main <snapshot_audit.json> --in-place {quoted_manifest_path}" not in spaced_next_action_result.stdout:
            return "{} --next-action did not shell-quote a copyable staged apply command".format(
                PUBLIC_LAUNCH_MANIFEST_TOOL.relative_to(ROOT_DIR)
            )
        if f"  - check command: contrib/devtools/zkcoin_public_launch_profile.py --check-snapshot-audit main <snapshot_audit.json> {quoted_manifest_path}" not in spaced_next_action_result.stdout:
            return "{} --next-action did not shell-quote a copyable staged check command".format(
                PUBLIC_LAUNCH_MANIFEST_TOOL.relative_to(ROOT_DIR)
            )
        if f"  - template command: contrib/devtools/zkcoin_public_launch_profile.py --snapshot-audit-template main {quoted_manifest_path}" not in spaced_next_action_result.stdout:
            return "{} --next-action did not shell-quote a copyable staged template command".format(
                PUBLIC_LAUNCH_MANIFEST_TOOL.relative_to(ROOT_DIR)
            )
        if f"  - later blocker readiness summary commands: main.auxpow_chain_id=contrib/devtools/zkcoin_public_launch_profile.py --blocker-readiness-summary main.auxpow_chain_id {quoted_manifest_path}" not in spaced_next_action_result.stdout:
            return "{} --next-action did not shell-quote staged later blocker summary commands".format(
                PUBLIC_LAUNCH_MANIFEST_TOOL.relative_to(ROOT_DIR)
            )
        if f"testnet.dns_seeds=contrib/devtools/zkcoin_public_launch_profile.py --blocker-readiness-summary testnet.dns_seeds {quoted_manifest_path}" not in spaced_next_action_result.stdout:
            return "{} --next-action did not shell-quote the final staged later blocker summary command".format(
                PUBLIC_LAUNCH_MANIFEST_TOOL.relative_to(ROOT_DIR)
            )

        spaced_action_plan_result = subprocess.run(
            [
                sys.executable,
                str(PUBLIC_LAUNCH_MANIFEST_TOOL),
                "--action-plan",
                str(spaced_manifest_path),
            ],
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        if spaced_action_plan_result.returncode != 0:
            return "{} --action-plan failed for a staged manifest path with spaces: {}".format(
                PUBLIC_LAUNCH_MANIFEST_TOOL.relative_to(ROOT_DIR),
                spaced_action_plan_result.stderr.strip()
                or spaced_action_plan_result.stdout.strip()
                or "no output",
            )
        if f"--in-place {quoted_manifest_path}" not in spaced_action_plan_result.stdout:
            return "{} --action-plan did not shell-quote a staged manifest path with spaces".format(
                PUBLIC_LAUNCH_MANIFEST_TOOL.relative_to(ROOT_DIR)
            )
        if f"     apply command: contrib/devtools/zkcoin_public_launch_profile.py --set-snapshot-audit main <snapshot_audit.json> --in-place {quoted_manifest_path}" not in spaced_action_plan_result.stdout:
            return "{} --action-plan did not shell-quote a copyable staged apply command".format(
                PUBLIC_LAUNCH_MANIFEST_TOOL.relative_to(ROOT_DIR)
            )
        if f"     check command: contrib/devtools/zkcoin_public_launch_profile.py --check-snapshot-audit main <snapshot_audit.json> {quoted_manifest_path}" not in spaced_action_plan_result.stdout:
            return "{} --action-plan did not shell-quote a copyable staged check command".format(
                PUBLIC_LAUNCH_MANIFEST_TOOL.relative_to(ROOT_DIR)
            )
        if f"     readiness summary command: contrib/devtools/zkcoin_public_launch_profile.py --readiness-summary {quoted_manifest_path}" not in spaced_action_plan_result.stdout:
            return "{} --action-plan did not shell-quote a copyable staged readiness-summary command".format(
                PUBLIC_LAUNCH_MANIFEST_TOOL.relative_to(ROOT_DIR)
            )

        spaced_readiness_result = subprocess.run(
            [
                sys.executable,
                str(PUBLIC_LAUNCH_MANIFEST_TOOL),
                "--readiness-summary",
                str(spaced_manifest_path),
            ],
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        if spaced_readiness_result.returncode != 0:
            return "{} --readiness-summary failed for a staged manifest path with spaces: {}".format(
                PUBLIC_LAUNCH_MANIFEST_TOOL.relative_to(ROOT_DIR),
                spaced_readiness_result.stderr.strip()
                or spaced_readiness_result.stdout.strip()
                or "no output",
            )
        if "  - blocked networks: main, testnet" not in spaced_readiness_result.stdout:
            return "{} --readiness-summary did not print staged blocked networks".format(
                PUBLIC_LAUNCH_MANIFEST_TOOL.relative_to(ROOT_DIR)
            )
        if "  - blocked networks by blocker type: litecoin_snapshot=main, testnet; auxpow_chain_id=main, testnet; public_network_identity=main, testnet; dns_seeds=main, testnet" not in spaced_readiness_result.stdout:
            return "{} --readiness-summary did not print staged blocked networks by blocker type".format(
                PUBLIC_LAUNCH_MANIFEST_TOOL.relative_to(ROOT_DIR)
            )
        if "  - ready networks by blocker type: litecoin_snapshot=none; auxpow_chain_id=none; public_network_identity=none; dns_seeds=none" not in spaced_readiness_result.stdout:
            return "{} --readiness-summary did not print staged ready networks by blocker type".format(
                PUBLIC_LAUNCH_MANIFEST_TOOL.relative_to(ROOT_DIR)
            )
        if f"  - action plan command: contrib/devtools/zkcoin_public_launch_profile.py --action-plan {quoted_manifest_path}" not in spaced_readiness_result.stdout:
            return "{} --readiness-summary did not shell-quote staged action-plan commands".format(
                PUBLIC_LAUNCH_MANIFEST_TOOL.relative_to(ROOT_DIR)
            )
        if f"  - next action command: contrib/devtools/zkcoin_public_launch_profile.py --next-action {quoted_manifest_path}" not in spaced_readiness_result.stdout:
            return "{} --readiness-summary did not shell-quote staged next-action commands".format(
                PUBLIC_LAUNCH_MANIFEST_TOOL.relative_to(ROOT_DIR)
            )
        if f"  - readiness summary command: contrib/devtools/zkcoin_public_launch_profile.py --readiness-summary {quoted_manifest_path}" not in spaced_readiness_result.stdout:
            return "{} --readiness-summary did not shell-quote staged rerun commands".format(
                PUBLIC_LAUNCH_MANIFEST_TOOL.relative_to(ROOT_DIR)
            )
        if f"  - status JSON command: contrib/devtools/zkcoin_public_launch_profile.py --status-json {quoted_manifest_path}" not in spaced_readiness_result.stdout:
            return "{} --readiness-summary did not shell-quote staged status-json commands".format(
                PUBLIC_LAUNCH_MANIFEST_TOOL.relative_to(ROOT_DIR)
            )
        if "  - unresolved blockers by network: main=4, testnet=4" not in spaced_readiness_result.stdout:
            return "{} --readiness-summary did not print staged per-network blocker counts".format(
                PUBLIC_LAUNCH_MANIFEST_TOOL.relative_to(ROOT_DIR)
            )
        if "  - blocked fields by network: main=23, testnet=23" not in spaced_readiness_result.stdout:
            return "{} --readiness-summary did not print staged per-network field counts".format(
                PUBLIC_LAUNCH_MANIFEST_TOOL.relative_to(ROOT_DIR)
            )
        if "  - next blockers by network: main=main.litecoin_snapshot, testnet=testnet.litecoin_snapshot" not in spaced_readiness_result.stdout:
            return "{} --readiness-summary did not print staged per-network next blockers".format(
                PUBLIC_LAUNCH_MANIFEST_TOOL.relative_to(ROOT_DIR)
            )
        if "  - next blocker fields by network: main=11, testnet=11" not in spaced_readiness_result.stdout:
            return "{} --readiness-summary did not print staged per-network next blocker field counts".format(
                PUBLIC_LAUNCH_MANIFEST_TOOL.relative_to(ROOT_DIR)
            )
        if f"  - next template commands by network: main=contrib/devtools/zkcoin_public_launch_profile.py --snapshot-audit-template main {quoted_manifest_path}; testnet=contrib/devtools/zkcoin_public_launch_profile.py --snapshot-audit-template testnet {quoted_manifest_path}" not in spaced_readiness_result.stdout:
            return "{} --readiness-summary did not shell-quote staged per-network next template commands".format(
                PUBLIC_LAUNCH_MANIFEST_TOOL.relative_to(ROOT_DIR)
            )
        if f"  - next check commands by network: main=contrib/devtools/zkcoin_public_launch_profile.py --check-snapshot-audit main <snapshot_audit.json> {quoted_manifest_path}; testnet=contrib/devtools/zkcoin_public_launch_profile.py --check-snapshot-audit testnet <snapshot_audit.json> {quoted_manifest_path}" not in spaced_readiness_result.stdout:
            return "{} --readiness-summary did not shell-quote staged per-network next check commands".format(
                PUBLIC_LAUNCH_MANIFEST_TOOL.relative_to(ROOT_DIR)
            )
        if f"  - next apply commands by network: main=contrib/devtools/zkcoin_public_launch_profile.py --set-snapshot-audit main <snapshot_audit.json> --in-place {quoted_manifest_path}; testnet=contrib/devtools/zkcoin_public_launch_profile.py --set-snapshot-audit testnet <snapshot_audit.json> --in-place {quoted_manifest_path}" not in spaced_readiness_result.stdout:
            return "{} --readiness-summary did not shell-quote staged per-network next apply commands".format(
                PUBLIC_LAUNCH_MANIFEST_TOOL.relative_to(ROOT_DIR)
            )
        if f"  - next template commands by blocker type: litecoin_snapshot=contrib/devtools/zkcoin_public_launch_profile.py --snapshot-audit-template main {quoted_manifest_path}; auxpow_chain_id=none; public_network_identity=none; dns_seeds=none" not in spaced_readiness_result.stdout:
            return "{} --readiness-summary did not shell-quote staged blocker-type next template commands".format(
                PUBLIC_LAUNCH_MANIFEST_TOOL.relative_to(ROOT_DIR)
            )
        if f"auxpow_chain_id=contrib/devtools/zkcoin_public_launch_profile.py --check-auxpow main <chain_id> {quoted_manifest_path}" not in spaced_readiness_result.stdout:
            return "{} --readiness-summary did not shell-quote staged blocker-type next check commands".format(
                PUBLIC_LAUNCH_MANIFEST_TOOL.relative_to(ROOT_DIR)
            )
        if f"dns_seeds=contrib/devtools/zkcoin_public_launch_profile.py --set-dns-seeds main <seed1.hostname>,<seed2.hostname> --in-place {quoted_manifest_path}" not in spaced_readiness_result.stdout:
            return "{} --readiness-summary did not shell-quote staged blocker-type next apply commands".format(
                PUBLIC_LAUNCH_MANIFEST_TOOL.relative_to(ROOT_DIR)
            )
        if f"  - next network readiness summary commands by blocker type: litecoin_snapshot=contrib/devtools/zkcoin_public_launch_profile.py --network-readiness-summary main {quoted_manifest_path}" not in spaced_readiness_result.stdout:
            return "{} --readiness-summary did not shell-quote staged blocker-type next network summary commands".format(
                PUBLIC_LAUNCH_MANIFEST_TOOL.relative_to(ROOT_DIR)
            )
        if f"dns_seeds=contrib/devtools/zkcoin_public_launch_profile.py --blocker-type-readiness-summary dns_seeds {quoted_manifest_path}" not in spaced_readiness_result.stdout:
            return "{} --readiness-summary did not shell-quote staged blocker-type next blocker-type summary commands".format(
                PUBLIC_LAUNCH_MANIFEST_TOOL.relative_to(ROOT_DIR)
            )
        if f"  - next blocker readiness summary commands by blocker type: litecoin_snapshot=contrib/devtools/zkcoin_public_launch_profile.py --blocker-readiness-summary main.litecoin_snapshot {quoted_manifest_path}" not in spaced_readiness_result.stdout:
            return "{} --readiness-summary did not shell-quote staged blocker-type next blocker summary commands".format(
                PUBLIC_LAUNCH_MANIFEST_TOOL.relative_to(ROOT_DIR)
            )
        if f"  - next blocker type readiness summary commands by network: main=contrib/devtools/zkcoin_public_launch_profile.py --blocker-type-readiness-summary litecoin_snapshot {quoted_manifest_path}; testnet=contrib/devtools/zkcoin_public_launch_profile.py --blocker-type-readiness-summary litecoin_snapshot {quoted_manifest_path}" not in spaced_readiness_result.stdout:
            return "{} --readiness-summary did not shell-quote staged per-network next blocker-type summary commands".format(
                PUBLIC_LAUNCH_MANIFEST_TOOL.relative_to(ROOT_DIR)
            )
        if f"  - network readiness summary commands by network: main=contrib/devtools/zkcoin_public_launch_profile.py --network-readiness-summary main {quoted_manifest_path}; testnet=contrib/devtools/zkcoin_public_launch_profile.py --network-readiness-summary testnet {quoted_manifest_path}" not in spaced_readiness_result.stdout:
            return "{} --readiness-summary did not shell-quote staged per-network summary commands".format(
                PUBLIC_LAUNCH_MANIFEST_TOOL.relative_to(ROOT_DIR)
            )
        if f"  - blocker type readiness summary commands by blocker type: litecoin_snapshot=contrib/devtools/zkcoin_public_launch_profile.py --blocker-type-readiness-summary litecoin_snapshot {quoted_manifest_path}" not in spaced_readiness_result.stdout:
            return "{} --readiness-summary did not shell-quote staged blocker-type summary commands".format(
                PUBLIC_LAUNCH_MANIFEST_TOOL.relative_to(ROOT_DIR)
            )
        if "    - main.litecoin_snapshot.audit.total_amount" not in spaced_readiness_result.stdout:
            return "{} --readiness-summary did not print staged next blocked fields".format(
                PUBLIC_LAUNCH_MANIFEST_TOOL.relative_to(ROOT_DIR)
            )
        if f"--in-place {quoted_manifest_path}" not in spaced_readiness_result.stdout:
            return "{} --readiness-summary did not shell-quote a staged manifest path with spaces".format(
                PUBLIC_LAUNCH_MANIFEST_TOOL.relative_to(ROOT_DIR)
            )
        if f"  - check command: contrib/devtools/zkcoin_public_launch_profile.py --check-snapshot-audit main <snapshot_audit.json> {quoted_manifest_path}" not in spaced_readiness_result.stdout:
            return "{} --readiness-summary did not shell-quote a copyable staged check command".format(
                PUBLIC_LAUNCH_MANIFEST_TOOL.relative_to(ROOT_DIR)
            )
        if f"  - network readiness summary command: contrib/devtools/zkcoin_public_launch_profile.py --network-readiness-summary main {quoted_manifest_path}" not in spaced_readiness_result.stdout:
            return "{} --readiness-summary did not shell-quote staged network summary commands".format(
                PUBLIC_LAUNCH_MANIFEST_TOOL.relative_to(ROOT_DIR)
            )
        if f"  - blocker type readiness summary command: contrib/devtools/zkcoin_public_launch_profile.py --blocker-type-readiness-summary litecoin_snapshot {quoted_manifest_path}" not in spaced_readiness_result.stdout:
            return "{} --readiness-summary did not shell-quote staged blocker-type summary commands".format(
                PUBLIC_LAUNCH_MANIFEST_TOOL.relative_to(ROOT_DIR)
            )
        if f"  - blocker readiness summary command: contrib/devtools/zkcoin_public_launch_profile.py --blocker-readiness-summary main.litecoin_snapshot {quoted_manifest_path}" not in spaced_readiness_result.stdout:
            return "{} --readiness-summary did not shell-quote staged blocker summary commands".format(
                PUBLIC_LAUNCH_MANIFEST_TOOL.relative_to(ROOT_DIR)
            )
        if f"  - later blocker readiness summary commands: main.auxpow_chain_id=contrib/devtools/zkcoin_public_launch_profile.py --blocker-readiness-summary main.auxpow_chain_id {quoted_manifest_path}" not in spaced_readiness_result.stdout:
            return "{} --readiness-summary did not shell-quote staged later blocker summary commands".format(
                PUBLIC_LAUNCH_MANIFEST_TOOL.relative_to(ROOT_DIR)
            )

        spaced_network_readiness_result = subprocess.run(
            [
                sys.executable,
                str(PUBLIC_LAUNCH_MANIFEST_TOOL),
                "--network-readiness-summary",
                "main",
                str(spaced_manifest_path),
            ],
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        if spaced_network_readiness_result.returncode != 0:
            return "{} --network-readiness-summary failed for a staged manifest path with spaces: {}".format(
                PUBLIC_LAUNCH_MANIFEST_TOOL.relative_to(ROOT_DIR),
                spaced_network_readiness_result.stderr.strip()
                or spaced_network_readiness_result.stdout.strip()
                or "no output",
            )
        if f"  - template command: contrib/devtools/zkcoin_public_launch_profile.py --snapshot-audit-template main {quoted_manifest_path}" not in spaced_network_readiness_result.stdout:
            return "{} --network-readiness-summary did not shell-quote a staged template command".format(
                PUBLIC_LAUNCH_MANIFEST_TOOL.relative_to(ROOT_DIR)
            )
        if f"  - check command: contrib/devtools/zkcoin_public_launch_profile.py --check-snapshot-audit main <snapshot_audit.json> {quoted_manifest_path}" not in spaced_network_readiness_result.stdout:
            return "{} --network-readiness-summary did not shell-quote a staged check command".format(
                PUBLIC_LAUNCH_MANIFEST_TOOL.relative_to(ROOT_DIR)
            )
        if f"  - apply command: contrib/devtools/zkcoin_public_launch_profile.py --set-snapshot-audit main <snapshot_audit.json> --in-place {quoted_manifest_path}" not in spaced_network_readiness_result.stdout:
            return "{} --network-readiness-summary did not shell-quote a staged apply command".format(
                PUBLIC_LAUNCH_MANIFEST_TOOL.relative_to(ROOT_DIR)
            )
        if f"  - network readiness summary command: contrib/devtools/zkcoin_public_launch_profile.py --network-readiness-summary main {quoted_manifest_path}" not in spaced_network_readiness_result.stdout:
            return "{} --network-readiness-summary did not shell-quote a staged network summary command".format(
                PUBLIC_LAUNCH_MANIFEST_TOOL.relative_to(ROOT_DIR)
            )
        if "  - blocked blocker types: litecoin_snapshot, auxpow_chain_id, public_network_identity, dns_seeds" not in spaced_network_readiness_result.stdout:
            return "{} --network-readiness-summary did not print staged blocked blocker types".format(
                PUBLIC_LAUNCH_MANIFEST_TOOL.relative_to(ROOT_DIR)
            )
        if "  - ready blocker types: none" not in spaced_network_readiness_result.stdout:
            return "{} --network-readiness-summary did not print staged ready blocker types".format(
                PUBLIC_LAUNCH_MANIFEST_TOOL.relative_to(ROOT_DIR)
            )
        if f"main.dns_seeds=contrib/devtools/zkcoin_public_launch_profile.py --blocker-readiness-summary main.dns_seeds {quoted_manifest_path}" not in spaced_network_readiness_result.stdout:
            return "{} --network-readiness-summary did not shell-quote staged later blocker summary commands".format(
                PUBLIC_LAUNCH_MANIFEST_TOOL.relative_to(ROOT_DIR)
            )

        spaced_blocker_type_readiness_result = subprocess.run(
            [
                sys.executable,
                str(PUBLIC_LAUNCH_MANIFEST_TOOL),
                "--blocker-type-readiness-summary",
                "litecoin_snapshot",
                str(spaced_manifest_path),
            ],
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        if spaced_blocker_type_readiness_result.returncode != 0:
            return "{} --blocker-type-readiness-summary failed for a staged manifest path with spaces: {}".format(
                PUBLIC_LAUNCH_MANIFEST_TOOL.relative_to(ROOT_DIR),
                spaced_blocker_type_readiness_result.stderr.strip()
                or spaced_blocker_type_readiness_result.stdout.strip()
                or "no output",
            )
        if f"  - template command: contrib/devtools/zkcoin_public_launch_profile.py --snapshot-audit-template main {quoted_manifest_path}" not in spaced_blocker_type_readiness_result.stdout:
            return "{} --blocker-type-readiness-summary did not shell-quote a staged template command".format(
                PUBLIC_LAUNCH_MANIFEST_TOOL.relative_to(ROOT_DIR)
            )
        if f"  - check command: contrib/devtools/zkcoin_public_launch_profile.py --check-snapshot-audit main <snapshot_audit.json> {quoted_manifest_path}" not in spaced_blocker_type_readiness_result.stdout:
            return "{} --blocker-type-readiness-summary did not shell-quote a staged check command".format(
                PUBLIC_LAUNCH_MANIFEST_TOOL.relative_to(ROOT_DIR)
            )
        if f"  - apply command: contrib/devtools/zkcoin_public_launch_profile.py --set-snapshot-audit main <snapshot_audit.json> --in-place {quoted_manifest_path}" not in spaced_blocker_type_readiness_result.stdout:
            return "{} --blocker-type-readiness-summary did not shell-quote a staged apply command".format(
                PUBLIC_LAUNCH_MANIFEST_TOOL.relative_to(ROOT_DIR)
            )
        if f"  - network readiness summary command: contrib/devtools/zkcoin_public_launch_profile.py --network-readiness-summary main {quoted_manifest_path}" not in spaced_blocker_type_readiness_result.stdout:
            return "{} --blocker-type-readiness-summary did not shell-quote a staged network summary command".format(
                PUBLIC_LAUNCH_MANIFEST_TOOL.relative_to(ROOT_DIR)
            )
        if "  - blocked networks: main, testnet" not in spaced_blocker_type_readiness_result.stdout:
            return "{} --blocker-type-readiness-summary did not print staged blocked networks".format(
                PUBLIC_LAUNCH_MANIFEST_TOOL.relative_to(ROOT_DIR)
            )
        if "  - ready networks: none" not in spaced_blocker_type_readiness_result.stdout:
            return "{} --blocker-type-readiness-summary did not print staged ready networks".format(
                PUBLIC_LAUNCH_MANIFEST_TOOL.relative_to(ROOT_DIR)
            )
        if f"  - blocker type readiness summary command: contrib/devtools/zkcoin_public_launch_profile.py --blocker-type-readiness-summary litecoin_snapshot {quoted_manifest_path}" not in spaced_blocker_type_readiness_result.stdout:
            return "{} --blocker-type-readiness-summary did not shell-quote a staged blocker-type summary command".format(
                PUBLIC_LAUNCH_MANIFEST_TOOL.relative_to(ROOT_DIR)
            )
        if f"  - later blocker readiness summary commands: testnet.litecoin_snapshot=contrib/devtools/zkcoin_public_launch_profile.py --blocker-readiness-summary testnet.litecoin_snapshot {quoted_manifest_path}" not in spaced_blocker_type_readiness_result.stdout:
            return "{} --blocker-type-readiness-summary did not shell-quote staged later blocker summary commands".format(
                PUBLIC_LAUNCH_MANIFEST_TOOL.relative_to(ROOT_DIR)
            )

        spaced_blocker_readiness_result = subprocess.run(
            [
                sys.executable,
                str(PUBLIC_LAUNCH_MANIFEST_TOOL),
                "--blocker-readiness-summary",
                "main.litecoin_snapshot",
                str(spaced_manifest_path),
            ],
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        if spaced_blocker_readiness_result.returncode != 0:
            return "{} --blocker-readiness-summary failed for a staged manifest path with spaces: {}".format(
                PUBLIC_LAUNCH_MANIFEST_TOOL.relative_to(ROOT_DIR),
                spaced_blocker_readiness_result.stderr.strip()
                or spaced_blocker_readiness_result.stdout.strip()
                or "no output",
            )
        if f"  - template command: contrib/devtools/zkcoin_public_launch_profile.py --snapshot-audit-template main {quoted_manifest_path}" not in spaced_blocker_readiness_result.stdout:
            return "{} --blocker-readiness-summary did not shell-quote a staged template command".format(
                PUBLIC_LAUNCH_MANIFEST_TOOL.relative_to(ROOT_DIR)
            )
        if f"  - check command: contrib/devtools/zkcoin_public_launch_profile.py --check-snapshot-audit main <snapshot_audit.json> {quoted_manifest_path}" not in spaced_blocker_readiness_result.stdout:
            return "{} --blocker-readiness-summary did not shell-quote a staged check command".format(
                PUBLIC_LAUNCH_MANIFEST_TOOL.relative_to(ROOT_DIR)
            )
        if f"  - apply command: contrib/devtools/zkcoin_public_launch_profile.py --set-snapshot-audit main <snapshot_audit.json> --in-place {quoted_manifest_path}" not in spaced_blocker_readiness_result.stdout:
            return "{} --blocker-readiness-summary did not shell-quote a staged apply command".format(
                PUBLIC_LAUNCH_MANIFEST_TOOL.relative_to(ROOT_DIR)
            )
        if f"  - network readiness summary command: contrib/devtools/zkcoin_public_launch_profile.py --network-readiness-summary main {quoted_manifest_path}" not in spaced_blocker_readiness_result.stdout:
            return "{} --blocker-readiness-summary did not shell-quote a staged network summary command".format(
                PUBLIC_LAUNCH_MANIFEST_TOOL.relative_to(ROOT_DIR)
            )
        if f"  - blocker type readiness summary command: contrib/devtools/zkcoin_public_launch_profile.py --blocker-type-readiness-summary litecoin_snapshot {quoted_manifest_path}" not in spaced_blocker_readiness_result.stdout:
            return "{} --blocker-readiness-summary did not shell-quote a staged blocker-type summary command".format(
                PUBLIC_LAUNCH_MANIFEST_TOOL.relative_to(ROOT_DIR)
            )
        if f"  - blocker readiness summary command: contrib/devtools/zkcoin_public_launch_profile.py --blocker-readiness-summary main.litecoin_snapshot {quoted_manifest_path}" not in spaced_blocker_readiness_result.stdout:
            return "{} --blocker-readiness-summary did not shell-quote a staged blocker summary command".format(
                PUBLIC_LAUNCH_MANIFEST_TOOL.relative_to(ROOT_DIR)
            )
        if "  - network launch order: 1 of 4" not in spaced_blocker_readiness_result.stdout:
            return "{} --blocker-readiness-summary did not print staged network launch order".format(
                PUBLIC_LAUNCH_MANIFEST_TOOL.relative_to(ROOT_DIR)
            )
        if "  - blocker-type launch order: 1 of 2" not in spaced_blocker_readiness_result.stdout:
            return "{} --blocker-readiness-summary did not print staged blocker-type launch order".format(
                PUBLIC_LAUNCH_MANIFEST_TOOL.relative_to(ROOT_DIR)
            )
        if f"testnet.dns_seeds=contrib/devtools/zkcoin_public_launch_profile.py --blocker-readiness-summary testnet.dns_seeds {quoted_manifest_path}" not in spaced_blocker_readiness_result.stdout:
            return "{} --blocker-readiness-summary did not shell-quote staged later blocker summary commands".format(
                PUBLIC_LAUNCH_MANIFEST_TOOL.relative_to(ROOT_DIR)
            )

        spaced_terminal_blocker_readiness_result = subprocess.run(
            [
                sys.executable,
                str(PUBLIC_LAUNCH_MANIFEST_TOOL),
                "--blocker-readiness-summary",
                "testnet.dns_seeds",
                str(spaced_manifest_path),
            ],
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        if spaced_terminal_blocker_readiness_result.returncode != 0:
            return "{} --blocker-readiness-summary failed for a staged terminal blocker path with spaces: {}".format(
                PUBLIC_LAUNCH_MANIFEST_TOOL.relative_to(ROOT_DIR),
                spaced_terminal_blocker_readiness_result.stderr.strip()
                or spaced_terminal_blocker_readiness_result.stdout.strip()
                or "no output",
            )
        if f"  - earlier blocker readiness summary commands: main.litecoin_snapshot=contrib/devtools/zkcoin_public_launch_profile.py --blocker-readiness-summary main.litecoin_snapshot {quoted_manifest_path}" not in spaced_terminal_blocker_readiness_result.stdout:
            return "{} --blocker-readiness-summary did not shell-quote staged earlier blocker summary commands".format(
                PUBLIC_LAUNCH_MANIFEST_TOOL.relative_to(ROOT_DIR)
            )
        if f"testnet.public_network_identity=contrib/devtools/zkcoin_public_launch_profile.py --blocker-readiness-summary testnet.public_network_identity {quoted_manifest_path}" not in spaced_terminal_blocker_readiness_result.stdout:
            return "{} --blocker-readiness-summary did not shell-quote staged terminal earlier blocker summary commands".format(
                PUBLIC_LAUNCH_MANIFEST_TOOL.relative_to(ROOT_DIR)
            )

        spaced_status_json_result = subprocess.run(
            [
                sys.executable,
                str(PUBLIC_LAUNCH_MANIFEST_TOOL),
                "--status-json",
                str(spaced_manifest_path),
            ],
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        if spaced_status_json_result.returncode != 0:
            return "{} --status-json failed for a staged manifest path with spaces: {}".format(
                PUBLIC_LAUNCH_MANIFEST_TOOL.relative_to(ROOT_DIR),
                spaced_status_json_result.stderr.strip()
                or spaced_status_json_result.stdout.strip()
                or "no output",
            )
        try:
            spaced_status_json = json.loads(spaced_status_json_result.stdout)
        except json.JSONDecodeError as exc:
            return "{} --status-json for a staged manifest path did not emit JSON: {}".format(
                PUBLIC_LAUNCH_MANIFEST_TOOL.relative_to(ROOT_DIR),
                exc,
            )
        schema_version_error = require_status_json_schema_version(spaced_status_json)
        if schema_version_error:
            return schema_version_error
        if spaced_status_json.get("action_count") != 8:
            return "{} --status-json did not count staged action-plan entries".format(
                PUBLIC_LAUNCH_MANIFEST_TOOL.relative_to(ROOT_DIR)
            )
        if spaced_status_json.get("action_counts_by_network") != {"main": 4, "testnet": 4}:
            return "{} --status-json did not count staged action-plan entries by network".format(
                PUBLIC_LAUNCH_MANIFEST_TOOL.relative_to(ROOT_DIR)
            )
        if spaced_status_json.get("action_counts_by_blocker_type") != expected_action_counts_by_blocker_type:
            return "{} --status-json did not count staged action-plan entries by blocker type".format(
                PUBLIC_LAUNCH_MANIFEST_TOOL.relative_to(ROOT_DIR)
            )
        spaced_action_count_matrix = spaced_status_json.get("action_counts_by_network_and_blocker_type")
        if spaced_action_count_matrix != expected_action_counts_by_network_and_blocker_type:
            return "{} --status-json did not count staged action-plan entries by network and blocker type".format(
                PUBLIC_LAUNCH_MANIFEST_TOOL.relative_to(ROOT_DIR)
            )
        spaced_action_id_matrix = action_ids_by_network_and_blocker_type(
            spaced_status_json.get("actions_by_network_and_blocker_type", {})
        )
        if spaced_action_id_matrix != expected_blockers_by_network_and_blocker_type:
            return "{} --status-json did not group staged action-plan entries by network and blocker type".format(
                PUBLIC_LAUNCH_MANIFEST_TOOL.relative_to(ROOT_DIR)
            )
        spaced_next_action_id_matrix = next_action_ids_by_network_and_blocker_type(
            spaced_status_json.get("next_actions_by_network_and_blocker_type", {})
        )
        if spaced_next_action_id_matrix != expected_next_action_ids_by_network_and_blocker_type:
            return "{} --status-json did not expose staged next action entries by network and blocker type".format(
                PUBLIC_LAUNCH_MANIFEST_TOOL.relative_to(ROOT_DIR)
            )
        spaced_next_command_matrix = spaced_status_json.get("next_commands_by_network_and_blocker_type", {})
        if quoted_manifest_path not in spaced_next_command_matrix.get("main", {}).get("litecoin_snapshot", {}).get("check_command", ""):
            return "{} --status-json did not shell-quote staged next commands by network and blocker type".format(
                PUBLIC_LAUNCH_MANIFEST_TOOL.relative_to(ROOT_DIR)
            )
        if spaced_status_json.get("next_blocker_commands_by_network_and_blocker_type") != spaced_next_command_matrix:
            return "{} --status-json did not alias staged matrix next blocker commands".format(
                PUBLIC_LAUNCH_MANIFEST_TOOL.relative_to(ROOT_DIR)
            )
        if spaced_status_json.get("unresolved_blocker_counts_by_blocker_type") != expected_blocker_counts_by_blocker_type:
            return "{} --status-json did not count staged blockers by blocker type".format(
                PUBLIC_LAUNCH_MANIFEST_TOOL.relative_to(ROOT_DIR)
            )
        if spaced_status_json.get("unresolved_blocker_counts_by_network_and_blocker_type") != expected_blocker_counts_by_network_and_blocker_type:
            return "{} --status-json did not count staged blockers by network and blocker type".format(
                PUBLIC_LAUNCH_MANIFEST_TOOL.relative_to(ROOT_DIR)
            )
        if spaced_status_json.get("unresolved_blockers_by_network_and_blocker_type") != expected_blockers_by_network_and_blocker_type:
            return "{} --status-json did not group staged blockers by network and blocker type".format(
                PUBLIC_LAUNCH_MANIFEST_TOOL.relative_to(ROOT_DIR)
            )
        if spaced_status_json.get("blocked_field_count") != 46:
            return "{} --status-json did not count staged field-level blockers".format(
                PUBLIC_LAUNCH_MANIFEST_TOOL.relative_to(ROOT_DIR)
            )
        if spaced_status_json.get("blocked_fields_by_network") != expected_blocked_fields_by_network:
            return "{} --status-json did not group staged field-level blockers by network".format(
                PUBLIC_LAUNCH_MANIFEST_TOOL.relative_to(ROOT_DIR)
            )
        if spaced_status_json.get("blocked_field_counts_by_blocker_type") != expected_blocked_field_counts_by_blocker_type:
            return "{} --status-json did not count staged field-level blockers by blocker type".format(
                PUBLIC_LAUNCH_MANIFEST_TOOL.relative_to(ROOT_DIR)
            )
        if spaced_status_json.get("blocked_field_counts_by_network_and_blocker_type") != expected_blocked_field_counts_by_network_and_blocker_type:
            return "{} --status-json did not count staged field-level blockers by network and blocker type".format(
                PUBLIC_LAUNCH_MANIFEST_TOOL.relative_to(ROOT_DIR)
            )
        if spaced_status_json.get("blocked_fields_by_network_and_blocker_type") != expected_blocked_fields_by_network_and_blocker_type:
            return "{} --status-json did not group staged field-level blockers by network and blocker type".format(
                PUBLIC_LAUNCH_MANIFEST_TOOL.relative_to(ROOT_DIR)
            )
        spaced_next_groups_by_network = spaced_status_json.get("next_blocked_field_groups_by_network", {})
        if spaced_status_json.get("next_blocker_field_groups_by_network") != spaced_next_groups_by_network:
            return "{} --status-json did not alias staged per-network next blocker groups".format(
                PUBLIC_LAUNCH_MANIFEST_TOOL.relative_to(ROOT_DIR)
            )
        spaced_next_group_matrix = spaced_status_json.get("next_blocked_field_groups_by_network_and_blocker_type", {})
        spaced_next_group_id_matrix = next_action_ids_by_network_and_blocker_type(spaced_next_group_matrix)
        if spaced_next_group_id_matrix != expected_next_action_ids_by_network_and_blocker_type:
            return "{} --status-json did not expose staged next blocker groups by network and blocker type".format(
                PUBLIC_LAUNCH_MANIFEST_TOOL.relative_to(ROOT_DIR)
            )
        if spaced_status_json.get("next_blocker_field_groups_by_network_and_blocker_type") != spaced_next_group_matrix:
            return "{} --status-json did not alias staged matrix next blocker groups".format(
                PUBLIC_LAUNCH_MANIFEST_TOOL.relative_to(ROOT_DIR)
            )
        if spaced_status_json.get("next_blockers_by_network_and_blocker_type") != expected_next_action_ids_by_network_and_blocker_type:
            return "{} --status-json did not expose staged next blockers by network and blocker type".format(
                PUBLIC_LAUNCH_MANIFEST_TOOL.relative_to(ROOT_DIR)
            )
        spaced_next_field_matrix = spaced_status_json.get("next_blocked_fields_by_network_and_blocker_type", {})
        if spaced_next_field_matrix.get("main", {}).get("litecoin_snapshot", [None])[0] != "main.litecoin_snapshot.height":
            return "{} --status-json did not expose staged mainnet snapshot next fields by network and blocker type".format(
                PUBLIC_LAUNCH_MANIFEST_TOOL.relative_to(ROOT_DIR)
            )
        if spaced_next_field_matrix.get("testnet", {}).get("dns_seeds") != ["testnet.public_network_identity.dns_seeds"]:
            return "{} --status-json did not expose staged testnet DNS seed next fields by network and blocker type".format(
                PUBLIC_LAUNCH_MANIFEST_TOOL.relative_to(ROOT_DIR)
            )
        if spaced_status_json.get("next_blocker_fields_by_network_and_blocker_type") != spaced_next_field_matrix:
            return "{} --status-json did not alias staged next blocker fields by network and blocker type".format(
                PUBLIC_LAUNCH_MANIFEST_TOOL.relative_to(ROOT_DIR)
            )
        if spaced_status_json.get("next_blocked_field_counts_by_network_and_blocker_type") != expected_blocked_field_counts_by_network_and_blocker_type:
            return "{} --status-json did not count staged next fields by network and blocker type".format(
                PUBLIC_LAUNCH_MANIFEST_TOOL.relative_to(ROOT_DIR)
            )
        if spaced_status_json.get("next_blocker_field_counts_by_network_and_blocker_type") != spaced_status_json.get("next_blocked_field_counts_by_network_and_blocker_type"):
            return "{} --status-json did not alias staged next blocker field counts by network and blocker type".format(
                PUBLIC_LAUNCH_MANIFEST_TOOL.relative_to(ROOT_DIR)
            )
        if len(spaced_status_json.get("blocked_field_groups", [])) != 8:
            return "{} --status-json did not include staged blocker field groups".format(
                PUBLIC_LAUNCH_MANIFEST_TOOL.relative_to(ROOT_DIR)
            )
        if spaced_status_json.get("blocked_field_group_count") != 8:
            return "{} --status-json did not count staged blocker field groups".format(
                PUBLIC_LAUNCH_MANIFEST_TOOL.relative_to(ROOT_DIR)
            )
        spaced_blocked_field_groups_by_network = spaced_status_json.get("blocked_field_groups_by_network", {})
        if {
            network: [group.get("id") for group in groups]
            for network, groups in spaced_blocked_field_groups_by_network.items()
        } != expected_blocked_field_group_ids_by_network:
            return "{} --status-json did not group staged blocker field groups by network".format(
                PUBLIC_LAUNCH_MANIFEST_TOOL.relative_to(ROOT_DIR)
            )
        if spaced_status_json.get("blocked_field_group_counts_by_network") != expected_blocked_field_group_counts_by_network:
            return "{} --status-json did not count staged blocker field groups by network".format(
                PUBLIC_LAUNCH_MANIFEST_TOOL.relative_to(ROOT_DIR)
            )
        spaced_blocked_field_groups_by_blocker_type = spaced_status_json.get("blocked_field_groups_by_blocker_type", {})
        if {
            blocker_type: [group.get("id") for group in groups]
            for blocker_type, groups in spaced_blocked_field_groups_by_blocker_type.items()
        } != expected_blocked_field_group_ids_by_blocker_type:
            return "{} --status-json did not group staged blocker field groups by blocker type".format(
                PUBLIC_LAUNCH_MANIFEST_TOOL.relative_to(ROOT_DIR)
            )
        if spaced_status_json.get("blocked_field_group_counts_by_blocker_type") != expected_blocked_field_group_counts_by_blocker_type:
            return "{} --status-json did not count staged blocker field groups by blocker type".format(
                PUBLIC_LAUNCH_MANIFEST_TOOL.relative_to(ROOT_DIR)
            )
        spaced_next_groups_by_blocker_type = spaced_status_json.get("next_blocked_field_groups_by_blocker_type", {})
        if {
            blocker_type: group.get("id") if group else None
            for blocker_type, group in spaced_next_groups_by_blocker_type.items()
        } != expected_next_blocked_field_group_ids_by_blocker_type:
            return "{} --status-json did not expose staged next blocker groups by blocker type".format(
                PUBLIC_LAUNCH_MANIFEST_TOOL.relative_to(ROOT_DIR)
            )
        if spaced_status_json.get("next_blocker_field_groups_by_blocker_type") != spaced_next_groups_by_blocker_type:
            return "{} --status-json did not alias staged next blocker groups by blocker type".format(
                PUBLIC_LAUNCH_MANIFEST_TOOL.relative_to(ROOT_DIR)
            )
        spaced_blocked_field_group_id_matrix = group_ids_by_network_and_blocker_type(
            spaced_status_json.get("blocked_field_groups_by_network_and_blocker_type", {})
        )
        if spaced_blocked_field_group_id_matrix != expected_blocked_field_group_ids_by_network_and_blocker_type:
            return "{} --status-json did not group staged blocker field groups by network and blocker type".format(
                PUBLIC_LAUNCH_MANIFEST_TOOL.relative_to(ROOT_DIR)
            )
        if spaced_status_json.get("blocked_field_group_counts_by_network_and_blocker_type") != expected_blocked_field_group_counts_by_network_and_blocker_type:
            return "{} --status-json did not count staged blocker field groups by network and blocker type".format(
                PUBLIC_LAUNCH_MANIFEST_TOOL.relative_to(ROOT_DIR)
            )
        if quoted_manifest_path not in spaced_status_json.get("action_plan_command", ""):
            return "{} --status-json did not shell-quote staged action-plan commands".format(
                PUBLIC_LAUNCH_MANIFEST_TOOL.relative_to(ROOT_DIR)
            )
        if quoted_manifest_path not in spaced_status_json.get("readiness_summary_command", ""):
            return "{} --status-json did not shell-quote staged readiness-summary commands".format(
                PUBLIC_LAUNCH_MANIFEST_TOOL.relative_to(ROOT_DIR)
            )
        if quoted_manifest_path not in spaced_status_json.get("status_json_command", ""):
            return "{} --status-json did not shell-quote staged status-json commands".format(
                PUBLIC_LAUNCH_MANIFEST_TOOL.relative_to(ROOT_DIR)
            )
        if quoted_manifest_path not in spaced_status_json.get("network_readiness_summary_commands_by_network", {}).get("main", ""):
            return "{} --status-json did not shell-quote staged network readiness-summary commands".format(
                PUBLIC_LAUNCH_MANIFEST_TOOL.relative_to(ROOT_DIR)
            )
        if quoted_manifest_path not in spaced_status_json.get("blocker_type_readiness_summary_commands_by_blocker_type", {}).get("litecoin_snapshot", ""):
            return "{} --status-json did not shell-quote staged blocker-type readiness-summary commands".format(
                PUBLIC_LAUNCH_MANIFEST_TOOL.relative_to(ROOT_DIR)
            )
        if quoted_manifest_path not in spaced_status_json.get("blocker_readiness_summary_commands_by_blocker", {}).get("main.litecoin_snapshot", ""):
            return "{} --status-json did not shell-quote staged blocker readiness-summary commands".format(
                PUBLIC_LAUNCH_MANIFEST_TOOL.relative_to(ROOT_DIR)
            )
        if quoted_manifest_path not in spaced_status_json.get("next_action_command", ""):
            return "{} --status-json did not shell-quote staged next-action commands".format(
                PUBLIC_LAUNCH_MANIFEST_TOOL.relative_to(ROOT_DIR)
            )
        for command_key, command_name in (
            ("action_plan", "action-plan"),
            ("next_action", "next-action"),
            ("readiness_summary", "readiness-summary"),
            ("status_json", "status-json"),
        ):
            if quoted_manifest_path not in spaced_status_json.get("commands", {}).get(command_key, ""):
                return "{} --status-json did not shell-quote staged command-map {} commands".format(
                    PUBLIC_LAUNCH_MANIFEST_TOOL.relative_to(ROOT_DIR),
                    command_name,
                )
        if quoted_manifest_path not in spaced_status_json.get("next_commands_by_network", {}).get("main", {}).get("check_command", ""):
            return "{} --status-json did not shell-quote staged network next commands".format(
                PUBLIC_LAUNCH_MANIFEST_TOOL.relative_to(ROOT_DIR)
            )
        if quoted_manifest_path not in spaced_status_json.get("next_commands_by_network", {}).get("main", {}).get("network_readiness_summary_command", ""):
            return "{} --status-json did not shell-quote staged network next network readiness-summary commands".format(
                PUBLIC_LAUNCH_MANIFEST_TOOL.relative_to(ROOT_DIR)
            )
        if spaced_status_json.get("next_blocker_commands_by_network") != spaced_status_json.get("next_commands_by_network"):
            return "{} --status-json did not alias staged per-network next blocker commands".format(
                PUBLIC_LAUNCH_MANIFEST_TOOL.relative_to(ROOT_DIR)
            )
        if quoted_manifest_path not in spaced_status_json.get("next_commands_by_blocker_type", {}).get("litecoin_snapshot", {}).get("check_command", ""):
            return "{} --status-json did not shell-quote staged blocker-type next commands".format(
                PUBLIC_LAUNCH_MANIFEST_TOOL.relative_to(ROOT_DIR)
            )
        if quoted_manifest_path not in spaced_status_json.get("next_commands_by_blocker_type", {}).get("litecoin_snapshot", {}).get("network_readiness_summary_command", ""):
            return "{} --status-json did not shell-quote staged blocker-type next network readiness-summary commands".format(
                PUBLIC_LAUNCH_MANIFEST_TOOL.relative_to(ROOT_DIR)
            )
        if spaced_status_json.get("next_blocker_commands_by_blocker_type") != spaced_status_json.get("next_commands_by_blocker_type"):
            return "{} --status-json did not alias staged blocker-type next blocker commands".format(
                PUBLIC_LAUNCH_MANIFEST_TOOL.relative_to(ROOT_DIR)
            )
        if f"--in-place {quoted_manifest_path}" not in spaced_status_json.get("blocked_field_groups", [{}])[0].get("action", ""):
            return "{} --status-json did not shell-quote a staged blocker field group action".format(
                PUBLIC_LAUNCH_MANIFEST_TOOL.relative_to(ROOT_DIR)
            )
        if f"--in-place {quoted_manifest_path}" not in spaced_status_json.get("next_blocked_field_group", {}).get("action", ""):
            return "{} --status-json did not shell-quote a staged next blocker field group action".format(
                PUBLIC_LAUNCH_MANIFEST_TOOL.relative_to(ROOT_DIR)
            )
        if spaced_status_json.get("next_blocker_field_group") != spaced_status_json.get("next_blocked_field_group"):
            return "{} --status-json did not alias the staged current blocker field group".format(
                PUBLIC_LAUNCH_MANIFEST_TOOL.relative_to(ROOT_DIR)
            )
        if spaced_status_json.get("next_blocker") != "main.litecoin_snapshot":
            return "{} --status-json did not expose the staged current blocker id".format(
                PUBLIC_LAUNCH_MANIFEST_TOOL.relative_to(ROOT_DIR)
            )
        if spaced_status_json.get("next_blocker_network") != "main":
            return "{} --status-json did not expose the staged current blocker network".format(
                PUBLIC_LAUNCH_MANIFEST_TOOL.relative_to(ROOT_DIR)
            )
        if spaced_status_json.get("next_blocker_type") != "litecoin_snapshot":
            return "{} --status-json did not expose the staged current blocker type".format(
                PUBLIC_LAUNCH_MANIFEST_TOOL.relative_to(ROOT_DIR)
            )
        if f"--in-place {quoted_manifest_path}" not in spaced_status_json.get("next_blocker_commands", {}).get("apply_command", ""):
            return "{} --status-json did not shell-quote a staged next blocker apply command".format(
                PUBLIC_LAUNCH_MANIFEST_TOOL.relative_to(ROOT_DIR)
            )
        if quoted_manifest_path not in spaced_status_json.get("next_blocker_commands", {}).get("check_command", ""):
            return "{} --status-json did not shell-quote a staged next blocker check command".format(
                PUBLIC_LAUNCH_MANIFEST_TOOL.relative_to(ROOT_DIR)
            )
        if spaced_status_json.get("next_blocker_fields", [None])[0] != "main.litecoin_snapshot.height":
            return "{} --status-json did not expose staged current blocker fields".format(
                PUBLIC_LAUNCH_MANIFEST_TOOL.relative_to(ROOT_DIR)
            )
        if spaced_status_json.get("next_blocker_field_count") != 11:
            return "{} --status-json did not expose staged current blocker field count".format(
                PUBLIC_LAUNCH_MANIFEST_TOOL.relative_to(ROOT_DIR)
            )
        if f"--in-place {quoted_manifest_path}" not in spaced_status_json.get("blocked_field_groups", [{}])[0].get("apply_command", ""):
            return "{} --status-json did not shell-quote a staged blocker field group apply command".format(
                PUBLIC_LAUNCH_MANIFEST_TOOL.relative_to(ROOT_DIR)
            )
        if quoted_manifest_path not in spaced_status_json.get("blocked_field_groups", [{}])[0].get("check_command", ""):
            return "{} --status-json did not shell-quote a staged blocker field group check command".format(
                PUBLIC_LAUNCH_MANIFEST_TOOL.relative_to(ROOT_DIR)
            )
        if quoted_manifest_path not in spaced_status_json.get("blocked_field_groups", [{}])[0].get("template_command", ""):
            return "{} --status-json did not shell-quote a staged blocker field group template command".format(
                PUBLIC_LAUNCH_MANIFEST_TOOL.relative_to(ROOT_DIR)
            )
        if quoted_manifest_path not in spaced_status_json.get("blocked_field_groups", [{}])[0].get("readiness_summary_command", ""):
            return "{} --status-json did not shell-quote a staged blocker field group readiness-summary command".format(
                PUBLIC_LAUNCH_MANIFEST_TOOL.relative_to(ROOT_DIR)
            )
        if quoted_manifest_path not in spaced_status_json.get("blocked_field_groups", [{}])[0].get("network_readiness_summary_command", ""):
            return "{} --status-json did not shell-quote a staged blocker field group network readiness-summary command".format(
                PUBLIC_LAUNCH_MANIFEST_TOOL.relative_to(ROOT_DIR)
            )
        if quoted_manifest_path not in spaced_status_json.get("blocked_field_groups", [{}])[0].get("blocker_type_readiness_summary_command", ""):
            return "{} --status-json did not shell-quote a staged blocker field group blocker-type readiness-summary command".format(
                PUBLIC_LAUNCH_MANIFEST_TOOL.relative_to(ROOT_DIR)
            )
        if quoted_manifest_path not in spaced_status_json.get("blocked_field_groups", [{}])[0].get("blocker_readiness_summary_command", ""):
            return "{} --status-json did not shell-quote a staged blocker field group blocker readiness-summary command".format(
                PUBLIC_LAUNCH_MANIFEST_TOOL.relative_to(ROOT_DIR)
            )
        if f"--in-place {quoted_manifest_path}" not in spaced_status_json.get("next_action", {}).get("action", ""):
            return "{} --status-json did not shell-quote a staged next_action".format(
                PUBLIC_LAUNCH_MANIFEST_TOOL.relative_to(ROOT_DIR)
            )
        if f"--in-place {quoted_manifest_path}" not in spaced_status_json.get("next_commands", {}).get("apply_command", ""):
            return "{} --status-json did not shell-quote a staged next_commands apply command".format(
                PUBLIC_LAUNCH_MANIFEST_TOOL.relative_to(ROOT_DIR)
            )
        if quoted_manifest_path not in spaced_status_json.get("next_commands", {}).get("check_command", ""):
            return "{} --status-json did not shell-quote a staged next_commands check command".format(
                PUBLIC_LAUNCH_MANIFEST_TOOL.relative_to(ROOT_DIR)
            )
        if quoted_manifest_path not in spaced_status_json.get("next_commands", {}).get("template_command", ""):
            return "{} --status-json did not shell-quote a staged next_commands template command".format(
                PUBLIC_LAUNCH_MANIFEST_TOOL.relative_to(ROOT_DIR)
            )
        if quoted_manifest_path not in spaced_status_json.get("next_commands", {}).get("readiness_summary_command", ""):
            return "{} --status-json did not shell-quote a staged next_commands readiness-summary command".format(
                PUBLIC_LAUNCH_MANIFEST_TOOL.relative_to(ROOT_DIR)
            )
        if quoted_manifest_path not in spaced_status_json.get("next_commands", {}).get("network_readiness_summary_command", ""):
            return "{} --status-json did not shell-quote a staged next_commands network readiness-summary command".format(
                PUBLIC_LAUNCH_MANIFEST_TOOL.relative_to(ROOT_DIR)
            )
        if quoted_manifest_path not in spaced_status_json.get("next_commands", {}).get("blocker_type_readiness_summary_command", ""):
            return "{} --status-json did not shell-quote a staged next_commands blocker-type readiness-summary command".format(
                PUBLIC_LAUNCH_MANIFEST_TOOL.relative_to(ROOT_DIR)
            )
        if quoted_manifest_path not in spaced_status_json.get("next_commands", {}).get("blocker_readiness_summary_command", ""):
            return "{} --status-json did not shell-quote a staged next_commands blocker readiness-summary command".format(
                PUBLIC_LAUNCH_MANIFEST_TOOL.relative_to(ROOT_DIR)
            )
        if spaced_status_json.get("next_blocked_field_count") != 11:
            return "{} --status-json did not count staged next blocker fields".format(
                PUBLIC_LAUNCH_MANIFEST_TOOL.relative_to(ROOT_DIR)
            )
        if f"--in-place {quoted_manifest_path}" not in spaced_status_json.get("actions", [{}])[0].get("action", ""):
            return "{} --status-json did not shell-quote a staged manifest path with spaces".format(
                PUBLIC_LAUNCH_MANIFEST_TOOL.relative_to(ROOT_DIR)
            )
        if f"--in-place {quoted_manifest_path}" not in spaced_status_json.get("actions", [{}])[0].get("apply_command", ""):
            return "{} --status-json did not shell-quote a staged action apply command".format(
                PUBLIC_LAUNCH_MANIFEST_TOOL.relative_to(ROOT_DIR)
            )
        if quoted_manifest_path not in spaced_status_json.get("actions", [{}])[0].get("check_command", ""):
            return "{} --status-json did not shell-quote a staged action check command".format(
                PUBLIC_LAUNCH_MANIFEST_TOOL.relative_to(ROOT_DIR)
            )
        if quoted_manifest_path not in spaced_status_json.get("actions", [{}])[0].get("readiness_summary_command", ""):
            return "{} --status-json did not shell-quote a staged action readiness-summary command".format(
                PUBLIC_LAUNCH_MANIFEST_TOOL.relative_to(ROOT_DIR)
            )
        if quoted_manifest_path not in spaced_status_json.get("actions", [{}])[0].get("network_readiness_summary_command", ""):
            return "{} --status-json did not shell-quote a staged action network readiness-summary command".format(
                PUBLIC_LAUNCH_MANIFEST_TOOL.relative_to(ROOT_DIR)
            )
        if quoted_manifest_path not in spaced_status_json.get("actions", [{}])[0].get("blocker_type_readiness_summary_command", ""):
            return "{} --status-json did not shell-quote a staged action blocker-type readiness-summary command".format(
                PUBLIC_LAUNCH_MANIFEST_TOOL.relative_to(ROOT_DIR)
            )
        if quoted_manifest_path not in spaced_status_json.get("actions", [{}])[0].get("blocker_readiness_summary_command", ""):
            return "{} --status-json did not shell-quote a staged action blocker readiness-summary command".format(
                PUBLIC_LAUNCH_MANIFEST_TOOL.relative_to(ROOT_DIR)
            )
        if quoted_manifest_path not in spaced_status_json.get("actions_by_network", {}).get("main", [{}])[0].get("check_command", ""):
            return "{} --status-json did not shell-quote a staged network action check command".format(
                PUBLIC_LAUNCH_MANIFEST_TOOL.relative_to(ROOT_DIR)
            )
        if quoted_manifest_path not in spaced_status_json.get("actions_by_blocker_type", {}).get("litecoin_snapshot", [{}])[0].get("check_command", ""):
            return "{} --status-json did not shell-quote a staged blocker-type action check command".format(
                PUBLIC_LAUNCH_MANIFEST_TOOL.relative_to(ROOT_DIR)
            )
        if spaced_status_json.get("actions", [{}])[0].get("network") != "main":
            return "{} --status-json did not preserve staged action network metadata".format(
                PUBLIC_LAUNCH_MANIFEST_TOOL.relative_to(ROOT_DIR)
            )
        if spaced_status_json.get("actions", [{}])[0].get("fields", [None])[0] != "main.litecoin_snapshot.height":
            return "{} --status-json did not preserve staged action blocked fields".format(
                PUBLIC_LAUNCH_MANIFEST_TOOL.relative_to(ROOT_DIR)
            )

        spaced_check_auxpow_result = subprocess.run(
            [
                sys.executable,
                str(PUBLIC_LAUNCH_MANIFEST_TOOL),
                "--check-auxpow",
                "main",
                "0x5001",
                str(spaced_manifest_path),
            ],
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        if spaced_check_auxpow_result.returncode != 0:
            return "{} --check-auxpow failed for a staged manifest path with spaces: {}".format(
                PUBLIC_LAUNCH_MANIFEST_TOOL.relative_to(ROOT_DIR),
                spaced_check_auxpow_result.stderr.strip()
                or spaced_check_auxpow_result.stdout.strip()
                or "no output",
            )
        if f"--set-auxpow main 0x5001 --in-place {quoted_manifest_path}" not in spaced_check_auxpow_result.stdout:
            return "{} --check-auxpow did not shell-quote a staged apply command".format(
                PUBLIC_LAUNCH_MANIFEST_TOOL.relative_to(ROOT_DIR)
            )
        if f"--readiness-summary {quoted_manifest_path}" not in spaced_check_auxpow_result.stdout:
            return "{} --check-auxpow did not shell-quote a staged readiness-summary command".format(
                PUBLIC_LAUNCH_MANIFEST_TOOL.relative_to(ROOT_DIR)
            )
        if f"--network-readiness-summary main {quoted_manifest_path}" not in spaced_check_auxpow_result.stdout:
            return "{} --check-auxpow did not shell-quote a staged network readiness-summary command".format(
                PUBLIC_LAUNCH_MANIFEST_TOOL.relative_to(ROOT_DIR)
            )
        if f"--blocker-type-readiness-summary auxpow_chain_id {quoted_manifest_path}" not in spaced_check_auxpow_result.stdout:
            return "{} --check-auxpow did not shell-quote a staged blocker-type readiness-summary command".format(
                PUBLIC_LAUNCH_MANIFEST_TOOL.relative_to(ROOT_DIR)
            )

        spaced_check_dns_result = subprocess.run(
            [
                sys.executable,
                str(PUBLIC_LAUNCH_MANIFEST_TOOL),
                "--check-dns-seeds",
                "main",
                "seed1.zkcoin.net,seed2.zkcoin.net",
                str(spaced_manifest_path),
            ],
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        if spaced_check_dns_result.returncode != 0:
            return "{} --check-dns-seeds failed for a staged manifest path with spaces: {}".format(
                PUBLIC_LAUNCH_MANIFEST_TOOL.relative_to(ROOT_DIR),
                spaced_check_dns_result.stderr.strip()
                or spaced_check_dns_result.stdout.strip()
                or "no output",
            )
        if f"--set-dns-seeds main seed1.zkcoin.net,seed2.zkcoin.net --in-place {quoted_manifest_path}" not in spaced_check_dns_result.stdout:
            return "{} --check-dns-seeds did not shell-quote a staged apply command".format(
                PUBLIC_LAUNCH_MANIFEST_TOOL.relative_to(ROOT_DIR)
            )
        if f"--readiness-summary {quoted_manifest_path}" not in spaced_check_dns_result.stdout:
            return "{} --check-dns-seeds did not shell-quote a staged readiness-summary command".format(
                PUBLIC_LAUNCH_MANIFEST_TOOL.relative_to(ROOT_DIR)
            )
        if f"--network-readiness-summary main {quoted_manifest_path}" not in spaced_check_dns_result.stdout:
            return "{} --check-dns-seeds did not shell-quote a staged network readiness-summary command".format(
                PUBLIC_LAUNCH_MANIFEST_TOOL.relative_to(ROOT_DIR)
            )
        if f"--blocker-type-readiness-summary dns_seeds {quoted_manifest_path}" not in spaced_check_dns_result.stdout:
            return "{} --check-dns-seeds did not shell-quote a staged blocker-type readiness-summary command".format(
                PUBLIC_LAUNCH_MANIFEST_TOOL.relative_to(ROOT_DIR)
            )

        spaced_check_identity_result = subprocess.run(
            [
                sys.executable,
                str(PUBLIC_LAUNCH_MANIFEST_TOOL),
                "--check-identity",
                "main",
                "fa,bf,b5,d9",
                "19445",
                "75",
                "76",
                "77",
                "178",
                "04202431",
                "04202432",
                "zk",
                "zkmweb",
                str(spaced_manifest_path),
            ],
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        if spaced_check_identity_result.returncode != 0:
            return "{} --check-identity failed for a staged manifest path with spaces: {}".format(
                PUBLIC_LAUNCH_MANIFEST_TOOL.relative_to(ROOT_DIR),
                spaced_check_identity_result.stderr.strip()
                or spaced_check_identity_result.stdout.strip()
                or "no output",
            )
        expected_identity_apply = (
            "contrib/devtools/zkcoin_public_launch_profile.py --set-identity "
            f"main 250,191,181,217 19445 75 76 77 178 04202431 04202432 zk zkmweb --in-place {quoted_manifest_path}"
        )
        if expected_identity_apply not in spaced_check_identity_result.stdout:
            return "{} --check-identity did not shell-quote a staged apply command".format(
                PUBLIC_LAUNCH_MANIFEST_TOOL.relative_to(ROOT_DIR)
            )
        if f"--readiness-summary {quoted_manifest_path}" not in spaced_check_identity_result.stdout:
            return "{} --check-identity did not shell-quote a staged readiness-summary command".format(
                PUBLIC_LAUNCH_MANIFEST_TOOL.relative_to(ROOT_DIR)
            )
        if f"--network-readiness-summary main {quoted_manifest_path}" not in spaced_check_identity_result.stdout:
            return "{} --check-identity did not shell-quote a staged network readiness-summary command".format(
                PUBLIC_LAUNCH_MANIFEST_TOOL.relative_to(ROOT_DIR)
            )
        if f"--blocker-type-readiness-summary public_network_identity {quoted_manifest_path}" not in spaced_check_identity_result.stdout:
            return "{} --check-identity did not shell-quote a staged blocker-type readiness-summary command".format(
                PUBLIC_LAUNCH_MANIFEST_TOOL.relative_to(ROOT_DIR)
            )

    mixed_action_result = subprocess.run(
        [
            sys.executable,
            str(PUBLIC_LAUNCH_MANIFEST_TOOL),
            "--set-auxpow",
            "main",
            "0x5001",
            "--next-action",
            str(PUBLIC_LAUNCH_MANIFEST),
        ],
        check=False,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    if mixed_action_result.returncode == 0:
        return "{} accepted mixed primary launch-profile actions".format(
            PUBLIC_LAUNCH_MANIFEST_TOOL.relative_to(ROOT_DIR)
        )
    if "use only one primary action at a time: --set-auxpow, --next-action" not in mixed_action_result.stderr:
        return "{} did not explain mixed primary launch-profile action rejection".format(
            PUBLIC_LAUNCH_MANIFEST_TOOL.relative_to(ROOT_DIR)
        )

    mixed_plan_result = subprocess.run(
        [
            sys.executable,
            str(PUBLIC_LAUNCH_MANIFEST_TOOL),
            "--next-action",
            "--action-plan",
            str(PUBLIC_LAUNCH_MANIFEST),
        ],
        check=False,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    if mixed_plan_result.returncode == 0:
        return "{} accepted mixed read-only launch-profile actions".format(
            PUBLIC_LAUNCH_MANIFEST_TOOL.relative_to(ROOT_DIR)
        )
    if "use only one primary action at a time: --next-action, --action-plan" not in mixed_plan_result.stderr:
        return "{} did not explain mixed read-only launch-profile action rejection".format(
            PUBLIC_LAUNCH_MANIFEST_TOOL.relative_to(ROOT_DIR)
        )

    mixed_summary_result = subprocess.run(
        [
            sys.executable,
            str(PUBLIC_LAUNCH_MANIFEST_TOOL),
            "--action-plan",
            "--readiness-summary",
            str(PUBLIC_LAUNCH_MANIFEST),
        ],
        check=False,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    if mixed_summary_result.returncode == 0:
        return "{} accepted mixed action-plan and readiness-summary actions".format(
            PUBLIC_LAUNCH_MANIFEST_TOOL.relative_to(ROOT_DIR)
        )
    if "use only one primary action at a time: --action-plan, --readiness-summary" not in mixed_summary_result.stderr:
        return "{} did not explain mixed readiness-summary action rejection".format(
            PUBLIC_LAUNCH_MANIFEST_TOOL.relative_to(ROOT_DIR)
        )

    mixed_status_result = subprocess.run(
        [
            sys.executable,
            str(PUBLIC_LAUNCH_MANIFEST_TOOL),
            "--action-plan",
            "--status-json",
            str(PUBLIC_LAUNCH_MANIFEST),
        ],
        check=False,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    if mixed_status_result.returncode == 0:
        return "{} accepted mixed text and JSON launch-profile actions".format(
            PUBLIC_LAUNCH_MANIFEST_TOOL.relative_to(ROOT_DIR)
        )
    if "use only one primary action at a time: --action-plan, --status-json" not in mixed_status_result.stderr:
        return "{} did not explain mixed status-json action rejection".format(
            PUBLIC_LAUNCH_MANIFEST_TOOL.relative_to(ROOT_DIR)
        )

    mixed_template_result = subprocess.run(
        [
            sys.executable,
            str(PUBLIC_LAUNCH_MANIFEST_TOOL),
            "--status-json",
            "--snapshot-audit-template",
            "main",
            str(PUBLIC_LAUNCH_MANIFEST),
        ],
        check=False,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    if mixed_template_result.returncode == 0:
        return "{} accepted mixed status-json and snapshot template actions".format(
            PUBLIC_LAUNCH_MANIFEST_TOOL.relative_to(ROOT_DIR)
        )
    if "use only one primary action at a time: --status-json, --snapshot-audit-template" not in mixed_template_result.stderr:
        return "{} did not explain mixed snapshot template action rejection".format(
            PUBLIC_LAUNCH_MANIFEST_TOOL.relative_to(ROOT_DIR)
        )

    action_plan_in_place_result = subprocess.run(
        [
            sys.executable,
            str(PUBLIC_LAUNCH_MANIFEST_TOOL),
            "--action-plan",
            "--in-place",
            str(PUBLIC_LAUNCH_MANIFEST),
        ],
        check=False,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    if action_plan_in_place_result.returncode == 0:
        return "{} --action-plan accepted --in-place".format(
            PUBLIC_LAUNCH_MANIFEST_TOOL.relative_to(ROOT_DIR)
        )
    if "--action-plan does not write the manifest" not in action_plan_in_place_result.stderr:
        return "{} --action-plan did not explain --in-place rejection".format(
            PUBLIC_LAUNCH_MANIFEST_TOOL.relative_to(ROOT_DIR)
        )

    readiness_summary_in_place_result = subprocess.run(
        [
            sys.executable,
            str(PUBLIC_LAUNCH_MANIFEST_TOOL),
            "--readiness-summary",
            "--in-place",
            str(PUBLIC_LAUNCH_MANIFEST),
        ],
        check=False,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    if readiness_summary_in_place_result.returncode == 0:
        return "{} --readiness-summary accepted --in-place".format(
            PUBLIC_LAUNCH_MANIFEST_TOOL.relative_to(ROOT_DIR)
        )
    if "--readiness-summary does not write the manifest" not in readiness_summary_in_place_result.stderr:
        return "{} --readiness-summary did not explain --in-place rejection".format(
            PUBLIC_LAUNCH_MANIFEST_TOOL.relative_to(ROOT_DIR)
        )

    blocker_type_summary_in_place_result = subprocess.run(
        [
            sys.executable,
            str(PUBLIC_LAUNCH_MANIFEST_TOOL),
            "--blocker-type-readiness-summary",
            "litecoin_snapshot",
            "--in-place",
            str(PUBLIC_LAUNCH_MANIFEST),
        ],
        check=False,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    if blocker_type_summary_in_place_result.returncode == 0:
        return "{} --blocker-type-readiness-summary accepted --in-place".format(
            PUBLIC_LAUNCH_MANIFEST_TOOL.relative_to(ROOT_DIR)
        )
    if "--blocker-type-readiness-summary does not write the manifest" not in blocker_type_summary_in_place_result.stderr:
        return "{} --blocker-type-readiness-summary did not explain --in-place rejection".format(
            PUBLIC_LAUNCH_MANIFEST_TOOL.relative_to(ROOT_DIR)
        )

    blocker_summary_in_place_result = subprocess.run(
        [
            sys.executable,
            str(PUBLIC_LAUNCH_MANIFEST_TOOL),
            "--blocker-readiness-summary",
            "main.litecoin_snapshot",
            "--in-place",
            str(PUBLIC_LAUNCH_MANIFEST),
        ],
        check=False,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    if blocker_summary_in_place_result.returncode == 0:
        return "{} --blocker-readiness-summary accepted --in-place".format(
            PUBLIC_LAUNCH_MANIFEST_TOOL.relative_to(ROOT_DIR)
        )
    if "--blocker-readiness-summary does not write the manifest" not in blocker_summary_in_place_result.stderr:
        return "{} --blocker-readiness-summary did not explain --in-place rejection".format(
            PUBLIC_LAUNCH_MANIFEST_TOOL.relative_to(ROOT_DIR)
        )

    status_json_in_place_result = subprocess.run(
        [
            sys.executable,
            str(PUBLIC_LAUNCH_MANIFEST_TOOL),
            "--status-json",
            "--in-place",
            str(PUBLIC_LAUNCH_MANIFEST),
        ],
        check=False,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    if status_json_in_place_result.returncode == 0:
        return "{} --status-json accepted --in-place".format(
            PUBLIC_LAUNCH_MANIFEST_TOOL.relative_to(ROOT_DIR)
        )
    if "--status-json does not write the manifest" not in status_json_in_place_result.stderr:
        return "{} --status-json did not explain --in-place rejection".format(
            PUBLIC_LAUNCH_MANIFEST_TOOL.relative_to(ROOT_DIR)
        )

    snapshot_template_in_place_result = subprocess.run(
        [
            sys.executable,
            str(PUBLIC_LAUNCH_MANIFEST_TOOL),
            "--snapshot-audit-template",
            "main",
            "--in-place",
            str(PUBLIC_LAUNCH_MANIFEST),
        ],
        check=False,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    if snapshot_template_in_place_result.returncode == 0:
        return "{} --snapshot-audit-template accepted --in-place".format(
            PUBLIC_LAUNCH_MANIFEST_TOOL.relative_to(ROOT_DIR)
        )
    if "--snapshot-audit-template does not write the manifest" not in snapshot_template_in_place_result.stderr:
        return "{} --snapshot-audit-template did not explain --in-place rejection".format(
            PUBLIC_LAUNCH_MANIFEST_TOOL.relative_to(ROOT_DIR)
        )

    with tempfile.TemporaryDirectory() as temp_dir:
        def reject_bool_manifest_case(name, mutate, expected_error):
            bool_manifest = json.loads(json.dumps(manifest))
            mutate(bool_manifest)
            bool_manifest_path = Path(temp_dir) / f"{name}.json"
            bool_manifest_path.write_text(json.dumps(bool_manifest), encoding="utf8")
            bool_manifest_result = subprocess.run(
                [
                    sys.executable,
                    str(PUBLIC_LAUNCH_MANIFEST_TOOL),
                    "--allow-blocked",
                    str(bool_manifest_path),
                ],
                check=False,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )
            if bool_manifest_result.returncode == 0:
                return "{} accepted boolean-backed integer field in {}".format(
                    PUBLIC_LAUNCH_MANIFEST_TOOL.relative_to(ROOT_DIR),
                    name,
                )
            if expected_error not in bool_manifest_result.stderr:
                return "{} did not explain boolean integer rejection for {}".format(
                    PUBLIC_LAUNCH_MANIFEST_TOOL.relative_to(ROOT_DIR),
                    name,
                )
            return None

        def remove_blocker(manifest_value, blocker_id):
            manifest_value["blockers"] = [
                blocker
                for blocker in manifest_value.get("blockers", [])
                if not (isinstance(blocker, dict) and blocker.get("id") == blocker_id)
            ]

        bool_manifest_cases = (
            (
                "boolean-manifest-version",
                lambda value: value.update({"version": True}),
                "version: must be 1",
            ),
            (
                "boolean-snapshot-height",
                lambda value: value["networks"]["main"]["litecoin_snapshot"].update({"height": True}),
                "main.litecoin_snapshot.height: must be a positive integer",
            ),
            (
                "boolean-auxpow-start-height",
                lambda value: value["networks"]["main"]["auxpow"].update({"start_height": True}),
                "main.auxpow.start_height: must be 1 for first post-genesis launch block",
            ),
            (
                "boolean-auxpow-chain-id",
                lambda value: (
                    value["networks"]["main"]["auxpow"].update({"chain_id": True}),
                    remove_blocker(value, "main.auxpow_chain_id"),
                ),
                "main.auxpow.chain_id: must be a non-zero AuxPoW-version encodable integer below 0x8000",
            ),
            (
                "boolean-default-port",
                lambda value: value["networks"]["main"]["public_network_identity"].update({"default_port": True}),
                "main.public_network_identity.default_port: must be in the public TCP port range 1025-65535",
            ),
            (
                "boolean-message-start-byte",
                lambda value: value["networks"]["main"]["public_network_identity"].update({"message_start": [True, 191, 181, 217]}),
                "main.public_network_identity.message_start: must be 4 non-Litecoin non-printable magic bytes",
            ),
            (
                "boolean-base58-prefix-byte",
                lambda value: value["networks"]["main"]["public_network_identity"]["base58_prefixes"].update({"pubkey_address": [True]}),
                "main.public_network_identity.base58_prefixes.pubkey_address: must be an array of 1 byte value(s)",
            ),
        )
        for name, mutate, expected_error in bool_manifest_cases:
            bool_manifest_error = reject_bool_manifest_case(name, mutate, expected_error)
            if bool_manifest_error:
                return bool_manifest_error

        def reject_extra_manifest_field_case(name, mutate, expected_error):
            extra_manifest = json.loads(json.dumps(manifest))
            mutate(extra_manifest)
            extra_manifest_path = Path(temp_dir) / f"{name}.json"
            extra_manifest_path.write_text(json.dumps(extra_manifest), encoding="utf8")
            extra_manifest_result = subprocess.run(
                [
                    sys.executable,
                    str(PUBLIC_LAUNCH_MANIFEST_TOOL),
                    "--allow-blocked",
                    str(extra_manifest_path),
                ],
                check=False,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )
            if extra_manifest_result.returncode == 0:
                return "{} accepted unexpected manifest field in {}".format(
                    PUBLIC_LAUNCH_MANIFEST_TOOL.relative_to(ROOT_DIR),
                    name,
                )
            if expected_error not in extra_manifest_result.stderr:
                return "{} did not explain unexpected manifest field rejection for {}".format(
                    PUBLIC_LAUNCH_MANIFEST_TOOL.relative_to(ROOT_DIR),
                    name,
                )
            return None

        extra_manifest_field_cases = (
            (
                "extra-top-level-field",
                lambda value: value.update({"selected_constants": "stale"}),
                "manifest: contains unexpected field(s): selected_constants",
            ),
            (
                "extra-blocker-field",
                lambda value: value["blockers"][0].update({"resolved": False}),
                "blockers[0]: contains unexpected field(s): resolved",
            ),
            (
                "extra-network-field",
                lambda value: value["networks"].update({"regtest": {}}),
                "networks: contains unexpected field(s): regtest",
            ),
            (
                "extra-profile-field",
                lambda value: value["networks"]["main"].update(
                    {"operator_notes": "stale"},
                ),
                "networks.main: contains unexpected field(s): operator_notes",
            ),
            (
                "extra-snapshot-audit-field",
                lambda value: value["networks"]["main"]["litecoin_snapshot"]["audit"].update(
                    {"operator_notes": "stale"},
                ),
                "main.litecoin_snapshot.audit: contains unexpected field(s): operator_notes",
            ),
        )
        for name, mutate, expected_error in extra_manifest_field_cases:
            extra_manifest_error = reject_extra_manifest_field_case(name, mutate, expected_error)
            if extra_manifest_error:
                return extra_manifest_error

        def copied_manifest_with(mutate):
            copied_manifest = json.loads(json.dumps(manifest))
            mutate(copied_manifest)
            return copied_manifest

        def reject_malformed_manifest_case(name, malformed_manifest, expected_error):
            malformed_manifest_path = Path(temp_dir) / f"{name}.json"
            malformed_manifest_path.write_text(json.dumps(malformed_manifest), encoding="utf8")
            malformed_manifest_result = subprocess.run(
                [
                    sys.executable,
                    str(PUBLIC_LAUNCH_MANIFEST_TOOL),
                    "--allow-blocked",
                    str(malformed_manifest_path),
                ],
                check=False,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )
            if malformed_manifest_result.returncode == 0:
                return "{} accepted malformed manifest section in {}".format(
                    PUBLIC_LAUNCH_MANIFEST_TOOL.relative_to(ROOT_DIR),
                    name,
                )
            if "Traceback" in malformed_manifest_result.stderr:
                return "{} emitted a traceback for malformed manifest section in {}".format(
                    PUBLIC_LAUNCH_MANIFEST_TOOL.relative_to(ROOT_DIR),
                    name,
                )
            if expected_error not in malformed_manifest_result.stderr:
                return "{} did not explain malformed manifest section rejection for {}".format(
                    PUBLIC_LAUNCH_MANIFEST_TOOL.relative_to(ROOT_DIR),
                    name,
                )
            return None

        malformed_manifest_cases = (
            (
                "root-array",
                [],
                "manifest: must be an object",
            ),
            (
                "networks-array",
                copied_manifest_with(lambda value: value.update({"networks": []})),
                "networks: must be an object",
            ),
            (
                "profile-array",
                copied_manifest_with(lambda value: value["networks"].update({"main": []})),
                "networks.main: must be an object",
            ),
            (
                "snapshot-array",
                copied_manifest_with(
                    lambda value: value["networks"]["main"].update(
                        {"litecoin_snapshot": []},
                    ),
                ),
                "main.litecoin_snapshot: must be an object",
            ),
            (
                "snapshot-audit-array",
                copied_manifest_with(
                    lambda value: value["networks"]["main"]["litecoin_snapshot"].update(
                        {"audit": []},
                    ),
                ),
                "main.litecoin_snapshot.audit: must be an object",
            ),
            (
                "auxpow-array",
                copied_manifest_with(lambda value: value["networks"]["main"].update({"auxpow": []})),
                "main.auxpow: must be an object",
            ),
            (
                "identity-array",
                copied_manifest_with(
                    lambda value: value["networks"]["main"].update(
                        {"public_network_identity": []},
                    ),
                ),
                "main.public_network_identity: must be an object",
            ),
            (
                "base58-array",
                copied_manifest_with(
                    lambda value: value["networks"]["main"]["public_network_identity"].update(
                        {"base58_prefixes": []},
                    ),
                ),
                "main.public_network_identity.base58_prefixes: must be an object",
            ),
        )
        for name, malformed_manifest, expected_error in malformed_manifest_cases:
            malformed_manifest_error = reject_malformed_manifest_case(
                name,
                malformed_manifest,
                expected_error,
            )
            if malformed_manifest_error:
                return malformed_manifest_error

        duplicate_field_manifest_path = Path(temp_dir) / "duplicate-field-manifest.json"
        duplicate_field_manifest_path.write_text(
            json.dumps(manifest).replace(
                '"status": "blocked"',
                '"status": "blocked", "status": "blocked"',
                1,
            ),
            encoding="utf8",
        )
        duplicate_field_manifest_result = subprocess.run(
            [
                sys.executable,
                str(PUBLIC_LAUNCH_MANIFEST_TOOL),
                "--allow-blocked",
                str(duplicate_field_manifest_path),
            ],
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        if duplicate_field_manifest_result.returncode == 0:
            return "{} accepted a manifest with duplicate JSON fields".format(
                PUBLIC_LAUNCH_MANIFEST_TOOL.relative_to(ROOT_DIR)
            )
        if "contains duplicate field: status" not in duplicate_field_manifest_result.stderr:
            return "{} did not explain duplicate manifest field rejection".format(
                PUBLIC_LAUNCH_MANIFEST_TOOL.relative_to(ROOT_DIR)
            )

        manifest_tool_spec = importlib.util.spec_from_file_location(
            "zkcoin_public_launch_profile_tool",
            PUBLIC_LAUNCH_MANIFEST_TOOL,
        )
        manifest_tool = importlib.util.module_from_spec(manifest_tool_spec)
        manifest_tool_spec.loader.exec_module(manifest_tool)

        invalid_utf8_manifest_path = Path(temp_dir) / "invalid-utf8-manifest.json"
        invalid_utf8_manifest_path.write_bytes(b'{"version": 1, "status": "' + bytes([0xff]) + b'"}')
        invalid_utf8_manifest_result = subprocess.run(
            [
                sys.executable,
                str(PUBLIC_LAUNCH_MANIFEST_TOOL),
                "--allow-blocked",
                str(invalid_utf8_manifest_path),
            ],
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        if invalid_utf8_manifest_result.returncode == 0:
            return "{} accepted an invalid UTF-8 manifest".format(
                PUBLIC_LAUNCH_MANIFEST_TOOL.relative_to(ROOT_DIR)
            )
        if "is not valid UTF-8" not in invalid_utf8_manifest_result.stderr:
            return "{} did not explain invalid UTF-8 manifest rejection".format(
                PUBLIC_LAUNCH_MANIFEST_TOOL.relative_to(ROOT_DIR)
            )
        if "Traceback" in invalid_utf8_manifest_result.stderr:
            return "{} leaked a traceback for invalid UTF-8 manifest input".format(
                PUBLIC_LAUNCH_MANIFEST_TOOL.relative_to(ROOT_DIR)
            )

        symlink_read_manifest_path = Path(temp_dir) / "symlink-read-manifest.json"
        symlink_read_manifest_path.symlink_to(PUBLIC_LAUNCH_MANIFEST)
        symlink_read_manifest_result = subprocess.run(
            [
                sys.executable,
                str(PUBLIC_LAUNCH_MANIFEST_TOOL),
                "--allow-blocked",
                str(symlink_read_manifest_path),
            ],
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        if symlink_read_manifest_result.returncode == 0:
            return "{} accepted a symlinked launch manifest for reading".format(
                PUBLIC_LAUNCH_MANIFEST_TOOL.relative_to(ROOT_DIR)
            )
        if "manifest path must not be a symlink" not in symlink_read_manifest_result.stderr:
            return "{} did not explain symlinked manifest read rejection".format(
                PUBLIC_LAUNCH_MANIFEST_TOOL.relative_to(ROOT_DIR)
            )

        parent_symlink_manifest_target = Path(temp_dir) / "manifest-read-parent-target"
        parent_symlink_manifest_target.mkdir()
        parent_symlink_manifest_file = parent_symlink_manifest_target / "manifest.json"
        parent_symlink_manifest_file.write_text(json.dumps(manifest), encoding="utf8")
        parent_symlink_manifest_parent = Path(temp_dir) / "manifest-read-parent-link"
        parent_symlink_manifest_parent.symlink_to(parent_symlink_manifest_target, target_is_directory=True)
        parent_symlink_manifest_result = subprocess.run(
            [
                sys.executable,
                str(PUBLIC_LAUNCH_MANIFEST_TOOL),
                "--allow-blocked",
                str(parent_symlink_manifest_parent / parent_symlink_manifest_file.name),
            ],
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        if parent_symlink_manifest_result.returncode == 0:
            return "{} accepted a launch manifest through a symlinked parent directory".format(
                PUBLIC_LAUNCH_MANIFEST_TOOL.relative_to(ROOT_DIR)
            )
        if "manifest parent directory must not be a symlink" not in parent_symlink_manifest_result.stderr:
            return "{} did not explain symlinked manifest parent read rejection".format(
                PUBLIC_LAUNCH_MANIFEST_TOOL.relative_to(ROOT_DIR)
            )

        oversized_manifest_path = Path(temp_dir) / "oversized-manifest.json"
        oversized_manifest_path.write_bytes(b" " * (manifest_tool.LAUNCH_MANIFEST_MAX_BYTES + 1))
        oversized_manifest_result = subprocess.run(
            [
                sys.executable,
                str(PUBLIC_LAUNCH_MANIFEST_TOOL),
                "--allow-blocked",
                str(oversized_manifest_path),
            ],
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        if oversized_manifest_result.returncode == 0:
            return "{} accepted an oversized launch manifest".format(
                PUBLIC_LAUNCH_MANIFEST_TOOL.relative_to(ROOT_DIR)
            )
        if "launch manifest must not exceed 262144 bytes" not in oversized_manifest_result.stderr:
            return "{} did not explain oversized manifest rejection".format(
                PUBLIC_LAUNCH_MANIFEST_TOOL.relative_to(ROOT_DIR)
            )

        changed_manifest_path = Path(temp_dir) / "changed-read-manifest.json"
        changed_manifest_path.write_text(json.dumps(manifest), encoding="utf8")
        changed_manifest_fd, changed_manifest_stat = manifest_tool.open_regular_file_no_symlink(
            changed_manifest_path,
            symlink_error="manifest path must not be a symlink",
            missing_error="cannot read manifest",
            not_regular_error="manifest path must be a regular file",
            open_error="cannot read manifest",
        )
        try:
            changed_manifest_path.write_text("{}", encoding="utf8")
            try:
                manifest_tool.require_regular_file_stable(
                    changed_manifest_path,
                    changed_manifest_stat,
                    changed_manifest_fd,
                    "manifest changed during read",
                )
            except ValueError as exc:
                if "manifest changed during read" not in str(exc):
                    return "{} reported the wrong changed-manifest read error".format(
                        PUBLIC_LAUNCH_MANIFEST_TOOL.relative_to(ROOT_DIR)
                    )
            else:
                return "{} accepted a changed manifest path after opening".format(
                    PUBLIC_LAUNCH_MANIFEST_TOOL.relative_to(ROOT_DIR)
                )
        finally:
            os.close(changed_manifest_fd)

        snapshot_artifact_path = Path(temp_dir) / "update-ltc-block-x.dat"
        snapshot_artifact = b"snapshot"
        snapshot_artifact_path.write_bytes(snapshot_artifact)
        update_audit_path = Path(temp_dir) / "update-snapshot-audit.json"
        update_audit_path.write_text(
            json.dumps(
                {
                    "height": 777,
                    "block_hash": "55" * 32,
                    "import_hash": "66" * 32,
                    "snapshot_hash": "77" * 32,
                    "coins": 4,
                    "base_nchaintx": 11,
                    "source_chain": "main",
                    "snapshot_file_size": len(snapshot_artifact),
                    "snapshot_file_sha256": hashlib.sha256(snapshot_artifact).hexdigest(),
                    "snapshot_file": str(snapshot_artifact_path),
                    "total_amount": "50.00000000",
                },
            ),
            encoding="utf8",
        )

        def reject_malformed_update_case(name, malformed_manifest, update_args, expected_error):
            malformed_update_path = Path(temp_dir) / f"{name}.json"
            malformed_update_path.write_text(json.dumps(malformed_manifest), encoding="utf8")
            malformed_update_result = subprocess.run(
                [
                    sys.executable,
                    str(PUBLIC_LAUNCH_MANIFEST_TOOL),
                    *update_args,
                    str(malformed_update_path),
                ],
                check=False,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )
            if malformed_update_result.returncode == 0:
                return "{} update command accepted malformed manifest section in {}".format(
                    PUBLIC_LAUNCH_MANIFEST_TOOL.relative_to(ROOT_DIR),
                    name,
                )
            if "Traceback" in malformed_update_result.stderr:
                return "{} update command emitted a traceback for malformed manifest section in {}".format(
                    PUBLIC_LAUNCH_MANIFEST_TOOL.relative_to(ROOT_DIR),
                    name,
                )
            if expected_error not in malformed_update_result.stderr:
                return "{} update command did not explain malformed manifest section rejection for {}".format(
                    PUBLIC_LAUNCH_MANIFEST_TOOL.relative_to(ROOT_DIR),
                    name,
                )
            return None

        malformed_update_cases = (
            (
                "update-root-array",
                [],
                ("--set-auxpow", "main", "0x5001"),
                "manifest must be an object",
            ),
            (
                "update-networks-array",
                copied_manifest_with(lambda value: value.update({"networks": []})),
                ("--set-auxpow", "main", "0x5001"),
                "networks must be an object",
            ),
            (
                "update-profile-array",
                copied_manifest_with(lambda value: value["networks"].update({"main": []})),
                ("--set-auxpow", "main", "0x5001"),
                "networks.main must be an object",
            ),
            (
                "update-snapshot-audit-networks-array",
                copied_manifest_with(lambda value: value.update({"networks": []})),
                ("--set-snapshot-audit", "main", str(update_audit_path)),
                "networks must be an object",
            ),
            (
                "update-dns-identity-array",
                copied_manifest_with(
                    lambda value: value["networks"]["main"].update(
                        {"public_network_identity": []},
                    ),
                ),
                ("--set-dns-seeds", "main", "seed1.zkcoin.net"),
                "main.public_network_identity must be an object",
            ),
            (
                "update-identity-array",
                copied_manifest_with(
                    lambda value: value["networks"]["main"].update(
                        {"public_network_identity": []},
                    ),
                ),
                (
                    "--set-identity",
                    "main",
                    "fa,bf,b5,d9",
                    "19445",
                    "75",
                    "76",
                    "77",
                    "178",
                    "04202431",
                    "04202432",
                    "zk",
                    "zkmweb",
                ),
                "main.public_network_identity must be an object",
            ),
            (
                "update-blockers-object",
                copied_manifest_with(lambda value: value.update({"blockers": {}})),
                ("--set-auxpow", "main", "0x5001"),
                "blockers must be an array",
            ),
        )
        for name, malformed_manifest, update_args, expected_error in malformed_update_cases:
            malformed_update_error = reject_malformed_update_case(
                name,
                malformed_manifest,
                update_args,
                expected_error,
            )
            if malformed_update_error:
                return malformed_update_error

        def reject_unsafe_in_place_case(name, manifest_path, update_args, expected_error):
            unsafe_in_place_result = subprocess.run(
                [
                    sys.executable,
                    str(PUBLIC_LAUNCH_MANIFEST_TOOL),
                    *update_args,
                    "--in-place",
                    str(manifest_path),
                ],
                check=False,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )
            if unsafe_in_place_result.returncode == 0:
                return "{} --in-place accepted unsafe manifest path in {}".format(
                    PUBLIC_LAUNCH_MANIFEST_TOOL.relative_to(ROOT_DIR),
                    name,
                )
            if "Traceback" in unsafe_in_place_result.stderr:
                return "{} --in-place emitted a traceback for unsafe manifest path in {}".format(
                    PUBLIC_LAUNCH_MANIFEST_TOOL.relative_to(ROOT_DIR),
                    name,
                )
            if expected_error not in unsafe_in_place_result.stderr:
                return "{} --in-place did not explain unsafe manifest path rejection for {}".format(
                    PUBLIC_LAUNCH_MANIFEST_TOOL.relative_to(ROOT_DIR),
                    name,
                )
            return None

        symlink_target_path = Path(temp_dir) / "symlink-target-manifest.json"
        symlink_target_text = json.dumps(manifest)
        symlink_target_path.write_text(symlink_target_text, encoding="utf8")
        symlink_manifest_path = Path(temp_dir) / "symlink-manifest.json"
        symlink_manifest_path.symlink_to(symlink_target_path)
        symlink_manifest_error = reject_unsafe_in_place_case(
            "symlink-manifest",
            symlink_manifest_path,
            ("--set-auxpow", "main", "0x5001"),
            "manifest path must not be a symlink",
        )
        if symlink_manifest_error:
            return symlink_manifest_error
        if symlink_target_path.read_text(encoding="utf8") != symlink_target_text:
            return "{} --in-place modified a symlinked manifest target".format(
                PUBLIC_LAUNCH_MANIFEST_TOOL.relative_to(ROOT_DIR)
            )

        parent_symlink_target = Path(temp_dir) / "parent-symlink-target"
        parent_symlink_target.mkdir()
        parent_symlink_manifest_text = json.dumps(manifest)
        parent_symlink_target_manifest = parent_symlink_target / "parent-symlink-manifest.json"
        parent_symlink_target_manifest.write_text(parent_symlink_manifest_text, encoding="utf8")
        parent_symlink_path = Path(temp_dir) / "manifest-parent-link"
        parent_symlink_path.symlink_to(parent_symlink_target, target_is_directory=True)
        parent_symlink_error = reject_unsafe_in_place_case(
            "symlink-parent",
            parent_symlink_path / parent_symlink_target_manifest.name,
            ("--set-auxpow", "main", "0x5001"),
            "manifest parent directory must not be a symlink",
        )
        if parent_symlink_error:
            return parent_symlink_error
        if parent_symlink_target_manifest.read_text(encoding="utf8") != parent_symlink_manifest_text:
            return "{} --in-place modified a manifest through a symlinked parent directory".format(
                PUBLIC_LAUNCH_MANIFEST_TOOL.relative_to(ROOT_DIR)
            )
        parent_symlink_temp = parent_symlink_target_manifest.with_name(parent_symlink_target_manifest.name + ".tmp")
        if parent_symlink_temp.exists() or parent_symlink_temp.is_symlink():
            return "{} --in-place left a temp file through a symlinked parent directory".format(
                PUBLIC_LAUNCH_MANIFEST_TOOL.relative_to(ROOT_DIR)
            )

        tmp_symlink_manifest_path = Path(temp_dir) / "tmp-symlink-manifest.json"
        tmp_symlink_manifest_text = json.dumps(manifest)
        tmp_symlink_manifest_path.write_text(tmp_symlink_manifest_text, encoding="utf8")
        tmp_symlink_target_path = Path(temp_dir) / "tmp-symlink-target.json"
        tmp_symlink_target_text = "do-not-write"
        tmp_symlink_target_path.write_text(tmp_symlink_target_text, encoding="utf8")
        tmp_symlink_path = tmp_symlink_manifest_path.with_name(tmp_symlink_manifest_path.name + ".tmp")
        tmp_symlink_path.symlink_to(tmp_symlink_target_path)
        tmp_symlink_error = reject_unsafe_in_place_case(
            "preexisting-temp-symlink",
            tmp_symlink_manifest_path,
            ("--set-auxpow", "main", "0x5001"),
            "manifest temp path already exists",
        )
        if tmp_symlink_error:
            return tmp_symlink_error
        if tmp_symlink_target_path.read_text(encoding="utf8") != tmp_symlink_target_text:
            return "{} --in-place wrote through a pre-existing temp symlink".format(
                PUBLIC_LAUNCH_MANIFEST_TOOL.relative_to(ROOT_DIR)
            )
        if tmp_symlink_manifest_path.read_text(encoding="utf8") != tmp_symlink_manifest_text:
            return "{} --in-place modified a manifest after temp-symlink rejection".format(
                PUBLIC_LAUNCH_MANIFEST_TOOL.relative_to(ROOT_DIR)
            )

        tmp_file_manifest_path = Path(temp_dir) / "tmp-file-manifest.json"
        tmp_file_manifest_text = json.dumps(manifest)
        tmp_file_manifest_path.write_text(tmp_file_manifest_text, encoding="utf8")
        tmp_file_path = tmp_file_manifest_path.with_name(tmp_file_manifest_path.name + ".tmp")
        tmp_file_text = "stale"
        tmp_file_path.write_text(tmp_file_text, encoding="utf8")
        tmp_file_error = reject_unsafe_in_place_case(
            "preexisting-temp-file",
            tmp_file_manifest_path,
            ("--set-auxpow", "main", "0x5001"),
            "manifest temp path already exists",
        )
        if tmp_file_error:
            return tmp_file_error
        if tmp_file_path.read_text(encoding="utf8") != tmp_file_text:
            return "{} --in-place modified a pre-existing manifest temp file".format(
                PUBLIC_LAUNCH_MANIFEST_TOOL.relative_to(ROOT_DIR)
            )
        if tmp_file_manifest_path.read_text(encoding="utf8") != tmp_file_manifest_text:
            return "{} --in-place modified a manifest after temp-file rejection".format(
                PUBLIC_LAUNCH_MANIFEST_TOOL.relative_to(ROOT_DIR)
            )

        race_parent = Path(temp_dir) / "race-parent"
        race_parent.mkdir()
        race_manifest_path = race_parent / "race-manifest.json"
        race_manifest_path.write_text(json.dumps(manifest), encoding="utf8")
        race_original_parent = Path(temp_dir) / "race-parent-original"
        race_symlink_target = Path(temp_dir) / "race-parent-target"
        race_symlink_target.mkdir()
        race_symlink_target_manifest = race_symlink_target / race_manifest_path.name
        race_symlink_target_text = "do-not-write-through-swapped-parent"
        race_symlink_target_manifest.write_text(race_symlink_target_text, encoding="utf8")
        race_update_manifest = {
            "written_through": "opened-parent-directory-fd",
        }
        real_open_manifest_parent_directory = manifest_tool.open_manifest_parent_directory

        def swap_manifest_parent_after_open(path):
            parent_fd = real_open_manifest_parent_directory(path)
            race_parent.rename(race_original_parent)
            race_parent.symlink_to(race_symlink_target, target_is_directory=True)
            return parent_fd

        manifest_tool.open_manifest_parent_directory = swap_manifest_parent_after_open
        try:
            try:
                manifest_tool.write_manifest(race_manifest_path, race_update_manifest)
            except ValueError as exc:
                return "{} write_manifest failed after opening a direct parent directory: {}".format(
                    PUBLIC_LAUNCH_MANIFEST_TOOL.relative_to(ROOT_DIR),
                    exc,
                )
        finally:
            manifest_tool.open_manifest_parent_directory = real_open_manifest_parent_directory
        if json.loads((race_original_parent / race_manifest_path.name).read_text(encoding="utf8")) != race_update_manifest:
            return "{} write_manifest did not update the originally opened parent directory".format(
                PUBLIC_LAUNCH_MANIFEST_TOOL.relative_to(ROOT_DIR)
            )
        if race_symlink_target_manifest.read_text(encoding="utf8") != race_symlink_target_text:
            return "{} write_manifest followed a swapped manifest parent symlink".format(
                PUBLIC_LAUNCH_MANIFEST_TOOL.relative_to(ROOT_DIR)
            )
        if (race_symlink_target / (race_manifest_path.name + ".tmp")).exists():
            return "{} write_manifest left a temp file through a swapped manifest parent symlink".format(
                PUBLIC_LAUNCH_MANIFEST_TOOL.relative_to(ROOT_DIR)
            )

        stale_blocker_manifest = json.loads(json.dumps(manifest))
        stale_blocker_manifest["networks"]["main"]["litecoin_snapshot"].update(
            {
                "height": 321,
                "block_hash": "11" * 32,
                "import_hash": "22" * 32,
                "audit": {
                    "snapshot_hash": "33" * 32,
                    "coins": 4,
                    "base_nchaintx": 11,
                    "source_chain": "main",
                    "snapshot_file_size": 8,
                    "snapshot_file_sha256": "88" * 32,
                    "snapshot_file": "/srv/snapshots/ltc-block-x.dat",
                    "total_amount": "50.00000000",
                },
            }
        )
        stale_blocker_path = Path(temp_dir) / "stale-blocker.json"
        stale_blocker_path.write_text(json.dumps(stale_blocker_manifest), encoding="utf8")
        stale_blocker_result = subprocess.run(
            [
                sys.executable,
                str(PUBLIC_LAUNCH_MANIFEST_TOOL),
                "--allow-blocked",
                str(stale_blocker_path),
            ],
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        if stale_blocker_result.returncode == 0:
            return "{} accepted a resolved stale blocker id".format(
                PUBLIC_LAUNCH_MANIFEST_TOOL.relative_to(ROOT_DIR)
            )
        if "contains resolved or unknown blocker ids: main.litecoin_snapshot" not in stale_blocker_result.stderr:
            return "{} did not report the resolved stale blocker id".format(
                PUBLIC_LAUNCH_MANIFEST_TOOL.relative_to(ROOT_DIR)
            )

        partial_audit_manifest = json.loads(json.dumps(manifest))
        partial_audit_manifest["networks"]["main"]["litecoin_snapshot"].update(
            {
                "height": 321,
                "block_hash": "11" * 32,
                "import_hash": "22" * 32,
                "audit": {
                    "snapshot_hash": "33" * 32,
                    "coins": 4,
                    "base_nchaintx": 11,
                    "source_chain": None,
                    "snapshot_file_size": None,
                    "snapshot_file_sha256": None,
                    "snapshot_file": "/srv/snapshots/ltc-block-x.dat",
                    "total_amount": "50.00000000",
                },
            }
        )
        partial_audit_path = Path(temp_dir) / "partial-audit.json"
        partial_audit_path.write_text(json.dumps(partial_audit_manifest), encoding="utf8")
        partial_audit_result = subprocess.run(
            [
                sys.executable,
                str(PUBLIC_LAUNCH_MANIFEST_TOOL),
                "--allow-blocked",
                str(partial_audit_path),
            ],
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        if partial_audit_result.returncode != 0:
            return "{} treated a partial snapshot audit blocker as stale: {}".format(
                PUBLIC_LAUNCH_MANIFEST_TOOL.relative_to(ROOT_DIR),
                partial_audit_result.stderr.strip() or partial_audit_result.stdout.strip() or "no output",
            )
        partial_audit_next_result = subprocess.run(
            [
                sys.executable,
                str(PUBLIC_LAUNCH_MANIFEST_TOOL),
                "--next-action",
                str(partial_audit_path),
            ],
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        if partial_audit_next_result.returncode != 0:
            return "{} --next-action failed for partial snapshot audit manifest: {}".format(
                PUBLIC_LAUNCH_MANIFEST_TOOL.relative_to(ROOT_DIR),
                partial_audit_next_result.stderr.strip() or partial_audit_next_result.stdout.strip() or "no output",
            )
        if "next blocker: main.litecoin_snapshot" not in partial_audit_next_result.stdout:
            return "{} --next-action skipped a partial snapshot audit blocker".format(
                PUBLIC_LAUNCH_MANIFEST_TOOL.relative_to(ROOT_DIR)
            )

        unknown_blocker_manifest = json.loads(json.dumps(manifest))
        unknown_blocker_manifest["blockers"].append(
            {
                "id": "main.untracked_launch_blocker",
                "description": "This should not be accepted by the public launch manifest.",
            }
        )
        unknown_blocker_path = Path(temp_dir) / "unknown-blocker.json"
        unknown_blocker_path.write_text(json.dumps(unknown_blocker_manifest), encoding="utf8")
        unknown_blocker_result = subprocess.run(
            [
                sys.executable,
                str(PUBLIC_LAUNCH_MANIFEST_TOOL),
                "--allow-blocked",
                str(unknown_blocker_path),
            ],
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        if unknown_blocker_result.returncode == 0:
            return "{} accepted an unknown blocker id".format(
                PUBLIC_LAUNCH_MANIFEST_TOOL.relative_to(ROOT_DIR)
            )
        if "blockers[8].id: unknown blocker id" not in unknown_blocker_result.stderr:
            return "{} did not report the unknown blocker id".format(
                PUBLIC_LAUNCH_MANIFEST_TOOL.relative_to(ROOT_DIR)
            )

        duplicate_blocker_manifest = json.loads(json.dumps(manifest))
        duplicate_blocker_manifest["blockers"].append(dict(duplicate_blocker_manifest["blockers"][0]))
        duplicate_blocker_path = Path(temp_dir) / "duplicate-blocker.json"
        duplicate_blocker_path.write_text(json.dumps(duplicate_blocker_manifest), encoding="utf8")
        duplicate_blocker_result = subprocess.run(
            [
                sys.executable,
                str(PUBLIC_LAUNCH_MANIFEST_TOOL),
                "--allow-blocked",
                str(duplicate_blocker_path),
            ],
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        if duplicate_blocker_result.returncode == 0:
            return "{} accepted a duplicate blocker id".format(
                PUBLIC_LAUNCH_MANIFEST_TOOL.relative_to(ROOT_DIR)
            )
        if "blockers[8].id: must be unique" not in duplicate_blocker_result.stderr:
            return "{} did not report the duplicate blocker id".format(
                PUBLIC_LAUNCH_MANIFEST_TOOL.relative_to(ROOT_DIR)
            )

        missing_audit_manifest = json.loads(json.dumps(manifest))
        missing_audit_manifest["networks"]["main"]["litecoin_snapshot"] = {
            "height": 321,
            "block_hash": "11" * 32,
            "import_hash": "22" * 32,
        }
        missing_audit_manifest["blockers"] = [
            blocker
            for blocker in missing_audit_manifest["blockers"]
            if blocker.get("id") != "main.litecoin_snapshot"
        ]
        missing_audit_path = Path(temp_dir) / "missing-audit.json"
        missing_audit_path.write_text(json.dumps(missing_audit_manifest), encoding="utf8")
        missing_audit_result = subprocess.run(
            [
                sys.executable,
                str(PUBLIC_LAUNCH_MANIFEST_TOOL),
                "--allow-blocked",
                str(missing_audit_path),
            ],
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        if missing_audit_result.returncode == 0:
            return "{} accepted resolved snapshot constants without audit metadata".format(
                PUBLIC_LAUNCH_MANIFEST_TOOL.relative_to(ROOT_DIR)
            )
        if "main.litecoin_snapshot.audit: must be an object" not in missing_audit_result.stderr:
            return "{} did not report missing snapshot audit metadata".format(
                PUBLIC_LAUNCH_MANIFEST_TOOL.relative_to(ROOT_DIR)
            )

    manual_snapshot_result = subprocess.run(
        [
            sys.executable,
            str(PUBLIC_LAUNCH_MANIFEST_TOOL),
            "--set-snapshot",
            "main",
            "321",
            "11" * 32,
            "22" * 32,
            str(PUBLIC_LAUNCH_MANIFEST),
        ],
        check=False,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    if manual_snapshot_result.returncode == 0:
        return "{} --set-snapshot accepted manual public snapshot constants".format(
            PUBLIC_LAUNCH_MANIFEST_TOOL.relative_to(ROOT_DIR),
        )
    if "manual snapshot constants are not accepted" not in manual_snapshot_result.stderr:
        return "{} --set-snapshot did not explain manual snapshot rejection".format(
            PUBLIC_LAUNCH_MANIFEST_TOOL.relative_to(ROOT_DIR)
        )

    with tempfile.TemporaryDirectory() as temp_dir:
        snapshot_artifact_path = Path(temp_dir) / "ltc-block-x.dat"
        snapshot_artifact = b"snapshot"
        snapshot_artifact_path.write_bytes(snapshot_artifact)
        snapshot_artifact_sha256 = hashlib.sha256(snapshot_artifact).hexdigest()

        audit_path = Path(temp_dir) / "snapshot-audit.json"
        audit = {
            "height": 777,
            "block_hash": "55" * 32,
            "import_hash": "66" * 32,
            "snapshot_hash": "77" * 32,
            "coins": 4,
            "base_nchaintx": 11,
            "source_chain": "main",
            "snapshot_file_size": len(snapshot_artifact),
            "snapshot_file_sha256": snapshot_artifact_sha256,
            "snapshot_file": str(snapshot_artifact_path),
            "total_amount": "50.00000000",
        }
        audit_path.write_text(json.dumps(audit), encoding="utf8")
        audit_result = subprocess.run(
            [
                sys.executable,
                str(PUBLIC_LAUNCH_MANIFEST_TOOL),
                "--set-snapshot-audit",
                "main",
                str(audit_path),
                str(PUBLIC_LAUNCH_MANIFEST),
            ],
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        if audit_result.returncode != 0:
            return "{} --set-snapshot-audit failed: {}".format(
                PUBLIC_LAUNCH_MANIFEST_TOOL.relative_to(ROOT_DIR),
                audit_result.stderr.strip() or audit_result.stdout.strip() or "no output",
            )
        try:
            audit_manifest = json.loads(audit_result.stdout)
        except json.JSONDecodeError as exc:
            return "{} --set-snapshot-audit did not emit JSON: {}".format(
                PUBLIC_LAUNCH_MANIFEST_TOOL.relative_to(ROOT_DIR),
                exc,
            )
        audit_snapshot = audit_manifest["networks"]["main"]["litecoin_snapshot"]
        if audit_snapshot != {
            "height": 777,
            "block_hash": "55" * 32,
            "import_hash": "66" * 32,
            "audit": {
                "snapshot_hash": "77" * 32,
                "coins": 4,
                "base_nchaintx": 11,
                "source_chain": "main",
                "snapshot_file_size": len(snapshot_artifact),
                "snapshot_file_sha256": snapshot_artifact_sha256,
                "snapshot_file": str(snapshot_artifact_path),
                "total_amount": "50.00000000",
            },
        }:
            return "{} --set-snapshot-audit did not update main snapshot fields".format(
                PUBLIC_LAUNCH_MANIFEST_TOOL.relative_to(ROOT_DIR)
            )
        audit_blockers = {
            blocker.get("id")
            for blocker in audit_manifest.get("blockers", [])
            if isinstance(blocker, dict)
        }
        if "main.litecoin_snapshot" in audit_blockers:
            return "{} --set-snapshot-audit did not remove the resolved main snapshot blocker".format(
                PUBLIC_LAUNCH_MANIFEST_TOOL.relative_to(ROOT_DIR)
            )
        if "main.auxpow_chain_id" not in audit_blockers:
            return "{} --set-snapshot-audit removed unrelated blockers".format(
                PUBLIC_LAUNCH_MANIFEST_TOOL.relative_to(ROOT_DIR)
            )

        audit_manifest_path = Path(temp_dir) / "snapshot-resolved-manifest.json"
        audit_manifest_path.write_text(json.dumps(audit_manifest), encoding="utf8")
        audit_next_action_result = subprocess.run(
            [
                sys.executable,
                str(PUBLIC_LAUNCH_MANIFEST_TOOL),
                "--next-action",
                str(audit_manifest_path),
            ],
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        if audit_next_action_result.returncode != 0:
            return "{} --next-action failed after resolving the snapshot blocker: {}".format(
                PUBLIC_LAUNCH_MANIFEST_TOOL.relative_to(ROOT_DIR),
                audit_next_action_result.stderr.strip()
                or audit_next_action_result.stdout.strip()
                or "no output",
            )
        if "next blocker: main.auxpow_chain_id" not in audit_next_action_result.stdout:
            return "{} --next-action did not advance to the AuxPoW blocker after snapshot resolution".format(
                PUBLIC_LAUNCH_MANIFEST_TOOL.relative_to(ROOT_DIR)
            )
        if "--check-auxpow main <chain_id>" not in audit_next_action_result.stdout:
            return "{} --next-action did not print the AuxPoW candidate check command".format(
                PUBLIC_LAUNCH_MANIFEST_TOOL.relative_to(ROOT_DIR)
            )
        if "--set-auxpow main <chain_id>" not in audit_next_action_result.stdout:
            return "{} --next-action did not print the AuxPoW update command".format(
                PUBLIC_LAUNCH_MANIFEST_TOOL.relative_to(ROOT_DIR)
            )
        if "  - check command: contrib/devtools/zkcoin_public_launch_profile.py --check-auxpow main <chain_id>" not in audit_next_action_result.stdout:
            return "{} --next-action did not print a copyable AuxPoW check command line".format(
                PUBLIC_LAUNCH_MANIFEST_TOOL.relative_to(ROOT_DIR)
            )
        if "  - apply command: contrib/devtools/zkcoin_public_launch_profile.py --set-auxpow main <chain_id>" not in audit_next_action_result.stdout:
            return "{} --next-action did not print a copyable AuxPoW apply command line".format(
                PUBLIC_LAUNCH_MANIFEST_TOOL.relative_to(ROOT_DIR)
            )
        if "  - template command:" in audit_next_action_result.stdout:
            return "{} --next-action printed a template command for the AuxPoW blocker".format(
                PUBLIC_LAUNCH_MANIFEST_TOOL.relative_to(ROOT_DIR)
            )

        check_audit_result = subprocess.run(
            [
                sys.executable,
                str(PUBLIC_LAUNCH_MANIFEST_TOOL),
                "--check-snapshot-audit",
                "main",
                str(audit_path),
                str(PUBLIC_LAUNCH_MANIFEST),
            ],
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        if check_audit_result.returncode != 0:
            return "{} --check-snapshot-audit failed: {}".format(
                PUBLIC_LAUNCH_MANIFEST_TOOL.relative_to(ROOT_DIR),
                check_audit_result.stderr.strip() or check_audit_result.stdout.strip() or "no output",
            )
        for expected in (
            "Snapshot audit verified for main.",
            "height: 777",
            f"snapshot file SHA-256: {snapshot_artifact_sha256}",
            "total amount: 50.00000000",
            "apply command: contrib/devtools/zkcoin_public_launch_profile.py "
            f"--set-snapshot-audit main {shlex.quote(str(audit_path))} "
            "--in-place contrib/devtools/zkcoin_public_launch_profile_manifest.json",
            "remaining blockers after applying audit: 7",
            "remaining blockers on main after applying audit: 3",
            "remaining blocked fields after applying audit: 35",
            "remaining blocked fields on main after applying audit: 12",
            "next action command after applying audit: contrib/devtools/zkcoin_public_launch_profile.py --next-action contrib/devtools/zkcoin_public_launch_profile_manifest.json",
            "readiness summary command after applying audit: contrib/devtools/zkcoin_public_launch_profile.py --readiness-summary contrib/devtools/zkcoin_public_launch_profile_manifest.json",
            "network readiness summary command after applying audit: contrib/devtools/zkcoin_public_launch_profile.py --network-readiness-summary main contrib/devtools/zkcoin_public_launch_profile_manifest.json",
            "blocker type readiness summary command after applying audit: contrib/devtools/zkcoin_public_launch_profile.py --blocker-type-readiness-summary litecoin_snapshot contrib/devtools/zkcoin_public_launch_profile_manifest.json",
            "next blocker after applying audit: main.auxpow_chain_id",
            "next check command after applying audit: contrib/devtools/zkcoin_public_launch_profile.py --check-auxpow main <chain_id> contrib/devtools/zkcoin_public_launch_profile_manifest.json",
            "next apply command after applying audit: contrib/devtools/zkcoin_public_launch_profile.py --set-auxpow main <chain_id> --in-place contrib/devtools/zkcoin_public_launch_profile_manifest.json",
            "next network readiness summary command after applying audit: contrib/devtools/zkcoin_public_launch_profile.py --network-readiness-summary main contrib/devtools/zkcoin_public_launch_profile_manifest.json",
            "next blocker type readiness summary command after applying audit: contrib/devtools/zkcoin_public_launch_profile.py --blocker-type-readiness-summary auxpow_chain_id contrib/devtools/zkcoin_public_launch_profile_manifest.json",
            "next blocker readiness summary command after applying audit: contrib/devtools/zkcoin_public_launch_profile.py --blocker-readiness-summary main.auxpow_chain_id contrib/devtools/zkcoin_public_launch_profile_manifest.json",
        ):
            if expected not in check_audit_result.stdout:
                return "{} --check-snapshot-audit did not print {}".format(
                    PUBLIC_LAUNCH_MANIFEST_TOOL.relative_to(ROOT_DIR),
                    expected,
                )

        spaced_audit_path = Path(temp_dir) / "snapshot audit.json"
        spaced_audit_path.write_text(json.dumps(audit), encoding="utf8")
        spaced_check_audit_result = subprocess.run(
            [
                sys.executable,
                str(PUBLIC_LAUNCH_MANIFEST_TOOL),
                "--check-snapshot-audit",
                "main",
                str(spaced_audit_path),
                str(PUBLIC_LAUNCH_MANIFEST),
            ],
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        if spaced_check_audit_result.returncode != 0:
            return "{} --check-snapshot-audit failed for an audit path with spaces: {}".format(
                PUBLIC_LAUNCH_MANIFEST_TOOL.relative_to(ROOT_DIR),
                spaced_check_audit_result.stderr.strip()
                or spaced_check_audit_result.stdout.strip()
                or "no output",
            )
        if f"--set-snapshot-audit main {shlex.quote(str(spaced_audit_path))} --in-place" not in spaced_check_audit_result.stdout:
            return "{} --check-snapshot-audit did not shell-quote an audit apply command".format(
                PUBLIC_LAUNCH_MANIFEST_TOOL.relative_to(ROOT_DIR)
            )

        spaced_audit_manifest_path = Path(temp_dir) / "public launch manifest.json"
        spaced_audit_manifest_path.write_text(PUBLIC_LAUNCH_MANIFEST.read_text(encoding="utf8"), encoding="utf8")
        spaced_manifest_check_result = subprocess.run(
            [
                sys.executable,
                str(PUBLIC_LAUNCH_MANIFEST_TOOL),
                "--check-snapshot-audit",
                "main",
                str(audit_path),
                str(spaced_audit_manifest_path),
            ],
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        if spaced_manifest_check_result.returncode != 0:
            return "{} --check-snapshot-audit failed for a manifest path with spaces: {}".format(
                PUBLIC_LAUNCH_MANIFEST_TOOL.relative_to(ROOT_DIR),
                spaced_manifest_check_result.stderr.strip()
                or spaced_manifest_check_result.stdout.strip()
                or "no output",
            )
        if f"--in-place {shlex.quote(str(spaced_audit_manifest_path))}" not in spaced_manifest_check_result.stdout:
            return "{} --check-snapshot-audit did not shell-quote a manifest apply command".format(
                PUBLIC_LAUNCH_MANIFEST_TOOL.relative_to(ROOT_DIR)
            )
        if f"--readiness-summary {shlex.quote(str(spaced_audit_manifest_path))}" not in spaced_manifest_check_result.stdout:
            return "{} --check-snapshot-audit did not shell-quote a manifest readiness-summary command".format(
                PUBLIC_LAUNCH_MANIFEST_TOOL.relative_to(ROOT_DIR)
            )
        if f"--network-readiness-summary main {shlex.quote(str(spaced_audit_manifest_path))}" not in spaced_manifest_check_result.stdout:
            return "{} --check-snapshot-audit did not shell-quote a manifest network readiness-summary command".format(
                PUBLIC_LAUNCH_MANIFEST_TOOL.relative_to(ROOT_DIR)
            )
        if f"--blocker-type-readiness-summary litecoin_snapshot {shlex.quote(str(spaced_audit_manifest_path))}" not in spaced_manifest_check_result.stdout:
            return "{} --check-snapshot-audit did not shell-quote a manifest blocker-type readiness-summary command".format(
                PUBLIC_LAUNCH_MANIFEST_TOOL.relative_to(ROOT_DIR)
            )
        if f"--blocker-readiness-summary main.auxpow_chain_id {shlex.quote(str(spaced_audit_manifest_path))}" not in spaced_manifest_check_result.stdout:
            return "{} --check-snapshot-audit did not shell-quote a manifest blocker readiness-summary command".format(
                PUBLIC_LAUNCH_MANIFEST_TOOL.relative_to(ROOT_DIR)
            )

        malformed_check_manifest = json.loads(PUBLIC_LAUNCH_MANIFEST.read_text(encoding="utf8"))
        malformed_check_manifest["networks"]["main"]["auxpow"] = "not-an-object"
        malformed_check_manifest_path = Path(temp_dir) / "malformed-check-manifest.json"
        malformed_check_manifest_path.write_text(json.dumps(malformed_check_manifest), encoding="utf8")
        malformed_check_result = subprocess.run(
            [
                sys.executable,
                str(PUBLIC_LAUNCH_MANIFEST_TOOL),
                "--check-snapshot-audit",
                "main",
                str(audit_path),
                str(malformed_check_manifest_path),
            ],
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        if malformed_check_result.returncode == 0:
            return "{} --check-snapshot-audit accepted a candidate against a malformed manifest".format(
                PUBLIC_LAUNCH_MANIFEST_TOOL.relative_to(ROOT_DIR)
            )
        if "Snapshot audit candidate failed validation:" not in malformed_check_result.stderr:
            return "{} --check-snapshot-audit did not report candidate validation failure".format(
                PUBLIC_LAUNCH_MANIFEST_TOOL.relative_to(ROOT_DIR)
            )
        if "main.auxpow: must be an object" not in malformed_check_result.stderr:
            return "{} --check-snapshot-audit did not validate the staged manifest candidate".format(
                PUBLIC_LAUNCH_MANIFEST_TOOL.relative_to(ROOT_DIR)
            )

        check_audit_in_place_result = subprocess.run(
            [
                sys.executable,
                str(PUBLIC_LAUNCH_MANIFEST_TOOL),
                "--check-snapshot-audit",
                "main",
                str(audit_path),
                "--in-place",
                str(PUBLIC_LAUNCH_MANIFEST),
            ],
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        if check_audit_in_place_result.returncode == 0:
            return "{} --check-snapshot-audit accepted --in-place".format(
                PUBLIC_LAUNCH_MANIFEST_TOOL.relative_to(ROOT_DIR)
            )
        if "--check-snapshot-audit does not write the manifest" not in check_audit_in_place_result.stderr:
            return "{} --check-snapshot-audit did not explain --in-place rejection".format(
                PUBLIC_LAUNCH_MANIFEST_TOOL.relative_to(ROOT_DIR)
            )

        symlink_audit_path = Path(temp_dir) / "snapshot-audit-link.json"
        symlink_audit_path.symlink_to(audit_path)
        symlink_audit_result = subprocess.run(
            [
                sys.executable,
                str(PUBLIC_LAUNCH_MANIFEST_TOOL),
                "--set-snapshot-audit",
                "main",
                str(symlink_audit_path),
                str(PUBLIC_LAUNCH_MANIFEST),
            ],
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        if symlink_audit_result.returncode == 0:
            return "{} --set-snapshot-audit accepted a symlinked audit summary".format(
                PUBLIC_LAUNCH_MANIFEST_TOOL.relative_to(ROOT_DIR)
            )
        if "snapshot audit summary must not be a symlink" not in symlink_audit_result.stderr:
            return "{} --set-snapshot-audit did not explain symlink audit summary rejection".format(
                PUBLIC_LAUNCH_MANIFEST_TOOL.relative_to(ROOT_DIR)
            )

        parent_symlink_audit_target = Path(temp_dir) / "snapshot-audit-parent-target"
        parent_symlink_audit_target.mkdir()
        parent_symlink_audit_file = parent_symlink_audit_target / "snapshot-audit.json"
        parent_symlink_audit_file.write_text(json.dumps(audit), encoding="utf8")
        parent_symlink_audit_parent = Path(temp_dir) / "snapshot-audit-parent-link"
        parent_symlink_audit_parent.symlink_to(parent_symlink_audit_target, target_is_directory=True)
        parent_symlink_audit_result = subprocess.run(
            [
                sys.executable,
                str(PUBLIC_LAUNCH_MANIFEST_TOOL),
                "--set-snapshot-audit",
                "main",
                str(parent_symlink_audit_parent / parent_symlink_audit_file.name),
                str(PUBLIC_LAUNCH_MANIFEST),
            ],
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        if parent_symlink_audit_result.returncode == 0:
            return "{} --set-snapshot-audit accepted an audit summary through a symlinked parent".format(
                PUBLIC_LAUNCH_MANIFEST_TOOL.relative_to(ROOT_DIR)
            )
        if "snapshot audit summary parent directory must not be a symlink" not in parent_symlink_audit_result.stderr:
            return "{} --set-snapshot-audit did not explain symlink audit summary parent rejection".format(
                PUBLIC_LAUNCH_MANIFEST_TOOL.relative_to(ROOT_DIR)
            )

        directory_audit_path = Path(temp_dir) / "snapshot-audit-dir"
        directory_audit_path.mkdir()
        directory_audit_result = subprocess.run(
            [
                sys.executable,
                str(PUBLIC_LAUNCH_MANIFEST_TOOL),
                "--set-snapshot-audit",
                "main",
                str(directory_audit_path),
                str(PUBLIC_LAUNCH_MANIFEST),
            ],
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        if directory_audit_result.returncode == 0:
            return "{} --set-snapshot-audit accepted a directory audit summary".format(
                PUBLIC_LAUNCH_MANIFEST_TOOL.relative_to(ROOT_DIR)
            )
        if "snapshot audit summary must be a regular file" not in directory_audit_result.stderr:
            return "{} --set-snapshot-audit did not explain directory audit summary rejection".format(
                PUBLIC_LAUNCH_MANIFEST_TOOL.relative_to(ROOT_DIR)
            )

        oversized_audit_path = Path(temp_dir) / "oversized-audit.json"
        oversized_audit_path.write_text(" " * (64 * 1024 + 1), encoding="utf8")
        oversized_audit_result = subprocess.run(
            [
                sys.executable,
                str(PUBLIC_LAUNCH_MANIFEST_TOOL),
                "--set-snapshot-audit",
                "main",
                str(oversized_audit_path),
                str(PUBLIC_LAUNCH_MANIFEST),
            ],
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        if oversized_audit_result.returncode == 0:
            return "{} --set-snapshot-audit accepted an oversized audit summary".format(
                PUBLIC_LAUNCH_MANIFEST_TOOL.relative_to(ROOT_DIR)
            )
        if "snapshot audit summary must not exceed 65536 bytes" not in oversized_audit_result.stderr:
            return "{} --set-snapshot-audit did not explain oversized audit summary rejection".format(
                PUBLIC_LAUNCH_MANIFEST_TOOL.relative_to(ROOT_DIR)
            )

        oversized_read_path = Path(temp_dir) / "oversized-read-audit.json"
        oversized_read_path.write_bytes(b" " * (manifest_tool.SNAPSHOT_AUDIT_SUMMARY_MAX_BYTES + 1))
        oversized_read_fd = os.open(oversized_read_path, os.O_RDONLY)
        try:
            try:
                manifest_tool.read_snapshot_audit_summary_text(oversized_read_fd, oversized_read_path)
            except ValueError as exc:
                if "snapshot audit summary must not exceed 65536 bytes" not in str(exc):
                    return "{} bounded audit-summary read reported the wrong oversized error".format(
                        PUBLIC_LAUNCH_MANIFEST_TOOL.relative_to(ROOT_DIR)
                    )
            else:
                return "{} bounded audit-summary read accepted oversized content".format(
                    PUBLIC_LAUNCH_MANIFEST_TOOL.relative_to(ROOT_DIR)
                )
        finally:
            os.close(oversized_read_fd)

        def reject_changed_audit_summary_case(name, mutate_path):
            changed_audit_path = Path(temp_dir) / f"{name}.json"
            changed_audit_path.write_text(json.dumps(audit), encoding="utf8")
            changed_audit_fd, changed_audit_stat = manifest_tool.open_regular_file_no_symlink(
                changed_audit_path,
                symlink_error="snapshot audit summary must not be a symlink",
                missing_error="cannot read snapshot audit summary",
                not_regular_error="snapshot audit summary must be a regular file",
                open_error="cannot read snapshot audit summary",
            )
            try:
                mutate_path(changed_audit_path)
                try:
                    manifest_tool.require_snapshot_audit_summary_stable(
                        changed_audit_path,
                        changed_audit_stat,
                        changed_audit_fd,
                    )
                except ValueError as exc:
                    if "snapshot audit summary changed during read" not in str(exc):
                        return "{} reported the wrong changed-audit-summary error for {}".format(
                            PUBLIC_LAUNCH_MANIFEST_TOOL.relative_to(ROOT_DIR),
                            name,
                        )
                else:
                    return "{} accepted a changed snapshot audit summary path in {}".format(
                        PUBLIC_LAUNCH_MANIFEST_TOOL.relative_to(ROOT_DIR),
                        name,
                    )
            finally:
                os.close(changed_audit_fd)
            return None

        def replace_changed_audit_summary(audit_path):
            replacement_path = Path(temp_dir) / "replacement-snapshot-audit-summary.json"
            replacement_path.write_text(json.dumps(audit), encoding="utf8")
            os.replace(replacement_path, audit_path)

        replaced_audit_summary_error = reject_changed_audit_summary_case(
            "replaced-snapshot-audit-summary",
            replace_changed_audit_summary,
        )
        if replaced_audit_summary_error:
            return replaced_audit_summary_error

        truncated_audit_summary_error = reject_changed_audit_summary_case(
            "truncated-snapshot-audit-summary",
            lambda audit_summary_path: audit_summary_path.write_text("{}", encoding="utf8"),
        )
        if truncated_audit_summary_error:
            return truncated_audit_summary_error

        invalid_utf8_audit_path = Path(temp_dir) / "invalid-utf8-audit.json"
        invalid_utf8_audit_path.write_bytes(b'{"height": 1, "block_hash": "' + bytes([0xff]) + b'"}')
        invalid_utf8_audit_result = subprocess.run(
            [
                sys.executable,
                str(PUBLIC_LAUNCH_MANIFEST_TOOL),
                "--set-snapshot-audit",
                "main",
                str(invalid_utf8_audit_path),
                str(PUBLIC_LAUNCH_MANIFEST),
            ],
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        if invalid_utf8_audit_result.returncode == 0:
            return "{} --set-snapshot-audit accepted an invalid UTF-8 audit summary".format(
                PUBLIC_LAUNCH_MANIFEST_TOOL.relative_to(ROOT_DIR)
            )
        if "snapshot audit summary is not valid UTF-8" not in invalid_utf8_audit_result.stderr:
            return "{} --set-snapshot-audit did not explain invalid UTF-8 audit summary rejection".format(
                PUBLIC_LAUNCH_MANIFEST_TOOL.relative_to(ROOT_DIR)
            )
        if "codec can't decode" in invalid_utf8_audit_result.stderr:
            return "{} --set-snapshot-audit leaked a codec-specific UTF-8 decode error".format(
                PUBLIC_LAUNCH_MANIFEST_TOOL.relative_to(ROOT_DIR)
            )

        incomplete_audit_path = Path(temp_dir) / "incomplete-audit.json"
        incomplete_audit = dict(audit)
        incomplete_audit.pop("snapshot_hash")
        incomplete_audit_path.write_text(json.dumps(incomplete_audit), encoding="utf8")
        incomplete_audit_result = subprocess.run(
            [
                sys.executable,
                str(PUBLIC_LAUNCH_MANIFEST_TOOL),
                "--set-snapshot-audit",
                "main",
                str(incomplete_audit_path),
                str(PUBLIC_LAUNCH_MANIFEST),
            ],
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        if incomplete_audit_result.returncode == 0:
            return "{} --set-snapshot-audit accepted an incomplete audit summary".format(
                PUBLIC_LAUNCH_MANIFEST_TOOL.relative_to(ROOT_DIR)
            )
        if "snapshot audit missing field: snapshot_hash" not in incomplete_audit_result.stderr:
            return "{} --set-snapshot-audit did not explain incomplete audit rejection".format(
                PUBLIC_LAUNCH_MANIFEST_TOOL.relative_to(ROOT_DIR)
            )

        uppercase_hash_audit_path = Path(temp_dir) / "uppercase-hash-audit.json"
        uppercase_hash_audit = dict(audit)
        uppercase_hash_audit["block_hash"] = ("aa" * 32).upper()
        uppercase_hash_audit_path.write_text(json.dumps(uppercase_hash_audit), encoding="utf8")
        uppercase_hash_result = subprocess.run(
            [
                sys.executable,
                str(PUBLIC_LAUNCH_MANIFEST_TOOL),
                "--set-snapshot-audit",
                "main",
                str(uppercase_hash_audit_path),
                str(PUBLIC_LAUNCH_MANIFEST),
            ],
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        if uppercase_hash_result.returncode == 0:
            return "{} --set-snapshot-audit accepted an uppercase audit hash".format(
                PUBLIC_LAUNCH_MANIFEST_TOOL.relative_to(ROOT_DIR)
            )
        if "snapshot audit block_hash must be a 64-character lowercase hex string" not in uppercase_hash_result.stderr:
            return "{} --set-snapshot-audit did not explain uppercase audit hash rejection".format(
                PUBLIC_LAUNCH_MANIFEST_TOOL.relative_to(ROOT_DIR)
            )

        duplicate_field_audit_path = Path(temp_dir) / "duplicate-field-audit.json"
        duplicate_field_audit_path.write_text(
            json.dumps(audit).replace(
                f'"block_hash": "{audit["block_hash"]}"',
                f'"block_hash": "{audit["block_hash"]}", "block_hash": "{audit["block_hash"]}"',
                1,
            ),
            encoding="utf8",
        )
        duplicate_field_audit_result = subprocess.run(
            [
                sys.executable,
                str(PUBLIC_LAUNCH_MANIFEST_TOOL),
                "--set-snapshot-audit",
                "main",
                str(duplicate_field_audit_path),
                str(PUBLIC_LAUNCH_MANIFEST),
            ],
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        if duplicate_field_audit_result.returncode == 0:
            return "{} --set-snapshot-audit accepted an audit summary with duplicate JSON fields".format(
                PUBLIC_LAUNCH_MANIFEST_TOOL.relative_to(ROOT_DIR)
            )
        if "snapshot audit summary contains duplicate field: block_hash" not in duplicate_field_audit_result.stderr:
            return "{} --set-snapshot-audit did not explain duplicate audit field rejection".format(
                PUBLIC_LAUNCH_MANIFEST_TOOL.relative_to(ROOT_DIR)
            )

        extra_field_audit_path = Path(temp_dir) / "extra-field-audit.json"
        extra_field_audit = dict(audit)
        extra_field_audit["unexpected_launch_value"] = "ignored-before"
        extra_field_audit_path.write_text(json.dumps(extra_field_audit), encoding="utf8")
        extra_field_audit_result = subprocess.run(
            [
                sys.executable,
                str(PUBLIC_LAUNCH_MANIFEST_TOOL),
                "--set-snapshot-audit",
                "main",
                str(extra_field_audit_path),
                str(PUBLIC_LAUNCH_MANIFEST),
            ],
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        if extra_field_audit_result.returncode == 0:
            return "{} --set-snapshot-audit accepted an audit summary with an extra field".format(
                PUBLIC_LAUNCH_MANIFEST_TOOL.relative_to(ROOT_DIR)
            )
        if "snapshot audit summary has unexpected field(s): unexpected_launch_value" not in extra_field_audit_result.stderr:
            return "{} --set-snapshot-audit did not explain extra audit field rejection".format(
                PUBLIC_LAUNCH_MANIFEST_TOOL.relative_to(ROOT_DIR)
            )

        reordered_field_audit_path = Path(temp_dir) / "reordered-field-audit.json"
        reordered_field_audit_path.write_text(
            json.dumps(dict(reversed(list(audit.items())))),
            encoding="utf8",
        )
        reordered_field_audit_result = subprocess.run(
            [
                sys.executable,
                str(PUBLIC_LAUNCH_MANIFEST_TOOL),
                "--check-snapshot-audit",
                "main",
                str(reordered_field_audit_path),
                str(PUBLIC_LAUNCH_MANIFEST),
            ],
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        if reordered_field_audit_result.returncode == 0:
            return "{} --check-snapshot-audit accepted an audit summary with reordered fields".format(
                PUBLIC_LAUNCH_MANIFEST_TOOL.relative_to(ROOT_DIR)
            )
        if "--snapshot-audit-template output" not in reordered_field_audit_result.stderr:
            return "{} --check-snapshot-audit did not explain reordered audit field rejection".format(
                PUBLIC_LAUNCH_MANIFEST_TOOL.relative_to(ROOT_DIR)
            )

        relative_file_audit_path = Path(temp_dir) / "relative-file-audit.json"
        relative_file_audit = dict(audit)
        relative_file_audit["snapshot_file"] = "snapshots/ltc-block-x.dat"
        relative_file_audit_path.write_text(json.dumps(relative_file_audit), encoding="utf8")
        relative_file_audit_result = subprocess.run(
            [
                sys.executable,
                str(PUBLIC_LAUNCH_MANIFEST_TOOL),
                "--set-snapshot-audit",
                "main",
                str(relative_file_audit_path),
                str(PUBLIC_LAUNCH_MANIFEST),
            ],
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        if relative_file_audit_result.returncode == 0:
            return "{} --set-snapshot-audit accepted a relative snapshot file path".format(
                PUBLIC_LAUNCH_MANIFEST_TOOL.relative_to(ROOT_DIR)
            )
        if "snapshot audit snapshot_file must be an absolute non-placeholder path" not in relative_file_audit_result.stderr:
            return "{} --set-snapshot-audit did not explain relative snapshot file rejection".format(
                PUBLIC_LAUNCH_MANIFEST_TOOL.relative_to(ROOT_DIR)
            )

        control_file_audit_path = Path(temp_dir) / "control-file-audit.json"
        control_file_audit = dict(audit)
        control_file_audit["snapshot_file"] = str(snapshot_artifact_path) + "\ntruncated"
        control_file_audit_path.write_text(json.dumps(control_file_audit), encoding="utf8")
        control_file_audit_result = subprocess.run(
            [
                sys.executable,
                str(PUBLIC_LAUNCH_MANIFEST_TOOL),
                "--set-snapshot-audit",
                "main",
                str(control_file_audit_path),
                str(PUBLIC_LAUNCH_MANIFEST),
            ],
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        if control_file_audit_result.returncode == 0:
            return "{} --set-snapshot-audit accepted a snapshot file path with control characters".format(
                PUBLIC_LAUNCH_MANIFEST_TOOL.relative_to(ROOT_DIR)
            )
        if "without control characters" not in control_file_audit_result.stderr:
            return "{} --set-snapshot-audit did not explain control-character snapshot file rejection".format(
                PUBLIC_LAUNCH_MANIFEST_TOOL.relative_to(ROOT_DIR)
            )

        self_reference_audit_path = Path(temp_dir) / "self-reference-audit.json"
        self_reference_audit = dict(audit)
        self_reference_audit["snapshot_file"] = str(self_reference_audit_path)
        self_reference_audit_path.write_text(json.dumps(self_reference_audit), encoding="utf8")
        self_reference_audit_result = subprocess.run(
            [
                sys.executable,
                str(PUBLIC_LAUNCH_MANIFEST_TOOL),
                "--set-snapshot-audit",
                "main",
                str(self_reference_audit_path),
                str(PUBLIC_LAUNCH_MANIFEST),
            ],
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        if self_reference_audit_result.returncode == 0:
            return "{} --set-snapshot-audit accepted an audit summary as the snapshot artifact".format(
                PUBLIC_LAUNCH_MANIFEST_TOOL.relative_to(ROOT_DIR)
            )
        if "snapshot audit file artifact must differ from audit summary" not in self_reference_audit_result.stderr:
            return "{} --set-snapshot-audit did not explain self-referential snapshot artifact rejection".format(
                PUBLIC_LAUNCH_MANIFEST_TOOL.relative_to(ROOT_DIR)
            )

        directory_artifact_path = Path(temp_dir) / "ltc-block-x-dir.dat"
        directory_artifact_path.mkdir()
        directory_artifact_audit_path = Path(temp_dir) / "directory-artifact-audit.json"
        directory_artifact_audit = dict(audit)
        directory_artifact_audit["snapshot_file"] = str(directory_artifact_path)
        directory_artifact_audit_path.write_text(json.dumps(directory_artifact_audit), encoding="utf8")
        directory_artifact_result = subprocess.run(
            [
                sys.executable,
                str(PUBLIC_LAUNCH_MANIFEST_TOOL),
                "--set-snapshot-audit",
                "main",
                str(directory_artifact_audit_path),
                str(PUBLIC_LAUNCH_MANIFEST),
            ],
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        if directory_artifact_result.returncode == 0:
            return "{} --set-snapshot-audit accepted a directory snapshot artifact".format(
                PUBLIC_LAUNCH_MANIFEST_TOOL.relative_to(ROOT_DIR)
            )
        if "snapshot audit file artifact must be a regular file" not in directory_artifact_result.stderr:
            return "{} --set-snapshot-audit did not explain directory snapshot artifact rejection".format(
                PUBLIC_LAUNCH_MANIFEST_TOOL.relative_to(ROOT_DIR)
            )

        symlink_artifact_path = Path(temp_dir) / "ltc-block-x-link.dat"
        symlink_artifact_path.symlink_to(snapshot_artifact_path)
        symlink_artifact_audit_path = Path(temp_dir) / "symlink-artifact-audit.json"
        symlink_artifact_audit = dict(audit)
        symlink_artifact_audit["snapshot_file"] = str(symlink_artifact_path)
        symlink_artifact_audit_path.write_text(json.dumps(symlink_artifact_audit), encoding="utf8")
        symlink_artifact_result = subprocess.run(
            [
                sys.executable,
                str(PUBLIC_LAUNCH_MANIFEST_TOOL),
                "--set-snapshot-audit",
                "main",
                str(symlink_artifact_audit_path),
                str(PUBLIC_LAUNCH_MANIFEST),
            ],
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        if symlink_artifact_result.returncode == 0:
            return "{} --set-snapshot-audit accepted a symlinked snapshot artifact".format(
                PUBLIC_LAUNCH_MANIFEST_TOOL.relative_to(ROOT_DIR)
            )
        if "snapshot audit file artifact must not be a symlink" not in symlink_artifact_result.stderr:
            return "{} --set-snapshot-audit did not explain symlink snapshot artifact rejection".format(
                PUBLIC_LAUNCH_MANIFEST_TOOL.relative_to(ROOT_DIR)
            )

        parent_symlink_artifact_target = Path(temp_dir) / "artifact-parent-target"
        parent_symlink_artifact_target.mkdir()
        parent_symlink_artifact_file = parent_symlink_artifact_target / "ltc-block-x.dat"
        parent_symlink_artifact_file.write_bytes(snapshot_artifact)
        parent_symlink_artifact_parent = Path(temp_dir) / "artifact-parent-link"
        parent_symlink_artifact_parent.symlink_to(parent_symlink_artifact_target, target_is_directory=True)
        parent_symlink_artifact_audit_path = Path(temp_dir) / "parent-symlink-artifact-audit.json"
        parent_symlink_artifact_audit = dict(audit)
        parent_symlink_artifact_audit["snapshot_file"] = str(
            parent_symlink_artifact_parent / parent_symlink_artifact_file.name
        )
        parent_symlink_artifact_audit_path.write_text(json.dumps(parent_symlink_artifact_audit), encoding="utf8")
        parent_symlink_artifact_result = subprocess.run(
            [
                sys.executable,
                str(PUBLIC_LAUNCH_MANIFEST_TOOL),
                "--set-snapshot-audit",
                "main",
                str(parent_symlink_artifact_audit_path),
                str(PUBLIC_LAUNCH_MANIFEST),
            ],
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        if parent_symlink_artifact_result.returncode == 0:
            return "{} --set-snapshot-audit accepted a snapshot artifact through a symlinked parent".format(
                PUBLIC_LAUNCH_MANIFEST_TOOL.relative_to(ROOT_DIR)
            )
        if "snapshot audit file artifact parent directory must not be a symlink" not in parent_symlink_artifact_result.stderr:
            return "{} --set-snapshot-audit did not explain symlink snapshot artifact parent rejection".format(
                PUBLIC_LAUNCH_MANIFEST_TOOL.relative_to(ROOT_DIR)
            )

        def reject_changed_artifact_case(name, mutate_path):
            changed_artifact_path = Path(temp_dir) / f"{name}.dat"
            changed_artifact_path.write_bytes(b"original artifact bytes")
            changed_artifact_fd, changed_artifact_stat = manifest_tool.open_regular_file_no_symlink(
                changed_artifact_path,
                symlink_error="snapshot audit file artifact must not be a symlink",
                missing_error="snapshot audit file artifact does not exist",
                not_regular_error="snapshot audit file artifact must be a regular file",
                open_error="cannot read snapshot audit file artifact",
            )
            try:
                with os.fdopen(changed_artifact_fd, "rb") as changed_artifact_file:
                    changed_artifact_fd = None
                    mutate_path(changed_artifact_path)
                    try:
                        manifest_tool.require_snapshot_audit_artifact_stable(
                            changed_artifact_path,
                            changed_artifact_stat,
                            changed_artifact_file,
                        )
                    except ValueError as exc:
                        if "snapshot audit file artifact changed during verification" not in str(exc):
                            return "{} reported the wrong changed-artifact error for {}".format(
                                PUBLIC_LAUNCH_MANIFEST_TOOL.relative_to(ROOT_DIR),
                                name,
                            )
                    else:
                        return "{} accepted a changed snapshot artifact path in {}".format(
                            PUBLIC_LAUNCH_MANIFEST_TOOL.relative_to(ROOT_DIR),
                            name,
                        )
            finally:
                if changed_artifact_fd is not None:
                    os.close(changed_artifact_fd)
            return None

        def replace_changed_artifact(artifact_path):
            replacement_path = Path(temp_dir) / "replacement-snapshot-artifact.dat"
            replacement_path.write_bytes(b"replacement artifact bytes")
            os.replace(replacement_path, artifact_path)

        replaced_artifact_error = reject_changed_artifact_case(
            "replaced-snapshot-artifact",
            replace_changed_artifact,
        )
        if replaced_artifact_error:
            return replaced_artifact_error

        truncated_artifact_error = reject_changed_artifact_case(
            "truncated-snapshot-artifact",
            lambda artifact_path: artifact_path.write_bytes(b"truncated"),
        )
        if truncated_artifact_error:
            return truncated_artifact_error

        malformed_amount_audit_path = Path(temp_dir) / "malformed-amount-audit.json"
        malformed_amount_audit = dict(audit)
        malformed_amount_audit["total_amount"] = "50"
        malformed_amount_audit_path.write_text(json.dumps(malformed_amount_audit), encoding="utf8")
        malformed_amount_audit_result = subprocess.run(
            [
                sys.executable,
                str(PUBLIC_LAUNCH_MANIFEST_TOOL),
                "--set-snapshot-audit",
                "main",
                str(malformed_amount_audit_path),
                str(PUBLIC_LAUNCH_MANIFEST),
            ],
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        if malformed_amount_audit_result.returncode == 0:
            return "{} --set-snapshot-audit accepted a malformed snapshot total amount".format(
                PUBLIC_LAUNCH_MANIFEST_TOOL.relative_to(ROOT_DIR)
            )
        if "snapshot audit total_amount must be a positive decimal amount with 8 fractional digits" not in malformed_amount_audit_result.stderr:
            return "{} --set-snapshot-audit did not explain malformed total amount rejection".format(
                PUBLIC_LAUNCH_MANIFEST_TOOL.relative_to(ROOT_DIR)
            )

        over_maximum_amount_audit_path = Path(temp_dir) / "over-maximum-amount-audit.json"
        over_maximum_amount_audit = dict(audit)
        over_maximum_amount_audit["total_amount"] = "84000000.00000001"
        over_maximum_amount_audit_path.write_text(json.dumps(over_maximum_amount_audit), encoding="utf8")
        over_maximum_amount_audit_result = subprocess.run(
            [
                sys.executable,
                str(PUBLIC_LAUNCH_MANIFEST_TOOL),
                "--set-snapshot-audit",
                "main",
                str(over_maximum_amount_audit_path),
                str(PUBLIC_LAUNCH_MANIFEST),
            ],
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        if over_maximum_amount_audit_result.returncode == 0:
            return "{} --set-snapshot-audit accepted an over-maximum snapshot total amount".format(
                PUBLIC_LAUNCH_MANIFEST_TOOL.relative_to(ROOT_DIR)
            )
        if "snapshot audit total_amount must not exceed 84000000.00000000" not in over_maximum_amount_audit_result.stderr:
            return "{} --set-snapshot-audit did not explain over-maximum total amount rejection".format(
                PUBLIC_LAUNCH_MANIFEST_TOOL.relative_to(ROOT_DIR)
            )

        missing_artifact_audit_path = Path(temp_dir) / "missing-artifact-audit.json"
        missing_artifact_audit = dict(audit)
        missing_artifact_audit["snapshot_file"] = str(Path(temp_dir) / "missing-ltc-block-x.dat")
        missing_artifact_audit_path.write_text(json.dumps(missing_artifact_audit), encoding="utf8")
        missing_artifact_audit_result = subprocess.run(
            [
                sys.executable,
                str(PUBLIC_LAUNCH_MANIFEST_TOOL),
                "--set-snapshot-audit",
                "main",
                str(missing_artifact_audit_path),
                str(PUBLIC_LAUNCH_MANIFEST),
            ],
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        if missing_artifact_audit_result.returncode == 0:
            return "{} --set-snapshot-audit accepted a missing snapshot artifact".format(
                PUBLIC_LAUNCH_MANIFEST_TOOL.relative_to(ROOT_DIR)
            )
        if "snapshot audit file artifact does not exist" not in missing_artifact_audit_result.stderr:
            return "{} --set-snapshot-audit did not explain missing snapshot artifact rejection".format(
                PUBLIC_LAUNCH_MANIFEST_TOOL.relative_to(ROOT_DIR)
            )

        mismatched_size_audit_path = Path(temp_dir) / "mismatched-size-audit.json"
        mismatched_size_audit = dict(audit)
        mismatched_size_audit["snapshot_file_size"] = len(snapshot_artifact) + 1
        mismatched_size_audit_path.write_text(json.dumps(mismatched_size_audit), encoding="utf8")
        mismatched_size_audit_result = subprocess.run(
            [
                sys.executable,
                str(PUBLIC_LAUNCH_MANIFEST_TOOL),
                "--set-snapshot-audit",
                "main",
                str(mismatched_size_audit_path),
                str(PUBLIC_LAUNCH_MANIFEST),
            ],
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        if mismatched_size_audit_result.returncode == 0:
            return "{} --set-snapshot-audit accepted a mismatched snapshot file size".format(
                PUBLIC_LAUNCH_MANIFEST_TOOL.relative_to(ROOT_DIR)
            )
        if "snapshot audit file size mismatch" not in mismatched_size_audit_result.stderr:
            return "{} --set-snapshot-audit did not explain snapshot file size mismatch".format(
                PUBLIC_LAUNCH_MANIFEST_TOOL.relative_to(ROOT_DIR)
            )

        mismatched_sha_audit_path = Path(temp_dir) / "mismatched-sha-audit.json"
        mismatched_sha_audit = dict(audit)
        mismatched_sha_audit["snapshot_file_sha256"] = "99" * 32
        mismatched_sha_audit_path.write_text(json.dumps(mismatched_sha_audit), encoding="utf8")
        mismatched_sha_audit_result = subprocess.run(
            [
                sys.executable,
                str(PUBLIC_LAUNCH_MANIFEST_TOOL),
                "--set-snapshot-audit",
                "main",
                str(mismatched_sha_audit_path),
                str(PUBLIC_LAUNCH_MANIFEST),
            ],
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        if mismatched_sha_audit_result.returncode == 0:
            return "{} --set-snapshot-audit accepted a mismatched snapshot file SHA-256".format(
                PUBLIC_LAUNCH_MANIFEST_TOOL.relative_to(ROOT_DIR)
            )
        if "snapshot audit file SHA-256 mismatch" not in mismatched_sha_audit_result.stderr:
            return "{} --set-snapshot-audit did not explain snapshot file SHA-256 mismatch".format(
                PUBLIC_LAUNCH_MANIFEST_TOOL.relative_to(ROOT_DIR)
            )

        mismatched_source_chain_audit_path = Path(temp_dir) / "mismatched-source-chain-audit.json"
        mismatched_source_chain_audit = dict(audit)
        mismatched_source_chain_audit["source_chain"] = "test"
        mismatched_source_chain_audit_path.write_text(json.dumps(mismatched_source_chain_audit), encoding="utf8")
        mismatched_source_chain_result = subprocess.run(
            [
                sys.executable,
                str(PUBLIC_LAUNCH_MANIFEST_TOOL),
                "--set-snapshot-audit",
                "main",
                str(mismatched_source_chain_audit_path),
                str(PUBLIC_LAUNCH_MANIFEST),
            ],
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        if mismatched_source_chain_result.returncode == 0:
            return "{} --set-snapshot-audit accepted a testnet source audit for main".format(
                PUBLIC_LAUNCH_MANIFEST_TOOL.relative_to(ROOT_DIR)
            )
        if "snapshot audit source_chain test does not match main; expected main" not in mismatched_source_chain_result.stderr:
            return "{} --set-snapshot-audit did not explain source-chain mismatch rejection".format(
                PUBLIC_LAUNCH_MANIFEST_TOOL.relative_to(ROOT_DIR)
            )

    auxpow_result = subprocess.run(
        [
            sys.executable,
            str(PUBLIC_LAUNCH_MANIFEST_TOOL),
            "--set-auxpow",
            "main",
            "0x5001",
            str(PUBLIC_LAUNCH_MANIFEST),
        ],
        check=False,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    if auxpow_result.returncode != 0:
        return "{} --set-auxpow failed: {}".format(
            PUBLIC_LAUNCH_MANIFEST_TOOL.relative_to(ROOT_DIR),
            auxpow_result.stderr.strip() or auxpow_result.stdout.strip() or "no output",
        )
    try:
        auxpow_manifest = json.loads(auxpow_result.stdout)
    except json.JSONDecodeError as exc:
        return "{} --set-auxpow did not emit JSON: {}".format(
            PUBLIC_LAUNCH_MANIFEST_TOOL.relative_to(ROOT_DIR),
            exc,
        )
    auxpow = auxpow_manifest["networks"]["main"]["auxpow"]
    if auxpow != {
        "start_height": 1,
        "chain_id": 0x5001,
        "strict_chain_id": True,
        "forbidden_parent_version_chain_id_range": [8192, 16383],
    }:
        return "{} --set-auxpow did not update main AuxPoW fields".format(
            PUBLIC_LAUNCH_MANIFEST_TOOL.relative_to(ROOT_DIR)
        )
    auxpow_blockers = {
        blocker.get("id")
        for blocker in auxpow_manifest.get("blockers", [])
        if isinstance(blocker, dict)
    }
    if "main.auxpow_chain_id" in auxpow_blockers:
        return "{} --set-auxpow did not remove the resolved main AuxPoW blocker".format(
            PUBLIC_LAUNCH_MANIFEST_TOOL.relative_to(ROOT_DIR)
        )
    if "main.litecoin_snapshot" not in auxpow_blockers:
        return "{} --set-auxpow removed unrelated blockers".format(
            PUBLIC_LAUNCH_MANIFEST_TOOL.relative_to(ROOT_DIR)
        )

    with tempfile.TemporaryDirectory() as temp_dir:
        snapshot_resolved_path = Path(temp_dir) / "snapshot-resolved.json"
        snapshot_resolved_path.write_text(json.dumps(audit_manifest), encoding="utf8")
        snapshot_auxpow_result = subprocess.run(
            [
                sys.executable,
                str(PUBLIC_LAUNCH_MANIFEST_TOOL),
                "--set-auxpow",
                "main",
                "0x5001",
                str(snapshot_resolved_path),
            ],
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        if snapshot_auxpow_result.returncode != 0:
            return "{} --set-auxpow failed after resolving the snapshot blocker: {}".format(
                PUBLIC_LAUNCH_MANIFEST_TOOL.relative_to(ROOT_DIR),
                snapshot_auxpow_result.stderr.strip()
                or snapshot_auxpow_result.stdout.strip()
                or "no output",
            )
        try:
            snapshot_auxpow_manifest = json.loads(snapshot_auxpow_result.stdout)
        except json.JSONDecodeError as exc:
            return "{} --set-auxpow after snapshot did not emit JSON: {}".format(
                PUBLIC_LAUNCH_MANIFEST_TOOL.relative_to(ROOT_DIR),
                exc,
            )
        snapshot_auxpow_path = Path(temp_dir) / "snapshot-auxpow-resolved.json"
        snapshot_auxpow_path.write_text(json.dumps(snapshot_auxpow_manifest), encoding="utf8")
        snapshot_auxpow_next_action_result = subprocess.run(
            [
                sys.executable,
                str(PUBLIC_LAUNCH_MANIFEST_TOOL),
                "--next-action",
                str(snapshot_auxpow_path),
            ],
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        if snapshot_auxpow_next_action_result.returncode != 0:
            return "{} --next-action failed after resolving snapshot and AuxPoW blockers: {}".format(
                PUBLIC_LAUNCH_MANIFEST_TOOL.relative_to(ROOT_DIR),
                snapshot_auxpow_next_action_result.stderr.strip()
                or snapshot_auxpow_next_action_result.stdout.strip()
                or "no output",
            )
        if "next blocker: main.public_network_identity" not in snapshot_auxpow_next_action_result.stdout:
            return "{} --next-action did not advance to the public identity blocker".format(
                PUBLIC_LAUNCH_MANIFEST_TOOL.relative_to(ROOT_DIR)
            )
        if "--check-identity main <message_start> <port>" not in snapshot_auxpow_next_action_result.stdout:
            return "{} --next-action did not print the public identity candidate check command".format(
                PUBLIC_LAUNCH_MANIFEST_TOOL.relative_to(ROOT_DIR)
            )
        if "--set-identity main <message_start> <port>" not in snapshot_auxpow_next_action_result.stdout:
            return "{} --next-action did not print the public identity update command".format(
                PUBLIC_LAUNCH_MANIFEST_TOOL.relative_to(ROOT_DIR)
            )
        if "  - check command: contrib/devtools/zkcoin_public_launch_profile.py --check-identity main <message_start> <port>" not in snapshot_auxpow_next_action_result.stdout:
            return "{} --next-action did not print a copyable public identity check command line".format(
                PUBLIC_LAUNCH_MANIFEST_TOOL.relative_to(ROOT_DIR)
            )
        if "  - apply command: contrib/devtools/zkcoin_public_launch_profile.py --set-identity main <message_start> <port>" not in snapshot_auxpow_next_action_result.stdout:
            return "{} --next-action did not print a copyable public identity apply command line".format(
                PUBLIC_LAUNCH_MANIFEST_TOOL.relative_to(ROOT_DIR)
            )

    check_auxpow_result = subprocess.run(
        [
            sys.executable,
            str(PUBLIC_LAUNCH_MANIFEST_TOOL),
            "--check-auxpow",
            "main",
            "0x5001",
            str(PUBLIC_LAUNCH_MANIFEST),
        ],
        check=False,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    if check_auxpow_result.returncode != 0:
        return "{} --check-auxpow failed: {}".format(
            PUBLIC_LAUNCH_MANIFEST_TOOL.relative_to(ROOT_DIR),
            check_auxpow_result.stderr.strip() or check_auxpow_result.stdout.strip() or "no output",
        )
    for expected in (
        "AuxPoW chain id candidate verified for main.",
        "chain id: 20481",
        "chain id hex: 0x5001",
        "strict chain id: true",
        "apply command: contrib/devtools/zkcoin_public_launch_profile.py --set-auxpow main 0x5001 --in-place contrib/devtools/zkcoin_public_launch_profile_manifest.json",
        "remaining blockers after applying candidate: 7",
        "remaining blockers on main after applying candidate: 3",
        "remaining blocked fields after applying candidate: 45",
        "remaining blocked fields on main after applying candidate: 22",
        "next action command after applying candidate: contrib/devtools/zkcoin_public_launch_profile.py --next-action contrib/devtools/zkcoin_public_launch_profile_manifest.json",
        "readiness summary command after applying candidate: contrib/devtools/zkcoin_public_launch_profile.py --readiness-summary contrib/devtools/zkcoin_public_launch_profile_manifest.json",
        "network readiness summary command after applying candidate: contrib/devtools/zkcoin_public_launch_profile.py --network-readiness-summary main contrib/devtools/zkcoin_public_launch_profile_manifest.json",
        "blocker type readiness summary command after applying candidate: contrib/devtools/zkcoin_public_launch_profile.py --blocker-type-readiness-summary auxpow_chain_id contrib/devtools/zkcoin_public_launch_profile_manifest.json",
        "next blocker after applying candidate: main.litecoin_snapshot",
        "next template command after applying candidate: contrib/devtools/zkcoin_public_launch_profile.py --snapshot-audit-template main contrib/devtools/zkcoin_public_launch_profile_manifest.json",
        "next check command after applying candidate: contrib/devtools/zkcoin_public_launch_profile.py --check-snapshot-audit main <snapshot_audit.json> contrib/devtools/zkcoin_public_launch_profile_manifest.json",
        "next apply command after applying candidate: contrib/devtools/zkcoin_public_launch_profile.py --set-snapshot-audit main <snapshot_audit.json> --in-place contrib/devtools/zkcoin_public_launch_profile_manifest.json",
        "next network readiness summary command after applying candidate: contrib/devtools/zkcoin_public_launch_profile.py --network-readiness-summary main contrib/devtools/zkcoin_public_launch_profile_manifest.json",
        "next blocker type readiness summary command after applying candidate: contrib/devtools/zkcoin_public_launch_profile.py --blocker-type-readiness-summary litecoin_snapshot contrib/devtools/zkcoin_public_launch_profile_manifest.json",
        "next blocker readiness summary command after applying candidate: contrib/devtools/zkcoin_public_launch_profile.py --blocker-readiness-summary main.litecoin_snapshot contrib/devtools/zkcoin_public_launch_profile_manifest.json",
    ):
        if expected not in check_auxpow_result.stdout:
            return "{} --check-auxpow did not print {}".format(
                PUBLIC_LAUNCH_MANIFEST_TOOL.relative_to(ROOT_DIR),
                expected,
            )

    check_auxpow_in_place_result = subprocess.run(
        [
            sys.executable,
            str(PUBLIC_LAUNCH_MANIFEST_TOOL),
            "--check-auxpow",
            "main",
            "0x5001",
            "--in-place",
            str(PUBLIC_LAUNCH_MANIFEST),
        ],
        check=False,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    if check_auxpow_in_place_result.returncode == 0:
        return "{} --check-auxpow accepted --in-place".format(
            PUBLIC_LAUNCH_MANIFEST_TOOL.relative_to(ROOT_DIR)
        )
    if "--check-auxpow does not write the manifest" not in check_auxpow_in_place_result.stderr:
        return "{} --check-auxpow did not explain --in-place rejection".format(
            PUBLIC_LAUNCH_MANIFEST_TOOL.relative_to(ROOT_DIR)
        )

    unsafe_check_auxpow_result = subprocess.run(
        [
            sys.executable,
            str(PUBLIC_LAUNCH_MANIFEST_TOOL),
            "--check-auxpow",
            "main",
            "0x2000",
            str(PUBLIC_LAUNCH_MANIFEST),
        ],
        check=False,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    if unsafe_check_auxpow_result.returncode == 0:
        return "{} --check-auxpow accepted a Litecoin parent-versionbits chain id".format(
            PUBLIC_LAUNCH_MANIFEST_TOOL.relative_to(ROOT_DIR)
        )
    if "0x2000-0x3fff" not in unsafe_check_auxpow_result.stderr:
        return "{} --check-auxpow did not explain the parent-versionbits chain-id rejection".format(
            PUBLIC_LAUNCH_MANIFEST_TOOL.relative_to(ROOT_DIR)
        )

    unsafe_auxpow_result = subprocess.run(
        [
            sys.executable,
            str(PUBLIC_LAUNCH_MANIFEST_TOOL),
            "--set-auxpow",
            "main",
            "0x2000",
            str(PUBLIC_LAUNCH_MANIFEST),
        ],
        check=False,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    if unsafe_auxpow_result.returncode == 0:
        return "{} --set-auxpow accepted a Litecoin parent-versionbits chain id".format(
            PUBLIC_LAUNCH_MANIFEST_TOOL.relative_to(ROOT_DIR)
        )
    if "0x2000-0x3fff" not in unsafe_auxpow_result.stderr:
        return "{} --set-auxpow did not explain the parent-versionbits chain-id rejection".format(
            PUBLIC_LAUNCH_MANIFEST_TOOL.relative_to(ROOT_DIR)
        )

    placeholder_auxpow_result = subprocess.run(
        [
            sys.executable,
            str(PUBLIC_LAUNCH_MANIFEST_TOOL),
            "--set-auxpow",
            "main",
            "0x5a4b",
            str(PUBLIC_LAUNCH_MANIFEST),
        ],
        check=False,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    if placeholder_auxpow_result.returncode == 0:
        return "{} --set-auxpow accepted the launch placeholder chain id".format(
            PUBLIC_LAUNCH_MANIFEST_TOOL.relative_to(ROOT_DIR)
        )
    if "placeholder chain id 0x5a4b" not in placeholder_auxpow_result.stderr:
        return "{} --set-auxpow did not explain placeholder chain-id rejection".format(
            PUBLIC_LAUNCH_MANIFEST_TOOL.relative_to(ROOT_DIR)
        )

    dns_result = subprocess.run(
        [
            sys.executable,
            str(PUBLIC_LAUNCH_MANIFEST_TOOL),
            "--set-dns-seeds",
            "main",
            "seed1.zkcoin.net,seed2.zkcoin.net",
            str(PUBLIC_LAUNCH_MANIFEST),
        ],
        check=False,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    if dns_result.returncode != 0:
        return "{} --set-dns-seeds failed: {}".format(
            PUBLIC_LAUNCH_MANIFEST_TOOL.relative_to(ROOT_DIR),
            dns_result.stderr.strip() or dns_result.stdout.strip() or "no output",
        )
    try:
        dns_manifest = json.loads(dns_result.stdout)
    except json.JSONDecodeError as exc:
        return "{} --set-dns-seeds did not emit JSON: {}".format(
            PUBLIC_LAUNCH_MANIFEST_TOOL.relative_to(ROOT_DIR),
            exc,
        )
    dns_seeds = dns_manifest["networks"]["main"]["public_network_identity"]["dns_seeds"]
    if dns_seeds != ["seed1.zkcoin.net", "seed2.zkcoin.net"]:
        return "{} --set-dns-seeds did not update main DNS seeds".format(
            PUBLIC_LAUNCH_MANIFEST_TOOL.relative_to(ROOT_DIR)
        )
    dns_blockers = {
        blocker.get("id")
        for blocker in dns_manifest.get("blockers", [])
        if isinstance(blocker, dict)
    }
    if "main.dns_seeds" in dns_blockers:
        return "{} --set-dns-seeds did not remove the resolved main DNS blocker".format(
            PUBLIC_LAUNCH_MANIFEST_TOOL.relative_to(ROOT_DIR)
        )
    if "main.public_network_identity" not in dns_blockers:
        return "{} --set-dns-seeds removed unrelated identity blockers".format(
            PUBLIC_LAUNCH_MANIFEST_TOOL.relative_to(ROOT_DIR)
        )

    check_dns_result = subprocess.run(
        [
            sys.executable,
            str(PUBLIC_LAUNCH_MANIFEST_TOOL),
            "--check-dns-seeds",
            "main",
            "seed1.zkcoin.net,seed2.zkcoin.net",
            str(PUBLIC_LAUNCH_MANIFEST),
        ],
        check=False,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    if check_dns_result.returncode != 0:
        return "{} --check-dns-seeds failed: {}".format(
            PUBLIC_LAUNCH_MANIFEST_TOOL.relative_to(ROOT_DIR),
            check_dns_result.stderr.strip() or check_dns_result.stdout.strip() or "no output",
        )
    for expected in (
        "DNS seed candidate verified for main.",
        "seed count: 2",
        "seeds: seed1.zkcoin.net, seed2.zkcoin.net",
        "apply command: contrib/devtools/zkcoin_public_launch_profile.py --set-dns-seeds main seed1.zkcoin.net,seed2.zkcoin.net --in-place contrib/devtools/zkcoin_public_launch_profile_manifest.json",
        "remaining blockers after applying candidate: 7",
        "remaining blockers on main after applying candidate: 3",
        "remaining blocked fields after applying candidate: 45",
        "remaining blocked fields on main after applying candidate: 22",
        "next action command after applying candidate: contrib/devtools/zkcoin_public_launch_profile.py --next-action contrib/devtools/zkcoin_public_launch_profile_manifest.json",
        "readiness summary command after applying candidate: contrib/devtools/zkcoin_public_launch_profile.py --readiness-summary contrib/devtools/zkcoin_public_launch_profile_manifest.json",
        "network readiness summary command after applying candidate: contrib/devtools/zkcoin_public_launch_profile.py --network-readiness-summary main contrib/devtools/zkcoin_public_launch_profile_manifest.json",
        "blocker type readiness summary command after applying candidate: contrib/devtools/zkcoin_public_launch_profile.py --blocker-type-readiness-summary dns_seeds contrib/devtools/zkcoin_public_launch_profile_manifest.json",
        "next blocker after applying candidate: main.litecoin_snapshot",
        "next template command after applying candidate: contrib/devtools/zkcoin_public_launch_profile.py --snapshot-audit-template main contrib/devtools/zkcoin_public_launch_profile_manifest.json",
        "next check command after applying candidate: contrib/devtools/zkcoin_public_launch_profile.py --check-snapshot-audit main <snapshot_audit.json> contrib/devtools/zkcoin_public_launch_profile_manifest.json",
        "next apply command after applying candidate: contrib/devtools/zkcoin_public_launch_profile.py --set-snapshot-audit main <snapshot_audit.json> --in-place contrib/devtools/zkcoin_public_launch_profile_manifest.json",
        "next network readiness summary command after applying candidate: contrib/devtools/zkcoin_public_launch_profile.py --network-readiness-summary main contrib/devtools/zkcoin_public_launch_profile_manifest.json",
        "next blocker type readiness summary command after applying candidate: contrib/devtools/zkcoin_public_launch_profile.py --blocker-type-readiness-summary litecoin_snapshot contrib/devtools/zkcoin_public_launch_profile_manifest.json",
        "next blocker readiness summary command after applying candidate: contrib/devtools/zkcoin_public_launch_profile.py --blocker-readiness-summary main.litecoin_snapshot contrib/devtools/zkcoin_public_launch_profile_manifest.json",
    ):
        if expected not in check_dns_result.stdout:
            return "{} --check-dns-seeds did not print {}".format(
                PUBLIC_LAUNCH_MANIFEST_TOOL.relative_to(ROOT_DIR),
                expected,
            )

    check_dns_in_place_result = subprocess.run(
        [
            sys.executable,
            str(PUBLIC_LAUNCH_MANIFEST_TOOL),
            "--check-dns-seeds",
            "main",
            "seed1.zkcoin.net,seed2.zkcoin.net",
            "--in-place",
            str(PUBLIC_LAUNCH_MANIFEST),
        ],
        check=False,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    if check_dns_in_place_result.returncode == 0:
        return "{} --check-dns-seeds accepted --in-place".format(
            PUBLIC_LAUNCH_MANIFEST_TOOL.relative_to(ROOT_DIR)
        )
    if "--check-dns-seeds does not write the manifest" not in check_dns_in_place_result.stderr:
        return "{} --check-dns-seeds did not explain --in-place rejection".format(
            PUBLIC_LAUNCH_MANIFEST_TOOL.relative_to(ROOT_DIR)
        )

    unsafe_check_dns_result = subprocess.run(
        [
            sys.executable,
            str(PUBLIC_LAUNCH_MANIFEST_TOOL),
            "--check-dns-seeds",
            "main",
            "seed-a.litecoin.net",
            str(PUBLIC_LAUNCH_MANIFEST),
        ],
        check=False,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    if unsafe_check_dns_result.returncode == 0:
        return "{} --check-dns-seeds accepted an inherited Litecoin seed hostname".format(
            PUBLIC_LAUNCH_MANIFEST_TOOL.relative_to(ROOT_DIR)
        )
    if "invalid DNS seed hostname" not in unsafe_check_dns_result.stderr:
        return "{} --check-dns-seeds did not explain inherited seed hostname rejection".format(
            PUBLIC_LAUNCH_MANIFEST_TOOL.relative_to(ROOT_DIR)
        )

    unsafe_dns_result = subprocess.run(
        [
            sys.executable,
            str(PUBLIC_LAUNCH_MANIFEST_TOOL),
            "--set-dns-seeds",
            "main",
            "seed-a.litecoin.net",
            str(PUBLIC_LAUNCH_MANIFEST),
        ],
        check=False,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    if unsafe_dns_result.returncode == 0:
        return "{} --set-dns-seeds accepted an inherited Litecoin seed hostname".format(
            PUBLIC_LAUNCH_MANIFEST_TOOL.relative_to(ROOT_DIR)
        )
    if "invalid DNS seed hostname" not in unsafe_dns_result.stderr:
        return "{} --set-dns-seeds did not explain inherited seed hostname rejection".format(
            PUBLIC_LAUNCH_MANIFEST_TOOL.relative_to(ROOT_DIR)
        )

    for rejected_seed, description in (
        ("zkcoinseed", "single-label DNS seed hostname"),
        ("a" * 64 + ".zkcoin.net", "overlong DNS seed label"),
        ("seed.zkcoin.123", "numeric final-label DNS seed hostname"),
        ("seed.zkcoin.example", "reserved DNS seed suffix"),
        ("seed.zkcoin.invalid", "reserved DNS seed suffix"),
        ("seed.zkcoin.local", "local-use DNS seed suffix"),
        ("seed.zkcoin.localhost", "reserved DNS seed suffix"),
        ("seed.zkcoin.test", "reserved DNS seed suffix"),
    ):
        invalid_dns_shape_result = subprocess.run(
            [
                sys.executable,
                str(PUBLIC_LAUNCH_MANIFEST_TOOL),
                "--set-dns-seeds",
                "main",
                rejected_seed,
                str(PUBLIC_LAUNCH_MANIFEST),
            ],
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        if invalid_dns_shape_result.returncode == 0:
            return "{} --set-dns-seeds accepted a {}".format(
                PUBLIC_LAUNCH_MANIFEST_TOOL.relative_to(ROOT_DIR),
                description,
            )
        if "invalid DNS seed hostname" not in invalid_dns_shape_result.stderr:
            return "{} --set-dns-seeds did not explain {} rejection".format(
                PUBLIC_LAUNCH_MANIFEST_TOOL.relative_to(ROOT_DIR),
                description,
            )

    identity_result = subprocess.run(
        [
            sys.executable,
            str(PUBLIC_LAUNCH_MANIFEST_TOOL),
            "--set-identity",
            "main",
            "fa,bf,b5,d9",
            "19445",
            "75",
            "76",
            "77",
            "178",
            "04202431",
            "04202432",
            "zk",
            "zkmweb",
            str(PUBLIC_LAUNCH_MANIFEST),
        ],
        check=False,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    if identity_result.returncode != 0:
        return "{} --set-identity failed: {}".format(
            PUBLIC_LAUNCH_MANIFEST_TOOL.relative_to(ROOT_DIR),
            identity_result.stderr.strip() or identity_result.stdout.strip() or "no output",
        )
    try:
        identity_manifest = json.loads(identity_result.stdout)
    except json.JSONDecodeError as exc:
        return "{} --set-identity did not emit JSON: {}".format(
            PUBLIC_LAUNCH_MANIFEST_TOOL.relative_to(ROOT_DIR),
            exc,
        )
    identity = identity_manifest["networks"]["main"]["public_network_identity"]
    if identity["message_start"] != [250, 191, 181, 217]:
        return "{} --set-identity did not update message start".format(
            PUBLIC_LAUNCH_MANIFEST_TOOL.relative_to(ROOT_DIR)
        )
    if identity["base58_prefixes"]["ext_public_key"] != [4, 32, 36, 49]:
        return "{} --set-identity did not parse compact extended public key bytes".format(
            PUBLIC_LAUNCH_MANIFEST_TOOL.relative_to(ROOT_DIR)
        )
    identity_blockers = {
        blocker.get("id")
        for blocker in identity_manifest.get("blockers", [])
        if isinstance(blocker, dict)
    }
    if "main.public_network_identity" in identity_blockers:
        return "{} --set-identity did not remove the resolved main public identity blocker".format(
            PUBLIC_LAUNCH_MANIFEST_TOOL.relative_to(ROOT_DIR)
        )
    if "main.dns_seeds" not in identity_blockers:
        return "{} --set-identity removed unrelated DNS seed blockers".format(
            PUBLIC_LAUNCH_MANIFEST_TOOL.relative_to(ROOT_DIR)
        )

    with tempfile.TemporaryDirectory() as temp_dir:
        snapshot_auxpow_identity_path = Path(temp_dir) / "snapshot-auxpow-resolved.json"
        snapshot_auxpow_identity_path.write_text(json.dumps(snapshot_auxpow_manifest), encoding="utf8")
        identity_next_manifest_result = subprocess.run(
            [
                sys.executable,
                str(PUBLIC_LAUNCH_MANIFEST_TOOL),
                "--set-identity",
                "main",
                "fa,bf,b5,d9",
                "19445",
                "75",
                "76",
                "77",
                "178",
                "04202431",
                "04202432",
                "zk",
                "zkmweb",
                str(snapshot_auxpow_identity_path),
            ],
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        if identity_next_manifest_result.returncode != 0:
            return "{} --set-identity failed after resolving snapshot and AuxPoW blockers: {}".format(
                PUBLIC_LAUNCH_MANIFEST_TOOL.relative_to(ROOT_DIR),
                identity_next_manifest_result.stderr.strip()
                or identity_next_manifest_result.stdout.strip()
                or "no output",
            )
        try:
            identity_next_manifest = json.loads(identity_next_manifest_result.stdout)
        except json.JSONDecodeError as exc:
            return "{} --set-identity after snapshot and AuxPoW did not emit JSON: {}".format(
                PUBLIC_LAUNCH_MANIFEST_TOOL.relative_to(ROOT_DIR),
                exc,
            )
        identity_manifest_path = Path(temp_dir) / "identity-resolved-manifest.json"
        identity_manifest_path.write_text(json.dumps(identity_next_manifest), encoding="utf8")
        identity_next_action_result = subprocess.run(
            [
                sys.executable,
                str(PUBLIC_LAUNCH_MANIFEST_TOOL),
                "--next-action",
                str(identity_manifest_path),
            ],
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        if identity_next_action_result.returncode != 0:
            return "{} --next-action failed after resolving the public identity blocker: {}".format(
                PUBLIC_LAUNCH_MANIFEST_TOOL.relative_to(ROOT_DIR),
                identity_next_action_result.stderr.strip()
                or identity_next_action_result.stdout.strip()
                or "no output",
            )
        if "next blocker: main.dns_seeds" not in identity_next_action_result.stdout:
            return "{} --next-action did not advance to the DNS seed blocker".format(
                PUBLIC_LAUNCH_MANIFEST_TOOL.relative_to(ROOT_DIR)
            )
        if "--check-dns-seeds main <seed1.hostname>,<seed2.hostname>" not in identity_next_action_result.stdout:
            return "{} --next-action did not print the DNS seed candidate check command".format(
                PUBLIC_LAUNCH_MANIFEST_TOOL.relative_to(ROOT_DIR)
            )
        if "--set-dns-seeds main <seed1.hostname>,<seed2.hostname>" not in identity_next_action_result.stdout:
            return "{} --next-action did not print the DNS seed update command".format(
                PUBLIC_LAUNCH_MANIFEST_TOOL.relative_to(ROOT_DIR)
            )
        if "  - check command: contrib/devtools/zkcoin_public_launch_profile.py --check-dns-seeds main <seed1.hostname>,<seed2.hostname>" not in identity_next_action_result.stdout:
            return "{} --next-action did not print a copyable DNS seed check command line".format(
                PUBLIC_LAUNCH_MANIFEST_TOOL.relative_to(ROOT_DIR)
            )
        if "  - apply command: contrib/devtools/zkcoin_public_launch_profile.py --set-dns-seeds main <seed1.hostname>,<seed2.hostname>" not in identity_next_action_result.stdout:
            return "{} --next-action did not print a copyable DNS seed apply command line".format(
                PUBLIC_LAUNCH_MANIFEST_TOOL.relative_to(ROOT_DIR)
            )

    check_identity_result = subprocess.run(
        [
            sys.executable,
            str(PUBLIC_LAUNCH_MANIFEST_TOOL),
            "--check-identity",
            "main",
            "fa,bf,b5,d9",
            "19445",
            "75",
            "76",
            "77",
            "178",
            "04202431",
            "04202432",
            "zk",
            "zkmweb",
            str(PUBLIC_LAUNCH_MANIFEST),
        ],
        check=False,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    if check_identity_result.returncode != 0:
        return "{} --check-identity failed: {}".format(
            PUBLIC_LAUNCH_MANIFEST_TOOL.relative_to(ROOT_DIR),
            check_identity_result.stderr.strip() or check_identity_result.stdout.strip() or "no output",
        )
    for expected in (
        "Public identity candidate verified for main.",
        "message start: 250,191,181,217",
        "default port: 19445",
        "extended public key prefix: 04,20,24,31",
        "bech32 HRP: zk",
        "MWEB HRP: zkmweb",
        "apply command: contrib/devtools/zkcoin_public_launch_profile.py --set-identity main 250,191,181,217 19445 75 76 77 178 04202431 04202432 zk zkmweb --in-place contrib/devtools/zkcoin_public_launch_profile_manifest.json",
        "remaining blockers after applying candidate: 7",
        "remaining blockers on main after applying candidate: 3",
        "remaining blocked fields after applying candidate: 36",
        "remaining blocked fields on main after applying candidate: 13",
        "next action command after applying candidate: contrib/devtools/zkcoin_public_launch_profile.py --next-action contrib/devtools/zkcoin_public_launch_profile_manifest.json",
        "readiness summary command after applying candidate: contrib/devtools/zkcoin_public_launch_profile.py --readiness-summary contrib/devtools/zkcoin_public_launch_profile_manifest.json",
        "network readiness summary command after applying candidate: contrib/devtools/zkcoin_public_launch_profile.py --network-readiness-summary main contrib/devtools/zkcoin_public_launch_profile_manifest.json",
        "blocker type readiness summary command after applying candidate: contrib/devtools/zkcoin_public_launch_profile.py --blocker-type-readiness-summary public_network_identity contrib/devtools/zkcoin_public_launch_profile_manifest.json",
        "next blocker after applying candidate: main.litecoin_snapshot",
        "next template command after applying candidate: contrib/devtools/zkcoin_public_launch_profile.py --snapshot-audit-template main contrib/devtools/zkcoin_public_launch_profile_manifest.json",
        "next check command after applying candidate: contrib/devtools/zkcoin_public_launch_profile.py --check-snapshot-audit main <snapshot_audit.json> contrib/devtools/zkcoin_public_launch_profile_manifest.json",
        "next apply command after applying candidate: contrib/devtools/zkcoin_public_launch_profile.py --set-snapshot-audit main <snapshot_audit.json> --in-place contrib/devtools/zkcoin_public_launch_profile_manifest.json",
        "next network readiness summary command after applying candidate: contrib/devtools/zkcoin_public_launch_profile.py --network-readiness-summary main contrib/devtools/zkcoin_public_launch_profile_manifest.json",
        "next blocker type readiness summary command after applying candidate: contrib/devtools/zkcoin_public_launch_profile.py --blocker-type-readiness-summary litecoin_snapshot contrib/devtools/zkcoin_public_launch_profile_manifest.json",
        "next blocker readiness summary command after applying candidate: contrib/devtools/zkcoin_public_launch_profile.py --blocker-readiness-summary main.litecoin_snapshot contrib/devtools/zkcoin_public_launch_profile_manifest.json",
    ):
        if expected not in check_identity_result.stdout:
            return "{} --check-identity did not print {}".format(
                PUBLIC_LAUNCH_MANIFEST_TOOL.relative_to(ROOT_DIR),
                expected,
            )

    check_identity_in_place_result = subprocess.run(
        [
            sys.executable,
            str(PUBLIC_LAUNCH_MANIFEST_TOOL),
            "--check-identity",
            "main",
            "fa,bf,b5,d9",
            "19445",
            "75",
            "76",
            "77",
            "178",
            "04202431",
            "04202432",
            "zk",
            "zkmweb",
            "--in-place",
            str(PUBLIC_LAUNCH_MANIFEST),
        ],
        check=False,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    if check_identity_in_place_result.returncode == 0:
        return "{} --check-identity accepted --in-place".format(
            PUBLIC_LAUNCH_MANIFEST_TOOL.relative_to(ROOT_DIR)
        )
    if "--check-identity does not write the manifest" not in check_identity_in_place_result.stderr:
        return "{} --check-identity did not explain --in-place rejection".format(
            PUBLIC_LAUNCH_MANIFEST_TOOL.relative_to(ROOT_DIR)
        )

    unsafe_check_identity_result = subprocess.run(
        [
            sys.executable,
            str(PUBLIC_LAUNCH_MANIFEST_TOOL),
            "--check-identity",
            "main",
            "fb,c0,b6,db",
            "19445",
            "75",
            "76",
            "77",
            "178",
            "04202431",
            "04202432",
            "zk",
            "zkmweb",
            str(PUBLIC_LAUNCH_MANIFEST),
        ],
        check=False,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    if unsafe_check_identity_result.returncode == 0:
        return "{} --check-identity accepted an inherited Litecoin message start".format(
            PUBLIC_LAUNCH_MANIFEST_TOOL.relative_to(ROOT_DIR)
        )
    if "non-Litecoin non-printable magic bytes" not in unsafe_check_identity_result.stderr:
        return "{} --check-identity did not explain inherited message-start rejection".format(
            PUBLIC_LAUNCH_MANIFEST_TOOL.relative_to(ROOT_DIR)
        )

    unsafe_identity_result = subprocess.run(
        [
            sys.executable,
            str(PUBLIC_LAUNCH_MANIFEST_TOOL),
            "--set-identity",
            "main",
            "fb,c0,b6,db",
            "19445",
            "75",
            "76",
            "77",
            "178",
            "04202431",
            "04202432",
            "zk",
            "zkmweb",
            str(PUBLIC_LAUNCH_MANIFEST),
        ],
        check=False,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    if unsafe_identity_result.returncode == 0:
        return "{} --set-identity accepted an inherited Litecoin message start".format(
            PUBLIC_LAUNCH_MANIFEST_TOOL.relative_to(ROOT_DIR)
        )
    if "non-Litecoin non-printable magic bytes" not in unsafe_identity_result.stderr:
        return "{} --set-identity did not explain inherited message-start rejection".format(
            PUBLIC_LAUNCH_MANIFEST_TOOL.relative_to(ROOT_DIR)
        )

    for bech32_hrp, mweb_hrp, description in (
        ("z" * 84, "zkmweb", "overlong Bech32 HRP"),
        ("zk", "m" * 84, "overlong MWEB HRP"),
    ):
        overlong_hrp_result = subprocess.run(
            [
                sys.executable,
                str(PUBLIC_LAUNCH_MANIFEST_TOOL),
                "--set-identity",
                "main",
                "fa,bf,b5,d9",
                "19445",
                "75",
                "76",
                "77",
                "178",
                "04202431",
                "04202432",
                bech32_hrp,
                mweb_hrp,
                str(PUBLIC_LAUNCH_MANIFEST),
            ],
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        if overlong_hrp_result.returncode == 0:
            return "{} --set-identity accepted an {}".format(
                PUBLIC_LAUNCH_MANIFEST_TOOL.relative_to(ROOT_DIR),
                description,
            )
        if "at most 83 characters" not in overlong_hrp_result.stderr:
            return "{} --set-identity did not explain {} rejection".format(
                PUBLIC_LAUNCH_MANIFEST_TOOL.relative_to(ROOT_DIR),
                description,
            )

    complete_manifest = json.loads(json.dumps(manifest))
    ready_profiles = {
        "main": {
            "snapshot": {
                "height": 321,
                "block_hash": "11" * 32,
                "import_hash": "22" * 32,
                "audit": {
                    "snapshot_hash": "aa" * 32,
                    "coins": 4,
                    "base_nchaintx": 11,
                    "source_chain": "main",
                    "snapshot_file_size": 8,
                    "snapshot_file_sha256": "aa" * 32,
                    "snapshot_file": "/srv/snapshots/ltc-main.dat",
                    "total_amount": "50.00000000",
                },
            },
            "chain_id": 0x5001,
            "identity": {
                "message_start": [250, 191, 181, 217],
                "default_port": 19445,
                "dns_seeds": ["seed1.zkcoin.net"],
                "base58_prefixes": {
                    "pubkey_address": [75],
                    "script_address": [76],
                    "script_address2": [77],
                    "secret_key": [178],
                    "ext_public_key": [4, 32, 36, 49],
                    "ext_secret_key": [4, 32, 36, 50],
                },
                "bech32_hrp": "zk",
                "mweb_hrp": "zkmweb",
            },
        },
        "testnet": {
            "snapshot": {
                "height": 654,
                "block_hash": "33" * 32,
                "import_hash": "44" * 32,
                "audit": {
                    "snapshot_hash": "bb" * 32,
                    "coins": 5,
                    "base_nchaintx": 12,
                    "source_chain": "test",
                    "snapshot_file_size": 8,
                    "snapshot_file_sha256": "bb" * 32,
                    "snapshot_file": "/srv/snapshots/ltc-testnet.dat",
                    "total_amount": "25.00000000",
                },
            },
            "chain_id": 0x5002,
            "identity": {
                "message_start": [250, 191, 181, 218],
                "default_port": 29445,
                "dns_seeds": ["seed1.test.zkcoin.net"],
                "base58_prefixes": {
                    "pubkey_address": [85],
                    "script_address": [86],
                    "script_address2": [87],
                    "secret_key": [188],
                    "ext_public_key": [4, 32, 36, 51],
                    "ext_secret_key": [4, 32, 36, 52],
                },
                "bech32_hrp": "tzk",
                "mweb_hrp": "tzkmweb",
            },
        },
    }
    for network, values in ready_profiles.items():
        profile = complete_manifest["networks"][network]
        profile["litecoin_snapshot"].update(values["snapshot"])
        profile["auxpow"]["chain_id"] = values["chain_id"]
        profile["public_network_identity"].update(values["identity"])
    complete_manifest["blockers"] = []

    with tempfile.TemporaryDirectory() as temp_dir:
        unresolved_path = Path(temp_dir) / "unresolved.json"
        unresolved_path.write_text(json.dumps(manifest), encoding="utf8")
        unresolved_result = subprocess.run(
            [
                sys.executable,
                str(PUBLIC_LAUNCH_MANIFEST_TOOL),
                "--mark-ready",
                "--in-place",
                str(unresolved_path),
            ],
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        if unresolved_result.returncode == 0:
            return "{} --mark-ready accepted unresolved production launch fields".format(
                PUBLIC_LAUNCH_MANIFEST_TOOL.relative_to(ROOT_DIR)
            )
        if "cannot mark launch profile ready" not in unresolved_result.stderr:
            return "{} --mark-ready did not explain unresolved production launch fields".format(
                PUBLIC_LAUNCH_MANIFEST_TOOL.relative_to(ROOT_DIR)
            )
        if "main.litecoin_snapshot.height" not in unresolved_result.stderr:
            return "{} --mark-ready did not report unresolved snapshot fields".format(
                PUBLIC_LAUNCH_MANIFEST_TOOL.relative_to(ROOT_DIR)
            )
        unresolved_after = json.loads(unresolved_path.read_text(encoding="utf8"))
        if unresolved_after.get("status") != "blocked":
            return "{} --mark-ready --in-place wrote an unresolved manifest".format(
                PUBLIC_LAUNCH_MANIFEST_TOOL.relative_to(ROOT_DIR)
            )

        complete_path = Path(temp_dir) / "complete.json"
        complete_path.write_text(json.dumps(complete_manifest), encoding="utf8")
        complete_next_result = subprocess.run(
            [
                sys.executable,
                str(PUBLIC_LAUNCH_MANIFEST_TOOL),
                "--next-action",
                str(complete_path),
            ],
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        if complete_next_result.returncode != 0:
            return "{} --next-action failed for a complete blocked manifest".format(
                PUBLIC_LAUNCH_MANIFEST_TOOL.relative_to(ROOT_DIR)
            )
        if "--mark-ready --in-place" not in complete_next_result.stdout:
            return "{} --next-action did not point complete blocked manifests at --mark-ready".format(
                PUBLIC_LAUNCH_MANIFEST_TOOL.relative_to(ROOT_DIR)
            )
        if str(complete_path) not in complete_next_result.stdout:
            return "{} --next-action did not preserve the checked complete manifest path".format(
                PUBLIC_LAUNCH_MANIFEST_TOOL.relative_to(ROOT_DIR)
            )

        complete_plan_result = subprocess.run(
            [
                sys.executable,
                str(PUBLIC_LAUNCH_MANIFEST_TOOL),
                "--action-plan",
                str(complete_path),
            ],
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        if complete_plan_result.returncode != 0:
            return "{} --action-plan failed for a complete blocked manifest".format(
                PUBLIC_LAUNCH_MANIFEST_TOOL.relative_to(ROOT_DIR)
            )
        if "1. mark-ready" not in complete_plan_result.stdout:
            return "{} --action-plan did not point complete blocked manifests at --mark-ready".format(
                PUBLIC_LAUNCH_MANIFEST_TOOL.relative_to(ROOT_DIR)
            )
        if str(complete_path) not in complete_plan_result.stdout:
            return "{} --action-plan did not preserve the checked complete manifest path".format(
                PUBLIC_LAUNCH_MANIFEST_TOOL.relative_to(ROOT_DIR)
            )

        complete_summary_result = subprocess.run(
            [
                sys.executable,
                str(PUBLIC_LAUNCH_MANIFEST_TOOL),
                "--readiness-summary",
                str(complete_path),
            ],
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        if complete_summary_result.returncode != 0:
            return "{} --readiness-summary failed for a complete blocked manifest".format(
                PUBLIC_LAUNCH_MANIFEST_TOOL.relative_to(ROOT_DIR)
            )
        for expected in (
            "  - status: blocked",
            "  - ready for chainparams: no",
            "  - action plan command: contrib/devtools/zkcoin_public_launch_profile.py --action-plan",
            "  - next action command: contrib/devtools/zkcoin_public_launch_profile.py --next-action",
            "  - readiness summary command: contrib/devtools/zkcoin_public_launch_profile.py --readiness-summary",
            "  - status JSON command: contrib/devtools/zkcoin_public_launch_profile.py --status-json",
            "  - blocked networks: none",
            "  - ready networks: main, testnet",
            "  - blocked networks by blocker type: litecoin_snapshot=none; auxpow_chain_id=none; public_network_identity=none; dns_seeds=none",
            "  - ready networks by blocker type: litecoin_snapshot=main, testnet; auxpow_chain_id=main, testnet; public_network_identity=main, testnet; dns_seeds=main, testnet",
            "  - unresolved blockers: 0",
            "  - unresolved blockers by network: main=0, testnet=0",
            "  - blocked fields: 0",
            "  - blocked fields by network: main=0, testnet=0",
            "  - next blockers by network: main=none, testnet=none",
            "  - next blocker fields by network: main=0, testnet=0",
            "  - next template commands by network: main=none; testnet=none",
            "  - next check commands by network: main=none; testnet=none",
            "  - next apply commands by network: main=none; testnet=none",
            "  - network readiness summary commands by network: main=contrib/devtools/zkcoin_public_launch_profile.py --network-readiness-summary main",
            "  - next step: mark-ready",
            "--mark-ready --in-place",
        ):
            if expected not in complete_summary_result.stdout:
                return "{} --readiness-summary did not print complete blocked manifest guidance {}".format(
                    PUBLIC_LAUNCH_MANIFEST_TOOL.relative_to(ROOT_DIR),
                    expected,
                )

        complete_status_result = subprocess.run(
            [
                sys.executable,
                str(PUBLIC_LAUNCH_MANIFEST_TOOL),
                "--status-json",
                str(complete_path),
            ],
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        if complete_status_result.returncode != 0:
            return "{} --status-json failed for a complete blocked manifest".format(
                PUBLIC_LAUNCH_MANIFEST_TOOL.relative_to(ROOT_DIR)
            )
        try:
            complete_status = json.loads(complete_status_result.stdout)
        except json.JSONDecodeError as exc:
            return "{} --status-json complete manifest output was not JSON: {}".format(
                PUBLIC_LAUNCH_MANIFEST_TOOL.relative_to(ROOT_DIR),
                exc,
            )
        schema_version_error = require_status_json_schema_version(complete_status)
        if schema_version_error:
            return schema_version_error
        if complete_status.get("unresolved_blocker_count") != 0:
            return "{} --status-json reported blockers for a complete blocked manifest".format(
                PUBLIC_LAUNCH_MANIFEST_TOOL.relative_to(ROOT_DIR)
            )
        if complete_status.get("unresolved_blocker_counts_by_network") != {"main": 0, "testnet": 0}:
            return "{} --status-json counted network blockers for a complete blocked manifest".format(
                PUBLIC_LAUNCH_MANIFEST_TOOL.relative_to(ROOT_DIR)
            )
        if complete_status.get("unresolved_blockers_by_network") != {"main": [], "testnet": []}:
            return "{} --status-json reported network blockers for a complete blocked manifest".format(
                PUBLIC_LAUNCH_MANIFEST_TOOL.relative_to(ROOT_DIR)
            )
        if complete_status.get("unresolved_blockers_by_blocker_type") != empty_blockers_by_blocker_type:
            return "{} --status-json reported blocker-type blockers for a complete blocked manifest".format(
                PUBLIC_LAUNCH_MANIFEST_TOOL.relative_to(ROOT_DIR)
            )
        if complete_status.get("unresolved_blocker_counts_by_blocker_type") != empty_blocker_counts_by_blocker_type:
            return "{} --status-json counted blocker-type blockers for a complete blocked manifest".format(
                PUBLIC_LAUNCH_MANIFEST_TOOL.relative_to(ROOT_DIR)
            )
        if complete_status.get("unresolved_blocker_counts_by_network_and_blocker_type") != empty_counts_by_network_and_blocker_type:
            return "{} --status-json counted network blocker-type blockers for a complete blocked manifest".format(
                PUBLIC_LAUNCH_MANIFEST_TOOL.relative_to(ROOT_DIR)
            )
        if complete_status.get("unresolved_blockers_by_network_and_blocker_type") != empty_items_by_network_and_blocker_type:
            return "{} --status-json reported network blocker-type blockers for a complete blocked manifest".format(
                PUBLIC_LAUNCH_MANIFEST_TOOL.relative_to(ROOT_DIR)
            )
        if complete_status.get("blocked_network_count") != 0 or complete_status.get("blocked_networks") != []:
            return "{} --status-json reported blocked networks for a complete blocked manifest".format(
                PUBLIC_LAUNCH_MANIFEST_TOOL.relative_to(ROOT_DIR)
            )
        if complete_status.get("ready_network_count") != 2 or complete_status.get("ready_networks") != ["main", "testnet"]:
            return "{} --status-json did not summarize complete ready networks".format(
                PUBLIC_LAUNCH_MANIFEST_TOOL.relative_to(ROOT_DIR)
            )
        if complete_status.get("blocked_blocker_type_count") != 0 or complete_status.get("blocked_blocker_types") != []:
            return "{} --status-json reported blocked blocker types for a complete blocked manifest".format(
                PUBLIC_LAUNCH_MANIFEST_TOOL.relative_to(ROOT_DIR)
            )
        if (
            complete_status.get("ready_blocker_type_count") != 4
            or complete_status.get("ready_blocker_types") != expected_blocker_type_order
        ):
            return "{} --status-json did not summarize complete ready blocker types".format(
                PUBLIC_LAUNCH_MANIFEST_TOOL.relative_to(ROOT_DIR)
            )
        if complete_status.get("blocked_blocker_types_by_network") != empty_blocker_types_by_network:
            return "{} --status-json reported blocked blocker types by network for a complete blocked manifest".format(
                PUBLIC_LAUNCH_MANIFEST_TOOL.relative_to(ROOT_DIR)
            )
        if complete_status.get("blocked_blocker_type_counts_by_network") != empty_blocker_type_counts_by_network:
            return "{} --status-json counted blocked blocker types by network for a complete blocked manifest".format(
                PUBLIC_LAUNCH_MANIFEST_TOOL.relative_to(ROOT_DIR)
            )
        if complete_status.get("ready_blocker_types_by_network") != expected_blocker_types_by_network:
            return "{} --status-json did not summarize complete ready blocker types by network".format(
                PUBLIC_LAUNCH_MANIFEST_TOOL.relative_to(ROOT_DIR)
            )
        if complete_status.get("ready_blocker_type_counts_by_network") != expected_blocker_type_counts_by_network:
            return "{} --status-json did not count complete ready blocker types by network".format(
                PUBLIC_LAUNCH_MANIFEST_TOOL.relative_to(ROOT_DIR)
            )
        if complete_status.get("blocked_networks_by_blocker_type") != empty_networks_by_blocker_type:
            return "{} --status-json reported blocked networks by blocker type for a complete blocked manifest".format(
                PUBLIC_LAUNCH_MANIFEST_TOOL.relative_to(ROOT_DIR)
            )
        if complete_status.get("blocked_network_counts_by_blocker_type") != empty_network_counts_by_blocker_type:
            return "{} --status-json counted blocked networks by blocker type for a complete blocked manifest".format(
                PUBLIC_LAUNCH_MANIFEST_TOOL.relative_to(ROOT_DIR)
            )
        if complete_status.get("ready_networks_by_blocker_type") != expected_networks_by_blocker_type:
            return "{} --status-json did not summarize complete ready networks by blocker type".format(
                PUBLIC_LAUNCH_MANIFEST_TOOL.relative_to(ROOT_DIR)
            )
        if complete_status.get("ready_network_counts_by_blocker_type") != expected_network_counts_by_blocker_type:
            return "{} --status-json did not count complete ready networks by blocker type".format(
                PUBLIC_LAUNCH_MANIFEST_TOOL.relative_to(ROOT_DIR)
            )
        if complete_status.get("action_count") != 1:
            return "{} --status-json did not count complete blocked manifest actions".format(
                PUBLIC_LAUNCH_MANIFEST_TOOL.relative_to(ROOT_DIR)
            )
        complete_expected_action_commands = [
            {command_field: action.get(command_field) for command_field in command_fields}
            for action in complete_status.get("actions", [])
        ]
        if (
            complete_status.get("action_ids") != ["mark-ready"]
            or complete_status.get("action_kinds") != ["mark-ready"]
            or complete_status.get("action_steps") != [1]
            or complete_status.get("action_networks") != [None]
            or complete_status.get("action_blocker_types") != [None]
            or complete_status.get("action_field_counts") != [None]
            or complete_status.get("action_commands") != complete_expected_action_commands
            or complete_status.get("action_command_count") != 1
            or complete_status.get("action_command_keys") != [["command"]]
            or complete_status.get("action_command_key_counts") != [1]
            or complete_status.get("action_command_values") != [
                [complete_status.get("action_commands", [{}])[0].get("command")]
            ]
            or complete_status.get("action_command_value_counts") != [1]
            or complete_status.get("action_command_pairs") != [
                [
                    {
                        "key": "command",
                        "value": complete_status.get("action_commands", [{}])[0].get("command"),
                    }
                ]
            ]
            or complete_status.get("action_command_pair_counts") != [1]
        ):
            return "{} --status-json did not expose complete blocked manifest action aliases".format(
                PUBLIC_LAUNCH_MANIFEST_TOOL.relative_to(ROOT_DIR)
            )
        if complete_status.get("later_actions") != [] or complete_status.get("later_action_count") != 0:
            return "{} --status-json reported later actions for a complete blocked manifest".format(
                PUBLIC_LAUNCH_MANIFEST_TOOL.relative_to(ROOT_DIR)
            )
        if (
            complete_status.get("later_action_ids") != []
            or complete_status.get("later_action_kinds") != []
            or complete_status.get("later_action_steps") != []
            or complete_status.get("later_action_networks") != []
            or complete_status.get("later_action_blocker_types") != []
            or complete_status.get("later_action_field_counts") != []
        ):
            return "{} --status-json reported later action list aliases for a complete blocked manifest".format(
                PUBLIC_LAUNCH_MANIFEST_TOOL.relative_to(ROOT_DIR)
            )
        if complete_status.get("later_commands") != [] or complete_status.get("later_command_count") != 0:
            return "{} --status-json reported later commands for a complete blocked manifest".format(
                PUBLIC_LAUNCH_MANIFEST_TOOL.relative_to(ROOT_DIR)
            )
        if complete_status.get("later_command_keys") != []:
            return "{} --status-json reported later command keys for a complete blocked manifest".format(
                PUBLIC_LAUNCH_MANIFEST_TOOL.relative_to(ROOT_DIR)
            )
        if complete_status.get("later_command_key_counts") != []:
            return "{} --status-json reported later command key counts for a complete blocked manifest".format(
                PUBLIC_LAUNCH_MANIFEST_TOOL.relative_to(ROOT_DIR)
            )
        if complete_status.get("later_command_values") != []:
            return "{} --status-json reported later command values for a complete blocked manifest".format(
                PUBLIC_LAUNCH_MANIFEST_TOOL.relative_to(ROOT_DIR)
            )
        if complete_status.get("later_command_value_counts") != []:
            return "{} --status-json reported later command value counts for a complete blocked manifest".format(
                PUBLIC_LAUNCH_MANIFEST_TOOL.relative_to(ROOT_DIR)
            )
        if complete_status.get("later_command_pairs") != []:
            return "{} --status-json reported later command pairs for a complete blocked manifest".format(
                PUBLIC_LAUNCH_MANIFEST_TOOL.relative_to(ROOT_DIR)
            )
        if complete_status.get("later_command_pair_counts") != []:
            return "{} --status-json reported later command pair counts for a complete blocked manifest".format(
                PUBLIC_LAUNCH_MANIFEST_TOOL.relative_to(ROOT_DIR)
            )
        if complete_status.get("action_counts_by_network") != {"main": 0, "testnet": 0}:
            return "{} --status-json counted network actions for a complete blocked manifest".format(
                PUBLIC_LAUNCH_MANIFEST_TOOL.relative_to(ROOT_DIR)
            )
        if complete_status.get("actions_by_network") != {"main": [], "testnet": []}:
            return "{} --status-json reported network actions for a complete blocked manifest".format(
                PUBLIC_LAUNCH_MANIFEST_TOOL.relative_to(ROOT_DIR)
            )
        empty_actions_by_blocker_type = {
            "litecoin_snapshot": [],
            "auxpow_chain_id": [],
            "public_network_identity": [],
            "dns_seeds": [],
        }
        empty_action_counts_by_blocker_type = {
            "litecoin_snapshot": 0,
            "auxpow_chain_id": 0,
            "public_network_identity": 0,
            "dns_seeds": 0,
        }
        if complete_status.get("action_counts_by_blocker_type") != empty_action_counts_by_blocker_type:
            return "{} --status-json counted blocker-type actions for a complete blocked manifest".format(
                PUBLIC_LAUNCH_MANIFEST_TOOL.relative_to(ROOT_DIR)
            )
        if complete_status.get("actions_by_blocker_type") != empty_actions_by_blocker_type:
            return "{} --status-json reported blocker-type actions for a complete blocked manifest".format(
                PUBLIC_LAUNCH_MANIFEST_TOOL.relative_to(ROOT_DIR)
            )
        if complete_status.get("action_counts_by_network_and_blocker_type") != empty_counts_by_network_and_blocker_type:
            return "{} --status-json counted network blocker-type actions for a complete blocked manifest".format(
                PUBLIC_LAUNCH_MANIFEST_TOOL.relative_to(ROOT_DIR)
            )
        if complete_status.get("actions_by_network_and_blocker_type") != empty_items_by_network_and_blocker_type:
            return "{} --status-json reported network blocker-type actions for a complete blocked manifest".format(
                PUBLIC_LAUNCH_MANIFEST_TOOL.relative_to(ROOT_DIR)
            )
        if complete_status.get("next_actions_by_network_and_blocker_type") != empty_next_by_network_and_blocker_type:
            return "{} --status-json reported network blocker-type next actions for a complete blocked manifest".format(
                PUBLIC_LAUNCH_MANIFEST_TOOL.relative_to(ROOT_DIR)
            )
        if complete_status.get("next_commands_by_network_and_blocker_type") != empty_next_by_network_and_blocker_type:
            return "{} --status-json reported network blocker-type next commands for a complete blocked manifest".format(
                PUBLIC_LAUNCH_MANIFEST_TOOL.relative_to(ROOT_DIR)
            )
        if complete_status.get("next_blocker_commands_by_network_and_blocker_type") != empty_next_by_network_and_blocker_type:
            return "{} --status-json reported network blocker-type next blocker command aliases for a complete blocked manifest".format(
                PUBLIC_LAUNCH_MANIFEST_TOOL.relative_to(ROOT_DIR)
            )
        if complete_status.get("next_blocked_field_groups_by_network_and_blocker_type") != empty_next_by_network_and_blocker_type:
            return "{} --status-json reported network blocker-type next groups for a complete blocked manifest".format(
                PUBLIC_LAUNCH_MANIFEST_TOOL.relative_to(ROOT_DIR)
            )
        if complete_status.get("next_blocker_field_groups_by_network_and_blocker_type") != empty_next_by_network_and_blocker_type:
            return "{} --status-json reported network blocker-type next group aliases for a complete blocked manifest".format(
                PUBLIC_LAUNCH_MANIFEST_TOOL.relative_to(ROOT_DIR)
            )
        if complete_status.get("next_blockers_by_network_and_blocker_type") != empty_next_by_network_and_blocker_type:
            return "{} --status-json reported network blocker-type next blockers for a complete blocked manifest".format(
                PUBLIC_LAUNCH_MANIFEST_TOOL.relative_to(ROOT_DIR)
            )
        if complete_status.get("next_blocked_fields_by_network_and_blocker_type") != empty_items_by_network_and_blocker_type:
            return "{} --status-json reported network blocker-type next fields for a complete blocked manifest".format(
                PUBLIC_LAUNCH_MANIFEST_TOOL.relative_to(ROOT_DIR)
            )
        if complete_status.get("next_blocker_fields_by_network_and_blocker_type") != empty_items_by_network_and_blocker_type:
            return "{} --status-json reported network blocker-type next field aliases for a complete blocked manifest".format(
                PUBLIC_LAUNCH_MANIFEST_TOOL.relative_to(ROOT_DIR)
            )
        if complete_status.get("next_blocked_field_counts_by_network_and_blocker_type") != empty_counts_by_network_and_blocker_type:
            return "{} --status-json counted network blocker-type next fields for a complete blocked manifest".format(
                PUBLIC_LAUNCH_MANIFEST_TOOL.relative_to(ROOT_DIR)
            )
        if complete_status.get("next_blocker_field_counts_by_network_and_blocker_type") != empty_counts_by_network_and_blocker_type:
            return "{} --status-json counted network blocker-type next field aliases for a complete blocked manifest".format(
                PUBLIC_LAUNCH_MANIFEST_TOOL.relative_to(ROOT_DIR)
            )
        if complete_status.get("blocked_field_count") != 0:
            return "{} --status-json reported field-level blockers for a complete blocked manifest".format(
                PUBLIC_LAUNCH_MANIFEST_TOOL.relative_to(ROOT_DIR)
            )
        if complete_status.get("blocked_field_counts_by_network") != {"main": 0, "testnet": 0}:
            return "{} --status-json counted network field blockers for a complete blocked manifest".format(
                PUBLIC_LAUNCH_MANIFEST_TOOL.relative_to(ROOT_DIR)
            )
        if complete_status.get("blocked_fields_by_network") != {"main": [], "testnet": []}:
            return "{} --status-json reported network field blockers for a complete blocked manifest".format(
                PUBLIC_LAUNCH_MANIFEST_TOOL.relative_to(ROOT_DIR)
            )
        if complete_status.get("blocked_fields_by_blocker_type") != empty_blocked_fields_by_blocker_type:
            return "{} --status-json reported blocker-type field blockers for a complete blocked manifest".format(
                PUBLIC_LAUNCH_MANIFEST_TOOL.relative_to(ROOT_DIR)
            )
        if complete_status.get("blocked_field_counts_by_blocker_type") != empty_blocked_field_counts_by_blocker_type:
            return "{} --status-json counted blocker-type field blockers for a complete blocked manifest".format(
                PUBLIC_LAUNCH_MANIFEST_TOOL.relative_to(ROOT_DIR)
            )
        if complete_status.get("blocked_field_counts_by_network_and_blocker_type") != empty_counts_by_network_and_blocker_type:
            return "{} --status-json counted network blocker-type field blockers for a complete blocked manifest".format(
                PUBLIC_LAUNCH_MANIFEST_TOOL.relative_to(ROOT_DIR)
            )
        if complete_status.get("blocked_fields_by_network_and_blocker_type") != empty_items_by_network_and_blocker_type:
            return "{} --status-json reported network blocker-type field blockers for a complete blocked manifest".format(
                PUBLIC_LAUNCH_MANIFEST_TOOL.relative_to(ROOT_DIR)
            )
        if complete_status.get("next_commands_by_network") != {"main": None, "testnet": None}:
            return "{} --status-json reported per-network next commands for a complete blocked manifest".format(
                PUBLIC_LAUNCH_MANIFEST_TOOL.relative_to(ROOT_DIR)
            )
        if complete_status.get("next_blocker_commands_by_network") != {"main": None, "testnet": None}:
            return "{} --status-json reported per-network next blocker command aliases for a complete blocked manifest".format(
                PUBLIC_LAUNCH_MANIFEST_TOOL.relative_to(ROOT_DIR)
            )
        empty_next_by_blocker_type = {
            "litecoin_snapshot": None,
            "auxpow_chain_id": None,
            "public_network_identity": None,
            "dns_seeds": None,
        }
        if complete_status.get("next_actions_by_blocker_type") != empty_next_by_blocker_type:
            return "{} --status-json reported blocker-type next actions for a complete blocked manifest".format(
                PUBLIC_LAUNCH_MANIFEST_TOOL.relative_to(ROOT_DIR)
            )
        if complete_status.get("next_commands_by_blocker_type") != empty_next_by_blocker_type:
            return "{} --status-json reported blocker-type next commands for a complete blocked manifest".format(
                PUBLIC_LAUNCH_MANIFEST_TOOL.relative_to(ROOT_DIR)
            )
        if complete_status.get("next_blocker_commands_by_blocker_type") != empty_next_by_blocker_type:
            return "{} --status-json reported blocker-type next blocker command aliases for a complete blocked manifest".format(
                PUBLIC_LAUNCH_MANIFEST_TOOL.relative_to(ROOT_DIR)
            )
        if complete_status.get("next_blocked_field_groups_by_blocker_type") != empty_next_by_blocker_type:
            return "{} --status-json reported blocker-type next groups for a complete blocked manifest".format(
                PUBLIC_LAUNCH_MANIFEST_TOOL.relative_to(ROOT_DIR)
            )
        if complete_status.get("next_blocker_field_groups_by_blocker_type") != empty_next_by_blocker_type:
            return "{} --status-json reported blocker-type next group aliases for a complete blocked manifest".format(
                PUBLIC_LAUNCH_MANIFEST_TOOL.relative_to(ROOT_DIR)
            )
        if complete_status.get("next_blocker_fields_by_blocker_type") != empty_blocked_fields_by_blocker_type:
            return "{} --status-json reported blocker-type next field aliases for a complete blocked manifest".format(
                PUBLIC_LAUNCH_MANIFEST_TOOL.relative_to(ROOT_DIR)
            )
        if complete_status.get("next_blocker_field_counts_by_blocker_type") != empty_blocked_field_counts_by_blocker_type:
            return "{} --status-json counted blocker-type next field aliases for a complete blocked manifest".format(
                PUBLIC_LAUNCH_MANIFEST_TOOL.relative_to(ROOT_DIR)
            )
        if complete_status.get("blocker_type_progress") != empty_blocker_type_progress:
            return "{} --status-json reported blocker-type progress for a complete blocked manifest".format(
                PUBLIC_LAUNCH_MANIFEST_TOOL.relative_to(ROOT_DIR)
            )
        if complete_status.get("next_blocked_fields_by_network") != {"main": [], "testnet": []}:
            return "{} --status-json reported per-network next fields for a complete blocked manifest".format(
                PUBLIC_LAUNCH_MANIFEST_TOOL.relative_to(ROOT_DIR)
            )
        if complete_status.get("next_blocker_fields_by_network") != {"main": [], "testnet": []}:
            return "{} --status-json reported per-network next field aliases for a complete blocked manifest".format(
                PUBLIC_LAUNCH_MANIFEST_TOOL.relative_to(ROOT_DIR)
            )
        if complete_status.get("next_blocked_field_counts_by_network") != {"main": 0, "testnet": 0}:
            return "{} --status-json counted per-network next fields for a complete blocked manifest".format(
                PUBLIC_LAUNCH_MANIFEST_TOOL.relative_to(ROOT_DIR)
            )
        if complete_status.get("next_blocker_field_counts_by_network") != {"main": 0, "testnet": 0}:
            return "{} --status-json counted per-network next field aliases for a complete blocked manifest".format(
                PUBLIC_LAUNCH_MANIFEST_TOOL.relative_to(ROOT_DIR)
            )
        if complete_status.get("next_blockers_by_network") != {"main": None, "testnet": None}:
            return "{} --status-json reported per-network next blockers for a complete blocked manifest".format(
                PUBLIC_LAUNCH_MANIFEST_TOOL.relative_to(ROOT_DIR)
            )
        if complete_status.get("next_blocker_types_by_network") != {"main": None, "testnet": None}:
            return "{} --status-json reported per-network next blocker types for a complete blocked manifest".format(
                PUBLIC_LAUNCH_MANIFEST_TOOL.relative_to(ROOT_DIR)
            )
        if complete_status.get("next_blocked_field_groups_by_network") != {"main": None, "testnet": None}:
            return "{} --status-json reported per-network next groups for a complete blocked manifest".format(
                PUBLIC_LAUNCH_MANIFEST_TOOL.relative_to(ROOT_DIR)
            )
        if complete_status.get("next_blocker_field_groups_by_network") != {"main": None, "testnet": None}:
            return "{} --status-json reported per-network next group aliases for a complete blocked manifest".format(
                PUBLIC_LAUNCH_MANIFEST_TOOL.relative_to(ROOT_DIR)
            )
        if complete_status.get("network_progress", {}).get("main") != {
            "ready_for_launch_profile": True,
            "unresolved_blocker_count": 0,
            "unresolved_blockers": [],
            "blocked_field_count": 0,
            "blocked_fields": [],
            "next_blocked_field_group": None,
        }:
            return "{} --status-json did not report complete mainnet network progress".format(
                PUBLIC_LAUNCH_MANIFEST_TOOL.relative_to(ROOT_DIR)
            )
        if complete_status.get("network_progress", {}).get("testnet") != {
            "ready_for_launch_profile": True,
            "unresolved_blocker_count": 0,
            "unresolved_blockers": [],
            "blocked_field_count": 0,
            "blocked_fields": [],
            "next_blocked_field_group": None,
        }:
            return "{} --status-json did not report complete testnet network progress".format(
                PUBLIC_LAUNCH_MANIFEST_TOOL.relative_to(ROOT_DIR)
            )
        if complete_status.get("next_blocked_fields") != [] or complete_status.get("next_blocked_field_count") != 0:
            return "{} --status-json reported next blocker fields for a complete blocked manifest".format(
                PUBLIC_LAUNCH_MANIFEST_TOOL.relative_to(ROOT_DIR)
            )
        if complete_status.get("blocked_field_groups") != []:
            return "{} --status-json reported blocker field groups for a complete blocked manifest".format(
                PUBLIC_LAUNCH_MANIFEST_TOOL.relative_to(ROOT_DIR)
            )
        if complete_status.get("blocked_field_group_count") != 0:
            return "{} --status-json counted blocker field groups for a complete blocked manifest".format(
                PUBLIC_LAUNCH_MANIFEST_TOOL.relative_to(ROOT_DIR)
            )
        if complete_status.get("blocked_field_groups_by_network") != {"main": [], "testnet": []}:
            return "{} --status-json reported network blocker field groups for a complete blocked manifest".format(
                PUBLIC_LAUNCH_MANIFEST_TOOL.relative_to(ROOT_DIR)
            )
        if complete_status.get("blocked_field_group_counts_by_network") != {"main": 0, "testnet": 0}:
            return "{} --status-json counted network blocker field groups for a complete blocked manifest".format(
                PUBLIC_LAUNCH_MANIFEST_TOOL.relative_to(ROOT_DIR)
            )
        if complete_status.get("blocked_field_groups_by_blocker_type") != empty_blocked_field_groups_by_blocker_type:
            return "{} --status-json reported blocker-type blocker field groups for a complete blocked manifest".format(
                PUBLIC_LAUNCH_MANIFEST_TOOL.relative_to(ROOT_DIR)
            )
        if complete_status.get("blocked_field_group_counts_by_blocker_type") != empty_blocked_field_group_counts_by_blocker_type:
            return "{} --status-json counted blocker-type blocker field groups for a complete blocked manifest".format(
                PUBLIC_LAUNCH_MANIFEST_TOOL.relative_to(ROOT_DIR)
            )
        if complete_status.get("blocked_field_groups_by_network_and_blocker_type") != empty_items_by_network_and_blocker_type:
            return "{} --status-json reported network blocker-type blocker field groups for a complete blocked manifest".format(
                PUBLIC_LAUNCH_MANIFEST_TOOL.relative_to(ROOT_DIR)
            )
        if complete_status.get("blocked_field_group_counts_by_network_and_blocker_type") != empty_counts_by_network_and_blocker_type:
            return "{} --status-json counted network blocker-type blocker field groups for a complete blocked manifest".format(
                PUBLIC_LAUNCH_MANIFEST_TOOL.relative_to(ROOT_DIR)
            )
        if complete_status.get("next_blocked_field_group") is not None:
            return "{} --status-json reported a current blocker field group for a complete blocked manifest".format(
                PUBLIC_LAUNCH_MANIFEST_TOOL.relative_to(ROOT_DIR)
            )
        if (
            complete_status.get("next_blocker_field_group") is not None
            or complete_status.get("next_blocker") is not None
            or complete_status.get("next_blocker_network") is not None
            or complete_status.get("next_blocker_type") is not None
            or complete_status.get("next_blocker_step") is not None
            or complete_status.get("next_blocker_network_step") is not None
            or complete_status.get("next_blocker_network_step_count") is not None
            or complete_status.get("next_blocker_type_step") is not None
            or complete_status.get("next_blocker_type_step_count") is not None
            or complete_status.get("next_blocker_commands") is not None
            or complete_status.get("next_blocker_fields") != []
            or complete_status.get("next_blocker_field_count") != 0
            or complete_status.get("later_blockers") != []
            or complete_status.get("later_blocker_count") != 0
            or complete_status.get("later_blocker_readiness_summary_commands_by_blocker") != {}
            or complete_status.get("later_blocker_readiness_summary_command_count") != 0
            or complete_status.get("later_blocker_field_groups") != []
            or complete_status.get("later_blocker_field_group_count") != 0
            or complete_status.get("later_blocker_fields") != []
            or complete_status.get("later_blocker_field_count") != 0
        ):
            return "{} --status-json reported a current blocker alias for a complete blocked manifest".format(
                PUBLIC_LAUNCH_MANIFEST_TOOL.relative_to(ROOT_DIR)
            )
        if complete_status.get("next", {}).get("id") != "mark-ready":
            return "{} --status-json did not point complete blocked manifests at --mark-ready".format(
                PUBLIC_LAUNCH_MANIFEST_TOOL.relative_to(ROOT_DIR)
            )
        if complete_status.get("next_action") != complete_status.get("next"):
            return "{} --status-json did not expose the complete-manifest next_action".format(
                PUBLIC_LAUNCH_MANIFEST_TOOL.relative_to(ROOT_DIR)
            )
        if (
            complete_status.get("next_action_id") != "mark-ready"
            or complete_status.get("next_action_kind") != "mark-ready"
            or complete_status.get("next_action_step") != 1
            or complete_status.get("next_action_network") is not None
            or complete_status.get("next_action_blocker_type") is not None
            or complete_status.get("next_action_field_count") is not None
        ):
            return "{} --status-json did not expose complete-manifest next_action aliases".format(
                PUBLIC_LAUNCH_MANIFEST_TOOL.relative_to(ROOT_DIR)
            )
        if complete_status.get("next_commands", {}).get("command") != complete_status.get("next_action", {}).get("command"):
            return "{} --status-json did not expose the complete-manifest next command".format(
                PUBLIC_LAUNCH_MANIFEST_TOOL.relative_to(ROOT_DIR)
            )
        if complete_status.get("next_command_keys") != ["command"]:
            return "{} --status-json did not expose the complete-manifest next command keys".format(
                PUBLIC_LAUNCH_MANIFEST_TOOL.relative_to(ROOT_DIR)
            )
        if complete_status.get("next_command_key_count") != 1:
            return "{} --status-json did not count the complete-manifest next command keys".format(
                PUBLIC_LAUNCH_MANIFEST_TOOL.relative_to(ROOT_DIR)
            )
        if complete_status.get("next_command_values") != [complete_status.get("next_commands", {}).get("command")]:
            return "{} --status-json did not expose the complete-manifest next command values".format(
                PUBLIC_LAUNCH_MANIFEST_TOOL.relative_to(ROOT_DIR)
            )
        if complete_status.get("next_command_value_count") != 1:
            return "{} --status-json did not count the complete-manifest next command values".format(
                PUBLIC_LAUNCH_MANIFEST_TOOL.relative_to(ROOT_DIR)
            )
        if complete_status.get("next_command_pairs") != [
            {"key": "command", "value": complete_status.get("next_commands", {}).get("command")}
        ]:
            return "{} --status-json did not expose the complete-manifest next command pairs".format(
                PUBLIC_LAUNCH_MANIFEST_TOOL.relative_to(ROOT_DIR)
            )
        if complete_status.get("next_command_pair_count") != 1:
            return "{} --status-json did not count the complete-manifest next command pairs".format(
                PUBLIC_LAUNCH_MANIFEST_TOOL.relative_to(ROOT_DIR)
            )
        if tuple(complete_status.get("command_field_order", [])) != command_fields:
            return "{} --status-json did not expose complete blocked manifest command field order".format(
                PUBLIC_LAUNCH_MANIFEST_TOOL.relative_to(ROOT_DIR)
            )
        if complete_status.get("command_field_count") != len(command_fields):
            return "{} --status-json did not count complete blocked manifest command fields".format(
                PUBLIC_LAUNCH_MANIFEST_TOOL.relative_to(ROOT_DIR)
            )
        if complete_status.get("network_readiness_summary_command_count") != len(
            complete_status.get("network_readiness_summary_commands_by_network", {})
        ):
            return "{} --status-json did not count complete blocked manifest network readiness-summary commands".format(
                PUBLIC_LAUNCH_MANIFEST_TOOL.relative_to(ROOT_DIR)
            )
        if complete_status.get("blocker_type_readiness_summary_command_count") != len(
            complete_status.get("blocker_type_readiness_summary_commands_by_blocker_type", {})
        ):
            return "{} --status-json did not count complete blocked manifest blocker-type readiness-summary commands".format(
                PUBLIC_LAUNCH_MANIFEST_TOOL.relative_to(ROOT_DIR)
            )
        if complete_status.get("blocker_readiness_summary_command_count") != len(
            complete_status.get("blocker_readiness_summary_commands_by_blocker", {})
        ):
            return "{} --status-json did not count complete blocked manifest blocker readiness-summary commands".format(
                PUBLIC_LAUNCH_MANIFEST_TOOL.relative_to(ROOT_DIR)
            )
        if complete_status.get("ready_for_chainparams") is not False:
            return "{} --status-json treated complete blocked manifest as ready".format(
                PUBLIC_LAUNCH_MANIFEST_TOOL.relative_to(ROOT_DIR)
            )

        mark_ready_result = subprocess.run(
            [
                sys.executable,
                str(PUBLIC_LAUNCH_MANIFEST_TOOL),
                "--mark-ready",
                str(complete_path),
            ],
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        if mark_ready_result.returncode != 0:
            return "{} --mark-ready rejected a complete manifest with unique public launch values: {}".format(
                PUBLIC_LAUNCH_MANIFEST_TOOL.relative_to(ROOT_DIR),
                mark_ready_result.stderr.strip() or mark_ready_result.stdout.strip() or "no output",
            )
        try:
            ready_manifest = json.loads(mark_ready_result.stdout)
        except json.JSONDecodeError as exc:
            return "{} --mark-ready did not emit JSON: {}".format(
                PUBLIC_LAUNCH_MANIFEST_TOOL.relative_to(ROOT_DIR),
                exc,
            )
        if ready_manifest.get("status") != "ready-for-chainparams":
            return "{} --mark-ready did not set ready-for-chainparams status".format(
                PUBLIC_LAUNCH_MANIFEST_TOOL.relative_to(ROOT_DIR)
            )
        if ready_manifest.get("blockers") != []:
            return "{} --mark-ready did not clear resolved blockers".format(
                PUBLIC_LAUNCH_MANIFEST_TOOL.relative_to(ROOT_DIR)
            )

        ready_path = Path(temp_dir) / "ready.json"
        ready_path.write_text(json.dumps(ready_manifest), encoding="utf8")
        ready_result = subprocess.run(
            [sys.executable, str(PUBLIC_LAUNCH_MANIFEST_TOOL), str(ready_path)],
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        if ready_result.returncode != 0:
            return "{} rejected a complete ready manifest with unique public launch values: {}".format(
                PUBLIC_LAUNCH_MANIFEST_TOOL.relative_to(ROOT_DIR),
                ready_result.stderr.strip() or ready_result.stdout.strip() or "no output",
            )
        ready_update_result = subprocess.run(
            [
                sys.executable,
                str(PUBLIC_LAUNCH_MANIFEST_TOOL),
                "--set-auxpow",
                "main",
                "0x5003",
                str(ready_path),
            ],
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        if ready_update_result.returncode != 0:
            return "{} --set-auxpow failed against a ready manifest: {}".format(
                PUBLIC_LAUNCH_MANIFEST_TOOL.relative_to(ROOT_DIR),
                ready_update_result.stderr.strip() or ready_update_result.stdout.strip() or "no output",
            )
        try:
            demoted_manifest = json.loads(ready_update_result.stdout)
        except json.JSONDecodeError as exc:
            return "{} --set-auxpow ready-manifest update did not emit JSON: {}".format(
                PUBLIC_LAUNCH_MANIFEST_TOOL.relative_to(ROOT_DIR),
                exc,
            )
        if demoted_manifest.get("status") != "blocked":
            return "{} --set-auxpow did not demote a ready manifest for review".format(
                PUBLIC_LAUNCH_MANIFEST_TOOL.relative_to(ROOT_DIR)
            )
        if demoted_manifest.get("blockers") != []:
            return "{} --set-auxpow added blockers while demoting a complete ready manifest".format(
                PUBLIC_LAUNCH_MANIFEST_TOOL.relative_to(ROOT_DIR)
            )

        ready_next_result = subprocess.run(
            [
                sys.executable,
                str(PUBLIC_LAUNCH_MANIFEST_TOOL),
                "--next-action",
                str(ready_path),
            ],
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        if ready_next_result.returncode != 0:
            return "{} --next-action failed for a ready manifest".format(
                PUBLIC_LAUNCH_MANIFEST_TOOL.relative_to(ROOT_DIR)
            )
        if "--emit-chainparams" not in ready_next_result.stdout or "--check-chainparams" not in ready_next_result.stdout:
            return "{} --next-action did not print ready-manifest chainparams handoff commands".format(
                PUBLIC_LAUNCH_MANIFEST_TOOL.relative_to(ROOT_DIR)
            )
        if str(ready_path) not in ready_next_result.stdout:
            return "{} --next-action did not preserve the checked ready manifest path".format(
                PUBLIC_LAUNCH_MANIFEST_TOOL.relative_to(ROOT_DIR)
            )

        ready_plan_result = subprocess.run(
            [
                sys.executable,
                str(PUBLIC_LAUNCH_MANIFEST_TOOL),
                "--action-plan",
                str(ready_path),
            ],
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        if ready_plan_result.returncode != 0:
            return "{} --action-plan failed for a ready manifest".format(
                PUBLIC_LAUNCH_MANIFEST_TOOL.relative_to(ROOT_DIR)
            )
        if "1. emit chainparams" not in ready_plan_result.stdout:
            return "{} --action-plan did not print ready-manifest emit step".format(
                PUBLIC_LAUNCH_MANIFEST_TOOL.relative_to(ROOT_DIR)
            )
        if "2. verify chainparams" not in ready_plan_result.stdout:
            return "{} --action-plan did not print ready-manifest verify step".format(
                PUBLIC_LAUNCH_MANIFEST_TOOL.relative_to(ROOT_DIR)
            )
        if "--emit-chainparams" not in ready_plan_result.stdout or "--check-chainparams" not in ready_plan_result.stdout:
            return "{} --action-plan did not print ready-manifest chainparams handoff commands".format(
                PUBLIC_LAUNCH_MANIFEST_TOOL.relative_to(ROOT_DIR)
            )
        if str(ready_path) not in ready_plan_result.stdout:
            return "{} --action-plan did not preserve the checked ready manifest path".format(
                PUBLIC_LAUNCH_MANIFEST_TOOL.relative_to(ROOT_DIR)
            )

        ready_summary_result = subprocess.run(
            [
                sys.executable,
                str(PUBLIC_LAUNCH_MANIFEST_TOOL),
                "--readiness-summary",
                str(ready_path),
            ],
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        if ready_summary_result.returncode != 0:
            return "{} --readiness-summary failed for a ready manifest".format(
                PUBLIC_LAUNCH_MANIFEST_TOOL.relative_to(ROOT_DIR)
            )
        for expected in (
            "  - status: ready-for-chainparams",
            "  - ready for chainparams: yes",
            "  - action plan command: contrib/devtools/zkcoin_public_launch_profile.py --action-plan",
            "  - next action command: contrib/devtools/zkcoin_public_launch_profile.py --next-action",
            "  - readiness summary command: contrib/devtools/zkcoin_public_launch_profile.py --readiness-summary",
            "  - status JSON command: contrib/devtools/zkcoin_public_launch_profile.py --status-json",
            "  - blocked networks: none",
            "  - ready networks: main, testnet",
            "  - blocked networks by blocker type: litecoin_snapshot=none; auxpow_chain_id=none; public_network_identity=none; dns_seeds=none",
            "  - ready networks by blocker type: litecoin_snapshot=main, testnet; auxpow_chain_id=main, testnet; public_network_identity=main, testnet; dns_seeds=main, testnet",
            "  - unresolved blockers: 0",
            "  - unresolved blockers by network: main=0, testnet=0",
            "  - blocked fields: 0",
            "  - blocked fields by network: main=0, testnet=0",
            "  - next blockers by network: main=none, testnet=none",
            "  - next blocker fields by network: main=0, testnet=0",
            "  - next template commands by network: main=none; testnet=none",
            "  - next check commands by network: main=none; testnet=none",
            "  - next apply commands by network: main=none; testnet=none",
            "  - network readiness summary commands by network: main=contrib/devtools/zkcoin_public_launch_profile.py --network-readiness-summary main",
            "  - next step: apply ready manifest to chainparams and verify sync",
            "  - emit-chainparams: contrib/devtools/zkcoin_public_launch_profile.py --emit-chainparams",
            "  - check-chainparams: contrib/devtools/zkcoin_public_launch_profile.py --check-chainparams src/chainparams.cpp",
        ):
            if expected not in ready_summary_result.stdout:
                return "{} --readiness-summary did not print ready manifest guidance {}".format(
                    PUBLIC_LAUNCH_MANIFEST_TOOL.relative_to(ROOT_DIR),
                    expected,
                )

        ready_status_result = subprocess.run(
            [
                sys.executable,
                str(PUBLIC_LAUNCH_MANIFEST_TOOL),
                "--status-json",
                str(ready_path),
            ],
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        if ready_status_result.returncode != 0:
            return "{} --status-json failed for a ready manifest".format(
                PUBLIC_LAUNCH_MANIFEST_TOOL.relative_to(ROOT_DIR)
            )
        try:
            ready_status = json.loads(ready_status_result.stdout)
        except json.JSONDecodeError as exc:
            return "{} --status-json ready manifest output was not JSON: {}".format(
                PUBLIC_LAUNCH_MANIFEST_TOOL.relative_to(ROOT_DIR),
                exc,
            )
        schema_version_error = require_status_json_schema_version(ready_status)
        if schema_version_error:
            return schema_version_error
        if ready_status.get("ready_for_chainparams") is not True:
            return "{} --status-json did not report ready manifest as ready".format(
                PUBLIC_LAUNCH_MANIFEST_TOOL.relative_to(ROOT_DIR)
            )
        if ready_status.get("blocked_network_count") != 0 or ready_status.get("blocked_networks") != []:
            return "{} --status-json reported blocked networks for a ready manifest".format(
                PUBLIC_LAUNCH_MANIFEST_TOOL.relative_to(ROOT_DIR)
            )
        if ready_status.get("ready_network_count") != 2 or ready_status.get("ready_networks") != ["main", "testnet"]:
            return "{} --status-json did not summarize ready networks".format(
                PUBLIC_LAUNCH_MANIFEST_TOOL.relative_to(ROOT_DIR)
            )
        if ready_status.get("blocked_blocker_type_count") != 0 or ready_status.get("blocked_blocker_types") != []:
            return "{} --status-json reported blocked blocker types for a ready manifest".format(
                PUBLIC_LAUNCH_MANIFEST_TOOL.relative_to(ROOT_DIR)
            )
        if (
            ready_status.get("ready_blocker_type_count") != 4
            or ready_status.get("ready_blocker_types") != expected_blocker_type_order
        ):
            return "{} --status-json did not summarize ready blocker types".format(
                PUBLIC_LAUNCH_MANIFEST_TOOL.relative_to(ROOT_DIR)
            )
        if ready_status.get("blocked_blocker_types_by_network") != empty_blocker_types_by_network:
            return "{} --status-json reported blocked blocker types by network for a ready manifest".format(
                PUBLIC_LAUNCH_MANIFEST_TOOL.relative_to(ROOT_DIR)
            )
        if ready_status.get("blocked_blocker_type_counts_by_network") != empty_blocker_type_counts_by_network:
            return "{} --status-json counted blocked blocker types by network for a ready manifest".format(
                PUBLIC_LAUNCH_MANIFEST_TOOL.relative_to(ROOT_DIR)
            )
        if ready_status.get("ready_blocker_types_by_network") != expected_blocker_types_by_network:
            return "{} --status-json did not summarize ready blocker types by network".format(
                PUBLIC_LAUNCH_MANIFEST_TOOL.relative_to(ROOT_DIR)
            )
        if ready_status.get("ready_blocker_type_counts_by_network") != expected_blocker_type_counts_by_network:
            return "{} --status-json did not count ready blocker types by network".format(
                PUBLIC_LAUNCH_MANIFEST_TOOL.relative_to(ROOT_DIR)
            )
        if ready_status.get("blocked_networks_by_blocker_type") != empty_networks_by_blocker_type:
            return "{} --status-json reported blocked networks by blocker type for a ready manifest".format(
                PUBLIC_LAUNCH_MANIFEST_TOOL.relative_to(ROOT_DIR)
            )
        if ready_status.get("blocked_network_counts_by_blocker_type") != empty_network_counts_by_blocker_type:
            return "{} --status-json counted blocked networks by blocker type for a ready manifest".format(
                PUBLIC_LAUNCH_MANIFEST_TOOL.relative_to(ROOT_DIR)
            )
        if ready_status.get("ready_networks_by_blocker_type") != expected_networks_by_blocker_type:
            return "{} --status-json did not summarize ready networks by blocker type".format(
                PUBLIC_LAUNCH_MANIFEST_TOOL.relative_to(ROOT_DIR)
            )
        if ready_status.get("ready_network_counts_by_blocker_type") != expected_network_counts_by_blocker_type:
            return "{} --status-json did not count ready networks by blocker type".format(
                PUBLIC_LAUNCH_MANIFEST_TOOL.relative_to(ROOT_DIR)
            )
        if ready_status.get("blocked_fields") != []:
            return "{} --status-json reported field blockers for a ready manifest".format(
                PUBLIC_LAUNCH_MANIFEST_TOOL.relative_to(ROOT_DIR)
            )
        if ready_status.get("blocked_field_count") != 0:
            return "{} --status-json counted field blockers for a ready manifest".format(
                PUBLIC_LAUNCH_MANIFEST_TOOL.relative_to(ROOT_DIR)
            )
        if ready_status.get("unresolved_blocker_counts_by_network") != {"main": 0, "testnet": 0}:
            return "{} --status-json counted network blockers for a ready manifest".format(
                PUBLIC_LAUNCH_MANIFEST_TOOL.relative_to(ROOT_DIR)
            )
        if ready_status.get("unresolved_blockers_by_network") != {"main": [], "testnet": []}:
            return "{} --status-json reported network blockers for a ready manifest".format(
                PUBLIC_LAUNCH_MANIFEST_TOOL.relative_to(ROOT_DIR)
            )
        if ready_status.get("unresolved_blockers_by_blocker_type") != empty_blockers_by_blocker_type:
            return "{} --status-json reported blocker-type blockers for a ready manifest".format(
                PUBLIC_LAUNCH_MANIFEST_TOOL.relative_to(ROOT_DIR)
            )
        if ready_status.get("unresolved_blocker_counts_by_blocker_type") != empty_blocker_counts_by_blocker_type:
            return "{} --status-json counted blocker-type blockers for a ready manifest".format(
                PUBLIC_LAUNCH_MANIFEST_TOOL.relative_to(ROOT_DIR)
            )
        if ready_status.get("unresolved_blocker_counts_by_network_and_blocker_type") != empty_counts_by_network_and_blocker_type:
            return "{} --status-json counted network blocker-type blockers for a ready manifest".format(
                PUBLIC_LAUNCH_MANIFEST_TOOL.relative_to(ROOT_DIR)
            )
        if ready_status.get("unresolved_blockers_by_network_and_blocker_type") != empty_items_by_network_and_blocker_type:
            return "{} --status-json reported network blocker-type blockers for a ready manifest".format(
                PUBLIC_LAUNCH_MANIFEST_TOOL.relative_to(ROOT_DIR)
            )
        if ready_status.get("blocked_field_counts_by_network") != {"main": 0, "testnet": 0}:
            return "{} --status-json counted network field blockers for a ready manifest".format(
                PUBLIC_LAUNCH_MANIFEST_TOOL.relative_to(ROOT_DIR)
            )
        if ready_status.get("blocked_fields_by_network") != {"main": [], "testnet": []}:
            return "{} --status-json reported network field blockers for a ready manifest".format(
                PUBLIC_LAUNCH_MANIFEST_TOOL.relative_to(ROOT_DIR)
            )
        if ready_status.get("blocked_fields_by_blocker_type") != empty_blocked_fields_by_blocker_type:
            return "{} --status-json reported blocker-type field blockers for a ready manifest".format(
                PUBLIC_LAUNCH_MANIFEST_TOOL.relative_to(ROOT_DIR)
            )
        if ready_status.get("blocked_field_counts_by_blocker_type") != empty_blocked_field_counts_by_blocker_type:
            return "{} --status-json counted blocker-type field blockers for a ready manifest".format(
                PUBLIC_LAUNCH_MANIFEST_TOOL.relative_to(ROOT_DIR)
            )
        if ready_status.get("blocked_field_counts_by_network_and_blocker_type") != empty_counts_by_network_and_blocker_type:
            return "{} --status-json counted network blocker-type field blockers for a ready manifest".format(
                PUBLIC_LAUNCH_MANIFEST_TOOL.relative_to(ROOT_DIR)
            )
        if ready_status.get("blocked_fields_by_network_and_blocker_type") != empty_items_by_network_and_blocker_type:
            return "{} --status-json reported network blocker-type field blockers for a ready manifest".format(
                PUBLIC_LAUNCH_MANIFEST_TOOL.relative_to(ROOT_DIR)
            )
        if ready_status.get("next_commands_by_network") != {"main": None, "testnet": None}:
            return "{} --status-json reported per-network next commands for a ready manifest".format(
                PUBLIC_LAUNCH_MANIFEST_TOOL.relative_to(ROOT_DIR)
            )
        if ready_status.get("next_blocker_commands_by_network") != {"main": None, "testnet": None}:
            return "{} --status-json reported per-network next blocker command aliases for a ready manifest".format(
                PUBLIC_LAUNCH_MANIFEST_TOOL.relative_to(ROOT_DIR)
            )
        if ready_status.get("next_actions_by_blocker_type") != empty_next_by_blocker_type:
            return "{} --status-json reported blocker-type next actions for a ready manifest".format(
                PUBLIC_LAUNCH_MANIFEST_TOOL.relative_to(ROOT_DIR)
            )
        if ready_status.get("next_commands_by_blocker_type") != empty_next_by_blocker_type:
            return "{} --status-json reported blocker-type next commands for a ready manifest".format(
                PUBLIC_LAUNCH_MANIFEST_TOOL.relative_to(ROOT_DIR)
            )
        if ready_status.get("next_blocker_commands_by_blocker_type") != empty_next_by_blocker_type:
            return "{} --status-json reported blocker-type next blocker command aliases for a ready manifest".format(
                PUBLIC_LAUNCH_MANIFEST_TOOL.relative_to(ROOT_DIR)
            )
        if ready_status.get("next_blocked_field_groups_by_blocker_type") != empty_next_by_blocker_type:
            return "{} --status-json reported blocker-type next groups for a ready manifest".format(
                PUBLIC_LAUNCH_MANIFEST_TOOL.relative_to(ROOT_DIR)
            )
        if ready_status.get("next_blocker_field_groups_by_blocker_type") != empty_next_by_blocker_type:
            return "{} --status-json reported blocker-type next group aliases for a ready manifest".format(
                PUBLIC_LAUNCH_MANIFEST_TOOL.relative_to(ROOT_DIR)
            )
        if ready_status.get("next_blocker_fields_by_blocker_type") != empty_blocked_fields_by_blocker_type:
            return "{} --status-json reported blocker-type next field aliases for a ready manifest".format(
                PUBLIC_LAUNCH_MANIFEST_TOOL.relative_to(ROOT_DIR)
            )
        if ready_status.get("next_blocker_field_counts_by_blocker_type") != empty_blocked_field_counts_by_blocker_type:
            return "{} --status-json counted blocker-type next field aliases for a ready manifest".format(
                PUBLIC_LAUNCH_MANIFEST_TOOL.relative_to(ROOT_DIR)
            )
        if ready_status.get("blocker_type_progress") != empty_blocker_type_progress:
            return "{} --status-json reported blocker-type progress for a ready manifest".format(
                PUBLIC_LAUNCH_MANIFEST_TOOL.relative_to(ROOT_DIR)
            )
        if ready_status.get("next_blocked_fields_by_network") != {"main": [], "testnet": []}:
            return "{} --status-json reported per-network next fields for a ready manifest".format(
                PUBLIC_LAUNCH_MANIFEST_TOOL.relative_to(ROOT_DIR)
            )
        if ready_status.get("next_blocker_fields_by_network") != {"main": [], "testnet": []}:
            return "{} --status-json reported per-network next field aliases for a ready manifest".format(
                PUBLIC_LAUNCH_MANIFEST_TOOL.relative_to(ROOT_DIR)
            )
        if ready_status.get("next_blocked_field_counts_by_network") != {"main": 0, "testnet": 0}:
            return "{} --status-json counted per-network next fields for a ready manifest".format(
                PUBLIC_LAUNCH_MANIFEST_TOOL.relative_to(ROOT_DIR)
            )
        if ready_status.get("next_blocker_field_counts_by_network") != {"main": 0, "testnet": 0}:
            return "{} --status-json counted per-network next field aliases for a ready manifest".format(
                PUBLIC_LAUNCH_MANIFEST_TOOL.relative_to(ROOT_DIR)
            )
        if ready_status.get("next_blockers_by_network") != {"main": None, "testnet": None}:
            return "{} --status-json reported per-network next blockers for a ready manifest".format(
                PUBLIC_LAUNCH_MANIFEST_TOOL.relative_to(ROOT_DIR)
            )
        if ready_status.get("next_blocker_types_by_network") != {"main": None, "testnet": None}:
            return "{} --status-json reported per-network next blocker types for a ready manifest".format(
                PUBLIC_LAUNCH_MANIFEST_TOOL.relative_to(ROOT_DIR)
            )
        if ready_status.get("next_blocked_field_groups_by_network") != {"main": None, "testnet": None}:
            return "{} --status-json reported per-network next groups for a ready manifest".format(
                PUBLIC_LAUNCH_MANIFEST_TOOL.relative_to(ROOT_DIR)
            )
        if ready_status.get("next_blocker_field_groups_by_network") != {"main": None, "testnet": None}:
            return "{} --status-json reported per-network next group aliases for a ready manifest".format(
                PUBLIC_LAUNCH_MANIFEST_TOOL.relative_to(ROOT_DIR)
            )
        if ready_status.get("network_progress", {}).get("main") != {
            "ready_for_launch_profile": True,
            "unresolved_blocker_count": 0,
            "unresolved_blockers": [],
            "blocked_field_count": 0,
            "blocked_fields": [],
            "next_blocked_field_group": None,
        }:
            return "{} --status-json did not report ready mainnet network progress".format(
                PUBLIC_LAUNCH_MANIFEST_TOOL.relative_to(ROOT_DIR)
            )
        if ready_status.get("network_progress", {}).get("testnet") != {
            "ready_for_launch_profile": True,
            "unresolved_blocker_count": 0,
            "unresolved_blockers": [],
            "blocked_field_count": 0,
            "blocked_fields": [],
            "next_blocked_field_group": None,
        }:
            return "{} --status-json did not report ready testnet network progress".format(
                PUBLIC_LAUNCH_MANIFEST_TOOL.relative_to(ROOT_DIR)
            )
        if ready_status.get("next_blocked_fields") != [] or ready_status.get("next_blocked_field_count") != 0:
            return "{} --status-json reported next blocker fields for a ready manifest".format(
                PUBLIC_LAUNCH_MANIFEST_TOOL.relative_to(ROOT_DIR)
            )
        if ready_status.get("blocked_field_groups") != []:
            return "{} --status-json reported blocker field groups for a ready manifest".format(
                PUBLIC_LAUNCH_MANIFEST_TOOL.relative_to(ROOT_DIR)
            )
        if ready_status.get("blocked_field_group_count") != 0:
            return "{} --status-json counted blocker field groups for a ready manifest".format(
                PUBLIC_LAUNCH_MANIFEST_TOOL.relative_to(ROOT_DIR)
            )
        if ready_status.get("blocked_field_groups_by_network") != {"main": [], "testnet": []}:
            return "{} --status-json reported network blocker field groups for a ready manifest".format(
                PUBLIC_LAUNCH_MANIFEST_TOOL.relative_to(ROOT_DIR)
            )
        if ready_status.get("blocked_field_group_counts_by_network") != {"main": 0, "testnet": 0}:
            return "{} --status-json counted network blocker field groups for a ready manifest".format(
                PUBLIC_LAUNCH_MANIFEST_TOOL.relative_to(ROOT_DIR)
            )
        if ready_status.get("blocked_field_groups_by_blocker_type") != empty_blocked_field_groups_by_blocker_type:
            return "{} --status-json reported blocker-type blocker field groups for a ready manifest".format(
                PUBLIC_LAUNCH_MANIFEST_TOOL.relative_to(ROOT_DIR)
            )
        if ready_status.get("blocked_field_group_counts_by_blocker_type") != empty_blocked_field_group_counts_by_blocker_type:
            return "{} --status-json counted blocker-type blocker field groups for a ready manifest".format(
                PUBLIC_LAUNCH_MANIFEST_TOOL.relative_to(ROOT_DIR)
            )
        if ready_status.get("blocked_field_groups_by_network_and_blocker_type") != empty_items_by_network_and_blocker_type:
            return "{} --status-json reported network blocker-type blocker field groups for a ready manifest".format(
                PUBLIC_LAUNCH_MANIFEST_TOOL.relative_to(ROOT_DIR)
            )
        if ready_status.get("blocked_field_group_counts_by_network_and_blocker_type") != empty_counts_by_network_and_blocker_type:
            return "{} --status-json counted network blocker-type blocker field groups for a ready manifest".format(
                PUBLIC_LAUNCH_MANIFEST_TOOL.relative_to(ROOT_DIR)
            )
        if ready_status.get("next_blocked_field_group") is not None:
            return "{} --status-json reported a current blocker field group for a ready manifest".format(
                PUBLIC_LAUNCH_MANIFEST_TOOL.relative_to(ROOT_DIR)
            )
        if (
            ready_status.get("next_blocker_field_group") is not None
            or ready_status.get("next_blocker") is not None
            or ready_status.get("next_blocker_network") is not None
            or ready_status.get("next_blocker_type") is not None
            or ready_status.get("next_blocker_step") is not None
            or ready_status.get("next_blocker_network_step") is not None
            or ready_status.get("next_blocker_network_step_count") is not None
            or ready_status.get("next_blocker_type_step") is not None
            or ready_status.get("next_blocker_type_step_count") is not None
            or ready_status.get("next_blocker_commands") is not None
            or ready_status.get("next_blocker_fields") != []
            or ready_status.get("next_blocker_field_count") != 0
            or ready_status.get("later_blockers") != []
            or ready_status.get("later_blocker_count") != 0
            or ready_status.get("later_blocker_readiness_summary_commands_by_blocker") != {}
            or ready_status.get("later_blocker_readiness_summary_command_count") != 0
            or ready_status.get("later_blocker_field_groups") != []
            or ready_status.get("later_blocker_field_group_count") != 0
            or ready_status.get("later_blocker_fields") != []
            or ready_status.get("later_blocker_field_count") != 0
        ):
            return "{} --status-json reported a current blocker alias for a ready manifest".format(
                PUBLIC_LAUNCH_MANIFEST_TOOL.relative_to(ROOT_DIR)
            )
        if ready_status.get("action_count") != 2:
            return "{} --status-json did not count ready manifest handoff actions".format(
                PUBLIC_LAUNCH_MANIFEST_TOOL.relative_to(ROOT_DIR)
            )
        ready_expected_action_commands = [
            {command_field: action.get(command_field) for command_field in command_fields}
            for action in ready_status.get("actions", [])
        ]
        if (
            ready_status.get("action_ids") != ["emit-chainparams", "check-chainparams"]
            or ready_status.get("action_kinds") != ["emit-chainparams", "check-chainparams"]
            or ready_status.get("action_steps") != [1, 2]
            or ready_status.get("action_networks") != [None, None]
            or ready_status.get("action_blocker_types") != [None, None]
            or ready_status.get("action_field_counts") != [None, None]
            or ready_status.get("action_commands") != ready_expected_action_commands
            or ready_status.get("action_command_count") != 2
            or ready_status.get("action_command_keys") != [["command"], ["command"]]
            or ready_status.get("action_command_key_counts") != [1, 1]
            or ready_status.get("action_command_values") != [
                [command.get("command")]
                for command in ready_expected_action_commands
            ]
            or ready_status.get("action_command_value_counts") != [1, 1]
            or ready_status.get("action_command_pairs") != [
                [{"key": "command", "value": command.get("command")}]
                for command in ready_expected_action_commands
            ]
            or ready_status.get("action_command_pair_counts") != [1, 1]
        ):
            return "{} --status-json did not expose ready manifest action aliases".format(
                PUBLIC_LAUNCH_MANIFEST_TOOL.relative_to(ROOT_DIR)
            )
        if ready_status.get("action_counts_by_network") != {"main": 0, "testnet": 0}:
            return "{} --status-json counted network actions for a ready manifest".format(
                PUBLIC_LAUNCH_MANIFEST_TOOL.relative_to(ROOT_DIR)
            )
        if ready_status.get("actions_by_network") != {"main": [], "testnet": []}:
            return "{} --status-json reported network actions for a ready manifest".format(
                PUBLIC_LAUNCH_MANIFEST_TOOL.relative_to(ROOT_DIR)
            )
        if ready_status.get("action_counts_by_blocker_type") != empty_action_counts_by_blocker_type:
            return "{} --status-json counted blocker-type actions for a ready manifest".format(
                PUBLIC_LAUNCH_MANIFEST_TOOL.relative_to(ROOT_DIR)
            )
        if ready_status.get("actions_by_blocker_type") != empty_actions_by_blocker_type:
            return "{} --status-json reported blocker-type actions for a ready manifest".format(
                PUBLIC_LAUNCH_MANIFEST_TOOL.relative_to(ROOT_DIR)
            )
        if ready_status.get("action_counts_by_network_and_blocker_type") != empty_counts_by_network_and_blocker_type:
            return "{} --status-json counted network blocker-type actions for a ready manifest".format(
                PUBLIC_LAUNCH_MANIFEST_TOOL.relative_to(ROOT_DIR)
            )
        if ready_status.get("actions_by_network_and_blocker_type") != empty_items_by_network_and_blocker_type:
            return "{} --status-json reported network blocker-type actions for a ready manifest".format(
                PUBLIC_LAUNCH_MANIFEST_TOOL.relative_to(ROOT_DIR)
            )
        if ready_status.get("next_actions_by_network_and_blocker_type") != empty_next_by_network_and_blocker_type:
            return "{} --status-json reported network blocker-type next actions for a ready manifest".format(
                PUBLIC_LAUNCH_MANIFEST_TOOL.relative_to(ROOT_DIR)
            )
        if ready_status.get("next_commands_by_network_and_blocker_type") != empty_next_by_network_and_blocker_type:
            return "{} --status-json reported network blocker-type next commands for a ready manifest".format(
                PUBLIC_LAUNCH_MANIFEST_TOOL.relative_to(ROOT_DIR)
            )
        if ready_status.get("next_blocker_commands_by_network_and_blocker_type") != empty_next_by_network_and_blocker_type:
            return "{} --status-json reported network blocker-type next blocker command aliases for a ready manifest".format(
                PUBLIC_LAUNCH_MANIFEST_TOOL.relative_to(ROOT_DIR)
            )
        if ready_status.get("next_blocked_field_groups_by_network_and_blocker_type") != empty_next_by_network_and_blocker_type:
            return "{} --status-json reported network blocker-type next groups for a ready manifest".format(
                PUBLIC_LAUNCH_MANIFEST_TOOL.relative_to(ROOT_DIR)
            )
        if ready_status.get("next_blocker_field_groups_by_network_and_blocker_type") != empty_next_by_network_and_blocker_type:
            return "{} --status-json reported network blocker-type next group aliases for a ready manifest".format(
                PUBLIC_LAUNCH_MANIFEST_TOOL.relative_to(ROOT_DIR)
            )
        if ready_status.get("next_blockers_by_network_and_blocker_type") != empty_next_by_network_and_blocker_type:
            return "{} --status-json reported network blocker-type next blockers for a ready manifest".format(
                PUBLIC_LAUNCH_MANIFEST_TOOL.relative_to(ROOT_DIR)
            )
        if ready_status.get("next_blocked_fields_by_network_and_blocker_type") != empty_items_by_network_and_blocker_type:
            return "{} --status-json reported network blocker-type next fields for a ready manifest".format(
                PUBLIC_LAUNCH_MANIFEST_TOOL.relative_to(ROOT_DIR)
            )
        if ready_status.get("next_blocker_fields_by_network_and_blocker_type") != empty_items_by_network_and_blocker_type:
            return "{} --status-json reported network blocker-type next field aliases for a ready manifest".format(
                PUBLIC_LAUNCH_MANIFEST_TOOL.relative_to(ROOT_DIR)
            )
        if ready_status.get("next_blocked_field_counts_by_network_and_blocker_type") != empty_counts_by_network_and_blocker_type:
            return "{} --status-json counted network blocker-type next fields for a ready manifest".format(
                PUBLIC_LAUNCH_MANIFEST_TOOL.relative_to(ROOT_DIR)
            )
        if ready_status.get("next_blocker_field_counts_by_network_and_blocker_type") != empty_counts_by_network_and_blocker_type:
            return "{} --status-json counted network blocker-type next field aliases for a ready manifest".format(
                PUBLIC_LAUNCH_MANIFEST_TOOL.relative_to(ROOT_DIR)
            )
        if [action.get("id") for action in ready_status.get("actions", [])] != [
            "emit-chainparams",
            "check-chainparams",
        ]:
            return "{} --status-json did not report ready chainparams handoff actions".format(
                PUBLIC_LAUNCH_MANIFEST_TOOL.relative_to(ROOT_DIR)
            )
        if ready_status.get("later_actions") != ready_status.get("actions", [])[1:]:
            return "{} --status-json did not expose ready-manifest later actions".format(
                PUBLIC_LAUNCH_MANIFEST_TOOL.relative_to(ROOT_DIR)
            )
        if ready_status.get("later_action_count") != 1 or ready_status.get("later_actions", [{}])[0].get("id") != "check-chainparams":
            return "{} --status-json did not count ready-manifest later actions".format(
                PUBLIC_LAUNCH_MANIFEST_TOOL.relative_to(ROOT_DIR)
            )
        if (
            ready_status.get("later_action_ids") != ["check-chainparams"]
            or ready_status.get("later_action_kinds") != ["check-chainparams"]
            or ready_status.get("later_action_steps") != [2]
            or ready_status.get("later_action_networks") != [None]
            or ready_status.get("later_action_blocker_types") != [None]
            or ready_status.get("later_action_field_counts") != [None]
        ):
            return "{} --status-json did not expose ready-manifest later action list aliases".format(
                PUBLIC_LAUNCH_MANIFEST_TOOL.relative_to(ROOT_DIR)
            )
        if ready_status.get("later_command_count") != 1 or ready_status.get("later_commands", [{}])[0].get("command") != ready_status.get("later_actions", [{}])[0].get("command"):
            return "{} --status-json did not expose ready-manifest later commands".format(
                PUBLIC_LAUNCH_MANIFEST_TOOL.relative_to(ROOT_DIR)
            )
        if ready_status.get("later_command_keys") != [["command"]]:
            return "{} --status-json did not expose ready-manifest later command keys".format(
                PUBLIC_LAUNCH_MANIFEST_TOOL.relative_to(ROOT_DIR)
            )
        if ready_status.get("later_command_key_counts") != [1]:
            return "{} --status-json did not count ready-manifest later command keys".format(
                PUBLIC_LAUNCH_MANIFEST_TOOL.relative_to(ROOT_DIR)
            )
        if ready_status.get("later_command_values") != [[ready_status.get("later_commands", [{}])[0].get("command")]]:
            return "{} --status-json did not expose ready-manifest later command values".format(
                PUBLIC_LAUNCH_MANIFEST_TOOL.relative_to(ROOT_DIR)
            )
        if ready_status.get("later_command_value_counts") != [1]:
            return "{} --status-json did not count ready-manifest later command values".format(
                PUBLIC_LAUNCH_MANIFEST_TOOL.relative_to(ROOT_DIR)
            )
        if ready_status.get("later_command_pairs") != [
            [{"key": "command", "value": ready_status.get("later_commands", [{}])[0].get("command")}]
        ]:
            return "{} --status-json did not expose ready-manifest later command pairs".format(
                PUBLIC_LAUNCH_MANIFEST_TOOL.relative_to(ROOT_DIR)
            )
        if ready_status.get("later_command_pair_counts") != [1]:
            return "{} --status-json did not count ready-manifest later command pairs".format(
                PUBLIC_LAUNCH_MANIFEST_TOOL.relative_to(ROOT_DIR)
            )
        if ready_status.get("next_action", {}).get("id") != "emit-chainparams":
            return "{} --status-json did not expose ready-manifest next_action".format(
                PUBLIC_LAUNCH_MANIFEST_TOOL.relative_to(ROOT_DIR)
            )
        if (
            ready_status.get("next_action_id") != "emit-chainparams"
            or ready_status.get("next_action_kind") != "emit-chainparams"
            or ready_status.get("next_action_step") != 1
            or ready_status.get("next_action_network") is not None
            or ready_status.get("next_action_blocker_type") is not None
            or ready_status.get("next_action_field_count") is not None
        ):
            return "{} --status-json did not expose ready-manifest next_action aliases".format(
                PUBLIC_LAUNCH_MANIFEST_TOOL.relative_to(ROOT_DIR)
            )
        if ready_status.get("next_commands", {}).get("command") != ready_status.get("next_action", {}).get("command"):
            return "{} --status-json did not expose ready-manifest next command".format(
                PUBLIC_LAUNCH_MANIFEST_TOOL.relative_to(ROOT_DIR)
            )
        if ready_status.get("next_command_keys") != ["command"]:
            return "{} --status-json did not expose ready-manifest next command keys".format(
                PUBLIC_LAUNCH_MANIFEST_TOOL.relative_to(ROOT_DIR)
            )
        if ready_status.get("next_command_key_count") != 1:
            return "{} --status-json did not count ready-manifest next command keys".format(
                PUBLIC_LAUNCH_MANIFEST_TOOL.relative_to(ROOT_DIR)
            )
        if ready_status.get("next_command_values") != [ready_status.get("next_commands", {}).get("command")]:
            return "{} --status-json did not expose ready-manifest next command values".format(
                PUBLIC_LAUNCH_MANIFEST_TOOL.relative_to(ROOT_DIR)
            )
        if ready_status.get("next_command_value_count") != 1:
            return "{} --status-json did not count ready-manifest next command values".format(
                PUBLIC_LAUNCH_MANIFEST_TOOL.relative_to(ROOT_DIR)
            )
        if ready_status.get("next_command_pairs") != [
            {"key": "command", "value": ready_status.get("next_commands", {}).get("command")}
        ]:
            return "{} --status-json did not expose ready-manifest next command pairs".format(
                PUBLIC_LAUNCH_MANIFEST_TOOL.relative_to(ROOT_DIR)
            )
        if ready_status.get("next_command_pair_count") != 1:
            return "{} --status-json did not count ready-manifest next command pairs".format(
                PUBLIC_LAUNCH_MANIFEST_TOOL.relative_to(ROOT_DIR)
            )
        if tuple(ready_status.get("command_field_order", [])) != command_fields:
            return "{} --status-json did not expose ready manifest command field order".format(
                PUBLIC_LAUNCH_MANIFEST_TOOL.relative_to(ROOT_DIR)
            )
        if ready_status.get("command_field_count") != len(command_fields):
            return "{} --status-json did not count ready manifest command fields".format(
                PUBLIC_LAUNCH_MANIFEST_TOOL.relative_to(ROOT_DIR)
            )
        if ready_status.get("network_readiness_summary_command_count") != len(
            ready_status.get("network_readiness_summary_commands_by_network", {})
        ):
            return "{} --status-json did not count ready manifest network readiness-summary commands".format(
                PUBLIC_LAUNCH_MANIFEST_TOOL.relative_to(ROOT_DIR)
            )
        if ready_status.get("blocker_type_readiness_summary_command_count") != len(
            ready_status.get("blocker_type_readiness_summary_commands_by_blocker_type", {})
        ):
            return "{} --status-json did not count ready manifest blocker-type readiness-summary commands".format(
                PUBLIC_LAUNCH_MANIFEST_TOOL.relative_to(ROOT_DIR)
            )
        if ready_status.get("blocker_readiness_summary_command_count") != len(
            ready_status.get("blocker_readiness_summary_commands_by_blocker", {})
        ):
            return "{} --status-json did not count ready manifest blocker readiness-summary commands".format(
                PUBLIC_LAUNCH_MANIFEST_TOOL.relative_to(ROOT_DIR)
            )

        emit_result = subprocess.run(
            [
                sys.executable,
                str(PUBLIC_LAUNCH_MANIFEST_TOOL),
                "--emit-chainparams",
                str(ready_path),
            ],
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        if emit_result.returncode != 0 or "testnet public launch profile generated" not in emit_result.stdout:
            return "{} did not emit chainparams from a complete ready manifest".format(
                PUBLIC_LAUNCH_MANIFEST_TOOL.relative_to(ROOT_DIR)
            )

        testnet_snippet_marker = "// testnet public launch profile generated"
        testnet_snippet_start = emit_result.stdout.find(testnet_snippet_marker)
        if testnet_snippet_start == -1:
            return "{} did not emit a testnet chainparams snippet marker".format(
                PUBLIC_LAUNCH_MANIFEST_TOOL.relative_to(ROOT_DIR)
            )
        main_snippet = emit_result.stdout[:testnet_snippet_start].strip()
        testnet_snippet = emit_result.stdout[testnet_snippet_start:].strip()

        def chainparams_text_with(main_block, testnet_block):
            return "\n".join(
                (
                    "class CMainParams : public CChainParams {",
                    main_block,
                    "};",
                    "class CTestNetParams : public CChainParams {",
                    testnet_block,
                    "};",
                    "class CRegTestParams : public CChainParams {",
                    "};",
                    "",
                )
            )

        synced_chainparams_path = Path(temp_dir) / "synced-chainparams.cpp"
        synced_chainparams_path.write_text(
            chainparams_text_with(main_snippet, testnet_snippet),
            encoding="utf8",
        )
        sync_result = subprocess.run(
            [
                sys.executable,
                str(PUBLIC_LAUNCH_MANIFEST_TOOL),
                "--check-chainparams",
                str(synced_chainparams_path),
                str(ready_path),
            ],
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        if sync_result.returncode != 0:
            return "{} --check-chainparams rejected emitted chainparams snippets: {}".format(
                PUBLIC_LAUNCH_MANIFEST_TOOL.relative_to(ROOT_DIR),
                sync_result.stderr.strip() or sync_result.stdout.strip() or "no output",
            )

        symlink_chainparams_path = Path(temp_dir) / "symlink-chainparams.cpp"
        symlink_chainparams_path.symlink_to(synced_chainparams_path)
        symlink_chainparams_result = subprocess.run(
            [
                sys.executable,
                str(PUBLIC_LAUNCH_MANIFEST_TOOL),
                "--check-chainparams",
                str(symlink_chainparams_path),
                str(ready_path),
            ],
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        if symlink_chainparams_result.returncode == 0:
            return "{} --check-chainparams accepted a symlinked chainparams input".format(
                PUBLIC_LAUNCH_MANIFEST_TOOL.relative_to(ROOT_DIR)
            )
        if "chainparams path must not be a symlink" not in symlink_chainparams_result.stderr:
            return "{} --check-chainparams did not explain symlinked chainparams rejection".format(
                PUBLIC_LAUNCH_MANIFEST_TOOL.relative_to(ROOT_DIR)
            )

        parent_symlink_chainparams_target = Path(temp_dir) / "chainparams-parent-target"
        parent_symlink_chainparams_target.mkdir()
        parent_symlink_chainparams_file = parent_symlink_chainparams_target / "chainparams.cpp"
        parent_symlink_chainparams_file.write_text(
            chainparams_text_with(main_snippet, testnet_snippet),
            encoding="utf8",
        )
        parent_symlink_chainparams_parent = Path(temp_dir) / "chainparams-parent-link"
        parent_symlink_chainparams_parent.symlink_to(parent_symlink_chainparams_target, target_is_directory=True)
        parent_symlink_chainparams_result = subprocess.run(
            [
                sys.executable,
                str(PUBLIC_LAUNCH_MANIFEST_TOOL),
                "--check-chainparams",
                str(parent_symlink_chainparams_parent / parent_symlink_chainparams_file.name),
                str(ready_path),
            ],
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        if parent_symlink_chainparams_result.returncode == 0:
            return "{} --check-chainparams accepted chainparams through a symlinked parent directory".format(
                PUBLIC_LAUNCH_MANIFEST_TOOL.relative_to(ROOT_DIR)
            )
        if "chainparams parent directory must not be a symlink" not in parent_symlink_chainparams_result.stderr:
            return "{} --check-chainparams did not explain symlinked chainparams parent rejection".format(
                PUBLIC_LAUNCH_MANIFEST_TOOL.relative_to(ROOT_DIR)
            )

        oversized_chainparams_path = Path(temp_dir) / "oversized-chainparams.cpp"
        oversized_chainparams_path.write_bytes(b" " * (manifest_tool.CHAINPARAMS_INPUT_MAX_BYTES + 1))
        oversized_chainparams_result = subprocess.run(
            [
                sys.executable,
                str(PUBLIC_LAUNCH_MANIFEST_TOOL),
                "--check-chainparams",
                str(oversized_chainparams_path),
                str(ready_path),
            ],
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        if oversized_chainparams_result.returncode == 0:
            return "{} --check-chainparams accepted oversized chainparams input".format(
                PUBLIC_LAUNCH_MANIFEST_TOOL.relative_to(ROOT_DIR)
            )
        if "chainparams input must not exceed 1048576 bytes" not in oversized_chainparams_result.stderr:
            return "{} --check-chainparams did not explain oversized chainparams rejection".format(
                PUBLIC_LAUNCH_MANIFEST_TOOL.relative_to(ROOT_DIR)
            )

        invalid_utf8_chainparams_path = Path(temp_dir) / "invalid-utf8-chainparams.cpp"
        invalid_utf8_chainparams_path.write_bytes(b"class CMainParams " + bytes([0xff]))
        invalid_utf8_chainparams_result = subprocess.run(
            [
                sys.executable,
                str(PUBLIC_LAUNCH_MANIFEST_TOOL),
                "--check-chainparams",
                str(invalid_utf8_chainparams_path),
                str(ready_path),
            ],
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        if invalid_utf8_chainparams_result.returncode == 0:
            return "{} --check-chainparams accepted invalid UTF-8 chainparams input".format(
                PUBLIC_LAUNCH_MANIFEST_TOOL.relative_to(ROOT_DIR)
            )
        if "is not valid UTF-8" not in invalid_utf8_chainparams_result.stderr:
            return "{} --check-chainparams did not explain invalid UTF-8 chainparams rejection".format(
                PUBLIC_LAUNCH_MANIFEST_TOOL.relative_to(ROOT_DIR)
            )

        changed_chainparams_path = Path(temp_dir) / "changed-chainparams.cpp"
        changed_chainparams_path.write_text(
            chainparams_text_with(main_snippet, testnet_snippet),
            encoding="utf8",
        )
        changed_chainparams_fd, changed_chainparams_stat = manifest_tool.open_regular_file_no_symlink(
            changed_chainparams_path,
            symlink_error="chainparams path must not be a symlink",
            missing_error="cannot read chainparams",
            not_regular_error="chainparams path must be a regular file",
            open_error="cannot read chainparams",
        )
        try:
            changed_chainparams_path.write_text("class CMainParams {}", encoding="utf8")
            try:
                manifest_tool.require_regular_file_stable(
                    changed_chainparams_path,
                    changed_chainparams_stat,
                    changed_chainparams_fd,
                    "chainparams input changed during read",
                )
            except ValueError as exc:
                if "chainparams input changed during read" not in str(exc):
                    return "{} reported the wrong changed-chainparams read error".format(
                        PUBLIC_LAUNCH_MANIFEST_TOOL.relative_to(ROOT_DIR)
                    )
            else:
                return "{} accepted a changed chainparams path after opening".format(
                    PUBLIC_LAUNCH_MANIFEST_TOOL.relative_to(ROOT_DIR)
                )
        finally:
            os.close(changed_chainparams_fd)

        swapped_chainparams_path = Path(temp_dir) / "swapped-chainparams.cpp"
        swapped_chainparams_path.write_text(
            chainparams_text_with(testnet_snippet, main_snippet),
            encoding="utf8",
        )
        swapped_result = subprocess.run(
            [
                sys.executable,
                str(PUBLIC_LAUNCH_MANIFEST_TOOL),
                "--check-chainparams",
                str(swapped_chainparams_path),
                str(ready_path),
            ],
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        if swapped_result.returncode == 0:
            return "{} --check-chainparams accepted snippets in the wrong chainparams classes".format(
                PUBLIC_LAUNCH_MANIFEST_TOOL.relative_to(ROOT_DIR)
            )
        if "main: generated snippet is present outside the CMainParams block" not in swapped_result.stderr:
            return "{} --check-chainparams did not report the misplaced main snippet".format(
                PUBLIC_LAUNCH_MANIFEST_TOOL.relative_to(ROOT_DIR)
            )

        contaminated_chainparams_path = Path(temp_dir) / "contaminated-chainparams.cpp"
        contaminated_chainparams_path.write_text(
            chainparams_text_with(main_snippet + "\n" + testnet_snippet, testnet_snippet),
            encoding="utf8",
        )
        contaminated_result = subprocess.run(
            [
                sys.executable,
                str(PUBLIC_LAUNCH_MANIFEST_TOOL),
                "--check-chainparams",
                str(contaminated_chainparams_path),
                str(ready_path),
            ],
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        if contaminated_result.returncode == 0:
            return "{} --check-chainparams accepted a foreign generated snippet in CMainParams".format(
                PUBLIC_LAUNCH_MANIFEST_TOOL.relative_to(ROOT_DIR)
            )
        if "main: foreign testnet generated snippet present in CMainParams" not in contaminated_result.stderr:
            return "{} --check-chainparams did not report the foreign testnet snippet in CMainParams".format(
                PUBLIC_LAUNCH_MANIFEST_TOOL.relative_to(ROOT_DIR)
            )

        duplicated_chainparams_path = Path(temp_dir) / "duplicated-chainparams.cpp"
        duplicated_chainparams_path.write_text(
            chainparams_text_with(main_snippet + "\n" + main_snippet, testnet_snippet),
            encoding="utf8",
        )
        duplicated_result = subprocess.run(
            [
                sys.executable,
                str(PUBLIC_LAUNCH_MANIFEST_TOOL),
                "--check-chainparams",
                str(duplicated_chainparams_path),
                str(ready_path),
            ],
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        if duplicated_result.returncode == 0:
            return "{} --check-chainparams accepted a duplicate generated snippet in CMainParams".format(
                PUBLIC_LAUNCH_MANIFEST_TOOL.relative_to(ROOT_DIR)
            )
        if "main: generated snippet appears more than once in CMainParams" not in duplicated_result.stderr:
            return "{} --check-chainparams did not report the duplicate main snippet in CMainParams".format(
                PUBLIC_LAUNCH_MANIFEST_TOOL.relative_to(ROOT_DIR)
            )

        drifted_chainparams_path = Path(temp_dir) / "drifted-chainparams.cpp"
        drifted_chainparams_path.write_text(
            chainparams_text_with(main_snippet, testnet_snippet).replace(
                "        consensus.auxpow.nChainId = 20482;",
                "        consensus.auxpow.nChainId = 20483;",
            ),
            encoding="utf8",
        )
        drift_result = subprocess.run(
            [
                sys.executable,
                str(PUBLIC_LAUNCH_MANIFEST_TOOL),
                "--check-chainparams",
                str(drifted_chainparams_path),
                str(ready_path),
            ],
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        if drift_result.returncode == 0:
            return "{} --check-chainparams accepted drifted chainparams".format(
                PUBLIC_LAUNCH_MANIFEST_TOOL.relative_to(ROOT_DIR)
            )
        if "testnet: missing line: consensus.auxpow.nChainId = 20482;" not in drift_result.stderr:
            return "{} --check-chainparams did not report the drifted testnet chain id".format(
                PUBLIC_LAUNCH_MANIFEST_TOOL.relative_to(ROOT_DIR)
            )

        collision_manifest = json.loads(json.dumps(ready_manifest))
        testnet = collision_manifest["networks"]["testnet"]
        testnet["auxpow"]["chain_id"] = ready_profiles["main"]["chain_id"]
        testnet_identity = testnet["public_network_identity"]
        testnet_identity["message_start"] = ready_profiles["main"]["identity"]["message_start"]
        testnet_identity["default_port"] = ready_profiles["main"]["identity"]["default_port"]
        testnet_identity["dns_seeds"] = ready_profiles["main"]["identity"]["dns_seeds"]
        testnet_identity["base58_prefixes"]["pubkey_address"] = (
            ready_profiles["main"]["identity"]["base58_prefixes"]["pubkey_address"]
        )
        testnet_identity["bech32_hrp"] = ready_profiles["main"]["identity"]["bech32_hrp"]
        testnet_identity["mweb_hrp"] = ready_profiles["main"]["identity"]["mweb_hrp"]

        collision_path = Path(temp_dir) / "collision.json"
        collision_path.write_text(json.dumps(collision_manifest), encoding="utf8")
        collision_result = subprocess.run(
            [sys.executable, str(PUBLIC_LAUNCH_MANIFEST_TOOL), str(collision_path)],
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        if collision_result.returncode == 0:
            return "{} accepted cross-network public launch value collisions".format(
                PUBLIC_LAUNCH_MANIFEST_TOOL.relative_to(ROOT_DIR)
            )
        for needle in (
            "testnet.auxpow.chain_id",
            "testnet.public_network_identity.message_start",
            "testnet.public_network_identity.default_port",
            "testnet.public_network_identity.dns_seeds[0]",
            "testnet.public_network_identity.base58_prefixes.pubkey_address",
            "testnet.public_network_identity.bech32_hrp",
            "testnet.public_network_identity.mweb_hrp",
        ):
            if needle not in collision_result.stderr:
                return "{} did not report cross-network collision for {}".format(
                    PUBLIC_LAUNCH_MANIFEST_TOOL.relative_to(ROOT_DIR),
                    needle,
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
        "!status.chain_id_placeholder",
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

    manifest_tool_checks = (
        ("FORBIDDEN_PARENT_VERSION_CHAIN_IDS = range(0x2000, 0x4000)", "manifest rejects Litecoin parent-version chain-id range"),
        ("PLACEHOLDER_AUXPOW_CHAIN_ID = 0x5A4B", "manifest rejects placeholder AuxPoW chain id"),
        ("LITECOIN_MESSAGE_STARTS", "manifest rejects inherited Litecoin message starts"),
        ("LITECOIN_BASE58_PREFIXES", "manifest rejects inherited Litecoin Base58 prefixes"),
        ("RESERVED_DNS_SEED_SUFFIXES", "manifest rejects reserved DNS seed suffixes"),
        ("MAX_BECH32_HRP_LENGTH = 83", "manifest caps Bech32 HRP length"),
        ("REQUIRED_BLOCKERS", "manifest requires explicit blocker ids"),
        ("BLOCKER_TYPES", "manifest defines stable blocker type order"),
        ("CHAINPARAMS_CLASS_BOUNDS", "manifest maps public networks to chainparams classes"),
        ("contains resolved or unknown blocker ids", "manifest rejects stale or unknown blocker ids"),
        ("DuplicateJSONFieldError", "manifest rejects duplicate JSON fields"),
        ("is not valid UTF-8", "manifest rejects invalid UTF-8 JSON"),
        ("LAUNCH_MANIFEST_MAX_BYTES", "manifest caps launch manifest input size"),
        ("read_launch_manifest_text", "manifest opens launch manifests through the hardened read path"),
        ("manifest parent directory must not be a symlink", "manifest reads reject symlinked direct parent directories"),
        ("manifest changed during read", "manifest rechecks launch manifests after reading"),
        ("object_or_empty", "manifest reports malformed schema sections without tracebacks"),
        ("update_network_profile", "manifest update commands reject malformed profile sections"),
        ("blockers must be an array", "manifest update commands reject malformed blocker lists"),
        ("require_known_fields", "manifest rejects unexpected schema fields"),
        ("is_plain_int", "manifest rejects JSON booleans in integer and byte fields"),
        ("manifest path must not be a symlink", "manifest in-place updates reject symlinked manifest paths"),
        ("manifest parent directory must not be a symlink", "manifest in-place updates reject symlinked manifest parent directories"),
        ("open_manifest_parent_directory", "manifest in-place updates open direct parent directories"),
        ("manifest temp path already exists", "manifest in-place updates reject pre-existing temp paths"),
        ("os.O_EXCL", "manifest in-place updates create temp files exclusively"),
        ("dir_fd=parent_fd", "manifest in-place updates write relative to the opened parent directory"),
        ("fsync_manifest_parent_directory", "manifest in-place updates sync the parent directory after replace"),
        ("ready-for-chainparams", "manifest ready status"),
        ("--allow-blocked", "manifest lint-mode flag"),
        ("selected_primary_actions", "manifest rejects mixed primary actions"),
        ("--next-action", "manifest next-action guidance flag"),
        ("--action-plan", "manifest full action-plan guidance flag"),
        ("--readiness-summary", "manifest readiness summary flag"),
        ("--network-readiness-summary", "manifest network readiness summary flag"),
        ("--blocker-type-readiness-summary", "manifest blocker-type readiness summary flag"),
        ("--blocker-readiness-summary", "manifest blocker readiness summary flag"),
        ("--status-json", "manifest machine-readable status guidance flag"),
        ("STATUS_JSON_SCHEMA_VERSION = 2", "manifest status JSON schema version"),
        ("--emit-chainparams", "manifest chainparams emitter flag"),
        ("--check-chainparams", "manifest chainparams sync-check flag"),
        ("CHAINPARAMS_INPUT_MAX_BYTES", "manifest caps chainparams sync-check input size"),
        ("read_chainparams_text", "manifest reads chainparams sync-check input through hardened path"),
        ("chainparams parent directory must not be a symlink", "manifest rejects symlinked chainparams input parents"),
        ("chainparams input changed during read", "manifest rechecks chainparams sync-check input after reading"),
        ("--mark-ready", "manifest guarded ready transition flag"),
        ("manual snapshot constants are not accepted", "manifest rejects manual snapshot constants"),
        ("--snapshot-audit-template", "manifest snapshot audit template flag"),
        ("--set-snapshot-audit", "manifest verified snapshot audit update flag"),
        ("--check-snapshot-audit", "manifest verified snapshot audit read-only check flag"),
        ("--set-auxpow", "manifest AuxPoW update flag"),
        ("--check-auxpow", "manifest AuxPoW read-only check flag"),
        ("--set-dns-seeds", "manifest DNS seed update flag"),
        ("--check-dns-seeds", "manifest DNS seed read-only check flag"),
        ("--set-identity", "manifest public identity update flag"),
        ("--check-identity", "manifest public identity read-only check flag"),
        ("parse_chain_id", "manifest parses AuxPoW chain id"),
        ("auxpow_profile_from_chain_id", "manifest builds AuxPoW profiles from checked chain ids"),
        ("checked_auxpow_candidate", "manifest checks AuxPoW candidates without writing"),
        ("auxpow_apply_command", "manifest prints AuxPoW apply commands after read-only checks"),
        ("action_plan_command", "manifest prints action-plan commands after read-only checks"),
        ("next_action_command", "manifest prints next-action commands after read-only checks"),
        ("readiness_summary_command", "manifest prints readiness-summary commands after read-only checks"),
        ("status_json_command", "manifest prints status-json commands after read-only checks"),
        ("status_command_fields", "manifest builds status command maps"),
        ("network_readiness_summary_command", "manifest prints network readiness-summary commands after read-only checks"),
        ("blocker_type_readiness_summary_command", "manifest prints blocker-type readiness-summary commands after read-only checks"),
        ("blocker_readiness_summary_command", "manifest prints blocker readiness-summary commands after read-only checks"),
        ("auxpow_check_text", "manifest prints AuxPoW candidate check summaries"),
        ("candidate_next_step_text(candidate, \"candidate\", manifest_path, network, \"auxpow_chain_id\")", "manifest reports AuxPoW candidate progress"),
        ("remaining blocked fields after applying", "manifest reports read-only candidate field-count progress"),
        ("remaining blockers on {network} after applying", "manifest reports network-scoped candidate blocker progress"),
        ("remaining blocked fields on {network} after applying", "manifest reports network-scoped candidate field-count progress"),
        ("next action command after applying", "manifest reports post-apply next-action commands"),
        ("network readiness summary command after applying", "manifest reports network-scoped post-apply summary commands"),
        ("blocker type readiness summary command after applying", "manifest reports blocker-type post-apply summary commands"),
        ("blocker_action_commands(next_blocker, manifest_path)", "manifest reports next candidate handoff commands"),
        ("parse_snapshot_audit", "manifest parses verified snapshot audit summaries"),
        ("snapshot_audit_template", "manifest builds snapshot audit templates"),
        ("verified_snapshot_audit_for_network", "manifest reuses verified snapshot audit checks"),
        ("checked_snapshot_audit_candidate", "manifest checks snapshot audit candidates without writing"),
        ("snapshot_audit_apply_command", "manifest prints snapshot audit apply commands after read-only checks"),
        ("snapshot_audit_check_text", "manifest prints verified snapshot audit check summaries"),
        ("candidate_next_step_text", "manifest reports snapshot audit candidate progress"),
        ("candidate_next_step_text(candidate, \"audit\", manifest_path, network, \"litecoin_snapshot\")", "manifest reports snapshot audit candidate blocker count"),
        ("next network readiness summary command after applying", "manifest prints next network summaries after candidate checks"),
        ("next blocker type readiness summary command after applying", "manifest prints next blocker-type summaries after candidate checks"),
        ("next blocker readiness summary command after applying", "manifest prints exact next-blocker summaries after candidate checks"),
        ("verify_snapshot_audit_artifact", "manifest verifies snapshot audit artifact fingerprints"),
        ("O_NOFOLLOW", "manifest opens snapshot audit inputs without following symlinks"),
        ("parent_symlink_error", "manifest can reject symlinked snapshot audit input parents"),
        ("snapshot audit summary must be a regular file", "manifest rejects non-file snapshot audit summaries"),
        ("snapshot audit summary parent directory must not be a symlink", "manifest rejects symlinked snapshot audit summary parents"),
        ("SNAPSHOT_AUDIT_SUMMARY_MAX_BYTES", "manifest caps snapshot audit summary input size"),
        ("snapshot audit summary must not exceed", "manifest rejects oversized snapshot audit summaries"),
        ("read_snapshot_audit_summary_text", "manifest enforces snapshot audit summary cap while reading"),
        ("require_snapshot_audit_summary_stable", "manifest rechecks snapshot audit summaries after reading"),
        ("snapshot audit summary is not valid UTF-8", "manifest rejects invalid UTF-8 snapshot audit summaries"),
        ("SNAPSHOT_AUDIT_SUMMARY_FIELDS", "manifest requires exact snapshot audit summary fields"),
        ("SNAPSHOT_AUDIT_FIELDS", "manifest blocker derivation tracks all snapshot audit fields"),
        ("SNAPSHOT_MAX_MONEY", "manifest caps snapshot audit total amount at inherited Litecoin supply"),
        ("snapshot audit summary must not be a symlink", "manifest rejects symlinked snapshot audit summaries"),
        ("snapshot audit missing field", "manifest rejects incomplete snapshot audit summaries"),
        ("snapshot audit summary has unexpected field", "manifest rejects extra snapshot audit summary fields"),
        ("snapshot audit summary field order must match --snapshot-audit-template output", "manifest rejects reordered snapshot audit summary fields"),
        ("SNAPSHOT_SOURCE_CHAINS", "manifest maps public profiles to Litecoin source chains"),
        ("64-character lowercase hex string", "manifest rejects non-lowercase snapshot audit hashes"),
        ("source_chain", "manifest preserves snapshot source-chain audit metadata"),
        ("snapshot_file_size", "manifest preserves snapshot file byte-size metadata"),
        ("snapshot_file_sha256", "manifest preserves snapshot file SHA-256 metadata"),
        ("snapshot audit file artifact does not exist", "manifest rejects missing snapshot audit artifacts"),
        ("snapshot audit file artifact must differ from audit summary", "manifest rejects self-referential snapshot audit artifacts"),
        ("snapshot audit file artifact must not be a symlink", "manifest rejects symlinked snapshot audit artifacts"),
        ("snapshot audit file artifact parent directory must not be a symlink", "manifest rejects symlinked snapshot audit artifact parents"),
        ("snapshot audit file artifact must be a regular file", "manifest rejects non-file snapshot audit artifacts"),
        ("require_snapshot_audit_artifact_stable", "manifest rechecks snapshot audit artifacts after hashing"),
        ("snapshot audit file size mismatch", "manifest rejects mismatched snapshot audit artifact sizes"),
        ("snapshot audit file SHA-256 mismatch", "manifest rejects mismatched snapshot audit artifact hashes"),
        ("snapshot_file_valid", "manifest rejects malformed snapshot audit file paths"),
        ("without control characters", "manifest rejects control characters in snapshot audit file paths"),
        ("snapshot_total_amount_valid", "manifest rejects malformed snapshot audit amounts"),
        ("SNAPSHOT_TOTAL_AMOUNT_RE", "manifest requires fixed-scale snapshot audit amount strings"),
        ("must not exceed {SNAPSHOT_MAX_MONEY_TEXT}", "manifest rejects over-maximum snapshot audit amounts"),
        ("litecoin_snapshot.audit.snapshot_hash", "manifest reports unresolved snapshot audit blockers"),
        ("snapshot_hash", "manifest preserves snapshot audit hash metadata"),
        ("base_nchaintx", "manifest preserves snapshot audit transaction-count metadata"),
        ("parse_dns_seeds", "manifest parses DNS seed hostnames"),
        ("dns_seeds_apply_command", "manifest prints DNS seed apply commands after read-only checks"),
        ("len(labels) < 2", "manifest rejects single-label DNS seed hostnames"),
        ("re.search(r\"[a-z]\", labels[-1]) is None", "manifest rejects numeric final-label DNS seed hostnames"),
        ("len(label) <= 63", "manifest rejects overlong DNS seed labels"),
        ("parse_byte_sequence", "manifest parses public identity byte fields"),
        ("parse_default_port", "manifest parses public identity default port"),
        ("display_path", "manifest guidance preserves non-default manifest paths"),
        ("shell_quote", "manifest guidance shell-quotes handoff paths"),
        ("ordered_unresolved_blocker_ids", "manifest orders unresolved blocker guidance"),
        ("blocked_fields_for_blocker", "manifest filters field-level blockers by blocker id"),
        ("blocked_field_group_entries", "manifest builds field-level blocker group entries"),
        ("actions_with_blocked_fields", "manifest enriches action entries with blocked fields"),
        ("items_by_network", "manifest groups status items by network"),
        ("item_counts_by_network", "manifest counts status items by network"),
        ("actions_by_network", "manifest groups action entries by network"),
        ("action_counts_by_network", "manifest counts action entries by network"),
        ("actions_by_blocker_type", "manifest groups action entries by blocker type"),
        ("action_counts_by_blocker_type", "manifest counts action entries by blocker type"),
        ("network_step", "manifest includes network-scoped action order"),
        ("network_step_count", "manifest includes network-scoped action count"),
        ("blocker_type_step", "manifest includes blocker-type-scoped action order"),
        ("blocker_type_step_count", "manifest includes blocker-type-scoped action count"),
        ("actions_by_network_and_blocker_type", "manifest groups action entries by network and blocker type"),
        ("action_counts_by_network_and_blocker_type", "manifest counts action entries by network and blocker type"),
        ("next_actions_by_network_and_blocker_type", "manifest exposes next action entries by network and blocker type"),
        ("next_commands_by_network_and_blocker_type", "manifest exposes next commands by network and blocker type"),
        ("next_blocker_commands_by_network_and_blocker_type", "manifest aliases next blocker commands by network and blocker type"),
        ("next_blocker_commands_by_network", "manifest aliases next blocker commands by network"),
        ("next_actions_by_blocker_type", "manifest exposes next action entries by blocker type"),
        ("next_commands_by_blocker_type", "manifest exposes next commands by blocker type"),
        ("next_blocker_commands_by_blocker_type", "manifest aliases next blocker commands by blocker type"),
        ("blockers_by_blocker_type", "manifest groups blocker entries by blocker type"),
        ("blocker_counts_by_blocker_type", "manifest counts blocker entries by blocker type"),
        ("blockers_by_network_and_blocker_type", "manifest groups blocker entries by network and blocker type"),
        ("blocker_counts_by_network_and_blocker_type", "manifest counts blocker entries by network and blocker type"),
        ("blocked_fields_by_blocker_type", "manifest groups blocked fields by blocker type"),
        ("blocked_field_counts_by_blocker_type", "manifest counts blocked fields by blocker type"),
        ("blocked_fields_by_network_and_blocker_type", "manifest groups blocked fields by network and blocker type"),
        ("blocked_field_counts_by_network_and_blocker_type", "manifest counts blocked fields by network and blocker type"),
        ("blocked_field_groups_by_network", "manifest groups blocked field groups by network"),
        ("blocked_field_group_counts_by_network", "manifest counts blocked field groups by network"),
        ("blocked_field_groups_by_blocker_type", "manifest groups blocked field groups by blocker type"),
        ("blocked_field_group_counts_by_blocker_type", "manifest counts blocked field groups by blocker type"),
        ("blocked_field_groups_by_network_and_blocker_type", "manifest groups blocked field groups by network and blocker type"),
        ("blocked_field_group_counts_by_network_and_blocker_type", "manifest counts blocked field groups by network and blocker type"),
        ("blocked_blocker_types_by_network", "manifest summarizes blocked blocker types by network"),
        ("blocked_blocker_type_counts_by_network", "manifest counts blocked blocker types by network"),
        ("ready_blocker_types_by_network", "manifest summarizes ready blocker types by network"),
        ("ready_blocker_type_counts_by_network", "manifest counts ready blocker types by network"),
        ("blocked_networks_by_blocker_type", "manifest summarizes blocked networks by blocker type"),
        ("blocked_network_counts_by_blocker_type", "manifest counts blocked networks by blocker type"),
        ("ready_networks_by_blocker_type", "manifest summarizes ready networks by blocker type"),
        ("ready_network_counts_by_blocker_type", "manifest counts ready networks by blocker type"),
        ("next_blocked_field_groups_by_network_and_blocker_type", "manifest exposes next blocked field groups by network and blocker type"),
        ("next_blocker_field_groups_by_network_and_blocker_type", "manifest aliases next blocker field groups by network and blocker type"),
        ("next_blocked_fields_by_network_and_blocker_type", "manifest exposes next blocked fields by network and blocker type"),
        ("next_blocked_field_counts_by_network_and_blocker_type", "manifest counts next blocked fields by network and blocker type"),
        ("next_blocker_fields_by_network_and_blocker_type", "manifest aliases next blocker fields by network and blocker type"),
        ("next_blocker_field_counts_by_network_and_blocker_type", "manifest aliases next blocker field counts by network and blocker type"),
        ("next_blocked_field_groups_by_blocker_type", "manifest exposes next blocked field groups by blocker type"),
        ("next_blocker_field_groups_by_blocker_type", "manifest aliases next blocker field groups by blocker type"),
        ("next_blocker_fields_by_blocker_type", "manifest aliases next blocker fields by blocker type"),
        ("next_blocker_field_counts_by_blocker_type", "manifest aliases next blocker field counts by blocker type"),
        ("next_blockers_by_network_and_blocker_type", "manifest exposes next blockers by network and blocker type"),
        ("blocker_type_progress_entries", "manifest builds blocker-type progress entries"),
        ("blocker_type_next_blocked_fields", "manifest builds blocker-type next blocked field aliases"),
        ("blocker_type_next_blocked_field_counts", "manifest builds blocker-type next blocked field count aliases"),
        ("blocker_type_next_blockers", "manifest builds blocker-type next blocker aliases"),
        ("blocker_type_next_blocker_networks", "manifest builds blocker-type next network aliases"),
        ("network_progress_entries", "manifest builds network progress entries"),
        ("blocked_networks", "manifest summarizes blocked networks"),
        ("ready_networks", "manifest summarizes ready networks"),
        ("blocked_blocker_types", "manifest summarizes blocked blocker types"),
        ("ready_blocker_types", "manifest summarizes ready blocker types"),
        ("list_summary", "manifest formats compact readiness lists"),
        ("network_count_summary", "manifest formats network counts for readiness summaries"),
        ("blocker_type_count_summary", "manifest formats blocker-type counts for readiness summaries"),
        ("network_blocker_type_count_summary", "manifest formats network blocker-type matrices for readiness summaries"),
        ("network_blocker_type_value_summary", "manifest formats network blocker-type value matrices for readiness summaries"),
        ("blocker_type_list_summary", "manifest formats blocker-type network lists for readiness summaries"),
        ("network_next_blocker_summary", "manifest formats network next blockers for readiness summaries"),
        ("network_next_blocker_field_count_summary", "manifest formats network next blocker field counts for readiness summaries"),
        ("network_next_blocker_command_summary", "manifest formats network next blocker commands for readiness summaries"),
        ("blocked blocker types", "manifest prints blocked blocker types in network readiness summaries"),
        ("ready blocker types", "manifest prints ready blocker types in network readiness summaries"),
        ("blocked networks by blocker type", "manifest prints blocked network lists by blocker type in readiness summaries"),
        ("ready networks by blocker type", "manifest prints ready network lists by blocker type in readiness summaries"),
        ("blocker_type_next_blocker_summary", "manifest formats blocker-type next blockers for readiness summaries"),
        ("blocker_type_next_blocker_network_summary", "manifest formats blocker-type next networks for readiness summaries"),
        ("blocker_type_next_blocker_field_count_summary", "manifest formats blocker-type next field counts for readiness summaries"),
        ("blocker_type_next_action_command_summary", "manifest formats blocker-type next action commands for readiness summaries"),
        ("next network readiness summary commands by blocker type", "manifest prints blocker-type next network summary commands for readiness summaries"),
        ("next blocker type readiness summary commands by blocker type", "manifest prints blocker-type next blocker-type summary commands for readiness summaries"),
        ("next blocker type readiness summary commands by network", "manifest prints network next blocker-type summary commands for readiness summaries"),
        ("next blocker readiness summary commands by blocker type", "manifest prints blocker-type next blocker summary commands for readiness summaries"),
        ("next blocker readiness summary commands by network", "manifest prints network next blocker summary commands for readiness summaries"),
        ("action plan command:", "manifest prints action-plan commands in readiness summaries"),
        ("next action command:", "manifest prints next-action commands in readiness summaries"),
        ("readiness summary command:", "manifest prints rerun commands in readiness summaries"),
        ("status JSON command:", "manifest prints status-json commands in readiness summaries"),
        ("network_readiness_summary_command_summary", "manifest formats network readiness-summary commands for readiness summaries"),
        ("blocker_type_readiness_summary_command_summary", "manifest formats blocker-type readiness-summary commands for readiness summaries"),
        ("blocker_readiness_summary_commands", "manifest builds blocker readiness-summary command maps"),
        ("blocker_readiness_summary_command_summary", "manifest formats blocker readiness-summary command summaries"),
        ("network launch order", "manifest prints blocker order within its network in blocker readiness summaries"),
        ("blocker-type launch order", "manifest prints blocker order within its blocker type in blocker readiness summaries"),
        ("earlier blocker readiness summary commands", "manifest prints earlier blocker summary commands for blocker readiness summaries"),
        ("later blocker readiness summary commands", "manifest prints later blocker summary commands for readiness summaries"),
        ("yes_no", "manifest formats readiness booleans"),
        ("COMMAND_FIELDS", "manifest centralizes command field order"),
        ("action_command_fields", "manifest builds current action command aliases"),
        ("action_command_keys", "manifest builds current action command key aliases"),
        ("action_command_values", "manifest builds current action command value aliases"),
        ("action_command_pairs", "manifest builds current action command pair aliases"),
        ("blocker_action_commands", "manifest builds machine-readable blocker commands"),
        ("next_action_text", "manifest prints next action guidance"),
        ("append_blocker_command_lines", "manifest prints copyable blocker command lines"),
        ("append_blocker_field_lines", "manifest prints human-readable blocked field paths"),
        ("action_plan_entries", "manifest builds reusable action-plan entries"),
        ("blocker_action_entry", "manifest builds action entries with blocker metadata"),
        ("action_plan_text", "manifest prints full action-plan guidance"),
        ("readiness_summary_text", "manifest prints compact readiness guidance"),
        ("network_readiness_summary_text", "manifest prints network-scoped readiness guidance"),
        ("blocker_type_readiness_summary_text", "manifest prints blocker-type-scoped readiness guidance"),
        ("blocker_readiness_summary_text", "manifest prints blocker-scoped readiness guidance"),
        ("status_json_text", "manifest prints machine-readable status guidance"),
        ("schema_version", "manifest status JSON includes a schema version"),
        ("action_count", "manifest status JSON includes an action count"),
        ("action_ids", "manifest status JSON includes action id aliases"),
        ("action_kinds", "manifest status JSON includes action kind aliases"),
        ("action_steps", "manifest status JSON includes action step aliases"),
        ("action_networks", "manifest status JSON includes action network aliases"),
        ("action_blocker_types", "manifest status JSON includes action blocker type aliases"),
        ("action_field_counts", "manifest status JSON includes action field count aliases"),
        ("action_commands", "manifest status JSON includes action command aliases"),
        ("action_command_count", "manifest status JSON counts action command aliases"),
        ("action_command_keys", "manifest status JSON includes action command key aliases"),
        ("action_command_key_counts", "manifest status JSON counts action command key aliases"),
        ("action_command_values", "manifest status JSON includes action command value aliases"),
        ("action_command_value_counts", "manifest status JSON counts action command value aliases"),
        ("action_command_pairs", "manifest status JSON includes action command pair aliases"),
        ("action_command_pair_counts", "manifest status JSON counts action command pair aliases"),
        ("command_field_order", "manifest status JSON exposes command field order"),
        ("command_field_count", "manifest status JSON counts command fields"),
        ("later_actions", "manifest status JSON includes later action aliases"),
        ("later_action_count", "manifest status JSON counts later action aliases"),
        ("later_action_ids", "manifest status JSON includes later action id aliases"),
        ("later_action_kinds", "manifest status JSON includes later action kind aliases"),
        ("later_action_steps", "manifest status JSON includes later action step aliases"),
        ("later_action_networks", "manifest status JSON includes later action network aliases"),
        ("later_action_blocker_types", "manifest status JSON includes later action blocker type aliases"),
        ("later_action_field_counts", "manifest status JSON includes later action field count aliases"),
        ("later_commands", "manifest status JSON includes later command aliases"),
        ("later_command_count", "manifest status JSON counts later command aliases"),
        ("later_command_keys", "manifest status JSON includes later command key aliases"),
        ("later_command_key_counts", "manifest status JSON counts later command key aliases"),
        ("later_command_values", "manifest status JSON includes later command value aliases"),
        ("later_command_value_counts", "manifest status JSON counts later command value aliases"),
        ("later_command_pairs", "manifest status JSON includes later command pair aliases"),
        ("later_command_pair_counts", "manifest status JSON counts later command pair aliases"),
        ("actions_by_network", "manifest status JSON groups actions by network"),
        ("action_counts_by_network", "manifest status JSON counts actions by network"),
        ("actions_by_blocker_type", "manifest status JSON groups actions by blocker type"),
        ("action_counts_by_blocker_type", "manifest status JSON counts actions by blocker type"),
        ("actions_by_network_and_blocker_type", "manifest status JSON groups actions by network and blocker type"),
        ("action_counts_by_network_and_blocker_type", "manifest status JSON counts actions by network and blocker type"),
        ("next_actions_by_network_and_blocker_type", "manifest status JSON includes next actions by network and blocker type"),
        ("next_commands_by_network_and_blocker_type", "manifest status JSON includes next commands by network and blocker type"),
        ("next_blocker_commands_by_network_and_blocker_type", "manifest status JSON aliases network blocker-type next blocker commands"),
        ("next_actions_by_blocker_type", "manifest status JSON includes next actions by blocker type"),
        ("next_commands_by_blocker_type", "manifest status JSON includes next commands by blocker type"),
        ("next_blocker_commands_by_blocker_type", "manifest status JSON aliases blocker-type next blocker commands"),
        ("next_blocked_field_groups_by_blocker_type", "manifest status JSON includes blocker-type next blocked field groups"),
        ("next_blocker_field_groups_by_blocker_type", "manifest status JSON aliases blocker-type next blocker field groups"),
        ("next_blocked_fields_by_blocker_type", "manifest status JSON includes blocker-type next blocked fields"),
        ("next_blocked_field_counts_by_blocker_type", "manifest status JSON counts blocker-type next blocked fields"),
        ("next_blockers_by_blocker_type", "manifest status JSON includes blocker-type next blockers"),
        ("next_blocker_networks_by_blocker_type", "manifest status JSON includes blocker-type next networks"),
        ("action_plan_command", "manifest status JSON includes a copyable action-plan command"),
        ("readiness_summary_command", "manifest status JSON includes a copyable readiness-summary command"),
        ("status_json_command", "manifest status JSON includes a copyable status-json command"),
        ("status_command_fields(manifest_path)", "manifest status JSON includes a copyable command map"),
        ("next_action", "manifest status JSON includes the current handoff action"),
        ("next_action_id", "manifest status JSON includes current next action id alias"),
        ("next_action_kind", "manifest status JSON includes current next action kind alias"),
        ("next_action_step", "manifest status JSON includes current next action step alias"),
        ("next_action_network", "manifest status JSON includes current next action network alias"),
        ("next_action_blocker_type", "manifest status JSON includes current next action blocker type alias"),
        ("next_action_field_count", "manifest status JSON includes current next action field count alias"),
        ("next_action_command", "manifest status JSON includes a copyable next-action command"),
        ("next_commands", "manifest status JSON includes current handoff commands"),
        ("next_command_keys", "manifest status JSON includes current handoff command keys"),
        ("next_command_key_count", "manifest status JSON counts current handoff command keys"),
        ("next_command_value_count", "manifest status JSON counts current handoff command values"),
        ("next_command_pair_count", "manifest status JSON counts current handoff command pairs"),
        ("network_next_command_fields", "manifest status JSON includes network-scoped current handoff commands"),
        ("network_next_blocked_field_groups", "manifest status JSON includes network-scoped next blocked field groups"),
        ("network_next_blocked_fields", "manifest status JSON includes network-scoped next blocked fields"),
        ("network_next_blockers", "manifest status JSON includes network-scoped next blockers"),
        ("network_next_blocker_types", "manifest status JSON includes network-scoped next blocker types"),
        ("check_command", "manifest status JSON includes current check commands"),
        ("apply_command", "manifest status JSON includes current apply commands"),
        ("readiness_summary_command", "manifest status JSON includes current readiness-summary commands"),
        ("field_count", "manifest status JSON includes action field counts"),
        ("blocked_field_count", "manifest status JSON includes a blocked field count"),
        ("blocked_network_count", "manifest status JSON includes a blocked network count"),
        ("ready_network_count", "manifest status JSON includes a ready network count"),
        ("blocked_blocker_type_count", "manifest status JSON includes a blocked blocker-type count"),
        ("blocked_blocker_types", "manifest status JSON includes blocked blocker types"),
        ("ready_blocker_type_count", "manifest status JSON includes a ready blocker-type count"),
        ("ready_blocker_types", "manifest status JSON includes ready blocker types"),
        ("blocked_blocker_type_counts_by_network", "manifest status JSON includes blocked blocker-type counts by network"),
        ("blocked_blocker_types_by_network", "manifest status JSON includes blocked blocker types by network"),
        ("ready_blocker_type_counts_by_network", "manifest status JSON includes ready blocker-type counts by network"),
        ("ready_blocker_types_by_network", "manifest status JSON includes ready blocker types by network"),
        ("blocked_network_counts_by_blocker_type", "manifest status JSON includes blocked network counts by blocker type"),
        ("blocked_networks_by_blocker_type", "manifest status JSON includes blocked networks by blocker type"),
        ("ready_network_counts_by_blocker_type", "manifest status JSON includes ready network counts by blocker type"),
        ("ready_networks_by_blocker_type", "manifest status JSON includes ready networks by blocker type"),
        ("unresolved_blockers_by_network", "manifest status JSON groups blockers by network"),
        ("unresolved_blocker_counts_by_network", "manifest status JSON counts blockers by network"),
        ("unresolved_blockers_by_blocker_type", "manifest status JSON groups blockers by blocker type"),
        ("unresolved_blocker_counts_by_blocker_type", "manifest status JSON counts blockers by blocker type"),
        ("unresolved_blockers_by_network_and_blocker_type", "manifest status JSON groups blockers by network and blocker type"),
        ("unresolved_blocker_counts_by_network_and_blocker_type", "manifest status JSON counts blockers by network and blocker type"),
        ("blocked_fields_by_network", "manifest status JSON groups blocked fields by network"),
        ("blocked_field_counts_by_network", "manifest status JSON counts blocked fields by network"),
        ("blocked_fields_by_blocker_type", "manifest status JSON groups blocked fields by blocker type"),
        ("blocked_field_counts_by_blocker_type", "manifest status JSON counts blocked fields by blocker type"),
        ("blocked_fields_by_network_and_blocker_type", "manifest status JSON groups blocked fields by network and blocker type"),
        ("blocked_field_counts_by_network_and_blocker_type", "manifest status JSON counts blocked fields by network and blocker type"),
        ("blocked_field_groups_by_network", "manifest status JSON groups blocked field groups by network"),
        ("blocked_field_group_counts_by_network", "manifest status JSON counts blocked field groups by network"),
        ("blocked_field_groups_by_blocker_type", "manifest status JSON groups blocked field groups by blocker type"),
        ("blocked_field_group_counts_by_blocker_type", "manifest status JSON counts blocked field groups by blocker type"),
        ("blocked_field_groups_by_network_and_blocker_type", "manifest status JSON groups blocked field groups by network and blocker type"),
        ("blocked_field_group_counts_by_network_and_blocker_type", "manifest status JSON counts blocked field groups by network and blocker type"),
        ("next_blocked_field_groups_by_network_and_blocker_type", "manifest status JSON includes next blocked field groups by network and blocker type"),
        ("next_blocker_field_groups_by_network_and_blocker_type", "manifest status JSON aliases next blocker field groups by network and blocker type"),
        ("next_blocked_fields_by_network_and_blocker_type", "manifest status JSON includes next blocked fields by network and blocker type"),
        ("next_blocked_field_counts_by_network_and_blocker_type", "manifest status JSON counts next blocked fields by network and blocker type"),
        ("next_blocker_fields_by_network_and_blocker_type", "manifest status JSON aliases next blocker fields by network and blocker type"),
        ("next_blocker_field_counts_by_network_and_blocker_type", "manifest status JSON aliases next blocker field counts by network and blocker type"),
        ("next_blocked_field_groups_by_blocker_type", "manifest status JSON includes blocker-type next blocked field groups"),
        ("next_blocker_field_groups_by_blocker_type", "manifest status JSON aliases blocker-type next blocker field groups"),
        ("next_blocker_fields_by_blocker_type", "manifest status JSON aliases blocker-type next blocker fields"),
        ("next_blocker_field_counts_by_blocker_type", "manifest status JSON aliases blocker-type next blocker field counts"),
        ("next_blockers_by_network_and_blocker_type", "manifest status JSON includes next blockers by network and blocker type"),
        ("network_readiness_summary_commands_by_network", "manifest status JSON includes network readiness-summary commands"),
        ("network_readiness_summary_command_count", "manifest status JSON counts network readiness-summary commands"),
        ("blocker_type_readiness_summary_commands_by_blocker_type", "manifest status JSON includes blocker-type readiness-summary commands"),
        ("blocker_type_readiness_summary_command_count", "manifest status JSON counts blocker-type readiness-summary commands"),
        ("blocker_readiness_summary_commands_by_blocker", "manifest status JSON includes blocker readiness-summary commands"),
        ("blocker_readiness_summary_command_count", "manifest status JSON counts blocker readiness-summary commands"),
        ("blocker_type_progress", "manifest status JSON includes blocker-type progress entries"),
        ("next_commands_by_network", "manifest status JSON includes per-network next commands"),
        ("next_blocker_commands_by_network", "manifest status JSON aliases per-network next blocker commands"),
        ("next_blocked_field_groups_by_network", "manifest status JSON includes per-network next blocked field groups"),
        ("next_blocker_field_groups_by_network", "manifest status JSON aliases per-network next blocker field groups"),
        ("next_blocked_fields_by_network", "manifest status JSON includes per-network next blocked fields"),
        ("next_blocked_field_counts_by_network", "manifest status JSON counts per-network next blocked fields"),
        ("next_blocker_fields_by_network", "manifest status JSON aliases per-network next blocker fields"),
        ("next_blocker_field_counts_by_network", "manifest status JSON aliases per-network next blocker field counts"),
        ("next_blockers_by_network", "manifest status JSON includes per-network next blockers"),
        ("next_blocker_types_by_network", "manifest status JSON includes per-network next blocker types"),
        ("network_progress", "manifest status JSON includes network progress entries"),
        ("blocked_field_groups", "manifest status JSON includes blocked field groups"),
        ("blocked_field_group_count", "manifest status JSON includes a blocked field group count"),
        ("blocker_type", "manifest status JSON includes blocked field group blocker type"),
        ("next_blocked_field_group", "manifest status JSON includes current blocked field group"),
        ("next_blocker_field_group", "manifest status JSON aliases current blocker field group"),
        ("next_blocker", "manifest status JSON includes current blocker aliases"),
        ("next_blocker_step", "manifest status JSON includes current blocker global order"),
        ("next_blocker_network_step", "manifest status JSON includes current blocker network order"),
        ("next_blocker_network_step_count", "manifest status JSON includes current blocker network count"),
        ("next_blocker_type_step", "manifest status JSON includes current blocker type order"),
        ("next_blocker_type_step_count", "manifest status JSON includes current blocker type count"),
        ("next_blocker_commands", "manifest status JSON includes current blocker command aliases"),
        ("next_blocker_fields", "manifest status JSON includes current blocker field aliases"),
        ("later_blockers", "manifest status JSON includes later blocker aliases"),
        ("later_blocker_count", "manifest status JSON counts later blocker aliases"),
        ("later_blocker_readiness_summary_commands_by_blocker", "manifest status JSON includes later blocker summary command aliases"),
        ("later_blocker_readiness_summary_command_count", "manifest status JSON counts later blocker summary command aliases"),
        ("later_blocker_field_groups", "manifest status JSON includes later blocker field group aliases"),
        ("later_blocker_field_group_count", "manifest status JSON counts later blocker field group aliases"),
        ("later_blocker_fields", "manifest status JSON includes later blocker field aliases"),
        ("later_blocker_field_count", "manifest status JSON counts later blocker field aliases"),
        ("next_blocked_field_count", "manifest status JSON includes a next blocked field count"),
        ("next_blocked_fields", "manifest status JSON includes next blocked fields"),
        ("blocked_fields", "manifest status JSON includes field-level blockers"),
        ("require_unique_manifest_value", "manifest reports duplicate ready-value paths"),
        ("validate_unique_launch_values", "manifest rejects cross-network launch value collisions"),
        ("validation_failure_message", "manifest emits detailed transition failures"),
        ("mark_ready", "manifest marks complete profiles ready only after validation"),
        ("demote_ready_for_review", "manifest demotes edited ready profiles for re-review"),
        ("set_auxpow", "manifest updates AuxPoW chain id"),
        ("set_dns_seeds", "manifest updates DNS seeds"),
        ("checked_dns_seeds_candidate", "manifest checks DNS seed candidates without writing"),
        ("dns_seeds_check_text", "manifest prints DNS seed candidate check summaries"),
        (
            "dns_seeds_check_text(args.check_dns_seeds[0], dns_seeds, candidate, args.manifest)",
            "manifest reports DNS seed candidate progress",
        ),
        ("set_identity", "manifest updates public network identity"),
        ("identity_profile_from_args", "manifest builds public identity profiles from checked inputs"),
        ("checked_identity_candidate", "manifest checks public identity candidates without writing"),
        ("identity_apply_command", "manifest prints public identity apply commands after read-only checks"),
        ("identity_check_text", "manifest prints public identity candidate check summaries"),
        (
            "identity_check_text(args.check_identity[0], identity, candidate, args.manifest)",
            "manifest reports public identity candidate progress",
        ),
        ("remove_blocker(manifest, f\"{network}.public_network_identity\")", "manifest removes resolved public identity blocker"),
        ("remove_blocker(manifest, f\"{network}.dns_seeds\")", "manifest removes resolved DNS seed blocker"),
        ("remove_blocker(manifest, f\"{network}.auxpow_chain_id\")", "manifest removes resolved AuxPoW blocker"),
        ("remove_blocker(manifest, f\"{network}.litecoin_snapshot\")", "manifest removes resolved snapshot blocker"),
        ("unresolved_blocker_ids", "manifest derives blockers from unresolved fields"),
        ("hashUTXORoot", "manifest emits snapshot import hash assignment"),
        ("nStartHeight = 0", "manifest emits always-active Taproot height reset"),
        ("vSeeds.emplace_back", "manifest emits DNS seed assignments"),
        ("base58Prefixes[EXT_PUBLIC_KEY]", "manifest emits extended key prefixes"),
        ("chainparams_class_block", "manifest extracts chainparams class blocks"),
        ("chainparams_sync_errors", "manifest checks emitted chainparams snippets against source"),
    )
    for needle, description in manifest_tool_checks:
        error = require_text(PUBLIC_LAUNCH_MANIFEST_TOOL, needle, description)
        if error:
            return fail(PUBLIC_LAUNCH_MANIFEST_TOOL, error)

    error = require_public_launch_manifest_current()
    if error:
        return fail(PUBLIC_LAUNCH_MANIFEST, error)

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
        ("const PublicLaunchProfileStatus public_launch = GetPublicLaunchProfileStatus(chainparams);", "public launch status captured for diagnostics"),
        ("if (!public_launch.configured) {", "public launch readiness gate"),
        ("Missing hardcoded launch checks", "public launch startup diagnostic failures"),
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
            "ChainParams_PUBLIC_launch_profile_failure_reasons_are_actionable",
            "runtime public launch failure reason unit test",
        ),
        ("AuxPoW chain id still uses the launch placeholder", "runtime placeholder AuxPoW chain-id failure coverage"),
        ("SetAuxPowChainId(0x5a4b)", "runtime placeholder AuxPoW chain-id rejection fixture"),
        (
            "ChainParams_PUBLIC_identity_failure_reasons_are_actionable",
            "runtime public identity failure reason unit test",
        ),
        (
            "GetPublicLaunchProfileFailures(",
            "runtime public launch failure helper coverage",
        ),
        (
            "GetPublicNetworkIdentityFailures(",
            "runtime public identity failure helper coverage",
        ),
        (
            "ChainParams_REGTEST_launch_profile_accepts_complete_rehearsal_args",
            "runtime positive launch-profile rehearsal unit test",
        ),
        (
            "ChainParams_PUBLIC_launch_profile_accepts_complete_non_mockable_values",
            "runtime positive non-mockable launch-profile unit test",
        ),
        (
            "chainParams.ConfigureCompleteLaunchProfile();",
            "test-only complete non-mockable launch-profile fixture",
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
        ("std::string(84, 'z')", "runtime overlong Bech32 HRP rejection coverage"),
        ("std::string(84, 'm')", "runtime overlong MWEB HRP rejection coverage"),
        ("seed.zkcoin.localhost", "runtime reserved DNS seed suffix rejection coverage"),
        ("std::string(64, 'a') + \".zkcoin.net\"", "runtime overlong DNS seed label rejection coverage"),
        ("seed.zkcoin.123", "runtime numeric final-label DNS seed rejection coverage"),
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
        ("reject_duplicate_json_fields", "preflight rejects duplicate getblockchaininfo JSON fields"),
        (
            "object_pairs_hook=reject_duplicate_json_fields",
            "preflight parses getblockchaininfo JSON without duplicate shadowing",
        ),
        (
            "getblockchaininfo contains duplicate field",
            "preflight explains duplicate getblockchaininfo JSON field rejection",
        ),
        (
            "getblockchaininfo response must be a JSON object",
            "preflight rejects non-object getblockchaininfo JSON",
        ),
        (
            "getblockchaininfo.chain must be a recognized chain name",
            "preflight validates chain name shape",
        ),
        (
            "getblockchaininfo.ltc_snapshot.imported must match launch_readiness.snapshot_imported",
            "preflight cross-checks snapshot import detail",
        ),
        (
            "getblockchaininfo.ltc_snapshot.height must be a positive integer",
            "preflight validates configured snapshot height shape",
        ),
        (
            "getblockchaininfo.ltc_snapshot.import_hash must be a non-null lowercase 64-character hex string",
            "preflight validates configured snapshot import hash shape",
        ),
        (
            "getblockchaininfo.blocks must be 0 when launch_readiness.at_launch_tip is true",
            "preflight cross-checks launch-tip chain height",
        ),
        (
            "getblockchaininfo.headers must be 0 when launch_readiness.at_launch_tip is true",
            "preflight cross-checks launch-tip header height",
        ),
        (
            "getblockchaininfo.bestblockhash must be a non-null lowercase 64-character hex string",
            "preflight validates launch-tip hash shape",
        ),
        (
            "getblockchaininfo.chainwork must be a non-null lowercase 64-character hex string",
            "preflight validates chainwork shape",
        ),
        (
            "getblockchaininfo.verificationprogress must be a non-negative number not exceeding 1",
            "preflight validates bounded verification progress shape",
        ),
        (
            "getblockchaininfo.difficulty must be a non-negative number",
            "preflight validates difficulty shape",
        ),
        (
            "getblockchaininfo.size_on_disk must be a positive integer",
            "preflight validates disk footprint shape",
        ),
        (
            "getblockchaininfo.time must be a non-negative integer",
            "preflight validates launch-tip time shape",
        ),
        (
            "getblockchaininfo.mediantime must be less than or equal to time",
            "preflight validates launch-tip median time ordering",
        ),
        (
            "getblockchaininfo.initialblockdownload must be a boolean",
            "preflight validates initial block download shape",
        ),
        ("node is still in initial block download", "preflight rejects initial block download"),
        (
            "getblockchaininfo.pruned must be a boolean",
            "preflight validates pruned mode shape",
        ),
        ("launch node is running in pruned mode", "preflight rejects pruned mode"),
        (
            "getblockchaininfo.warnings must be a string",
            "preflight validates node warning shape",
        ),
        ("launch node reports warnings", "preflight rejects node warnings"),
        ("snapshot import is still in progress", "preflight rejects in-progress snapshot imports"),
        (
            "getblockchaininfo.auxpow.next_block_active must match launch_readiness.auxpow_active_at_launch at the launch tip",
            "preflight cross-checks AuxPoW next-block activation detail",
        ),
        (
            "getblockchaininfo.auxpow.start_height must be 1 when launch_readiness.auxpow_active_at_launch is true",
            "preflight validates AuxPoW launch start height",
        ),
        (
            "getblockchaininfo.auxpow.strict_chain_id must be true when launch_readiness.chain_id_configured is true",
            "preflight cross-checks strict AuxPoW chain-id detail",
        ),
        (
            "AuxPoW chain id is still the local launch placeholder 0x5a4b",
            "preflight rejects placeholder AuxPoW chain id",
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
        (
            "getblockchaininfo.shielded_pool.start_height must not be 1 when launch_readiness.shielded_inactive_at_launch is true",
            "preflight rejects shielded launch-height activation detail",
        ),
    )
    for needle, description in preflight_checks:
        error = require_text(LAUNCH_PREFLIGHT, needle, description)
        if error:
            return fail(LAUNCH_PREFLIGHT, error)

    preflight_test_checks = (
        (
            "Reject duplicate getblockchaininfo fields in launch preflight",
            "preflight fake-CLI duplicate JSON field coverage",
        ),
        (
            "Reject non-object getblockchaininfo JSON in launch preflight",
            "preflight fake-CLI non-object JSON coverage",
        ),
        (
            "Reject placeholder AuxPoW chain id in launch preflight",
            "preflight fake-CLI placeholder AuxPoW chain-id coverage",
        ),
        (
            '"AuxPoW chain id is still the local launch placeholder 0x5a4b"',
            "preflight fake-CLI placeholder AuxPoW chain-id assertion",
        ),
        (
            "Reject launch-tip readiness away from genesis height",
            "preflight fake-CLI launch-tip height coverage",
        ),
        (
            "Reject malformed chain name in launch preflight",
            "preflight fake-CLI chain name coverage",
        ),
        (
            "Reject malformed header height in launch preflight",
            "preflight fake-CLI header height coverage",
        ),
        (
            "Reject malformed best block hash in launch preflight",
            "preflight fake-CLI launch-tip hash coverage",
        ),
        (
            "Reject malformed chainwork in launch preflight",
            "preflight fake-CLI chainwork coverage",
        ),
        (
            "Reject malformed verification progress in launch preflight",
            "preflight fake-CLI verification progress coverage",
        ),
        (
            "over_one_verification_progress",
            "preflight fake-CLI rejects over-one verification progress",
        ),
        (
            "Reject malformed difficulty in launch preflight",
            "preflight fake-CLI difficulty coverage",
        ),
        (
            "Reject malformed size on disk in launch preflight",
            "preflight fake-CLI disk footprint coverage",
        ),
        (
            "Reject malformed launch-tip times in launch preflight",
            "preflight fake-CLI launch-tip time coverage",
        ),
        (
            "Reject initial block download in launch preflight",
            "preflight fake-CLI initial block download coverage",
        ),
        (
            "Reject pruned mode in launch preflight",
            "preflight fake-CLI pruned mode coverage",
        ),
        (
            "Reject node warnings in launch preflight",
            "preflight fake-CLI node warning coverage",
        ),
        (
            "Reject malformed configured snapshot detail shape",
            "preflight fake-CLI snapshot detail shape coverage",
        ),
        (
            "Reject malformed or non-launch AuxPoW start height",
            "preflight fake-CLI AuxPoW start-height coverage",
        ),
        (
            "Reject malformed or launch-height shielded start height",
            "preflight fake-CLI shielded start-height coverage",
        ),
    )
    for needle, description in preflight_test_checks:
        error = require_text(LAUNCH_PREFLIGHT_TEST, needle, description)
        if error:
            return fail(LAUNCH_PREFLIGHT_TEST, error)

    ltc_snapshot_script_checks = (
        ("Snapshot public launch-profile manifest handoff", "snapshot script prints manifest handoff section"),
        ("public launch-profile manifest handoff\ncommands", "snapshot script usage describes manifest handoff commands"),
        ("ZKCOIN_SNAPSHOT_AUDIT_JSON", "snapshot script writes optional audit summary"),
        ("write_audit_summary", "snapshot script writes audit summaries through a hardened path"),
        ("open_direct_audit_parent_directory", "snapshot script rechecks audit output parents before writes"),
        ("os.O_EXCL", "snapshot script creates audit summaries exclusively"),
        ("os.fsync", "snapshot script fsyncs audit summary writes"),
        ("height must be a positive integer", "snapshot script rejects zero or malformed snapshot heights"),
        ("expected block hash must be a lowercase 64-character hex string", "snapshot script rejects non-lowercase expected block hashes"),
        ("expected block hash must not be the null uint256", "snapshot script rejects null expected block hashes"),
        ("NULL_UINT256", "snapshot script rejects null verifier hashes"),
        ("litecoin-cli getblockchaininfo did not return JSON", "snapshot script validates source chain info JSON"),
        ("response must be a JSON object", "snapshot script rejects non-object RPC JSON"),
        ("reject_duplicate_json_fields", "snapshot script rejects duplicate RPC JSON fields"),
        ("object_pairs_hook=reject_duplicate_json_fields", "snapshot script parses RPC JSON without duplicate shadowing"),
        ("must be a lowercase 64-character hex string", "snapshot script rejects non-lowercase RPC snapshot hashes"),
        ('require_string("chain")', "snapshot script validates source chain name shape"),
        ("Litecoin source node chain must be main or test for public snapshot generation", "snapshot script rejects non-public source chains"),
        (
            "litecoin-cli getblockchaininfo.bestblockhash must be a non-null lowercase 64-character hex string",
            "snapshot script validates source best block hash shape",
        ),
        (
            "litecoin-cli getblockchaininfo.bestblockhash must match expected block hash when source tip is at snapshot height",
            "snapshot script validates source active tip hash",
        ),
        (
            "litecoin-cli getblockchaininfo.chainwork must be a non-null lowercase 64-character hex string",
            "snapshot script validates source chainwork shape",
        ),
        (
            "litecoin-cli getblockchaininfo.verificationprogress must be a non-negative number not exceeding 1",
            "snapshot script validates bounded source verification progress shape",
        ),
        (
            "litecoin-cli getblockchaininfo.difficulty must be a non-negative number",
            "snapshot script validates source difficulty shape",
        ),
        ('require_positive_int("size_on_disk")', "snapshot script validates source disk footprint shape"),
        ('require_nonnegative_int("headers")', "snapshot script validates source header height shape"),
        ('require_nonnegative_int("time")', "snapshot script validates source tip time shape"),
        ('require_nonnegative_int("mediantime")', "snapshot script validates source median time shape"),
        (
            "litecoin-cli getblockchaininfo.mediantime must be less than or equal to time",
            "snapshot script validates source median time ordering",
        ),
        (
            "litecoin-cli getblockchaininfo.headers must be greater than or equal to blocks",
            "snapshot script validates source header/block ordering",
        ),
        ("headers are ahead of downloaded blocks", "snapshot script rejects incompletely synced source headers"),
        ('require_bool("initialblockdownload")', "snapshot script validates source IBD flag shape"),
        ('require_bool("pruned")', "snapshot script validates source pruned flag shape"),
        ("Litecoin source node is still in initial block download", "snapshot script rejects IBD source nodes"),
        ("Litecoin source node must not be pruned for snapshot generation", "snapshot script rejects pruned source nodes"),
        ("litecoin-cli getblockchaininfo.warnings must be a string", "snapshot script validates source warning shape"),
        ("Litecoin source node reports warnings", "snapshot script rejects warned source nodes"),
        ("snapshot audit summary path must differ from snapshot output path", "snapshot script rejects audit path collisions"),
        ("SNAPSHOT_CANONICAL_PATH", "snapshot script canonicalizes output paths before collision checks"),
        ("SNAPSHOT_INCOMPLETE_CANONICAL_PATH", "snapshot script canonicalizes incomplete output paths before collision checks"),
        ("AUDIT_CANONICAL_PATH", "snapshot script canonicalizes audit output paths before collision checks"),
        ("snapshot audit summary path must differ from snapshot incomplete output path", "snapshot script rejects audit path collisions with dump work files"),
        ("path must not contain control characters", "snapshot script rejects control-character output paths"),
        ("snapshot audit summary path must not be a symlink", "snapshot script rejects symlink audit output paths"),
        ("snapshot audit summary directory does not exist", "snapshot script rejects missing audit output directories"),
        ("snapshot audit summary directory is not writable", "snapshot script rejects unwritable audit output directories"),
        ("snapshot audit summary directory must not be a symlink", "snapshot script rejects symlink audit output directories"),
        ("ZKCOIN_SNAPSHOT_AUDIT_DIR_FINGERPRINT", "snapshot script fingerprints audit output directories before RPC calls"),
        ("snapshot audit summary directory changed during snapshot verification", "snapshot script rejects audit output directory replacement"),
        ("snapshot output path must not be a symlink", "snapshot script rejects symlink snapshot output paths"),
        ("directory does not exist", "snapshot script rejects missing snapshot output directories"),
        ("snapshot output directory is not writable", "snapshot script rejects unwritable snapshot output directories"),
        ("directory must not be a symlink", "snapshot script rejects symlink snapshot output directories"),
        ("SNAPSHOT_DIR_FINGERPRINT", "snapshot script fingerprints snapshot output directories before RPC calls"),
        ("require_snapshot_output_directory_direct", "snapshot script rechecks snapshot output parents after RPC calls"),
        ("snapshot output directory changed during snapshot generation", "snapshot script rejects snapshot output directory replacement"),
        ("snapshot incomplete output path must not be a symlink", "snapshot script rejects symlink dump work files"),
        ("snapshot incomplete output already exists", "snapshot script rejects pre-existing dump work files"),
        ("snapshot incomplete output remained after dumptxoutset", "snapshot script rejects leftover dump work files"),
        ("restore block hash at height", "snapshot script validates rewind restore hashes"),
        (
            "litecoin-cli getblockcount after rewind returned unexpected value",
            "snapshot script validates post-rewind tip shape",
        ),
        ("snapshot block hash at height", "snapshot script validates source snapshot block hashes"),
        ("Litecoin source tip after rewind is", "snapshot script verifies post-rewind source tip"),
        ("snapshot output was not created by dumptxoutset", "snapshot script rejects missing dump artifact"),
        ("snapshot output must not be a symlink after dumptxoutset", "snapshot script rejects symlink dump artifacts"),
        ("snapshot output is empty after dumptxoutset", "snapshot script rejects empty dump artifact"),
        ("snapshot_file_metadata", "snapshot script fingerprints dump artifacts through a stable helper"),
        ("snapshot output changed during fingerprinting", "snapshot script rejects dump artifact replacement during fingerprinting"),
        ("SNAPSHOT_FILE_SHA256", "snapshot script fingerprints dump artifacts"),
        ("POST_VERIFY_SNAPSHOT_FILE_SHA256", "snapshot script rechecks dump artifact after verification"),
        (
            "read -r POST_VERIFY_SNAPSHOT_FILE_SIZE POST_VERIFY_SNAPSHOT_FILE_SHA256",
            "snapshot script rechecks dump artifacts after verification through the stable helper",
        ),
        ("snapshot output became a symlink during verification", "snapshot script rejects verifier-time symlink replacement"),
        ("snapshot output changed during verification", "snapshot script rejects artifact mutation during verification"),
        ("dumptxoutset base_height mismatch", "snapshot script rejects dump metadata before verifier handoff"),
        ("dumptxoutset.path must match requested snapshot output path", "snapshot script rejects dump output path mismatches"),
        ("INT_RE", "snapshot script rejects fractional audit heights and counts"),
        ("require_positive_int", "snapshot script requires positive audit counts"),
        ("MAX_MONEY", "snapshot script caps verifier total amount at inherited Litecoin supply"),
        ("positive decimal amount with 8 fractional digits", "snapshot script validates verifier total amount"),
        ("must not exceed {MAX_MONEY_TEXT}", "snapshot script rejects over-maximum verifier total amount"),
        ("AUDIT_SUMMARY_FIELDS", "snapshot script preserves audit summary field order"),
        ("snapshot audit summary field order does not match public launch template", "snapshot script fails on audit summary field-order drift"),
        ("json.dumps(summary, indent=2, sort_keys=False)", "snapshot script does not sort audit summary keys"),
        ("shell_quote", "snapshot script shell-quotes handoff paths"),
        ("target_network", "snapshot script derives the target public profile from the Litecoin source chain"),
        ("--snapshot-audit-template {target_network}", "snapshot script prints audit template handoff command"),
        ("--check-snapshot-audit {target_network}", "snapshot script prints audit-backed manifest check command"),
        ("--set-snapshot-audit {target_network}", "snapshot script prints audit-backed manifest update command"),
        ("--readiness-summary contrib/devtools/zkcoin_public_launch_profile_manifest.json", "snapshot script prints post-apply readiness summary command"),
        ("--blocker-readiness-summary {blocker_id}", "snapshot script prints blocker-scoped post-apply summary command"),
        ("zkcoin_public_launch_profile_manifest.json", "snapshot script points at public launch manifest"),
    )
    for needle, description in ltc_snapshot_script_checks:
        error = require_text(LTC_SNAPSHOT_SCRIPT, needle, description)
        if error:
            return fail(LTC_SNAPSHOT_SCRIPT, error)

    ltc_snapshot_script_test_checks = (
        ("Snapshot public launch-profile manifest handoff:", "snapshot script test checks manifest handoff section"),
        ("Snapshot audit summary written:", "snapshot script test checks audit summary output"),
        ("AUDIT_SUMMARY_FIELDS", "snapshot script test checks audit summary field order"),
        ("--snapshot-audit-template main", "snapshot script test checks audit template manifest handoff"),
        ("--check-snapshot-audit main", "snapshot script test checks read-only manifest handoff"),
        ("--readiness-summary contrib/devtools/zkcoin_public_launch_profile_manifest.json", "snapshot script test checks readiness summary handoff"),
        ("--blocker-readiness-summary main.litecoin_snapshot", "snapshot script test checks blocker readiness summary handoff"),
        ("Print placeholder audit handoff when no audit summary path is configured", "snapshot script test checks placeholder audit handoff"),
        ("snapshot_file_sha256", "snapshot script test checks audit artifact SHA-256 output"),
        ("Quote snapshot and audit paths in printed handoff commands", "snapshot script test checks shell-quoted handoff paths"),
        ("Reject a zero snapshot height", "snapshot script test rejects zero snapshot height"),
        ("Reject a null expected snapshot block hash", "snapshot script test rejects null expected block hash"),
        (
            "Reject a non-lowercase expected snapshot block hash",
            "snapshot script test rejects non-lowercase expected block hashes",
        ),
        ("Reject control characters in snapshot and audit output paths", "snapshot script test rejects control-character output paths"),
        ("Reject malformed Litecoin source chain info", "snapshot script test rejects malformed source chain info"),
        ("Reject non-object Litecoin source chain info", "snapshot script test rejects non-object source chain info"),
        ("Reject duplicate Litecoin source chain info fields", "snapshot script test rejects duplicate source chain info fields"),
        ("Reject malformed Litecoin source chain name", "snapshot script test validates source chain name shape"),
        ("Reject fractional Litecoin source chain heights", "snapshot script test rejects fractional source heights"),
        ("Reject malformed Litecoin source header height", "snapshot script test validates source header height shape"),
        (
            "Reject malformed Litecoin source best block hash",
            "snapshot script test validates source best block hash shape",
        ),
        (
            "Reject a Litecoin source whose active tip hash differs from the selected snapshot hash",
            "snapshot script test validates source active tip hash",
        ),
        ("Reject malformed Litecoin source chainwork", "snapshot script test validates source chainwork shape"),
        (
            "Reject malformed Litecoin source verification progress",
            "snapshot script test validates source verification progress shape",
        ),
        (
            "source-over-one-verificationprogress",
            "snapshot script test rejects over-one source verification progress",
        ),
        ("Reject malformed Litecoin source difficulty", "snapshot script test validates source difficulty shape"),
        ("Reject malformed Litecoin source disk footprint", "snapshot script test validates source disk footprint shape"),
        ("Reject malformed Litecoin source tip times", "snapshot script test validates source tip times"),
        (
            "Reject a Litecoin source whose headers are below downloaded blocks",
            "snapshot script test validates source header/block ordering",
        ),
        ("Reject a Litecoin source with headers ahead of downloaded blocks", "snapshot script test rejects unsynced source headers"),
        ("Reject malformed rewind restore block hash", "snapshot script test rejects malformed rewind restore hashes"),
        (
            "Reject non-lowercase rewind restore block hash",
            "snapshot script test rejects non-lowercase rewind restore hashes",
        ),
        ("Reject malformed Litecoin source sync booleans", "snapshot script test validates source sync boolean shape"),
        (
            "Reject a Litecoin source still in initial block download",
            "snapshot script test rejects IBD source nodes",
        ),
        ("Reject a pruned Litecoin snapshot source", "snapshot script test rejects pruned source nodes"),
        ("Reject malformed Litecoin source warnings", "snapshot script test validates source warning shape"),
        ("Reject a Litecoin source with node warnings", "snapshot script test rejects warned source nodes"),
        ("Reject a non-public Litecoin source chain", "snapshot script test rejects non-public source chains"),
        (
            "Reject rewind that does not leave the source at the snapshot height",
            "snapshot script test rejects post-rewind tip mismatches",
        ),
        (
            "Reject malformed post-rewind source tip",
            "snapshot script test rejects malformed post-rewind tips",
        ),
        (
            "Reject a pre-existing audit summary output path before calling either CLI",
            "snapshot script test rejects pre-existing audit output before RPC",
        ),
        (
            "Reject an audit summary path matching the snapshot output path before calling either CLI",
            "snapshot script test rejects audit path collisions before RPC",
        ),
        (
            "Reject an audit summary path aliasing the snapshot output path before calling either CLI",
            "snapshot script test rejects canonical audit path collisions before RPC",
        ),
        (
            "Reject audit summary paths colliding with snapshot incomplete output before calling either CLI",
            "snapshot script test rejects audit path collisions with dump work files before RPC",
        ),
        (
            "Reject a missing audit summary output directory before calling either CLI",
            "snapshot script test rejects missing audit directory before RPC",
        ),
        (
            "Reject an unwritable audit summary output directory before calling either CLI",
            "snapshot script test rejects unwritable audit directory before RPC",
        ),
        (
            "Reject a symlinked audit summary output directory before calling either CLI",
            "snapshot script test rejects symlink audit directory before RPC",
        ),
        (
            "Reject a symlinked audit summary output path before calling either CLI",
            "snapshot script test rejects symlink audit output before RPC",
        ),
        (
            "Reject a symlinked snapshot output path before calling either CLI",
            "snapshot script test rejects symlink snapshot output before RPC",
        ),
        (
            "Reject pre-existing snapshot incomplete output paths before calling either CLI",
            "snapshot script test rejects pre-existing dump work files before RPC",
        ),
        (
            "Reject a missing snapshot output directory before calling either CLI",
            "snapshot script test rejects missing snapshot directory before RPC",
        ),
        (
            "Reject an unwritable snapshot output directory before calling either CLI",
            "snapshot script test rejects unwritable snapshot directory before RPC",
        ),
        (
            "Reject a symlinked snapshot output directory before calling either CLI",
            "snapshot script test rejects symlink snapshot directory before RPC",
        ),
        ("Reject malformed source snapshot block hash", "snapshot script test rejects malformed source block hashes"),
        (
            "Reject non-lowercase source snapshot block hash",
            "snapshot script test rejects non-lowercase source block hashes",
        ),
        ("Reject non-object snapshot dump JSON", "snapshot script test rejects non-object dump JSON"),
        ("Reject non-lowercase snapshot dump hashes", "snapshot script test rejects non-lowercase dump hashes"),
        (
            "Reject snapshot dump height and hash mismatches before verification",
            "snapshot script test rejects dump metadata mismatches before verifier handoff",
        ),
        (
            "Reject malformed snapshot dump output paths before verification",
            "snapshot script test rejects dump output path mismatches before verifier handoff",
        ),
        ("Reject missing snapshot dump file before verification", "snapshot script test rejects missing dump file"),
        ("Reject empty snapshot dump file before verification", "snapshot script test rejects empty dump file"),
        ("Reject symlink snapshot dump artifact before verification", "snapshot script test rejects symlink dump file"),
        (
            "Reject snapshot output directory symlink replacement during dump",
            "snapshot script test rejects dump-time snapshot directory symlink replacement",
        ),
        (
            "Reject snapshot output directory replacement during dump",
            "snapshot script test rejects dump-time snapshot directory replacement",
        ),
        (
            "Reject leftover snapshot incomplete output after dump before verification",
            "snapshot script test rejects leftover dump work files before verifier handoff",
        ),
        ("Reject snapshot artifact mutation during verification", "snapshot script test rejects verifier-time dump mutation"),
        ("Reject snapshot artifact symlink replacement during verification", "snapshot script test rejects verifier-time symlink replacement"),
        (
            "Reject snapshot output directory symlink replacement during verification",
            "snapshot script test rejects verifier-time snapshot directory symlink replacement",
        ),
        (
            "Reject snapshot output directory replacement during verification",
            "snapshot script test rejects verifier-time snapshot directory replacement",
        ),
        ("Reject audit summary symlink replacement during verification", "snapshot script test rejects verifier-time audit symlink replacement"),
        (
            "Reject audit summary directory symlink replacement during verification",
            "snapshot script test rejects verifier-time audit directory symlink replacement",
        ),
        (
            "Reject audit summary directory replacement during verification",
            "snapshot script test rejects verifier-time audit directory replacement",
        ),
        ("Reject non-object verifier manifest JSON", "snapshot script test rejects non-object verifier JSON"),
        ("Reject duplicate snapshot dump fields", "snapshot script test rejects duplicate dump JSON fields"),
        ("Reject duplicate verifier manifest fields", "snapshot script test rejects duplicate verifier JSON fields"),
        ("Reject non-lowercase verifier hashes", "snapshot script test rejects non-lowercase verifier hashes"),
        ("Reject null verifier snapshot and import hashes", "snapshot script test rejects null verifier hashes"),
        ("Reject malformed verifier total amount", "snapshot script test rejects malformed total amount"),
        ("Reject over maximum verifier total amount", "snapshot script test rejects over-maximum total amount"),
        ("Reject fractional snapshot dump heights", "snapshot script test rejects fractional dump heights"),
        ("Reject fractional verifier coin counts", "snapshot script test rejects fractional verifier counts"),
        ("Reject zero snapshot dump coin count", "snapshot script test rejects zero dump coin counts"),
        ("Reject zero verifier base transaction count", "snapshot script test rejects zero base transaction count"),
        ("Print the testnet snapshot audit manifest handoff", "snapshot script test checks source-chain manifest handoff mapping"),
        ("--set-snapshot-audit testnet", "snapshot script test checks audit-backed manifest update command"),
        ("--blocker-readiness-summary testnet.litecoin_snapshot", "snapshot script test checks testnet blocker summary handoff"),
        ("zkcoin_public_launch_profile_manifest.json", "snapshot script test checks public launch manifest path"),
    )
    for needle, description in ltc_snapshot_script_test_checks:
        error = require_text(LTC_SNAPSHOT_SCRIPT_TEST, needle, description)
        if error:
            return fail(LTC_SNAPSHOT_SCRIPT_TEST, error)

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
            "rejects the local launch placeholder `0x5a4b` chain id",
            "preflight placeholder AuxPoW chain-id documentation",
        ),
        ("getblockchaininfo.chain", "preflight chain name documentation"),
        ("duplicate-free JSON object", "preflight duplicate-field JSON documentation"),
        ("getblockchaininfo.blocks=0", "preflight genesis height documentation"),
        ("getblockchaininfo.headers=0", "preflight genesis header documentation"),
        ("getblockchaininfo.bestblockhash", "preflight launch-tip hash documentation"),
        ("getblockchaininfo.chainwork", "preflight chainwork documentation"),
        ("getblockchaininfo.verificationprogress", "preflight verification progress documentation"),
        ("not exceeding 1", "bounded verification progress documentation"),
        ("getblockchaininfo.difficulty", "preflight difficulty documentation"),
        ("getblockchaininfo.size_on_disk", "preflight disk footprint documentation"),
        ("getblockchaininfo.time", "preflight launch-tip time documentation"),
        ("getblockchaininfo.mediantime", "preflight launch-tip median time documentation"),
        ("getblockchaininfo.initialblockdownload=false", "preflight IBD documentation"),
        ("getblockchaininfo.pruned=false", "preflight pruned mode documentation"),
        ('getblockchaininfo.warnings=""', "preflight node warning documentation"),
        ("auxpow.start_height=1", "preflight AuxPoW start-height documentation"),
        (
            "positive snapshot height plus non-null lowercase snapshot block/import hashes",
            "preflight configured snapshot detail shape documentation",
        ),
        (
            "transactions must remain inactive for the first launch block",
            "shielded launch posture documentation",
        ),
        ("inherited Litecoin public network identity", "identity readiness documentation"),
        (
            "startup error lists the exact hardcoded launch checks that still fail",
            "public launch startup diagnostics documentation",
        ),
        (
            "zkcoin_public_launch_profile_manifest.json",
            "public launch manifest documentation",
        ),
        (
            "zkcoin_public_launch_profile.py --allow-blocked",
            "public launch manifest validator documentation",
        ),
        (
            "blocker list must match the unresolved fields exactly",
            "public launch manifest blocker consistency documentation",
        ),
        (
            "Duplicate JSON fields are rejected",
            "public launch manifest duplicate JSON field documentation",
        ),
        (
            "manifest must be valid UTF-8 JSON",
            "public launch manifest UTF-8 JSON documentation",
        ),
        (
            "must not exceed 262144 bytes",
            "public launch manifest input size documentation",
        ),
        (
            "read from a direct parent directory as a",
            "public launch manifest hardened read documentation",
        ),
        (
            "malformed manifest sections are reported as validation errors",
            "public launch manifest malformed schema documentation",
        ),
        (
            "Manifest update commands reject malformed sections before mutation",
            "public launch manifest update malformed schema documentation",
        ),
        (
            "In-place manifest writes reject symlinked manifest paths, symlinked parent directories, and pre-existing temp files",
            "public launch manifest safe in-place write documentation",
        ),
        (
            "opened parent directory descriptor",
            "public launch manifest directory-fd write documentation",
        ),
        (
            "fsync their parent directory after replacement",
            "public launch manifest durable in-place write documentation",
        ),
        (
            "Use one primary launch-profile action per invocation",
            "public launch manifest single primary action documentation",
        ),
        (
            "zkcoin_public_launch_profile.py --check-auxpow NETWORK <chain_id>",
            "public launch manifest AuxPoW read-only check documentation",
        ),
        (
            "read-only AuxPoW check reports the exact apply command, remaining blocker",
            "public launch manifest AuxPoW candidate-progress documentation",
        ),
        (
            "next check/apply commands that would remain",
            "public launch manifest candidate next-command documentation",
        ),
        (
            "target-network readiness summary command",
            "public launch manifest candidate network summary documentation",
        ),
        (
            "blocker-type readiness summary command",
            "public launch manifest candidate blocker-type summary documentation",
        ),
        (
            "zkcoin_public_launch_profile.py --set-auxpow NETWORK <chain_id>",
            "public launch manifest AuxPoW update documentation",
        ),
        (
            "0x2000..0x3fff",
            "public launch manifest AuxPoW forbidden range documentation",
        ),
        (
            "local launch placeholder `0x5a4b`",
            "public launch manifest AuxPoW placeholder rejection documentation",
        ),
        (
            "no longer the local launch placeholder",
            "public launch readiness AuxPoW placeholder documentation",
        ),
        (
            "zkcoin_public_launch_profile.py --check-dns-seeds NETWORK <seed1.hostname>,<seed2.hostname>",
            "public launch manifest DNS seed read-only check documentation",
        ),
        (
            "read-only DNS seed check reports the exact apply command, remaining blocker",
            "public launch manifest DNS seed candidate-progress documentation",
        ),
        (
            "zkcoin_public_launch_profile.py --set-dns-seeds NETWORK <seed1.hostname>,<seed2.hostname>",
            "public launch manifest DNS seed update documentation",
        ),
        (
            "reserved or local-use suffixes",
            "public launch manifest DNS seed rejection documentation",
        ),
        (
            "zkcoin_public_launch_profile.py --check-identity NETWORK",
            "public launch manifest identity read-only check documentation",
        ),
        (
            "read-only identity check reports the exact apply command, remaining blocker",
            "public launch manifest identity candidate-progress documentation",
        ),
        (
            "zkcoin_public_launch_profile.py --set-identity NETWORK",
            "public launch manifest identity update documentation",
        ),
        (
            "rejects inherited Litecoin message",
            "public launch manifest identity rejection documentation",
        ),
        (
            "overlong HRPs",
            "public launch manifest HRP length documentation",
        ),
        (
            "distinct AuxPoW chain ids, message starts, ports, DNS seed hostnames",
            "public launch manifest cross-network uniqueness documentation",
        ),
        (
            "ready-for-chainparams",
            "public launch manifest ready status documentation",
        ),
        (
            "zkcoin_public_launch_profile.py --next-action",
            "public launch manifest next-action documentation",
        ),
        (
            "zkcoin_public_launch_profile.py --action-plan",
            "public launch manifest action-plan documentation",
        ),
        (
            "zkcoin_public_launch_profile.py --readiness-summary",
            "public launch manifest readiness-summary documentation",
        ),
        (
            "zkcoin_public_launch_profile.py --blocker-type-readiness-summary BLOCKER_TYPE",
            "public launch manifest blocker-type readiness-summary documentation",
        ),
        (
            "zkcoin_public_launch_profile.py --blocker-readiness-summary BLOCKER_ID",
            "public launch manifest blocker readiness-summary documentation",
        ),
        (
            "compact human-readable summary of blocked networks",
            "public launch manifest readiness-summary contents documentation",
        ),
        (
            "immediate blocker's exact field paths",
            "public launch manifest readiness-summary field-path documentation",
        ),
        (
            "per-network next blocker-scoped summary\n  commands",
            "public launch manifest readiness-summary network blocker summary documentation",
        ),
        (
            "per-network/per-workstream blocker and field matrices",
            "public launch manifest readiness-summary matrix documentation",
        ),
        (
            "per-network/per-workstream next blocker matrix",
            "public launch manifest readiness-summary next blocker matrix documentation",
        ),
        (
            "per-network/per-workstream next blocker field-count matrix",
            "public launch manifest readiness-summary next blocker field-count matrix documentation",
        ),
        (
            "per-network next\n  blocker-type summary commands",
            "public launch manifest readiness-summary network blocker-type summary documentation",
        ),
        (
            "copyable action-plan, next-action, status-json, and rerun commands",
            "public launch manifest readiness-summary entry command documentation",
        ),
        (
            "zkcoin_public_launch_profile.py --status-json",
            "public launch manifest status-json documentation",
        ),
        (
            "copyable `template command`, `check command`,",
            "public launch manifest copyable command-line documentation",
        ),
        (
            "zkcoin_public_launch_profile.py --snapshot-audit-template NETWORK",
            "public launch manifest snapshot audit template documentation",
        ),
        (
            "machine-readable JSON",
            "public launch manifest status-json machine-readable documentation",
        ),
        (
            "schema_version",
            "public launch manifest status-json schema version documentation",
        ),
        (
            "action_count",
            "public launch manifest status-json action count documentation",
        ),
        (
            "action_ids",
            "public launch manifest status-json action id documentation",
        ),
        (
            "action_kinds",
            "public launch manifest status-json action kind documentation",
        ),
        (
            "action_steps",
            "public launch manifest status-json action step documentation",
        ),
        (
            "action_networks",
            "public launch manifest status-json action network documentation",
        ),
        (
            "action_blocker_types",
            "public launch manifest status-json action blocker type documentation",
        ),
        (
            "action_field_counts",
            "public launch manifest status-json action field count documentation",
        ),
        (
            "action_commands",
            "public launch manifest status-json action command documentation",
        ),
        (
            "action_command_count",
            "public launch manifest status-json action command count documentation",
        ),
        (
            "action_command_keys",
            "public launch manifest status-json action command key documentation",
        ),
        (
            "action_command_key_counts",
            "public launch manifest status-json action command key count documentation",
        ),
        (
            "action_command_values",
            "public launch manifest status-json action command value documentation",
        ),
        (
            "action_command_value_counts",
            "public launch manifest status-json action command value count documentation",
        ),
        (
            "action_command_pairs",
            "public launch manifest status-json action command pair documentation",
        ),
        (
            "action_command_pair_counts",
            "public launch manifest status-json action command pair count documentation",
        ),
        (
            "command_field_order",
            "public launch manifest status-json command field order documentation",
        ),
        (
            "command_field_count",
            "public launch manifest status-json command field count documentation",
        ),
        (
            "actions_by_network",
            "public launch manifest status-json network action documentation",
        ),
        (
            "action_counts_by_network",
            "public launch manifest status-json network action count documentation",
        ),
        (
            "actions_by_blocker_type",
            "public launch manifest status-json blocker-type action documentation",
        ),
        (
            "action_counts_by_blocker_type",
            "public launch manifest status-json blocker-type action count documentation",
        ),
        (
            "actions_by_network_and_blocker_type",
            "public launch manifest status-json network blocker-type action documentation",
        ),
        (
            "action_counts_by_network_and_blocker_type",
            "public launch manifest status-json network blocker-type action count documentation",
        ),
        (
            "next_actions_by_network_and_blocker_type",
            "public launch manifest status-json network blocker-type next action documentation",
        ),
        (
            "next_commands_by_network_and_blocker_type",
            "public launch manifest status-json network blocker-type next command documentation",
        ),
        (
            "next_blocker_commands_by_network_and_blocker_type",
            "public launch manifest status-json network blocker-type next blocker command alias documentation",
        ),
        (
            "next_actions_by_blocker_type",
            "public launch manifest status-json blocker-type next action documentation",
        ),
        (
            "next_commands_by_blocker_type",
            "public launch manifest status-json blocker-type next command documentation",
        ),
        (
            "next_blocker_commands_by_blocker_type",
            "public launch manifest status-json blocker-type next blocker command alias documentation",
        ),
        (
            "action_plan_command",
            "public launch manifest status-json action-plan command documentation",
        ),
        (
            "readiness_summary_command",
            "public launch manifest status-json readiness-summary command documentation",
        ),
        (
            "status_json_command",
            "public launch manifest status-json status-json command documentation",
        ),
        (
            "global `commands` map",
            "public launch manifest status-json command map documentation",
        ),
        (
            "next_action",
            "public launch manifest status-json next action documentation",
        ),
        (
            "next_action_id",
            "public launch manifest status-json next action id documentation",
        ),
        (
            "next_action_kind",
            "public launch manifest status-json next action kind documentation",
        ),
        (
            "next_action_step",
            "public launch manifest status-json next action step documentation",
        ),
        (
            "next_action_network",
            "public launch manifest status-json next action network documentation",
        ),
        (
            "next_action_blocker_type",
            "public launch manifest status-json next action blocker type documentation",
        ),
        (
            "next_action_field_count",
            "public launch manifest status-json next action field count documentation",
        ),
        (
            "next_action_command",
            "public launch manifest status-json next action command documentation",
        ),
        (
            "next_commands",
            "public launch manifest status-json next command documentation",
        ),
        (
            "next_command_keys",
            "public launch manifest status-json next command key documentation",
        ),
        (
            "next_command_key_count",
            "public launch manifest status-json next command key count documentation",
        ),
        (
            "next_command_values",
            "public launch manifest status-json next command value documentation",
        ),
        (
            "next_command_value_count",
            "public launch manifest status-json next command value count documentation",
        ),
        (
            "next_command_pairs",
            "public launch manifest status-json next command pair documentation",
        ),
        (
            "next_command_pair_count",
            "public launch manifest status-json next command pair count documentation",
        ),
        (
            "action entries expose `network` and `blocker_type`",
            "public launch manifest status-json action metadata documentation",
        ),
        (
            "later_actions",
            "public launch manifest status-json later action documentation",
        ),
        (
            "later_action_count",
            "public launch manifest status-json later action count documentation",
        ),
        (
            "later_action_ids",
            "public launch manifest status-json later action id documentation",
        ),
        (
            "later_action_kinds",
            "public launch manifest status-json later action kind documentation",
        ),
        (
            "later_action_steps",
            "public launch manifest status-json later action step documentation",
        ),
        (
            "later_action_networks",
            "public launch manifest status-json later action network documentation",
        ),
        (
            "later_action_blocker_types",
            "public launch manifest status-json later action blocker type documentation",
        ),
        (
            "later_action_field_counts",
            "public launch manifest status-json later action field count documentation",
        ),
        (
            "later_command_keys",
            "public launch manifest status-json later command key documentation",
        ),
        (
            "later_command_key_counts",
            "public launch manifest status-json later command key count documentation",
        ),
        (
            "later_command_values",
            "public launch manifest status-json later command value documentation",
        ),
        (
            "later_command_value_counts",
            "public launch manifest status-json later command value count documentation",
        ),
        (
            "later_command_pairs",
            "public launch manifest status-json later command pair documentation",
        ),
        (
            "later_command_pair_counts",
            "public launch manifest status-json later command pair count documentation",
        ),
        (
            "later_commands",
            "public launch manifest status-json later command documentation",
        ),
        (
            "later_command_count",
            "public launch manifest status-json later command count documentation",
        ),
        (
            "network_step",
            "public launch manifest status-json action network order documentation",
        ),
        (
            "network_step_count",
            "public launch manifest status-json action network count documentation",
        ),
        (
            "blocker_type_step",
            "public launch manifest status-json action workstream order documentation",
        ),
        (
            "blocker_type_step_count",
            "public launch manifest status-json action workstream count documentation",
        ),
        (
            "blocker_readiness_summary_command",
            "public launch manifest status-json action blocker summary command documentation",
        ),
        (
            "`template_command` is `null` for blocker types",
            "public launch manifest status-json stable command-field documentation",
        ),
        (
            "blocked_field_count",
            "public launch manifest status-json blocked field count documentation",
        ),
        (
            "unresolved_blockers_by_network",
            "public launch manifest status-json network blocker documentation",
        ),
        (
            "unresolved_blocker_counts_by_network",
            "public launch manifest status-json network blocker count documentation",
        ),
        (
            "unresolved_blockers_by_blocker_type",
            "public launch manifest status-json blocker-type blocker documentation",
        ),
        (
            "unresolved_blocker_counts_by_blocker_type",
            "public launch manifest status-json blocker-type blocker count documentation",
        ),
        (
            "unresolved_blocker_counts_by_network_and_blocker_type",
            "public launch manifest status-json network blocker-type blocker count documentation",
        ),
        (
            "unresolved_blockers_by_network_and_blocker_type",
            "public launch manifest status-json network blocker-type blocker matrix documentation",
        ),
        (
            "blocked_fields_by_network",
            "public launch manifest status-json network field documentation",
        ),
        (
            "blocked_field_counts_by_network",
            "public launch manifest status-json network field count documentation",
        ),
        (
            "blocked_fields_by_blocker_type",
            "public launch manifest status-json blocker-type field documentation",
        ),
        (
            "blocked_field_counts_by_blocker_type",
            "public launch manifest status-json blocker-type field count documentation",
        ),
        (
            "blocked_field_counts_by_network_and_blocker_type",
            "public launch manifest status-json network blocker-type field count documentation",
        ),
        (
            "blocked_fields_by_network_and_blocker_type",
            "public launch manifest status-json network blocker-type field matrix documentation",
        ),
        (
            "blocker_type_progress",
            "public launch manifest status-json blocker-type progress documentation",
        ),
        (
            "next_blockers_by_blocker_type",
            "public launch manifest status-json blocker-type next blocker documentation",
        ),
        (
            "next_blocker_networks_by_blocker_type",
            "public launch manifest status-json blocker-type next network documentation",
        ),
        (
            "next_blocked_field_groups_by_blocker_type",
            "public launch manifest status-json blocker-type next field-group documentation",
        ),
        (
            "next_blocker_field_groups_by_blocker_type",
            "public launch manifest status-json blocker-type next blocker field-group alias documentation",
        ),
        (
            "next_blocked_fields_by_blocker_type",
            "public launch manifest status-json blocker-type next field documentation",
        ),
        (
            "next_blocked_field_counts_by_blocker_type",
            "public launch manifest status-json blocker-type next field count documentation",
        ),
        (
            "next_blocker_fields_by_blocker_type",
            "public launch manifest status-json blocker-type next blocker field alias documentation",
        ),
        (
            "next_blocker_field_counts_by_blocker_type",
            "public launch manifest status-json blocker-type next blocker field-count alias documentation",
        ),
        (
            "blocker_type_readiness_summary_commands_by_blocker_type",
            "public launch manifest status-json blocker-type readiness-summary command documentation",
        ),
        (
            "blocker_type_readiness_summary_command_count",
            "public launch manifest status-json blocker-type readiness-summary command count documentation",
        ),
        (
            "blocker_readiness_summary_commands_by_blocker",
            "public launch manifest status-json blocker readiness-summary command documentation",
        ),
        (
            "blocker_readiness_summary_command_count",
            "public launch manifest status-json blocker readiness-summary command count documentation",
        ),
        (
            "network_readiness_summary_commands_by_network",
            "public launch manifest status-json network readiness-summary command documentation",
        ),
        (
            "network_readiness_summary_command_count",
            "public launch manifest status-json network readiness-summary command count documentation",
        ),
        (
            "next_commands_by_network",
            "public launch manifest status-json network next command documentation",
        ),
        (
            "next_blocker_commands_by_network",
            "public launch manifest status-json network next blocker command alias documentation",
        ),
        (
            "next_blocked_field_groups_by_network",
            "public launch manifest status-json network next field-group documentation",
        ),
        (
            "next_blocker_field_groups_by_network",
            "public launch manifest status-json network next blocker field-group alias documentation",
        ),
        (
            "next_blocked_fields_by_network",
            "public launch manifest status-json network next field documentation",
        ),
        (
            "next_blocked_field_counts_by_network",
            "public launch manifest status-json network next field-count documentation",
        ),
        (
            "next_blocker_fields_by_network",
            "public launch manifest status-json network next blocker field alias documentation",
        ),
        (
            "next_blocker_field_counts_by_network",
            "public launch manifest status-json network next blocker field-count alias documentation",
        ),
        (
            "next_blocked_field_groups_by_network_and_blocker_type",
            "public launch manifest status-json network blocker-type next field-group documentation",
        ),
        (
            "next_blocker_field_groups_by_network_and_blocker_type",
            "public launch manifest status-json network blocker-type next blocker field-group alias documentation",
        ),
        (
            "next_blocked_fields_by_network_and_blocker_type",
            "public launch manifest status-json network blocker-type next field documentation",
        ),
        (
            "next_blocked_field_counts_by_network_and_blocker_type",
            "public launch manifest status-json network blocker-type next field-count documentation",
        ),
        (
            "next_blocker_fields_by_network_and_blocker_type",
            "public launch manifest status-json network blocker-type next blocker field alias documentation",
        ),
        (
            "next_blocker_field_counts_by_network_and_blocker_type",
            "public launch manifest status-json network blocker-type next blocker field-count alias documentation",
        ),
        (
            "next_blockers_by_network_and_blocker_type",
            "public launch manifest status-json network blocker-type next blocker documentation",
        ),
        (
            "next_blockers_by_network",
            "public launch manifest status-json network next blocker documentation",
        ),
        (
            "next_blocker_types_by_network",
            "public launch manifest status-json network next blocker type documentation",
        ),
        (
            "blocked_networks",
            "public launch manifest status-json blocked network summary documentation",
        ),
        (
            "ready_networks",
            "public launch manifest status-json ready network summary documentation",
        ),
        (
            "blocked_blocker_types",
            "public launch manifest status-json blocked blocker-type summary documentation",
        ),
        (
            "ready_blocker_types",
            "public launch manifest status-json ready blocker-type summary documentation",
        ),
        (
            "blocked_blocker_types_by_network",
            "public launch manifest status-json network blocked blocker-type summary documentation",
        ),
        (
            "ready_blocker_types_by_network",
            "public launch manifest status-json network ready blocker-type summary documentation",
        ),
        (
            "blocked_networks_by_blocker_type",
            "public launch manifest status-json blocker-type blocked network summary documentation",
        ),
        (
            "blocked_network_counts_by_blocker_type",
            "public launch manifest status-json blocker-type blocked network count documentation",
        ),
        (
            "ready_networks_by_blocker_type",
            "public launch manifest status-json blocker-type ready network summary documentation",
        ),
        (
            "ready_network_counts_by_blocker_type",
            "public launch manifest status-json blocker-type ready network count documentation",
        ),
        (
            "blocked networks by blocker type",
            "public launch manifest readiness summary blocker-type blocked network documentation",
        ),
        (
            "ready networks by blocker type",
            "public launch manifest readiness summary blocker-type ready network documentation",
        ),
        (
            "blocked blocker types",
            "public launch manifest network readiness summary blocked blocker-type documentation",
        ),
        (
            "ready blocker types",
            "public launch manifest network readiness summary ready blocker-type documentation",
        ),
        (
            "network_progress",
            "public launch manifest status-json network progress documentation",
        ),
        (
            "blocked_field_groups",
            "public launch manifest status-json blocked field groups documentation",
        ),
        (
            "blocked_field_groups_by_network",
            "public launch manifest status-json network blocked field groups documentation",
        ),
        (
            "blocked_field_group_counts_by_network",
            "public launch manifest status-json network blocked field group counts documentation",
        ),
        (
            "blocked_field_groups_by_blocker_type",
            "public launch manifest status-json blocker-type blocked field groups documentation",
        ),
        (
            "blocked_field_group_counts_by_blocker_type",
            "public launch manifest status-json blocker-type blocked field group counts documentation",
        ),
        (
            "blocked_field_groups_by_network_and_blocker_type",
            "public launch manifest status-json network blocker-type blocked field groups documentation",
        ),
        (
            "blocked_field_group_counts_by_network_and_blocker_type",
            "public launch manifest status-json network blocker-type blocked field group counts documentation",
        ),
        (
            "blocked field groups carry the same split command fields",
            "public launch manifest status-json grouped command-field documentation",
        ),
        (
            "blocker_type",
            "public launch manifest status-json blocked field group type documentation",
        ),
        (
            "blocked_field_group_count",
            "public launch manifest status-json blocked field group count documentation",
        ),
        (
            "next_blocked_field_group",
            "public launch manifest status-json current blocked field group documentation",
        ),
        (
            "next_blocker_field_group",
            "public launch manifest status-json current blocker field group alias documentation",
        ),
        (
            "next_blocker_step",
            "public launch manifest status-json current blocker global order documentation",
        ),
        (
            "next_blocker_network_step",
            "public launch manifest status-json current blocker network order documentation",
        ),
        (
            "next_blocker_network_step_count",
            "public launch manifest status-json current blocker network count documentation",
        ),
        (
            "next_blocker_type_step",
            "public launch manifest status-json current blocker type order documentation",
        ),
        (
            "next_blocker_type_step_count",
            "public launch manifest status-json current blocker type count documentation",
        ),
        (
            "next_blocker_commands",
            "public launch manifest status-json current blocker command documentation",
        ),
        (
            "next_blocker_fields",
            "public launch manifest status-json current blocker field documentation",
        ),
        (
            "later_blockers",
            "public launch manifest status-json later blocker documentation",
        ),
        (
            "later_blocker_count",
            "public launch manifest status-json later blocker count documentation",
        ),
        (
            "later_blocker_readiness_summary_commands_by_blocker",
            "public launch manifest status-json later blocker command documentation",
        ),
        (
            "later_blocker_readiness_summary_command_count",
            "public launch manifest status-json later blocker command count documentation",
        ),
        (
            "later_blocker_field_groups",
            "public launch manifest status-json later blocker field group documentation",
        ),
        (
            "later_blocker_field_group_count",
            "public launch manifest status-json later blocker field group count documentation",
        ),
        (
            "later_blocker_fields",
            "public launch manifest status-json later blocker field documentation",
        ),
        (
            "later_blocker_field_count",
            "public launch manifest status-json later blocker field count documentation",
        ),
        (
            "next_blocked_fields",
            "public launch manifest status-json next blocked fields documentation",
        ),
        (
            "shell-quotes the manifest path",
            "public launch manifest next-action path quoting documentation",
        ),
        (
            "zkcoin_public_launch_profile.py --mark-ready",
            "public launch manifest guarded ready transition documentation",
        ),
        (
            "zkcoin_public_launch_profile.py --emit-chainparams",
            "public launch manifest chainparams emitter documentation",
        ),
        (
            "zkcoin_public_launch_profile.py --check-chainparams src/chainparams.cpp",
            "public launch manifest chainparams sync-check documentation",
        ),
        (
            "direct regular file capped at 1048576 bytes",
            "public launch manifest chainparams hardened read documentation",
        ),
        (
            "reserved-suffix DNS seed",
            "public launch preflight DNS seed suffix documentation",
        ),
        (
            "ZKCOIN_SNAPSHOT_AUDIT_JSON",
            "public launch snapshot audit summary documentation",
        ),
        (
            "same field order as the",
            "public launch snapshot audit template-order documentation",
        ),
        (
            "rejects reordered audit summaries",
            "public launch snapshot audit order rejection documentation",
        ),
        (
            "template command, the read-only check command, the follow-up update command",
            "public launch snapshot audit check-before-update documentation",
        ),
        (
            "read-only check also reports the exact apply command, remaining blocker",
            "public launch snapshot audit candidate-progress documentation",
        ),
        (
            "exclusive final-path write, fsyncs the file and parent directory",
            "public launch snapshot audit durable write documentation",
        ),
        (
            "audit summary directories are also rechecked",
            "public launch snapshot audit parent stability documentation",
        ),
        (
            "audit summary path itself must also be a direct file",
            "public launch snapshot audit summary symlink rejection documentation",
        ),
        (
            "rejects symlinked direct parent directories for both handoff inputs",
            "public launch snapshot audit parent directory rejection documentation",
        ),
        (
            "size cap is enforced again while reading",
            "public launch snapshot audit summary bounded-read documentation",
        ),
        (
            "rechecks the audit summary path after reading",
            "public launch snapshot audit summary stability documentation",
        ),
        (
            "valid UTF-8 JSON",
            "public launch snapshot audit summary UTF-8 documentation",
        ),
        (
            "snapshot_hash` and `import_hash` values that are the null uint256",
            "public launch snapshot null verifier hash documentation",
        ),
        (
            "positive Litecoin snapshot height",
            "public launch snapshot positive height documentation",
        ),
        (
            "source has headers ahead of downloaded blocks",
            "public launch snapshot source headers synced documentation",
        ),
        (
            "headers below downloaded blocks",
            "public launch snapshot source header-order documentation",
        ),
        (
            "malformed source sync booleans",
            "public launch snapshot source sync boolean documentation",
        ),
        (
            "malformed source chain names",
            "public launch snapshot source chain-name documentation",
        ),
        (
            "malformed source block or header heights",
            "public launch snapshot source height-shape documentation",
        ),
        (
            "validates the block `X + 1` restore hash before invalidating",
            "public launch snapshot rewind restore-hash validation documentation",
        ),
        (
            "snapshot output directory must also exist",
            "public launch snapshot output directory preflight documentation",
        ),
        (
            "snapshot and audit output directories must be writable",
            "public launch snapshot output directory writable preflight documentation",
        ),
        (
            "snapshot and audit output paths must be direct files",
            "public launch snapshot output symlink rejection documentation",
        ),
        (
            "same canonical output target",
            "public launch snapshot canonical output collision documentation",
        ),
        (
            "well-formed lowercase non-null block hash for height X",
            "public launch snapshot source block-hash validation documentation",
        ),
        (
            "active source tip hash does not match the expected block hash",
            "public launch snapshot source active-tip hash validation documentation",
        ),
        (
            "non-null source chainwork",
            "public launch snapshot source chainwork documentation",
        ),
        (
            "non-negative source verification progress",
            "public launch snapshot source verification progress documentation",
        ),
        (
            "non-negative source verification progress not\nexceeding 1",
            "public launch snapshot bounded source verification progress documentation",
        ),
        (
            "non-negative source difficulty",
            "public launch snapshot source difficulty documentation",
        ),
        (
            "positive source disk footprint",
            "public launch snapshot source disk footprint documentation",
        ),
        (
            "non-negative source tip times",
            "public launch snapshot source tip time documentation",
        ),
        (
            "expected block hash is the null uint256 placeholder",
            "public launch snapshot null expected hash rejection documentation",
        ),
        (
            "not lowercase 64-character hex",
            "snapshot operator lowercase expected hash documentation",
        ),
        (
            "well-formed lowercase non-null block hash for height X",
            "snapshot operator lowercase source block hash documentation",
        ),
        (
            "zkcoin_public_launch_profile.py \\\n  --check-snapshot-audit NETWORK <snapshot_audit.json>",
            "public launch manifest read-only snapshot audit check documentation",
        ),
        (
            "zkcoin_public_launch_profile.py \\\n  --set-snapshot-audit NETWORK <snapshot_audit.json>",
            "public launch manifest audit-backed snapshot update documentation",
        ),
        (
            "zkcoin_public_launch_profile.py \\\n  --readiness-summary",
            "public launch manifest post-apply readiness summary documentation",
        ),
        (
            "zkcoin_public_launch_profile.py \\\n  --blocker-readiness-summary NETWORK.litecoin_snapshot",
            "public launch manifest post-apply blocker summary documentation",
        ),
        (
            "without modifying the manifest",
            "public launch manifest read-only snapshot audit check behavior documentation",
        ),
        (
            "post-apply readiness summary command",
            "public launch snapshot operator post-apply summary documentation",
        ),
        (
            "target-network readiness summary command",
            "public launch snapshot operator target-network summary documentation",
        ),
        (
            "blocker-type readiness summary command",
            "public launch snapshot operator blocker-type summary documentation",
        ),
        (
            "exact next `--blocker-readiness-summary` command",
            "public launch snapshot operator post-apply blocker summary documentation",
        ),
        (
            "network launch order",
            "public launch exact blocker network order documentation",
        ),
        (
            "blocker-type launch order",
            "public launch exact blocker workstream order documentation",
        ),
        (
            "target profile derived from `source_chain`",
            "public launch snapshot operator exact handoff documentation",
        ),
        (
            "stores those audit fields with the snapshot constants",
            "public launch manifest snapshot audit retention documentation",
        ),
        (
            "64-character lowercase hex strings",
            "public launch manifest snapshot audit lowercase hash documentation",
        ),
        (
            "absolute snapshot file path",
            "public launch manifest snapshot audit file-path documentation",
        ),
        (
            "must not contain control characters",
            "public launch manifest snapshot audit control-character documentation",
        ),
        (
            "positive decimal total amount with 8 fractional digits",
            "public launch manifest snapshot audit amount documentation",
        ),
        (
            "not exceed `84000000.00000000`",
            "public launch manifest snapshot audit amount cap documentation",
        ),
        (
            "positive coin and transaction counts",
            "public launch snapshot positive audit count documentation",
        ),
        (
            "non-lowercase or null hash fields",
            "snapshot operator non-lowercase hash rejection documentation",
        ),
        (
            "source_chain",
            "public launch manifest source-chain audit documentation",
        ),
        (
            "snapshot file byte size",
            "public launch manifest snapshot file size documentation",
        ),
        (
            "snapshot file SHA-256",
            "public launch manifest snapshot file SHA-256 documentation",
        ),
        (
            "verifies the local snapshot artifact size and SHA-256",
            "public launch manifest snapshot artifact verification documentation",
        ),
        (
            "rejects symlinked snapshot artifacts",
            "public launch manifest snapshot artifact symlink rejection documentation",
        ),
        (
            "names itself as the snapshot artifact",
            "public launch manifest snapshot self-reference rejection documentation",
        ),
        (
            "rechecks the snapshot artifact path after hashing",
            "public launch manifest snapshot artifact stability documentation",
        ),
        (
            "changes during zkCoin verification",
            "snapshot operator verifier-time artifact mutation documentation",
        ),
        (
            "direct file descriptor before",
            "snapshot operator direct artifact fingerprint documentation",
        ),
        (
            "replaced after dump or verification",
            "snapshot operator post-write directory replacement documentation",
        ),
        (
            "rejects a snapshot audit whose source chain does not match",
            "public launch manifest source-chain mismatch documentation",
        ),
        (
            "non-empty snapshot file before running zkCoin verification",
            "snapshot operator verifies dump artifact documentation",
        ),
        (
            "before invoking `verifysnapshotmanifest`",
            "snapshot operator rejects bad dump metadata before verifier documentation",
        ),
        (
            "requires `dumptxoutset.path` to match",
            "snapshot operator dump output path validation documentation",
        ),
        (
            "duplicate-field JSON",
            "snapshot operator duplicate RPC JSON documentation",
        ),
        (
            "non-object",
            "snapshot operator non-object RPC JSON documentation",
        ),
        (
            "validates the audit summary output path before running snapshot RPCs",
            "snapshot operator preflights audit output documentation",
        ),
        (
            "snapshot `.incomplete` work file",
            "snapshot operator preflights and rechecks dump work-file documentation",
        ),
        (
            "must also differ from the reserved `.incomplete` work-file path",
            "snapshot operator audit path dump work-file collision documentation",
        ),
        (
            "Litecoin source node is still in initial block download",
            "snapshot operator IBD source rejection documentation",
        ),
        (
            "Litecoin source node must not be pruned for snapshot generation",
            "snapshot operator pruned source rejection documentation",
        ),
        (
            "Litecoin source node reports warnings",
            "snapshot operator source warning rejection documentation",
        ),
        (
            "requires `getblockcount` to return an integer source tip exactly equal to height X",
            "snapshot operator post-rewind tip verification documentation",
        ),
        (
            "Manual public snapshot constants are not accepted",
            "public launch manifest rejects manual snapshot constants documentation",
        ),
        (
            "removes only that network's snapshot blocker",
            "public launch manifest partial blocker documentation",
        ),
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
