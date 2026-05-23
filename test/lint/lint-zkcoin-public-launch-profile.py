#!/usr/bin/env python3
# Copyright (c) 2026 The zkCoin developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Check that public zkCoin launch parameters stay fail-closed."""

import hashlib
import json
from pathlib import Path
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
    if "--set-snapshot-audit main <snapshot_audit.json>" not in next_action_result.stdout:
        return "{} --next-action did not print the snapshot handoff command".format(
            PUBLIC_LAUNCH_MANIFEST_TOOL.relative_to(ROOT_DIR)
        )

    with tempfile.TemporaryDirectory() as temp_dir:
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
        ("CHAINPARAMS_CLASS_BOUNDS", "manifest maps public networks to chainparams classes"),
        ("contains resolved or unknown blocker ids", "manifest rejects stale or unknown blocker ids"),
        ("ready-for-chainparams", "manifest ready status"),
        ("--allow-blocked", "manifest lint-mode flag"),
        ("--next-action", "manifest next-action guidance flag"),
        ("--emit-chainparams", "manifest chainparams emitter flag"),
        ("--check-chainparams", "manifest chainparams sync-check flag"),
        ("--mark-ready", "manifest guarded ready transition flag"),
        ("manual snapshot constants are not accepted", "manifest rejects manual snapshot constants"),
        ("--set-snapshot-audit", "manifest verified snapshot audit update flag"),
        ("--set-auxpow", "manifest AuxPoW update flag"),
        ("--set-dns-seeds", "manifest DNS seed update flag"),
        ("--set-identity", "manifest public identity update flag"),
        ("parse_chain_id", "manifest parses AuxPoW chain id"),
        ("parse_snapshot_audit", "manifest parses verified snapshot audit summaries"),
        ("verify_snapshot_audit_artifact", "manifest verifies snapshot audit artifact fingerprints"),
        ("SNAPSHOT_AUDIT_FIELDS", "manifest blocker derivation tracks all snapshot audit fields"),
        ("snapshot audit missing field", "manifest rejects incomplete snapshot audit summaries"),
        ("SNAPSHOT_SOURCE_CHAINS", "manifest maps public profiles to Litecoin source chains"),
        ("source_chain", "manifest preserves snapshot source-chain audit metadata"),
        ("snapshot_file_size", "manifest preserves snapshot file byte-size metadata"),
        ("snapshot_file_sha256", "manifest preserves snapshot file SHA-256 metadata"),
        ("snapshot audit file artifact does not exist", "manifest rejects missing snapshot audit artifacts"),
        ("snapshot audit file size mismatch", "manifest rejects mismatched snapshot audit artifact sizes"),
        ("snapshot audit file SHA-256 mismatch", "manifest rejects mismatched snapshot audit artifact hashes"),
        ("snapshot_file_valid", "manifest rejects malformed snapshot audit file paths"),
        ("snapshot_total_amount_valid", "manifest rejects malformed snapshot audit amounts"),
        ("SNAPSHOT_TOTAL_AMOUNT_RE", "manifest requires fixed-scale snapshot audit amount strings"),
        ("litecoin_snapshot.audit.snapshot_hash", "manifest reports unresolved snapshot audit blockers"),
        ("snapshot_hash", "manifest preserves snapshot audit hash metadata"),
        ("base_nchaintx", "manifest preserves snapshot audit transaction-count metadata"),
        ("parse_dns_seeds", "manifest parses DNS seed hostnames"),
        ("len(labels) < 2", "manifest rejects single-label DNS seed hostnames"),
        ("re.search(r\"[a-z]\", labels[-1]) is None", "manifest rejects numeric final-label DNS seed hostnames"),
        ("len(label) <= 63", "manifest rejects overlong DNS seed labels"),
        ("parse_byte_sequence", "manifest parses public identity byte fields"),
        ("parse_default_port", "manifest parses public identity default port"),
        ("display_path", "manifest guidance preserves non-default manifest paths"),
        ("ordered_unresolved_blocker_ids", "manifest orders unresolved blocker guidance"),
        ("next_action_text", "manifest prints next action guidance"),
        ("require_unique_manifest_value", "manifest reports duplicate ready-value paths"),
        ("validate_unique_launch_values", "manifest rejects cross-network launch value collisions"),
        ("validation_failure_message", "manifest emits detailed transition failures"),
        ("mark_ready", "manifest marks complete profiles ready only after validation"),
        ("demote_ready_for_review", "manifest demotes edited ready profiles for re-review"),
        ("set_auxpow", "manifest updates AuxPoW chain id"),
        ("set_dns_seeds", "manifest updates DNS seeds"),
        ("set_identity", "manifest updates public network identity"),
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
    )
    for needle, description in preflight_checks:
        error = require_text(LAUNCH_PREFLIGHT, needle, description)
        if error:
            return fail(LAUNCH_PREFLIGHT, error)

    preflight_test_checks = (
        (
            "Reject placeholder AuxPoW chain id in launch preflight",
            "preflight fake-CLI placeholder AuxPoW chain-id coverage",
        ),
        (
            '"AuxPoW chain id is still the local launch placeholder 0x5a4b"',
            "preflight fake-CLI placeholder AuxPoW chain-id assertion",
        ),
    )
    for needle, description in preflight_test_checks:
        error = require_text(LAUNCH_PREFLIGHT_TEST, needle, description)
        if error:
            return fail(LAUNCH_PREFLIGHT_TEST, error)

    ltc_snapshot_script_checks = (
        ("Snapshot public launch-profile manifest update", "snapshot script prints manifest update section"),
        ("ZKCOIN_SNAPSHOT_AUDIT_JSON", "snapshot script writes optional audit summary"),
        ("height must be a positive integer", "snapshot script rejects zero or malformed snapshot heights"),
        ("expected block hash must not be the null uint256", "snapshot script rejects null expected block hashes"),
        ("litecoin-cli getblockchaininfo did not return JSON", "snapshot script validates source chain info JSON"),
        ("Litecoin source node chain must be main or test for public snapshot generation", "snapshot script rejects non-public source chains"),
        ("headers are ahead of downloaded blocks", "snapshot script rejects incompletely synced source headers"),
        ("Litecoin source node is still in initial block download", "snapshot script rejects IBD source nodes"),
        ("Litecoin source node must not be pruned for snapshot generation", "snapshot script rejects pruned source nodes"),
        ("snapshot audit summary path must differ from snapshot output path", "snapshot script rejects audit path collisions"),
        ("snapshot audit summary directory does not exist", "snapshot script rejects missing audit output directories"),
        ("snapshot output directory does not exist", "snapshot script rejects missing snapshot output directories"),
        ("restore block hash at height", "snapshot script validates rewind restore hashes"),
        ("snapshot block hash at height", "snapshot script validates source snapshot block hashes"),
        ("Litecoin source tip after rewind is", "snapshot script verifies post-rewind source tip"),
        ("snapshot output was not created by dumptxoutset", "snapshot script rejects missing dump artifact"),
        ("snapshot output is empty after dumptxoutset", "snapshot script rejects empty dump artifact"),
        ("SNAPSHOT_FILE_SHA256", "snapshot script fingerprints dump artifacts"),
        ("POST_VERIFY_SNAPSHOT_FILE_SHA256", "snapshot script rechecks dump artifact after verification"),
        ("snapshot output changed during verification", "snapshot script rejects artifact mutation during verification"),
        ("require_positive_int", "snapshot script requires positive audit counts"),
        ("positive decimal amount with 8 fractional digits", "snapshot script validates verifier total amount"),
        ("target_network", "snapshot script derives the target public profile from the Litecoin source chain"),
        ("--set-snapshot-audit {target_network}", "snapshot script prints audit-backed manifest update command"),
        ("zkcoin_public_launch_profile_manifest.json", "snapshot script points at public launch manifest"),
    )
    for needle, description in ltc_snapshot_script_checks:
        error = require_text(LTC_SNAPSHOT_SCRIPT, needle, description)
        if error:
            return fail(LTC_SNAPSHOT_SCRIPT, error)

    ltc_snapshot_script_test_checks = (
        ("Snapshot public launch-profile manifest update:", "snapshot script test checks manifest update section"),
        ("Snapshot audit summary written:", "snapshot script test checks audit summary output"),
        ("snapshot_file_sha256", "snapshot script test checks audit artifact SHA-256 output"),
        ("Reject a zero snapshot height", "snapshot script test rejects zero snapshot height"),
        ("Reject a null expected snapshot block hash", "snapshot script test rejects null expected block hash"),
        ("Reject malformed Litecoin source chain info", "snapshot script test rejects malformed source chain info"),
        ("Reject a Litecoin source with headers ahead of downloaded blocks", "snapshot script test rejects unsynced source headers"),
        ("Reject malformed rewind restore block hash", "snapshot script test rejects malformed rewind restore hashes"),
        (
            "Reject a Litecoin source still in initial block download",
            "snapshot script test rejects IBD source nodes",
        ),
        ("Reject a pruned Litecoin snapshot source", "snapshot script test rejects pruned source nodes"),
        ("Reject a non-public Litecoin source chain", "snapshot script test rejects non-public source chains"),
        (
            "Reject rewind that does not leave the source at the snapshot height",
            "snapshot script test rejects post-rewind tip mismatches",
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
            "Reject a missing audit summary output directory before calling either CLI",
            "snapshot script test rejects missing audit directory before RPC",
        ),
        (
            "Reject a missing snapshot output directory before calling either CLI",
            "snapshot script test rejects missing snapshot directory before RPC",
        ),
        ("Reject malformed source snapshot block hash", "snapshot script test rejects malformed source block hashes"),
        ("Reject missing snapshot dump file before verification", "snapshot script test rejects missing dump file"),
        ("Reject empty snapshot dump file before verification", "snapshot script test rejects empty dump file"),
        ("Reject snapshot artifact mutation during verification", "snapshot script test rejects verifier-time dump mutation"),
        ("Reject malformed verifier total amount", "snapshot script test rejects malformed total amount"),
        ("Reject zero snapshot dump coin count", "snapshot script test rejects zero dump coin counts"),
        ("Reject zero verifier base transaction count", "snapshot script test rejects zero base transaction count"),
        ("Print the testnet snapshot audit manifest handoff", "snapshot script test checks source-chain manifest handoff mapping"),
        ("--set-snapshot-audit testnet", "snapshot script test checks audit-backed manifest update command"),
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
            "zkcoin_public_launch_profile.py --set-dns-seeds NETWORK <seed1.hostname>,<seed2.hostname>",
            "public launch manifest DNS seed update documentation",
        ),
        (
            "reserved or local-use suffixes",
            "public launch manifest DNS seed rejection documentation",
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
            "reserved-suffix DNS seed",
            "public launch preflight DNS seed suffix documentation",
        ),
        (
            "ZKCOIN_SNAPSHOT_AUDIT_JSON",
            "public launch snapshot audit summary documentation",
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
            "validates the block `X + 1` restore hash before invalidating",
            "public launch snapshot rewind restore-hash validation documentation",
        ),
        (
            "snapshot output directory must also exist",
            "public launch snapshot output directory preflight documentation",
        ),
        (
            "well-formed non-null block hash for height X",
            "public launch snapshot source block-hash validation documentation",
        ),
        (
            "expected block hash is the null uint256 placeholder",
            "public launch snapshot null expected hash rejection documentation",
        ),
        (
            "zkcoin_public_launch_profile.py \\\n  --set-snapshot-audit NETWORK <snapshot_audit.json>",
            "public launch manifest audit-backed snapshot update documentation",
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
            "absolute snapshot file path",
            "public launch manifest snapshot audit file-path documentation",
        ),
        (
            "positive decimal total amount with 8 fractional digits",
            "public launch manifest snapshot audit amount documentation",
        ),
        (
            "positive coin and transaction counts",
            "public launch snapshot positive audit count documentation",
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
            "changes during zkCoin verification",
            "snapshot operator verifier-time artifact mutation documentation",
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
            "validates the audit summary output path before running snapshot RPCs",
            "snapshot operator preflights audit output documentation",
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
            "confirms the source tip is exactly height X after invalidation",
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
