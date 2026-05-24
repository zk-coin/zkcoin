#!/usr/bin/env bash
#
# Copyright (c) 2026 The zkCoin developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
#
# Check a configured launch node's getblockchaininfo.launch_readiness status.

export LC_ALL=C
set -euo pipefail

usage() {
  cat <<'EOF'
Usage:
  zkcoin_launch_preflight.sh <zkcoin-cli ...>

Example:
  contrib/devtools/zkcoin_launch_preflight.sh \
    ./src/litecoin-cli -datadir=/srv/zkcoin-data

The target node must already be started with the chosen block-X snapshot
constants and the snapshot manifest must already be imported. The script exits
0 only when getblockchaininfo.launch_readiness.ready is true.
EOF
}

if (( $# == 0 )); then
  usage
  exit 1
fi

ZK_CLI=("$@")

zk_cli() {
  "${ZK_CLI[@]}" -rpcclienttimeout=9999999 "$@"
}

INFO_JSON="$(zk_cli getblockchaininfo)"

python3 - "$INFO_JSON" <<'PY'
import json
import re
import sys

PLACEHOLDER_AUXPOW_CHAIN_ID = 0x5A4B
HEX64_RE = re.compile(r"^[0-9a-f]{64}$")
NULL_UINT256 = "0" * 64
SNAPSHOT_HASH_FIELD_ERRORS = {
    "block_hash": "getblockchaininfo.ltc_snapshot.block_hash must be a non-null lowercase 64-character hex string when launch_readiness.snapshot_configured is true",
    "import_hash": "getblockchaininfo.ltc_snapshot.import_hash must be a non-null lowercase 64-character hex string when launch_readiness.snapshot_configured is true",
}

try:
    info = json.loads(sys.argv[1])
except json.JSONDecodeError as exc:
    print(f"error: getblockchaininfo did not return JSON: {exc}", file=sys.stderr)
    sys.exit(1)

readiness = info.get("launch_readiness")
if not isinstance(readiness, dict):
    print("error: getblockchaininfo response does not include launch_readiness", file=sys.stderr)
    sys.exit(1)

REQUIRED_READINESS_BOOL_FIELDS = (
    "ready",
    "snapshot_configured",
    "snapshot_imported",
    "auxpow_active_at_launch",
    "chain_id_configured",
    "chain_id_parent_version_safe",
    "script_rules_active_at_launch",
    "chain_history_clean",
    "public_network_identity_configured",
    "shielded_inactive_at_launch",
    "at_launch_tip",
)
REQUIRED_READINESS_FIELDS = REQUIRED_READINESS_BOOL_FIELDS + ("public_network_identity", "failures",)
REQUIRED_PUBLIC_IDENTITY_BOOL_FIELDS = (
    "configured",
    "inherited_litecoin_message_start",
    "message_start_shape_valid",
    "inherited_litecoin_default_port",
    "default_port_shape_valid",
    "inherited_litecoin_dns_seed",
    "dns_seeds_shape_valid",
    "fixed_seeds_present",
    "inherited_litecoin_base58_prefixes",
    "base58_prefixes_shape_valid",
    "base58_prefixes_unique",
    "inherited_litecoin_bech32_hrp",
    "bech32_hrp_shape_valid",
    "inherited_litecoin_mweb_hrp",
    "mweb_hrp_shape_valid",
    "hrps_unique",
)
REQUIRED_PUBLIC_IDENTITY_FIELDS = REQUIRED_PUBLIC_IDENTITY_BOOL_FIELDS + ("failures",)
REQUIRED_DETAIL_FIELDS = {
    "ltc_snapshot": ("enabled", "height", "block_hash", "import_hash", "imported", "import_in_progress"),
    "auxpow": ("next_block_active", "start_height", "chain_id", "strict_chain_id", "parent_version_safe"),
    "shielded_pool": ("next_block_active", "start_height", "scaffold_proofs", "real_proof_backend", "real_proof_verification"),
}

schema_errors = []
blocks = info.get("blocks")
if type(blocks) is not int or blocks < 0:
    schema_errors.append("getblockchaininfo.blocks must be a non-negative integer")
headers = info.get("headers")
if type(headers) is not int or headers < 0:
    schema_errors.append("getblockchaininfo.headers must be a non-negative integer")
if type(blocks) is int and type(headers) is int and headers < blocks:
    schema_errors.append("getblockchaininfo.headers must be greater than or equal to blocks")
initialblockdownload = info.get("initialblockdownload")
if type(initialblockdownload) is not bool:
    schema_errors.append("getblockchaininfo.initialblockdownload must be a boolean")
pruned = info.get("pruned")
if type(pruned) is not bool:
    schema_errors.append("getblockchaininfo.pruned must be a boolean")
warnings = info.get("warnings")
if type(warnings) is not str:
    schema_errors.append("getblockchaininfo.warnings must be a string")

missing_readiness = [field for field in REQUIRED_READINESS_FIELDS if field not in readiness]
if missing_readiness:
    schema_errors.append("missing launch_readiness fields: " + ", ".join(missing_readiness))

unexpected_readiness = sorted(set(readiness) - set(REQUIRED_READINESS_FIELDS))
if unexpected_readiness:
    schema_errors.append("unexpected launch_readiness fields: " + ", ".join(unexpected_readiness))

for field in REQUIRED_READINESS_BOOL_FIELDS:
    if field in readiness and type(readiness[field]) is not bool:
        schema_errors.append(f"launch_readiness.{field} must be a boolean")

failures = readiness.get("failures")
if "failures" in readiness:
    if not isinstance(failures, list):
        schema_errors.append("launch_readiness.failures must be an array")
    elif not all(isinstance(failure, str) for failure in failures):
        schema_errors.append("launch_readiness.failures entries must be strings")

public_identity = readiness.get("public_network_identity")
if not isinstance(public_identity, dict):
    schema_errors.append("launch_readiness.public_network_identity must be an object")
else:
    missing_public_identity = [field for field in REQUIRED_PUBLIC_IDENTITY_FIELDS if field not in public_identity]
    if missing_public_identity:
        schema_errors.append("missing launch_readiness.public_network_identity fields: " + ", ".join(missing_public_identity))

    unexpected_public_identity = sorted(set(public_identity) - set(REQUIRED_PUBLIC_IDENTITY_FIELDS))
    if unexpected_public_identity:
        schema_errors.append("unexpected launch_readiness.public_network_identity fields: " + ", ".join(unexpected_public_identity))

    for field in REQUIRED_PUBLIC_IDENTITY_BOOL_FIELDS:
        if field in public_identity and type(public_identity[field]) is not bool:
            schema_errors.append(f"launch_readiness.public_network_identity.{field} must be a boolean")

    public_identity_failures = public_identity.get("failures")
    if "failures" in public_identity:
        if not isinstance(public_identity_failures, list):
            schema_errors.append("launch_readiness.public_network_identity.failures must be an array")
        elif not all(isinstance(failure, str) for failure in public_identity_failures):
            schema_errors.append("launch_readiness.public_network_identity.failures entries must be strings")
    if (
        "configured" in public_identity
        and "public_network_identity_configured" in readiness
        and type(public_identity.get("configured")) is bool
        and type(readiness.get("public_network_identity_configured")) is bool
        and public_identity["configured"] != readiness["public_network_identity_configured"]
    ):
        schema_errors.append("launch_readiness.public_network_identity.configured must match public_network_identity_configured")

if (
    type(blocks) is int
    and "at_launch_tip" in readiness
    and type(readiness.get("at_launch_tip")) is bool
    and readiness["at_launch_tip"] is True
    and blocks != 0
):
    schema_errors.append("getblockchaininfo.blocks must be 0 when launch_readiness.at_launch_tip is true")
if (
    type(headers) is int
    and "at_launch_tip" in readiness
    and type(readiness.get("at_launch_tip")) is bool
    and readiness["at_launch_tip"] is True
    and headers != 0
):
    schema_errors.append("getblockchaininfo.headers must be 0 when launch_readiness.at_launch_tip is true")

detail_sections = {}
for section, required_fields in REQUIRED_DETAIL_FIELDS.items():
    value = info.get(section)
    if not isinstance(value, dict):
        schema_errors.append(f"getblockchaininfo.{section} must be an object")
        continue
    missing_fields = [field for field in required_fields if field not in value]
    if missing_fields:
        schema_errors.append(f"missing getblockchaininfo.{section} fields: " + ", ".join(missing_fields))
    detail_sections[section] = value

snapshot_detail = detail_sections.get("ltc_snapshot")
if snapshot_detail is not None:
    for field in ("enabled", "imported", "import_in_progress"):
        if field in snapshot_detail and type(snapshot_detail[field]) is not bool:
            schema_errors.append(f"getblockchaininfo.ltc_snapshot.{field} must be a boolean")
    if readiness.get("snapshot_configured") is True:
        if type(snapshot_detail.get("height")) is not int or snapshot_detail.get("height") <= 0:
            schema_errors.append(
                "getblockchaininfo.ltc_snapshot.height must be a positive integer when launch_readiness.snapshot_configured is true"
            )
        for field in ("block_hash", "import_hash"):
            value = snapshot_detail.get(field)
            if not isinstance(value, str) or HEX64_RE.fullmatch(value) is None or value == NULL_UINT256:
                schema_errors.append(SNAPSHOT_HASH_FIELD_ERRORS[field])
    if (
        "enabled" in snapshot_detail
        and "snapshot_configured" in readiness
        and type(snapshot_detail.get("enabled")) is bool
        and type(readiness.get("snapshot_configured")) is bool
        and snapshot_detail["enabled"] != readiness["snapshot_configured"]
    ):
        schema_errors.append("getblockchaininfo.ltc_snapshot.enabled must match launch_readiness.snapshot_configured")
    if (
        "imported" in snapshot_detail
        and "snapshot_imported" in readiness
        and type(snapshot_detail.get("imported")) is bool
        and type(readiness.get("snapshot_imported")) is bool
        and snapshot_detail["imported"] != readiness["snapshot_imported"]
    ):
        schema_errors.append("getblockchaininfo.ltc_snapshot.imported must match launch_readiness.snapshot_imported")

auxpow_detail = detail_sections.get("auxpow")
if auxpow_detail is not None:
    if "next_block_active" in auxpow_detail and type(auxpow_detail["next_block_active"]) is not bool:
        schema_errors.append("getblockchaininfo.auxpow.next_block_active must be a boolean")
    if "start_height" in auxpow_detail and type(auxpow_detail["start_height"]) is not int:
        schema_errors.append("getblockchaininfo.auxpow.start_height must be an integer")
    if "chain_id" in auxpow_detail and type(auxpow_detail["chain_id"]) is not int:
        schema_errors.append("getblockchaininfo.auxpow.chain_id must be an integer")
    if "strict_chain_id" in auxpow_detail and type(auxpow_detail["strict_chain_id"]) is not bool:
        schema_errors.append("getblockchaininfo.auxpow.strict_chain_id must be a boolean")
    if "parent_version_safe" in auxpow_detail and type(auxpow_detail["parent_version_safe"]) is not bool:
        schema_errors.append("getblockchaininfo.auxpow.parent_version_safe must be a boolean")
    if (
        "next_block_active" in auxpow_detail
        and "auxpow_active_at_launch" in readiness
        and "at_launch_tip" in readiness
        and type(auxpow_detail.get("next_block_active")) is bool
        and type(readiness.get("auxpow_active_at_launch")) is bool
        and readiness.get("at_launch_tip") is True
        and auxpow_detail["next_block_active"] != readiness["auxpow_active_at_launch"]
    ):
        schema_errors.append("getblockchaininfo.auxpow.next_block_active must match launch_readiness.auxpow_active_at_launch at the launch tip")
    if (
        "start_height" in auxpow_detail
        and "auxpow_active_at_launch" in readiness
        and type(auxpow_detail.get("start_height")) is int
        and type(readiness.get("auxpow_active_at_launch")) is bool
        and readiness["auxpow_active_at_launch"] is True
        and auxpow_detail["start_height"] != 1
    ):
        schema_errors.append("getblockchaininfo.auxpow.start_height must be 1 when launch_readiness.auxpow_active_at_launch is true")
    if (
        "chain_id" in auxpow_detail
        and "chain_id_configured" in readiness
        and type(auxpow_detail.get("chain_id")) is int
        and type(readiness.get("chain_id_configured")) is bool
        and readiness["chain_id_configured"] is True
        and not (0 < auxpow_detail["chain_id"] < 0x8000)
    ):
        schema_errors.append("getblockchaininfo.auxpow.chain_id must be non-zero and AuxPoW-version encodable when launch_readiness.chain_id_configured is true")
    if (
        "strict_chain_id" in auxpow_detail
        and "chain_id_configured" in readiness
        and type(auxpow_detail.get("strict_chain_id")) is bool
        and type(readiness.get("chain_id_configured")) is bool
        and readiness["chain_id_configured"] is True
        and auxpow_detail["strict_chain_id"] is not True
    ):
        schema_errors.append("getblockchaininfo.auxpow.strict_chain_id must be true when launch_readiness.chain_id_configured is true")
    if (
        "parent_version_safe" in auxpow_detail
        and "chain_id_parent_version_safe" in readiness
        and type(auxpow_detail.get("parent_version_safe")) is bool
        and type(readiness.get("chain_id_parent_version_safe")) is bool
        and auxpow_detail["parent_version_safe"] != readiness["chain_id_parent_version_safe"]
    ):
        schema_errors.append("getblockchaininfo.auxpow.parent_version_safe must match launch_readiness.chain_id_parent_version_safe")

shielded_detail = detail_sections.get("shielded_pool")
if shielded_detail is not None:
    if "next_block_active" in shielded_detail and type(shielded_detail["next_block_active"]) is not bool:
        schema_errors.append("getblockchaininfo.shielded_pool.next_block_active must be a boolean")
    if "start_height" in shielded_detail and type(shielded_detail["start_height"]) is not int:
        schema_errors.append("getblockchaininfo.shielded_pool.start_height must be an integer")
    if "scaffold_proofs" in shielded_detail and type(shielded_detail["scaffold_proofs"]) is not bool:
        schema_errors.append("getblockchaininfo.shielded_pool.scaffold_proofs must be a boolean")
    if "real_proof_verification" in shielded_detail and type(shielded_detail["real_proof_verification"]) is not bool:
        schema_errors.append("getblockchaininfo.shielded_pool.real_proof_verification must be a boolean")
    if "real_proof_backend" in shielded_detail and not isinstance(shielded_detail["real_proof_backend"], str):
        schema_errors.append("getblockchaininfo.shielded_pool.real_proof_backend must be a string")
    if (
        "next_block_active" in shielded_detail
        and "shielded_inactive_at_launch" in readiness
        and "at_launch_tip" in readiness
        and type(shielded_detail.get("next_block_active")) is bool
        and type(readiness.get("shielded_inactive_at_launch")) is bool
        and readiness.get("at_launch_tip") is True
        and shielded_detail["next_block_active"] == readiness["shielded_inactive_at_launch"]
    ):
        schema_errors.append("getblockchaininfo.shielded_pool.next_block_active must agree with launch_readiness.shielded_inactive_at_launch at the launch tip")
    if (
        "start_height" in shielded_detail
        and "shielded_inactive_at_launch" in readiness
        and "at_launch_tip" in readiness
        and type(shielded_detail.get("start_height")) is int
        and type(readiness.get("shielded_inactive_at_launch")) is bool
        and readiness.get("at_launch_tip") is True
        and readiness["shielded_inactive_at_launch"] is True
        and shielded_detail["start_height"] == 1
    ):
        schema_errors.append("getblockchaininfo.shielded_pool.start_height must not be 1 when launch_readiness.shielded_inactive_at_launch is true")

if schema_errors:
    print("error: malformed launch preflight response", file=sys.stderr)
    for error in schema_errors:
        print(f"  - {error}", file=sys.stderr)
    sys.exit(1)

snapshot = detail_sections["ltc_snapshot"]
auxpow = detail_sections["auxpow"]
shielded = detail_sections["shielded_pool"]

print("zkCoin launch readiness preflight")
print(f"  ready: {str(readiness['ready']).lower()}")
print(f"  chain height: {blocks}")
print(f"  header height: {headers}")
print(f"  initial block download: {str(initialblockdownload).lower()}")
print(f"  pruned: {str(pruned).lower()}")
print(f"  warnings: {warnings if warnings else '<none>'}")
print(f"  at launch tip: {str(readiness['at_launch_tip']).lower()}")
print(f"  snapshot configured: {str(readiness['snapshot_configured']).lower()}")
print(f"  snapshot imported: {str(readiness['snapshot_imported']).lower()}")
print(f"  snapshot detail enabled: {str(snapshot['enabled']).lower()}")
print(f"  snapshot detail imported: {str(snapshot['imported']).lower()}")
print(f"  snapshot import in progress: {str(snapshot['import_in_progress']).lower()}")
print(f"  snapshot height: {snapshot.get('height')}")
print(f"  snapshot block hash: {snapshot.get('block_hash')}")
print(f"  snapshot import hash: {snapshot.get('import_hash')}")
print(f"  auxpow active at launch: {str(readiness['auxpow_active_at_launch']).lower()}")
print(f"  auxpow next block active: {str(auxpow['next_block_active']).lower()}")
print(f"  auxpow start height: {auxpow.get('start_height')}")
print(f"  auxpow chain id: {auxpow.get('chain_id')}")
print(f"  auxpow strict chain id: {str(auxpow['strict_chain_id']).lower()}")
print(f"  auxpow parent version safe: {str(auxpow['parent_version_safe']).lower()}")
print(f"  chain id configured: {str(readiness['chain_id_configured']).lower()}")
print(f"  chain id parent version safe: {str(readiness['chain_id_parent_version_safe']).lower()}")
print(f"  script rules active at launch: {str(readiness['script_rules_active_at_launch']).lower()}")
print(f"  chain history clean: {str(readiness['chain_history_clean']).lower()}")
print(f"  public network identity configured: {str(readiness['public_network_identity_configured']).lower()}")
print(f"  public identity message start inherited: {str(public_identity['inherited_litecoin_message_start']).lower()}")
print(f"  public identity message start shape valid: {str(public_identity['message_start_shape_valid']).lower()}")
print(f"  public identity default port inherited: {str(public_identity['inherited_litecoin_default_port']).lower()}")
print(f"  public identity default port shape valid: {str(public_identity['default_port_shape_valid']).lower()}")
print(f"  public identity DNS seed inherited: {str(public_identity['inherited_litecoin_dns_seed']).lower()}")
print(f"  public identity DNS seed shape valid: {str(public_identity['dns_seeds_shape_valid']).lower()}")
print(f"  public identity fixed seeds present: {str(public_identity['fixed_seeds_present']).lower()}")
print(f"  public identity Base58 prefixes inherited: {str(public_identity['inherited_litecoin_base58_prefixes']).lower()}")
print(f"  public identity Base58 prefix shape valid: {str(public_identity['base58_prefixes_shape_valid']).lower()}")
print(f"  public identity Base58 prefixes unique: {str(public_identity['base58_prefixes_unique']).lower()}")
print(f"  public identity Bech32 HRP inherited: {str(public_identity['inherited_litecoin_bech32_hrp']).lower()}")
print(f"  public identity Bech32 HRP shape valid: {str(public_identity['bech32_hrp_shape_valid']).lower()}")
print(f"  public identity MWEB HRP inherited: {str(public_identity['inherited_litecoin_mweb_hrp']).lower()}")
print(f"  public identity MWEB HRP shape valid: {str(public_identity['mweb_hrp_shape_valid']).lower()}")
print(f"  public identity HRPs unique: {str(public_identity['hrps_unique']).lower()}")
print(f"  shielded inactive at launch: {str(readiness['shielded_inactive_at_launch']).lower()}")
print(f"  shielded next block active: {str(shielded['next_block_active']).lower()}")
print(f"  shielded start height: {shielded.get('start_height')}")
print(f"  shielded scaffold proofs: {str(shielded.get('scaffold_proofs')).lower()}")
print(f"  shielded real proof backend: {shielded.get('real_proof_backend')}")
print(f"  shielded real proof verification: {str(shielded.get('real_proof_verification')).lower()}")

false_ready_fields = [
    field for field in REQUIRED_READINESS_BOOL_FIELDS
    if field != "ready" and readiness[field] is not True
]

posture_failures = []
if initialblockdownload is not False:
    posture_failures.append("node is still in initial block download")
if pruned is not False:
    posture_failures.append("launch node is running in pruned mode")
if warnings:
    posture_failures.append("launch node reports warnings")
if snapshot["import_in_progress"] is not False:
    posture_failures.append("snapshot import is still in progress")
if shielded["scaffold_proofs"] is not False:
    posture_failures.append("shielded scaffold proofs are enabled")
if shielded["real_proof_backend"] != "orchard-v1":
    posture_failures.append(f"shielded real proof backend is not orchard-v1: {shielded['real_proof_backend']}")
if shielded["real_proof_verification"] is not True:
    posture_failures.append("shielded real proof verification is not available")
if auxpow["chain_id"] == PLACEHOLDER_AUXPOW_CHAIN_ID:
    posture_failures.append("AuxPoW chain id is still the local launch placeholder 0x5a4b")

if readiness["ready"] is True and failures == [] and public_identity["failures"] == [] and not false_ready_fields and not posture_failures:
    print("Launch preflight passed.")
    sys.exit(0)

print("Launch preflight failed.", file=sys.stderr)
if readiness["ready"] is True and false_ready_fields:
    print(
        "  - readiness flag is true but required readiness fields are false: "
        + ", ".join(false_ready_fields),
        file=sys.stderr,
    )
if posture_failures:
    print("Operator posture failures:", file=sys.stderr)
    for failure in posture_failures:
        print(f"  - {failure}", file=sys.stderr)
if public_identity["failures"]:
    print("Public network identity failures:", file=sys.stderr)
    for failure in public_identity["failures"]:
        print(f"  - {failure}", file=sys.stderr)
if failures:
    print("Failures:", file=sys.stderr)
    for failure in failures:
        print(f"  - {failure}", file=sys.stderr)
elif readiness["ready"] is not True:
    print("  - readiness flag is false but no failure reason was returned", file=sys.stderr)
elif not false_ready_fields:
    print("  - readiness flag is true but failure reasons were returned", file=sys.stderr)
sys.exit(1)
PY
