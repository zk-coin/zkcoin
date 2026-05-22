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
import sys

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
    "chain_history_clean",
    "shielded_inactive_at_launch",
    "at_launch_tip",
)
REQUIRED_READINESS_FIELDS = REQUIRED_READINESS_BOOL_FIELDS + ("failures",)
REQUIRED_DETAIL_FIELDS = {
    "ltc_snapshot": ("height", "block_hash", "import_hash"),
    "auxpow": ("start_height", "chain_id", "strict_chain_id", "parent_version_safe"),
    "shielded_pool": ("start_height", "scaffold_proofs", "real_proof_backend", "real_proof_verification"),
}

schema_errors = []
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

shielded_detail = detail_sections.get("shielded_pool")
if shielded_detail is not None:
    if "scaffold_proofs" in shielded_detail and type(shielded_detail["scaffold_proofs"]) is not bool:
        schema_errors.append("getblockchaininfo.shielded_pool.scaffold_proofs must be a boolean")
    if "real_proof_verification" in shielded_detail and type(shielded_detail["real_proof_verification"]) is not bool:
        schema_errors.append("getblockchaininfo.shielded_pool.real_proof_verification must be a boolean")
    if "real_proof_backend" in shielded_detail and not isinstance(shielded_detail["real_proof_backend"], str):
        schema_errors.append("getblockchaininfo.shielded_pool.real_proof_backend must be a string")

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
print(f"  chain height: {info.get('blocks')}")
print(f"  at launch tip: {str(readiness['at_launch_tip']).lower()}")
print(f"  snapshot configured: {str(readiness['snapshot_configured']).lower()}")
print(f"  snapshot imported: {str(readiness['snapshot_imported']).lower()}")
print(f"  snapshot height: {snapshot.get('height')}")
print(f"  snapshot block hash: {snapshot.get('block_hash')}")
print(f"  snapshot import hash: {snapshot.get('import_hash')}")
print(f"  auxpow active at launch: {str(readiness['auxpow_active_at_launch']).lower()}")
print(f"  auxpow start height: {auxpow.get('start_height')}")
print(f"  auxpow chain id: {auxpow.get('chain_id')}")
print(f"  auxpow strict chain id: {str(bool(auxpow.get('strict_chain_id'))).lower()}")
print(f"  auxpow parent version safe: {str(bool(auxpow.get('parent_version_safe'))).lower()}")
print(f"  chain id configured: {str(readiness['chain_id_configured']).lower()}")
print(f"  chain id parent version safe: {str(readiness['chain_id_parent_version_safe']).lower()}")
print(f"  chain history clean: {str(readiness['chain_history_clean']).lower()}")
print(f"  shielded inactive at launch: {str(readiness['shielded_inactive_at_launch']).lower()}")
print(f"  shielded start height: {shielded.get('start_height')}")
print(f"  shielded scaffold proofs: {str(shielded.get('scaffold_proofs')).lower()}")
print(f"  shielded real proof backend: {shielded.get('real_proof_backend')}")
print(f"  shielded real proof verification: {str(shielded.get('real_proof_verification')).lower()}")

false_ready_fields = [
    field for field in REQUIRED_READINESS_BOOL_FIELDS
    if field != "ready" and readiness[field] is not True
]

posture_failures = []
if shielded["scaffold_proofs"] is not False:
    posture_failures.append("shielded scaffold proofs are enabled")
if shielded["real_proof_backend"] != "orchard-v1":
    posture_failures.append(f"shielded real proof backend is not orchard-v1: {shielded['real_proof_backend']}")
if shielded["real_proof_verification"] is not True:
    posture_failures.append("shielded real proof verification is not available")

if readiness["ready"] is True and failures == [] and not false_ready_fields and not posture_failures:
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
