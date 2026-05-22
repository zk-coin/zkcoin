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

snapshot = info.get("ltc_snapshot", {})
auxpow = info.get("auxpow", {})
shielded = info.get("shielded_pool", {})
failures = readiness.get("failures", [])

print("zkCoin launch readiness preflight")
print(f"  ready: {str(bool(readiness.get('ready'))).lower()}")
print(f"  chain height: {info.get('blocks')}")
print(f"  at launch tip: {str(bool(readiness.get('at_launch_tip'))).lower()}")
print(f"  snapshot configured: {str(bool(readiness.get('snapshot_configured'))).lower()}")
print(f"  snapshot imported: {str(bool(readiness.get('snapshot_imported'))).lower()}")
print(f"  snapshot height: {snapshot.get('height')}")
print(f"  snapshot block hash: {snapshot.get('block_hash')}")
print(f"  snapshot import hash: {snapshot.get('import_hash')}")
print(f"  auxpow active at launch: {str(bool(readiness.get('auxpow_active_at_launch'))).lower()}")
print(f"  auxpow start height: {auxpow.get('start_height')}")
print(f"  auxpow chain id: {auxpow.get('chain_id')}")
print(f"  auxpow strict chain id: {str(bool(auxpow.get('strict_chain_id'))).lower()}")
print(f"  auxpow parent version safe: {str(bool(auxpow.get('parent_version_safe'))).lower()}")
print(f"  shielded inactive at launch: {str(bool(readiness.get('shielded_inactive_at_launch'))).lower()}")
print(f"  shielded start height: {shielded.get('start_height')}")

if readiness.get("ready") is True and failures == []:
    print("Launch preflight passed.")
    sys.exit(0)

print("Launch preflight failed.", file=sys.stderr)
if failures:
    print("Failures:", file=sys.stderr)
    for failure in failures:
        print(f"  - {failure}", file=sys.stderr)
else:
    print("  - readiness flag is false but no failure reason was returned", file=sys.stderr)
sys.exit(1)
PY
