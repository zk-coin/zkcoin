#!/usr/bin/env bash
#
# Copyright (c) 2026 The zkCoin developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
#
# Generate and verify the Litecoin block-X UTXO snapshot constants used by
# zkCoin launch nodes.

export LC_ALL=C
set -euo pipefail

usage() {
  cat <<'EOF'
Usage:
  zkcoin_ltc_snapshot.sh <height> <expected-block-hash> <snapshot-out-path> <litecoin-cli ...> -- <zkcoin-cli ...>

Example:
  contrib/devtools/zkcoin_ltc_snapshot.sh \
    3000000 \
    0000000000000000000000000000000000000000000000000000000000000000 \
    /srv/snapshots/ltc-block-x.dat \
    /srv/litecoin/src/litecoin-cli -datadir=/srv/litecoin-data \
    -- \
    ./src/litecoin-cli -datadir=/srv/zkcoin-data

The Litecoin node must be exactly at <height>. If it is beyond <height>, this
script refuses to rewind it unless ZKCOIN_SNAPSHOT_ALLOW_REWIND=1 is set.
Only use rewind mode on a dedicated disposable snapshot node.

The script prints snapshot-related launch-node arguments, including
-ltcsnapshotfile=<path>, and the public launch-profile manifest update command
after the snapshot manifest is dumped and verified. Combine them with the
AuxPoW launch profile and confirm launch_readiness before mining the first
child block.
EOF
}

die() {
  echo "error: $*" >&2
  exit 1
}

if (( $# < 6 )); then
  usage
  exit 1
fi

HEIGHT="$1"
EXPECTED_BLOCK_HASH="$(printf '%s' "$2" | tr '[:upper:]' '[:lower:]')"
SNAPSHOT_PATH="$3"
shift 3

if [[ ! "$HEIGHT" =~ ^[0-9]+$ ]]; then
  die "height must be a non-negative integer"
fi

if [[ ! "$EXPECTED_BLOCK_HASH" =~ ^[0-9a-f]{64}$ ]]; then
  die "expected block hash must be 64 hex characters"
fi

LTC_CLI=()
while (( $# > 0 )) && [[ "$1" != "--" ]]; do
  LTC_CLI+=("$1")
  shift
done

if (( $# == 0 )); then
  die "missing -- separator before zkcoin-cli command"
fi
shift

ZK_CLI=("$@")
if (( ${#LTC_CLI[@]} == 0 )); then
  die "missing litecoin-cli command"
fi
if (( ${#ZK_CLI[@]} == 0 )); then
  die "missing zkcoin-cli command"
fi

case "$SNAPSHOT_PATH" in
  /*) ;;
  *) SNAPSHOT_PATH="$(pwd -P)/$SNAPSHOT_PATH" ;;
esac

if [[ -e "$SNAPSHOT_PATH" ]]; then
  die "snapshot output already exists: $SNAPSHOT_PATH"
fi

ltc_cli() {
  "${LTC_CLI[@]}" -rpcclienttimeout=9999999 "$@"
}

zk_cli() {
  "${ZK_CLI[@]}" -rpcclienttimeout=9999999 "$@"
}

RESTORE_BLOCK_HASH=""
cleanup() {
  local status=$?
  if [[ -n "$RESTORE_BLOCK_HASH" ]]; then
    echo "Restoring Litecoin source chain by reconsidering $RESTORE_BLOCK_HASH" >&2
    if ! ltc_cli reconsiderblock "$RESTORE_BLOCK_HASH" >/dev/null; then
      echo "error: failed to restore Litecoin source chain at $RESTORE_BLOCK_HASH" >&2
      if (( status == 0 )); then
        status=1
      fi
    fi
  fi
  exit "$status"
}
trap cleanup EXIT

SOURCE_TIP="$(ltc_cli getblockcount)"
if [[ ! "$SOURCE_TIP" =~ ^[0-9]+$ ]]; then
  die "litecoin-cli getblockcount returned unexpected value: $SOURCE_TIP"
fi

if (( SOURCE_TIP < HEIGHT )); then
  die "Litecoin source tip $SOURCE_TIP is below requested snapshot height $HEIGHT"
fi

if (( SOURCE_TIP > HEIGHT )); then
  if [[ "${ZKCOIN_SNAPSHOT_ALLOW_REWIND:-0}" != "1" ]]; then
    die "Litecoin source tip $SOURCE_TIP is beyond height $HEIGHT. Set ZKCOIN_SNAPSHOT_ALLOW_REWIND=1 only on a disposable snapshot node."
  fi

  RESTORE_BLOCK_HASH="$(ltc_cli getblockhash "$((HEIGHT + 1))")"
  echo "Rewinding Litecoin source to height $HEIGHT by invalidating $RESTORE_BLOCK_HASH" >&2
  ltc_cli invalidateblock "$RESTORE_BLOCK_HASH" >/dev/null
fi

ACTUAL_BLOCK_HASH="$(ltc_cli getblockhash "$HEIGHT")"
ACTUAL_BLOCK_HASH_LOWER="$(printf '%s' "$ACTUAL_BLOCK_HASH" | tr '[:upper:]' '[:lower:]')"
if [[ "$ACTUAL_BLOCK_HASH_LOWER" != "$EXPECTED_BLOCK_HASH" ]]; then
  die "snapshot block hash mismatch at height $HEIGHT: expected=$EXPECTED_BLOCK_HASH actual=$ACTUAL_BLOCK_HASH_LOWER"
fi

echo "Dumping Litecoin UTXO snapshot at height $HEIGHT to $SNAPSHOT_PATH" >&2
DUMP_JSON="$(ltc_cli dumptxoutset "$SNAPSHOT_PATH")"

echo "Verifying normalized zkCoin import hash" >&2
VERIFY_JSON="$(zk_cli verifysnapshotmanifest "$SNAPSHOT_PATH")"

python3 - "$HEIGHT" "$EXPECTED_BLOCK_HASH" "$SNAPSHOT_PATH" "$DUMP_JSON" "$VERIFY_JSON" <<'PY'
import json
import re
import sys

height = int(sys.argv[1])
expected_hash = sys.argv[2].lower()
snapshot_path = sys.argv[3]
dump_json = sys.argv[4]
verify_json = sys.argv[5]
HEX64_RE = re.compile(r"^[0-9a-f]{64}$")

def fail(message):
    print(f"error: {message}", file=sys.stderr)
    sys.exit(1)

def load_json(source, raw):
    try:
        value = json.loads(raw)
    except json.JSONDecodeError as exc:
        fail(f"{source} did not return JSON: {exc}")
    if not isinstance(value, dict):
        fail(f"{source} response must be a JSON object")
    return value

def require_field(obj, source, field):
    if field not in obj:
        fail(f"missing {source} field: {field}")
    return obj[field]

def require_int(obj, source, field):
    value = require_field(obj, source, field)
    if isinstance(value, bool):
        fail(f"{source}.{field} must be an integer")
    try:
        parsed = int(value)
    except (TypeError, ValueError):
        fail(f"{source}.{field} must be an integer")
    if parsed < 0:
        fail(f"{source}.{field} must be a non-negative integer")
    return parsed

def require_hash(obj, source, field):
    value = require_field(obj, source, field)
    if not isinstance(value, str):
        fail(f"{source}.{field} must be a 64-character hex string")
    value = value.lower()
    if not HEX64_RE.fullmatch(value):
        fail(f"{source}.{field} must be a 64-character hex string")
    return value

dump = load_json("dumptxoutset", dump_json)
verify = load_json("verifysnapshotmanifest", verify_json)

dump_height = require_int(dump, "dumptxoutset", "base_height")
dump_hash = require_hash(dump, "dumptxoutset", "base_hash")
dump_coins = require_int(dump, "dumptxoutset", "coins_written")
verify_height = require_int(verify, "verifysnapshotmanifest", "base_height")
verify_hash = require_hash(verify, "verifysnapshotmanifest", "base_hash")
verify_coins = require_int(verify, "verifysnapshotmanifest", "coins")
verify_metadata_coins = require_int(verify, "verifysnapshotmanifest", "metadata_coins")
verify_base_nchaintx = require_int(verify, "verifysnapshotmanifest", "base_nchaintx")
snapshot_hash = require_hash(verify, "verifysnapshotmanifest", "snapshot_hash")
import_hash = require_hash(verify, "verifysnapshotmanifest", "import_hash")
total_amount = require_field(verify, "verifysnapshotmanifest", "total_amount")

if dump_height != height:
    fail(f"dumptxoutset base_height mismatch: expected={height} actual={dump_height}")

if dump_hash != expected_hash:
    fail(f"dumptxoutset base_hash mismatch: expected={expected_hash} actual={dump_hash}")

if verify_hash != expected_hash:
    fail(f"verifysnapshotmanifest base_hash mismatch: expected={expected_hash} actual={verify_hash}")

if verify_height != height:
    fail(f"verifysnapshotmanifest base_height mismatch: expected={height} actual={verify_height}")

if verify_coins != dump_coins:
    fail(f"coin count mismatch: dumptxoutset={dump_coins} verified={verify_coins}")

if verify_metadata_coins != dump_coins:
    fail(f"metadata coin count mismatch: dumptxoutset={dump_coins} metadata={verify_metadata_coins}")

summary = {
    "height": height,
    "block_hash": expected_hash,
    "coins": verify_coins,
    "base_nchaintx": verify_base_nchaintx,
    "snapshot_hash": snapshot_hash,
    "import_hash": import_hash,
    "snapshot_file": snapshot_path,
    "total_amount": total_amount,
}

print("Snapshot verified.")
print()
print("Snapshot launch-node arguments:")
print(f"-ltcsnapshotheight={height}")
print(f"-ltcsnapshotblockhash={expected_hash}")
print(f"-ltcsnapshotutxoroot={import_hash}")
print(f"-ltcsnapshotfile={snapshot_path}")
print()
print("Snapshot public launch-profile manifest update:")
print("Replace NETWORK with main or testnet after selecting the target public profile.")
print(
    "contrib/devtools/zkcoin_public_launch_profile.py "
    f"--set-snapshot NETWORK {height} {expected_hash} {import_hash} "
    "--in-place contrib/devtools/zkcoin_public_launch_profile_manifest.json"
)
print()
print("Combine these with the AuxPoW launch profile and confirm")
print("getblockchaininfo.launch_readiness.ready is true before mining.")
print()
print("Audit summary:")
print(json.dumps(summary, indent=2, sort_keys=True))
PY
