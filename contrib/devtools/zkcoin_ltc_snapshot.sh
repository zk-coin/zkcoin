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
  if [[ -n "$RESTORE_BLOCK_HASH" ]]; then
    echo "Restoring Litecoin source chain by reconsidering $RESTORE_BLOCK_HASH" >&2
    ltc_cli reconsiderblock "$RESTORE_BLOCK_HASH" >/dev/null || true
  fi
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

python3 - "$HEIGHT" "$EXPECTED_BLOCK_HASH" "$DUMP_JSON" "$VERIFY_JSON" <<'PY'
import json
import sys

height = int(sys.argv[1])
expected_hash = sys.argv[2].lower()
dump = json.loads(sys.argv[3])
verify = json.loads(sys.argv[4])

def fail(message):
    print(f"error: {message}", file=sys.stderr)
    sys.exit(1)

if int(dump["base_height"]) != height:
    fail(f"dumptxoutset base_height mismatch: expected={height} actual={dump['base_height']}")

if dump["base_hash"].lower() != expected_hash:
    fail(f"dumptxoutset base_hash mismatch: expected={expected_hash} actual={dump['base_hash'].lower()}")

if verify["base_hash"].lower() != expected_hash:
    fail(f"verifysnapshotmanifest base_hash mismatch: expected={expected_hash} actual={verify['base_hash'].lower()}")

if int(verify["base_height"]) != height:
    fail(f"verifysnapshotmanifest base_height mismatch: expected={height} actual={verify['base_height']}")

if int(verify["coins"]) != int(dump["coins_written"]):
    fail(f"coin count mismatch: dumptxoutset={dump['coins_written']} verified={verify['coins']}")

if int(verify["metadata_coins"]) != int(dump["coins_written"]):
    fail(f"metadata coin count mismatch: dumptxoutset={dump['coins_written']} metadata={verify['metadata_coins']}")

summary = {
    "height": height,
    "block_hash": expected_hash,
    "coins": int(verify["coins"]),
    "base_nchaintx": int(verify["base_nchaintx"]),
    "snapshot_hash": verify["snapshot_hash"],
    "import_hash": verify["import_hash"],
    "total_amount": verify["total_amount"],
}

print("Snapshot verified.")
print()
print("Launch node arguments:")
print(f"-ltcsnapshotheight={height}")
print(f"-ltcsnapshotblockhash={expected_hash}")
print(f"-ltcsnapshotutxoroot={verify['import_hash']}")
print()
print("Audit summary:")
print(json.dumps(summary, indent=2, sort_keys=True))
PY
