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
    <expected-litecoin-block-hash> \
    /srv/snapshots/ltc-block-x.dat \
    /srv/litecoin/src/litecoin-cli -datadir=/srv/litecoin-data \
    -- \
    ./src/litecoin-cli -datadir=/srv/zkcoin-data

The Litecoin snapshot height must be a positive integer. The Litecoin node must
be exactly at <height>. If it is beyond <height>, this script refuses to rewind
it unless ZKCOIN_SNAPSHOT_ALLOW_REWIND=1 is set.
Only use rewind mode on a dedicated disposable snapshot node.

The script prints snapshot-related launch-node arguments, including
-ltcsnapshotfile=<path>, and the public launch-profile manifest update command
after the snapshot manifest is dumped and verified. Combine them with the
AuxPoW launch profile and confirm launch_readiness before mining the first
child block.

Set ZKCOIN_SNAPSHOT_AUDIT_JSON=<path> to write the verified audit summary that
zkcoin_public_launch_profile.py --set-snapshot-audit consumes for the public
launch-profile handoff.
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
NULL_UINT256="0000000000000000000000000000000000000000000000000000000000000000"
shift 3

if [[ ! "$HEIGHT" =~ ^[1-9][0-9]*$ ]]; then
  die "height must be a positive integer"
fi

if [[ ! "$EXPECTED_BLOCK_HASH" =~ ^[0-9a-f]{64}$ ]]; then
  die "expected block hash must be 64 hex characters"
fi
if [[ "$EXPECTED_BLOCK_HASH" == "$NULL_UINT256" ]]; then
  die "expected block hash must not be the null uint256"
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
SNAPSHOT_DIR="$(dirname "$SNAPSHOT_PATH")"
if [[ ! -d "$SNAPSHOT_DIR" ]]; then
  die "snapshot output directory does not exist: $SNAPSHOT_DIR"
fi

if [[ -n "${ZKCOIN_SNAPSHOT_AUDIT_JSON:-}" ]]; then
  AUDIT_JSON_PATH="$ZKCOIN_SNAPSHOT_AUDIT_JSON"
  case "$AUDIT_JSON_PATH" in
    /*) ;;
    *) AUDIT_JSON_PATH="$(pwd -P)/$AUDIT_JSON_PATH" ;;
  esac
  if [[ "$AUDIT_JSON_PATH" == "$SNAPSHOT_PATH" ]]; then
    die "snapshot audit summary path must differ from snapshot output path: $AUDIT_JSON_PATH"
  fi
  if [[ -e "$AUDIT_JSON_PATH" ]]; then
    die "snapshot audit summary already exists: $AUDIT_JSON_PATH"
  fi
  AUDIT_JSON_DIR="$(dirname "$AUDIT_JSON_PATH")"
  if [[ ! -d "$AUDIT_JSON_DIR" ]]; then
    die "snapshot audit summary directory does not exist: $AUDIT_JSON_DIR"
  fi
  export ZKCOIN_SNAPSHOT_AUDIT_JSON="$AUDIT_JSON_PATH"
fi

ltc_cli() {
  "${LTC_CLI[@]}" -rpcclienttimeout=9999999 "$@"
}

zk_cli() {
  "${ZK_CLI[@]}" -rpcclienttimeout=9999999 "$@"
}

snapshot_sha256() {
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum "$SNAPSHOT_PATH" | awk '{print $1}'
  elif command -v shasum >/dev/null 2>&1; then
    shasum -a 256 "$SNAPSHOT_PATH" | awk '{print $1}'
  else
    die "missing sha256sum or shasum for snapshot artifact fingerprinting"
  fi
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

SOURCE_CHAININFO_JSON="$(ltc_cli getblockchaininfo)"
read -r SOURCE_CHAIN SOURCE_TIP <<< "$(python3 - "$SOURCE_CHAININFO_JSON" <<'PY'
import json
import sys

raw = sys.argv[1]

def fail(message):
    print(f"error: {message}", file=sys.stderr)
    sys.exit(1)

try:
    chaininfo = json.loads(raw)
except json.JSONDecodeError as exc:
    fail(f"litecoin-cli getblockchaininfo did not return JSON: {exc}")

if not isinstance(chaininfo, dict):
    fail("litecoin-cli getblockchaininfo response must be a JSON object")

def require_bool(field):
    if field not in chaininfo or type(chaininfo[field]) is not bool:
        fail(f"litecoin-cli getblockchaininfo.{field} must be a boolean")
    return chaininfo[field]

def require_nonnegative_int(field):
    if field not in chaininfo or isinstance(chaininfo[field], bool):
        fail(f"litecoin-cli getblockchaininfo.{field} must be a non-negative integer")
    try:
        value = int(chaininfo[field])
    except (TypeError, ValueError):
        fail(f"litecoin-cli getblockchaininfo.{field} must be a non-negative integer")
    if value < 0:
        fail(f"litecoin-cli getblockchaininfo.{field} must be a non-negative integer")
    return value

def require_string(field):
    if field not in chaininfo or not isinstance(chaininfo[field], str) or not chaininfo[field]:
        fail(f"litecoin-cli getblockchaininfo.{field} must be a non-empty string")
    return chaininfo[field]

chain = require_string("chain")
if chain not in ("main", "test"):
    fail("Litecoin source node chain must be main or test for public snapshot generation")
blocks = require_nonnegative_int("blocks")
headers = require_nonnegative_int("headers")
if headers < blocks:
    fail("litecoin-cli getblockchaininfo.headers must be greater than or equal to blocks")
if headers > blocks:
    fail("Litecoin source node headers are ahead of downloaded blocks; wait for the source to finish syncing")
if require_bool("initialblockdownload"):
    fail("Litecoin source node is still in initial block download")
if require_bool("pruned"):
    fail("Litecoin source node must not be pruned for snapshot generation")

print(chain, blocks)
PY
)"

if (( SOURCE_TIP < HEIGHT )); then
  die "Litecoin source tip $SOURCE_TIP is below requested snapshot height $HEIGHT"
fi

if (( SOURCE_TIP > HEIGHT )); then
  if [[ "${ZKCOIN_SNAPSHOT_ALLOW_REWIND:-0}" != "1" ]]; then
    die "Litecoin source tip $SOURCE_TIP is beyond height $HEIGHT. Set ZKCOIN_SNAPSHOT_ALLOW_REWIND=1 only on a disposable snapshot node."
  fi

  RESTORE_CANDIDATE_HASH="$(ltc_cli getblockhash "$((HEIGHT + 1))")"
  RESTORE_CANDIDATE_HASH="$(printf '%s' "$RESTORE_CANDIDATE_HASH" | tr '[:upper:]' '[:lower:]')"
  if [[ ! "$RESTORE_CANDIDATE_HASH" =~ ^[0-9a-f]{64}$ ]]; then
    die "restore block hash at height $((HEIGHT + 1)) must be 64 hex characters"
  fi
  if [[ "$RESTORE_CANDIDATE_HASH" == "$NULL_UINT256" ]]; then
    die "restore block hash at height $((HEIGHT + 1)) must not be the null uint256"
  fi
  RESTORE_BLOCK_HASH="$RESTORE_CANDIDATE_HASH"
  echo "Rewinding Litecoin source to height $HEIGHT by invalidating $RESTORE_BLOCK_HASH" >&2
  ltc_cli invalidateblock "$RESTORE_BLOCK_HASH" >/dev/null

  POST_REWIND_TIP="$(ltc_cli getblockcount)"
  if [[ ! "$POST_REWIND_TIP" =~ ^[0-9]+$ ]]; then
    die "litecoin-cli getblockcount after rewind returned unexpected value: $POST_REWIND_TIP"
  fi
  if (( POST_REWIND_TIP != HEIGHT )); then
    die "Litecoin source tip after rewind is $POST_REWIND_TIP; expected $HEIGHT"
  fi
fi

ACTUAL_BLOCK_HASH="$(ltc_cli getblockhash "$HEIGHT")"
ACTUAL_BLOCK_HASH_LOWER="$(printf '%s' "$ACTUAL_BLOCK_HASH" | tr '[:upper:]' '[:lower:]')"
if [[ ! "$ACTUAL_BLOCK_HASH_LOWER" =~ ^[0-9a-f]{64}$ ]]; then
  die "snapshot block hash at height $HEIGHT must be 64 hex characters"
fi
if [[ "$ACTUAL_BLOCK_HASH_LOWER" == "$NULL_UINT256" ]]; then
  die "snapshot block hash at height $HEIGHT must not be the null uint256"
fi
if [[ "$ACTUAL_BLOCK_HASH_LOWER" != "$EXPECTED_BLOCK_HASH" ]]; then
  die "snapshot block hash mismatch at height $HEIGHT: expected=$EXPECTED_BLOCK_HASH actual=$ACTUAL_BLOCK_HASH_LOWER"
fi

echo "Dumping Litecoin UTXO snapshot at height $HEIGHT to $SNAPSHOT_PATH" >&2
DUMP_JSON="$(ltc_cli dumptxoutset "$SNAPSHOT_PATH")"
if [[ ! -f "$SNAPSHOT_PATH" ]]; then
  die "snapshot output was not created by dumptxoutset: $SNAPSHOT_PATH"
fi
if [[ ! -s "$SNAPSHOT_PATH" ]]; then
  die "snapshot output is empty after dumptxoutset: $SNAPSHOT_PATH"
fi
SNAPSHOT_FILE_SIZE="$(wc -c < "$SNAPSHOT_PATH" | tr -d '[:space:]')"
if [[ ! "$SNAPSHOT_FILE_SIZE" =~ ^[1-9][0-9]*$ ]]; then
  die "snapshot output size is not a positive byte count: $SNAPSHOT_FILE_SIZE"
fi
SNAPSHOT_FILE_SHA256="$(snapshot_sha256)"
if [[ ! "$SNAPSHOT_FILE_SHA256" =~ ^[0-9a-f]{64}$ ]]; then
  die "snapshot output SHA-256 fingerprint is malformed: $SNAPSHOT_FILE_SHA256"
fi

echo "Verifying normalized zkCoin import hash" >&2
VERIFY_JSON="$(zk_cli verifysnapshotmanifest "$SNAPSHOT_PATH")"
POST_VERIFY_SNAPSHOT_FILE_SIZE="$(wc -c < "$SNAPSHOT_PATH" | tr -d '[:space:]')"
if [[ "$POST_VERIFY_SNAPSHOT_FILE_SIZE" != "$SNAPSHOT_FILE_SIZE" ]]; then
  die "snapshot output changed during verification: size_before=$SNAPSHOT_FILE_SIZE size_after=$POST_VERIFY_SNAPSHOT_FILE_SIZE"
fi
POST_VERIFY_SNAPSHOT_FILE_SHA256="$(snapshot_sha256)"
if [[ "$POST_VERIFY_SNAPSHOT_FILE_SHA256" != "$SNAPSHOT_FILE_SHA256" ]]; then
  die "snapshot output changed during verification: sha256_before=$SNAPSHOT_FILE_SHA256 sha256_after=$POST_VERIFY_SNAPSHOT_FILE_SHA256"
fi

python3 - "$HEIGHT" "$EXPECTED_BLOCK_HASH" "$SNAPSHOT_PATH" "$SOURCE_CHAIN" "$SNAPSHOT_FILE_SIZE" "$SNAPSHOT_FILE_SHA256" "$DUMP_JSON" "$VERIFY_JSON" <<'PY'
import json
import os
import re
import sys

height = int(sys.argv[1])
expected_hash = sys.argv[2].lower()
snapshot_path = sys.argv[3]
source_chain = sys.argv[4]
snapshot_file_size = int(sys.argv[5])
snapshot_file_sha256 = sys.argv[6]
dump_json = sys.argv[7]
verify_json = sys.argv[8]
HEX64_RE = re.compile(r"^[0-9a-f]{64}$")
AMOUNT_RE = re.compile(r"^(0|[1-9][0-9]*)\.[0-9]{8}$")

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

def require_positive_int(obj, source, field):
    parsed = require_int(obj, source, field)
    if parsed <= 0:
        fail(f"{source}.{field} must be positive")
    return parsed

def require_hash(obj, source, field):
    value = require_field(obj, source, field)
    if not isinstance(value, str):
        fail(f"{source}.{field} must be a 64-character hex string")
    value = value.lower()
    if not HEX64_RE.fullmatch(value):
        fail(f"{source}.{field} must be a 64-character hex string")
    return value

def require_amount(obj, source, field):
    value = require_field(obj, source, field)
    if not isinstance(value, str) or not AMOUNT_RE.fullmatch(value) or value == "0.00000000":
        fail(f"{source}.{field} must be a positive decimal amount with 8 fractional digits")
    return value

dump = load_json("dumptxoutset", dump_json)
verify = load_json("verifysnapshotmanifest", verify_json)

dump_height = require_int(dump, "dumptxoutset", "base_height")
dump_hash = require_hash(dump, "dumptxoutset", "base_hash")
dump_coins = require_positive_int(dump, "dumptxoutset", "coins_written")
verify_height = require_int(verify, "verifysnapshotmanifest", "base_height")
verify_hash = require_hash(verify, "verifysnapshotmanifest", "base_hash")
verify_coins = require_positive_int(verify, "verifysnapshotmanifest", "coins")
verify_metadata_coins = require_positive_int(verify, "verifysnapshotmanifest", "metadata_coins")
verify_base_nchaintx = require_positive_int(verify, "verifysnapshotmanifest", "base_nchaintx")
snapshot_hash = require_hash(verify, "verifysnapshotmanifest", "snapshot_hash")
import_hash = require_hash(verify, "verifysnapshotmanifest", "import_hash")
total_amount = require_amount(verify, "verifysnapshotmanifest", "total_amount")

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
    "source_chain": source_chain,
    "snapshot_file_size": snapshot_file_size,
    "snapshot_file_sha256": snapshot_file_sha256,
    "block_hash": expected_hash,
    "coins": verify_coins,
    "base_nchaintx": verify_base_nchaintx,
    "snapshot_hash": snapshot_hash,
    "import_hash": import_hash,
    "snapshot_file": snapshot_path,
    "total_amount": total_amount,
}

audit_json_path = os.environ.get("ZKCOIN_SNAPSHOT_AUDIT_JSON")
if audit_json_path:
    if os.path.exists(audit_json_path):
        fail(f"snapshot audit summary already exists: {audit_json_path}")
    with open(audit_json_path, "x", encoding="utf8") as audit_file:
        json.dump(summary, audit_file, indent=2, sort_keys=True)
        audit_file.write("\n")
target_network = "main" if source_chain == "main" else "testnet"

print("Snapshot verified.")
if audit_json_path:
    print(f"Snapshot audit summary written: {audit_json_path}")
print()
print("Snapshot launch-node arguments:")
print(f"-ltcsnapshotheight={height}")
print(f"-ltcsnapshotblockhash={expected_hash}")
print(f"-ltcsnapshotutxoroot={import_hash}")
print(f"-ltcsnapshotfile={snapshot_path}")
print()
print("Snapshot public launch-profile manifest update:")
if audit_json_path:
    print("Apply the verified audit summary to the matching public profile.")
    print(
        "contrib/devtools/zkcoin_public_launch_profile.py "
        f"--set-snapshot-audit {target_network} {audit_json_path} "
        "--in-place contrib/devtools/zkcoin_public_launch_profile_manifest.json"
    )
else:
    print("Set ZKCOIN_SNAPSHOT_AUDIT_JSON=<path> and rerun before updating the public profile.")
    print(
        "contrib/devtools/zkcoin_public_launch_profile.py "
        f"--set-snapshot-audit {target_network} <snapshot_audit.json> "
        "--in-place contrib/devtools/zkcoin_public_launch_profile_manifest.json"
    )
print()
print("Combine these with the AuxPoW launch profile and confirm")
print("getblockchaininfo.launch_readiness.ready is true before mining.")
print()
print("Audit summary:")
print(json.dumps(summary, indent=2, sort_keys=True))
PY
