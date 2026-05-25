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
-ltcsnapshotfile=<path>, and the public launch-profile manifest handoff
commands after the snapshot manifest is dumped and verified. Combine them with
the AuxPoW launch profile and confirm launch_readiness before mining the first
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

reject_control_path() {
  python3 - "$1" "$2" <<'PY'
import sys

path = sys.argv[1]
label = sys.argv[2]
if any(ord(char) < 0x20 or ord(char) == 0x7f for char in path):
    print(f"error: {label} path must not contain control characters: {path!r}", file=sys.stderr)
    sys.exit(1)
PY
}

if (( $# < 6 )); then
  usage
  exit 1
fi

HEIGHT="$1"
EXPECTED_BLOCK_HASH="$2"
SNAPSHOT_PATH="$3"
NULL_UINT256="0000000000000000000000000000000000000000000000000000000000000000"
shift 3

if [[ ! "$HEIGHT" =~ ^[1-9][0-9]*$ ]]; then
  die "height must be a positive integer"
fi

if [[ ! "$EXPECTED_BLOCK_HASH" =~ ^[0-9a-f]{64}$ ]]; then
  die "expected block hash must be a lowercase 64-character hex string"
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

reject_control_path "$SNAPSHOT_PATH" "snapshot output"
if [[ -L "$SNAPSHOT_PATH" ]]; then
  die "snapshot output path must not be a symlink: $SNAPSHOT_PATH"
fi
if [[ -e "$SNAPSHOT_PATH" ]]; then
  die "snapshot output already exists: $SNAPSHOT_PATH"
fi
SNAPSHOT_INCOMPLETE_PATH="${SNAPSHOT_PATH}.incomplete"
if [[ -L "$SNAPSHOT_INCOMPLETE_PATH" ]]; then
  die "snapshot incomplete output path must not be a symlink: $SNAPSHOT_INCOMPLETE_PATH"
fi
if [[ -e "$SNAPSHOT_INCOMPLETE_PATH" ]]; then
  die "snapshot incomplete output already exists: $SNAPSHOT_INCOMPLETE_PATH"
fi
direct_directory_fingerprint() {
  python3 - "$1" "$2" <<'PY'
import os
import stat
import sys

label = sys.argv[1]
path = sys.argv[2]
try:
    directory_stat = os.lstat(path)
except FileNotFoundError:
    print(f"error: {label} directory does not exist: {path}", file=sys.stderr)
    sys.exit(1)
except OSError as exc:
    print(f"error: cannot stat {label} directory: {exc}", file=sys.stderr)
    sys.exit(1)

if stat.S_ISLNK(directory_stat.st_mode):
    print(f"error: {label} directory must not be a symlink: {path}", file=sys.stderr)
    sys.exit(1)
if not stat.S_ISDIR(directory_stat.st_mode):
    print(f"error: {label} directory does not exist: {path}", file=sys.stderr)
    sys.exit(1)

print(f"{directory_stat.st_dev}:{directory_stat.st_ino}:{directory_stat.st_mode}")
PY
}

SNAPSHOT_DIR="$(dirname "$SNAPSHOT_PATH")"

snapshot_output_directory_fingerprint() {
  direct_directory_fingerprint "snapshot output" "$SNAPSHOT_DIR"
}

require_snapshot_output_directory_direct() {
  local current_fingerprint
  current_fingerprint="$(snapshot_output_directory_fingerprint)"
  if [[ -n "${SNAPSHOT_DIR_FINGERPRINT:-}" && "$current_fingerprint" != "$SNAPSHOT_DIR_FINGERPRINT" ]]; then
    die "snapshot output directory changed during snapshot generation: $SNAPSHOT_DIR"
  fi
}

SNAPSHOT_DIR_FINGERPRINT="$(snapshot_output_directory_fingerprint)"
require_snapshot_output_directory_direct
if [[ ! -w "$SNAPSHOT_DIR" ]]; then
  die "snapshot output directory is not writable: $SNAPSHOT_DIR"
fi
SNAPSHOT_DIR_PHYSICAL="$(cd "$SNAPSHOT_DIR" && pwd -P)" || die "cannot resolve snapshot output directory: $SNAPSHOT_DIR"
SNAPSHOT_CANONICAL_PATH="$SNAPSHOT_DIR_PHYSICAL/$(basename "$SNAPSHOT_PATH")"
SNAPSHOT_INCOMPLETE_CANONICAL_PATH="$SNAPSHOT_DIR_PHYSICAL/$(basename "$SNAPSHOT_INCOMPLETE_PATH")"

if [[ -n "${ZKCOIN_SNAPSHOT_AUDIT_JSON:-}" ]]; then
  AUDIT_JSON_PATH="$ZKCOIN_SNAPSHOT_AUDIT_JSON"
  case "$AUDIT_JSON_PATH" in
    /*) ;;
    *) AUDIT_JSON_PATH="$(pwd -P)/$AUDIT_JSON_PATH" ;;
  esac
  reject_control_path "$AUDIT_JSON_PATH" "snapshot audit summary"
  if [[ "$AUDIT_JSON_PATH" == "$SNAPSHOT_PATH" ]]; then
    die "snapshot audit summary path must differ from snapshot output path: $AUDIT_JSON_PATH"
  fi
  if [[ "$AUDIT_JSON_PATH" == "$SNAPSHOT_INCOMPLETE_PATH" ]]; then
    die "snapshot audit summary path must differ from snapshot incomplete output path: $AUDIT_JSON_PATH"
  fi
  if [[ -L "$AUDIT_JSON_PATH" ]]; then
    die "snapshot audit summary path must not be a symlink: $AUDIT_JSON_PATH"
  fi
  if [[ -e "$AUDIT_JSON_PATH" ]]; then
    die "snapshot audit summary already exists: $AUDIT_JSON_PATH"
  fi
  AUDIT_JSON_DIR="$(dirname "$AUDIT_JSON_PATH")"
  if [[ ! -d "$AUDIT_JSON_DIR" ]]; then
    die "snapshot audit summary directory does not exist: $AUDIT_JSON_DIR"
  fi
  if [[ ! -w "$AUDIT_JSON_DIR" ]]; then
    die "snapshot audit summary directory is not writable: $AUDIT_JSON_DIR"
  fi
  AUDIT_JSON_DIR_PHYSICAL="$(cd "$AUDIT_JSON_DIR" && pwd -P)" || die "cannot resolve snapshot audit summary directory: $AUDIT_JSON_DIR"
  AUDIT_CANONICAL_PATH="$AUDIT_JSON_DIR_PHYSICAL/$(basename "$AUDIT_JSON_PATH")"
  if [[ "$AUDIT_CANONICAL_PATH" == "$SNAPSHOT_CANONICAL_PATH" ]]; then
    die "snapshot audit summary path must differ from snapshot output path: $AUDIT_JSON_PATH"
  fi
  if [[ "$AUDIT_CANONICAL_PATH" == "$SNAPSHOT_INCOMPLETE_CANONICAL_PATH" ]]; then
    die "snapshot audit summary path must differ from snapshot incomplete output path: $AUDIT_JSON_PATH"
  fi

  audit_output_directory_fingerprint() {
    direct_directory_fingerprint "snapshot audit summary" "$AUDIT_JSON_DIR"
  }

  AUDIT_JSON_DIR_FINGERPRINT="$(audit_output_directory_fingerprint)"
  export ZKCOIN_SNAPSHOT_AUDIT_DIR_FINGERPRINT="$AUDIT_JSON_DIR_FINGERPRINT"
  export ZKCOIN_SNAPSHOT_AUDIT_JSON="$AUDIT_JSON_PATH"
fi

ltc_cli() {
  "${LTC_CLI[@]}" -rpcclienttimeout=9999999 "$@"
}

zk_cli() {
  "${ZK_CLI[@]}" -rpcclienttimeout=9999999 "$@"
}

snapshot_file_metadata() {
  python3 - "$SNAPSHOT_PATH" <<'PY'
import errno
import hashlib
import os
import stat
import sys

path = sys.argv[1]

def fail(message):
    print(f"error: {message}", file=sys.stderr)
    sys.exit(1)

def file_fingerprint(file_stat):
    return (
        file_stat.st_dev,
        file_stat.st_ino,
        file_stat.st_mode,
        file_stat.st_size,
        file_stat.st_mtime_ns,
        file_stat.st_ctime_ns,
    )

flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
try:
    fd = os.open(path, flags)
except OSError as exc:
    if exc.errno == errno.ELOOP:
        fail(f"snapshot output must not be a symlink after dumptxoutset: {path}")
    if exc.errno in (errno.ENOENT, errno.ENOTDIR):
        fail(f"snapshot output was not created by dumptxoutset: {path}")
    fail(f"cannot open snapshot output for fingerprinting: {exc}")

try:
    initial_stat = os.fstat(fd)
    if not stat.S_ISREG(initial_stat.st_mode):
        fail(f"snapshot output was not created by dumptxoutset: {path}")
    if initial_stat.st_size <= 0:
        fail(f"snapshot output is empty after dumptxoutset: {path}")

    digest = hashlib.sha256()
    while True:
        chunk = os.read(fd, 1024 * 1024)
        if not chunk:
            break
        digest.update(chunk)

    final_fd_stat = os.fstat(fd)
    final_path_stat = os.stat(path, follow_symlinks=False)
except OSError as exc:
    fail(f"cannot read snapshot output for fingerprinting: {exc}")
finally:
    os.close(fd)

if (
    not stat.S_ISREG(final_path_stat.st_mode)
    or file_fingerprint(final_fd_stat) != file_fingerprint(initial_stat)
    or file_fingerprint(final_path_stat) != file_fingerprint(initial_stat)
):
    fail(f"snapshot output changed during fingerprinting: {path}")

print(f"{initial_stat.st_size} {digest.hexdigest()}")
PY
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
read -r SOURCE_CHAIN SOURCE_TIP <<< "$(python3 - "$SOURCE_CHAININFO_JSON" "$HEIGHT" "$EXPECTED_BLOCK_HASH" <<'PY'
import json
import math
import re
import sys

raw = sys.argv[1]
expected_height = int(sys.argv[2])
expected_hash = sys.argv[3]
HEX64_RE = re.compile(r"^[0-9a-f]{64}$")
INT_RE = re.compile(r"^[0-9]+$")
NULL_UINT256 = "0" * 64

class DuplicateJSONFieldError(ValueError):
    pass

def reject_duplicate_json_fields(pairs):
    result = {}
    for field, value in pairs:
        if field in result:
            raise DuplicateJSONFieldError(field)
        result[field] = value
    return result

def fail(message):
    print(f"error: {message}", file=sys.stderr)
    sys.exit(1)

try:
    chaininfo = json.loads(raw, object_pairs_hook=reject_duplicate_json_fields)
except DuplicateJSONFieldError as exc:
    fail(f"litecoin-cli getblockchaininfo contains duplicate field: {exc}")
except json.JSONDecodeError as exc:
    fail(f"litecoin-cli getblockchaininfo did not return JSON: {exc}")

if not isinstance(chaininfo, dict):
    fail("litecoin-cli getblockchaininfo response must be a JSON object")

def require_bool(field):
    if field not in chaininfo or type(chaininfo[field]) is not bool:
        fail(f"litecoin-cli getblockchaininfo.{field} must be a boolean")
    return chaininfo[field]

def require_nonnegative_int(field):
    if field not in chaininfo:
        fail(f"litecoin-cli getblockchaininfo.{field} must be a non-negative integer")
    value = chaininfo[field]
    if isinstance(value, bool):
        fail(f"litecoin-cli getblockchaininfo.{field} must be a non-negative integer")
    if isinstance(value, int):
        parsed = value
    elif isinstance(value, str) and INT_RE.fullmatch(value):
        parsed = int(value)
    else:
        fail(f"litecoin-cli getblockchaininfo.{field} must be a non-negative integer")
    if parsed < 0:
        fail(f"litecoin-cli getblockchaininfo.{field} must be a non-negative integer")
    return parsed

def require_positive_int(field):
    if field not in chaininfo:
        fail(f"litecoin-cli getblockchaininfo.{field} must be a positive integer")
    value = chaininfo[field]
    if isinstance(value, bool):
        fail(f"litecoin-cli getblockchaininfo.{field} must be a positive integer")
    if isinstance(value, int):
        parsed = value
    elif isinstance(value, str) and INT_RE.fullmatch(value):
        parsed = int(value)
    else:
        fail(f"litecoin-cli getblockchaininfo.{field} must be a positive integer")
    if parsed <= 0:
        fail(f"litecoin-cli getblockchaininfo.{field} must be a positive integer")
    return parsed

def require_string(field):
    if field not in chaininfo or not isinstance(chaininfo[field], str) or not chaininfo[field]:
        fail(f"litecoin-cli getblockchaininfo.{field} must be a non-empty string")
    return chaininfo[field]

def require_bestblockhash():
    value = require_string("bestblockhash")
    if not HEX64_RE.fullmatch(value) or value == NULL_UINT256:
        fail("litecoin-cli getblockchaininfo.bestblockhash must be a non-null lowercase 64-character hex string")
    return value

def require_chainwork():
    value = require_string("chainwork")
    if not HEX64_RE.fullmatch(value) or value == NULL_UINT256:
        fail("litecoin-cli getblockchaininfo.chainwork must be a non-null lowercase 64-character hex string")
    return value

def require_verificationprogress():
    if "verificationprogress" not in chaininfo:
        fail("litecoin-cli getblockchaininfo.verificationprogress must be a non-negative number not exceeding 1")
    value = chaininfo["verificationprogress"]
    if isinstance(value, bool) or not isinstance(value, (int, float)) or not math.isfinite(value) or value < 0 or value > 1:
        fail("litecoin-cli getblockchaininfo.verificationprogress must be a non-negative number not exceeding 1")
    return value

def require_difficulty():
    if "difficulty" not in chaininfo:
        fail("litecoin-cli getblockchaininfo.difficulty must be a non-negative number")
    value = chaininfo["difficulty"]
    if isinstance(value, bool) or not isinstance(value, (int, float)) or not math.isfinite(value) or value < 0:
        fail("litecoin-cli getblockchaininfo.difficulty must be a non-negative number")
    return value

chain = require_string("chain")
if chain not in ("main", "test"):
    fail("Litecoin source node chain must be main or test for public snapshot generation")
blocks = require_nonnegative_int("blocks")
headers = require_nonnegative_int("headers")
bestblockhash = require_bestblockhash()
require_chainwork()
require_verificationprogress()
require_difficulty()
require_positive_int("size_on_disk")
source_time = require_nonnegative_int("time")
source_mediantime = require_nonnegative_int("mediantime")
if source_mediantime > source_time:
    fail("litecoin-cli getblockchaininfo.mediantime must be less than or equal to time")
if headers < blocks:
    fail("litecoin-cli getblockchaininfo.headers must be greater than or equal to blocks")
if headers > blocks:
    fail("Litecoin source node headers are ahead of downloaded blocks; wait for the source to finish syncing")
if blocks == expected_height and bestblockhash != expected_hash:
    fail("litecoin-cli getblockchaininfo.bestblockhash must match expected block hash when source tip is at snapshot height")
if require_bool("initialblockdownload"):
    fail("Litecoin source node is still in initial block download")
if require_bool("pruned"):
    fail("Litecoin source node must not be pruned for snapshot generation")
if "warnings" not in chaininfo or not isinstance(chaininfo["warnings"], str):
    fail("litecoin-cli getblockchaininfo.warnings must be a string")
if chaininfo["warnings"]:
    fail(f"Litecoin source node reports warnings; resolve them before snapshot generation: {chaininfo['warnings']}")

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
  if [[ ! "$RESTORE_CANDIDATE_HASH" =~ ^[0-9a-f]{64}$ ]]; then
    die "restore block hash at height $((HEIGHT + 1)) must be a lowercase 64-character hex string"
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
if [[ ! "$ACTUAL_BLOCK_HASH" =~ ^[0-9a-f]{64}$ ]]; then
  die "snapshot block hash at height $HEIGHT must be a lowercase 64-character hex string"
fi
if [[ "$ACTUAL_BLOCK_HASH" == "$NULL_UINT256" ]]; then
  die "snapshot block hash at height $HEIGHT must not be the null uint256"
fi
if [[ "$ACTUAL_BLOCK_HASH" != "$EXPECTED_BLOCK_HASH" ]]; then
  die "snapshot block hash mismatch at height $HEIGHT: expected=$EXPECTED_BLOCK_HASH actual=$ACTUAL_BLOCK_HASH"
fi

echo "Dumping Litecoin UTXO snapshot at height $HEIGHT to $SNAPSHOT_PATH" >&2
DUMP_JSON="$(ltc_cli dumptxoutset "$SNAPSHOT_PATH")"
require_snapshot_output_directory_direct
if [[ -L "$SNAPSHOT_INCOMPLETE_PATH" ]] || [[ -e "$SNAPSHOT_INCOMPLETE_PATH" ]]; then
  die "snapshot incomplete output remained after dumptxoutset: $SNAPSHOT_INCOMPLETE_PATH"
fi
if [[ -L "$SNAPSHOT_PATH" ]]; then
  die "snapshot output must not be a symlink after dumptxoutset: $SNAPSHOT_PATH"
fi
read -r SNAPSHOT_FILE_SIZE SNAPSHOT_FILE_SHA256 <<< "$(snapshot_file_metadata)"
if [[ ! "$SNAPSHOT_FILE_SIZE" =~ ^[1-9][0-9]*$ ]]; then
  die "snapshot output size is not a positive byte count: $SNAPSHOT_FILE_SIZE"
fi
if [[ ! "$SNAPSHOT_FILE_SHA256" =~ ^[0-9a-f]{64}$ ]]; then
  die "snapshot output SHA-256 fingerprint is malformed: $SNAPSHOT_FILE_SHA256"
fi

python3 - "$HEIGHT" "$EXPECTED_BLOCK_HASH" "$SNAPSHOT_PATH" "$DUMP_JSON" <<'PY'
import json
import re
import sys

height = int(sys.argv[1])
expected_hash = sys.argv[2].lower()
snapshot_path = sys.argv[3]
dump_json = sys.argv[4]
HEX64_RE = re.compile(r"^[0-9a-f]{64}$")
INT_RE = re.compile(r"^[0-9]+$")
NULL_UINT256 = "0" * 64

class DuplicateJSONFieldError(ValueError):
    pass

def reject_duplicate_json_fields(pairs):
    result = {}
    for field, value in pairs:
        if field in result:
            raise DuplicateJSONFieldError(field)
        result[field] = value
    return result

def fail(message):
    print(f"error: {message}", file=sys.stderr)
    sys.exit(1)

def load_json(source, raw):
    try:
        value = json.loads(raw, object_pairs_hook=reject_duplicate_json_fields)
    except DuplicateJSONFieldError as exc:
        fail(f"{source} contains duplicate field: {exc}")
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
    if isinstance(value, int):
        parsed = value
    elif isinstance(value, str) and INT_RE.fullmatch(value):
        parsed = int(value)
    else:
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
        fail(f"{source}.{field} must be a lowercase 64-character hex string")
    if not HEX64_RE.fullmatch(value):
        fail(f"{source}.{field} must be a lowercase 64-character hex string")
    if value == NULL_UINT256:
        fail(f"{source}.{field} must not be the null uint256")
    return value

def require_path(obj, source, field):
    value = require_field(obj, source, field)
    if not isinstance(value, str) or not value:
        fail(f"{source}.{field} must be a non-empty string")
    return value

dump = load_json("dumptxoutset", dump_json)
dump_height = require_int(dump, "dumptxoutset", "base_height")
dump_hash = require_hash(dump, "dumptxoutset", "base_hash")
dump_path = require_path(dump, "dumptxoutset", "path")
require_positive_int(dump, "dumptxoutset", "coins_written")

if dump_height != height:
    fail(f"dumptxoutset base_height mismatch: expected={height} actual={dump_height}")

if dump_hash != expected_hash:
    fail(f"dumptxoutset base_hash mismatch: expected={expected_hash} actual={dump_hash}")

if dump_path != snapshot_path:
    fail(f"dumptxoutset.path must match requested snapshot output path: expected={snapshot_path} actual={dump_path}")
PY

echo "Verifying normalized zkCoin import hash" >&2
VERIFY_JSON="$(zk_cli verifysnapshotmanifest "$SNAPSHOT_PATH")"
require_snapshot_output_directory_direct
if [[ -L "$SNAPSHOT_PATH" ]]; then
  die "snapshot output became a symlink during verification: $SNAPSHOT_PATH"
fi
read -r POST_VERIFY_SNAPSHOT_FILE_SIZE POST_VERIFY_SNAPSHOT_FILE_SHA256 <<< "$(snapshot_file_metadata)"
if [[ "$POST_VERIFY_SNAPSHOT_FILE_SIZE" != "$SNAPSHOT_FILE_SIZE" ]]; then
  die "snapshot output changed during verification: size_before=$SNAPSHOT_FILE_SIZE size_after=$POST_VERIFY_SNAPSHOT_FILE_SIZE"
fi
if [[ "$POST_VERIFY_SNAPSHOT_FILE_SHA256" != "$SNAPSHOT_FILE_SHA256" ]]; then
  die "snapshot output changed during verification: sha256_before=$SNAPSHOT_FILE_SHA256 sha256_after=$POST_VERIFY_SNAPSHOT_FILE_SHA256"
fi

python3 - "$HEIGHT" "$EXPECTED_BLOCK_HASH" "$SNAPSHOT_PATH" "$SOURCE_CHAIN" "$SNAPSHOT_FILE_SIZE" "$SNAPSHOT_FILE_SHA256" "$DUMP_JSON" "$VERIFY_JSON" <<'PY'
import errno
import json
import os
import re
import shlex
import stat
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
INT_RE = re.compile(r"^[0-9]+$")
AMOUNT_RE = re.compile(r"^(0|[1-9][0-9]*)\.[0-9]{8}$")
COIN = 100000000
MAX_MONEY = 84000000 * COIN
MAX_MONEY_TEXT = "84000000.00000000"
NULL_UINT256 = "0" * 64
AUDIT_SUMMARY_FIELDS = (
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
)

class DuplicateJSONFieldError(ValueError):
    pass

def reject_duplicate_json_fields(pairs):
    result = {}
    for field, value in pairs:
        if field in result:
            raise DuplicateJSONFieldError(field)
        result[field] = value
    return result

def fail(message):
    print(f"error: {message}", file=sys.stderr)
    sys.exit(1)

def load_json(source, raw):
    try:
        value = json.loads(raw, object_pairs_hook=reject_duplicate_json_fields)
    except DuplicateJSONFieldError as exc:
        fail(f"{source} contains duplicate field: {exc}")
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
    if isinstance(value, int):
        parsed = value
    elif isinstance(value, str) and INT_RE.fullmatch(value):
        parsed = int(value)
    else:
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
        fail(f"{source}.{field} must be a lowercase 64-character hex string")
    if not HEX64_RE.fullmatch(value):
        fail(f"{source}.{field} must be a lowercase 64-character hex string")
    if value == NULL_UINT256:
        fail(f"{source}.{field} must not be the null uint256")
    return value

def require_path(obj, source, field):
    value = require_field(obj, source, field)
    if not isinstance(value, str) or not value:
        fail(f"{source}.{field} must be a non-empty string")
    return value

def require_amount(obj, source, field):
    value = require_field(obj, source, field)
    if not isinstance(value, str) or not AMOUNT_RE.fullmatch(value) or value == "0.00000000":
        fail(f"{source}.{field} must be a positive decimal amount with 8 fractional digits")
    whole, fractional = value.split(".")
    atoms = int(whole) * COIN + int(fractional)
    if atoms > MAX_MONEY:
        fail(f"{source}.{field} must not exceed {MAX_MONEY_TEXT}")
    return value

dump = load_json("dumptxoutset", dump_json)
verify = load_json("verifysnapshotmanifest", verify_json)

dump_height = require_int(dump, "dumptxoutset", "base_height")
dump_hash = require_hash(dump, "dumptxoutset", "base_hash")
dump_path = require_path(dump, "dumptxoutset", "path")
dump_coins = require_positive_int(dump, "dumptxoutset", "coins_written")
verify_height = require_int(verify, "verifysnapshotmanifest", "base_height")
verify_hash = require_hash(verify, "verifysnapshotmanifest", "base_hash")
verify_coins = require_positive_int(verify, "verifysnapshotmanifest", "coins")
verify_metadata_coins = require_positive_int(verify, "verifysnapshotmanifest", "metadata_coins")
verify_base_nchaintx = require_positive_int(verify, "verifysnapshotmanifest", "base_nchaintx")
snapshot_hash = require_hash(verify, "verifysnapshotmanifest", "snapshot_hash")
import_hash = require_hash(verify, "verifysnapshotmanifest", "import_hash")
total_amount = require_amount(verify, "verifysnapshotmanifest", "total_amount")

def shell_quote(value):
    return shlex.quote(value)

def open_direct_audit_parent_directory(path):
    parent = os.path.dirname(path) or "."
    flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        parent_fd = os.open(parent, flags)
    except OSError as exc:
        if exc.errno == errno.ENOENT:
            fail(f"snapshot audit summary directory does not exist: {parent}")
        if exc.errno == errno.ELOOP or (exc.errno == errno.ENOTDIR and os.path.islink(parent)):
            fail(f"snapshot audit summary directory must not be a symlink: {parent}")
        if exc.errno == errno.ENOTDIR:
            fail(f"snapshot audit summary directory does not exist: {parent}")
        fail(f"cannot open snapshot audit summary directory securely: {exc}")
    if not stat.S_ISDIR(os.fstat(parent_fd).st_mode):
        os.close(parent_fd)
        fail(f"snapshot audit summary directory does not exist: {parent}")
    return parent, parent_fd

def fsync_parent_directory(parent_fd):
    os.fsync(parent_fd)

def audit_parent_fingerprint(parent_fd):
    parent_stat = os.fstat(parent_fd)
    return f"{parent_stat.st_dev}:{parent_stat.st_ino}:{parent_stat.st_mode}"

def write_audit_summary(audit_json_path, summary):
    if os.path.islink(audit_json_path):
        fail(f"snapshot audit summary path must not be a symlink: {audit_json_path}")
    if os.path.lexists(audit_json_path):
        fail(f"snapshot audit summary already exists: {audit_json_path}")

    audit_text = json.dumps(summary, indent=2, sort_keys=False) + "\n"
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
    audit_basename = os.path.basename(audit_json_path)
    parent_fd = None
    fd = None
    created = False
    try:
        parent, parent_fd = open_direct_audit_parent_directory(audit_json_path)
        expected_parent_fingerprint = os.environ.get("ZKCOIN_SNAPSHOT_AUDIT_DIR_FINGERPRINT")
        if (
            expected_parent_fingerprint
            and audit_parent_fingerprint(parent_fd) != expected_parent_fingerprint
        ):
            fail(f"snapshot audit summary directory changed during snapshot verification: {parent}")
        fd = os.open(audit_basename, flags, 0o644, dir_fd=parent_fd)
        created = True
        audit_file = os.fdopen(fd, "w", encoding="utf8")
        fd = None
        with audit_file:
            audit_file.write(audit_text)
            audit_file.flush()
            os.fsync(audit_file.fileno())
        fsync_parent_directory(parent_fd)
    except FileExistsError:
        fail(f"snapshot audit summary already exists: {audit_json_path}")
    except OSError as exc:
        if fd is not None:
            os.close(fd)
        if created:
            try:
                os.unlink(audit_basename, dir_fd=parent_fd)
            except OSError:
                pass
        if exc.errno == errno.ELOOP:
            fail(f"snapshot audit summary path must not be a symlink: {audit_json_path}")
        fail(f"cannot write snapshot audit summary durably: {exc}")
    finally:
        if parent_fd is not None:
            os.close(parent_fd)

if dump_height != height:
    fail(f"dumptxoutset base_height mismatch: expected={height} actual={dump_height}")

if dump_hash != expected_hash:
    fail(f"dumptxoutset base_hash mismatch: expected={expected_hash} actual={dump_hash}")

if dump_path != snapshot_path:
    fail(f"dumptxoutset.path must match requested snapshot output path: expected={snapshot_path} actual={dump_path}")

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
    "import_hash": import_hash,
    "snapshot_hash": snapshot_hash,
    "coins": verify_coins,
    "base_nchaintx": verify_base_nchaintx,
    "source_chain": source_chain,
    "snapshot_file_size": snapshot_file_size,
    "snapshot_file_sha256": snapshot_file_sha256,
    "snapshot_file": snapshot_path,
    "total_amount": total_amount,
}
if tuple(summary) != AUDIT_SUMMARY_FIELDS:
    fail("snapshot audit summary field order does not match public launch template")

audit_json_path = os.environ.get("ZKCOIN_SNAPSHOT_AUDIT_JSON")
if audit_json_path:
    write_audit_summary(audit_json_path, summary)
target_network = "main" if source_chain == "main" else "testnet"

print("Snapshot verified.")
if audit_json_path:
    print(f"Snapshot audit summary written: {audit_json_path}")
print()
print("Snapshot launch-node arguments:")
print(f"-ltcsnapshotheight={height}")
print(f"-ltcsnapshotblockhash={expected_hash}")
print(f"-ltcsnapshotutxoroot={import_hash}")
print(f"-ltcsnapshotfile={shell_quote(snapshot_path)}")
print()
print("Snapshot public launch-profile manifest handoff:")
print(
    "contrib/devtools/zkcoin_public_launch_profile.py "
    f"--snapshot-audit-template {target_network} "
    "contrib/devtools/zkcoin_public_launch_profile_manifest.json"
)
if audit_json_path:
    print("Verify the audit summary, then apply it to the matching public profile.")
    print(
        "contrib/devtools/zkcoin_public_launch_profile.py "
        f"--check-snapshot-audit {target_network} {shell_quote(audit_json_path)} "
        "contrib/devtools/zkcoin_public_launch_profile_manifest.json"
    )
    print(
        "contrib/devtools/zkcoin_public_launch_profile.py "
        f"--set-snapshot-audit {target_network} {shell_quote(audit_json_path)} "
        "--in-place contrib/devtools/zkcoin_public_launch_profile_manifest.json"
    )
else:
    print("Set ZKCOIN_SNAPSHOT_AUDIT_JSON=<path> and rerun before updating the public profile.")
    print(
        "contrib/devtools/zkcoin_public_launch_profile.py "
        f"--check-snapshot-audit {target_network} <snapshot_audit.json> "
        "contrib/devtools/zkcoin_public_launch_profile_manifest.json"
    )
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
print(json.dumps(summary, indent=2, sort_keys=False))
PY
