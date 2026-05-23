#!/usr/bin/env bash
# Copyright (c) 2026 The zkCoin developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.

export LC_ALL=C
set -euo pipefail

usage() {
  echo "usage: $0 TOOLCHAIN_FILE EXPECTED_RUST_TARGETS" >&2
}

if [ "$#" -ne 2 ]; then
  usage
  exit 1
fi

toolchain_file="$1"
expected_rust_targets="$2"

if [ ! -f "$toolchain_file" ]; then
  echo "missing zkCoin Gitian Rust toolchain provenance file: $toolchain_file" >&2
  exit 1
fi

load_required_field() {
  local field_name="$1"
  local field_lines
  local field_count

  field_lines="$(awk -F= -v key="$field_name" '$1 == key { print }' "$toolchain_file")"
  if [ -z "$field_lines" ]; then
    echo "missing required Gitian Rust toolchain provenance field: $field_name" >&2
    exit 1
  fi

  field_count="$(printf '%s\n' "$field_lines" | wc -l | awk '{ print $1 }')"
  if [ "$field_count" -ne 1 ]; then
    echo "multiple values for Gitian Rust toolchain provenance field: $field_name" >&2
    exit 1
  fi

  printf '%s\n' "$field_lines" | cut -d= -f2-
}

reject_placeholder_field() {
  local field_name="$1"
  local field_value="$2"

  case "$field_value" in
    ''|TODO|TBD|todo|tbd|*'<'*|*'>'*)
      echo "ZKCOIN_GITIAN_RUST toolchain provenance fields must not be placeholders: $field_name" >&2
      exit 1
      ;;
  esac

  case "$field_value" in
    ' '*|*' ')
      echo "ZKCOIN_GITIAN_RUST toolchain provenance fields must not have leading or trailing spaces: $field_name" >&2
      exit 1
      ;;
  esac
}

validate_commit_hash_field() {
  local field_name="$1"
  local field_value="$2"

  case "$field_value" in
    *[!0123456789abcdef]*)
      echo "ZKCOIN_GITIAN_RUST commit-hash fields must be lowercase hexadecimal: $field_name" >&2
      exit 1
      ;;
  esac

  if [ "${#field_value}" -ne 40 ]; then
    echo "ZKCOIN_GITIAN_RUST commit-hash fields must be full 40-character hashes: $field_name" >&2
    exit 1
  fi
}

rustc_version="$(load_required_field ZKCOIN_GITIAN_RUSTC_VERSION)"
rustc_commit_hash="$(load_required_field ZKCOIN_GITIAN_RUSTC_COMMIT_HASH)"
cargo_version="$(load_required_field ZKCOIN_GITIAN_CARGO_VERSION)"
cargo_commit_hash="$(load_required_field ZKCOIN_GITIAN_CARGO_COMMIT_HASH)"
rust_targets="$(load_required_field ZKCOIN_GITIAN_RUST_TARGETS)"

for field_name in \
  ZKCOIN_GITIAN_RUSTC_VERSION \
  ZKCOIN_GITIAN_RUSTC_COMMIT_HASH \
  ZKCOIN_GITIAN_CARGO_VERSION \
  ZKCOIN_GITIAN_CARGO_COMMIT_HASH \
  ZKCOIN_GITIAN_RUST_TARGETS; do
  reject_placeholder_field "$field_name" "$(load_required_field "$field_name")"
done

validate_commit_hash_field ZKCOIN_GITIAN_RUSTC_COMMIT_HASH "$rustc_commit_hash"
validate_commit_hash_field ZKCOIN_GITIAN_CARGO_COMMIT_HASH "$cargo_commit_hash"

if [ "$(rustc --version | awk '{ print $2 }')" != "$rustc_version" ]; then
  echo "rustc version does not match ZKCOIN_GITIAN_RUSTC_VERSION" >&2
  exit 1
fi

actual_rustc_commit_hash="$(rustc -vV | awk -F': ' '$1 == "commit-hash" { print $2 }')"
if [ "$actual_rustc_commit_hash" != "$rustc_commit_hash" ]; then
  echo "rustc commit hash does not match ZKCOIN_GITIAN_RUSTC_COMMIT_HASH" >&2
  exit 1
fi

if [ "$(cargo --version | awk '{ print $2 }')" != "$cargo_version" ]; then
  echo "cargo version does not match ZKCOIN_GITIAN_CARGO_VERSION" >&2
  exit 1
fi

actual_cargo_commit_hash="$(cargo -vV | awk -F': ' '$1 == "commit-hash" { print $2 }')"
if [ "$actual_cargo_commit_hash" != "$cargo_commit_hash" ]; then
  echo "cargo commit hash does not match ZKCOIN_GITIAN_CARGO_COMMIT_HASH" >&2
  exit 1
fi

if [ "$rust_targets" != "$expected_rust_targets" ]; then
  echo "ZKCOIN_GITIAN_RUST_TARGETS does not match descriptor Rust targets" >&2
  exit 1
fi

for rust_target in $expected_rust_targets; do
  if ! rustc --print target-list | grep -x "$rust_target" >/dev/null; then
    echo "rustc target-list does not include Gitian Rust target: $rust_target" >&2
    exit 1
  fi

  rust_target_libdir="$(rustc --print target-libdir --target="$rust_target" 2>/dev/null || true)"
  if [ -z "$rust_target_libdir" ] || [ ! -d "$rust_target_libdir" ]; then
    echo "rust std library is not installed for Gitian Rust target: $rust_target" >&2
    exit 1
  fi
done
