#!/usr/bin/env bash
#
# Copyright (c) 2026 The zkCoin developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
#
# Build a source tarball and verify that zkCoin release-critical verifier
# sources are present without Cargo build outputs.

export LC_ALL=C
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd -P)"
cd "$ROOT_DIR"

DIST_VERSION="${DIST_VERSION:-brandcheck}"
distdir="$(make -s print-distdir VERSION="$DIST_VERSION" | sed -n 's/^distdir = //p')"
if [[ -z "$distdir" ]]; then
  echo "error: could not determine distdir; run ./configure before this smoke" >&2
  exit 1
fi

tarball="${distdir}.tar.gz"
entries_file="$(mktemp "${TMPDIR:-/tmp}/zkcoin-source-dist.XXXXXX")"
trap 'rm -f "$entries_file"; rm -rf "$distdir" "$tarball"' EXIT

echo "Building source tarball ${tarball}"
rm -rf "$distdir" "$tarball"
make dist-gzip VERSION="$DIST_VERSION"

if [[ ! -f "$tarball" ]]; then
  echo "error: expected source tarball ${tarball}" >&2
  exit 1
fi

tar -tf "$tarball" > "$entries_file"

required_entries=(
  "${distdir}/contrib/devtools/zkcoin_source_dist_smoke.sh"
  "${distdir}/src/rust/shielded-verifier/Cargo.lock"
  "${distdir}/src/rust/shielded-verifier/Cargo.toml"
  "${distdir}/src/rust/shielded-verifier/README.md"
  "${distdir}/src/rust/shielded-verifier/examples/orchard_mint_vector.rs"
  "${distdir}/src/rust/shielded-verifier/examples/orchard_spend_vector.rs"
  "${distdir}/src/rust/shielded-verifier/include/zkc_shielded_verifier.h"
  "${distdir}/src/rust/shielded-verifier/scripts/abi-smoke.sh"
  "${distdir}/src/rust/shielded-verifier/scripts/fixture-consensus-smoke.sh"
  "${distdir}/src/rust/shielded-verifier/scripts/orchard-consensus-smoke.sh"
  "${distdir}/src/rust/shielded-verifier/scripts/unsupported-consensus-smoke.sh"
  "${distdir}/src/rust/shielded-verifier/src/lib.rs"
  "${distdir}/src/rust/shielded-verifier/tests/abi_smoke.c"
  "${distdir}/src/rust/shielded-verifier/tests/cxx_abi_smoke.cpp"
  "${distdir}/src/rust/shielded-verifier/tests/cxx_fixture_consensus_smoke.cpp"
  "${distdir}/src/rust/shielded-verifier/tests/cxx_orchard_consensus_smoke.cpp"
  "${distdir}/src/rust/shielded-verifier/tests/cxx_unsupported_consensus_smoke.cpp"
  "${distdir}/src/rust/shielded-verifier/tests/vectors/orchard_mint_vector.txt"
  "${distdir}/src/rust/shielded-verifier/tests/vectors/orchard_spend_vector.txt"
)

for entry in "${required_entries[@]}"; do
  if ! grep -Fqx "$entry" "$entries_file"; then
    echo "error: source tarball missing ${entry}" >&2
    exit 1
  fi
done

if grep -Fq "${distdir}/src/rust/shielded-verifier/target/" "$entries_file"; then
  echo "error: source tarball contains Cargo target build outputs" >&2
  exit 1
fi

echo "zkCoin source dist smoke passed for ${tarball}"
