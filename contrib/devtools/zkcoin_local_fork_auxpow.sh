#!/usr/bin/env bash
#
# Copyright (c) 2026 The zkCoin developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
#
# Build and run the local Litecoin-style fork launch + AuxPoW regression loop.

export LC_ALL=C
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd -P)"
cd "$ROOT_DIR"

if [[ -z "${JOBS:-}" ]]; then
  if command -v sysctl >/dev/null 2>&1; then
    JOBS="$(sysctl -n hw.ncpu 2>/dev/null || true)"
  fi
  if [[ -z "${JOBS:-}" ]] && command -v nproc >/dev/null 2>&1; then
    JOBS="$(nproc 2>/dev/null || true)"
  fi
  JOBS="${JOBS:-4}"
fi

echo "Building litecoind, litecoin-cli, and test_litecoin with ${JOBS} jobs"
make -C src -j"$JOBS" litecoind litecoin-cli test/test_litecoin

echo "Running AuxPoW unit tests"
(cd src && ./test/test_litecoin --run_test=auxpow_tests)

echo "Running AuxPoW RPC functional test"
test/functional/feature_auxpow_rpc.py

echo "Running snapshot launch functional test"
test/functional/feature_ltc_snapshot_launch.py

echo "Running local parent-fork AuxPoW functional test"
test/functional/feature_local_ltc_fork_auxpow.py

echo "Local fork AuxPoW loop passed"
