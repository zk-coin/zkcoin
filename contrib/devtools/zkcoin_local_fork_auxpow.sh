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

export TEST_RUNNER_PORT_MIN="${TEST_RUNNER_PORT_MIN:-20000}"

if [[ -z "${JOBS:-}" ]]; then
  if command -v sysctl >/dev/null 2>&1; then
    JOBS="$(sysctl -n hw.ncpu 2>/dev/null || true)"
  fi
  if [[ -z "${JOBS:-}" ]] && command -v nproc >/dev/null 2>&1; then
    JOBS="$(nproc 2>/dev/null || true)"
  fi
  JOBS="${JOBS:-4}"
fi

echo "Using functional test port minimum ${TEST_RUNNER_PORT_MIN}"

echo "Building litecoind, litecoin-cli, and test_litecoin with ${JOBS} jobs"
make -C src -j"$JOBS" litecoind litecoin-cli test/test_litecoin

echo "Running Rust shielded verifier tests"
(cd src/rust/shielded-verifier && cargo test --locked && cargo test --locked --features verifier-fixture && scripts/abi-smoke.sh && scripts/unsupported-consensus-smoke.sh && scripts/fixture-consensus-smoke.sh && scripts/orchard-consensus-smoke.sh)

echo "Running AuxPoW unit tests"
(cd src && ./test/test_litecoin --run_test=auxpow_tests)

echo "Running UTXO snapshot unit tests"
(cd src && ./test/test_litecoin --run_test=utxo_snapshot_tests)

echo "Running shielded pool unit tests"
(cd src && ./test/test_litecoin --run_test=shielded_tests)

echo "Running AuxPoW RPC functional test"
test/functional/feature_auxpow_rpc.py

echo "Running shielded pool scaffold functional test"
test/functional/feature_shielded_pool.py

echo "Running snapshot launch functional test"
test/functional/feature_ltc_snapshot_launch.py

echo "Running local parent-fork AuxPoW functional test"
test/functional/feature_local_ltc_fork_auxpow.py

echo "Local fork AuxPoW and shielded regression loop passed"
