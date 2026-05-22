#!/usr/bin/env bash
#
# Copyright (c) 2026 The zkCoin developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
#
# Run a fast local zkCoin launch-path smoke loop for iteration.
#
# This is not a replacement for zkcoin_launch_validation.sh. The canonical
# wrapper rebuilds with the real Orchard verifier backend and must pass before
# treating launch-path changes as release-candidate work.

export LC_ALL=C
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd -P)"
cd "$ROOT_DIR"

export TEST_RUNNER_PORT_MIN="${TEST_RUNNER_PORT_MIN:-24000}"

if [[ -z "${JOBS:-}" ]]; then
  if command -v sysctl >/dev/null 2>&1; then
    JOBS="$(sysctl -n hw.ncpu 2>/dev/null || true)"
  fi
  if [[ -z "${JOBS:-}" ]] && command -v nproc >/dev/null 2>&1; then
    JOBS="$(nproc 2>/dev/null || true)"
  fi
  JOBS="${JOBS:-4}"
fi

run_step() {
  echo
  echo "==> $*"
  "$@"
}

echo "Running zkCoin launch smoke with ${JOBS} jobs and functional test port minimum ${TEST_RUNNER_PORT_MIN}"

if [[ "${SKIP_BUILD:-0}" != "1" ]]; then
  run_step make -C src -j"$JOBS" litecoind litecoin-cli test/test_litecoin
fi

run_step test/lint/lint-zkcoin-launch-validation.sh
run_step test/lint/lint-zkcoin-public-launch-profile.sh
run_step test/lint/lint-zkcoin-product-identity.sh
run_step test/lint/lint-zkcoin-release-infrastructure.sh
run_step test/lint/lint-zkcoin-previous-releases.sh

run_step src/test/test_litecoin --run_test=pow_tests
run_step src/test/test_litecoin --run_test=auxpow_tests
run_step src/test/test_litecoin --run_test=utxo_snapshot_tests

run_step test/functional/feature_config_args.py
run_step test/functional/feature_ltc_snapshot_script.py
run_step test/functional/feature_launch_preflight_script.py
run_step test/functional/feature_shielded_pool.py
run_step test/functional/rpc_blockchain.py
run_step test/functional/feature_auxpow_rpc.py
run_step test/functional/feature_ltc_snapshot_launch.py

if [[ "${RUN_DISTDIR:-1}" != "0" ]]; then
  run_step contrib/devtools/zkcoin_source_dist_smoke.sh
fi

echo
echo "zkCoin launch smoke passed"
