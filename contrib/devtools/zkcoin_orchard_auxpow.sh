#!/usr/bin/env bash
#
# Copyright (c) 2026 The zkCoin developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
#
# Build and run the Orchard verifier + local Litecoin-style AuxPoW regression.

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

boost_args=()
if [[ -n "${BOOST_PREFIX:-}" ]]; then
  boost_args=("--with-boost=$BOOST_PREFIX")
  if [[ -d "$BOOST_PREFIX/lib" ]]; then
    boost_args+=("--with-boost-libdir=$BOOST_PREFIX/lib")
  fi
else
  for prefix in /opt/homebrew/opt/boost@1.85 /opt/homebrew/opt/boost /usr/local/opt/boost@1.85 /usr/local/opt/boost; do
    if [[ -d "$prefix/include/boost" ]]; then
      boost_args=("--with-boost=$prefix")
      if [[ -d "$prefix/lib" ]]; then
        boost_args+=("--with-boost-libdir=$prefix/lib")
      fi
      break
    fi
  done
fi

cppflags="${CPPFLAGS:-}"
ldflags="${LDFLAGS:-}"
for prefix in \
  /opt/homebrew/opt/fmt \
  /usr/local/opt/fmt \
  /opt/homebrew/opt/libevent \
  /usr/local/opt/libevent \
  /opt/homebrew/opt/openssl@3 \
  /usr/local/opt/openssl@3 \
  /opt/homebrew/opt/berkeley-db@4 \
  /usr/local/opt/berkeley-db@4 \
  /opt/homebrew/opt/berkeley-db4 \
  /usr/local/opt/berkeley-db4; do
  if [[ -d "$prefix/include" && " $cppflags " != *" -I$prefix/include "* ]]; then
    cppflags="${cppflags:+$cppflags }-I$prefix/include"
  fi
  if [[ -d "$prefix/lib" && " $ldflags " != *" -L$prefix/lib "* ]]; then
    ldflags="${ldflags:+$ldflags }-L$prefix/lib"
  fi
done

echo "Running public launch profile and seed quarantine lint"
test/lint/lint-zkcoin-public-launch-profile.sh

echo "Configuring with the real Orchard Rust verifier backend"
./configure \
  --without-gui \
  --disable-wallet \
  --disable-zmq \
  --disable-bench \
  --disable-fuzz-binary \
  --without-miniupnpc \
  --without-natpmp \
  "${boost_args[@]}" \
  --enable-rust-shielded-verifier \
  --enable-rust-orchard-verifier \
  CPPFLAGS="$cppflags" \
  LDFLAGS="$ldflags"

echo "Cleaning C++ objects so verifier-linkage flags are rebuilt"
make -C src clean

echo "Building Orchard-enabled litecoind, litecoin-cli, and shielded unit tests with ${JOBS} jobs"
make -C src -j"$JOBS" litecoind litecoin-cli test/test_litecoin

echo "Running public launch profile unit tests"
src/test/test_litecoin --run_test=pow_tests

echo "Running shielded unit tests"
src/test/test_litecoin --run_test=shielded_tests

echo "Running AuxPoW unit tests"
src/test/test_litecoin --run_test=auxpow_tests

echo "Running UTXO snapshot unit tests"
src/test/test_litecoin --run_test=utxo_snapshot_tests

echo "Running Rust shielded verifier unit and ABI smoke tests"
(
  cd src/rust/shielded-verifier
  cargo test --locked
  cargo test --locked --features verifier-fixture
  cargo test --locked --features orchard-verifier
  scripts/abi-smoke.sh
  scripts/unsupported-consensus-smoke.sh
  scripts/fixture-consensus-smoke.sh
  scripts/orchard-consensus-smoke.sh
)

echo "Running launch consensus-parameter override guard test"
test/functional/feature_config_args.py

echo "Running explicit unsupported signet startup test"
test/functional/feature_signet.py

echo "Running Litecoin snapshot operator script test"
test/functional/feature_ltc_snapshot_script.py

echo "Running launch preflight fail-closed script test"
test/functional/feature_launch_preflight_script.py

echo "Running shielded pool scaffold functional test"
test/functional/feature_shielded_pool.py

echo "Running AuxPoW RPC functional test"
test/functional/feature_auxpow_rpc.py

echo "Running blockchain RPC launch-readiness schema test"
test/functional/rpc_blockchain.py

echo "Running local Litecoin fork AuxPoW baseline functional test"
test/functional/feature_local_ltc_fork_auxpow.py

echo "Running Litecoin snapshot launch functional test"
test/functional/feature_ltc_snapshot_launch.py

echo "Running Orchard AuxPoW real-proof functional test with skip treated as failure"
ZKCOIN_REQUIRE_ORCHARD_VERIFIER=1 test/functional/feature_orchard_auxpow_realproof.py

echo "Orchard verifier AuxPoW regression loop passed"
