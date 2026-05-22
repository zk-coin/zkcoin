#!/usr/bin/env bash
#
# Copyright (c) 2026 The zkCoin developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
#
# Build a source tarball, unpack it into a temporary build root, and prove the
# unpacked release source can run the real Orchard AuxPoW regression.

export LC_ALL=C
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd -P)"
cd "$ROOT_DIR"

DIST_VERSION="${DIST_VERSION:-realproof}"
export TEST_RUNNER_PORT_MIN="${TEST_RUNNER_PORT_MIN:-28000}"

if [[ -z "${JOBS:-}" ]]; then
  if command -v sysctl >/dev/null 2>&1; then
    JOBS="$(sysctl -n hw.ncpu 2>/dev/null || true)"
  fi
  if [[ -z "${JOBS:-}" ]] && command -v nproc >/dev/null 2>&1; then
    JOBS="$(nproc 2>/dev/null || true)"
  fi
  JOBS="${JOBS:-4}"
fi

distdir="$(make -s print-distdir VERSION="$DIST_VERSION" | sed -n 's/^distdir = //p')"
if [[ -z "$distdir" ]]; then
  echo "error: could not determine distdir; run ./configure before this smoke" >&2
  exit 1
fi

tarball="${distdir}.tar.gz"
workdir="$(mktemp -d "${TMPDIR:-/tmp}/zkcoin-source-realproof.XXXXXX")"
cleanup() {
  rm -rf "$workdir"
  rm -rf "$distdir" "$tarball"
}
if [[ "${KEEP_SOURCE_DIST_REALPROOF:-0}" != "1" ]]; then
  trap cleanup EXIT
else
  echo "Keeping source-dist real-proof workdir: ${workdir}"
  trap 'rm -rf "$distdir" "$tarball"' EXIT
fi

echo "Building source tarball ${tarball}"
rm -rf "$distdir" "$tarball"
make dist-gzip VERSION="$DIST_VERSION"

if [[ ! -f "$tarball" ]]; then
  echo "error: expected source tarball ${tarball}" >&2
  exit 1
fi

tar -xzf "$tarball" -C "$workdir"
release_src="${workdir}/${distdir}"
if [[ ! -d "$release_src" ]]; then
  echo "error: expected unpacked source directory ${release_src}" >&2
  exit 1
fi

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

echo "Configuring unpacked source with the real Orchard Rust verifier backend"
(
  cd "$release_src"
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

  echo "Building unpacked source litecoind, litecoin-cli, and test_litecoin with ${JOBS} jobs"
  make -C src -j"$JOBS" litecoind litecoin-cli test/test_litecoin

  echo "Running real Orchard AuxPoW regression from unpacked source"
  ZKCOIN_REQUIRE_ORCHARD_VERIFIER=1 test/functional/feature_orchard_auxpow_realproof.py
)

echo "zkCoin source dist real-proof smoke passed for ${tarball}"
