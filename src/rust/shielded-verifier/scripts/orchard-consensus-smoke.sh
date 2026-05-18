#!/usr/bin/env bash
#
# Copyright (c) 2026 The zkCoin developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.

export LC_ALL=C
set -euo pipefail

CRATE_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"
SRC_DIR="$(cd "$CRATE_DIR/../.." && pwd -P)"
cd "$CRATE_DIR"

required_libs=(
    "$SRC_DIR/libbitcoin_common.a"
    "$SRC_DIR/libbitcoin_util.a"
    "$SRC_DIR/libbitcoin_consensus.a"
    "$SRC_DIR/crypto/libbitcoin_crypto_base.a"
    "$SRC_DIR/libmw.a"
    "$SRC_DIR/univalue/.libs/libunivalue.a"
    "$SRC_DIR/secp256k1-zkp/.libs/libsecp256k1.a"
)
for lib in "${required_libs[@]}"; do
    if [[ ! -f "$lib" ]]; then
        echo "Missing $lib; build the node/test libraries first with: make -C \"$SRC_DIR\" litecoind litecoin-cli test/test_litecoin" >&2
        exit 1
    fi
done

if [[ ! -f tests/vectors/orchard_mint_vector.txt ]]; then
    mkdir -p tests/vectors
    cargo run --locked --features orchard-verifier --example orchard_mint_vector > tests/vectors/orchard_mint_vector.txt
fi

cargo build --locked --lib --features orchard-verifier

cxx_bin="${CXX:-c++}"
static_lib="target/debug/libzkc_shielded_verifier.a"
smoke_bin="target/debug/zkc_shielded_verifier_orchard_consensus_smoke"

boost_cppflags=()
boost_cppflags_line="$(awk -F' = ' '/^BOOST_CPPFLAGS = / { print $2; exit }' "$SRC_DIR/Makefile")"
if [[ -n "$boost_cppflags_line" ]]; then
    boost_cppflags=($boost_cppflags_line)
fi

cppflags=()
cppflags_line="$(awk -F' = ' '/^CPPFLAGS = / { print $2; exit }' "$SRC_DIR/Makefile")"
if [[ -n "$cppflags_line" ]]; then
    cppflags=($cppflags_line)
fi

boost_libs=()
boost_libs_line="$(awk -F' = ' '/^BOOST_LIBS = / { print $2; exit }' "$SRC_DIR/Makefile")"
if [[ -n "$boost_libs_line" ]]; then
    boost_libs=($boost_libs_line)
fi

crypto_libs=()
crypto_libs_line="$(awk -F' = ' '/^CRYPTO_LIBS = / { print $2; exit }' "$SRC_DIR/Makefile")"
if [[ -n "$crypto_libs_line" ]]; then
    crypto_libs=($crypto_libs_line)
fi

fmt_libs=()
if command -v pkg-config >/dev/null 2>&1 && pkg-config --exists fmt; then
    fmt_libs=($(pkg-config --libs fmt))
else
    for fmt_lib_dir in /opt/homebrew/opt/fmt/lib /usr/local/opt/fmt/lib; do
        if [[ -d "$fmt_lib_dir" ]]; then
            fmt_libs+=("-L$fmt_lib_dir")
        fi
    done
    fmt_libs+=("-lfmt")
fi

"$cxx_bin" -std=c++17 -Wall -Wextra -Werror -Wno-unused-parameter -Wno-deprecated-declarations \
    -DZKC_SHIELDED_VERIFIER_EXTERNAL -DHAVE_CONFIG_H \
    -I "$SRC_DIR/config" -I "$SRC_DIR" -I "$SRC_DIR/libmw/include" -I "$SRC_DIR/libmw/deps/crypto/include" \
    "${boost_cppflags[@]}" "${cppflags[@]}" \
    tests/cxx_orchard_consensus_smoke.cpp \
    "$SRC_DIR/consensus/shielded_verifier.cpp" \
    "$SRC_DIR/crypto/sha256.cpp" \
    "$static_lib" \
    "${required_libs[@]}" \
    "${boost_libs[@]}" "${crypto_libs[@]}" "${fmt_libs[@]}" \
    -o "$smoke_bin"
"$smoke_bin"
