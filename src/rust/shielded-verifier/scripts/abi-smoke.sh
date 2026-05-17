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

cargo build --locked --lib

cc_bin="${CC:-cc}"
static_lib="target/debug/libzkc_shielded_verifier.a"
smoke_bin="target/debug/zkc_shielded_verifier_abi_smoke"

"$cc_bin" -std=c11 -Wall -Wextra -Werror -I include tests/abi_smoke.c "$static_lib" -o "$smoke_bin"
"$smoke_bin"

cxx_bin="${CXX:-c++}"
cxx_smoke_bin="target/debug/zkc_shielded_verifier_cxx_abi_smoke"
boost_cppflags=()
if [[ -f "$SRC_DIR/Makefile" ]]; then
    boost_cppflags_line="$(awk -F' = ' '/^BOOST_CPPFLAGS = / { print $2; exit }' "$SRC_DIR/Makefile")"
    if [[ -n "$boost_cppflags_line" ]]; then
        boost_cppflags=($boost_cppflags_line)
    fi
fi

"$cxx_bin" -std=c++17 -Wall -Wextra -Werror -Wno-unused-parameter -DZKC_SHIELDED_VERIFIER_EXTERNAL \
    -DHAVE_CONFIG_H -I "$SRC_DIR/config" -I "$SRC_DIR" "${boost_cppflags[@]}" \
    tests/cxx_abi_smoke.cpp \
    "$SRC_DIR/consensus/shielded_verifier.cpp" \
    "$SRC_DIR/crypto/sha256.cpp" \
    "$static_lib" \
    -o "$cxx_smoke_bin"
"$cxx_smoke_bin"
