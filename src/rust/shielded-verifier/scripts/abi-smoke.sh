#!/usr/bin/env bash
#
# Copyright (c) 2026 The zkCoin developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.

export LC_ALL=C
set -euo pipefail

CRATE_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"
cd "$CRATE_DIR"

cargo build --locked --lib

cc_bin="${CC:-cc}"
static_lib="target/debug/libzkc_shielded_verifier.a"
smoke_bin="target/debug/zkc_shielded_verifier_abi_smoke"

"$cc_bin" -std=c11 -Wall -Wextra -Werror -I include tests/abi_smoke.c "$static_lib" -o "$smoke_bin"
"$smoke_bin"
