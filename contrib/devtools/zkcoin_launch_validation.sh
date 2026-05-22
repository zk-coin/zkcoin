#!/usr/bin/env bash
#
# Copyright (c) 2026 The zkCoin developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
#
# Run the canonical zkCoin launch-profile validation loop.

export LC_ALL=C
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd -P)"

echo "Running zkCoin launch validation with launch argument/preflight guards, real Orchard verifier, and AuxPoW regressions"
exec "$ROOT_DIR/contrib/devtools/zkcoin_orchard_auxpow.sh"
