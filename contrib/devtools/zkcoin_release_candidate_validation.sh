#!/usr/bin/env bash
#
# Copyright (c) 2026 The zkCoin developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
#
# Run the full zkCoin release-candidate validation gate.

export LC_ALL=C
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd -P)"

echo "Running canonical zkCoin launch validation"
"$ROOT_DIR/contrib/devtools/zkcoin_launch_validation.sh"

echo "Running source distribution real-proof release-candidate validation"
"$ROOT_DIR/contrib/devtools/zkcoin_source_dist_realproof_smoke.sh"

echo "zkCoin release-candidate validation gate passed"
