#!/usr/bin/env bash
#
# Copyright (c) 2026 The zkCoin developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
#
# Check that previous-release validation stays explicit about artifact sources.

export LC_ALL=C

test/lint/lint-zkcoin-previous-releases.py
