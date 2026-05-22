#!/usr/bin/env bash
#
# Copyright (c) 2026 The zkCoin developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
#
# Check that inherited release infrastructure stays explicit and fail-closed.

export LC_ALL=C

test/lint/lint-zkcoin-release-infrastructure.py
