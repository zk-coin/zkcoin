#!/usr/bin/env bash
#
# Copyright (c) 2026 The zkCoin developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
#
# Check that CI keeps the zkCoin launch validation lane on the canonical path.

export LC_ALL=C

test/lint/lint-zkcoin-launch-validation.py
