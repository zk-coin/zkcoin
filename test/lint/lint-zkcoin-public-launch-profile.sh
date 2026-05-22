#!/usr/bin/env bash
#
# Copyright (c) 2026 The zkCoin developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
#
# Check that public zkCoin launch parameters stay fail-closed until final
# production constants are hardcoded.

export LC_ALL=C

test/lint/lint-zkcoin-public-launch-profile.py
