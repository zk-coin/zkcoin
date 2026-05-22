#!/usr/bin/env bash
#
# Copyright (c) 2026 The zkCoin developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
#
# Check that core user-facing identity stays on zkCoin while legacy binary and
# datadir names remain intentionally unchanged.

export LC_ALL=C

EXIT_CODE=0

check_contains() {
  local file="$1"
  local pattern="$2"
  local description="$3"

  if ! grep -Fq "$pattern" "$file"; then
    echo "${file}: missing ${description}: ${pattern}"
    EXIT_CODE=1
  fi
}

check_contains README.md "zkCoin Core integration/staging tree" "README product title"
check_contains configure.ac "AC_INIT([zkCoin Core]," "autotools package name"
check_contains configure.ac "[https://github.com/zk-coin/zkcoin/issues]" "bug-report URL"
check_contains configure.ac "[https://github.com/zk-coin/zkcoin])" "project URL"
check_contains configure.ac "[litecoin],[https://github.com/zk-coin/zkcoin])" "unchanged package tarname"
check_contains src/clientversion.cpp 'CLIENT_NAME("zkCoinCore")' "P2P user agent name"
check_contains src/init.cpp "https://github.com/zk-coin/zkcoin" "source-code URL"
check_contains doc/README.md "zkCoin Core" "docs product title"
check_contains doc/README_windows.txt "zkCoin Core" "Windows README product title"
check_contains contrib/debian/litecoin-qt.desktop "Name=zkCoin Core" "Debian desktop display name"
check_contains src/bitcoind-res.rc '"CompanyName",        "zkCoin"' "Windows daemon company name"
check_contains src/qt/res/bitcoin-qt-res.rc '"CompanyName",        "zkCoin"' "Windows GUI company name"
check_contains configure.ac "BITCOIN_DAEMON_NAME=litecoind" "unchanged daemon binary name"
check_contains configure.ac "BITCOIN_CLI_NAME=litecoin-cli" "unchanged CLI binary name"
check_contains configure.ac "BITCOIN_GUI_NAME=litecoin-qt" "unchanged GUI binary name"
check_contains src/util/system.cpp 'BITCOIN_CONF_FILENAME = "litecoin.conf"' "unchanged config filename"
check_contains src/util/system.cpp 'pathRet / ".litecoin"' "unchanged Unix datadir"

exit ${EXIT_CODE}
