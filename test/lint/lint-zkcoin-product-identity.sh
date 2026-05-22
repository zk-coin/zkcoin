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
check_contains doc/man/litecoind.1 "Start zkCoin Core" "daemon manpage product action"
check_contains doc/man/litecoin-cli.1 "Send command to zkCoin Core" "CLI manpage product action"
check_contains build_msvc/bitcoin_config.h '#define CLIENT_VERSION_BUILD 5' "MSVC version build"
check_contains build_msvc/bitcoin_config.h '#define COPYRIGHT_HOLDERS_FINAL "The zkCoin developers"' "MSVC copyright holder"
check_contains build_msvc/bitcoin_config.h '#define COPYRIGHT_HOLDERS_SUBSTITUTION "zkCoin"' "MSVC copyright substitution"
check_contains build_msvc/bitcoin_config.h '#define PACKAGE_BUGREPORT "https://github.com/zk-coin/zkcoin/issues"' "MSVC bug-report URL"
check_contains build_msvc/bitcoin_config.h '#define PACKAGE_NAME "zkCoin Core"' "MSVC package name"
check_contains build_msvc/bitcoin_config.h '#define PACKAGE_STRING "zkCoin Core 0.21.5.5"' "MSVC package string"
check_contains build_msvc/bitcoin_config.h '#define PACKAGE_TARNAME "litecoin"' "unchanged MSVC package tarname"
check_contains build_msvc/bitcoin_config.h '#define PACKAGE_URL "https://github.com/zk-coin/zkcoin"' "MSVC package URL"
check_contains build_msvc/bitcoin_config.h '#define PACKAGE_VERSION "0.21.5.5"' "MSVC package version"
check_contains build_msvc/README.md "Building zkCoin Core with Visual Studio" "MSVC README title"
check_contains build_msvc/bitcoind/bitcoind.vcxproj 'Replace="@PACKAGE_NAME@" By="zkCoin Core"' "MSVC test package name"
check_contains contrib/devtools/gen-manpages.sh 'for suffix in "${BTCVER[@]:1}"' "manpage version suffix cleanup"
check_contains configure.ac "BITCOIN_DAEMON_NAME=litecoind" "unchanged daemon binary name"
check_contains configure.ac "BITCOIN_CLI_NAME=litecoin-cli" "unchanged CLI binary name"
check_contains configure.ac "BITCOIN_GUI_NAME=litecoin-qt" "unchanged GUI binary name"
check_contains src/util/system.cpp 'BITCOIN_CONF_FILENAME = "litecoin.conf"' "unchanged config filename"
check_contains src/util/system.cpp 'pathRet / ".litecoin"' "unchanged Unix datadir"

if grep -R -Fq "Litecoin Core" doc/man; then
  echo "doc/man: stale Litecoin Core identity remains"
  grep -R -Fn "Litecoin Core" doc/man
  EXIT_CODE=1
fi

if grep -R -Fq "https://litecoin.org/" doc/man; then
  echo "doc/man: stale litecoin.org URL remains"
  grep -R -Fn "https://litecoin.org/" doc/man
  EXIT_CODE=1
fi

if grep -R -Fq "https://github.com/litecoin-project/litecoin" doc/man; then
  echo "doc/man: stale upstream source URL remains"
  grep -R -Fn "https://github.com/litecoin-project/litecoin" doc/man
  EXIT_CODE=1
fi

if grep -R -Fq "dirty" doc/man; then
  echo "doc/man: dirty generated version suffix remains"
  grep -R -Fn "dirty" doc/man
  EXIT_CODE=1
fi

exit ${EXIT_CODE}
