#!/usr/bin/env bash
#
# Copyright (c) 2026 The zkCoin developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
#
# Check that literal Automake sources in the bundled secp256k1-zkp subtree exist.

export LC_ALL=C

EXIT_CODE=0
while IFS= read -r source_path; do
  if [ ! -e "src/secp256k1-zkp/${source_path}" ]; then
    echo "src/secp256k1-zkp: Automake source does not exist: ${source_path}"
    EXIT_CODE=1
  fi
done < <(
  awk -F= '
    /_SOURCES[[:space:]]*=/ {
      rhs = $2
      for (i = 3; i <= NF; ++i) {
        rhs = rhs "=" $i
      }
      gsub(/\\/, " ", rhs)
      count = split(rhs, sources, /[[:space:]]+/)
      for (i = 1; i <= count; ++i) {
        if (sources[i] ~ /^src\/.*\.(c|cc|cpp|h|hpp|s|S)$/) {
          print sources[i]
        }
      }
    }
  ' src/secp256k1-zkp/Makefile.am src/secp256k1-zkp/src/modules/*/Makefile.am.include | sort -u
)

exit ${EXIT_CODE}
