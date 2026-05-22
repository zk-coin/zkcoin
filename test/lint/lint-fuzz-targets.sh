#!/usr/bin/env bash
#
# Copyright (c) 2026 The zkCoin developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
#
# Check that FUZZ_TARGETS lists program targets, not source filenames.

export LC_ALL=C

EXIT_CODE=0
while IFS= read -r target; do
  case "$target" in
    *.*)
      echo "src/Makefile.test.include: FUZZ_TARGETS entry must not include a source extension: ${target}"
      EXIT_CODE=1
      ;;
  esac
done < <(
  awk '
    /^FUZZ_TARGETS = \\/ { in_targets = 1; next }
    in_targets && NF == 0 { exit }
    in_targets {
      target = $1
      sub(/\\$/, "", target)
      print target
    }
  ' src/Makefile.test.include
)

exit ${EXIT_CODE}
