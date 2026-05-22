Contents
========
This directory contains tools for developers working on this repository.

zkcoin_launch_validation.sh
===========================

Runs the canonical zkCoin launch-profile validation loop. The wrapper delegates
to `zkcoin_orchard_auxpow.sh`, which configures the real Orchard verifier
backend, rebuilds the node, and runs AuxPoW, snapshot, shielded, Orchard-feature
Rust, launch argument guards, snapshot operator-script guards, launch preflight
guards, and real-proof functional regressions together.

The launch preflight guard also checks the shielded proof posture reported by
`getblockchaininfo`: scaffold proofs must be disabled, the real proof backend
must be `orchard-v1`, and real proof verification must be available.

The real-proof functional regression is run with
`ZKCOIN_REQUIRE_ORCHARD_VERIFIER=1`, so a missing Orchard verifier backend is a
validation failure instead of a skipped test.

CI runs the same wrapper in the dedicated `zkCoin canonical launch validation
[real Orchard AuxPoW]` Cirrus task. This lane calls the wrapper directly instead
of going through `test_runner.py`, because skipped functional tests are reported
as successful by the generic runner.

Example:

```bash
JOBS="$(sysctl -n hw.ncpu 2>/dev/null || nproc 2>/dev/null || echo 4)" \
  contrib/devtools/zkcoin_launch_validation.sh
```

zkcoin_launch_smoke.sh
======================

Runs a faster local launch-path smoke loop for day-to-day iteration. It builds
the current local configuration, runs the zkCoin launch/profile lints, key C++
unit suites, launch argument and preflight guards, the snapshot operator-script
guard, shielded pool scaffold regressions, blockchain readiness RPC schema
checks, AuxPoW RPC regressions, snapshot launch regressions, and source
distribution packaging.

This wrapper is intentionally lower impact than `zkcoin_launch_validation.sh`:
it does not reconfigure the tree, does not run `make clean`, and does not
require the real Orchard verifier backend. Use it to catch common launch-path
regressions quickly, then run the canonical validation wrapper before treating
AuxPoW, snapshot import, shielded validation, or launch configuration changes as
release-candidate work.

Set `SKIP_BUILD=1` to reuse already-built binaries, and `RUN_DISTDIR=0` to skip
the source-distribution packaging check while iterating.

The expected canonical and smoke-lane checks are tracked in
`zkcoin_launch_validation_manifest.json`; `test/lint/lint-zkcoin-launch-validation.py`
fails if either wrapper stops executing a manifest entry.

Example:

```bash
JOBS="$(sysctl -n hw.ncpu 2>/dev/null || nproc 2>/dev/null || echo 4)" \
  contrib/devtools/zkcoin_launch_smoke.sh
```

zkcoin_release_infrastructure_manifest.json
===========================================

Tracks the inherited Gitian, signing, packaging, and binary-verification
surfaces that are not production-ready for zkCoin releases yet. The
`test/lint/lint-zkcoin-release-infrastructure.py` guard keeps those surfaces
explicit, checks that release docs remain blocked, and fails closed until
zkCoin release keys, signing repositories, artifact hosts, and namespace
decisions are configured.

clang-format-diff.py
===================

A script to format unified git diffs according to [.clang-format](../../src/.clang-format).

Requires `clang-format`, installed e.g. via `brew install clang-format` on macOS.

For instance, to format the last commit with 0 lines of context,
the script should be called from the git root folder as follows.

```
git diff -U0 HEAD~1.. | ./contrib/devtools/clang-format-diff.py -p1 -i -v
```

copyright\_header.py
====================

Provides utilities for managing copyright headers of `The Bitcoin Core
developers` in repository source files. It has three subcommands:

```
$ ./copyright_header.py report <base_directory> [verbose]
$ ./copyright_header.py update <base_directory>
$ ./copyright_header.py insert <file>
```
Running these subcommands without arguments displays a usage string.

copyright\_header.py report \<base\_directory\> [verbose]
---------------------------------------------------------

Produces a report of all copyright header notices found inside the source files
of a repository. Useful to quickly visualize the state of the headers.
Specifying `verbose` will list the full filenames of files of each category.

copyright\_header.py update \<base\_directory\> [verbose]
---------------------------------------------------------
Updates all the copyright headers of `The Bitcoin Core developers` which were
changed in a year more recent than is listed. For example:
```
// Copyright (c) <firstYear>-<lastYear> The Bitcoin Core developers
```
will be updated to:
```
// Copyright (c) <firstYear>-<lastModifiedYear> The Bitcoin Core developers
```
where `<lastModifiedYear>` is obtained from the `git log` history.

This subcommand also handles copyright headers that have only a single year. In
those cases:
```
// Copyright (c) <year> The Bitcoin Core developers
```
will be updated to:
```
// Copyright (c) <year>-<lastModifiedYear> The Bitcoin Core developers
```
where the update is appropriate.

copyright\_header.py insert \<file\>
------------------------------------
Inserts a copyright header for `The Bitcoin Core developers` at the top of the
file in either Python or C++ style as determined by the file extension. If the
file is a Python file and it has  `#!` starting the first line, the header is
inserted in the line below it.

The copyright dates will be set to be `<year_introduced>-<current_year>` where
`<year_introduced>` is according to the `git log` history. If
`<year_introduced>` is equal to `<current_year>`, it will be set as a single
year rather than two hyphenated years.

If the file already has a copyright for `The Bitcoin Core developers`, the
script will exit.

gen-manpages.sh
===============

A small script to automatically create manpages in ../../doc/man by running the release binaries with the -help option.
This requires help2man which can be found at: https://www.gnu.org/software/help2man/

With in-tree builds this tool can be run from any directory within the
repostitory. To use this tool with out-of-tree builds set `BUILDDIR`. For
example:

```bash
BUILDDIR=$PWD/build contrib/devtools/gen-manpages.sh
```

security-check.py and test-security-check.py
============================================

Perform basic security checks on a series of executables.

symbol-check.py
===============

A script to check that the executables produced by gitian only contain
certain symbols and are only linked against allowed libraries.

For Linux this means checking for allowed gcc, glibc and libstdc++ version symbols.
This makes sure they are still compatible with the minimum supported distribution versions.

For macOS and Windows we check that the executables are only linked against libraries we allow.

Example usage after a gitian build:

    find ../gitian-builder/build -type f -executable | xargs python3 contrib/devtools/symbol-check.py

If no errors occur the return value will be 0 and the output will be empty.

If there are any errors the return value will be 1 and output like this will be printed:

    .../64/test_bitcoin: symbol memcpy from unsupported version GLIBC_2.14
    .../64/test_bitcoin: symbol __fdelt_chk from unsupported version GLIBC_2.15
    .../64/test_bitcoin: symbol std::out_of_range::~out_of_range() from unsupported version GLIBCXX_3.4.15
    .../64/test_bitcoin: symbol _ZNSt8__detail15_List_nod from unsupported version GLIBCXX_3.4.15

circular-dependencies.py
========================

Run this script from the root of the source tree (`src/`) to find circular dependencies in the source code.
This looks only at which files include other files, treating the `.cpp` and `.h` file as one unit.

Example usage:

    cd .../src
    ../contrib/devtools/circular-dependencies.py {*,*/*,*/*/*}.{h,cpp}
