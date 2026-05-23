This folder contains lint scripts.

check-doc.py
============
Check for missing documentation of command line options.

commit-script-check.sh
======================
Verification of [scripted diffs](/doc/developer-notes.md#scripted-diffs).
Scripted diffs are only assumed to run on the latest LTS release of Ubuntu. Running them on other operating systems
might require installing GNU tools, such as GNU sed.

git-subtree-check.sh
====================
Run this script from the root of the repository to verify that a subtree matches the contents of
the commit it claims to have been updated to.

To use, make sure that you have fetched the upstream repository branch in which the subtree is
maintained:
* for `src/secp256k1`: https://github.com/bitcoin-core/secp256k1.git (branch master)
* for `src/leveldb`: https://github.com/bitcoin-core/leveldb.git (branch bitcoin-fork)
* for `src/univalue`: https://github.com/bitcoin-core/univalue.git (branch master)
* for `src/crypto/ctaes`: https://github.com/bitcoin-core/ctaes.git (branch master)
* for `src/crc32c`: https://github.com/google/crc32c.git (branch master)

To do so, add the upstream repository as remote:

```
git remote add --fetch secp256k1 https://github.com/bitcoin-core/secp256k1.git
```

Usage: `git-subtree-check.sh DIR (COMMIT)`

`COMMIT` may be omitted, in which case `HEAD` is used.

lint-all.sh
===========
Calls other scripts with the `lint-` prefix.

lint-fuzz-targets.sh
====================
Checks that fuzz harness program lists contain target names rather than source
filenames, so automake does not synthesize invalid source dependencies for
release packaging.

lint-secp256k1-zkp-sources.sh
=============================
Checks that literal Automake source paths in the bundled secp256k1-zkp subtree
exist, so release packaging does not depend on stale module registrations.

lint-zkcoin-launch-validation.py
================================
Checks that the Cirrus zkCoin launch-validation task still invokes the
canonical launch wrapper directly, and that the wrapper path still reaches the
real Orchard AuxPoW functional regression with skipped Orchard verification
treated as a failure. The required canonical and smoke-lane checks are listed in
`contrib/devtools/zkcoin_launch_validation_manifest.json`, and the lint checks
actual shell command lines instead of comments or status messages. The same
manifest also tracks the heavier release-candidate source-artifact gate so the
operator wrapper keeps running the canonical validation loop plus the unpacked
source-dist real-proof regression before source release candidates.

lint-zkcoin-previous-releases.py
================================
Checks that zkCoin previous-release artifact metadata remains explicit, and
that inherited Litecoin compatibility downloads require the
`--upstream-litecoin-compat` opt-in flag.

lint-zkcoin-public-launch-profile.py
====================================
Checks that public `chainparams` stay fail-closed until production launch
constants are hardcoded, and that the launch readiness gate still requires the
Litecoin snapshot, strict parent-version-safe AuxPoW at the first launch block,
script-rule activation, shielded inactivity at launch, neutral inherited chain
history, and non-Litecoin public network identity together.

lint-zkcoin-release-infrastructure.py
=====================================
Checks that inherited Gitian, signing, packaging, and binary-verification
release infrastructure is tracked in
`contrib/devtools/zkcoin_release_infrastructure_manifest.json`, and that
release docs keep legacy binary verification guarded while zkCoin binary
verification remains parameterized until release keys, repositories, artifact
hosts, and namespace decisions are configured.

lint-zkcoin-product-identity.sh
===============================
Checks that the core display identity remains zkCoin in package metadata,
source URLs, P2P user-agent naming, and primary Windows resource metadata while
legacy binary and datadir names are kept unchanged for a separate migration.
