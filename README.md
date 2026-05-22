zkCoin Core integration/staging tree
====================================

https://github.com/zk-coin/zkcoin

What is zkCoin?
---------------

zkCoin is a launch-stage cryptocurrency implementation derived from Litecoin
Core. The project combines Litecoin-style scrypt proof-of-work, AuxPoW merged
mining support, a deterministic Litecoin block-X UTXO snapshot import path, and
an Orchard-based shielded transaction verifier.

The public main and test networks intentionally fail closed until the
production launch profile is hardcoded. That profile must replace inherited
Litecoin public network identity, configure the launch snapshot, activate
strict, parent-version-safe AuxPoW for the first post-genesis block, and keep
real Orchard proof verification available.

License
-------

zkCoin Core is released under the terms of the MIT license. See
[COPYING](COPYING) for more information or see
https://opensource.org/licenses/MIT.

Development Process
-------------------

The `master` branch is regularly built and tested, but it should be treated as
integration-stage code until the launch profile and release validation lane are
complete. Launch-path changes should pass the canonical validation wrapper:

```bash
JOBS="$(sysctl -n hw.ncpu 2>/dev/null || nproc 2>/dev/null || echo 4)" \
  contrib/devtools/zkcoin_launch_validation.sh
```

The contribution workflow is described in [CONTRIBUTING.md](CONTRIBUTING.md)
and useful hints for developers can be found in
[doc/developer-notes.md](doc/developer-notes.md).

Testing
-------

Developers are strongly encouraged to write [unit tests](src/test/README.md)
for new code and to submit focused regression tests for existing behavior.
Unit tests can be compiled and run, assuming they were not disabled in
configure, with:

```bash
make check
```

Regression and integration tests are in [test](/test) and can be run with:

```bash
test/functional/test_runner.py
```

For AuxPoW, snapshot import, shielded validation, or launch configuration
changes, individual tests do not replace the combined zkCoin launch validation
loop.

For faster local iteration before the full real-Orchard validation lane, run the
launch smoke wrapper:

```bash
JOBS="$(sysctl -n hw.ncpu 2>/dev/null || nproc 2>/dev/null || echo 4)" \
  contrib/devtools/zkcoin_launch_smoke.sh
```

Translations
------------

The inherited Qt translation workflow still follows the upstream Transifex
process. Translation-only pull requests are not accepted because the next
translation import would overwrite them.
