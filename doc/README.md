zkCoin Core
===========

Setup
---------------------
zkCoin Core is a launch-stage cryptocurrency implementation derived from
Litecoin Core. It combines Litecoin-style scrypt proof-of-work, AuxPoW merged
mining, a deterministic Litecoin block-X UTXO snapshot import path, and
Orchard-based shielded transaction validation.

Public main and test networks intentionally fail closed until the production
launch profile is hardcoded. See the repository for current launch and build
documentation: [github.com/zk-coin/zkcoin](https://github.com/zk-coin/zkcoin).

Running
---------------------
The following are some helpful notes on how to run zkCoin Core on your native platform.

### Unix

Unpack the files into a directory and run:

- `bin/litecoin-qt` (GUI) or
- `bin/litecoind` (headless)

### Windows

Unpack the files into a directory, and then run litecoin-qt.exe.

### macOS

Drag the application bundle to your applications folder, and then run it.

### Need Help?

* See the repository documentation at [github.com/zk-coin/zkcoin](https://github.com/zk-coin/zkcoin).

Building
---------------------
The following are developer notes on how to build zkCoin Core on your native platform. They are not complete guides, but include notes on the necessary libraries, compile flags, etc.

- [Dependencies](dependencies.md)
- [macOS Build Notes](build-osx.md)
- [Unix Build Notes](build-unix.md)
- [Windows Build Notes](build-windows.md)
- [FreeBSD Build Notes](build-freebsd.md)
- [OpenBSD Build Notes](build-openbsd.md)
- [NetBSD Build Notes](build-netbsd.md)
- [Gitian Building Guide (External Link)](https://github.com/bitcoin-core/docs/blob/master/gitian-building.md)

Development
---------------------
The zkCoin repo's [root README](/README.md) contains relevant information on the development process and automated testing.

- [Developer Notes](developer-notes.md)
- [Productivity Notes](productivity.md)
- [Release Notes](release-notes.md)
- [Release Process](release-process.md)
- [Source Code Documentation (External Link)](https://doxygen.bitcoincore.org/)
- [Translation Process](translation_process.md)
- [Translation Strings Policy](translation_strings_policy.md)
- [JSON-RPC Interface](JSON-RPC-interface.md)
- [Unauthenticated REST Interface](REST-interface.md)
- [Shared Libraries](shared-libraries.md)
- [BIPS](bips.md)
- [Dnsseed Policy](dnsseed-policy.md)
- [Benchmarking](benchmarking.md)

### Miscellaneous
- [Assets Attribution](assets-attribution.md)
- [bitcoin.conf Configuration File](bitcoin-conf.md)
- [Files](files.md)
- [Fuzz-testing](fuzzing.md)
- [Reduce Memory](reduce-memory.md)
- [Reduce Traffic](reduce-traffic.md)
- [Tor Support](tor.md)
- [Init Scripts (systemd/upstart/openrc)](init.md)
- [ZMQ](zmq.md)
- [PSBT support](psbt.md)

License
---------------------
Distributed under the [MIT software license](/COPYING).
