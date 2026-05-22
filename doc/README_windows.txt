zkCoin Core
===========

Intro
-----
zkCoin is a launch-stage cryptocurrency implementation derived from Litecoin
Core. It combines Litecoin-style scrypt proof-of-work, AuxPoW merged mining,
a deterministic Litecoin block-X UTXO snapshot import path, and Orchard-based
shielded transaction validation.

Public main and test networks intentionally fail closed until the production
launch profile is hardcoded.

Setup
-----
Unpack the files into a directory and run litecoin-qt.exe.

The executable names are still inherited from Litecoin while binary, config,
and datadir migration is handled as a separate release step.

See the repository for current launch and build documentation:
  https://github.com/zk-coin/zkcoin
