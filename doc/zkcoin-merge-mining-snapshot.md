# zkCoin Merge-Mining and Snapshot Plan

This fork is intended to be a Litecoin tribute chain, not a Zcash mutation. The base stays Litecoin: scrypt proof of work parameters, Litecoin transaction model, MWEB already present in the codebase, and a one-time Litecoin balance snapshot at a chosen block X. ZK privacy is added as a later shielded pool or extension after the fork and merge-mining path is stable.

## Direction

1. Fork from Litecoin Core and keep scrypt as the work function.
2. Hardcode a Litecoin snapshot block height and hash before launch.
3. Build a deterministic UTXO snapshot manifest from that Litecoin block.
4. Import balances on the new chain using the manifest root as consensus data.
5. Enable AuxPoW so Litecoin miners can merge mine zkCoin without leaving Litecoin.
6. Add a shielded pool after the base chain validates, syncs, mines, and reorganizes safely.

## Snapshot Rules

The snapshot is a consensus object. Nodes must agree on:

- Litecoin block height X.
- Litecoin block hash at height X.
- UTXO inclusion rules.
- Dust and unspendable-output policy.
- Deterministic serialization of each allocation entry.
- Manifest hash or Merkle root.
- Total imported supply.

The snapshot tool should fail closed if the local Litecoin node does not report the exact expected block hash for height X.

## AuxPoW Rules

The target model is Namecoin and Dogecoin style AuxPoW:

- zkCoin block header keeps the child chain header hash.
- AuxPoW data proves the child header hash is committed in a Litecoin parent coinbase.
- The parent block header must satisfy Litecoin scrypt proof of work.
- The parent coinbase must commit to the zkCoin chain id.
- Chain merkle branches must place the child commitment at the expected index.
- Activation height must be explicit and testable.

The first code steps add disabled consensus parameters for activation height and chain id, AuxPoW header serialization, validation, regtest mining, and a first pool-facing `getauxblock` RPC.

`getauxblock` is the initial merge-mining RPC:

- `getauxblock` with no arguments returns a child-chain block hash, chain id, child target, and `auxpowcommitment`.
- The `auxpowcommitment` bytes are the merged-mining tag, the child commitment, the chain-merkle size, and the chain-merkle nonce. They are intended to be included in the Litecoin parent coinbase scriptSig.
- `getauxblock <hash> <auxpow>` submits a serialized AuxPoW proof for a previously returned candidate.
- The child block is accepted when the AuxPoW proof commits the child header into the parent coinbase and the parent Litecoin-style scrypt header satisfies the child target.

This is enough for regtest and pool-integration prototyping. A production launch still needs hardcoded mainnet activation constants, broader interop testing with real Litecoin pool software, and a final review of chain id/version-bit interactions.

## Shielded Pool

Do not start by forking Zcash and swapping Equihash for scrypt. That would make the project a Zcash-derived chain with Litecoin mining parameters. For a Litecoin tribute chain, the simpler narrative and safer engineering path is:

- Keep Litecoin as the consensus base.
- Merge mine with Litecoin.
- Add a shielded pool as a new transaction component or extension area.
- Reuse a modern proving stack where practical, such as Orchard/Halo2-style components, but integrate it into Litecoin-derived validation deliberately.

SNARK privacy is not quantum resistance. If post-quantum privacy becomes a requirement, that is a separate cryptographic design track.

## Current Consensus Placeholders

`Consensus::Params::ltc_snapshot` records block X and the deterministic UTXO root. It is disabled until `nHeight` is set.

`Consensus::Params::auxpow` records the AuxPoW start height and chain id. It is disabled until `nStartHeight` is set. The placeholder chain id is `0x5a4b` (`ZK`) so it fits in the AuxPoW block-version chain-id field.

The validation path should switch at that height:

- before activation, headers must not carry AuxPoW data and are checked against their own scrypt PoW hash;
- at and after activation, headers must carry AuxPoW data, must encode the zkCoin chain id, and are checked against the parent Litecoin-style scrypt header hash committed through the parent coinbase.

The zkCoin consensus check compares the parent header scrypt hash to the child
target carried by the AuxPoW candidate. A real merged miner can also submit the
same parent block to Litecoin if it meets Litecoin's own target, but zkCoin's
child-chain acceptance is governed by the child target and the AuxPoW
commitment, not by Litecoin network difficulty.

The hidden `verifysnapshotmanifest` RPC reads a `dumptxoutset`-compatible UTXO snapshot file, decodes every serialized UTXO, and returns a deterministic `snapshot_hash` for source-file auditability.

It also returns an `import_hash`, which is the launch-consensus hash to use for imported balances. The import hash preserves each Litecoin outpoint, script, and value, but normalizes chain-local metadata such as UTXO height and coinbase status. Imported coins are stored as non-coinbase outputs at launch import height `1`, so Litecoin coinbase maturity does not make old Litecoin outputs unspendable on the new chain and block undo has explicit height metadata for single-output parent transactions.

Because imported balances preserve original Litecoin outpoints, built-in mining templates include a small `zkcoin` push in the child coinbase scriptSig after the BIP34 height/extranonce fields. When block-X snapshot parameters are configured, templates also push the configured Litecoin snapshot block hash. This keeps locally generated launch coinbases from accidentally recreating an imported Litecoin coinbase transaction id. `getblocktemplate` exposes the base tag in `coinbaseaux.zkcoin` and the configured snapshot block hash in `coinbaseaux.zkcoin_snapshot` for external miners.

Both are intentionally present before behavior changes so tests and review can track the launch-critical constants.

## Current RPC Status

- `-auxpowheight=<n>` enables AuxPoW on regtest from height `n`.
- `-auxpowchainid=<n>` overrides the AuxPoW child chain id on regtest for launch rehearsal. It must fit in the AuxPoW block-version chain-id field and avoid the Litecoin parent versionbits-derived range `0x2000` through `0x3fff`. Use the default `23115` (`0x5a4b`) unless explicitly testing chain-id failure handling.
- `-auxpowstrictchainid` keeps regtest AuxPoW in strict merged-mining mode. `-noauxpowstrictchainid` is only for rehearsing launch-readiness failures.
- `-ltcsnapshotheight=<n>`, `-ltcsnapshotblockhash=<hex>`, and `-ltcsnapshotutxoroot=<hex>` configure the block-X snapshot constants on regtest for launch rehearsal.
- `-ltcsnapshotfile=<path>` points reindex and reindex-chainstate startup at the verified block-X snapshot manifest so the imported launch UTXO set can be reseeded before replaying fork-chain blocks.
- Public `main` and `testnet` startup is fail-closed until the production
  launch profile is hardcoded in `chainparams`: the Litecoin block-X snapshot
  constants must be set, strict AuxPoW must activate for the first launch block
  with a parent-version-safe child chain id, shielded transactions must remain
  inactive for the first launch block, inherited Litecoin chain-history
  assumptions must be cleared, and the inherited Litecoin public network identity
  must be replaced, including public magic, ports, address prefixes, HRPs, and
  seeds. Regtest remains the only place where these values can be overridden by
  CLI for rehearsal.
- `generatetodescriptor` and related local generation RPCs can mine AuxPoW blocks after activation.
- `getauxblock` exposes wallet-backed candidate creation and AuxPoW submission for merge-mining integration.
- `createauxblock <address>` exposes explicit-address candidate creation for pool software and no-wallet nodes.
- `getauxblock` and `createauxblock` expose Dogecoin-style `target` plus `_target` for Namecoin-compatible pool software; both are the expanded target in AuxPoW byte order.
- `getauxblock <hash> <auxpow>` and `submitauxblock <hash> <auxpow>` return Dogecoin-style booleans on submission.
- `getblockchaininfo.launch_readiness` exposes a base-launch preflight summary. It is only ready at the genesis launch tip, before the first child block is mined, when the block-X snapshot is configured and imported, AuxPoW is active for the first post-genesis launch block, the AuxPoW chain id is strict, encodable, and outside Litecoin's parent versionbits-derived chain-id range, inherited Litecoin chain-history assumptions are clear, the public network identity is not inherited from Litecoin, and shielded transactions are inactive for the first launch block.
- `verifysnapshotmanifest` verifies a deterministic Litecoin UTXO snapshot manifest and returns the normalized `import_hash`.
- `importsnapshotmanifest` imports the normalized snapshot UTXOs into the launch chainstate. It is guarded so it only runs at the genesis chain tip, and it enforces configured snapshot constants unless explicitly allowed on test chains.

`importsnapshotmanifest` is intended to be restart-safe during launch rehearsal:

- it verifies the manifest before mutating chainstate;
- it writes an in-progress marker keyed by height, Litecoin block hash, and normalized import hash;
- if the same import is replayed at the genesis tip, already-written identical UTXOs are accepted and missing UTXOs continue to be imported;
- if an existing or in-progress marker points at a different snapshot, the RPC fails closed;
- after a successful flush, the in-progress marker is atomically replaced by the completed import marker.

This makes local block-X launch tests repeatable without requiring a full datadir reset after an interrupted import.

## Launch Validation

`contrib/devtools/zkcoin_launch_validation.sh` is the canonical production-profile validation command for zkCoin launch-path work. It delegates to `zkcoin_orchard_auxpow.sh`, which configures the real Orchard verifier backend, rebuilds the node, and runs the combined AuxPoW, local Litecoin-fork, snapshot import, shielded unit, Rust verifier, and real-proof functional regressions.

The validation loop also runs the launch argument guards, the launch preflight guard, and a fake-CLI test for the Litecoin snapshot operator script so malformed snapshot RPC output or unsafe rewind cleanup behavior cannot silently pass a launch rehearsal.

Run it before treating changes to AuxPoW, snapshot import, shielded validation, or launch configuration as release-candidate work:

```bash
JOBS="$(sysctl -n hw.ncpu 2>/dev/null || nproc 2>/dev/null || echo 4)" \
  contrib/devtools/zkcoin_launch_validation.sh
```

Individual unit or functional tests are useful while iterating, but they do not replace this combined launch validation loop.

## Block-X Snapshot Constant Generation

`contrib/devtools/zkcoin_ltc_snapshot.sh` is the operator tool for turning a selected Litecoin block X into launch constants. It requires:

- the Litecoin snapshot height;
- the expected Litecoin block hash at that height;
- an output path for the `dumptxoutset` snapshot;
- a `litecoin-cli` command pointed at the source Litecoin node;
- a `zkcoin-cli` command pointed at a zkCoin node with `verifysnapshotmanifest`.

The script fails closed if the source node does not report the expected block hash for height X, if `dumptxoutset` or `verifysnapshotmanifest` returns malformed JSON, or if required snapshot/manifest fields are missing or inconsistent. If the source node is already beyond height X, it refuses to rewind unless `ZKCOIN_SNAPSHOT_ALLOW_REWIND=1` is set. Rewind mode should only be used on a dedicated disposable snapshot node because it invalidates block `X + 1` and then reconsiders it on exit. A failed restore makes the script fail even when the snapshot dump itself succeeded.

Example:

```bash
contrib/devtools/zkcoin_ltc_snapshot.sh \
  3000000 \
  <expected-litecoin-block-hash> \
  /srv/snapshots/ltc-block-x.dat \
  /srv/litecoin/src/litecoin-cli -datadir=/srv/litecoin-data \
  -- \
  ./src/litecoin-cli -datadir=/srv/zkcoin-data
```

It prints the snapshot-related launch-node arguments:

```text
-ltcsnapshotheight=<height>
-ltcsnapshotblockhash=<block_hash>
-ltcsnapshotutxoroot=<normalized_import_hash>
-ltcsnapshotfile=<snapshot_path>
```

Keep `-ltcsnapshotfile` with the other snapshot arguments for launch rehearsal and reindex operations. Startup fails closed if snapshot constants are configured with `-reindex` or `-reindex-chainstate` but the snapshot file path is missing.

After the first child block is mined, rehearse both rebuild paths against the
same datadir:

```text
-reindex-chainstate -ltcsnapshotfile=<snapshot_path>
-reindex -ltcsnapshotfile=<snapshot_path>
```

Both runs should reseed the configured block-X UTXO set from the snapshot file,
replay the zkCoin blocks from disk, preserve the `ltc_snapshot.imported_*`
marker reported by `getblockchaininfo`, and leave sampled imported Litecoin
outpoints spendable through `gettxout`.

Combine those snapshot arguments with the AuxPoW launch profile, then check the launch node before mining:

```bash
contrib/devtools/zkcoin_launch_preflight.sh \
  ./src/litecoin-cli -datadir=/srv/zkcoin-data
```

The preflight script exits successfully only when `getblockchaininfo.launch_readiness.ready` is `true`, which requires the node to still be at the genesis launch tip before block 1 is mined and to report `launch_readiness.chain_history_clean=true` and `launch_readiness.public_network_identity_configured=true`. When public network identity is not configured, inspect `launch_readiness.public_network_identity` for the inherited message-start, port, seed, Base58, Bech32, and MWEB HRP checks that still need replacement. It also fails closed unless scaffold proofs are disabled, `shielded_pool.real_proof_backend` is `orchard-v1`, and `shielded_pool.real_proof_verification` is `true`.
