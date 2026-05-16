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

The hidden `verifysnapshotmanifest` RPC reads a `dumptxoutset`-compatible UTXO snapshot file, decodes every serialized UTXO, and returns a deterministic `snapshot_hash` for source-file auditability.

It also returns an `import_hash`, which is the launch-consensus hash to use for imported balances. The import hash preserves each Litecoin outpoint, script, and value, but normalizes chain-local metadata such as UTXO height and coinbase status. That matters because Litecoin coinbase maturity must not make old, already-mature Litecoin outputs unspendable on the new chain.

Both are intentionally present before behavior changes so tests and review can track the launch-critical constants.

## Current RPC Status

- `-auxpowheight=<n>` enables AuxPoW on regtest from height `n`.
- `-ltcsnapshotheight=<n>`, `-ltcsnapshotblockhash=<hex>`, and `-ltcsnapshotutxoroot=<hex>` configure the block-X snapshot constants on regtest for launch rehearsal.
- `generatetodescriptor` and related local generation RPCs can mine AuxPoW blocks after activation.
- `getauxblock` exposes candidate creation and AuxPoW submission for merge-mining integration.
- `verifysnapshotmanifest` verifies a deterministic Litecoin UTXO snapshot manifest and returns the normalized `import_hash`.
- `importsnapshotmanifest` imports the normalized snapshot UTXOs into the launch chainstate. It is guarded so it only runs at the genesis chain tip, and it enforces configured snapshot constants unless explicitly allowed on test chains.
