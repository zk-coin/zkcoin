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

`Consensus::Params::auxpow` records the AuxPoW start height and chain id. It is disabled until `nStartHeight` is set. The placeholder chain id is `0x5a4b` (`ZK`) so it fits in the AuxPoW block-version chain-id field and avoids the Litecoin parent versionbits-derived range `0x2000` through `0x3fff`.

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
  with a parent-version-safe child chain id, script validation rules needed for
  imported Litecoin outputs must be active for the first launch block, shielded
  transactions must remain inactive for the first launch block, inherited Litecoin chain-history
  assumptions must be cleared, and the inherited Litecoin public network identity
  must be replaced with structurally valid public magic, ports, DNS seeds,
  unique address prefixes, and distinct HRPs. Inherited Litecoin DNS and fixed
  seeds are cleared until zkCoin-specific seed infrastructure is generated, so
  public launch remains fail-closed on missing zkCoin DNS seeds. The fail-closed
  startup error lists the exact hardcoded launch checks that still fail, so a
  release engineer can distinguish missing snapshot, AuxPoW, script-rule,
  shielded, chain-history, and public identity work before public networks are
  enabled. Regtest remains the only place where these values can be overridden
  by CLI for rehearsal.
- `contrib/devtools/zkcoin_public_launch_profile_manifest.json` is the
  machine-readable handoff for those final public launch constants. Keep it in
  `blocked` status while any snapshot, AuxPoW chain id, DNS seed, or public
  network identity value is still undecided; lint validates the blocked schema
  with `contrib/devtools/zkcoin_public_launch_profile.py --allow-blocked`.
  The blocker list must match the unresolved fields exactly, so stale,
  duplicate, or untracked blocker ids cannot hide the real next launch action.
  At any point, run
  `contrib/devtools/zkcoin_public_launch_profile.py --next-action` to print
  the next unresolved blocker group, the matching handoff command template, and
  blocker-scoped summary commands for later blockers;
  run `contrib/devtools/zkcoin_public_launch_profile.py --action-plan` to print
  every unresolved blocker group and handoff command in launch order. Use
  `contrib/devtools/zkcoin_public_launch_profile.py --readiness-summary` for a
  compact human-readable summary of blocked networks, ready networks, blocker
  counts, per-network and per-workstream blocker counts, blocked field counts,
  per-network and per-workstream blocked field counts, per-network next blockers,
  per-network next blocker field counts, per-workstream next blockers,
  per-workstream next blocker networks, per-workstream next blocker field counts,
  per-network and per-workstream next template/check/apply commands,
  per-workstream next network, blocker-type, and blocker-scoped summary
  commands, per-network next
  blocker-type summary commands, per-network next blocker-scoped summary
  commands, per-network scoped summary commands, the immediate blocker's exact field paths,
  earlier and later blocker ids with blocker-scoped summary commands, and the immediate handoff commands. These
  commands are read-only and print copyable `template command`, `check command`,
  `apply command`, `readiness summary command`,
  `network readiness summary command`,
  `blocker type readiness summary command`, and
  `blocker readiness summary command` lines next to the prose handoff, omitting
  the template line for blocker types that only need check/apply commands. Use
  `contrib/devtools/zkcoin_public_launch_profile.py --network-readiness-summary NETWORK`
  for the same read-only next-blocker detail scoped to one public network; the
  network summary prints its own copyable rerun command after the handoff commands. Use
  `contrib/devtools/zkcoin_public_launch_profile.py --blocker-type-readiness-summary BLOCKER_TYPE`
  for the same read-only next-blocker detail scoped to one workstream such as
  `litecoin_snapshot`, `auxpow_chain_id`, `public_network_identity`, or
  `dns_seeds`. Use
  `contrib/devtools/zkcoin_public_launch_profile.py --blocker-readiness-summary BLOCKER_ID`
  for the same read-only handoff detail scoped to one exact unresolved blocker,
  such as `main.litecoin_snapshot`, when release operators need to hand off a
  single blocker without the surrounding network or workstream queue. Use
  `contrib/devtools/zkcoin_public_launch_profile.py --status-json` when CI or
  release automation needs the same blocker order, field-level blockers, blocked
  field count, blocked field group count, action count, and action-plan guidance
  as machine-readable JSON with a stable `schema_version` (`2` for the grouped
  blocker payload) plus direct `blocked_field_count`,
  `blocked_field_group_count`, `action_count`, `next_action`, and
  `next_action_command`; it also exposes
  `unresolved_blockers_by_network`, `unresolved_blocker_counts_by_network`, and
  `blocked_field_counts_by_network` so dashboards can track mainnet and testnet
  launch readiness separately without parsing field paths, plus
  `unresolved_blockers_by_blocker_type`,
  `unresolved_blocker_counts_by_blocker_type`,
  `blocked_fields_by_blocker_type`, and
  `blocked_field_counts_by_blocker_type` so the same remaining gaps can be
  tracked by snapshot, AuxPoW, public identity, and DNS seed workstream, plus
  `blocker_type_progress` so each workstream has its ready flag, remaining
  blockers, blocked fields, and next action in one object, plus
  `next_blockers_by_blocker_type`, `next_blocker_networks_by_blocker_type`,
  `next_blocked_fields_by_blocker_type`, and
  `next_blocked_field_counts_by_blocker_type` so dashboards can read each
  workstream's next blocker, target network, and field gap directly, plus
  `blocker_type_readiness_summary_commands_by_blocker_type` so dashboards and
  operators can jump directly to a scoped workstream handoff, plus
  `blocker_readiness_summary_commands_by_blocker` so dashboards and operators
  can deep-link directly to exact unresolved blocker handoffs, plus
  `network_readiness_summary_commands_by_network` so dashboards and operators
  can jump directly to a scoped mainnet or testnet handoff. `actions_by_network`
  and `action_counts_by_network` group and count the remaining blocker handoffs
  by public network while non-network chainparams handoffs remain only in the
  global `actions` list. `actions_by_blocker_type` and
  `action_counts_by_blocker_type` also group and count remaining blocker
  handoffs by snapshot, AuxPoW, public identity, and DNS seed workstream, with
  `next_actions_by_blocker_type` and `next_commands_by_blocker_type` exposing
  the next dispatchable handoff for each workstream. The payload also exposes
  `next_commands_by_network`, which mirrors the current command fields for each
  network's next blocker, including the network and blocker-type summary
  commands, so automation can dispatch scoped handoffs directly.
  `next_blocked_field_groups_by_network` exposes the same current blocker group
  objects by network without requiring clients to traverse `network_progress`.
  `next_blocked_fields_by_network` and
  `next_blocked_field_counts_by_network` provide the same per-network field gap
  view without parsing `network_progress`.
  `next_blockers_by_network` and `next_blocker_types_by_network` provide the
  current per-network blocker ids and blocker classes directly for dashboards.
  It also exposes
  `blocked_networks`, `blocked_network_count`, `ready_networks`, and
  `ready_network_count` for a compact network readiness summary without parsing
  per-network progress entries. It also includes `network_progress`, which consolidates each network's ready flag,
  unresolved blockers, blocked fields, and next blocker group for operator views.
  The same payload
  includes ordered `blocked_field_groups`, `next_blocked_field_group`, and
  `next_blocked_fields` so dashboards can show the concrete fields and action
  guidance for each unresolved blocker and the first unresolved blocker. Blocker
  action entries expose `network` and `blocker_type` values directly in `actions`
  and `next_action`, include the same blocker `fields` and `field_count`, and
  always expose split command fields such as `template_command`, `check_command`,
  `apply_command`, `readiness_summary_command`,
  `network_readiness_summary_command`,
  `blocker_type_readiness_summary_command`, and
  `blocker_readiness_summary_command`; `next_commands` mirrors the command
  fields from the current `next_action` so automation can dispatch the immediate
  handoff and post-apply readiness check without parsing the full action entry;
  blocked field groups carry the same split command fields.
  `template_command` is `null` for blocker types that only need check/apply
  commands, so automation does not need to parse blocker ids, blocked field paths,
  or human-readable action prose;
  when checking a staged copy, pass that manifest path so the printed command
  targets the same file. The printed command shell-quotes the manifest path
  when needed, so staged copies in directories with spaces are safe to use.
  Before collecting final snapshot constants, run
  `contrib/devtools/zkcoin_public_launch_profile.py --snapshot-audit-template NETWORK`
  to print the exact JSON summary shape expected by the snapshot audit handoff;
  the template fills only the network-specific Litecoin `source_chain` value and
  leaves production snapshot values unset until the real audit is complete.
  After selecting a final AuxPoW child chain id, verify it without modifying
  the manifest with
  `contrib/devtools/zkcoin_public_launch_profile.py --check-auxpow NETWORK <chain_id>`,
  then update the target profile with
  `contrib/devtools/zkcoin_public_launch_profile.py --set-auxpow NETWORK <chain_id>`;
  the read-only AuxPoW check reports the exact apply command, remaining blocker
  count, target-network remaining blocker count, overall and target-network
  remaining blocked field counts, post-apply next-action command,
  post-apply readiness summary command,
  target-network readiness summary command, blocker-type readiness summary command,
  next blocker, next check/apply commands that would remain after applying
  the candidate, and next scoped summary commands for that next blocker, so reviewers can verify blocker progress before changing the manifest;
  the validator accepts decimal or `0x...` input but rejects zero, values outside
  the AuxPoW version field, the local launch placeholder `0x5a4b`, and the
  Litecoin parent versionbits-derived `0x2000..0x3fff` range. After provisioning
  zkCoin-operated DNS seeds, verify them without modifying the manifest with
  `contrib/devtools/zkcoin_public_launch_profile.py --check-dns-seeds NETWORK <seed1.hostname>,<seed2.hostname>`,
  then update the target profile with
  `contrib/devtools/zkcoin_public_launch_profile.py --set-dns-seeds NETWORK <seed1.hostname>,<seed2.hostname>`;
  the read-only DNS seed check reports the exact apply command, remaining blocker
  count, target-network remaining blocker count, overall and target-network
  remaining blocked field counts, post-apply next-action command,
  post-apply readiness summary command,
  target-network readiness summary command, blocker-type readiness summary command,
  next blocker, next check/apply commands that would remain after applying
  the candidate, and next scoped summary commands for that next blocker, so reviewers can verify seed handoff progress before changing the manifest;
  the validator rejects empty, duplicate, single-label, numeric final-label,
  overlong-label, malformed, uppercase, reserved or local-use suffixes, and
  inherited Litecoin seed hostnames. After choosing the public network identity,
  verify it without modifying the manifest with
  `contrib/devtools/zkcoin_public_launch_profile.py --check-identity NETWORK <message_start> <port> <pubkey> <script> <script2> <secret> <xpub> <xprv> <bech32_hrp> <mweb_hrp>`,
  then update the target profile with
  `contrib/devtools/zkcoin_public_launch_profile.py --set-identity NETWORK <message_start> <port> <pubkey> <script> <script2> <secret> <xpub> <xprv> <bech32_hrp> <mweb_hrp>`;
  the read-only identity check reports the exact apply command, remaining blocker
  count, target-network remaining blocker count, overall and target-network
  remaining blocked field counts, post-apply next-action command,
  post-apply readiness summary command,
  target-network readiness summary command, blocker-type readiness summary command,
  next blocker, next check/apply commands that would remain after applying
  the candidate, and next scoped summary commands for that next blocker, so reviewers can verify identity handoff progress before changing the manifest;
  byte values may be decimal, `0x..`, comma-separated, or compact hex for
  multi-byte fields, and the validator rejects inherited Litecoin message
  starts, ports, Base58 prefixes, HRPs, overlong HRPs, duplicate prefixes, and
  matching Bech32 and MWEB HRPs. Before a manifest can become ready, mainnet and testnet must
  also use distinct AuxPoW chain ids, message starts, ports, DNS seed hostnames,
  Base58 prefixes, and HRP namespaces so the emitted `chainparams` snippets
  cannot accidentally collide across public networks.
  Before copying values into `chainparams`, run
  `contrib/devtools/zkcoin_public_launch_profile.py --mark-ready --in-place contrib/devtools/zkcoin_public_launch_profile_manifest.json`;
  it clears blockers and sets `ready-for-chainparams` only after strict
  validation confirms every production field is resolved. Any later `--set-*`
  update against a ready manifest demotes it back to `blocked`, so rerun
  `--mark-ready` after reviewing the change. Then use
  `contrib/devtools/zkcoin_public_launch_profile.py --emit-chainparams` to emit
  the reviewed `chainparams.cpp` assignment skeleton. After applying the
  snippet, run
  `contrib/devtools/zkcoin_public_launch_profile.py --check-chainparams src/chainparams.cpp`
  against the ready manifest so the committed `chainparams.cpp` stays
  synchronized with the reviewed launch manifest and the main/testnet snippets
  are present only once in their matching chainparams classes without foreign
  generated snippets. The checked `chainparams.cpp` input is read from a direct
  parent directory as a direct regular file capped at 1048576 bytes, decoded as
  UTF-8, and rechecked before sync comparison so symlinked or concurrently
  changed files cannot mask drift.
- `generatetodescriptor` and related local generation RPCs can mine AuxPoW blocks after activation.
- `getauxblock` exposes wallet-backed candidate creation and AuxPoW submission for merge-mining integration.
- `createauxblock <address>` exposes explicit-address candidate creation for pool software and no-wallet nodes.
- `getauxblock` and `createauxblock` expose Dogecoin-style `target` plus `_target` for Namecoin-compatible pool software; both are the expanded target in AuxPoW byte order.
- `getauxblock <hash> <auxpow>` and `submitauxblock <hash> <auxpow>` return Dogecoin-style booleans on submission.
- `getblockchaininfo.launch_readiness` exposes a base-launch preflight summary. It is only ready at the genesis launch tip, before the first child block is mined, when the block-X snapshot is configured and imported, AuxPoW is active for the first post-genesis launch block, the AuxPoW chain id is strict, encodable, outside Litecoin's parent versionbits-derived chain-id range, and no longer the local launch placeholder, legacy and Taproot script validation rules are active for the first launch block, inherited Litecoin chain-history assumptions are clear, the public network identity is not inherited from Litecoin and has valid public-network shape, and shielded transactions are inactive for the first launch block.
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

`contrib/devtools/zkcoin_launch_validation.sh` is the canonical production-profile validation command for zkCoin launch-path work. It delegates to `zkcoin_orchard_auxpow.sh`, which configures the real Orchard verifier backend, rebuilds the node, and runs the combined AuxPoW, local Litecoin-fork, snapshot import, shielded unit, Rust verifier, source distribution packaging, and real-proof functional regressions.

The validation loop also runs the public launch/seed quarantine lint, release-infrastructure and previous-release fail-closed lints, launch argument guards, the launch preflight guard, explicit unsupported-signet startup policy, and a fake-CLI test for the Litecoin snapshot operator script so malformed snapshot RPC output, unsafe rewind cleanup behavior, or missing release gates cannot silently pass a launch rehearsal.
The expected validation entries are tracked in a checked manifest, and the lint
rejects duplicate JSON fields in that manifest so hand-edited validation tasks
cannot be shadowed by later duplicate keys.

Run it before treating changes to AuxPoW, snapshot import, shielded validation, or launch configuration as release-candidate work:

```bash
JOBS="$(sysctl -n hw.ncpu 2>/dev/null || nproc 2>/dev/null || echo 4)" \
  contrib/devtools/zkcoin_launch_validation.sh
```

Individual unit or functional tests are useful while iterating, but they do not replace this combined launch validation loop.

Before tagging or publishing a source release candidate, run the heavier
release-candidate gate as well:

```bash
JOBS="$(sysctl -n hw.ncpu 2>/dev/null || nproc 2>/dev/null || echo 4)" \
  TEST_RUNNER_PORT_MIN=28000 \
  contrib/devtools/zkcoin_release_candidate_validation.sh
```

That wrapper runs the canonical launch validation loop, then builds the source
tarball, unpacks it into a temporary build root, configures the real Orchard
verifier backend there, rebuilds `litecoind`, `litecoin-cli`, and
`test_litecoin`, and reruns the real Orchard AuxPoW regression from the
unpacked release source. It is a source-artifact gate only; signing, Gitian, and
binary-verification infrastructure must still be replaced before production
release publication.

## Block-X Snapshot Constant Generation

`contrib/devtools/zkcoin_ltc_snapshot.sh` is the operator tool for turning a selected Litecoin block X into launch constants. It requires:

- a positive Litecoin snapshot height;
- the expected Litecoin block hash at that height;
- an output path for the `dumptxoutset` snapshot;
- a `litecoin-cli` command pointed at the source Litecoin node;
- a `zkcoin-cli` command pointed at a zkCoin node with `verifysnapshotmanifest`.

The script fails closed if the source node does not report a usable duplicate-free JSON object from
`getblockchaininfo`, if the source is still in initial block download, if the
source has headers ahead of downloaded blocks or reports headers below downloaded blocks,
if the source reports malformed source sync booleans or malformed source chain names,
if it reports malformed source block or header heights, if the source is pruned,
if the source node reports non-empty warnings, if the
requested snapshot height is zero or malformed, if the expected block hash is
not lowercase 64-character hex, if the source node does not report a
well-formed lowercase non-null block hash for height X, if that hash does not
match the expected block hash, if the active source tip hash does not match the expected block hash
when the source is already at height X, if the source node does not report
non-null source chainwork, non-negative source verification progress not
exceeding 1,
non-negative source difficulty, positive source disk footprint, or
non-negative source tip times with median time not after block time, if the
expected block hash is the null uint256 placeholder, if
`dumptxoutset` does not leave a non-empty snapshot file before running zkCoin verification, if `dumptxoutset` or `verifysnapshotmanifest`
returns malformed, non-object, or duplicate-field JSON, or if required snapshot/manifest fields are missing or
inconsistent, including non-lowercase or null hash fields and non-positive coin or transaction counts. The operator error is explicit: `Litecoin source node is still in initial block download`, `Litecoin source node must not be pruned for snapshot generation`, or `Litecoin source node reports warnings`.
It parses and cross-checks the `dumptxoutset` height, block hash, and positive
coin count before invoking `verifysnapshotmanifest`, so malformed or inconsistent
Litecoin dump metadata cannot advance to zkCoin verifier handoff. It also
requires `dumptxoutset.path` to match the requested snapshot output path before
trusting the dump handoff.
It fingerprints the snapshot artifact through a direct file descriptor before
and after zkCoin verification, rechecks the path after hashing, and fails if the
artifact becomes a symlink after dump or verification, or if its size or SHA-256
changes during zkCoin verification, so the audit summary always describes the
exact verified file.
If the source node is already beyond height X, it refuses to rewind unless
`ZKCOIN_SNAPSHOT_ALLOW_REWIND=1` is set. Rewind mode should only be used on a
dedicated disposable snapshot node because it invalidates block `X + 1` and then
requires `getblockcount` to return an integer source tip exactly equal to height X
after invalidation before dumping the snapshot. It validates the block `X + 1` restore hash before invalidating
anything, then reconsiders block `X + 1` on exit. A failed restore makes the
script fail even when the snapshot dump itself succeeded.
When `ZKCOIN_SNAPSHOT_AUDIT_JSON` is set, the script validates the audit summary output path before running snapshot RPCs: the audit path must not already
exist, must not equal the snapshot output path, and must have an existing parent
directory. The snapshot output directory must also exist before the script calls
either node, and snapshot and audit output directories must be writable direct
directories, not symlinks. The snapshot and audit output paths must be direct files,
not symlinks, before the operator writes launch artifacts. The snapshot `.incomplete` work file used by
`dumptxoutset` must also be absent and non-symlinked before the dump starts,
and it must not remain after a successful dump response. The snapshot output and
audit summary directories are also rechecked so they cannot become symlinks or be
replaced after dump or verification. The audit summary path
must also differ from the reserved `.incomplete` work-file path. Paths that resolve
through physical parent directories to the same canonical output target, or
that contain control characters, are rejected before any node RPC is called.

Example:

```bash
ZKCOIN_SNAPSHOT_AUDIT_JSON=/srv/snapshots/ltc-block-x.audit.json \
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

It also writes a machine-readable audit summary when `ZKCOIN_SNAPSHOT_AUDIT_JSON`
is set. The audit summary uses the same field order as the
`--snapshot-audit-template` output, so reviewers can compare the generated
artifact against the expected handoff shape without key reordering noise. Use
that verified audit summary for the public launch-profile manifest handoff:

```bash
contrib/devtools/zkcoin_public_launch_profile.py \
  --snapshot-audit-template NETWORK \
  contrib/devtools/zkcoin_public_launch_profile_manifest.json

contrib/devtools/zkcoin_public_launch_profile.py \
  --check-snapshot-audit NETWORK <snapshot_audit.json> \
  contrib/devtools/zkcoin_public_launch_profile_manifest.json

contrib/devtools/zkcoin_public_launch_profile.py \
  --set-snapshot-audit NETWORK <snapshot_audit.json> \
  --in-place contrib/devtools/zkcoin_public_launch_profile_manifest.json

contrib/devtools/zkcoin_public_launch_profile.py \
  --readiness-summary contrib/devtools/zkcoin_public_launch_profile_manifest.json

contrib/devtools/zkcoin_public_launch_profile.py \
  --blocker-readiness-summary NETWORK.litecoin_snapshot \
  contrib/devtools/zkcoin_public_launch_profile_manifest.json
```

Replace `NETWORK` with `main` or `testnet` after choosing the target profile.
Use the read-only `--check-snapshot-audit` command first to verify the audit
summary, source-chain mapping, snapshot file byte size, and snapshot file
SHA-256, then stage the candidate through launch-manifest validation without
modifying the manifest.
The read-only check also reports the exact apply command, remaining blocker
count, target-network remaining blocker count, overall and target-network
remaining blocked field counts, post-apply next-action command,
post-apply readiness summary command,
target-network readiness summary command, blocker-type readiness summary command,
next blocker, next check/apply commands, next network and blocker-type
readiness summary commands, and the
exact next `--blocker-readiness-summary` command that would remain after applying
the audit, so reviewers can confirm the handoff advances the expected profile
before any manifest write. After applying the audit summary, run `--readiness-summary`
to confirm the current blocker moved from the snapshot handoff to the next
production launch input.
The manifest handoff rejects reordered audit summaries when all expected fields
are present, so the reviewed artifact must keep the template order.
When `ZKCOIN_SNAPSHOT_AUDIT_JSON` is set, the operator script prints this
template command, the read-only check command, the follow-up update command,
the post-apply readiness summary command, and the blocker-scoped readiness
summary command
with the target profile derived from `source_chain` and the exact audit summary path filled in. Printed
snapshot and audit paths are shell-quoted when needed, so copy the generated
commands exactly. The operator creates the audit summary with an
exclusive final-path write, fsyncs the file and parent directory, and rejects final-path or
parent-directory symlink replacement before writing the handoff artifact.
The audit summary path itself must also be a direct file, not a symlink, when
it is applied to the launch profile. The manifest update opens the audit summary
and referenced snapshot artifact as regular files without following symlinks,
and rejects symlinked direct parent directories for both handoff inputs.
It also rejects audit summaries larger than 65536 bytes before parsing.
That size cap is enforced again while reading the already-open audit summary, so
a concurrently changed summary cannot grow past the limit after the initial file check.
The manifest update also rechecks the audit summary path after reading, rejecting
summary replacement or truncation before it parses launch metadata.
Audit summaries must be valid UTF-8 JSON; invalid byte sequences are rejected
with a stable operator-facing error before JSON parsing.
The manifest validator reads the verified `height`, `block_hash`, and `import_hash`
from the audit summary. It requires the audit-only `snapshot_hash`, coin count,
transaction count, `source_chain`, snapshot file byte size, snapshot file SHA-256,
an absolute snapshot file path, and positive decimal total amount with 8 fractional digits
that does not exceed `84000000.00000000`. The snapshot operator rejects verifier
`snapshot_hash` and `import_hash` values that are the null uint256 before writing
an audit summary. Hash fields must be exact 64-character lowercase hex strings;
the handoff does not silently normalize operator-edited uppercase hashes. The manifest update rejects audit
summaries with unexpected extra fields, so hand-edited or stale summaries do not
silently carry ignored launch values.
The stored snapshot file path must not contain control characters, preventing
operator-edited summaries from carrying multi-line or terminal-control paths into
the launch profile.
The snapshot operator and manifest handoff only accept positive coin and transaction counts
and integral source heights, and reject fractional values instead of rounding or truncating them.
The launch manifest validator also rejects JSON booleans in integer and byte
fields, because booleans are not valid production constants. It rejects
unexpected manifest keys so stale or hand-edited fields cannot silently shadow
the launch profile that will be emitted into `chainparams`.
Duplicate JSON fields are rejected in both the launch manifest and snapshot
audit summaries, so hand-edited values cannot be shadowed by later duplicate
keys.
The launch manifest must be valid UTF-8 JSON; invalid byte sequences are
reported as stable operator-facing errors instead of Python decode tracebacks.
It must not exceed 262144 bytes and is read from a direct parent directory as a
direct regular file, with the path rechecked before parsing so symlinked or
concurrently changed manifests do not feed launch-profile decisions.
The validator ensures malformed manifest sections are reported as validation errors
instead of operator-facing tool tracebacks.
Manifest update commands reject malformed sections before mutation, so operator
handoff commands do not partially rewrite a bad launch manifest.
In-place manifest writes reject symlinked manifest paths, symlinked parent directories, and pre-existing temp files
before writing the updated launch handoff.
They create the temp file and replacement through an opened parent directory descriptor,
so a parent-directory symlink swap cannot redirect the in-place update after preflight.
Successful in-place manifest writes also fsync their parent directory after replacement,
so the atomic rename is durable before the command exits.
Use one primary launch-profile action per invocation: update one blocker, mark
the reviewed manifest ready, emit chainparams, or check chainparams in separate
commands.
Before it clears the blocker, the update path verifies the local snapshot artifact size and SHA-256
against the audit summary and rejects symlinked snapshot artifacts and other non-file artifacts.
It also rejects an audit summary that names itself as the snapshot artifact.
It also rechecks the snapshot artifact path after hashing, rejecting artifact
replacement or truncation during verification before writing launch metadata.
The manifest update rejects a snapshot audit whose source chain does not match
the target profile: `main` requires Litecoin `main`, and `testnet` requires
Litecoin `test`.
The manifest stores those audit fields with the snapshot constants.
The validator removes only that network's snapshot blocker; the remaining AuxPoW,
DNS seed, and public identity blockers stay explicit until their production
values are selected.
Manual public snapshot constants are not accepted by the manifest update path;
use the verified audit summary so the launch handoff cannot be cleared from
copied or guessed values.

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

The preflight script exits successfully only when `getblockchaininfo.launch_readiness.ready` is `true`, which requires the node to still be at the genesis launch tip before block 1 is mined and to report a duplicate-free JSON object with a recognized `getblockchaininfo.chain` name, `getblockchaininfo.blocks=0`, `getblockchaininfo.headers=0`, `getblockchaininfo.bestblockhash` as a non-null lowercase 64-character launch-tip hash, `getblockchaininfo.chainwork` as a non-null lowercase 64-character accumulated-work value, non-negative numeric `getblockchaininfo.verificationprogress` not exceeding 1, non-negative numeric `getblockchaininfo.difficulty`, positive integer `getblockchaininfo.size_on_disk`, non-negative integer `getblockchaininfo.time`, `getblockchaininfo.mediantime` not greater than `time`, `getblockchaininfo.initialblockdownload=false`, `getblockchaininfo.pruned=false`, `getblockchaininfo.warnings=""`, `launch_readiness.chain_id_configured=true`, `launch_readiness.chain_id_parent_version_safe=true`, `auxpow.start_height=1`, `auxpow.parent_version_safe=true`, `launch_readiness.script_rules_active_at_launch=true`, `launch_readiness.chain_history_clean=true`, and `launch_readiness.public_network_identity_configured=true`. It cross-checks the detailed `ltc_snapshot`, `auxpow`, and `shielded_pool` sections against those readiness booleans, requires a positive snapshot height plus non-null lowercase snapshot block/import hashes when the snapshot is configured, rejects the local launch placeholder `0x5a4b` chain id, rejects `shielded_pool.start_height=1` while shielded transactions are inactive at launch, rejects malformed chain names, rejects launch-tip reports with headers beyond genesis, rejects malformed launch-tip hashes, chainwork, verification progress, difficulty, disk footprint reports, or launch-tip times, rejects nodes still in initial block download, rejects pruned launch nodes, rejects non-empty node warnings, and rejects in-progress snapshot imports. When public network identity is not configured, inspect `launch_readiness.public_network_identity` for inherited message-start, port, seed, Base58, Bech32, and MWEB HRP checks plus malformed message-start, reserved port, missing, malformed, reserved-suffix DNS seed, invalid or duplicate Base58 prefix, and non-distinct HRP failures. It also fails closed unless scaffold proofs are disabled, `shielded_pool.real_proof_backend` is `orchard-v1`, and `shielded_pool.real_proof_verification` is `true`.
