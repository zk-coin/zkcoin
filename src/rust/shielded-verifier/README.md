# zkCoin shielded verifier

This crate exposes the `zkc_shielded_verify_proof_v1`,
`zkc_shielded_verify_proof_v2`, and `zkc_shielded_verify_proof_v3` C ABIs used
by the C++ consensus shielded pool. The current implementation is a
deterministic scaffold that verifies the proof payload committed by the C++
tests. The v3 ABI binds the proof kind to a consensus public-input hash, so the
C++ transaction parser can hand Rust one stable verifier digest before the
scaffold is replaced by an Orchard or Sapling verifier.

The ABI shape is intentionally stable for the next milestone: replacing this
payload check with an Orchard proof verifier without changing transaction
parsing, AuxPoW merge mining, or block-X snapshot import logic.

Run the Rust tests and C ABI smoke test with:

```sh
cargo test --locked
scripts/abi-smoke.sh
```
