# zkCoin shielded verifier

This crate exposes the `zkc_shielded_verify_proof_v1` and
`zkc_shielded_verify_proof_v2` C ABIs used by the C++ consensus shielded pool.
The current implementation is a deterministic scaffold that verifies the proof
payload committed by the C++ tests. The v2 ABI additionally binds the proof kind
so mint and spend witnesses live in separate verifier domains.

The ABI shape is intentionally stable for the next milestone: replacing this
payload check with an Orchard proof verifier without changing transaction
parsing, AuxPoW merge mining, or block-X snapshot import logic.

Run the Rust tests and C ABI smoke test with:

```sh
cargo test --locked
scripts/abi-smoke.sh
```
