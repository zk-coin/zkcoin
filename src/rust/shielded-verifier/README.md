# zkCoin shielded verifier

This crate exposes the `zkc_shielded_verify_proof_v1`,
`zkc_shielded_verify_proof_v2`, `zkc_shielded_verify_proof_v3`, and
`zkc_shielded_verify_bundle_v4` C ABIs used by the C++ consensus shielded pool.
The current v4 path moves consensus toward the real verifier boundary: C++
computes the consensus public-input hash, while Rust parses a versioned proof
bundle and dispatches by proof-system id.

The v4 bundle layout is:

```text
zkc-p4 || version || kind || proof_system || flags || public_input_hash || proof_len_le32 || proof_bytes
```

`proof_system = 1` is reserved for the Orchard verifier. The current proof bytes
remain a deterministic boundary payload so the consensus plumbing, local
Litecoin snapshot launch, and Scrypt AuxPoW tests stay reproducible while the
next milestone replaces that payload check with Orchard proof verification.

Run the Rust tests and C ABI smoke test with:

```sh
cargo test --locked
scripts/abi-smoke.sh
```
