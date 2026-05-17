# zkCoin shielded verifier

This crate exposes the `zkc_shielded_verify_proof_v1`,
`zkc_shielded_verify_proof_v2`, `zkc_shielded_verify_proof_v3`,
`zkc_shielded_verify_bundle_v4`, and `zkc_shielded_verify_orchard_proof_v1`
C ABIs used by the C++ consensus shielded pool. The current v4 path moves
consensus toward the real verifier boundary: C++ computes the consensus
public-input hash, while Rust parses a versioned proof bundle and dispatches by
proof-system id.

The v4 bundle layout is:

```text
zkc-p4 || version || kind || proof_system || flags || public_input_hash || proof_len_le32 || proof_bytes
```

`proof_system = 1` is reserved for the Orchard verifier. For that proof system,
`proof_bytes` is itself a structured payload:

```text
zkc-orchard-proof-v1 || kind || public_input_hash || proof_body_len_le32 || proof_body
```

The `proof_body` is verified through the dedicated
`zkc_shielded_verify_orchard_proof_v1` ABI. It is also self-describing:

```text
zkc-orchard-body-v1 || mode || body_len_le32 || body
```

`mode = 0` is the deterministic scaffold mode. Unknown modes are rejected so
the consensus boundary can later add a real Orchard verification mode without
accepting ambiguous proof bytes. The scaffold body keeps local Litecoin snapshot
launch and Scrypt AuxPoW tests reproducible while the next milestone replaces
only that mode-specific body check with Orchard proof verification.

Run the Rust tests and C ABI smoke test with:

```sh
cargo test --locked
scripts/abi-smoke.sh
```
