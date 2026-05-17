# zkCoin shielded verifier

This crate exposes the `zkc_shielded_verify_proof_v1`,
`zkc_shielded_verify_proof_v2`, `zkc_shielded_verify_proof_v3`,
`zkc_shielded_verify_bundle_v4`, `zkc_shielded_verify_orchard_proof_v1`, and
`zkc_shielded_verify_orchard_real_proof_v1` C ABIs used by the C++ consensus
shielded pool. A companion
`zkc_shielded_verify_orchard_real_proof_status_v1` ABI returns a typed status
for diagnostics and future verifier wiring, and
`zkc_shielded_orchard_real_proof_request_hash_v1` exposes the canonical backend
request fingerprint. The `zkc_shielded_orchard_real_proof_check_v1` ABI returns
both the typed status and request fingerprint in one call, which is the stable
boundary a native verifier backend must preserve. `zkc_shielded_check_bundle_v4`
extends that contract to the full witness bundle: it returns the parsed proof
body mode, the typed status, and the real-proof request fingerprint when the
bundle contains native proof bytes. The current v4 path moves consensus toward
the real verifier boundary: C++ computes the consensus public-input hash, while
Rust parses a versioned proof bundle and dispatches by proof-system id.

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

`mode = 0` is the deterministic scaffold mode. `mode = 1` is reserved for
native Orchard-style proof bytes and contains another typed envelope:

```text
zkc-orchard-real-v1 || flags || kind || public_input_hash || verifier_key_hash || proof_len_le32 || proof_bytes
```

Unknown modes, unknown flags, wrong proof kinds, wrong public inputs, wrong
verifier-key commitments, and malformed lengths are rejected. The real-proof
backend still returns unsupported until the Orchard verifier is wired; this
keeps local Litecoin snapshot launch and Scrypt AuxPoW tests reproducible while
preventing placeholder proof bytes from being accepted as production proofs.
After parsing, the Rust verifier hands the backend a typed request containing
the action kind, consensus public-input hash, verifier-key commitment, and raw
proof bytes.
That request also has a canonical `zkc-orchard-real-request-v1` fingerprint:

```text
Hash256("zkc-orchard-real-request-v1" || kind || public_input_hash || verifier_key_hash || proof_len_le32 || proof_bytes)
```

The real-proof status ABI returns `1` for a valid proof, `0` for malformed
bytes or context mismatch, `-1` for a parsed but invalid proof, and `-2` when a
well-formed proof reaches a verifier backend that has not been wired yet.
The backend capability ABI returns `0` for the current unsupported backend and
`1` for the reserved native `orchard-v1` backend; nodes also expose this in
`getblockchaininfo.shielded_pool` so launch/regression tests can prove whether
real proof verification is actually linked.

Run the Rust tests and C ABI smoke test with:

```sh
cargo test --locked
scripts/abi-smoke.sh
```
