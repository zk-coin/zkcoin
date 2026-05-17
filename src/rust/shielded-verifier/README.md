# zkCoin shielded verifier

This crate exposes the `zkc_shielded_verify_proof_v1`,
`zkc_shielded_verify_proof_v2`, `zkc_shielded_verify_proof_v3`,
`zkc_shielded_verify_bundle_v4`, `zkc_shielded_verify_orchard_proof_v1`, and
`zkc_shielded_verify_orchard_real_proof_v1` C ABIs used by the C++ consensus
shielded pool. A companion
`zkc_shielded_verify_orchard_real_proof_status_v1` ABI returns a typed status
for diagnostics and future verifier wiring, and
`zkc_shielded_orchard_real_proof_request_hash_v1` exposes the canonical backend
request fingerprint. `zkc_shielded_orchard_real_verifier_input_hash_v1` exposes
the proof-byte-independent verifier input digest that a native verifier should
bind to its public instance. `zkc_shielded_orchard_real_native_proof_hash_v1`
exposes the fingerprint of the decoded native proof bytes inside the versioned
native proof envelope. The `zkc_shielded_orchard_real_proof_check_v1` ABI
returns both the typed status and request fingerprint in one call. The v2 check
ABI adds the verifier-input fingerprint to that same atomic parse result. The
v3 check ABI also returns the native proof-byte fingerprint when the real proof
contains a structurally valid native proof packet.
`zkc_shielded_check_bundle_v4` extends the v1 contract to the full witness
bundle: it returns the parsed proof body mode, the typed status, and the
real-proof request fingerprint when the bundle contains native proof bytes.
`zkc_shielded_check_bundle_v5` extends the full-bundle check with the
verifier-input fingerprint, so callers do not need to peel the witness bundle
twice. `zkc_shielded_check_bundle_v6` adds the decoded native proof-byte
fingerprint to that same parse result. The current v4-v6 path moves consensus
toward the real verifier boundary: C++ computes the consensus public-input
hash, while Rust parses a versioned proof bundle and dispatches by
proof-system id.
Internally, real proof verification now goes through an explicit backend
adapter, so native Orchard verification can be wired behind the same request
contract without changing the consensus witness format again.
The default build remains fail-closed and reports the real-proof backend as
unsupported. For verifier-plumbing tests only, the Cargo feature
`verifier-fixture` switches the Rust crate to a deterministic fixture backend
that accepts native proof packets whose inner payload has the form:

```text
zkc-orchard-fixture-proof-v1 || verifier_input_hash
```

That fixture is nested inside the same `zkc-orchard-native-proof-v1` envelope
used by production verifier packets. It proves the public ABI, bundle parser,
request hash, verifier-key binding, and verifier input hash can return `valid`
through the same native-verifier boundary. It is not a production cryptographic
proof system and is intentionally excluded from normal node builds.
`scripts/fixture-consensus-smoke.sh` links that fixture backend into a
standalone C++ consensus smoke test and proves a real-mode shielded mint and
spend witness are accepted with scaffold proofs disabled, while tampered
real-mode proofs are still rejected.
C++ transaction consensus now checks witness envelopes through the v6 bundle
boundary, so accepted real-mode fixture proofs and rejected production
unsupported proofs exercise the same verifier-input and native proof digest
path.

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

The nested `proof_bytes` field is also versioned before it can reach the native
backend:

```text
zkc-orchard-native-proof-v1 || flags || verifier_key_hash || verifier_input_hash || native_proof_len_le32 || native_proof_bytes
```

The default unsupported backend returns `unsupported` only for that structurally
native proof envelope. Arbitrary raw proof bytes inside `zkc-orchard-real-v1`
are parsed, fingerprinted, and rejected as `invalid`, which keeps the production
boundary fail-closed while preserving a stable place to wire the cryptographic
Orchard verifier. The duplicated verifier-key commitment is checked against the
outer real-proof envelope before dispatch, so the backend receives a
self-contained verifier packet and cannot accidentally verify against a
different proving-key identity.

Unknown modes, unknown flags, wrong proof kinds, wrong public inputs, wrong
verifier-key commitments, non-native proof bytes, and malformed lengths are
rejected. The real-proof backend still returns unsupported until the Orchard
verifier is wired; this keeps local Litecoin snapshot launch and Scrypt AuxPoW
tests reproducible while preventing placeholder proof bytes from being accepted
as production proofs.
After parsing, the Rust verifier hands the backend a typed request containing
the action kind, consensus public-input hash, verifier-key commitment, and raw
proof bytes.
That request also has a canonical `zkc-orchard-real-request-v1` fingerprint:

```text
Hash256("zkc-orchard-real-request-v1" || kind || public_input_hash || verifier_key_hash || proof_len_le32 || proof_bytes)
```

The verifier input has a separate canonical `zkc-orchard-real-input-v1`
fingerprint that deliberately excludes the raw proof bytes:

```text
Hash256("zkc-orchard-real-input-v1" || kind || public_input_hash || verifier_key_hash)
```

Structurally valid native proof packets also have a canonical
`zkc-orchard-native-proof-hash-v1` fingerprint of the decoded proof bytes:

```text
Hash256("zkc-orchard-native-proof-hash-v1" || verifier_key_hash || verifier_input_hash || native_proof_len_le32 || native_proof_bytes)
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
cargo test --locked --features verifier-fixture
scripts/abi-smoke.sh
scripts/fixture-consensus-smoke.sh
```
