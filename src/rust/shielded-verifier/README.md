# zkCoin shielded verifier

This crate exposes the `zkc_shielded_verify_proof_v1` C ABI used by the C++
consensus shielded pool. The current implementation is a deterministic scaffold
that verifies the proof payload committed by the C++ tests.

The ABI shape is intentionally stable for the next milestone: replacing this
payload check with an Orchard proof verifier without changing transaction
parsing, AuxPoW merge mining, or block-X snapshot import logic.
