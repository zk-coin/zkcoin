// Copyright (c) 2026 The zkCoin developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

use core::slice;
use sha2::{Digest, Sha256};

const HASH_SIZE: usize = 32;
const PROOF_ENVELOPE_PREIMAGE_PREFIX: &[u8] = b"zkc-proof-envelope-v1";
const PROOF_ENVELOPE_PREIMAGE_PREFIX_V2: &[u8] = b"zkc-proof-envelope-v2";
const PROOF_PUBLIC_INPUT_PREIMAGE_PREFIX: &[u8] = b"zkc-public-input-v1";
const PROOF_ENVELOPE_PREIMAGE_PREFIX_V3: &[u8] = b"zkc-proof-envelope-v3";
const PROOF_BUNDLE_PREFIX_V4: &[u8] = b"zkc-p4";
const PROOF_BUNDLE_PREIMAGE_PREFIX_V4: &[u8] = b"zkc-proof-bundle-v4";
const ORCHARD_PROOF_PAYLOAD_PREFIX_V1: &[u8] = b"zkc-orchard-proof-v1";
const ORCHARD_PROOF_BODY_PREFIX_V1: &[u8] = b"zkc-orchard-body-v1";
const ORCHARD_REAL_PROOF_PREFIX_V1: &[u8] = b"zkc-orchard-real-v1";
const ORCHARD_REAL_NATIVE_PROOF_PREFIX_V1: &[u8] = b"zkc-orchard-native-proof-v1";
const ORCHARD_REAL_NATIVE_PROOF_HASH_PREIMAGE_PREFIX_V1: &[u8] =
    b"zkc-orchard-native-proof-hash-v1";
const ORCHARD_REAL_PROOF_REQUEST_PREIMAGE_PREFIX_V1: &[u8] = b"zkc-orchard-real-request-v1";
const ORCHARD_REAL_VERIFIER_INPUT_PREIMAGE_PREFIX_V1: &[u8] = b"zkc-orchard-real-input-v1";
const ORCHARD_REAL_VERIFIER_KEY_HASH_PREIMAGE_PREFIX_V1: &[u8] = b"zkc-orchard-real-vk-v1";
#[cfg(feature = "verifier-fixture")]
const ORCHARD_REAL_FIXTURE_PROOF_PREFIX_V1: &[u8] = b"zkc-orchard-fixture-proof-v1";
const PROOF_BUNDLE_VERSION_V4: u8 = 1;
const PROOF_SYSTEM_ORCHARD: u8 = 1;
const PROOF_BUNDLE_FLAGS_NONE: u8 = 0;
const ORCHARD_PROOF_BODY_MODE_SCAFFOLD: u8 = 0;
const ORCHARD_PROOF_BODY_MODE_REAL: u8 = 1;
pub const ORCHARD_REAL_PROOF_STATUS_MALFORMED: i32 = 0;
pub const ORCHARD_REAL_PROOF_STATUS_VALID: i32 = 1;
pub const ORCHARD_REAL_PROOF_STATUS_INVALID: i32 = -1;
pub const ORCHARD_REAL_PROOF_STATUS_UNSUPPORTED: i32 = -2;
pub const ORCHARD_REAL_VERIFIER_BACKEND_UNSUPPORTED: i32 = 0;
pub const ORCHARD_REAL_VERIFIER_BACKEND_ORCHARD_V1: i32 = 1;
const PROOF_BUNDLE_HEADER_LEN_V4: usize =
    6 + 1 + 1 + 1 + 1 + HASH_SIZE + core::mem::size_of::<u32>();
const ORCHARD_PROOF_PAYLOAD_HEADER_LEN_V1: usize =
    ORCHARD_PROOF_PAYLOAD_PREFIX_V1.len() + 1 + HASH_SIZE + core::mem::size_of::<u32>();
const ORCHARD_PROOF_BODY_HEADER_LEN_V1: usize =
    ORCHARD_PROOF_BODY_PREFIX_V1.len() + 1 + core::mem::size_of::<u32>();
const ORCHARD_REAL_PROOF_HEADER_LEN_V1: usize = ORCHARD_REAL_PROOF_PREFIX_V1.len()
    + 1
    + 1
    + HASH_SIZE
    + HASH_SIZE
    + core::mem::size_of::<u32>();
const ORCHARD_REAL_NATIVE_PROOF_HEADER_LEN_V1: usize = ORCHARD_REAL_NATIVE_PROOF_PREFIX_V1.len()
    + 1
    + HASH_SIZE
    + HASH_SIZE
    + core::mem::size_of::<u32>();
#[cfg(feature = "verifier-fixture")]
const ORCHARD_REAL_FIXTURE_PROOF_LEN_V1: usize =
    ORCHARD_REAL_FIXTURE_PROOF_PREFIX_V1.len() + HASH_SIZE;

fn hash256(data: &[u8]) -> [u8; HASH_SIZE] {
    let first = Sha256::digest(data);
    let second = Sha256::digest(first);
    second.into()
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum OrchardRealProofStatus {
    Valid,
    Malformed,
    Invalid,
    Unsupported,
}

impl OrchardRealProofStatus {
    pub fn as_ffi_code(self) -> i32 {
        match self {
            OrchardRealProofStatus::Valid => ORCHARD_REAL_PROOF_STATUS_VALID,
            OrchardRealProofStatus::Malformed => ORCHARD_REAL_PROOF_STATUS_MALFORMED,
            OrchardRealProofStatus::Invalid => ORCHARD_REAL_PROOF_STATUS_INVALID,
            OrchardRealProofStatus::Unsupported => ORCHARD_REAL_PROOF_STATUS_UNSUPPORTED,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum OrchardRealVerifierBackend {
    Unsupported,
    OrchardV1,
}

impl OrchardRealVerifierBackend {
    pub fn as_ffi_code(self) -> i32 {
        match self {
            OrchardRealVerifierBackend::Unsupported => ORCHARD_REAL_VERIFIER_BACKEND_UNSUPPORTED,
            OrchardRealVerifierBackend::OrchardV1 => ORCHARD_REAL_VERIFIER_BACKEND_ORCHARD_V1,
        }
    }

    pub fn supports_real_proofs(self) -> bool {
        matches!(self, OrchardRealVerifierBackend::OrchardV1)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct OrchardRealProofRequest<'a> {
    pub proof_kind: u8,
    pub public_input_hash: [u8; HASH_SIZE],
    pub verifier_key_hash: [u8; HASH_SIZE],
    pub proof_bytes: &'a [u8],
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct OrchardRealVerifierInput {
    pub proof_kind: u8,
    pub public_input_hash: [u8; HASH_SIZE],
    pub verifier_key_hash: [u8; HASH_SIZE],
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct OrchardNativeProof<'a> {
    pub verifier_key_hash: [u8; HASH_SIZE],
    pub verifier_input_hash: [u8; HASH_SIZE],
    pub proof_bytes: &'a [u8],
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct OrchardRealProofCheck {
    pub status: OrchardRealProofStatus,
    pub request_hash: Option<[u8; HASH_SIZE]>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct OrchardRealProofCheckV2 {
    pub status: OrchardRealProofStatus,
    pub request_hash: Option<[u8; HASH_SIZE]>,
    pub verifier_input_hash: Option<[u8; HASH_SIZE]>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct OrchardRealProofCheckV3 {
    pub status: OrchardRealProofStatus,
    pub request_hash: Option<[u8; HASH_SIZE]>,
    pub verifier_input_hash: Option<[u8; HASH_SIZE]>,
    pub native_proof_hash: Option<[u8; HASH_SIZE]>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ProofBundleCheck {
    pub status: OrchardRealProofStatus,
    pub proof_body_mode: Option<u8>,
    pub real_request_hash: Option<[u8; HASH_SIZE]>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ProofBundleCheckV2 {
    pub status: OrchardRealProofStatus,
    pub proof_body_mode: Option<u8>,
    pub real_request_hash: Option<[u8; HASH_SIZE]>,
    pub real_verifier_input_hash: Option<[u8; HASH_SIZE]>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ProofBundleCheckV3 {
    pub status: OrchardRealProofStatus,
    pub proof_body_mode: Option<u8>,
    pub real_request_hash: Option<[u8; HASH_SIZE]>,
    pub real_verifier_input_hash: Option<[u8; HASH_SIZE]>,
    pub real_native_proof_hash: Option<[u8; HASH_SIZE]>,
}

impl From<OrchardRealProofCheckV2> for OrchardRealProofCheck {
    fn from(check: OrchardRealProofCheckV2) -> Self {
        Self {
            status: check.status,
            request_hash: check.request_hash,
        }
    }
}

impl From<OrchardRealProofCheckV3> for OrchardRealProofCheckV2 {
    fn from(check: OrchardRealProofCheckV3) -> Self {
        Self {
            status: check.status,
            request_hash: check.request_hash,
            verifier_input_hash: check.verifier_input_hash,
        }
    }
}

impl From<ProofBundleCheckV2> for ProofBundleCheck {
    fn from(check: ProofBundleCheckV2) -> Self {
        Self {
            status: check.status,
            proof_body_mode: check.proof_body_mode,
            real_request_hash: check.real_request_hash,
        }
    }
}

impl From<ProofBundleCheckV3> for ProofBundleCheckV2 {
    fn from(check: ProofBundleCheckV3) -> Self {
        Self {
            status: check.status,
            proof_body_mode: check.proof_body_mode,
            real_request_hash: check.real_request_hash,
            real_verifier_input_hash: check.real_verifier_input_hash,
        }
    }
}

#[cfg(all(test, not(feature = "verifier-fixture")))]
impl ProofBundleCheck {
    fn malformed() -> Self {
        Self {
            status: OrchardRealProofStatus::Malformed,
            proof_body_mode: None,
            real_request_hash: None,
        }
    }
}

impl ProofBundleCheckV3 {
    fn malformed() -> Self {
        Self {
            status: OrchardRealProofStatus::Malformed,
            proof_body_mode: None,
            real_request_hash: None,
            real_verifier_input_hash: None,
            real_native_proof_hash: None,
        }
    }

    fn with_mode(status: OrchardRealProofStatus, proof_body_mode: u8) -> Self {
        Self {
            status,
            proof_body_mode: Some(proof_body_mode),
            real_request_hash: None,
            real_verifier_input_hash: None,
            real_native_proof_hash: None,
        }
    }
}

trait OrchardRealProofBackend {
    fn backend(&self) -> OrchardRealVerifierBackend;
    fn verify(&self, request: &OrchardRealProofRequest<'_>) -> OrchardRealProofStatus;
}

#[cfg(not(feature = "verifier-fixture"))]
struct UnsupportedOrchardRealProofBackend;

#[cfg(not(feature = "verifier-fixture"))]
impl OrchardRealProofBackend for UnsupportedOrchardRealProofBackend {
    fn backend(&self) -> OrchardRealVerifierBackend {
        OrchardRealVerifierBackend::Unsupported
    }

    fn verify(&self, request: &OrchardRealProofRequest<'_>) -> OrchardRealProofStatus {
        if decode_orchard_native_proof_bytes_v1(request).is_some() {
            OrchardRealProofStatus::Unsupported
        } else {
            OrchardRealProofStatus::Invalid
        }
    }
}

#[cfg(feature = "verifier-fixture")]
struct FixtureOrchardRealProofBackend;

#[cfg(feature = "verifier-fixture")]
impl OrchardRealProofBackend for FixtureOrchardRealProofBackend {
    fn backend(&self) -> OrchardRealVerifierBackend {
        OrchardRealVerifierBackend::OrchardV1
    }

    fn verify(&self, request: &OrchardRealProofRequest<'_>) -> OrchardRealProofStatus {
        let Some(native_proof) = decode_orchard_native_proof_bytes_v1(request) else {
            return OrchardRealProofStatus::Invalid;
        };
        if native_proof.proof_bytes.len() != ORCHARD_REAL_FIXTURE_PROOF_LEN_V1 {
            return OrchardRealProofStatus::Invalid;
        }
        if !native_proof
            .proof_bytes
            .starts_with(ORCHARD_REAL_FIXTURE_PROOF_PREFIX_V1)
        {
            return OrchardRealProofStatus::Invalid;
        }

        let input_hash_offset = ORCHARD_REAL_FIXTURE_PROOF_PREFIX_V1.len();
        let fixture_input_hash: [u8; HASH_SIZE] = native_proof.proof_bytes
            [input_hash_offset..input_hash_offset + HASH_SIZE]
            .try_into()
            .expect("fixture proof input hash has fixed length");
        if fixture_input_hash == native_proof.verifier_input_hash {
            OrchardRealProofStatus::Valid
        } else {
            OrchardRealProofStatus::Invalid
        }
    }
}

fn default_orchard_real_proof_backend_v1() -> impl OrchardRealProofBackend {
    #[cfg(feature = "verifier-fixture")]
    {
        FixtureOrchardRealProofBackend
    }
    #[cfg(not(feature = "verifier-fixture"))]
    {
        UnsupportedOrchardRealProofBackend
    }
}

impl OrchardRealProofRequest<'_> {
    pub fn verifier_input(&self) -> OrchardRealVerifierInput {
        OrchardRealVerifierInput {
            proof_kind: self.proof_kind,
            public_input_hash: self.public_input_hash,
            verifier_key_hash: self.verifier_key_hash,
        }
    }

    pub fn verifier_input_hash_v1(&self) -> [u8; HASH_SIZE] {
        self.verifier_input().input_hash_v1()
    }

    pub fn request_hash_v1(&self) -> [u8; HASH_SIZE] {
        let proof_len: u32 = self
            .proof_bytes
            .len()
            .try_into()
            .expect("proof request length fits in v1 envelope");
        let mut preimage = Vec::with_capacity(
            ORCHARD_REAL_PROOF_REQUEST_PREIMAGE_PREFIX_V1.len()
                + 1
                + HASH_SIZE
                + HASH_SIZE
                + core::mem::size_of::<u32>()
                + self.proof_bytes.len(),
        );
        preimage.extend_from_slice(ORCHARD_REAL_PROOF_REQUEST_PREIMAGE_PREFIX_V1);
        preimage.push(self.proof_kind);
        preimage.extend_from_slice(&self.public_input_hash);
        preimage.extend_from_slice(&self.verifier_key_hash);
        preimage.extend_from_slice(&proof_len.to_le_bytes());
        preimage.extend_from_slice(self.proof_bytes);
        hash256(&preimage)
    }
}

impl OrchardRealVerifierInput {
    pub fn input_hash_v1(&self) -> [u8; HASH_SIZE] {
        let mut preimage = Vec::with_capacity(
            ORCHARD_REAL_VERIFIER_INPUT_PREIMAGE_PREFIX_V1.len() + 1 + HASH_SIZE + HASH_SIZE,
        );
        preimage.extend_from_slice(ORCHARD_REAL_VERIFIER_INPUT_PREIMAGE_PREFIX_V1);
        preimage.push(self.proof_kind);
        preimage.extend_from_slice(&self.public_input_hash);
        preimage.extend_from_slice(&self.verifier_key_hash);
        hash256(&preimage)
    }
}

impl OrchardNativeProof<'_> {
    pub fn proof_hash_v1(&self) -> [u8; HASH_SIZE] {
        let proof_len: u32 = self
            .proof_bytes
            .len()
            .try_into()
            .expect("native proof length fits in v1 envelope");
        let mut preimage = Vec::with_capacity(
            ORCHARD_REAL_NATIVE_PROOF_HASH_PREIMAGE_PREFIX_V1.len()
                + HASH_SIZE
                + HASH_SIZE
                + core::mem::size_of::<u32>()
                + self.proof_bytes.len(),
        );
        preimage.extend_from_slice(ORCHARD_REAL_NATIVE_PROOF_HASH_PREIMAGE_PREFIX_V1);
        preimage.extend_from_slice(&self.verifier_key_hash);
        preimage.extend_from_slice(&self.verifier_input_hash);
        preimage.extend_from_slice(&proof_len.to_le_bytes());
        preimage.extend_from_slice(self.proof_bytes);
        hash256(&preimage)
    }
}

pub fn expected_proof_payload_v1(
    field_hash: &[u8; HASH_SIZE],
    tx_binding_hash: &[u8; HASH_SIZE],
) -> [u8; HASH_SIZE] {
    let mut preimage =
        Vec::with_capacity(PROOF_ENVELOPE_PREIMAGE_PREFIX.len() + HASH_SIZE + HASH_SIZE);
    preimage.extend_from_slice(PROOF_ENVELOPE_PREIMAGE_PREFIX);
    preimage.extend_from_slice(field_hash);
    preimage.extend_from_slice(tx_binding_hash);
    hash256(&preimage)
}

pub fn expected_proof_payload_v2(
    proof_kind: u8,
    field_hash: &[u8; HASH_SIZE],
    tx_binding_hash: &[u8; HASH_SIZE],
) -> [u8; HASH_SIZE] {
    let mut preimage =
        Vec::with_capacity(PROOF_ENVELOPE_PREIMAGE_PREFIX_V2.len() + 1 + HASH_SIZE + HASH_SIZE);
    preimage.extend_from_slice(PROOF_ENVELOPE_PREIMAGE_PREFIX_V2);
    preimage.push(proof_kind);
    preimage.extend_from_slice(field_hash);
    preimage.extend_from_slice(tx_binding_hash);
    hash256(&preimage)
}

pub fn proof_public_input_hash(
    proof_kind: u8,
    field_hash: &[u8; HASH_SIZE],
    tx_binding_hash: &[u8; HASH_SIZE],
) -> [u8; HASH_SIZE] {
    let mut preimage =
        Vec::with_capacity(PROOF_PUBLIC_INPUT_PREIMAGE_PREFIX.len() + 1 + HASH_SIZE + HASH_SIZE);
    preimage.extend_from_slice(PROOF_PUBLIC_INPUT_PREIMAGE_PREFIX);
    preimage.push(proof_kind);
    preimage.extend_from_slice(field_hash);
    preimage.extend_from_slice(tx_binding_hash);
    hash256(&preimage)
}

pub fn expected_proof_payload_v3(
    proof_kind: u8,
    public_input_hash: &[u8; HASH_SIZE],
) -> [u8; HASH_SIZE] {
    let mut preimage = Vec::with_capacity(PROOF_ENVELOPE_PREIMAGE_PREFIX_V3.len() + 1 + HASH_SIZE);
    preimage.extend_from_slice(PROOF_ENVELOPE_PREIMAGE_PREFIX_V3);
    preimage.push(proof_kind);
    preimage.extend_from_slice(public_input_hash);
    hash256(&preimage)
}

pub fn expected_proof_payload_v4(
    proof_kind: u8,
    public_input_hash: &[u8; HASH_SIZE],
) -> [u8; HASH_SIZE] {
    let mut preimage = Vec::with_capacity(PROOF_BUNDLE_PREIMAGE_PREFIX_V4.len() + 4 + HASH_SIZE);
    preimage.extend_from_slice(PROOF_BUNDLE_PREIMAGE_PREFIX_V4);
    preimage.push(PROOF_BUNDLE_VERSION_V4);
    preimage.push(proof_kind);
    preimage.push(PROOF_SYSTEM_ORCHARD);
    preimage.push(PROOF_BUNDLE_FLAGS_NONE);
    preimage.extend_from_slice(public_input_hash);
    hash256(&preimage)
}

pub fn expected_orchard_real_verifier_key_hash_v1() -> [u8; HASH_SIZE] {
    hash256(ORCHARD_REAL_VERIFIER_KEY_HASH_PREIMAGE_PREFIX_V1)
}

pub fn build_orchard_real_proof_v1(
    proof_kind: u8,
    public_input_hash: &[u8; HASH_SIZE],
    proof_bytes: &[u8],
) -> Vec<u8> {
    let verifier_key_hash = expected_orchard_real_verifier_key_hash_v1();
    let mut proof = Vec::with_capacity(ORCHARD_REAL_PROOF_HEADER_LEN_V1 + proof_bytes.len());
    proof.extend_from_slice(ORCHARD_REAL_PROOF_PREFIX_V1);
    proof.push(PROOF_BUNDLE_FLAGS_NONE);
    proof.push(proof_kind);
    proof.extend_from_slice(public_input_hash);
    proof.extend_from_slice(&verifier_key_hash);
    proof.extend_from_slice(&(proof_bytes.len() as u32).to_le_bytes());
    proof.extend_from_slice(proof_bytes);
    proof
}

pub fn build_orchard_native_proof_bytes_v1(
    input: &OrchardRealVerifierInput,
    proof_bytes: &[u8],
) -> Vec<u8> {
    let verifier_input_hash = input.input_hash_v1();
    let mut proof = Vec::with_capacity(ORCHARD_REAL_NATIVE_PROOF_HEADER_LEN_V1 + proof_bytes.len());
    proof.extend_from_slice(ORCHARD_REAL_NATIVE_PROOF_PREFIX_V1);
    proof.push(PROOF_BUNDLE_FLAGS_NONE);
    proof.extend_from_slice(&input.verifier_key_hash);
    proof.extend_from_slice(&verifier_input_hash);
    proof.extend_from_slice(&(proof_bytes.len() as u32).to_le_bytes());
    proof.extend_from_slice(proof_bytes);
    proof
}

#[cfg(feature = "verifier-fixture")]
pub fn build_orchard_fixture_proof_bytes_v1(input: &OrchardRealVerifierInput) -> Vec<u8> {
    let input_hash = input.input_hash_v1();
    let mut fixture_payload = Vec::with_capacity(ORCHARD_REAL_FIXTURE_PROOF_LEN_V1);
    fixture_payload.extend_from_slice(ORCHARD_REAL_FIXTURE_PROOF_PREFIX_V1);
    fixture_payload.extend_from_slice(&input_hash);
    build_orchard_native_proof_bytes_v1(input, &fixture_payload)
}

pub fn decode_orchard_real_proof_v1<'a>(
    proof: &'a [u8],
    proof_kind: u8,
    public_input_hash: &[u8; HASH_SIZE],
) -> Option<&'a [u8]> {
    decode_orchard_real_proof_request_v1(proof, proof_kind, public_input_hash)
        .map(|request| request.proof_bytes)
}

pub fn decode_orchard_real_proof_request_v1<'a>(
    proof: &'a [u8],
    proof_kind: u8,
    public_input_hash: &[u8; HASH_SIZE],
) -> Option<OrchardRealProofRequest<'a>> {
    if proof.len() < ORCHARD_REAL_PROOF_HEADER_LEN_V1 {
        return None;
    }
    if !proof.starts_with(ORCHARD_REAL_PROOF_PREFIX_V1) {
        return None;
    }

    let flags_offset = ORCHARD_REAL_PROOF_PREFIX_V1.len();
    let kind_offset = flags_offset + 1;
    let public_input_offset = kind_offset + 1;
    let verifier_key_hash_offset = public_input_offset + HASH_SIZE;
    let proof_len_offset = verifier_key_hash_offset + HASH_SIZE;
    let proof_offset = proof_len_offset + core::mem::size_of::<u32>();

    if proof[flags_offset] != PROOF_BUNDLE_FLAGS_NONE {
        return None;
    }
    if proof[kind_offset] != proof_kind {
        return None;
    }
    if &proof[public_input_offset..verifier_key_hash_offset] != public_input_hash {
        return None;
    }
    let verifier_key_hash: [u8; HASH_SIZE] = proof[verifier_key_hash_offset..proof_len_offset]
        .try_into()
        .expect("verifier key hash slice has fixed length");
    if verifier_key_hash != expected_orchard_real_verifier_key_hash_v1() {
        return None;
    }

    let proof_len = u32::from_le_bytes(
        proof[proof_len_offset..proof_offset]
            .try_into()
            .expect("proof length slice has fixed length"),
    ) as usize;
    if proof_len != proof.len() - proof_offset {
        return None;
    }

    Some(OrchardRealProofRequest {
        proof_kind,
        public_input_hash: *public_input_hash,
        verifier_key_hash,
        proof_bytes: &proof[proof_offset..],
    })
}

pub fn decode_orchard_native_proof_bytes_v1<'a>(
    request: &OrchardRealProofRequest<'a>,
) -> Option<OrchardNativeProof<'a>> {
    let proof = request.proof_bytes;
    if proof.len() < ORCHARD_REAL_NATIVE_PROOF_HEADER_LEN_V1 {
        return None;
    }
    if !proof.starts_with(ORCHARD_REAL_NATIVE_PROOF_PREFIX_V1) {
        return None;
    }

    let flags_offset = ORCHARD_REAL_NATIVE_PROOF_PREFIX_V1.len();
    let verifier_key_hash_offset = flags_offset + 1;
    let verifier_input_offset = verifier_key_hash_offset + HASH_SIZE;
    let proof_len_offset = verifier_input_offset + HASH_SIZE;
    let proof_offset = proof_len_offset + core::mem::size_of::<u32>();
    if proof[flags_offset] != PROOF_BUNDLE_FLAGS_NONE {
        return None;
    }

    let verifier_key_hash: [u8; HASH_SIZE] = proof[verifier_key_hash_offset..verifier_input_offset]
        .try_into()
        .expect("verifier key hash slice has fixed length");
    if verifier_key_hash != request.verifier_key_hash {
        return None;
    }

    let verifier_input_hash: [u8; HASH_SIZE] = proof[verifier_input_offset..proof_len_offset]
        .try_into()
        .expect("verifier input hash slice has fixed length");
    if verifier_input_hash != request.verifier_input_hash_v1() {
        return None;
    }

    let proof_len = u32::from_le_bytes(
        proof[proof_len_offset..proof_offset]
            .try_into()
            .expect("native proof length slice has fixed length"),
    ) as usize;
    if proof_len == 0 || proof_len != proof.len() - proof_offset {
        return None;
    }

    Some(OrchardNativeProof {
        verifier_key_hash,
        verifier_input_hash,
        proof_bytes: &proof[proof_offset..],
    })
}

pub fn is_well_formed_orchard_real_proof_v1(
    proof: &[u8],
    proof_kind: u8,
    public_input_hash: &[u8; HASH_SIZE],
) -> bool {
    decode_orchard_real_proof_v1(proof, proof_kind, public_input_hash).is_some()
}

pub fn orchard_real_proof_request_hash_v1(
    proof: &[u8],
    proof_kind: u8,
    public_input_hash: &[u8; HASH_SIZE],
) -> Option<[u8; HASH_SIZE]> {
    decode_orchard_real_proof_request_v1(proof, proof_kind, public_input_hash)
        .map(|request| request.request_hash_v1())
}

pub fn orchard_real_verifier_input_hash_v1(
    proof: &[u8],
    proof_kind: u8,
    public_input_hash: &[u8; HASH_SIZE],
) -> Option<[u8; HASH_SIZE]> {
    decode_orchard_real_proof_request_v1(proof, proof_kind, public_input_hash)
        .map(|request| request.verifier_input_hash_v1())
}

pub fn orchard_real_native_proof_hash_v1(
    proof: &[u8],
    proof_kind: u8,
    public_input_hash: &[u8; HASH_SIZE],
) -> Option<[u8; HASH_SIZE]> {
    let request = decode_orchard_real_proof_request_v1(proof, proof_kind, public_input_hash)?;
    decode_orchard_native_proof_bytes_v1(&request).map(|native_proof| native_proof.proof_hash_v1())
}

pub fn orchard_real_proof_check_v1(
    proof: &[u8],
    proof_kind: u8,
    public_input_hash: &[u8; HASH_SIZE],
) -> OrchardRealProofCheck {
    orchard_real_proof_check_v2(proof, proof_kind, public_input_hash).into()
}

pub fn orchard_real_proof_check_v2(
    proof: &[u8],
    proof_kind: u8,
    public_input_hash: &[u8; HASH_SIZE],
) -> OrchardRealProofCheckV2 {
    orchard_real_proof_check_v3(proof, proof_kind, public_input_hash).into()
}

pub fn orchard_real_proof_check_v3(
    proof: &[u8],
    proof_kind: u8,
    public_input_hash: &[u8; HASH_SIZE],
) -> OrchardRealProofCheckV3 {
    let backend = default_orchard_real_proof_backend_v1();
    orchard_real_proof_check_with_backend_v3(proof, proof_kind, public_input_hash, &backend)
}

#[cfg(all(test, not(feature = "verifier-fixture")))]
fn orchard_real_proof_check_with_backend_v1<B: OrchardRealProofBackend>(
    proof: &[u8],
    proof_kind: u8,
    public_input_hash: &[u8; HASH_SIZE],
    backend: &B,
) -> OrchardRealProofCheck {
    orchard_real_proof_check_with_backend_v2(proof, proof_kind, public_input_hash, backend).into()
}

#[cfg(all(test, not(feature = "verifier-fixture")))]
fn orchard_real_proof_check_with_backend_v2<B: OrchardRealProofBackend>(
    proof: &[u8],
    proof_kind: u8,
    public_input_hash: &[u8; HASH_SIZE],
    backend: &B,
) -> OrchardRealProofCheckV2 {
    orchard_real_proof_check_with_backend_v3(proof, proof_kind, public_input_hash, backend).into()
}

fn orchard_real_proof_check_with_backend_v3<B: OrchardRealProofBackend>(
    proof: &[u8],
    proof_kind: u8,
    public_input_hash: &[u8; HASH_SIZE],
    backend: &B,
) -> OrchardRealProofCheckV3 {
    let Some(request) = decode_orchard_real_proof_request_v1(proof, proof_kind, public_input_hash)
    else {
        return OrchardRealProofCheckV3 {
            status: OrchardRealProofStatus::Malformed,
            request_hash: None,
            verifier_input_hash: None,
            native_proof_hash: None,
        };
    };
    let request_hash = request.request_hash_v1();
    let verifier_input_hash = request.verifier_input_hash_v1();
    let native_proof_hash = decode_orchard_native_proof_bytes_v1(&request)
        .map(|native_proof| native_proof.proof_hash_v1());
    OrchardRealProofCheckV3 {
        status: verify_orchard_real_proof_backend_status_with_backend_v1(&request, backend),
        request_hash: Some(request_hash),
        verifier_input_hash: Some(verifier_input_hash),
        native_proof_hash,
    }
}

pub fn verify_orchard_real_proof_v1(
    proof: &[u8],
    proof_kind: u8,
    public_input_hash: &[u8; HASH_SIZE],
) -> bool {
    orchard_real_proof_status_v1(proof, proof_kind, public_input_hash)
        == OrchardRealProofStatus::Valid
}

pub fn orchard_real_proof_status_v1(
    proof: &[u8],
    proof_kind: u8,
    public_input_hash: &[u8; HASH_SIZE],
) -> OrchardRealProofStatus {
    orchard_real_proof_check_v1(proof, proof_kind, public_input_hash).status
}

pub fn orchard_real_verifier_backend_v1() -> OrchardRealVerifierBackend {
    let backend = default_orchard_real_proof_backend_v1();
    backend.backend()
}

pub fn orchard_real_verifier_supports_real_proofs_v1() -> bool {
    orchard_real_verifier_backend_v1().supports_real_proofs()
}

fn verify_orchard_real_proof_backend_status_with_backend_v1<B: OrchardRealProofBackend>(
    request: &OrchardRealProofRequest<'_>,
    backend: &B,
) -> OrchardRealProofStatus {
    backend.verify(request)
}

pub fn build_proof_bundle_v4(proof_kind: u8, public_input_hash: &[u8; HASH_SIZE]) -> Vec<u8> {
    let proof_payload = build_orchard_proof_payload_v1(proof_kind, public_input_hash);
    build_proof_bundle_with_payload_v4(proof_kind, public_input_hash, &proof_payload)
}

pub fn build_proof_bundle_with_payload_v4(
    proof_kind: u8,
    public_input_hash: &[u8; HASH_SIZE],
    proof_payload: &[u8],
) -> Vec<u8> {
    let mut bundle = Vec::with_capacity(PROOF_BUNDLE_HEADER_LEN_V4 + proof_payload.len());
    bundle.extend_from_slice(PROOF_BUNDLE_PREFIX_V4);
    bundle.push(PROOF_BUNDLE_VERSION_V4);
    bundle.push(proof_kind);
    bundle.push(PROOF_SYSTEM_ORCHARD);
    bundle.push(PROOF_BUNDLE_FLAGS_NONE);
    bundle.extend_from_slice(public_input_hash);
    bundle.extend_from_slice(&(proof_payload.len() as u32).to_le_bytes());
    bundle.extend_from_slice(&proof_payload);
    bundle
}

pub fn build_orchard_proof_payload_v1(
    proof_kind: u8,
    public_input_hash: &[u8; HASH_SIZE],
) -> Vec<u8> {
    let proof_body = build_orchard_proof_body_v1(proof_kind, public_input_hash);
    build_orchard_proof_payload_with_body_v1(proof_kind, public_input_hash, &proof_body)
}

pub fn build_orchard_proof_payload_with_body_v1(
    proof_kind: u8,
    public_input_hash: &[u8; HASH_SIZE],
    proof_body: &[u8],
) -> Vec<u8> {
    let mut payload = Vec::with_capacity(ORCHARD_PROOF_PAYLOAD_HEADER_LEN_V1 + proof_body.len());
    payload.extend_from_slice(ORCHARD_PROOF_PAYLOAD_PREFIX_V1);
    payload.push(proof_kind);
    payload.extend_from_slice(public_input_hash);
    payload.extend_from_slice(&(proof_body.len() as u32).to_le_bytes());
    payload.extend_from_slice(&proof_body);
    payload
}

pub fn build_orchard_proof_body_v1(proof_kind: u8, public_input_hash: &[u8; HASH_SIZE]) -> Vec<u8> {
    let scaffold_body = expected_proof_payload_v4(proof_kind, public_input_hash);
    build_orchard_proof_body_with_mode_v1(ORCHARD_PROOF_BODY_MODE_SCAFFOLD, &scaffold_body)
}

pub fn build_orchard_proof_body_with_mode_v1(mode: u8, proof_bytes: &[u8]) -> Vec<u8> {
    let mut proof_body = Vec::with_capacity(ORCHARD_PROOF_BODY_HEADER_LEN_V1 + proof_bytes.len());
    proof_body.extend_from_slice(ORCHARD_PROOF_BODY_PREFIX_V1);
    proof_body.push(mode);
    proof_body.extend_from_slice(&(proof_bytes.len() as u32).to_le_bytes());
    proof_body.extend_from_slice(proof_bytes);
    proof_body
}

pub fn build_orchard_real_proof_body_v1(proof_bytes: &[u8]) -> Vec<u8> {
    build_orchard_proof_body_with_mode_v1(ORCHARD_PROOF_BODY_MODE_REAL, proof_bytes)
}

pub fn build_orchard_real_proof_body_with_context_v1(
    proof_kind: u8,
    public_input_hash: &[u8; HASH_SIZE],
    proof_bytes: &[u8],
) -> Vec<u8> {
    let proof = build_orchard_real_proof_v1(proof_kind, public_input_hash, proof_bytes);
    build_orchard_real_proof_body_v1(&proof)
}

pub fn verify_orchard_proof_payload_v1(
    proof_payload: &[u8],
    proof_kind: u8,
    public_input_hash: &[u8; HASH_SIZE],
) -> bool {
    check_orchard_proof_payload_v1(proof_payload, proof_kind, public_input_hash).status
        == OrchardRealProofStatus::Valid
}

pub fn check_orchard_proof_payload_v1(
    proof_payload: &[u8],
    proof_kind: u8,
    public_input_hash: &[u8; HASH_SIZE],
) -> ProofBundleCheck {
    check_orchard_proof_payload_v2(proof_payload, proof_kind, public_input_hash).into()
}

pub fn check_orchard_proof_payload_v2(
    proof_payload: &[u8],
    proof_kind: u8,
    public_input_hash: &[u8; HASH_SIZE],
) -> ProofBundleCheckV2 {
    check_orchard_proof_payload_v3(proof_payload, proof_kind, public_input_hash).into()
}

pub fn check_orchard_proof_payload_v3(
    proof_payload: &[u8],
    proof_kind: u8,
    public_input_hash: &[u8; HASH_SIZE],
) -> ProofBundleCheckV3 {
    let backend = default_orchard_real_proof_backend_v1();
    check_orchard_proof_payload_with_backend_v3(
        proof_payload,
        proof_kind,
        public_input_hash,
        &backend,
    )
}

fn check_orchard_proof_payload_with_backend_v3<B: OrchardRealProofBackend>(
    proof_payload: &[u8],
    proof_kind: u8,
    public_input_hash: &[u8; HASH_SIZE],
    backend: &B,
) -> ProofBundleCheckV3 {
    if proof_payload.len() < ORCHARD_PROOF_PAYLOAD_HEADER_LEN_V1 {
        return ProofBundleCheckV3::malformed();
    }
    if !proof_payload.starts_with(ORCHARD_PROOF_PAYLOAD_PREFIX_V1) {
        return ProofBundleCheckV3::malformed();
    }

    let kind_offset = ORCHARD_PROOF_PAYLOAD_PREFIX_V1.len();
    let public_input_offset = kind_offset + 1;
    let proof_len_offset = public_input_offset + HASH_SIZE;
    let proof_offset = proof_len_offset + core::mem::size_of::<u32>();

    if proof_payload[kind_offset] != proof_kind {
        return ProofBundleCheckV3::malformed();
    }
    if &proof_payload[public_input_offset..proof_len_offset] != public_input_hash {
        return ProofBundleCheckV3::malformed();
    }

    let proof_len = u32::from_le_bytes(
        proof_payload[proof_len_offset..proof_offset]
            .try_into()
            .expect("proof length slice has fixed length"),
    ) as usize;
    if proof_len != proof_payload.len() - proof_offset {
        return ProofBundleCheckV3::malformed();
    }

    let proof_body = &proof_payload[proof_offset..];
    check_orchard_proof_body_with_backend_v3(proof_body, proof_kind, public_input_hash, backend)
}

pub fn verify_orchard_proof_body_v1(
    proof_body: &[u8],
    proof_kind: u8,
    public_input_hash: &[u8; HASH_SIZE],
) -> bool {
    check_orchard_proof_body_v1(proof_body, proof_kind, public_input_hash).status
        == OrchardRealProofStatus::Valid
}

pub fn check_orchard_proof_body_v1(
    proof_body: &[u8],
    proof_kind: u8,
    public_input_hash: &[u8; HASH_SIZE],
) -> ProofBundleCheck {
    check_orchard_proof_body_v2(proof_body, proof_kind, public_input_hash).into()
}

pub fn check_orchard_proof_body_v2(
    proof_body: &[u8],
    proof_kind: u8,
    public_input_hash: &[u8; HASH_SIZE],
) -> ProofBundleCheckV2 {
    check_orchard_proof_body_v3(proof_body, proof_kind, public_input_hash).into()
}

pub fn check_orchard_proof_body_v3(
    proof_body: &[u8],
    proof_kind: u8,
    public_input_hash: &[u8; HASH_SIZE],
) -> ProofBundleCheckV3 {
    let backend = default_orchard_real_proof_backend_v1();
    check_orchard_proof_body_with_backend_v3(proof_body, proof_kind, public_input_hash, &backend)
}

fn check_orchard_proof_body_with_backend_v3<B: OrchardRealProofBackend>(
    proof_body: &[u8],
    proof_kind: u8,
    public_input_hash: &[u8; HASH_SIZE],
    backend: &B,
) -> ProofBundleCheckV3 {
    if proof_body.len() < ORCHARD_PROOF_BODY_HEADER_LEN_V1 {
        return ProofBundleCheckV3::malformed();
    }
    if !proof_body.starts_with(ORCHARD_PROOF_BODY_PREFIX_V1) {
        return ProofBundleCheckV3::malformed();
    }

    let mode_offset = ORCHARD_PROOF_BODY_PREFIX_V1.len();
    let body_len_offset = mode_offset + 1;
    let body_offset = body_len_offset + core::mem::size_of::<u32>();
    let body_mode = proof_body[mode_offset];

    let body_len = u32::from_le_bytes(
        proof_body[body_len_offset..body_offset]
            .try_into()
            .expect("body length slice has fixed length"),
    ) as usize;
    if body_len != proof_body.len() - body_offset {
        return ProofBundleCheckV3::malformed();
    }

    match body_mode {
        ORCHARD_PROOF_BODY_MODE_SCAFFOLD => ProofBundleCheckV3::with_mode(
            if proof_body[body_offset..] == expected_proof_payload_v4(proof_kind, public_input_hash)
            {
                OrchardRealProofStatus::Valid
            } else {
                OrchardRealProofStatus::Invalid
            },
            ORCHARD_PROOF_BODY_MODE_SCAFFOLD,
        ),
        ORCHARD_PROOF_BODY_MODE_REAL => {
            let check = orchard_real_proof_check_with_backend_v3(
                &proof_body[body_offset..],
                proof_kind,
                public_input_hash,
                backend,
            );
            ProofBundleCheckV3 {
                status: check.status,
                proof_body_mode: Some(ORCHARD_PROOF_BODY_MODE_REAL),
                real_request_hash: check.request_hash,
                real_verifier_input_hash: check.verifier_input_hash,
                real_native_proof_hash: check.native_proof_hash,
            }
        }
        _ => ProofBundleCheckV3::with_mode(OrchardRealProofStatus::Malformed, body_mode),
    }
}

pub fn verify_proof_payload_v1(
    proof: &[u8],
    field_hash: &[u8; HASH_SIZE],
    tx_binding_hash: &[u8; HASH_SIZE],
) -> bool {
    proof == expected_proof_payload_v1(field_hash, tx_binding_hash)
}

pub fn verify_proof_payload_v2(
    proof: &[u8],
    proof_kind: u8,
    field_hash: &[u8; HASH_SIZE],
    tx_binding_hash: &[u8; HASH_SIZE],
) -> bool {
    proof == expected_proof_payload_v2(proof_kind, field_hash, tx_binding_hash)
}

pub fn verify_proof_payload_v3(
    proof: &[u8],
    proof_kind: u8,
    public_input_hash: &[u8; HASH_SIZE],
) -> bool {
    proof == expected_proof_payload_v3(proof_kind, public_input_hash)
}

pub fn verify_proof_bundle_v4(
    bundle: &[u8],
    proof_kind: u8,
    public_input_hash: &[u8; HASH_SIZE],
) -> bool {
    check_proof_bundle_v4(bundle, proof_kind, public_input_hash).status
        == OrchardRealProofStatus::Valid
}

pub fn check_proof_bundle_v4(
    bundle: &[u8],
    proof_kind: u8,
    public_input_hash: &[u8; HASH_SIZE],
) -> ProofBundleCheck {
    check_proof_bundle_v5(bundle, proof_kind, public_input_hash).into()
}

pub fn check_proof_bundle_v5(
    bundle: &[u8],
    proof_kind: u8,
    public_input_hash: &[u8; HASH_SIZE],
) -> ProofBundleCheckV2 {
    check_proof_bundle_v6(bundle, proof_kind, public_input_hash).into()
}

pub fn check_proof_bundle_v6(
    bundle: &[u8],
    proof_kind: u8,
    public_input_hash: &[u8; HASH_SIZE],
) -> ProofBundleCheckV3 {
    let backend = default_orchard_real_proof_backend_v1();
    check_proof_bundle_with_backend_v6(bundle, proof_kind, public_input_hash, &backend)
}

#[cfg(all(test, not(feature = "verifier-fixture")))]
fn check_proof_bundle_with_backend_v4<B: OrchardRealProofBackend>(
    bundle: &[u8],
    proof_kind: u8,
    public_input_hash: &[u8; HASH_SIZE],
    backend: &B,
) -> ProofBundleCheck {
    check_proof_bundle_with_backend_v5(bundle, proof_kind, public_input_hash, backend).into()
}

#[cfg(all(test, not(feature = "verifier-fixture")))]
fn check_proof_bundle_with_backend_v5<B: OrchardRealProofBackend>(
    bundle: &[u8],
    proof_kind: u8,
    public_input_hash: &[u8; HASH_SIZE],
    backend: &B,
) -> ProofBundleCheckV2 {
    check_proof_bundle_with_backend_v6(bundle, proof_kind, public_input_hash, backend).into()
}

fn check_proof_bundle_with_backend_v6<B: OrchardRealProofBackend>(
    bundle: &[u8],
    proof_kind: u8,
    public_input_hash: &[u8; HASH_SIZE],
    backend: &B,
) -> ProofBundleCheckV3 {
    if bundle.len() < PROOF_BUNDLE_HEADER_LEN_V4 {
        return ProofBundleCheckV3::malformed();
    }
    if !bundle.starts_with(PROOF_BUNDLE_PREFIX_V4) {
        return ProofBundleCheckV3::malformed();
    }

    let version_offset = PROOF_BUNDLE_PREFIX_V4.len();
    let kind_offset = version_offset + 1;
    let proof_system_offset = kind_offset + 1;
    let flags_offset = proof_system_offset + 1;
    let public_input_offset = flags_offset + 1;
    let proof_len_offset = public_input_offset + HASH_SIZE;
    let proof_offset = proof_len_offset + core::mem::size_of::<u32>();

    if bundle[version_offset] != PROOF_BUNDLE_VERSION_V4 {
        return ProofBundleCheckV3::malformed();
    }
    if bundle[kind_offset] != proof_kind {
        return ProofBundleCheckV3::malformed();
    }
    if bundle[proof_system_offset] != PROOF_SYSTEM_ORCHARD {
        return ProofBundleCheckV3::malformed();
    }
    if bundle[flags_offset] != PROOF_BUNDLE_FLAGS_NONE {
        return ProofBundleCheckV3::malformed();
    }
    if &bundle[public_input_offset..proof_len_offset] != public_input_hash {
        return ProofBundleCheckV3::malformed();
    }

    let proof_len = u32::from_le_bytes(
        bundle[proof_len_offset..proof_offset]
            .try_into()
            .expect("proof length slice has fixed length"),
    ) as usize;
    if proof_len != bundle.len() - proof_offset {
        return ProofBundleCheckV3::malformed();
    }

    check_orchard_proof_payload_with_backend_v3(
        &bundle[proof_offset..],
        proof_kind,
        public_input_hash,
        backend,
    )
}

unsafe fn read_hash<'a>(ptr: *const u8, len: usize) -> Option<&'a [u8; HASH_SIZE]> {
    if ptr.is_null() || len != HASH_SIZE {
        return None;
    }
    let bytes = slice::from_raw_parts(ptr, len);
    bytes.try_into().ok()
}

#[no_mangle]
pub unsafe extern "C" fn zkc_shielded_verify_proof_v1(
    proof: *const u8,
    proof_len: usize,
    field_hash: *const u8,
    field_hash_len: usize,
    tx_binding_hash: *const u8,
    tx_binding_hash_len: usize,
) -> i32 {
    if proof.is_null() || proof_len != HASH_SIZE {
        return 0;
    }
    let Some(field_hash) = read_hash(field_hash, field_hash_len) else {
        return 0;
    };
    let Some(tx_binding_hash) = read_hash(tx_binding_hash, tx_binding_hash_len) else {
        return 0;
    };

    let proof = slice::from_raw_parts(proof, proof_len);
    i32::from(verify_proof_payload_v1(proof, field_hash, tx_binding_hash))
}

#[no_mangle]
pub unsafe extern "C" fn zkc_shielded_verify_proof_v2(
    proof: *const u8,
    proof_len: usize,
    proof_kind: u8,
    field_hash: *const u8,
    field_hash_len: usize,
    tx_binding_hash: *const u8,
    tx_binding_hash_len: usize,
) -> i32 {
    if proof.is_null() || proof_len != HASH_SIZE {
        return 0;
    }
    let Some(field_hash) = read_hash(field_hash, field_hash_len) else {
        return 0;
    };
    let Some(tx_binding_hash) = read_hash(tx_binding_hash, tx_binding_hash_len) else {
        return 0;
    };

    let proof = slice::from_raw_parts(proof, proof_len);
    i32::from(verify_proof_payload_v2(
        proof,
        proof_kind,
        field_hash,
        tx_binding_hash,
    ))
}

#[no_mangle]
pub unsafe extern "C" fn zkc_shielded_verify_proof_v3(
    proof: *const u8,
    proof_len: usize,
    proof_kind: u8,
    public_input_hash: *const u8,
    public_input_hash_len: usize,
) -> i32 {
    if proof.is_null() || proof_len != HASH_SIZE {
        return 0;
    }
    let Some(public_input_hash) = read_hash(public_input_hash, public_input_hash_len) else {
        return 0;
    };

    let proof = slice::from_raw_parts(proof, proof_len);
    i32::from(verify_proof_payload_v3(
        proof,
        proof_kind,
        public_input_hash,
    ))
}

#[no_mangle]
pub unsafe extern "C" fn zkc_shielded_verify_bundle_v4(
    bundle: *const u8,
    bundle_len: usize,
    proof_kind: u8,
    public_input_hash: *const u8,
    public_input_hash_len: usize,
) -> i32 {
    if bundle.is_null() {
        return 0;
    }
    let Some(public_input_hash) = read_hash(public_input_hash, public_input_hash_len) else {
        return 0;
    };

    let bundle = slice::from_raw_parts(bundle, bundle_len);
    i32::from(verify_proof_bundle_v4(
        bundle,
        proof_kind,
        public_input_hash,
    ))
}

#[no_mangle]
pub unsafe extern "C" fn zkc_shielded_check_bundle_v4(
    bundle: *const u8,
    bundle_len: usize,
    proof_kind: u8,
    public_input_hash: *const u8,
    public_input_hash_len: usize,
    proof_body_mode_out: *mut u8,
    real_request_hash_out: *mut u8,
    real_request_hash_out_len: usize,
) -> i32 {
    if proof_body_mode_out.is_null()
        || real_request_hash_out.is_null()
        || real_request_hash_out_len != HASH_SIZE
    {
        return ORCHARD_REAL_PROOF_STATUS_MALFORMED;
    }
    *proof_body_mode_out = 0xff;
    core::ptr::write_bytes(real_request_hash_out, 0, HASH_SIZE);

    if bundle.is_null() {
        return ORCHARD_REAL_PROOF_STATUS_MALFORMED;
    }
    let Some(public_input_hash) = read_hash(public_input_hash, public_input_hash_len) else {
        return ORCHARD_REAL_PROOF_STATUS_MALFORMED;
    };

    let bundle = slice::from_raw_parts(bundle, bundle_len);
    let check = check_proof_bundle_v4(bundle, proof_kind, public_input_hash);
    if let Some(proof_body_mode) = check.proof_body_mode {
        *proof_body_mode_out = proof_body_mode;
    }
    if let Some(request_hash) = check.real_request_hash {
        core::ptr::copy_nonoverlapping(request_hash.as_ptr(), real_request_hash_out, HASH_SIZE);
    }
    check.status.as_ffi_code()
}

#[no_mangle]
pub unsafe extern "C" fn zkc_shielded_check_bundle_v5(
    bundle: *const u8,
    bundle_len: usize,
    proof_kind: u8,
    public_input_hash: *const u8,
    public_input_hash_len: usize,
    proof_body_mode_out: *mut u8,
    real_request_hash_out: *mut u8,
    real_request_hash_out_len: usize,
    real_verifier_input_hash_out: *mut u8,
    real_verifier_input_hash_out_len: usize,
) -> i32 {
    if proof_body_mode_out.is_null()
        || real_request_hash_out.is_null()
        || real_request_hash_out_len != HASH_SIZE
        || real_verifier_input_hash_out.is_null()
        || real_verifier_input_hash_out_len != HASH_SIZE
    {
        return ORCHARD_REAL_PROOF_STATUS_MALFORMED;
    }
    *proof_body_mode_out = 0xff;
    core::ptr::write_bytes(real_request_hash_out, 0, HASH_SIZE);
    core::ptr::write_bytes(real_verifier_input_hash_out, 0, HASH_SIZE);

    if bundle.is_null() {
        return ORCHARD_REAL_PROOF_STATUS_MALFORMED;
    }
    let Some(public_input_hash) = read_hash(public_input_hash, public_input_hash_len) else {
        return ORCHARD_REAL_PROOF_STATUS_MALFORMED;
    };

    let bundle = slice::from_raw_parts(bundle, bundle_len);
    let check = check_proof_bundle_v5(bundle, proof_kind, public_input_hash);
    if let Some(proof_body_mode) = check.proof_body_mode {
        *proof_body_mode_out = proof_body_mode;
    }
    if let Some(request_hash) = check.real_request_hash {
        core::ptr::copy_nonoverlapping(request_hash.as_ptr(), real_request_hash_out, HASH_SIZE);
    }
    if let Some(verifier_input_hash) = check.real_verifier_input_hash {
        core::ptr::copy_nonoverlapping(
            verifier_input_hash.as_ptr(),
            real_verifier_input_hash_out,
            HASH_SIZE,
        );
    }
    check.status.as_ffi_code()
}

#[no_mangle]
pub unsafe extern "C" fn zkc_shielded_check_bundle_v6(
    bundle: *const u8,
    bundle_len: usize,
    proof_kind: u8,
    public_input_hash: *const u8,
    public_input_hash_len: usize,
    proof_body_mode_out: *mut u8,
    real_request_hash_out: *mut u8,
    real_request_hash_out_len: usize,
    real_verifier_input_hash_out: *mut u8,
    real_verifier_input_hash_out_len: usize,
    real_native_proof_hash_out: *mut u8,
    real_native_proof_hash_out_len: usize,
) -> i32 {
    if proof_body_mode_out.is_null()
        || real_request_hash_out.is_null()
        || real_request_hash_out_len != HASH_SIZE
        || real_verifier_input_hash_out.is_null()
        || real_verifier_input_hash_out_len != HASH_SIZE
        || real_native_proof_hash_out.is_null()
        || real_native_proof_hash_out_len != HASH_SIZE
    {
        return ORCHARD_REAL_PROOF_STATUS_MALFORMED;
    }
    *proof_body_mode_out = 0xff;
    core::ptr::write_bytes(real_request_hash_out, 0, HASH_SIZE);
    core::ptr::write_bytes(real_verifier_input_hash_out, 0, HASH_SIZE);
    core::ptr::write_bytes(real_native_proof_hash_out, 0, HASH_SIZE);

    if bundle.is_null() {
        return ORCHARD_REAL_PROOF_STATUS_MALFORMED;
    }
    let Some(public_input_hash) = read_hash(public_input_hash, public_input_hash_len) else {
        return ORCHARD_REAL_PROOF_STATUS_MALFORMED;
    };

    let bundle = slice::from_raw_parts(bundle, bundle_len);
    let check = check_proof_bundle_v6(bundle, proof_kind, public_input_hash);
    if let Some(proof_body_mode) = check.proof_body_mode {
        *proof_body_mode_out = proof_body_mode;
    }
    if let Some(request_hash) = check.real_request_hash {
        core::ptr::copy_nonoverlapping(request_hash.as_ptr(), real_request_hash_out, HASH_SIZE);
    }
    if let Some(verifier_input_hash) = check.real_verifier_input_hash {
        core::ptr::copy_nonoverlapping(
            verifier_input_hash.as_ptr(),
            real_verifier_input_hash_out,
            HASH_SIZE,
        );
    }
    if let Some(native_proof_hash) = check.real_native_proof_hash {
        core::ptr::copy_nonoverlapping(
            native_proof_hash.as_ptr(),
            real_native_proof_hash_out,
            HASH_SIZE,
        );
    }
    check.status.as_ffi_code()
}

#[no_mangle]
pub unsafe extern "C" fn zkc_shielded_verify_orchard_proof_v1(
    proof_body: *const u8,
    proof_body_len: usize,
    proof_kind: u8,
    public_input_hash: *const u8,
    public_input_hash_len: usize,
) -> i32 {
    if proof_body.is_null() {
        return 0;
    }
    let Some(public_input_hash) = read_hash(public_input_hash, public_input_hash_len) else {
        return 0;
    };

    let proof_body = slice::from_raw_parts(proof_body, proof_body_len);
    i32::from(verify_orchard_proof_body_v1(
        proof_body,
        proof_kind,
        public_input_hash,
    ))
}

#[no_mangle]
pub unsafe extern "C" fn zkc_shielded_verify_orchard_real_proof_v1(
    proof: *const u8,
    proof_len: usize,
    proof_kind: u8,
    public_input_hash: *const u8,
    public_input_hash_len: usize,
) -> i32 {
    if proof.is_null() {
        return 0;
    }
    let Some(public_input_hash) = read_hash(public_input_hash, public_input_hash_len) else {
        return 0;
    };

    let proof = slice::from_raw_parts(proof, proof_len);
    i32::from(verify_orchard_real_proof_v1(
        proof,
        proof_kind,
        public_input_hash,
    ))
}

#[no_mangle]
pub unsafe extern "C" fn zkc_shielded_verify_orchard_real_proof_status_v1(
    proof: *const u8,
    proof_len: usize,
    proof_kind: u8,
    public_input_hash: *const u8,
    public_input_hash_len: usize,
) -> i32 {
    if proof.is_null() {
        return ORCHARD_REAL_PROOF_STATUS_MALFORMED;
    }
    let Some(public_input_hash) = read_hash(public_input_hash, public_input_hash_len) else {
        return ORCHARD_REAL_PROOF_STATUS_MALFORMED;
    };

    let proof = slice::from_raw_parts(proof, proof_len);
    orchard_real_proof_status_v1(proof, proof_kind, public_input_hash).as_ffi_code()
}

#[no_mangle]
pub extern "C" fn zkc_shielded_orchard_real_verifier_backend_v1() -> i32 {
    orchard_real_verifier_backend_v1().as_ffi_code()
}

#[no_mangle]
pub extern "C" fn zkc_shielded_orchard_real_verifier_supports_proofs_v1() -> i32 {
    i32::from(orchard_real_verifier_supports_real_proofs_v1())
}

#[no_mangle]
pub unsafe extern "C" fn zkc_shielded_orchard_real_proof_request_hash_v1(
    proof: *const u8,
    proof_len: usize,
    proof_kind: u8,
    public_input_hash: *const u8,
    public_input_hash_len: usize,
    request_hash_out: *mut u8,
    request_hash_out_len: usize,
) -> i32 {
    if proof.is_null() || request_hash_out.is_null() || request_hash_out_len != HASH_SIZE {
        return 0;
    }
    let Some(public_input_hash) = read_hash(public_input_hash, public_input_hash_len) else {
        return 0;
    };

    let proof = slice::from_raw_parts(proof, proof_len);
    let Some(request_hash) =
        orchard_real_proof_request_hash_v1(proof, proof_kind, public_input_hash)
    else {
        return 0;
    };
    core::ptr::copy_nonoverlapping(request_hash.as_ptr(), request_hash_out, HASH_SIZE);
    1
}

#[no_mangle]
pub unsafe extern "C" fn zkc_shielded_orchard_real_verifier_input_hash_v1(
    proof: *const u8,
    proof_len: usize,
    proof_kind: u8,
    public_input_hash: *const u8,
    public_input_hash_len: usize,
    verifier_input_hash_out: *mut u8,
    verifier_input_hash_out_len: usize,
) -> i32 {
    if verifier_input_hash_out.is_null() || verifier_input_hash_out_len != HASH_SIZE {
        return 0;
    }
    core::ptr::write_bytes(verifier_input_hash_out, 0, HASH_SIZE);

    if proof.is_null() {
        return 0;
    }
    let Some(public_input_hash) = read_hash(public_input_hash, public_input_hash_len) else {
        return 0;
    };

    let proof = slice::from_raw_parts(proof, proof_len);
    let Some(verifier_input_hash) =
        orchard_real_verifier_input_hash_v1(proof, proof_kind, public_input_hash)
    else {
        return 0;
    };
    core::ptr::copy_nonoverlapping(
        verifier_input_hash.as_ptr(),
        verifier_input_hash_out,
        HASH_SIZE,
    );
    1
}

#[no_mangle]
pub unsafe extern "C" fn zkc_shielded_orchard_real_native_proof_hash_v1(
    proof: *const u8,
    proof_len: usize,
    proof_kind: u8,
    public_input_hash: *const u8,
    public_input_hash_len: usize,
    native_proof_hash_out: *mut u8,
    native_proof_hash_out_len: usize,
) -> i32 {
    if native_proof_hash_out.is_null() || native_proof_hash_out_len != HASH_SIZE {
        return 0;
    }
    core::ptr::write_bytes(native_proof_hash_out, 0, HASH_SIZE);

    if proof.is_null() {
        return 0;
    }
    let Some(public_input_hash) = read_hash(public_input_hash, public_input_hash_len) else {
        return 0;
    };

    let proof = slice::from_raw_parts(proof, proof_len);
    let Some(native_proof_hash) =
        orchard_real_native_proof_hash_v1(proof, proof_kind, public_input_hash)
    else {
        return 0;
    };
    core::ptr::copy_nonoverlapping(native_proof_hash.as_ptr(), native_proof_hash_out, HASH_SIZE);
    1
}

#[no_mangle]
pub unsafe extern "C" fn zkc_shielded_orchard_real_proof_check_v1(
    proof: *const u8,
    proof_len: usize,
    proof_kind: u8,
    public_input_hash: *const u8,
    public_input_hash_len: usize,
    request_hash_out: *mut u8,
    request_hash_out_len: usize,
) -> i32 {
    if request_hash_out.is_null() || request_hash_out_len != HASH_SIZE {
        return ORCHARD_REAL_PROOF_STATUS_MALFORMED;
    }
    core::ptr::write_bytes(request_hash_out, 0, HASH_SIZE);

    if proof.is_null() {
        return ORCHARD_REAL_PROOF_STATUS_MALFORMED;
    }
    let Some(public_input_hash) = read_hash(public_input_hash, public_input_hash_len) else {
        return ORCHARD_REAL_PROOF_STATUS_MALFORMED;
    };

    let proof = slice::from_raw_parts(proof, proof_len);
    let check = orchard_real_proof_check_v1(proof, proof_kind, public_input_hash);
    if let Some(request_hash) = check.request_hash {
        core::ptr::copy_nonoverlapping(request_hash.as_ptr(), request_hash_out, HASH_SIZE);
    }
    check.status.as_ffi_code()
}

#[no_mangle]
pub unsafe extern "C" fn zkc_shielded_orchard_real_proof_check_v2(
    proof: *const u8,
    proof_len: usize,
    proof_kind: u8,
    public_input_hash: *const u8,
    public_input_hash_len: usize,
    request_hash_out: *mut u8,
    request_hash_out_len: usize,
    verifier_input_hash_out: *mut u8,
    verifier_input_hash_out_len: usize,
) -> i32 {
    if request_hash_out.is_null()
        || request_hash_out_len != HASH_SIZE
        || verifier_input_hash_out.is_null()
        || verifier_input_hash_out_len != HASH_SIZE
    {
        return ORCHARD_REAL_PROOF_STATUS_MALFORMED;
    }
    core::ptr::write_bytes(request_hash_out, 0, HASH_SIZE);
    core::ptr::write_bytes(verifier_input_hash_out, 0, HASH_SIZE);

    if proof.is_null() {
        return ORCHARD_REAL_PROOF_STATUS_MALFORMED;
    }
    let Some(public_input_hash) = read_hash(public_input_hash, public_input_hash_len) else {
        return ORCHARD_REAL_PROOF_STATUS_MALFORMED;
    };

    let proof = slice::from_raw_parts(proof, proof_len);
    let check = orchard_real_proof_check_v2(proof, proof_kind, public_input_hash);
    if let Some(request_hash) = check.request_hash {
        core::ptr::copy_nonoverlapping(request_hash.as_ptr(), request_hash_out, HASH_SIZE);
    }
    if let Some(verifier_input_hash) = check.verifier_input_hash {
        core::ptr::copy_nonoverlapping(
            verifier_input_hash.as_ptr(),
            verifier_input_hash_out,
            HASH_SIZE,
        );
    }
    check.status.as_ffi_code()
}

#[no_mangle]
pub unsafe extern "C" fn zkc_shielded_orchard_real_proof_check_v3(
    proof: *const u8,
    proof_len: usize,
    proof_kind: u8,
    public_input_hash: *const u8,
    public_input_hash_len: usize,
    request_hash_out: *mut u8,
    request_hash_out_len: usize,
    verifier_input_hash_out: *mut u8,
    verifier_input_hash_out_len: usize,
    native_proof_hash_out: *mut u8,
    native_proof_hash_out_len: usize,
) -> i32 {
    if request_hash_out.is_null()
        || request_hash_out_len != HASH_SIZE
        || verifier_input_hash_out.is_null()
        || verifier_input_hash_out_len != HASH_SIZE
        || native_proof_hash_out.is_null()
        || native_proof_hash_out_len != HASH_SIZE
    {
        return ORCHARD_REAL_PROOF_STATUS_MALFORMED;
    }
    core::ptr::write_bytes(request_hash_out, 0, HASH_SIZE);
    core::ptr::write_bytes(verifier_input_hash_out, 0, HASH_SIZE);
    core::ptr::write_bytes(native_proof_hash_out, 0, HASH_SIZE);

    if proof.is_null() {
        return ORCHARD_REAL_PROOF_STATUS_MALFORMED;
    }
    let Some(public_input_hash) = read_hash(public_input_hash, public_input_hash_len) else {
        return ORCHARD_REAL_PROOF_STATUS_MALFORMED;
    };

    let proof = slice::from_raw_parts(proof, proof_len);
    let check = orchard_real_proof_check_v3(proof, proof_kind, public_input_hash);
    if let Some(request_hash) = check.request_hash {
        core::ptr::copy_nonoverlapping(request_hash.as_ptr(), request_hash_out, HASH_SIZE);
    }
    if let Some(verifier_input_hash) = check.verifier_input_hash {
        core::ptr::copy_nonoverlapping(
            verifier_input_hash.as_ptr(),
            verifier_input_hash_out,
            HASH_SIZE,
        );
    }
    if let Some(native_proof_hash) = check.native_proof_hash {
        core::ptr::copy_nonoverlapping(
            native_proof_hash.as_ptr(),
            native_proof_hash_out,
            HASH_SIZE,
        );
    }
    check.status.as_ffi_code()
}

#[cfg(test)]
mod tests {
    use super::*;

    const FIELD_HASH: [u8; HASH_SIZE] = [0x11; HASH_SIZE];
    const TX_BINDING_HASH: [u8; HASH_SIZE] = [0x22; HASH_SIZE];
    const EXPECTED_PROOF: [u8; HASH_SIZE] = [
        0x8d, 0x88, 0xec, 0x0b, 0xaa, 0x50, 0x6b, 0x9d, 0x0a, 0xdd, 0x03, 0x36, 0x13, 0x74, 0x4b,
        0x45, 0x1f, 0x87, 0xe0, 0xd1, 0x17, 0xe7, 0x5e, 0xe5, 0xd4, 0x8f, 0x48, 0x89, 0xa0, 0x7e,
        0x59, 0x8c,
    ];
    const EXPECTED_MINT_PROOF_V2: [u8; HASH_SIZE] = [
        0xae, 0x9b, 0x4e, 0x8b, 0x11, 0x17, 0xc7, 0x69, 0x37, 0x62, 0x97, 0x1b, 0x55, 0x55, 0xcf,
        0xd3, 0x80, 0xd6, 0xa8, 0x94, 0xe5, 0xd9, 0x16, 0xf4, 0x4d, 0x2a, 0x99, 0x1c, 0xea, 0xb3,
        0x9d, 0xa1,
    ];
    const EXPECTED_PUBLIC_INPUT_HASH: [u8; HASH_SIZE] = [
        0x90, 0xd5, 0xa8, 0xbb, 0x82, 0x0b, 0x4f, 0x47, 0x4e, 0x1a, 0x44, 0x5f, 0x0b, 0x23, 0x03,
        0x27, 0x18, 0xc0, 0x7e, 0xbc, 0x5b, 0x94, 0xec, 0x51, 0x23, 0x43, 0x63, 0xa0, 0x67, 0x82,
        0x6e, 0x31,
    ];
    const EXPECTED_MINT_PROOF_V3: [u8; HASH_SIZE] = [
        0x46, 0x50, 0x2b, 0x6c, 0x3c, 0xab, 0xfb, 0xe2, 0x17, 0x8f, 0xbb, 0x6e, 0x7c, 0xcb, 0x90,
        0x14, 0x45, 0x91, 0xf8, 0xce, 0x03, 0x16, 0xf9, 0x0b, 0x5c, 0x0e, 0xb6, 0xc1, 0xa6, 0x3f,
        0x5b, 0x3a,
    ];
    const EXPECTED_MINT_PROOF_V4: [u8; HASH_SIZE] = [
        0xe1, 0x60, 0x23, 0x9b, 0x4c, 0x8b, 0xfc, 0x13, 0x7c, 0xac, 0xf2, 0x10, 0xd0, 0xea, 0xc3,
        0xcb, 0xc8, 0xe6, 0xfa, 0xd5, 0xff, 0xaa, 0x06, 0xca, 0xe6, 0x93, 0x1d, 0xb0, 0x34, 0x58,
        0xc4, 0x24,
    ];
    const EXPECTED_ORCHARD_REAL_VK_HASH: [u8; HASH_SIZE] = [
        0x44, 0x98, 0xa4, 0xda, 0xde, 0xe9, 0x35, 0xcc, 0x2a, 0x7a, 0xf6, 0x97, 0xc5, 0x7a, 0xc3,
        0x55, 0x93, 0xbf, 0xff, 0x59, 0x71, 0x7f, 0x1b, 0x74, 0x0f, 0xe2, 0x82, 0xaf, 0xe3, 0xf3,
        0x2c, 0xd3,
    ];
    const EXPECTED_ORCHARD_REAL_REQUEST_HASH: [u8; HASH_SIZE] = [
        0x85, 0xc1, 0x9b, 0xb0, 0x4c, 0x39, 0x8f, 0x2f, 0xcd, 0x05, 0x8c, 0x10, 0xe9, 0x4c, 0x0c,
        0x4d, 0x41, 0x46, 0xcb, 0x37, 0x9c, 0x8d, 0x21, 0x0b, 0xba, 0x90, 0x48, 0x01, 0xa4, 0x9d,
        0x70, 0x05,
    ];
    #[cfg(not(feature = "verifier-fixture"))]
    const EXPECTED_RAW_ORCHARD_REAL_REQUEST_HASH: [u8; HASH_SIZE] = [
        0xb5, 0xc0, 0x80, 0x93, 0xab, 0x92, 0x5b, 0x51, 0x3b, 0xa1, 0x01, 0xe8, 0x8a, 0x99, 0x52,
        0x51, 0xed, 0x51, 0x5d, 0xbd, 0xce, 0x32, 0xbb, 0x17, 0x63, 0xad, 0xbc, 0x04, 0x6d, 0xff,
        0x91, 0x52,
    ];
    const EXPECTED_ORCHARD_REAL_VERIFIER_INPUT_HASH: [u8; HASH_SIZE] = [
        0x66, 0xb7, 0xae, 0xc4, 0xde, 0xa3, 0x68, 0x22, 0xc7, 0xe8, 0xef, 0xaf, 0x4b, 0x21, 0xed,
        0xd6, 0x91, 0x5c, 0x31, 0x91, 0x6a, 0xc8, 0x09, 0x27, 0x91, 0x50, 0x23, 0x6c, 0xf9, 0x4d,
        0x5b, 0xc7,
    ];
    const EXPECTED_ORCHARD_NATIVE_PROOF_HASH: [u8; HASH_SIZE] = [
        0xb9, 0x90, 0x35, 0x4b, 0x50, 0xf0, 0xa8, 0xf9, 0xed, 0x5b, 0x45, 0xae, 0x4f, 0x4b, 0xfc,
        0xdb, 0xba, 0x7f, 0x30, 0x8d, 0x1f, 0x95, 0x5e, 0x1f, 0x8f, 0x44, 0xe1, 0xb7, 0xd2, 0xfd,
        0x8e, 0xbe,
    ];
    #[cfg(not(feature = "verifier-fixture"))]
    const EXPECTED_ORCHARD_NATIVE_PROOF_HASH_77: [u8; HASH_SIZE] = [
        0xb1, 0x29, 0x70, 0xb0, 0xf7, 0x27, 0xc4, 0x5c, 0x4f, 0x40, 0x7d, 0x94, 0x52, 0x0e, 0x43,
        0x1d, 0xf6, 0x56, 0xfa, 0x10, 0x2e, 0x85, 0xca, 0xbf, 0xa9, 0xa3, 0x98, 0xec, 0xcf, 0x07,
        0x73, 0xb2,
    ];
    #[cfg(not(feature = "verifier-fixture"))]
    const EXPECTED_ORCHARD_NATIVE_PROOF_HASH_78: [u8; HASH_SIZE] = [
        0x98, 0x3c, 0x0d, 0xbf, 0x85, 0x84, 0x36, 0x07, 0xcb, 0x7e, 0x91, 0xae, 0xef, 0x54, 0x8d,
        0xe2, 0x32, 0x8d, 0xfe, 0xd4, 0x81, 0x75, 0x87, 0x6e, 0xdd, 0x41, 0xe0, 0x1f, 0x41, 0x56,
        0x7c, 0xb2,
    ];

    fn expected_verifier_input() -> OrchardRealVerifierInput {
        OrchardRealVerifierInput {
            proof_kind: 1,
            public_input_hash: EXPECTED_PUBLIC_INPUT_HASH,
            verifier_key_hash: EXPECTED_ORCHARD_REAL_VK_HASH,
        }
    }

    fn native_proof_bytes(fill: u8) -> Vec<u8> {
        build_orchard_native_proof_bytes_v1(&expected_verifier_input(), &[fill; 192])
    }

    #[cfg(not(feature = "verifier-fixture"))]
    struct TestVectorOrchardRealProofBackend {
        valid_request_hash: [u8; HASH_SIZE],
    }

    #[cfg(not(feature = "verifier-fixture"))]
    impl OrchardRealProofBackend for TestVectorOrchardRealProofBackend {
        fn backend(&self) -> OrchardRealVerifierBackend {
            OrchardRealVerifierBackend::OrchardV1
        }

        fn verify(&self, request: &OrchardRealProofRequest<'_>) -> OrchardRealProofStatus {
            if request.request_hash_v1() == self.valid_request_hash {
                OrchardRealProofStatus::Valid
            } else {
                OrchardRealProofStatus::Invalid
            }
        }
    }

    #[test]
    fn builds_known_payload() {
        assert_eq!(
            expected_proof_payload_v1(&FIELD_HASH, &TX_BINDING_HASH),
            EXPECTED_PROOF
        );
        assert_eq!(
            expected_proof_payload_v2(1, &FIELD_HASH, &TX_BINDING_HASH),
            EXPECTED_MINT_PROOF_V2
        );
        assert_eq!(
            proof_public_input_hash(1, &FIELD_HASH, &TX_BINDING_HASH),
            EXPECTED_PUBLIC_INPUT_HASH
        );
        assert_eq!(
            expected_proof_payload_v3(1, &EXPECTED_PUBLIC_INPUT_HASH),
            EXPECTED_MINT_PROOF_V3
        );
        assert_eq!(
            expected_proof_payload_v4(1, &EXPECTED_PUBLIC_INPUT_HASH),
            EXPECTED_MINT_PROOF_V4
        );
        assert_eq!(
            expected_orchard_real_verifier_key_hash_v1(),
            EXPECTED_ORCHARD_REAL_VK_HASH
        );
        let native_bytes = native_proof_bytes(0x42);
        assert_eq!(
            native_bytes.len(),
            ORCHARD_REAL_NATIVE_PROOF_HEADER_LEN_V1 + 192
        );
        let real_proof_v1 =
            build_orchard_real_proof_v1(1, &EXPECTED_PUBLIC_INPUT_HASH, &native_bytes);
        assert_eq!(
            orchard_real_proof_request_hash_v1(&real_proof_v1, 1, &EXPECTED_PUBLIC_INPUT_HASH),
            Some(EXPECTED_ORCHARD_REAL_REQUEST_HASH)
        );
        assert_eq!(
            orchard_real_verifier_input_hash_v1(&real_proof_v1, 1, &EXPECTED_PUBLIC_INPUT_HASH),
            Some(EXPECTED_ORCHARD_REAL_VERIFIER_INPUT_HASH)
        );
        assert_eq!(
            orchard_real_native_proof_hash_v1(&real_proof_v1, 1, &EXPECTED_PUBLIC_INPUT_HASH),
            Some(EXPECTED_ORCHARD_NATIVE_PROOF_HASH)
        );
        assert_eq!(
            build_orchard_proof_payload_v1(1, &EXPECTED_PUBLIC_INPUT_HASH).len(),
            ORCHARD_PROOF_PAYLOAD_HEADER_LEN_V1 + ORCHARD_PROOF_BODY_HEADER_LEN_V1 + HASH_SIZE
        );
        assert_eq!(
            build_orchard_proof_body_v1(1, &EXPECTED_PUBLIC_INPUT_HASH).len(),
            ORCHARD_PROOF_BODY_HEADER_LEN_V1 + HASH_SIZE
        );
        assert_eq!(
            build_proof_bundle_v4(1, &EXPECTED_PUBLIC_INPUT_HASH).len(),
            PROOF_BUNDLE_HEADER_LEN_V4
                + ORCHARD_PROOF_PAYLOAD_HEADER_LEN_V1
                + ORCHARD_PROOF_BODY_HEADER_LEN_V1
                + HASH_SIZE
        );
        assert_eq!(
            real_proof_v1.len(),
            ORCHARD_REAL_PROOF_HEADER_LEN_V1 + native_bytes.len()
        );
        assert_eq!(
            build_orchard_real_proof_body_with_context_v1(
                1,
                &EXPECTED_PUBLIC_INPUT_HASH,
                &native_bytes
            )
            .len(),
            ORCHARD_PROOF_BODY_HEADER_LEN_V1
                + ORCHARD_REAL_PROOF_HEADER_LEN_V1
                + native_bytes.len()
        );
    }

    #[cfg(not(feature = "verifier-fixture"))]
    #[test]
    fn rejects_wrong_proof_context_and_lengths() {
        assert!(verify_proof_payload_v1(
            &EXPECTED_PROOF,
            &FIELD_HASH,
            &TX_BINDING_HASH
        ));
        assert!(!verify_proof_payload_v1(
            &EXPECTED_PROOF[..31],
            &FIELD_HASH,
            &TX_BINDING_HASH
        ));
        assert!(verify_proof_payload_v2(
            &EXPECTED_MINT_PROOF_V2,
            1,
            &FIELD_HASH,
            &TX_BINDING_HASH
        ));
        assert!(!verify_proof_payload_v2(
            &EXPECTED_MINT_PROOF_V2,
            2,
            &FIELD_HASH,
            &TX_BINDING_HASH
        ));
        assert!(verify_proof_payload_v3(
            &EXPECTED_MINT_PROOF_V3,
            1,
            &EXPECTED_PUBLIC_INPUT_HASH
        ));
        assert!(!verify_proof_payload_v3(
            &EXPECTED_MINT_PROOF_V3,
            2,
            &EXPECTED_PUBLIC_INPUT_HASH
        ));
        let bundle_v4 = build_proof_bundle_v4(1, &EXPECTED_PUBLIC_INPUT_HASH);
        let orchard_payload_v1 = build_orchard_proof_payload_v1(1, &EXPECTED_PUBLIC_INPUT_HASH);
        let orchard_body_v1 = build_orchard_proof_body_v1(1, &EXPECTED_PUBLIC_INPUT_HASH);
        assert!(verify_orchard_proof_body_v1(
            &orchard_body_v1,
            1,
            &EXPECTED_PUBLIC_INPUT_HASH
        ));
        assert!(!verify_orchard_proof_body_v1(
            &orchard_body_v1,
            2,
            &EXPECTED_PUBLIC_INPUT_HASH
        ));
        assert!(!verify_orchard_proof_body_v1(
            &EXPECTED_MINT_PROOF_V4,
            1,
            &EXPECTED_PUBLIC_INPUT_HASH
        ));
        let native_bytes = native_proof_bytes(0x42);
        let real_proof_v1 =
            build_orchard_real_proof_v1(1, &EXPECTED_PUBLIC_INPUT_HASH, &native_bytes);
        let real_request_v1 =
            decode_orchard_real_proof_request_v1(&real_proof_v1, 1, &EXPECTED_PUBLIC_INPUT_HASH)
                .expect("real proof request decodes");
        assert_eq!(real_request_v1.proof_kind, 1);
        assert_eq!(
            real_request_v1.public_input_hash,
            EXPECTED_PUBLIC_INPUT_HASH
        );
        assert_eq!(
            real_request_v1.verifier_key_hash,
            EXPECTED_ORCHARD_REAL_VK_HASH
        );
        assert_eq!(real_request_v1.proof_bytes, native_bytes.as_slice());
        let expected_native_proof_bytes = [0x42; 192];
        let decoded_native_proof =
            decode_orchard_native_proof_bytes_v1(&real_request_v1).expect("native proof decodes");
        assert_eq!(
            decoded_native_proof,
            OrchardNativeProof {
                verifier_key_hash: EXPECTED_ORCHARD_REAL_VK_HASH,
                verifier_input_hash: EXPECTED_ORCHARD_REAL_VERIFIER_INPUT_HASH,
                proof_bytes: &expected_native_proof_bytes,
            }
        );
        assert_eq!(
            decoded_native_proof.proof_hash_v1(),
            EXPECTED_ORCHARD_NATIVE_PROOF_HASH
        );
        assert_eq!(
            real_request_v1.request_hash_v1(),
            EXPECTED_ORCHARD_REAL_REQUEST_HASH
        );
        assert_eq!(
            real_request_v1.verifier_input(),
            OrchardRealVerifierInput {
                proof_kind: 1,
                public_input_hash: EXPECTED_PUBLIC_INPUT_HASH,
                verifier_key_hash: EXPECTED_ORCHARD_REAL_VK_HASH,
            }
        );
        assert_eq!(
            real_request_v1.verifier_input_hash_v1(),
            EXPECTED_ORCHARD_REAL_VERIFIER_INPUT_HASH
        );
        assert!(is_well_formed_orchard_real_proof_v1(
            &real_proof_v1,
            1,
            &EXPECTED_PUBLIC_INPUT_HASH
        ));
        assert_eq!(
            decode_orchard_real_proof_v1(&real_proof_v1, 1, &EXPECTED_PUBLIC_INPUT_HASH),
            Some(native_bytes.as_slice())
        );
        assert_eq!(
            orchard_real_proof_request_hash_v1(&real_proof_v1, 1, &EXPECTED_PUBLIC_INPUT_HASH),
            Some(EXPECTED_ORCHARD_REAL_REQUEST_HASH)
        );
        assert_eq!(
            orchard_real_verifier_input_hash_v1(&real_proof_v1, 1, &EXPECTED_PUBLIC_INPUT_HASH),
            Some(EXPECTED_ORCHARD_REAL_VERIFIER_INPUT_HASH)
        );
        assert_eq!(
            orchard_real_native_proof_hash_v1(&real_proof_v1, 1, &EXPECTED_PUBLIC_INPUT_HASH),
            Some(EXPECTED_ORCHARD_NATIVE_PROOF_HASH)
        );
        assert_eq!(
            orchard_real_proof_check_v1(&real_proof_v1, 1, &EXPECTED_PUBLIC_INPUT_HASH),
            OrchardRealProofCheck {
                status: OrchardRealProofStatus::Unsupported,
                request_hash: Some(EXPECTED_ORCHARD_REAL_REQUEST_HASH),
            }
        );
        assert_eq!(
            orchard_real_proof_check_v2(&real_proof_v1, 1, &EXPECTED_PUBLIC_INPUT_HASH),
            OrchardRealProofCheckV2 {
                status: OrchardRealProofStatus::Unsupported,
                request_hash: Some(EXPECTED_ORCHARD_REAL_REQUEST_HASH),
                verifier_input_hash: Some(EXPECTED_ORCHARD_REAL_VERIFIER_INPUT_HASH),
            }
        );
        assert_eq!(
            orchard_real_proof_check_v3(&real_proof_v1, 1, &EXPECTED_PUBLIC_INPUT_HASH),
            OrchardRealProofCheckV3 {
                status: OrchardRealProofStatus::Unsupported,
                request_hash: Some(EXPECTED_ORCHARD_REAL_REQUEST_HASH),
                verifier_input_hash: Some(EXPECTED_ORCHARD_REAL_VERIFIER_INPUT_HASH),
                native_proof_hash: Some(EXPECTED_ORCHARD_NATIVE_PROOF_HASH),
            }
        );
        assert!(!verify_orchard_real_proof_v1(
            &real_proof_v1,
            1,
            &EXPECTED_PUBLIC_INPUT_HASH
        ));
        assert_eq!(
            orchard_real_proof_status_v1(&real_proof_v1, 1, &EXPECTED_PUBLIC_INPUT_HASH),
            OrchardRealProofStatus::Unsupported
        );
        let raw_real_proof_v1 =
            build_orchard_real_proof_v1(1, &EXPECTED_PUBLIC_INPUT_HASH, &[0x42; 192]);
        assert_eq!(
            orchard_real_proof_check_v2(&raw_real_proof_v1, 1, &EXPECTED_PUBLIC_INPUT_HASH),
            OrchardRealProofCheckV2 {
                status: OrchardRealProofStatus::Invalid,
                request_hash: Some(EXPECTED_RAW_ORCHARD_REAL_REQUEST_HASH),
                verifier_input_hash: Some(EXPECTED_ORCHARD_REAL_VERIFIER_INPUT_HASH),
            }
        );
        assert_eq!(
            orchard_real_proof_check_v3(&raw_real_proof_v1, 1, &EXPECTED_PUBLIC_INPUT_HASH),
            OrchardRealProofCheckV3 {
                status: OrchardRealProofStatus::Invalid,
                request_hash: Some(EXPECTED_RAW_ORCHARD_REAL_REQUEST_HASH),
                verifier_input_hash: Some(EXPECTED_ORCHARD_REAL_VERIFIER_INPUT_HASH),
                native_proof_hash: None,
            }
        );
        assert_eq!(
            orchard_real_proof_status_v1(&raw_real_proof_v1, 1, &EXPECTED_PUBLIC_INPUT_HASH),
            OrchardRealProofStatus::Invalid
        );
        let mut wrong_native_vk_bytes = native_bytes.clone();
        wrong_native_vk_bytes[ORCHARD_REAL_NATIVE_PROOF_PREFIX_V1.len() + 1] ^= 0x01;
        let wrong_native_vk_proof_v1 =
            build_orchard_real_proof_v1(1, &EXPECTED_PUBLIC_INPUT_HASH, &wrong_native_vk_bytes);
        assert_eq!(
            orchard_real_proof_status_v1(&wrong_native_vk_proof_v1, 1, &EXPECTED_PUBLIC_INPUT_HASH),
            OrchardRealProofStatus::Invalid
        );
        let wrong_native_vk_request = decode_orchard_real_proof_request_v1(
            &wrong_native_vk_proof_v1,
            1,
            &EXPECTED_PUBLIC_INPUT_HASH,
        )
        .expect("wrong native verifier key outer envelope decodes");
        assert_eq!(
            decode_orchard_native_proof_bytes_v1(&wrong_native_vk_request),
            None
        );
        let raw_real_request_v1 = decode_orchard_real_proof_request_v1(
            &raw_real_proof_v1,
            1,
            &EXPECTED_PUBLIC_INPUT_HASH,
        )
        .expect("raw real proof outer envelope decodes");
        assert_eq!(
            decode_orchard_native_proof_bytes_v1(&raw_real_request_v1),
            None
        );
        assert!(!is_well_formed_orchard_real_proof_v1(
            &real_proof_v1,
            2,
            &EXPECTED_PUBLIC_INPUT_HASH
        ));
        assert_eq!(
            orchard_real_proof_status_v1(&real_proof_v1, 2, &EXPECTED_PUBLIC_INPUT_HASH),
            OrchardRealProofStatus::Malformed
        );
        assert_eq!(
            orchard_real_proof_request_hash_v1(&real_proof_v1, 2, &EXPECTED_PUBLIC_INPUT_HASH),
            None
        );
        assert_eq!(
            orchard_real_verifier_input_hash_v1(&real_proof_v1, 2, &EXPECTED_PUBLIC_INPUT_HASH),
            None
        );
        assert_eq!(
            orchard_real_native_proof_hash_v1(&real_proof_v1, 2, &EXPECTED_PUBLIC_INPUT_HASH),
            None
        );
        assert_eq!(
            orchard_real_proof_check_v1(&real_proof_v1, 2, &EXPECTED_PUBLIC_INPUT_HASH),
            OrchardRealProofCheck {
                status: OrchardRealProofStatus::Malformed,
                request_hash: None,
            }
        );
        assert_eq!(
            orchard_real_proof_check_v2(&real_proof_v1, 2, &EXPECTED_PUBLIC_INPUT_HASH),
            OrchardRealProofCheckV2 {
                status: OrchardRealProofStatus::Malformed,
                request_hash: None,
                verifier_input_hash: None,
            }
        );
        assert_eq!(
            orchard_real_proof_check_v3(&real_proof_v1, 2, &EXPECTED_PUBLIC_INPUT_HASH),
            OrchardRealProofCheckV3 {
                status: OrchardRealProofStatus::Malformed,
                request_hash: None,
                verifier_input_hash: None,
                native_proof_hash: None,
            }
        );
        let mut wrong_real_proof_v1 = real_proof_v1.clone();
        wrong_real_proof_v1[ORCHARD_REAL_PROOF_PREFIX_V1.len()] = 0x01;
        assert!(!is_well_formed_orchard_real_proof_v1(
            &wrong_real_proof_v1,
            1,
            &EXPECTED_PUBLIC_INPUT_HASH
        ));
        assert_eq!(
            orchard_real_proof_status_v1(&wrong_real_proof_v1, 1, &EXPECTED_PUBLIC_INPUT_HASH),
            OrchardRealProofStatus::Malformed
        );
        let mut wrong_real_proof_v1 = real_proof_v1.clone();
        let verifier_key_hash_offset = ORCHARD_REAL_PROOF_PREFIX_V1.len() + 1 + 1 + HASH_SIZE;
        wrong_real_proof_v1[verifier_key_hash_offset] ^= 0x01;
        assert!(!is_well_formed_orchard_real_proof_v1(
            &wrong_real_proof_v1,
            1,
            &EXPECTED_PUBLIC_INPUT_HASH
        ));
        let mut wrong_real_proof_v1 = real_proof_v1.clone();
        let proof_len_offset = verifier_key_hash_offset + HASH_SIZE;
        wrong_real_proof_v1[proof_len_offset] ^= 0x01;
        assert!(!is_well_formed_orchard_real_proof_v1(
            &wrong_real_proof_v1,
            1,
            &EXPECTED_PUBLIC_INPUT_HASH
        ));
        let real_body_v1 = build_orchard_real_proof_body_with_context_v1(
            1,
            &EXPECTED_PUBLIC_INPUT_HASH,
            &native_bytes,
        );
        let real_payload_v1 =
            build_orchard_proof_payload_with_body_v1(1, &EXPECTED_PUBLIC_INPUT_HASH, &real_body_v1);
        let real_bundle_v4 =
            build_proof_bundle_with_payload_v4(1, &EXPECTED_PUBLIC_INPUT_HASH, &real_payload_v1);
        assert!(!verify_orchard_proof_body_v1(
            &real_body_v1,
            1,
            &EXPECTED_PUBLIC_INPUT_HASH
        ));
        assert!(!verify_orchard_proof_payload_v1(
            &real_payload_v1,
            1,
            &EXPECTED_PUBLIC_INPUT_HASH
        ));
        assert!(!verify_proof_bundle_v4(
            &real_bundle_v4,
            1,
            &EXPECTED_PUBLIC_INPUT_HASH
        ));
        assert_eq!(
            check_orchard_proof_body_v1(&real_body_v1, 1, &EXPECTED_PUBLIC_INPUT_HASH),
            ProofBundleCheck {
                status: OrchardRealProofStatus::Unsupported,
                proof_body_mode: Some(ORCHARD_PROOF_BODY_MODE_REAL),
                real_request_hash: Some(EXPECTED_ORCHARD_REAL_REQUEST_HASH),
            }
        );
        assert_eq!(
            check_orchard_proof_payload_v1(&real_payload_v1, 1, &EXPECTED_PUBLIC_INPUT_HASH),
            ProofBundleCheck {
                status: OrchardRealProofStatus::Unsupported,
                proof_body_mode: Some(ORCHARD_PROOF_BODY_MODE_REAL),
                real_request_hash: Some(EXPECTED_ORCHARD_REAL_REQUEST_HASH),
            }
        );
        assert_eq!(
            check_proof_bundle_v4(&real_bundle_v4, 1, &EXPECTED_PUBLIC_INPUT_HASH),
            ProofBundleCheck {
                status: OrchardRealProofStatus::Unsupported,
                proof_body_mode: Some(ORCHARD_PROOF_BODY_MODE_REAL),
                real_request_hash: Some(EXPECTED_ORCHARD_REAL_REQUEST_HASH),
            }
        );
        assert_eq!(
            check_proof_bundle_v5(&real_bundle_v4, 1, &EXPECTED_PUBLIC_INPUT_HASH),
            ProofBundleCheckV2 {
                status: OrchardRealProofStatus::Unsupported,
                proof_body_mode: Some(ORCHARD_PROOF_BODY_MODE_REAL),
                real_request_hash: Some(EXPECTED_ORCHARD_REAL_REQUEST_HASH),
                real_verifier_input_hash: Some(EXPECTED_ORCHARD_REAL_VERIFIER_INPUT_HASH),
            }
        );
        assert_eq!(
            check_proof_bundle_v6(&real_bundle_v4, 1, &EXPECTED_PUBLIC_INPUT_HASH),
            ProofBundleCheckV3 {
                status: OrchardRealProofStatus::Unsupported,
                proof_body_mode: Some(ORCHARD_PROOF_BODY_MODE_REAL),
                real_request_hash: Some(EXPECTED_ORCHARD_REAL_REQUEST_HASH),
                real_verifier_input_hash: Some(EXPECTED_ORCHARD_REAL_VERIFIER_INPUT_HASH),
                real_native_proof_hash: Some(EXPECTED_ORCHARD_NATIVE_PROOF_HASH),
            }
        );
        let mut unknown_body_mode = orchard_body_v1.clone();
        unknown_body_mode[ORCHARD_PROOF_BODY_PREFIX_V1.len()] = 0xff;
        assert!(!verify_orchard_proof_body_v1(
            &unknown_body_mode,
            1,
            &EXPECTED_PUBLIC_INPUT_HASH
        ));
        assert_eq!(
            check_orchard_proof_body_v1(&unknown_body_mode, 1, &EXPECTED_PUBLIC_INPUT_HASH),
            ProofBundleCheck {
                status: OrchardRealProofStatus::Malformed,
                proof_body_mode: Some(0xff),
                real_request_hash: None,
            }
        );
        assert!(verify_orchard_proof_payload_v1(
            &orchard_payload_v1,
            1,
            &EXPECTED_PUBLIC_INPUT_HASH
        ));
        assert!(!verify_orchard_proof_payload_v1(
            &orchard_payload_v1,
            2,
            &EXPECTED_PUBLIC_INPUT_HASH
        ));
        assert!(verify_proof_bundle_v4(
            &bundle_v4,
            1,
            &EXPECTED_PUBLIC_INPUT_HASH
        ));
        assert_eq!(
            check_proof_bundle_v4(&bundle_v4, 1, &EXPECTED_PUBLIC_INPUT_HASH),
            ProofBundleCheck {
                status: OrchardRealProofStatus::Valid,
                proof_body_mode: Some(ORCHARD_PROOF_BODY_MODE_SCAFFOLD),
                real_request_hash: None,
            }
        );
        assert_eq!(
            check_proof_bundle_v5(&bundle_v4, 1, &EXPECTED_PUBLIC_INPUT_HASH),
            ProofBundleCheckV2 {
                status: OrchardRealProofStatus::Valid,
                proof_body_mode: Some(ORCHARD_PROOF_BODY_MODE_SCAFFOLD),
                real_request_hash: None,
                real_verifier_input_hash: None,
            }
        );
        assert_eq!(
            check_proof_bundle_v6(&bundle_v4, 1, &EXPECTED_PUBLIC_INPUT_HASH),
            ProofBundleCheckV3 {
                status: OrchardRealProofStatus::Valid,
                proof_body_mode: Some(ORCHARD_PROOF_BODY_MODE_SCAFFOLD),
                real_request_hash: None,
                real_verifier_input_hash: None,
                real_native_proof_hash: None,
            }
        );
        assert!(!verify_proof_bundle_v4(
            &bundle_v4,
            2,
            &EXPECTED_PUBLIC_INPUT_HASH
        ));
        assert_eq!(
            check_proof_bundle_v4(&bundle_v4, 2, &EXPECTED_PUBLIC_INPUT_HASH),
            ProofBundleCheck::malformed()
        );

        let mut invalid_scaffold_body = orchard_body_v1.clone();
        *invalid_scaffold_body.last_mut().expect("body has payload") ^= 1;
        assert_eq!(
            check_orchard_proof_body_v1(&invalid_scaffold_body, 1, &EXPECTED_PUBLIC_INPUT_HASH),
            ProofBundleCheck {
                status: OrchardRealProofStatus::Invalid,
                proof_body_mode: Some(ORCHARD_PROOF_BODY_MODE_SCAFFOLD),
                real_request_hash: None,
            }
        );

        let mut wrong_field_hash = FIELD_HASH;
        wrong_field_hash[0] ^= 1;
        assert!(!verify_proof_payload_v1(
            &EXPECTED_PROOF,
            &wrong_field_hash,
            &TX_BINDING_HASH
        ));
        assert!(!verify_proof_payload_v2(
            &EXPECTED_MINT_PROOF_V2,
            1,
            &wrong_field_hash,
            &TX_BINDING_HASH
        ));
        let wrong_public_input_hash =
            proof_public_input_hash(1, &wrong_field_hash, &TX_BINDING_HASH);
        assert!(!verify_proof_payload_v3(
            &EXPECTED_MINT_PROOF_V3,
            1,
            &wrong_public_input_hash
        ));
        assert!(!verify_proof_bundle_v4(
            &bundle_v4,
            1,
            &wrong_public_input_hash
        ));

        let mut wrong_bundle = bundle_v4;
        wrong_bundle[0] ^= 1;
        assert!(!verify_proof_bundle_v4(
            &wrong_bundle,
            1,
            &EXPECTED_PUBLIC_INPUT_HASH
        ));
        assert_eq!(
            check_proof_bundle_v4(&wrong_bundle, 1, &EXPECTED_PUBLIC_INPUT_HASH),
            ProofBundleCheck::malformed()
        );

        let mut wrong_payload = orchard_payload_v1;
        wrong_payload[ORCHARD_PROOF_PAYLOAD_PREFIX_V1.len()] ^= 1;
        assert!(!verify_orchard_proof_payload_v1(
            &wrong_payload,
            1,
            &EXPECTED_PUBLIC_INPUT_HASH
        ));
    }

    #[cfg(not(feature = "verifier-fixture"))]
    #[test]
    fn reports_orchard_real_verifier_backend_capability() {
        assert_eq!(
            orchard_real_verifier_backend_v1(),
            OrchardRealVerifierBackend::Unsupported
        );
        assert!(!orchard_real_verifier_supports_real_proofs_v1());
        assert_eq!(
            orchard_real_verifier_backend_v1().as_ffi_code(),
            ORCHARD_REAL_VERIFIER_BACKEND_UNSUPPORTED
        );
        assert_eq!(
            OrchardRealVerifierBackend::OrchardV1.as_ffi_code(),
            ORCHARD_REAL_VERIFIER_BACKEND_ORCHARD_V1
        );
        assert!(OrchardRealVerifierBackend::OrchardV1.supports_real_proofs());
    }

    #[cfg(not(feature = "verifier-fixture"))]
    #[test]
    fn injected_backend_drives_real_bundle_validity() {
        let valid_proof_bytes = native_proof_bytes(0x77);
        let valid_proof_v1 =
            build_orchard_real_proof_v1(1, &EXPECTED_PUBLIC_INPUT_HASH, &valid_proof_bytes);
        let valid_request_hash =
            orchard_real_proof_request_hash_v1(&valid_proof_v1, 1, &EXPECTED_PUBLIC_INPUT_HASH)
                .expect("valid test vector request hash");
        let backend = TestVectorOrchardRealProofBackend { valid_request_hash };
        assert_eq!(backend.backend(), OrchardRealVerifierBackend::OrchardV1);

        let valid_request =
            decode_orchard_real_proof_request_v1(&valid_proof_v1, 1, &EXPECTED_PUBLIC_INPUT_HASH)
                .expect("valid test vector decodes");
        assert_eq!(
            verify_orchard_real_proof_backend_status_with_backend_v1(&valid_request, &backend),
            OrchardRealProofStatus::Valid
        );
        assert_eq!(
            valid_request.verifier_input_hash_v1(),
            EXPECTED_ORCHARD_REAL_VERIFIER_INPUT_HASH
        );
        let valid_native_proof = decode_orchard_native_proof_bytes_v1(&valid_request)
            .expect("valid native test vector decodes");
        assert_eq!(
            valid_native_proof.proof_hash_v1(),
            EXPECTED_ORCHARD_NATIVE_PROOF_HASH_77
        );
        assert_eq!(
            orchard_real_proof_check_with_backend_v1(
                &valid_proof_v1,
                1,
                &EXPECTED_PUBLIC_INPUT_HASH,
                &backend,
            ),
            OrchardRealProofCheck {
                status: OrchardRealProofStatus::Valid,
                request_hash: Some(valid_request_hash),
            }
        );
        assert_eq!(
            orchard_real_proof_check_with_backend_v2(
                &valid_proof_v1,
                1,
                &EXPECTED_PUBLIC_INPUT_HASH,
                &backend,
            ),
            OrchardRealProofCheckV2 {
                status: OrchardRealProofStatus::Valid,
                request_hash: Some(valid_request_hash),
                verifier_input_hash: Some(EXPECTED_ORCHARD_REAL_VERIFIER_INPUT_HASH),
            }
        );
        assert_eq!(
            orchard_real_proof_check_with_backend_v3(
                &valid_proof_v1,
                1,
                &EXPECTED_PUBLIC_INPUT_HASH,
                &backend,
            ),
            OrchardRealProofCheckV3 {
                status: OrchardRealProofStatus::Valid,
                request_hash: Some(valid_request_hash),
                verifier_input_hash: Some(EXPECTED_ORCHARD_REAL_VERIFIER_INPUT_HASH),
                native_proof_hash: Some(EXPECTED_ORCHARD_NATIVE_PROOF_HASH_77),
            }
        );

        let valid_body_v1 = build_orchard_real_proof_body_with_context_v1(
            1,
            &EXPECTED_PUBLIC_INPUT_HASH,
            &valid_proof_bytes,
        );
        let valid_payload_v1 = build_orchard_proof_payload_with_body_v1(
            1,
            &EXPECTED_PUBLIC_INPUT_HASH,
            &valid_body_v1,
        );
        let valid_bundle_v4 =
            build_proof_bundle_with_payload_v4(1, &EXPECTED_PUBLIC_INPUT_HASH, &valid_payload_v1);
        assert_eq!(
            check_proof_bundle_with_backend_v4(
                &valid_bundle_v4,
                1,
                &EXPECTED_PUBLIC_INPUT_HASH,
                &backend,
            ),
            ProofBundleCheck {
                status: OrchardRealProofStatus::Valid,
                proof_body_mode: Some(ORCHARD_PROOF_BODY_MODE_REAL),
                real_request_hash: Some(valid_request_hash),
            }
        );
        assert_eq!(
            check_proof_bundle_with_backend_v5(
                &valid_bundle_v4,
                1,
                &EXPECTED_PUBLIC_INPUT_HASH,
                &backend,
            ),
            ProofBundleCheckV2 {
                status: OrchardRealProofStatus::Valid,
                proof_body_mode: Some(ORCHARD_PROOF_BODY_MODE_REAL),
                real_request_hash: Some(valid_request_hash),
                real_verifier_input_hash: Some(EXPECTED_ORCHARD_REAL_VERIFIER_INPUT_HASH),
            }
        );
        assert_eq!(
            check_proof_bundle_with_backend_v6(
                &valid_bundle_v4,
                1,
                &EXPECTED_PUBLIC_INPUT_HASH,
                &backend,
            ),
            ProofBundleCheckV3 {
                status: OrchardRealProofStatus::Valid,
                proof_body_mode: Some(ORCHARD_PROOF_BODY_MODE_REAL),
                real_request_hash: Some(valid_request_hash),
                real_verifier_input_hash: Some(EXPECTED_ORCHARD_REAL_VERIFIER_INPUT_HASH),
                real_native_proof_hash: Some(EXPECTED_ORCHARD_NATIVE_PROOF_HASH_77),
            }
        );

        let invalid_proof_bytes = native_proof_bytes(0x78);
        let invalid_proof_v1 =
            build_orchard_real_proof_v1(1, &EXPECTED_PUBLIC_INPUT_HASH, &invalid_proof_bytes);
        let invalid_request_hash =
            orchard_real_proof_request_hash_v1(&invalid_proof_v1, 1, &EXPECTED_PUBLIC_INPUT_HASH)
                .expect("invalid test vector request hash");
        let invalid_request =
            decode_orchard_real_proof_request_v1(&invalid_proof_v1, 1, &EXPECTED_PUBLIC_INPUT_HASH)
                .expect("invalid test vector decodes");
        assert_eq!(
            invalid_request.verifier_input_hash_v1(),
            EXPECTED_ORCHARD_REAL_VERIFIER_INPUT_HASH
        );
        let invalid_native_proof = decode_orchard_native_proof_bytes_v1(&invalid_request)
            .expect("invalid native test vector decodes");
        assert_eq!(
            invalid_native_proof.proof_hash_v1(),
            EXPECTED_ORCHARD_NATIVE_PROOF_HASH_78
        );
        assert_eq!(
            orchard_real_proof_check_with_backend_v1(
                &invalid_proof_v1,
                1,
                &EXPECTED_PUBLIC_INPUT_HASH,
                &backend,
            ),
            OrchardRealProofCheck {
                status: OrchardRealProofStatus::Invalid,
                request_hash: Some(invalid_request_hash),
            }
        );
        assert_eq!(
            orchard_real_proof_check_with_backend_v2(
                &invalid_proof_v1,
                1,
                &EXPECTED_PUBLIC_INPUT_HASH,
                &backend,
            ),
            OrchardRealProofCheckV2 {
                status: OrchardRealProofStatus::Invalid,
                request_hash: Some(invalid_request_hash),
                verifier_input_hash: Some(EXPECTED_ORCHARD_REAL_VERIFIER_INPUT_HASH),
            }
        );
        assert_eq!(
            orchard_real_proof_check_with_backend_v3(
                &invalid_proof_v1,
                1,
                &EXPECTED_PUBLIC_INPUT_HASH,
                &backend,
            ),
            OrchardRealProofCheckV3 {
                status: OrchardRealProofStatus::Invalid,
                request_hash: Some(invalid_request_hash),
                verifier_input_hash: Some(EXPECTED_ORCHARD_REAL_VERIFIER_INPUT_HASH),
                native_proof_hash: Some(EXPECTED_ORCHARD_NATIVE_PROOF_HASH_78),
            }
        );

        let invalid_body_v1 = build_orchard_real_proof_body_with_context_v1(
            1,
            &EXPECTED_PUBLIC_INPUT_HASH,
            &invalid_proof_bytes,
        );
        let invalid_payload_v1 = build_orchard_proof_payload_with_body_v1(
            1,
            &EXPECTED_PUBLIC_INPUT_HASH,
            &invalid_body_v1,
        );
        let invalid_bundle_v4 =
            build_proof_bundle_with_payload_v4(1, &EXPECTED_PUBLIC_INPUT_HASH, &invalid_payload_v1);
        assert_eq!(
            check_proof_bundle_with_backend_v4(
                &invalid_bundle_v4,
                1,
                &EXPECTED_PUBLIC_INPUT_HASH,
                &backend,
            ),
            ProofBundleCheck {
                status: OrchardRealProofStatus::Invalid,
                proof_body_mode: Some(ORCHARD_PROOF_BODY_MODE_REAL),
                real_request_hash: Some(invalid_request_hash),
            }
        );
        assert_eq!(
            check_proof_bundle_with_backend_v6(
                &invalid_bundle_v4,
                1,
                &EXPECTED_PUBLIC_INPUT_HASH,
                &backend,
            ),
            ProofBundleCheckV3 {
                status: OrchardRealProofStatus::Invalid,
                proof_body_mode: Some(ORCHARD_PROOF_BODY_MODE_REAL),
                real_request_hash: Some(invalid_request_hash),
                real_verifier_input_hash: Some(EXPECTED_ORCHARD_REAL_VERIFIER_INPUT_HASH),
                real_native_proof_hash: Some(EXPECTED_ORCHARD_NATIVE_PROOF_HASH_78),
            }
        );

        assert_eq!(
            check_proof_bundle_v4(&valid_bundle_v4, 1, &EXPECTED_PUBLIC_INPUT_HASH),
            ProofBundleCheck {
                status: OrchardRealProofStatus::Unsupported,
                proof_body_mode: Some(ORCHARD_PROOF_BODY_MODE_REAL),
                real_request_hash: Some(valid_request_hash),
            }
        );
    }

    #[cfg(feature = "verifier-fixture")]
    #[test]
    fn fixture_backend_drives_public_real_proof_abi() {
        assert_eq!(
            orchard_real_verifier_backend_v1(),
            OrchardRealVerifierBackend::OrchardV1
        );
        assert!(orchard_real_verifier_supports_real_proofs_v1());
        assert_eq!(
            orchard_real_verifier_backend_v1().as_ffi_code(),
            ORCHARD_REAL_VERIFIER_BACKEND_ORCHARD_V1
        );
        assert_eq!(
            zkc_shielded_orchard_real_verifier_backend_v1(),
            ORCHARD_REAL_VERIFIER_BACKEND_ORCHARD_V1
        );
        assert_eq!(zkc_shielded_orchard_real_verifier_supports_proofs_v1(), 1);

        let verifier_input = OrchardRealVerifierInput {
            proof_kind: 1,
            public_input_hash: EXPECTED_PUBLIC_INPUT_HASH,
            verifier_key_hash: expected_orchard_real_verifier_key_hash_v1(),
        };
        let proof_bytes = build_orchard_fixture_proof_bytes_v1(&verifier_input);
        assert_eq!(
            proof_bytes.len(),
            ORCHARD_REAL_NATIVE_PROOF_HEADER_LEN_V1 + ORCHARD_REAL_FIXTURE_PROOF_LEN_V1
        );

        let real_proof_v1 =
            build_orchard_real_proof_v1(1, &EXPECTED_PUBLIC_INPUT_HASH, &proof_bytes);
        let real_request =
            decode_orchard_real_proof_request_v1(&real_proof_v1, 1, &EXPECTED_PUBLIC_INPUT_HASH)
                .expect("fixture native proof request decodes");
        let native_proof = decode_orchard_native_proof_bytes_v1(&real_request)
            .expect("fixture native proof decodes");
        assert_eq!(
            native_proof.verifier_key_hash,
            EXPECTED_ORCHARD_REAL_VK_HASH
        );
        assert_eq!(
            native_proof.verifier_input_hash,
            EXPECTED_ORCHARD_REAL_VERIFIER_INPUT_HASH
        );
        assert_eq!(
            native_proof.proof_bytes.len(),
            ORCHARD_REAL_FIXTURE_PROOF_LEN_V1
        );
        assert!(native_proof
            .proof_bytes
            .starts_with(ORCHARD_REAL_FIXTURE_PROOF_PREFIX_V1));
        assert_eq!(
            &native_proof.proof_bytes[ORCHARD_REAL_FIXTURE_PROOF_PREFIX_V1.len()..],
            EXPECTED_ORCHARD_REAL_VERIFIER_INPUT_HASH
        );
        let native_proof_hash = native_proof.proof_hash_v1();
        assert_eq!(
            orchard_real_native_proof_hash_v1(&real_proof_v1, 1, &EXPECTED_PUBLIC_INPUT_HASH),
            Some(native_proof_hash)
        );
        let request_hash =
            orchard_real_proof_request_hash_v1(&real_proof_v1, 1, &EXPECTED_PUBLIC_INPUT_HASH)
                .expect("fixture proof request hash");
        assert_ne!(request_hash, EXPECTED_ORCHARD_REAL_REQUEST_HASH);
        assert_eq!(
            orchard_real_verifier_input_hash_v1(&real_proof_v1, 1, &EXPECTED_PUBLIC_INPUT_HASH),
            Some(EXPECTED_ORCHARD_REAL_VERIFIER_INPUT_HASH)
        );
        assert!(verify_orchard_real_proof_v1(
            &real_proof_v1,
            1,
            &EXPECTED_PUBLIC_INPUT_HASH
        ));
        assert_eq!(
            orchard_real_proof_status_v1(&real_proof_v1, 1, &EXPECTED_PUBLIC_INPUT_HASH),
            OrchardRealProofStatus::Valid
        );
        assert_eq!(
            orchard_real_proof_check_v2(&real_proof_v1, 1, &EXPECTED_PUBLIC_INPUT_HASH),
            OrchardRealProofCheckV2 {
                status: OrchardRealProofStatus::Valid,
                request_hash: Some(request_hash),
                verifier_input_hash: Some(EXPECTED_ORCHARD_REAL_VERIFIER_INPUT_HASH),
            }
        );
        assert_eq!(
            orchard_real_proof_check_v3(&real_proof_v1, 1, &EXPECTED_PUBLIC_INPUT_HASH),
            OrchardRealProofCheckV3 {
                status: OrchardRealProofStatus::Valid,
                request_hash: Some(request_hash),
                verifier_input_hash: Some(EXPECTED_ORCHARD_REAL_VERIFIER_INPUT_HASH),
                native_proof_hash: Some(native_proof_hash),
            }
        );

        let mut request_hash_out = [0xaa; HASH_SIZE];
        let mut verifier_input_hash_out = [0xaa; HASH_SIZE];
        let mut native_proof_hash_out = [0xaa; HASH_SIZE];
        let status = unsafe {
            zkc_shielded_orchard_real_proof_check_v2(
                real_proof_v1.as_ptr(),
                real_proof_v1.len(),
                1,
                EXPECTED_PUBLIC_INPUT_HASH.as_ptr(),
                EXPECTED_PUBLIC_INPUT_HASH.len(),
                request_hash_out.as_mut_ptr(),
                request_hash_out.len(),
                verifier_input_hash_out.as_mut_ptr(),
                verifier_input_hash_out.len(),
            )
        };
        assert_eq!(status, ORCHARD_REAL_PROOF_STATUS_VALID);
        assert_eq!(request_hash_out, request_hash);
        assert_eq!(
            verifier_input_hash_out,
            EXPECTED_ORCHARD_REAL_VERIFIER_INPUT_HASH
        );
        let status_v3 = unsafe {
            zkc_shielded_orchard_real_proof_check_v3(
                real_proof_v1.as_ptr(),
                real_proof_v1.len(),
                1,
                EXPECTED_PUBLIC_INPUT_HASH.as_ptr(),
                EXPECTED_PUBLIC_INPUT_HASH.len(),
                request_hash_out.as_mut_ptr(),
                request_hash_out.len(),
                verifier_input_hash_out.as_mut_ptr(),
                verifier_input_hash_out.len(),
                native_proof_hash_out.as_mut_ptr(),
                native_proof_hash_out.len(),
            )
        };
        assert_eq!(status_v3, ORCHARD_REAL_PROOF_STATUS_VALID);
        assert_eq!(request_hash_out, request_hash);
        assert_eq!(
            verifier_input_hash_out,
            EXPECTED_ORCHARD_REAL_VERIFIER_INPUT_HASH
        );
        assert_eq!(native_proof_hash_out, native_proof_hash);

        let real_body_v1 = build_orchard_real_proof_body_with_context_v1(
            1,
            &EXPECTED_PUBLIC_INPUT_HASH,
            &proof_bytes,
        );
        let real_payload_v1 =
            build_orchard_proof_payload_with_body_v1(1, &EXPECTED_PUBLIC_INPUT_HASH, &real_body_v1);
        let real_bundle_v4 =
            build_proof_bundle_with_payload_v4(1, &EXPECTED_PUBLIC_INPUT_HASH, &real_payload_v1);
        assert_eq!(
            check_proof_bundle_v5(&real_bundle_v4, 1, &EXPECTED_PUBLIC_INPUT_HASH),
            ProofBundleCheckV2 {
                status: OrchardRealProofStatus::Valid,
                proof_body_mode: Some(ORCHARD_PROOF_BODY_MODE_REAL),
                real_request_hash: Some(request_hash),
                real_verifier_input_hash: Some(EXPECTED_ORCHARD_REAL_VERIFIER_INPUT_HASH),
            }
        );
        assert_eq!(
            check_proof_bundle_v6(&real_bundle_v4, 1, &EXPECTED_PUBLIC_INPUT_HASH),
            ProofBundleCheckV3 {
                status: OrchardRealProofStatus::Valid,
                proof_body_mode: Some(ORCHARD_PROOF_BODY_MODE_REAL),
                real_request_hash: Some(request_hash),
                real_verifier_input_hash: Some(EXPECTED_ORCHARD_REAL_VERIFIER_INPUT_HASH),
                real_native_proof_hash: Some(native_proof_hash),
            }
        );

        let mut proof_body_mode = 0xff;
        request_hash_out.fill(0xaa);
        verifier_input_hash_out.fill(0xaa);
        native_proof_hash_out.fill(0xaa);
        let bundle_status = unsafe {
            zkc_shielded_check_bundle_v5(
                real_bundle_v4.as_ptr(),
                real_bundle_v4.len(),
                1,
                EXPECTED_PUBLIC_INPUT_HASH.as_ptr(),
                EXPECTED_PUBLIC_INPUT_HASH.len(),
                &mut proof_body_mode,
                request_hash_out.as_mut_ptr(),
                request_hash_out.len(),
                verifier_input_hash_out.as_mut_ptr(),
                verifier_input_hash_out.len(),
            )
        };
        assert_eq!(bundle_status, ORCHARD_REAL_PROOF_STATUS_VALID);
        assert_eq!(proof_body_mode, ORCHARD_PROOF_BODY_MODE_REAL);
        assert_eq!(request_hash_out, request_hash);
        assert_eq!(
            verifier_input_hash_out,
            EXPECTED_ORCHARD_REAL_VERIFIER_INPUT_HASH
        );
        let bundle_status_v6 = unsafe {
            zkc_shielded_check_bundle_v6(
                real_bundle_v4.as_ptr(),
                real_bundle_v4.len(),
                1,
                EXPECTED_PUBLIC_INPUT_HASH.as_ptr(),
                EXPECTED_PUBLIC_INPUT_HASH.len(),
                &mut proof_body_mode,
                request_hash_out.as_mut_ptr(),
                request_hash_out.len(),
                verifier_input_hash_out.as_mut_ptr(),
                verifier_input_hash_out.len(),
                native_proof_hash_out.as_mut_ptr(),
                native_proof_hash_out.len(),
            )
        };
        assert_eq!(bundle_status_v6, ORCHARD_REAL_PROOF_STATUS_VALID);
        assert_eq!(proof_body_mode, ORCHARD_PROOF_BODY_MODE_REAL);
        assert_eq!(request_hash_out, request_hash);
        assert_eq!(
            verifier_input_hash_out,
            EXPECTED_ORCHARD_REAL_VERIFIER_INPUT_HASH
        );
        assert_eq!(native_proof_hash_out, native_proof_hash);

        let mut tampered_proof_bytes = proof_bytes.clone();
        *tampered_proof_bytes
            .last_mut()
            .expect("fixture proof has input hash") ^= 1;
        let tampered_proof_v1 =
            build_orchard_real_proof_v1(1, &EXPECTED_PUBLIC_INPUT_HASH, &tampered_proof_bytes);
        let tampered_request_hash =
            orchard_real_proof_request_hash_v1(&tampered_proof_v1, 1, &EXPECTED_PUBLIC_INPUT_HASH)
                .expect("tampered fixture proof request hash");
        assert_eq!(
            orchard_real_proof_check_v2(&tampered_proof_v1, 1, &EXPECTED_PUBLIC_INPUT_HASH),
            OrchardRealProofCheckV2 {
                status: OrchardRealProofStatus::Invalid,
                request_hash: Some(tampered_request_hash),
                verifier_input_hash: Some(EXPECTED_ORCHARD_REAL_VERIFIER_INPUT_HASH),
            }
        );
        assert_eq!(
            orchard_real_proof_check_v3(&tampered_proof_v1, 1, &EXPECTED_PUBLIC_INPUT_HASH)
                .native_proof_hash
                .is_some(),
            true
        );
        let raw_fixture_payload = native_proof.proof_bytes.to_vec();
        let raw_fixture_proof_v1 =
            build_orchard_real_proof_v1(1, &EXPECTED_PUBLIC_INPUT_HASH, &raw_fixture_payload);
        let raw_fixture_request_hash = orchard_real_proof_request_hash_v1(
            &raw_fixture_proof_v1,
            1,
            &EXPECTED_PUBLIC_INPUT_HASH,
        )
        .expect("raw fixture proof request hash");
        assert_eq!(
            orchard_real_proof_check_v2(&raw_fixture_proof_v1, 1, &EXPECTED_PUBLIC_INPUT_HASH),
            OrchardRealProofCheckV2 {
                status: OrchardRealProofStatus::Invalid,
                request_hash: Some(raw_fixture_request_hash),
                verifier_input_hash: Some(EXPECTED_ORCHARD_REAL_VERIFIER_INPUT_HASH),
            }
        );
        assert_eq!(
            orchard_real_proof_check_v3(&raw_fixture_proof_v1, 1, &EXPECTED_PUBLIC_INPUT_HASH)
                .native_proof_hash,
            None
        );
        assert_eq!(
            orchard_real_proof_status_v1(&real_proof_v1, 2, &EXPECTED_PUBLIC_INPUT_HASH),
            OrchardRealProofStatus::Malformed
        );
    }

    #[cfg(not(feature = "verifier-fixture"))]
    #[test]
    fn c_abi_matches_safe_api() {
        let ok = unsafe {
            zkc_shielded_verify_proof_v1(
                EXPECTED_PROOF.as_ptr(),
                EXPECTED_PROOF.len(),
                FIELD_HASH.as_ptr(),
                FIELD_HASH.len(),
                TX_BINDING_HASH.as_ptr(),
                TX_BINDING_HASH.len(),
            )
        };
        assert_eq!(ok, 1);

        let bad = unsafe {
            zkc_shielded_verify_proof_v1(
                EXPECTED_PROOF.as_ptr(),
                EXPECTED_PROOF.len() - 1,
                FIELD_HASH.as_ptr(),
                FIELD_HASH.len(),
                TX_BINDING_HASH.as_ptr(),
                TX_BINDING_HASH.len(),
            )
        };
        assert_eq!(bad, 0);

        let null = unsafe {
            zkc_shielded_verify_proof_v1(
                core::ptr::null(),
                EXPECTED_PROOF.len(),
                FIELD_HASH.as_ptr(),
                FIELD_HASH.len(),
                TX_BINDING_HASH.as_ptr(),
                TX_BINDING_HASH.len(),
            )
        };
        assert_eq!(null, 0);

        let ok_v2 = unsafe {
            zkc_shielded_verify_proof_v2(
                EXPECTED_MINT_PROOF_V2.as_ptr(),
                EXPECTED_MINT_PROOF_V2.len(),
                1,
                FIELD_HASH.as_ptr(),
                FIELD_HASH.len(),
                TX_BINDING_HASH.as_ptr(),
                TX_BINDING_HASH.len(),
            )
        };
        assert_eq!(ok_v2, 1);

        let bad_kind_v2 = unsafe {
            zkc_shielded_verify_proof_v2(
                EXPECTED_MINT_PROOF_V2.as_ptr(),
                EXPECTED_MINT_PROOF_V2.len(),
                2,
                FIELD_HASH.as_ptr(),
                FIELD_HASH.len(),
                TX_BINDING_HASH.as_ptr(),
                TX_BINDING_HASH.len(),
            )
        };
        assert_eq!(bad_kind_v2, 0);

        let ok_v3 = unsafe {
            zkc_shielded_verify_proof_v3(
                EXPECTED_MINT_PROOF_V3.as_ptr(),
                EXPECTED_MINT_PROOF_V3.len(),
                1,
                EXPECTED_PUBLIC_INPUT_HASH.as_ptr(),
                EXPECTED_PUBLIC_INPUT_HASH.len(),
            )
        };
        assert_eq!(ok_v3, 1);

        let bad_kind_v3 = unsafe {
            zkc_shielded_verify_proof_v3(
                EXPECTED_MINT_PROOF_V3.as_ptr(),
                EXPECTED_MINT_PROOF_V3.len(),
                2,
                EXPECTED_PUBLIC_INPUT_HASH.as_ptr(),
                EXPECTED_PUBLIC_INPUT_HASH.len(),
            )
        };
        assert_eq!(bad_kind_v3, 0);

        let bundle_v4 = build_proof_bundle_v4(1, &EXPECTED_PUBLIC_INPUT_HASH);
        let ok_v4 = unsafe {
            zkc_shielded_verify_bundle_v4(
                bundle_v4.as_ptr(),
                bundle_v4.len(),
                1,
                EXPECTED_PUBLIC_INPUT_HASH.as_ptr(),
                EXPECTED_PUBLIC_INPUT_HASH.len(),
            )
        };
        assert_eq!(ok_v4, 1);

        let bad_kind_v4 = unsafe {
            zkc_shielded_verify_bundle_v4(
                bundle_v4.as_ptr(),
                bundle_v4.len(),
                2,
                EXPECTED_PUBLIC_INPUT_HASH.as_ptr(),
                EXPECTED_PUBLIC_INPUT_HASH.len(),
            )
        };
        assert_eq!(bad_kind_v4, 0);

        let mut proof_body_mode = 0xff;
        let mut request_hash = [0xaa; HASH_SIZE];
        let check_bundle_v4 = unsafe {
            zkc_shielded_check_bundle_v4(
                bundle_v4.as_ptr(),
                bundle_v4.len(),
                1,
                EXPECTED_PUBLIC_INPUT_HASH.as_ptr(),
                EXPECTED_PUBLIC_INPUT_HASH.len(),
                &mut proof_body_mode,
                request_hash.as_mut_ptr(),
                request_hash.len(),
            )
        };
        assert_eq!(check_bundle_v4, ORCHARD_REAL_PROOF_STATUS_VALID);
        assert_eq!(proof_body_mode, ORCHARD_PROOF_BODY_MODE_SCAFFOLD);
        assert_eq!(request_hash, [0u8; HASH_SIZE]);

        let mut verifier_input_hash = [0xaa; HASH_SIZE];
        let check_bundle_v5 = unsafe {
            zkc_shielded_check_bundle_v5(
                bundle_v4.as_ptr(),
                bundle_v4.len(),
                1,
                EXPECTED_PUBLIC_INPUT_HASH.as_ptr(),
                EXPECTED_PUBLIC_INPUT_HASH.len(),
                &mut proof_body_mode,
                request_hash.as_mut_ptr(),
                request_hash.len(),
                verifier_input_hash.as_mut_ptr(),
                verifier_input_hash.len(),
            )
        };
        assert_eq!(check_bundle_v5, ORCHARD_REAL_PROOF_STATUS_VALID);
        assert_eq!(proof_body_mode, ORCHARD_PROOF_BODY_MODE_SCAFFOLD);
        assert_eq!(request_hash, [0u8; HASH_SIZE]);
        assert_eq!(verifier_input_hash, [0u8; HASH_SIZE]);

        let check_bundle_bad_kind_v4 = unsafe {
            zkc_shielded_check_bundle_v4(
                bundle_v4.as_ptr(),
                bundle_v4.len(),
                2,
                EXPECTED_PUBLIC_INPUT_HASH.as_ptr(),
                EXPECTED_PUBLIC_INPUT_HASH.len(),
                &mut proof_body_mode,
                request_hash.as_mut_ptr(),
                request_hash.len(),
            )
        };
        assert_eq!(
            check_bundle_bad_kind_v4,
            ORCHARD_REAL_PROOF_STATUS_MALFORMED
        );
        assert_eq!(proof_body_mode, 0xff);
        assert_eq!(request_hash, [0u8; HASH_SIZE]);

        let orchard_body_v1 = build_orchard_proof_body_v1(1, &EXPECTED_PUBLIC_INPUT_HASH);
        let ok_orchard_body_v1 = unsafe {
            zkc_shielded_verify_orchard_proof_v1(
                orchard_body_v1.as_ptr(),
                orchard_body_v1.len(),
                1,
                EXPECTED_PUBLIC_INPUT_HASH.as_ptr(),
                EXPECTED_PUBLIC_INPUT_HASH.len(),
            )
        };
        assert_eq!(ok_orchard_body_v1, 1);

        let bad_kind_orchard_body_v1 = unsafe {
            zkc_shielded_verify_orchard_proof_v1(
                orchard_body_v1.as_ptr(),
                orchard_body_v1.len(),
                2,
                EXPECTED_PUBLIC_INPUT_HASH.as_ptr(),
                EXPECTED_PUBLIC_INPUT_HASH.len(),
            )
        };
        assert_eq!(bad_kind_orchard_body_v1, 0);

        let bad_len_orchard_body_v1 = unsafe {
            zkc_shielded_verify_orchard_proof_v1(
                orchard_body_v1.as_ptr(),
                orchard_body_v1.len() - 1,
                1,
                EXPECTED_PUBLIC_INPUT_HASH.as_ptr(),
                EXPECTED_PUBLIC_INPUT_HASH.len(),
            )
        };
        assert_eq!(bad_len_orchard_body_v1, 0);

        let native_bytes = native_proof_bytes(0x42);
        let real_proof_v1 =
            build_orchard_real_proof_v1(1, &EXPECTED_PUBLIC_INPUT_HASH, &native_bytes);
        let unsupported_real_proof_status_v1 = unsafe {
            zkc_shielded_verify_orchard_real_proof_status_v1(
                real_proof_v1.as_ptr(),
                real_proof_v1.len(),
                1,
                EXPECTED_PUBLIC_INPUT_HASH.as_ptr(),
                EXPECTED_PUBLIC_INPUT_HASH.len(),
            )
        };
        assert_eq!(
            unsupported_real_proof_status_v1,
            ORCHARD_REAL_PROOF_STATUS_UNSUPPORTED
        );
        let unsupported_real_proof_v1 = unsafe {
            zkc_shielded_verify_orchard_real_proof_v1(
                real_proof_v1.as_ptr(),
                real_proof_v1.len(),
                1,
                EXPECTED_PUBLIC_INPUT_HASH.as_ptr(),
                EXPECTED_PUBLIC_INPUT_HASH.len(),
            )
        };
        assert_eq!(unsupported_real_proof_v1, 0);

        let malformed_real_proof_status_v1 = unsafe {
            zkc_shielded_verify_orchard_real_proof_status_v1(
                real_proof_v1.as_ptr(),
                real_proof_v1.len(),
                2,
                EXPECTED_PUBLIC_INPUT_HASH.as_ptr(),
                EXPECTED_PUBLIC_INPUT_HASH.len(),
            )
        };
        assert_eq!(
            malformed_real_proof_status_v1,
            ORCHARD_REAL_PROOF_STATUS_MALFORMED
        );
        assert_eq!(
            zkc_shielded_orchard_real_verifier_backend_v1(),
            ORCHARD_REAL_VERIFIER_BACKEND_UNSUPPORTED
        );
        assert_eq!(zkc_shielded_orchard_real_verifier_supports_proofs_v1(), 0);

        request_hash.fill(0);
        let request_hash_ok = unsafe {
            zkc_shielded_orchard_real_proof_request_hash_v1(
                real_proof_v1.as_ptr(),
                real_proof_v1.len(),
                1,
                EXPECTED_PUBLIC_INPUT_HASH.as_ptr(),
                EXPECTED_PUBLIC_INPUT_HASH.len(),
                request_hash.as_mut_ptr(),
                request_hash.len(),
            )
        };
        assert_eq!(request_hash_ok, 1);
        assert_eq!(request_hash, EXPECTED_ORCHARD_REAL_REQUEST_HASH);

        let request_hash_bad_kind = unsafe {
            zkc_shielded_orchard_real_proof_request_hash_v1(
                real_proof_v1.as_ptr(),
                real_proof_v1.len(),
                2,
                EXPECTED_PUBLIC_INPUT_HASH.as_ptr(),
                EXPECTED_PUBLIC_INPUT_HASH.len(),
                request_hash.as_mut_ptr(),
                request_hash.len(),
            )
        };
        assert_eq!(request_hash_bad_kind, 0);

        let request_hash_bad_out_len = unsafe {
            zkc_shielded_orchard_real_proof_request_hash_v1(
                real_proof_v1.as_ptr(),
                real_proof_v1.len(),
                1,
                EXPECTED_PUBLIC_INPUT_HASH.as_ptr(),
                EXPECTED_PUBLIC_INPUT_HASH.len(),
                request_hash.as_mut_ptr(),
                request_hash.len() - 1,
            )
        };
        assert_eq!(request_hash_bad_out_len, 0);

        verifier_input_hash = [0u8; HASH_SIZE];
        let verifier_input_hash_ok = unsafe {
            zkc_shielded_orchard_real_verifier_input_hash_v1(
                real_proof_v1.as_ptr(),
                real_proof_v1.len(),
                1,
                EXPECTED_PUBLIC_INPUT_HASH.as_ptr(),
                EXPECTED_PUBLIC_INPUT_HASH.len(),
                verifier_input_hash.as_mut_ptr(),
                verifier_input_hash.len(),
            )
        };
        assert_eq!(verifier_input_hash_ok, 1);
        assert_eq!(
            verifier_input_hash,
            EXPECTED_ORCHARD_REAL_VERIFIER_INPUT_HASH
        );

        verifier_input_hash.fill(0xaa);
        let verifier_input_hash_bad_kind = unsafe {
            zkc_shielded_orchard_real_verifier_input_hash_v1(
                real_proof_v1.as_ptr(),
                real_proof_v1.len(),
                2,
                EXPECTED_PUBLIC_INPUT_HASH.as_ptr(),
                EXPECTED_PUBLIC_INPUT_HASH.len(),
                verifier_input_hash.as_mut_ptr(),
                verifier_input_hash.len(),
            )
        };
        assert_eq!(verifier_input_hash_bad_kind, 0);
        assert_eq!(verifier_input_hash, [0u8; HASH_SIZE]);

        let verifier_input_hash_bad_out_len = unsafe {
            zkc_shielded_orchard_real_verifier_input_hash_v1(
                real_proof_v1.as_ptr(),
                real_proof_v1.len(),
                1,
                EXPECTED_PUBLIC_INPUT_HASH.as_ptr(),
                EXPECTED_PUBLIC_INPUT_HASH.len(),
                verifier_input_hash.as_mut_ptr(),
                verifier_input_hash.len() - 1,
            )
        };
        assert_eq!(verifier_input_hash_bad_out_len, 0);

        let mut native_proof_hash = [0xaa; HASH_SIZE];
        let native_proof_hash_ok = unsafe {
            zkc_shielded_orchard_real_native_proof_hash_v1(
                real_proof_v1.as_ptr(),
                real_proof_v1.len(),
                1,
                EXPECTED_PUBLIC_INPUT_HASH.as_ptr(),
                EXPECTED_PUBLIC_INPUT_HASH.len(),
                native_proof_hash.as_mut_ptr(),
                native_proof_hash.len(),
            )
        };
        assert_eq!(native_proof_hash_ok, 1);
        assert_eq!(native_proof_hash, EXPECTED_ORCHARD_NATIVE_PROOF_HASH);

        native_proof_hash.fill(0xaa);
        let native_proof_hash_bad_kind = unsafe {
            zkc_shielded_orchard_real_native_proof_hash_v1(
                real_proof_v1.as_ptr(),
                real_proof_v1.len(),
                2,
                EXPECTED_PUBLIC_INPUT_HASH.as_ptr(),
                EXPECTED_PUBLIC_INPUT_HASH.len(),
                native_proof_hash.as_mut_ptr(),
                native_proof_hash.len(),
            )
        };
        assert_eq!(native_proof_hash_bad_kind, 0);
        assert_eq!(native_proof_hash, [0u8; HASH_SIZE]);

        request_hash.fill(0xaa);
        let check_status = unsafe {
            zkc_shielded_orchard_real_proof_check_v1(
                real_proof_v1.as_ptr(),
                real_proof_v1.len(),
                1,
                EXPECTED_PUBLIC_INPUT_HASH.as_ptr(),
                EXPECTED_PUBLIC_INPUT_HASH.len(),
                request_hash.as_mut_ptr(),
                request_hash.len(),
            )
        };
        assert_eq!(check_status, ORCHARD_REAL_PROOF_STATUS_UNSUPPORTED);
        assert_eq!(request_hash, EXPECTED_ORCHARD_REAL_REQUEST_HASH);

        verifier_input_hash.fill(0xaa);
        let check_v2_status = unsafe {
            zkc_shielded_orchard_real_proof_check_v2(
                real_proof_v1.as_ptr(),
                real_proof_v1.len(),
                1,
                EXPECTED_PUBLIC_INPUT_HASH.as_ptr(),
                EXPECTED_PUBLIC_INPUT_HASH.len(),
                request_hash.as_mut_ptr(),
                request_hash.len(),
                verifier_input_hash.as_mut_ptr(),
                verifier_input_hash.len(),
            )
        };
        assert_eq!(check_v2_status, ORCHARD_REAL_PROOF_STATUS_UNSUPPORTED);
        assert_eq!(request_hash, EXPECTED_ORCHARD_REAL_REQUEST_HASH);
        assert_eq!(
            verifier_input_hash,
            EXPECTED_ORCHARD_REAL_VERIFIER_INPUT_HASH
        );

        native_proof_hash.fill(0xaa);
        let check_v3_status = unsafe {
            zkc_shielded_orchard_real_proof_check_v3(
                real_proof_v1.as_ptr(),
                real_proof_v1.len(),
                1,
                EXPECTED_PUBLIC_INPUT_HASH.as_ptr(),
                EXPECTED_PUBLIC_INPUT_HASH.len(),
                request_hash.as_mut_ptr(),
                request_hash.len(),
                verifier_input_hash.as_mut_ptr(),
                verifier_input_hash.len(),
                native_proof_hash.as_mut_ptr(),
                native_proof_hash.len(),
            )
        };
        assert_eq!(check_v3_status, ORCHARD_REAL_PROOF_STATUS_UNSUPPORTED);
        assert_eq!(request_hash, EXPECTED_ORCHARD_REAL_REQUEST_HASH);
        assert_eq!(
            verifier_input_hash,
            EXPECTED_ORCHARD_REAL_VERIFIER_INPUT_HASH
        );
        assert_eq!(native_proof_hash, EXPECTED_ORCHARD_NATIVE_PROOF_HASH);

        let check_bad_kind_status = unsafe {
            zkc_shielded_orchard_real_proof_check_v1(
                real_proof_v1.as_ptr(),
                real_proof_v1.len(),
                2,
                EXPECTED_PUBLIC_INPUT_HASH.as_ptr(),
                EXPECTED_PUBLIC_INPUT_HASH.len(),
                request_hash.as_mut_ptr(),
                request_hash.len(),
            )
        };
        assert_eq!(check_bad_kind_status, ORCHARD_REAL_PROOF_STATUS_MALFORMED);
        assert_eq!(request_hash, [0u8; HASH_SIZE]);

        verifier_input_hash.fill(0xaa);
        let check_v2_bad_kind_status = unsafe {
            zkc_shielded_orchard_real_proof_check_v2(
                real_proof_v1.as_ptr(),
                real_proof_v1.len(),
                2,
                EXPECTED_PUBLIC_INPUT_HASH.as_ptr(),
                EXPECTED_PUBLIC_INPUT_HASH.len(),
                request_hash.as_mut_ptr(),
                request_hash.len(),
                verifier_input_hash.as_mut_ptr(),
                verifier_input_hash.len(),
            )
        };
        assert_eq!(
            check_v2_bad_kind_status,
            ORCHARD_REAL_PROOF_STATUS_MALFORMED
        );
        assert_eq!(request_hash, [0u8; HASH_SIZE]);
        assert_eq!(verifier_input_hash, [0u8; HASH_SIZE]);

        let check_bad_out_len_status = unsafe {
            zkc_shielded_orchard_real_proof_check_v1(
                real_proof_v1.as_ptr(),
                real_proof_v1.len(),
                1,
                EXPECTED_PUBLIC_INPUT_HASH.as_ptr(),
                EXPECTED_PUBLIC_INPUT_HASH.len(),
                request_hash.as_mut_ptr(),
                request_hash.len() - 1,
            )
        };
        assert_eq!(
            check_bad_out_len_status,
            ORCHARD_REAL_PROOF_STATUS_MALFORMED
        );

        let real_body_v1 = build_orchard_real_proof_body_with_context_v1(
            1,
            &EXPECTED_PUBLIC_INPUT_HASH,
            &native_bytes,
        );
        let real_payload_v1 =
            build_orchard_proof_payload_with_body_v1(1, &EXPECTED_PUBLIC_INPUT_HASH, &real_body_v1);
        let real_bundle_v4 =
            build_proof_bundle_with_payload_v4(1, &EXPECTED_PUBLIC_INPUT_HASH, &real_payload_v1);
        proof_body_mode = 0xff;
        request_hash.fill(0xaa);
        let check_real_bundle_v4 = unsafe {
            zkc_shielded_check_bundle_v4(
                real_bundle_v4.as_ptr(),
                real_bundle_v4.len(),
                1,
                EXPECTED_PUBLIC_INPUT_HASH.as_ptr(),
                EXPECTED_PUBLIC_INPUT_HASH.len(),
                &mut proof_body_mode,
                request_hash.as_mut_ptr(),
                request_hash.len(),
            )
        };
        assert_eq!(check_real_bundle_v4, ORCHARD_REAL_PROOF_STATUS_UNSUPPORTED);
        assert_eq!(proof_body_mode, ORCHARD_PROOF_BODY_MODE_REAL);
        assert_eq!(request_hash, EXPECTED_ORCHARD_REAL_REQUEST_HASH);

        verifier_input_hash.fill(0xaa);
        let check_real_bundle_v5 = unsafe {
            zkc_shielded_check_bundle_v5(
                real_bundle_v4.as_ptr(),
                real_bundle_v4.len(),
                1,
                EXPECTED_PUBLIC_INPUT_HASH.as_ptr(),
                EXPECTED_PUBLIC_INPUT_HASH.len(),
                &mut proof_body_mode,
                request_hash.as_mut_ptr(),
                request_hash.len(),
                verifier_input_hash.as_mut_ptr(),
                verifier_input_hash.len(),
            )
        };
        assert_eq!(check_real_bundle_v5, ORCHARD_REAL_PROOF_STATUS_UNSUPPORTED);
        assert_eq!(proof_body_mode, ORCHARD_PROOF_BODY_MODE_REAL);
        assert_eq!(request_hash, EXPECTED_ORCHARD_REAL_REQUEST_HASH);
        assert_eq!(
            verifier_input_hash,
            EXPECTED_ORCHARD_REAL_VERIFIER_INPUT_HASH
        );

        native_proof_hash.fill(0xaa);
        let check_real_bundle_v6 = unsafe {
            zkc_shielded_check_bundle_v6(
                real_bundle_v4.as_ptr(),
                real_bundle_v4.len(),
                1,
                EXPECTED_PUBLIC_INPUT_HASH.as_ptr(),
                EXPECTED_PUBLIC_INPUT_HASH.len(),
                &mut proof_body_mode,
                request_hash.as_mut_ptr(),
                request_hash.len(),
                verifier_input_hash.as_mut_ptr(),
                verifier_input_hash.len(),
                native_proof_hash.as_mut_ptr(),
                native_proof_hash.len(),
            )
        };
        assert_eq!(check_real_bundle_v6, ORCHARD_REAL_PROOF_STATUS_UNSUPPORTED);
        assert_eq!(proof_body_mode, ORCHARD_PROOF_BODY_MODE_REAL);
        assert_eq!(request_hash, EXPECTED_ORCHARD_REAL_REQUEST_HASH);
        assert_eq!(
            verifier_input_hash,
            EXPECTED_ORCHARD_REAL_VERIFIER_INPUT_HASH
        );
        assert_eq!(native_proof_hash, EXPECTED_ORCHARD_NATIVE_PROOF_HASH);

        let unsupported_real_body_v1 = unsafe {
            zkc_shielded_verify_orchard_proof_v1(
                real_body_v1.as_ptr(),
                real_body_v1.len(),
                1,
                EXPECTED_PUBLIC_INPUT_HASH.as_ptr(),
                EXPECTED_PUBLIC_INPUT_HASH.len(),
            )
        };
        assert_eq!(unsupported_real_body_v1, 0);
    }
}
