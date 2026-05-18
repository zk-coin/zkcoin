// Copyright (c) 2026 The zkCoin developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#[cfg(all(feature = "orchard-verifier", not(feature = "verifier-fixture")))]
use incrementalmerkletree::{frontier::Frontier, Hashable};
#[cfg(all(feature = "orchard-verifier", not(feature = "verifier-fixture")))]
use orchard::builder::{Builder, BundleType};
#[cfg(all(feature = "orchard-verifier", not(feature = "verifier-fixture")))]
use orchard::bundle::Flags;
#[cfg(all(feature = "orchard-verifier", not(feature = "verifier-fixture")))]
use orchard::keys::{FullViewingKey, Scope, SpendAuthorizingKey, SpendingKey};
#[cfg(all(feature = "orchard-verifier", not(feature = "verifier-fixture")))]
use orchard::note::ExtractedNoteCommitment;
#[cfg(all(feature = "orchard-verifier", not(feature = "verifier-fixture")))]
use orchard::tree::MerkleHashOrchard;
#[cfg(all(feature = "orchard-verifier", not(feature = "verifier-fixture")))]
use orchard::value::NoteValue;
#[cfg(all(feature = "orchard-verifier", not(feature = "verifier-fixture")))]
use rand::{rngs::StdRng, SeedableRng};

#[cfg(all(feature = "orchard-verifier", not(feature = "verifier-fixture")))]
fn hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut encoded = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        encoded.push(HEX[(byte >> 4) as usize] as char);
        encoded.push(HEX[(byte & 0x0f) as usize] as char);
    }
    encoded
}

#[cfg(all(feature = "orchard-verifier", not(feature = "verifier-fixture")))]
fn main() {
    let mut rng = StdRng::from_seed([0x42; 32]);
    let sk = SpendingKey::from_bytes([0x07; 32]).expect("deterministic spending key");
    let fvk = FullViewingKey::from(&sk);
    let recipient = fvk.address_at(0u32, Scope::External);
    let shielded_value = 100_000_000u64;

    let mut mint_builder = Builder::new(
        BundleType::Transactional {
            flags: Flags::SPENDS_DISABLED,
            bundle_required: true,
        },
        orchard::Anchor::empty_tree(),
    );
    mint_builder
        .add_output(
            None,
            recipient,
            NoteValue::from_raw(shielded_value),
            [0x24; 512],
        )
        .expect("output can be added to mint bundle");
    let (mint_unauthorized, mint_meta) = mint_builder
        .build::<i64>(&mut rng)
        .expect("mint bundle builds")
        .expect("mint bundle is required");
    let minted_note = mint_unauthorized
        .decrypt_output_with_key(
            mint_meta
                .output_action_index(0)
                .expect("mint output action is present"),
            &fvk.to_ivk(Scope::External),
        )
        .map(|(note, _, _)| note)
        .expect("deterministic mint output decrypts");
    let mint_sighash: [u8; 32] = mint_unauthorized.commitment().into();
    let mint_proving_key = orchard::circuit::ProvingKey::build();
    let mint_bundle = mint_unauthorized
        .create_proof(&mint_proving_key, &mut rng)
        .expect("valid mint proof can be generated")
        .apply_signatures(&mut rng, mint_sighash, &[])
        .expect("dummy mint spend signatures finalize");
    let source_action = &mint_bundle.actions()[mint_meta
        .output_action_index(0)
        .expect("mint output action is present")];
    let source_commitment = source_action.cmx().to_bytes();

    let cmx: ExtractedNoteCommitment = minted_note.commitment().into();
    let leaf = MerkleHashOrchard::from_cmx(&cmx);
    let mut frontier = Frontier::<MerkleHashOrchard, 32>::empty();
    assert!(frontier.append(leaf));
    let root = frontier.root();
    let merkle_path = frontier
        .witness(|addr| Some(MerkleHashOrchard::empty_root(addr.level())))
        .expect("empty complement nodes complete the one-leaf witness")
        .expect("one-leaf tree has a witness");
    assert_eq!(root, merkle_path.root(leaf));

    let mut spend_builder = Builder::new(
        BundleType::Transactional {
            flags: Flags::OUTPUTS_DISABLED,
            bundle_required: true,
        },
        root.into(),
    );
    spend_builder
        .add_spend(fvk, minted_note, merkle_path.into())
        .expect("spend can be added to spend-only bundle");
    let (spend_unauthorized, spend_meta) = spend_builder
        .build::<i64>(&mut rng)
        .expect("spend bundle builds")
        .expect("spend bundle is required");
    let sighash: [u8; 32] = spend_unauthorized.commitment().into();
    let proving_key = orchard::circuit::ProvingKey::build();
    let spend_bundle = spend_unauthorized
        .create_proof(&proving_key, &mut rng)
        .expect("valid spend proof can be generated")
        .apply_signatures(&mut rng, sighash, &[SpendAuthorizingKey::from(&sk)])
        .expect("spend signatures finalize");

    spend_bundle
        .verify_proof(&orchard::circuit::VerifyingKey::build())
        .expect("upstream Orchard verifies generated spend proof");

    println!("shielded_value={shielded_value}");
    println!("source_commitment={}", hex(&source_commitment));
    println!(
        "marker_action_index={}",
        spend_meta
            .spend_action_index(0)
            .expect("spend action is present")
    );
    println!("enable_spend=1");
    println!("enable_output=0");
    println!("action_count={}", spend_bundle.actions().len());
    println!("anchor={}", hex(&spend_bundle.anchor().to_bytes()));
    for (index, action) in spend_bundle.actions().iter().enumerate() {
        println!("action{index}.cv_net={}", hex(&action.cv_net().to_bytes()));
        println!(
            "action{index}.nf_old={}",
            hex(&action.nullifier().to_bytes())
        );
        let rk: [u8; 32] = action.rk().into();
        println!("action{index}.rk={}", hex(&rk));
        println!("action{index}.cmx={}", hex(&action.cmx().to_bytes()));
    }
    println!(
        "proof={}",
        hex(spend_bundle.authorization().proof().as_ref())
    );
}

#[cfg(not(all(feature = "orchard-verifier", not(feature = "verifier-fixture"))))]
fn main() {
    eprintln!("run with --features orchard-verifier to generate the Orchard spend vector");
}
