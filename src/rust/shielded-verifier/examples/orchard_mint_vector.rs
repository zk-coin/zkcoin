// Copyright (c) 2026 The zkCoin developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#[cfg(all(feature = "orchard-verifier", not(feature = "verifier-fixture")))]
use orchard::builder::{Builder, BundleType};
#[cfg(all(feature = "orchard-verifier", not(feature = "verifier-fixture")))]
use orchard::bundle::Flags;
#[cfg(all(feature = "orchard-verifier", not(feature = "verifier-fixture")))]
use orchard::keys::{FullViewingKey, Scope, SpendingKey};
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

    let mut builder = Builder::new(
        BundleType::Transactional {
            flags: Flags::SPENDS_DISABLED,
            bundle_required: true,
        },
        orchard::Anchor::empty_tree(),
    );
    builder
        .add_output(
            None,
            recipient,
            NoteValue::from_raw(shielded_value),
            [0x24; 512],
        )
        .expect("output can be added to mint bundle");
    let (unauthorized, _) = builder
        .build::<i64>(&mut rng)
        .expect("mint bundle builds")
        .expect("mint bundle is required");
    let sighash: [u8; 32] = unauthorized.commitment().into();
    let proving_key = orchard::circuit::ProvingKey::build();
    let proven = unauthorized
        .create_proof(&proving_key, &mut rng)
        .expect("valid mint proof can be generated");
    let bundle = proven
        .apply_signatures(&mut rng, sighash, &[])
        .expect("dummy spend signatures finalize");

    bundle
        .verify_proof(&orchard::circuit::VerifyingKey::build())
        .expect("upstream Orchard verifies generated mint proof");

    println!("shielded_value={shielded_value}");
    println!("marker_action_index=0");
    println!("enable_spend=0");
    println!("enable_output=1");
    println!("action_count={}", bundle.actions().len());
    println!("anchor={}", hex(&bundle.anchor().to_bytes()));
    for (index, action) in bundle.actions().iter().enumerate() {
        println!("action{index}.cv_net={}", hex(&action.cv_net().to_bytes()));
        println!(
            "action{index}.nf_old={}",
            hex(&action.nullifier().to_bytes())
        );
        let rk: [u8; 32] = action.rk().into();
        println!("action{index}.rk={}", hex(&rk));
        println!("action{index}.cmx={}", hex(&action.cmx().to_bytes()));
    }
    println!("proof={}", hex(bundle.authorization().proof().as_ref()));
}

#[cfg(not(all(feature = "orchard-verifier", not(feature = "verifier-fixture"))))]
fn main() {
    eprintln!("run with --features orchard-verifier to generate the Orchard mint vector");
}
