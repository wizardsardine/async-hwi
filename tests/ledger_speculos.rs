//! Run with `tests/speculos/run.sh [nanox|nanosp]`. Requires
//! `--test-threads=1` (one shared Speculos child, one APDU socket).
//! Assertions assume Speculos's default BIP39 seed.

#![cfg(feature = "ledger")]

mod common;

use async_hwi::{ledger::LedgerSimulator, AddressScript, DeviceKind, HWI};
use bitcoin::{bip32::DerivationPath, psbt::Psbt};
use common::{build_wpkh_test_psbt, SPECULOS_BIP84_TESTNET_XPUB, SPECULOS_DEFAULT_FINGERPRINT};
use regex::Regex;
use speculos::{Button, SpawnOptions, Speculos};
use std::{str::FromStr, time::Duration};

/// /reset does not fully clear the embedded app's wallet-policy text
/// buffer or prior register-wallet state, so we boot per-test.
fn fresh_speculos() -> Speculos {
    let model = std::env::var("SPECULOS_MODEL")
        .expect("SPECULOS_MODEL")
        .parse::<speculos::Model>()
        .expect("parse model");
    Speculos::launch_model(model).expect("Speculos::launch_model")
}

async fn connect_to(sim: &Speculos) -> LedgerSimulator {
    LedgerSimulator::try_connect_on(sim.apdu_addr())
        .await
        .expect("connect to Speculos APDU port")
}

async fn get_xpub_for_path(device: &LedgerSimulator, path: &str) -> String {
    let derivation = DerivationPath::from_str(path).expect("valid derivation path");
    let fp = device
        .get_master_fingerprint()
        .await
        .expect("get_master_fingerprint");
    let xpub = device
        .get_extended_pubkey(&derivation)
        .await
        .expect("get_extended_pubkey");
    let path_in_origin = derivation.to_string();
    let path_in_origin = path_in_origin.trim_start_matches("m/");
    format!("[{fp:x}/{path_in_origin}]{xpub}")
}

fn run_steps(sim: &Speculos, steps: &[(&str, Button)]) {
    for &(text, button) in steps {
        screen_contains(sim, text);
        sim.press(button).unwrap();
    }
}

fn screen_contains(sim: &Speculos, expected: &str) {
    let re = Regex::new(&format!("^{}$", regex::escape(expected))).unwrap();
    if sim.wait_for(&re, Duration::from_secs(10)).is_err() {
        let last_screens: Vec<_> = sim
            .events()
            .unwrap()
            .into_iter()
            .rev()
            .take(12)
            .map(|e| e.text)
            .collect();
        let msg = format!(
            "expected screen {expected:?}; recent screens (newest first): {last_screens:?}"
        );
        panic!("{}", msg);
    }
}

#[tokio::test]
#[ignore = "requires SPECULOS_ELF"]
async fn speculos_device_kind() {
    let sim = fresh_speculos();
    let device = connect_to(&sim).await;
    assert_eq!(device.device_kind(), DeviceKind::LedgerSimulator);
}

#[tokio::test]
#[ignore = "requires SPECULOS_ELF"]
async fn speculos_get_version() {
    let sim = fresh_speculos();
    let device = connect_to(&sim).await;
    let version = device.get_version().await.expect("get_version");
    // Pinned to app-bitcoin-new 2.4.6 in CI.
    assert_eq!(version.major, 2, "got version {version}");
    assert_eq!(version.minor, 4, "got version {version}");
}

#[tokio::test]
#[ignore = "requires SPECULOS_ELF"]
async fn speculos_master_fingerprint() {
    let sim = fresh_speculos();
    let device = connect_to(&sim).await;
    let fp = device
        .get_master_fingerprint()
        .await
        .expect("get_master_fingerprint");
    assert_eq!(format!("{fp:x}"), SPECULOS_DEFAULT_FINGERPRINT);
}

/// Boot Speculos with the canonical "abandon abandon ... about" BIP39
/// mnemonic and verify `get_master_fingerprint` reports the well-known
/// fingerprint for that seed (`73c5da0a`), which is distinct from the
/// default speculos seed's `f5acc2fd`. Exercises [`Speculos::launch_with`]
/// + [`Seed::Mnemonic`].
#[tokio::test]
#[ignore = "requires SPECULOS_ELF"]
async fn speculos_master_fingerprint_with_custom_seed() {
    let elf = std::env::var("SPECULOS_ELF").expect("SPECULOS_ELF");
    let model = std::env::var("SPECULOS_MODEL")
        .expect("SPECULOS_MODEL")
        .parse::<speculos::Model>()
        .expect("parse model");
    let sim = Speculos::launch_with(
        std::path::Path::new(&elf),
        model,
        SpawnOptions {
            seed: Some(
                "abandon abandon abandon abandon abandon abandon abandon abandon abandon \
                 abandon abandon about"
                    .into(),
            ),
            apdu: None,
            api: None,
        },
    )
    .expect("Speculos::launch_with");
    let device = connect_to(&sim).await;
    let fp = device
        .get_master_fingerprint()
        .await
        .expect("get_master_fingerprint");
    assert_eq!(format!("{fp:x}"), "73c5da0a");
    assert_ne!(format!("{fp:x}"), SPECULOS_DEFAULT_FINGERPRINT);
}

#[tokio::test]
#[ignore = "requires SPECULOS_ELF"]
async fn speculos_get_extended_pubkey_bip84_testnet() {
    let sim = fresh_speculos();
    let device = connect_to(&sim).await;
    let path = DerivationPath::from_str("m/84h/1h/0h").unwrap();
    let xpub = device
        .get_extended_pubkey(&path)
        .await
        .expect("get_extended_pubkey");
    assert_eq!(xpub.to_string(), SPECULOS_BIP84_TESTNET_XPUB);
}

#[tokio::test]
#[ignore = "requires SPECULOS_ELF"]
async fn speculos_get_extended_pubkey_bip86_testnet() {
    let sim = fresh_speculos();
    let device = connect_to(&sim).await;
    let path = DerivationPath::from_str("m/86h/1h/0h").unwrap();
    let xpub = device
        .get_extended_pubkey(&path)
        .await
        .expect("get_extended_pubkey");
    assert!(xpub.to_string().starts_with("tpub"));
}

#[tokio::test]
#[ignore = "requires SPECULOS_ELF"]
async fn speculos_is_wallet_registered_without_options() {
    let sim = fresh_speculos();
    let device = connect_to(&sim).await;
    let device_key = get_xpub_for_path(&device, "m/84h/1h/0h").await;
    let policy = format!("wpkh({device_key}/**)");
    let registered = device
        .is_wallet_registered("any", &policy)
        .await
        .expect("is_wallet_registered");
    assert!(!registered);
}

// `flavor = "multi_thread"` lets the APDU task run on a separate worker
// while the test thread blocks driving the UI over HTTP.

/// Register `policy` to ack and return the hmac. Panics on any
/// non-success outcome. Used by display/sign helpers that need a
/// registered wallet before they can exercise their own flow.
async fn register_for_hmac(
    sim: &Speculos,
    device: LedgerSimulator,
    name: &str,
    policy: &str,
    register_steps: &[(&str, Button)],
) -> [u8; 32] {
    let name = name.to_string();
    let policy = policy.to_string();
    let task = tokio::spawn(async move { device.register_wallet(&name, &policy).await });
    run_steps(sim, register_steps);
    match task.await.unwrap() {
        Ok(Some(hmac)) => {
            assert_eq!(hmac.len(), 32, "expected 32-byte hmac from register_wallet");
            hmac
        }
        other => {
            let msg = format!("register_for_hmac unexpected outcome: {other:?}");
            panic!("{}", msg);
        }
    }
}

async fn run_register_wsh_sortedmulti_1of2(ack: bool) {
    let sim = fresh_speculos();
    let device = connect_to(&sim).await;

    let device_key = get_xpub_for_path(&device, "m/48h/1h/0h/2h").await;
    let cosigner_a = common::cosigner_origin("12345678", "m/48h/1h/0h/2h");
    let policy = format!("wsh(sortedmulti(1,{device_key}/**,{cosigner_a}/**))");

    let task = tokio::spawn(async move { device.register_wallet("test-wallet", &policy).await });

    let mut steps: Vec<(&str, Button)> = vec![
        ("Review account", Button::Right),
        ("Account name", Button::Right),
        ("Wallet policy", Button::Right),
        ("Review co-signer", Button::Right),
        ("Our key@0 (1/3)", Button::Right),
        ("Our key@0 (2/3)", Button::Right),
        ("Our key@0 (3/3)", Button::Right),
        ("Their key@1 (1/3)", Button::Right),
        ("Their key@1 (2/3)", Button::Right),
        ("Their key@1 (3/3)", Button::Right),
    ];
    if ack {
        steps.push(("Register account", Button::Both));
    } else {
        steps.push(("Register account", Button::Right));
        steps.push(("Reject operation", Button::Both));
    }
    run_steps(&sim, &steps);

    let result = task.await.unwrap();
    match (result, ack) {
        (Ok(Some(hmac)), true) => {
            assert_eq!(hmac.len(), 32, "expected 32-byte hmac from register_wallet");
        }
        (Ok(None), true) => panic!("register_wallet ack returned no hmac"),
        (Err(async_hwi::Error::UserRefused), false) => {}
        (other, ack) => {
            let msg = format!("register_wallet outcome mismatch (ack={ack}): {other:?}");
            panic!("{}", msg);
        }
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires SPECULOS_ELF"]
async fn speculos_register_wsh_sortedmulti_1of2() {
    run_register_wsh_sortedmulti_1of2(true).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires SPECULOS_ELF"]
async fn speculos_register_wsh_sortedmulti_1of2_reject() {
    run_register_wsh_sortedmulti_1of2(false).await;
}

async fn run_register_wsh_sortedmulti_2of3(ack: bool) {
    let sim = fresh_speculos();
    let device = connect_to(&sim).await;

    let device_key = get_xpub_for_path(&device, "m/48h/1h/0h/2h").await;
    let cosigner_a = common::cosigner_origin("12345678", "m/48h/1h/0h/2h");
    let cosigner_b = common::cosigner_origin("abcdef00", "m/48h/1h/1h/2h");
    let policy = format!("wsh(sortedmulti(2,{device_key}/**,{cosigner_a}/**,{cosigner_b}/**))");

    let task = tokio::spawn(async move { device.register_wallet("multi-2of3", &policy).await });

    let mut steps: Vec<(&str, Button)> = vec![
        ("Review account", Button::Right),
        ("Account name", Button::Right),
        ("Wallet policy", Button::Right),
        ("Review co-signer", Button::Right),
        ("Our key@0 (1/3)", Button::Right),
        ("Our key@0 (2/3)", Button::Right),
        ("Our key@0 (3/3)", Button::Right),
        ("Their key@1 (1/3)", Button::Right),
        ("Their key@1 (2/3)", Button::Right),
        ("Their key@1 (3/3)", Button::Right),
        ("Their key@2 (1/3)", Button::Right),
        ("Their key@2 (2/3)", Button::Right),
        ("Their key@2 (3/3)", Button::Right),
    ];
    if ack {
        steps.push(("Register account", Button::Both));
    } else {
        steps.push(("Register account", Button::Right));
        steps.push(("Reject operation", Button::Both));
    }
    run_steps(&sim, &steps);

    let result = task.await.unwrap();
    match (result, ack) {
        (Ok(Some(hmac)), true) => {
            assert_eq!(hmac.len(), 32, "expected 32-byte hmac from register_wallet");
        }
        (Ok(None), true) => panic!("register_wallet ack returned no hmac"),
        (Err(async_hwi::Error::UserRefused), false) => {}
        (other, ack) => {
            let msg = format!("register_wallet outcome mismatch (ack={ack}): {other:?}");
            panic!("{}", msg);
        }
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires SPECULOS_ELF"]
async fn speculos_register_wsh_sortedmulti_2of3() {
    run_register_wsh_sortedmulti_2of3(true).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires SPECULOS_ELF"]
async fn speculos_register_wsh_sortedmulti_2of3_reject() {
    run_register_wsh_sortedmulti_2of3(false).await;
}

const REGISTER_STEPS_1OF2_ACK: &[(&str, Button)] = &[
    ("Review account", Button::Right),
    ("Account name", Button::Right),
    ("Wallet policy", Button::Right),
    ("Review co-signer", Button::Right),
    ("Our key@0 (1/3)", Button::Right),
    ("Our key@0 (2/3)", Button::Right),
    ("Our key@0 (3/3)", Button::Right),
    ("Their key@1 (1/3)", Button::Right),
    ("Their key@1 (2/3)", Button::Right),
    ("Their key@1 (3/3)", Button::Right),
    ("Register account", Button::Both),
];

const REGISTER_STEPS_2OF3_ACK: &[(&str, Button)] = &[
    ("Review account", Button::Right),
    ("Account name", Button::Right),
    ("Wallet policy", Button::Right),
    ("Review co-signer", Button::Right),
    ("Our key@0 (1/3)", Button::Right),
    ("Our key@0 (2/3)", Button::Right),
    ("Our key@0 (3/3)", Button::Right),
    ("Their key@1 (1/3)", Button::Right),
    ("Their key@1 (2/3)", Button::Right),
    ("Their key@1 (3/3)", Button::Right),
    ("Their key@2 (1/3)", Button::Right),
    ("Their key@2 (2/3)", Button::Right),
    ("Their key@2 (3/3)", Button::Right),
    ("Register account", Button::Both),
];

async fn run_display_wsh_sortedmulti_1of2() {
    let sim = fresh_speculos();
    let device = connect_to(&sim).await;
    let device_key = get_xpub_for_path(&device, "m/48h/1h/0h/2h").await;
    let cosigner_a = common::cosigner_origin("12345678", "m/48h/1h/0h/2h");
    let policy = format!("wsh(sortedmulti(1,{device_key}/**,{cosigner_a}/**))");

    let hmac =
        register_for_hmac(&sim, device, "multi-1of2", &policy, REGISTER_STEPS_1OF2_ACK).await;

    let device = LedgerSimulator::try_connect_on(sim.apdu_addr())
        .await
        .expect("reconnect")
        .with_wallet("multi-1of2", &policy, Some(hmac))
        .expect("with_wallet");
    let task = tokio::spawn(async move {
        device
            .display_address(&AddressScript::Miniscript {
                index: 0,
                change: false,
            })
            .await
    });

    run_steps(
        &sim,
        &[
            ("Verify bitcoin", Button::Right),
            ("Address (1/2)", Button::Right),
            ("Address (2/2)", Button::Right),
            ("Account name", Button::Right),
            ("Confirm", Button::Both),
        ],
    );

    task.await.unwrap().expect("display_address");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires SPECULOS_ELF"]
async fn speculos_display_wsh_sortedmulti_1of2() {
    run_display_wsh_sortedmulti_1of2().await;
}

async fn run_display_wsh_sortedmulti_2of3() {
    let sim = fresh_speculos();
    let device = connect_to(&sim).await;
    let device_key = get_xpub_for_path(&device, "m/48h/1h/0h/2h").await;
    let cosigner_a = common::cosigner_origin("12345678", "m/48h/1h/0h/2h");
    let cosigner_b = common::cosigner_origin("abcdef00", "m/48h/1h/1h/2h");
    let policy = format!("wsh(sortedmulti(2,{device_key}/**,{cosigner_a}/**,{cosigner_b}/**))");

    let hmac =
        register_for_hmac(&sim, device, "multi-2of3", &policy, REGISTER_STEPS_2OF3_ACK).await;

    let device = LedgerSimulator::try_connect_on(sim.apdu_addr())
        .await
        .expect("reconnect")
        .with_wallet("multi-2of3", &policy, Some(hmac))
        .expect("with_wallet");
    let task = tokio::spawn(async move {
        device
            .display_address(&AddressScript::Miniscript {
                index: 0,
                change: false,
            })
            .await
    });

    run_steps(
        &sim,
        &[
            ("Verify bitcoin", Button::Right),
            ("Address (1/2)", Button::Right),
            ("Address (2/2)", Button::Right),
            ("Account name", Button::Right),
            ("Confirm", Button::Both),
        ],
    );

    task.await.unwrap().expect("display_address");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires SPECULOS_ELF"]
async fn speculos_display_wsh_sortedmulti_2of3() {
    run_display_wsh_sortedmulti_2of3().await;
}

/// Click sequence for a transaction-review flow on Nano X / Nano S Plus.
/// `from_screen=true` adds the multisig "From <wallet-name>" page that
/// the device shows for non-default wallet policies. `to_pages` is the
/// pagination count of the "To" address screen (1 for short bech32
/// wpkh addresses, 2 for longer wsh / taproot addresses).
fn sign_steps(ack: bool, from_screen: bool, to_pages: u32) -> Vec<(String, Button)> {
    let mut steps: Vec<(String, Button)> = vec![("Review transaction".into(), Button::Right)];
    if from_screen {
        steps.push(("From".into(), Button::Right));
    }
    steps.push(("Amount".into(), Button::Right));
    if to_pages == 1 {
        steps.push(("To".into(), Button::Right));
    } else {
        for i in 1..=to_pages {
            steps.push((format!("To ({i}/{to_pages})"), Button::Right));
        }
    }
    steps.push(("Fees".into(), Button::Right));
    if ack {
        steps.push(("Sign transaction".into(), Button::Both));
    } else {
        steps.push(("Sign transaction".into(), Button::Right));
        steps.push(("Reject transaction".into(), Button::Both));
    }
    steps
}

fn sign_step_refs(steps: &[(String, Button)]) -> Vec<(&str, Button)> {
    steps.iter().map(|(s, b)| (s.as_str(), *b)).collect()
}

async fn run_sign_wsh_sortedmulti_1of2(ack: bool) {
    let sim = fresh_speculos();
    let device = connect_to(&sim).await;
    let device_key = get_xpub_for_path(&device, "m/48h/1h/0h/2h").await;
    let cosigner_a = common::cosigner_origin("12345678", "m/48h/1h/0h/2h");
    let policy = format!("wsh(sortedmulti(1,{device_key}/**,{cosigner_a}/**))");

    let hmac =
        register_for_hmac(&sim, device, "multi-1of2", &policy, REGISTER_STEPS_1OF2_ACK).await;

    let device_fp = bitcoin::bip32::Fingerprint::from_hex(SPECULOS_DEFAULT_FINGERPRINT).unwrap();
    let key_origins = vec![
        common::KeyOrigin {
            fingerprint: device_fp,
            account_path: DerivationPath::from_str("m/48h/1h/0h/2h").unwrap(),
        },
        common::KeyOrigin::new("12345678", "m/48h/1h/0h/2h"),
    ];
    let mut psbt = common::build_wsh_test_psbt(&policy, &key_origins);

    let device = LedgerSimulator::try_connect_on(sim.apdu_addr())
        .await
        .expect("reconnect")
        .with_wallet("multi-1of2", &policy, Some(hmac))
        .expect("with_wallet");
    let task = tokio::spawn(async move {
        let res = device.sign_tx(&mut psbt).await;
        (res, psbt)
    });

    let steps = sign_steps(ack, true, 2);
    run_steps(&sim, &sign_step_refs(&steps));

    let (api_result, psbt) = task.await.unwrap();
    match (api_result, ack) {
        (Ok(()), true) => {
            assert!(
                !psbt.inputs[0].partial_sigs.is_empty(),
                "expected partial_sigs after ack"
            );
        }
        (Err(async_hwi::Error::UserRefused), false) => {
            assert!(
                psbt.inputs[0].partial_sigs.is_empty(),
                "expected no partial_sigs after nack"
            );
        }
        (other, ack) => {
            let msg = format!("sign_tx outcome mismatch (ack={ack}): {other:?}");
            panic!("{}", msg);
        }
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires SPECULOS_ELF"]
async fn speculos_sign_wsh_sortedmulti_1of2() {
    run_sign_wsh_sortedmulti_1of2(true).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires SPECULOS_ELF"]
async fn speculos_sign_wsh_sortedmulti_1of2_reject() {
    run_sign_wsh_sortedmulti_1of2(false).await;
}

async fn run_sign_wsh_sortedmulti_2of3(ack: bool) {
    let sim = fresh_speculos();
    let device = connect_to(&sim).await;
    let device_key = get_xpub_for_path(&device, "m/48h/1h/0h/2h").await;
    let cosigner_a = common::cosigner_origin("12345678", "m/48h/1h/0h/2h");
    let cosigner_b = common::cosigner_origin("abcdef00", "m/48h/1h/1h/2h");
    let policy = format!("wsh(sortedmulti(2,{device_key}/**,{cosigner_a}/**,{cosigner_b}/**))");

    let hmac =
        register_for_hmac(&sim, device, "multi-2of3", &policy, REGISTER_STEPS_2OF3_ACK).await;

    let device_fp = bitcoin::bip32::Fingerprint::from_hex(SPECULOS_DEFAULT_FINGERPRINT).unwrap();
    let key_origins = vec![
        common::KeyOrigin {
            fingerprint: device_fp,
            account_path: DerivationPath::from_str("m/48h/1h/0h/2h").unwrap(),
        },
        common::KeyOrigin::new("12345678", "m/48h/1h/0h/2h"),
        common::KeyOrigin::new("abcdef00", "m/48h/1h/1h/2h"),
    ];
    let mut psbt = common::build_wsh_test_psbt(&policy, &key_origins);

    let device = LedgerSimulator::try_connect_on(sim.apdu_addr())
        .await
        .expect("reconnect")
        .with_wallet("multi-2of3", &policy, Some(hmac))
        .expect("with_wallet");
    let task = tokio::spawn(async move {
        let res = device.sign_tx(&mut psbt).await;
        (res, psbt)
    });

    let steps = sign_steps(ack, true, 2);
    run_steps(&sim, &sign_step_refs(&steps));

    let (api_result, psbt) = task.await.unwrap();
    match (api_result, ack) {
        (Ok(()), true) => {
            assert!(
                !psbt.inputs[0].partial_sigs.is_empty(),
                "expected partial_sigs after ack"
            );
        }
        (Err(async_hwi::Error::UserRefused), false) => {
            assert!(
                psbt.inputs[0].partial_sigs.is_empty(),
                "expected no partial_sigs after nack"
            );
        }
        (other, ack) => {
            let msg = format!("sign_tx outcome mismatch (ack={ack}): {other:?}");
            panic!("{}", msg);
        }
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires SPECULOS_ELF"]
async fn speculos_sign_wsh_sortedmulti_2of3() {
    run_sign_wsh_sortedmulti_2of3(true).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires SPECULOS_ELF"]
async fn speculos_sign_wsh_sortedmulti_2of3_reject() {
    run_sign_wsh_sortedmulti_2of3(false).await;
}

// `wsh(or_d(pk(K0), and_v(v:pkh(K1), older(10))))` inheritance miniscript.
// Two helpers swap which key is on the device so we can exercise both
// branches (primary path = K0 alone; recovery path = K1 + sequence>=10).

fn inheritance_policy(k0: &str, k1: &str) -> String {
    format!("wsh(or_d(pk({k0}/**),and_v(v:pkh({k1}/**),older(10))))")
}

const REGISTER_STEPS_INHERITANCE_ACK: &[(&str, Button)] = &[
    ("Review account", Button::Right),
    ("Account name", Button::Right),
    ("Wallet policy (1/2)", Button::Right),
    ("Wallet policy (2/2)", Button::Right),
    ("Review co-signer", Button::Right),
    ("Our key@0 (1/3)", Button::Right),
    ("Our key@0 (2/3)", Button::Right),
    ("Our key@0 (3/3)", Button::Right),
    ("Their key@1 (1/3)", Button::Right),
    ("Their key@1 (2/3)", Button::Right),
    ("Their key@1 (3/3)", Button::Right),
    ("Register account", Button::Both),
];

// Same flow with the device occupying @1 (recovery slot) rather than @0.
const REGISTER_STEPS_INHERITANCE_RECOVERY_ACK: &[(&str, Button)] = &[
    ("Review account", Button::Right),
    ("Account name", Button::Right),
    ("Wallet policy (1/2)", Button::Right),
    ("Wallet policy (2/2)", Button::Right),
    ("Review co-signer", Button::Right),
    ("Their key@0 (1/3)", Button::Right),
    ("Their key@0 (2/3)", Button::Right),
    ("Their key@0 (3/3)", Button::Right),
    ("Our key@1 (1/3)", Button::Right),
    ("Our key@1 (2/3)", Button::Right),
    ("Our key@1 (3/3)", Button::Right),
    ("Register account", Button::Both),
];

async fn run_register_wsh_miniscript_inheritance(ack: bool) {
    let sim = fresh_speculos();
    let device = connect_to(&sim).await;
    let device_key = get_xpub_for_path(&device, "m/48h/1h/4h/2h").await;
    let recovery_key = common::cosigner_origin("cafebabe", "m/48h/1h/2h/2h");
    let policy = inheritance_policy(&device_key, &recovery_key);

    let task = tokio::spawn(async move { device.register_wallet("inherit", &policy).await });
    let mut steps = REGISTER_STEPS_INHERITANCE_ACK.to_vec();
    if !ack {
        steps.pop();
        steps.push(("Register account", Button::Right));
        steps.push(("Reject operation", Button::Both));
    }
    run_steps(&sim, &steps);

    match (task.await.unwrap(), ack) {
        (Ok(Some(hmac)), true) => assert_eq!(hmac.len(), 32),
        (Ok(None), true) => panic!("inherit register ack returned no hmac"),
        (Err(async_hwi::Error::UserRefused), false) => {}
        (other, ack) => {
            let msg = format!("inherit register outcome (ack={ack}): {other:?}");
            panic!("{}", msg);
        }
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires SPECULOS_ELF"]
async fn speculos_register_wsh_miniscript_inheritance() {
    run_register_wsh_miniscript_inheritance(true).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires SPECULOS_ELF"]
async fn speculos_register_wsh_miniscript_inheritance_reject() {
    run_register_wsh_miniscript_inheritance(false).await;
}

async fn run_display_wsh_miniscript_inheritance() {
    let sim = fresh_speculos();
    let device = connect_to(&sim).await;
    let device_key = get_xpub_for_path(&device, "m/48h/1h/4h/2h").await;
    let recovery_key = common::cosigner_origin("cafebabe", "m/48h/1h/2h/2h");
    let policy = inheritance_policy(&device_key, &recovery_key);

    let hmac = register_for_hmac(
        &sim,
        device,
        "inherit",
        &policy,
        REGISTER_STEPS_INHERITANCE_ACK,
    )
    .await;

    let device = LedgerSimulator::try_connect_on(sim.apdu_addr())
        .await
        .expect("reconnect")
        .with_wallet("inherit", &policy, Some(hmac))
        .expect("with_wallet");
    let task = tokio::spawn(async move {
        device
            .display_address(&AddressScript::Miniscript {
                index: 0,
                change: false,
            })
            .await
    });
    run_steps(
        &sim,
        &[
            ("Verify bitcoin", Button::Right),
            ("Address (1/2)", Button::Right),
            ("Address (2/2)", Button::Right),
            ("Account name", Button::Right),
            ("Confirm", Button::Both),
        ],
    );
    task.await.unwrap().expect("display_address inheritance");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires SPECULOS_ELF"]
async fn speculos_display_wsh_miniscript_inheritance() {
    run_display_wsh_miniscript_inheritance().await;
}

async fn run_sign_wsh_miniscript_inheritance_primary(ack: bool) {
    let sim = fresh_speculos();
    let device = connect_to(&sim).await;
    let device_key = get_xpub_for_path(&device, "m/48h/1h/4h/2h").await;
    let recovery_key = common::cosigner_origin("cafebabe", "m/48h/1h/2h/2h");
    let policy = inheritance_policy(&device_key, &recovery_key);

    let hmac = register_for_hmac(
        &sim,
        device,
        "inherit",
        &policy,
        REGISTER_STEPS_INHERITANCE_ACK,
    )
    .await;

    let device_fp = bitcoin::bip32::Fingerprint::from_hex(SPECULOS_DEFAULT_FINGERPRINT).unwrap();
    let key_origins = vec![
        common::KeyOrigin {
            fingerprint: device_fp,
            account_path: DerivationPath::from_str("m/48h/1h/4h/2h").unwrap(),
        },
        common::KeyOrigin::new("cafebabe", "m/48h/1h/2h/2h"),
    ];
    let mut psbt = common::build_wsh_test_psbt(&policy, &key_origins);

    let device = LedgerSimulator::try_connect_on(sim.apdu_addr())
        .await
        .expect("reconnect")
        .with_wallet("inherit", &policy, Some(hmac))
        .expect("with_wallet");
    let task = tokio::spawn(async move {
        let res = device.sign_tx(&mut psbt).await;
        (res, psbt)
    });
    let steps = sign_steps(ack, true, 2);
    run_steps(&sim, &sign_step_refs(&steps));

    let (api_result, psbt) = task.await.unwrap();
    match (api_result, ack) {
        (Ok(()), true) => assert!(
            !psbt.inputs[0].partial_sigs.is_empty(),
            "expected partial_sigs after ack"
        ),
        (Err(async_hwi::Error::UserRefused), false) => assert!(
            psbt.inputs[0].partial_sigs.is_empty(),
            "expected no partial_sigs after nack"
        ),
        (other, ack) => {
            let msg = format!("inheritance sign primary (ack={ack}): {other:?}");
            panic!("{}", msg);
        }
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires SPECULOS_ELF"]
async fn speculos_sign_wsh_miniscript_inheritance_primary() {
    run_sign_wsh_miniscript_inheritance_primary(true).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires SPECULOS_ELF"]
async fn speculos_sign_wsh_miniscript_inheritance_primary_reject() {
    run_sign_wsh_miniscript_inheritance_primary(false).await;
}

async fn run_sign_wsh_miniscript_inheritance_recovery(ack: bool) {
    let sim = fresh_speculos();
    let device = connect_to(&sim).await;
    // Recovery test: device sits in the recovery branch (K1).
    let primary_key = common::cosigner_origin("c658b283", "m/48h/1h/4h/2h");
    let device_key = get_xpub_for_path(&device, "m/48h/1h/2h/2h").await;
    let policy = inheritance_policy(&primary_key, &device_key);

    let hmac = register_for_hmac(
        &sim,
        device,
        "inherit-r",
        &policy,
        REGISTER_STEPS_INHERITANCE_RECOVERY_ACK,
    )
    .await;

    let device_fp = bitcoin::bip32::Fingerprint::from_hex(SPECULOS_DEFAULT_FINGERPRINT).unwrap();
    let key_origins = vec![
        common::KeyOrigin::new("c658b283", "m/48h/1h/4h/2h"),
        common::KeyOrigin {
            fingerprint: device_fp,
            account_path: DerivationPath::from_str("m/48h/1h/2h/2h").unwrap(),
        },
    ];
    // older(10) requires nSequence >= 10 (relative-block-height encoding,
    // type-flag clear).
    let mut psbt =
        common::build_wsh_test_psbt_with_sequence(&policy, &key_origins, bitcoin::Sequence(10));

    let device = LedgerSimulator::try_connect_on(sim.apdu_addr())
        .await
        .expect("reconnect")
        .with_wallet("inherit-r", &policy, Some(hmac))
        .expect("with_wallet");
    let task = tokio::spawn(async move {
        let res = device.sign_tx(&mut psbt).await;
        (res, psbt)
    });
    let steps = sign_steps(ack, true, 2);
    run_steps(&sim, &sign_step_refs(&steps));

    let (api_result, psbt) = task.await.unwrap();
    match (api_result, ack) {
        (Ok(()), true) => assert!(
            !psbt.inputs[0].partial_sigs.is_empty(),
            "expected partial_sigs after ack"
        ),
        (Err(async_hwi::Error::UserRefused), false) => assert!(
            psbt.inputs[0].partial_sigs.is_empty(),
            "expected no partial_sigs after nack"
        ),
        (other, ack) => {
            let msg = format!("inheritance sign recovery (ack={ack}): {other:?}");
            panic!("{}", msg);
        }
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires SPECULOS_ELF"]
async fn speculos_sign_wsh_miniscript_inheritance_recovery() {
    run_sign_wsh_miniscript_inheritance_recovery(true).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires SPECULOS_ELF"]
async fn speculos_sign_wsh_miniscript_inheritance_recovery_reject() {
    run_sign_wsh_miniscript_inheritance_recovery(false).await;
}

// -----------------------------------------------------------------------------
// Taproot
// -----------------------------------------------------------------------------

async fn run_sign_bip86_tr(ack: bool) {
    let sim = fresh_speculos();
    let device = connect_to(&sim).await;

    let device_key = get_xpub_for_path(&device, "m/86h/1h/0h").await;
    let policy = format!("tr({device_key}/**)");

    let device_fp = bitcoin::bip32::Fingerprint::from_hex(SPECULOS_DEFAULT_FINGERPRINT).unwrap();
    let mut psbt = common::build_tr_keypath_test_psbt(
        &policy,
        &[common::KeyOrigin {
            fingerprint: device_fp,
            account_path: DerivationPath::from_str("m/86h/1h/0h").unwrap(),
        }],
    );

    let device = LedgerSimulator::try_connect_on(sim.apdu_addr())
        .await
        .expect("reconnect")
        .with_wallet("", &policy, None)
        .expect("with_wallet bip86 tr");
    let task = tokio::spawn(async move {
        let res = device.sign_tx(&mut psbt).await;
        (res, psbt)
    });
    let steps = sign_steps(ack, false, 2);
    run_steps(&sim, &sign_step_refs(&steps));

    let (api_result, psbt) = task.await.unwrap();
    match (api_result, ack) {
        (Ok(()), true) => assert!(
            psbt.inputs[0].tap_key_sig.is_some(),
            "expected tap_key_sig after ack"
        ),
        (Err(async_hwi::Error::UserRefused), false) => assert!(
            psbt.inputs[0].tap_key_sig.is_none(),
            "expected no tap_key_sig after nack"
        ),
        (other, ack) => {
            let msg = format!("bip86 tr sign (ack={ack}): {other:?}");
            panic!("{}", msg);
        }
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires SPECULOS_ELF"]
async fn speculos_sign_bip86_tr() {
    run_sign_bip86_tr(true).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires SPECULOS_ELF"]
async fn speculos_sign_bip86_tr_reject() {
    run_sign_bip86_tr(false).await;
}

// `tr(internal, and_v(v:pk(leaf), older(50)))` single-leaf miniscript.

fn tr_1leaf_policy(internal: &str, leaf: &str) -> String {
    format!("tr({internal}/**,and_v(v:pk({leaf}/**),older(50)))")
}

async fn probe_register_tr_1leaf(ack: bool) {
    let sim = fresh_speculos();
    let device = connect_to(&sim).await;
    let internal_key = get_xpub_for_path(&device, "m/48h/1h/9h/2h").await;
    let leaf_key = common::cosigner_origin("d4ab66f1", "m/48h/1h/8h/2h");
    let policy = tr_1leaf_policy(&internal_key, &leaf_key);

    let task = tokio::spawn(async move { device.register_wallet("tr-1leaf", &policy).await });

    // Discover the screens by running with deliberately empty steps and
    // reading the panic; the helper below is the final committed
    // sequence.
    let mut steps = REGISTER_STEPS_TR_1LEAF_ACK.to_vec();
    if !ack {
        steps.pop();
        steps.push(("Register account", Button::Right));
        steps.push(("Reject operation", Button::Both));
    }
    run_steps(&sim, &steps);

    match (task.await.unwrap(), ack) {
        (Ok(Some(hmac)), true) => assert_eq!(hmac.len(), 32),
        (Ok(None), true) => panic!("tr-1leaf register ack returned no hmac"),
        (Err(async_hwi::Error::UserRefused), false) => {}
        (other, ack) => {
            let msg = format!("tr-1leaf register outcome (ack={ack}): {other:?}");
            panic!("{}", msg);
        }
    }
}

const REGISTER_STEPS_TR_1LEAF_ACK: &[(&str, Button)] = &[
    ("Review account", Button::Right),
    ("Account name", Button::Right),
    ("Wallet policy", Button::Right),
    ("Review co-signer", Button::Right),
    ("Our key@0 (1/3)", Button::Right),
    ("Our key@0 (2/3)", Button::Right),
    ("Our key@0 (3/3)", Button::Right),
    ("Their key@1 (1/3)", Button::Right),
    ("Their key@1 (2/3)", Button::Right),
    ("Their key@1 (3/3)", Button::Right),
    ("Register account", Button::Both),
];

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires SPECULOS_ELF"]
async fn speculos_register_tr_miniscript_1leaf() {
    probe_register_tr_1leaf(true).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires SPECULOS_ELF"]
async fn speculos_register_tr_miniscript_1leaf_reject() {
    probe_register_tr_1leaf(false).await;
}

const REGISTER_STEPS_TR_1LEAF_SCRIPTPATH_ACK: &[(&str, Button)] = &[
    ("Review account", Button::Right),
    ("Account name", Button::Right),
    ("Wallet policy", Button::Right),
    ("Review co-signer", Button::Right),
    ("Their key@0 (1/3)", Button::Right),
    ("Their key@0 (2/3)", Button::Right),
    ("Their key@0 (3/3)", Button::Right),
    ("Our key@1 (1/3)", Button::Right),
    ("Our key@1 (2/3)", Button::Right),
    ("Our key@1 (3/3)", Button::Right),
    ("Register account", Button::Both),
];

async fn run_display_tr_miniscript_1leaf() {
    let sim = fresh_speculos();
    let device = connect_to(&sim).await;
    let internal_key = get_xpub_for_path(&device, "m/48h/1h/9h/2h").await;
    let leaf_key = common::cosigner_origin("d4ab66f1", "m/48h/1h/8h/2h");
    let policy = tr_1leaf_policy(&internal_key, &leaf_key);

    let hmac = register_for_hmac(
        &sim,
        device,
        "tr-1leaf",
        &policy,
        REGISTER_STEPS_TR_1LEAF_ACK,
    )
    .await;

    let device = LedgerSimulator::try_connect_on(sim.apdu_addr())
        .await
        .expect("reconnect")
        .with_wallet("tr-1leaf", &policy, Some(hmac))
        .expect("with_wallet");
    let task = tokio::spawn(async move {
        device
            .display_address(&AddressScript::Miniscript {
                index: 0,
                change: false,
            })
            .await
    });
    run_steps(
        &sim,
        &[
            ("Verify bitcoin", Button::Right),
            ("Address (1/2)", Button::Right),
            ("Address (2/2)", Button::Right),
            ("Account name", Button::Right),
            ("Confirm", Button::Both),
        ],
    );
    task.await.unwrap().expect("display_address tr-1leaf");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires SPECULOS_ELF"]
async fn speculos_display_tr_miniscript_1leaf() {
    run_display_tr_miniscript_1leaf().await;
}

async fn run_sign_tr_miniscript_1leaf_keypath(ack: bool) {
    let sim = fresh_speculos();
    let device = connect_to(&sim).await;
    let internal_key = get_xpub_for_path(&device, "m/48h/1h/9h/2h").await;
    let leaf_key = common::cosigner_origin("d4ab66f1", "m/48h/1h/8h/2h");
    let policy = tr_1leaf_policy(&internal_key, &leaf_key);

    let hmac = register_for_hmac(
        &sim,
        device,
        "tr-1leaf",
        &policy,
        REGISTER_STEPS_TR_1LEAF_ACK,
    )
    .await;

    let device_fp = bitcoin::bip32::Fingerprint::from_hex(SPECULOS_DEFAULT_FINGERPRINT).unwrap();
    let key_origins = vec![
        common::KeyOrigin {
            fingerprint: device_fp,
            account_path: DerivationPath::from_str("m/48h/1h/9h/2h").unwrap(),
        },
        common::KeyOrigin::new("d4ab66f1", "m/48h/1h/8h/2h"),
    ];
    let mut psbt = common::build_tr_keypath_test_psbt(&policy, &key_origins);

    let device = LedgerSimulator::try_connect_on(sim.apdu_addr())
        .await
        .expect("reconnect")
        .with_wallet("tr-1leaf", &policy, Some(hmac))
        .expect("with_wallet");
    let task = tokio::spawn(async move {
        let res = device.sign_tx(&mut psbt).await;
        (res, psbt)
    });
    let steps = sign_steps(ack, true, 2);
    run_steps(&sim, &sign_step_refs(&steps));

    let (api_result, psbt) = task.await.unwrap();
    match (api_result, ack) {
        (Ok(()), true) => assert!(
            psbt.inputs[0].tap_key_sig.is_some(),
            "expected tap_key_sig after ack"
        ),
        (Err(async_hwi::Error::UserRefused), false) => assert!(
            psbt.inputs[0].tap_key_sig.is_none(),
            "expected no tap_key_sig after nack"
        ),
        (other, ack) => {
            let msg = format!("tr-1leaf keypath sign (ack={ack}): {other:?}");
            panic!("{}", msg);
        }
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires SPECULOS_ELF"]
async fn speculos_sign_tr_miniscript_1leaf_keypath() {
    run_sign_tr_miniscript_1leaf_keypath(true).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires SPECULOS_ELF"]
async fn speculos_sign_tr_miniscript_1leaf_keypath_reject() {
    run_sign_tr_miniscript_1leaf_keypath(false).await;
}

async fn run_sign_tr_miniscript_1leaf_scriptpath(ack: bool) {
    let sim = fresh_speculos();
    let device = connect_to(&sim).await;
    // Device sits in the leaf (K1).
    let internal_key = common::cosigner_origin("c658b283", "m/48h/1h/9h/2h");
    let leaf_key = get_xpub_for_path(&device, "m/48h/1h/8h/2h").await;
    let policy = tr_1leaf_policy(&internal_key, &leaf_key);

    let hmac = register_for_hmac(
        &sim,
        device,
        "tr-1leaf-s",
        &policy,
        REGISTER_STEPS_TR_1LEAF_SCRIPTPATH_ACK,
    )
    .await;

    let device_fp = bitcoin::bip32::Fingerprint::from_hex(SPECULOS_DEFAULT_FINGERPRINT).unwrap();
    let key_origins = vec![
        common::KeyOrigin::new("c658b283", "m/48h/1h/9h/2h"),
        common::KeyOrigin {
            fingerprint: device_fp,
            account_path: DerivationPath::from_str("m/48h/1h/8h/2h").unwrap(),
        },
    ];
    // older(50) requires nSequence >= 50.
    let mut psbt = common::build_tr_keypath_test_psbt_with_sequence(
        &policy,
        &key_origins,
        bitcoin::Sequence(50),
    );

    let device = LedgerSimulator::try_connect_on(sim.apdu_addr())
        .await
        .expect("reconnect")
        .with_wallet("tr-1leaf-s", &policy, Some(hmac))
        .expect("with_wallet");
    let task = tokio::spawn(async move {
        let res = device.sign_tx(&mut psbt).await;
        (res, psbt)
    });
    let steps = sign_steps(ack, true, 2);
    run_steps(&sim, &sign_step_refs(&steps));

    let (api_result, psbt) = task.await.unwrap();
    match (api_result, ack) {
        (Ok(()), true) => assert!(
            !psbt.inputs[0].tap_script_sigs.is_empty(),
            "expected tap_script_sigs after ack"
        ),
        (Err(async_hwi::Error::UserRefused), false) => assert!(
            psbt.inputs[0].tap_script_sigs.is_empty(),
            "expected no tap_script_sigs after nack"
        ),
        (other, ack) => {
            let msg = format!("tr-1leaf scriptpath sign (ack={ack}): {other:?}");
            panic!("{}", msg);
        }
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires SPECULOS_ELF"]
async fn speculos_sign_tr_miniscript_1leaf_scriptpath() {
    run_sign_tr_miniscript_1leaf_scriptpath(true).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires SPECULOS_ELF"]
async fn speculos_sign_tr_miniscript_1leaf_scriptpath_reject() {
    run_sign_tr_miniscript_1leaf_scriptpath(false).await;
}

// `tr(internal, {and_v(v:pk(leaf_a), older(50)), and_v(v:pk(leaf_b), older(100))})`
// (Liana Setup 1 shape, simplified to single signers per leaf.)

fn tr_2leaf_policy(internal: &str, leaf_a: &str, leaf_b: &str) -> String {
    format!(
        "tr({internal}/**,{{and_v(v:pk({leaf_a}/**),older(50)),and_v(v:pk({leaf_b}/**),older(100))}})"
    )
}

const REGISTER_STEPS_TR_2LEAF_INTERNAL_ACK: &[(&str, Button)] = &[
    ("Review account", Button::Right),
    ("Account name", Button::Right),
    ("Wallet policy (1/2)", Button::Right),
    ("Wallet policy (2/2)", Button::Right),
    ("Review co-signer", Button::Right),
    ("Our key@0 (1/3)", Button::Right),
    ("Our key@0 (2/3)", Button::Right),
    ("Our key@0 (3/3)", Button::Right),
    ("Their key@1 (1/3)", Button::Right),
    ("Their key@1 (2/3)", Button::Right),
    ("Their key@1 (3/3)", Button::Right),
    ("Their key@2 (1/3)", Button::Right),
    ("Their key@2 (2/3)", Button::Right),
    ("Their key@2 (3/3)", Button::Right),
    ("Register account", Button::Both),
];

const REGISTER_STEPS_TR_2LEAF_SCRIPTPATH_ACK: &[(&str, Button)] = &[
    ("Review account", Button::Right),
    ("Account name", Button::Right),
    ("Wallet policy (1/2)", Button::Right),
    ("Wallet policy (2/2)", Button::Right),
    ("Review co-signer", Button::Right),
    ("Their key@0 (1/3)", Button::Right),
    ("Their key@0 (2/3)", Button::Right),
    ("Their key@0 (3/3)", Button::Right),
    ("Our key@1 (1/3)", Button::Right),
    ("Our key@1 (2/3)", Button::Right),
    ("Our key@1 (3/3)", Button::Right),
    ("Their key@2 (1/3)", Button::Right),
    ("Their key@2 (2/3)", Button::Right),
    ("Their key@2 (3/3)", Button::Right),
    ("Register account", Button::Both),
];

async fn run_register_tr_miniscript_2leaf(ack: bool) {
    let sim = fresh_speculos();
    let device = connect_to(&sim).await;
    let internal_key = get_xpub_for_path(&device, "m/48h/1h/9h/2h").await;
    let leaf_a = common::cosigner_origin("d4ab66f1", "m/48h/1h/8h/2h");
    let leaf_b = common::cosigner_origin("e2e975b7", "m/48h/1h/5h/2h");
    let policy = tr_2leaf_policy(&internal_key, &leaf_a, &leaf_b);

    let task = tokio::spawn(async move { device.register_wallet("tr-2leaf", &policy).await });
    let mut steps = REGISTER_STEPS_TR_2LEAF_INTERNAL_ACK.to_vec();
    if !ack {
        steps.pop();
        steps.push(("Register account", Button::Right));
        steps.push(("Reject operation", Button::Both));
    }
    run_steps(&sim, &steps);

    match (task.await.unwrap(), ack) {
        (Ok(Some(hmac)), true) => assert_eq!(hmac.len(), 32),
        (Ok(None), true) => panic!("tr-2leaf register ack returned no hmac"),
        (Err(async_hwi::Error::UserRefused), false) => {}
        (other, ack) => {
            let msg = format!("tr-2leaf register outcome (ack={ack}): {other:?}");
            panic!("{}", msg);
        }
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires SPECULOS_ELF"]
async fn speculos_register_tr_miniscript_2leaf() {
    run_register_tr_miniscript_2leaf(true).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires SPECULOS_ELF"]
async fn speculos_register_tr_miniscript_2leaf_reject() {
    run_register_tr_miniscript_2leaf(false).await;
}

async fn run_display_tr_miniscript_2leaf() {
    let sim = fresh_speculos();
    let device = connect_to(&sim).await;
    let internal_key = get_xpub_for_path(&device, "m/48h/1h/9h/2h").await;
    let leaf_a = common::cosigner_origin("d4ab66f1", "m/48h/1h/8h/2h");
    let leaf_b = common::cosigner_origin("e2e975b7", "m/48h/1h/5h/2h");
    let policy = tr_2leaf_policy(&internal_key, &leaf_a, &leaf_b);

    let hmac = register_for_hmac(
        &sim,
        device,
        "tr-2leaf",
        &policy,
        REGISTER_STEPS_TR_2LEAF_INTERNAL_ACK,
    )
    .await;

    let device = LedgerSimulator::try_connect_on(sim.apdu_addr())
        .await
        .expect("reconnect")
        .with_wallet("tr-2leaf", &policy, Some(hmac))
        .expect("with_wallet");
    let task = tokio::spawn(async move {
        device
            .display_address(&AddressScript::Miniscript {
                index: 0,
                change: false,
            })
            .await
    });
    run_steps(
        &sim,
        &[
            ("Verify bitcoin", Button::Right),
            ("Address (1/2)", Button::Right),
            ("Address (2/2)", Button::Right),
            ("Account name", Button::Right),
            ("Confirm", Button::Both),
        ],
    );
    task.await.unwrap().expect("display_address tr-2leaf");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires SPECULOS_ELF"]
async fn speculos_display_tr_miniscript_2leaf() {
    run_display_tr_miniscript_2leaf().await;
}

async fn run_sign_tr_miniscript_2leaf_keypath(ack: bool) {
    let sim = fresh_speculos();
    let device = connect_to(&sim).await;
    let internal_key = get_xpub_for_path(&device, "m/48h/1h/9h/2h").await;
    let leaf_a = common::cosigner_origin("d4ab66f1", "m/48h/1h/8h/2h");
    let leaf_b = common::cosigner_origin("e2e975b7", "m/48h/1h/5h/2h");
    let policy = tr_2leaf_policy(&internal_key, &leaf_a, &leaf_b);

    let hmac = register_for_hmac(
        &sim,
        device,
        "tr-2leaf",
        &policy,
        REGISTER_STEPS_TR_2LEAF_INTERNAL_ACK,
    )
    .await;

    let device_fp = bitcoin::bip32::Fingerprint::from_hex(SPECULOS_DEFAULT_FINGERPRINT).unwrap();
    let key_origins = vec![
        common::KeyOrigin {
            fingerprint: device_fp,
            account_path: DerivationPath::from_str("m/48h/1h/9h/2h").unwrap(),
        },
        common::KeyOrigin::new("d4ab66f1", "m/48h/1h/8h/2h"),
        common::KeyOrigin::new("e2e975b7", "m/48h/1h/5h/2h"),
    ];
    let mut psbt = common::build_tr_keypath_test_psbt(&policy, &key_origins);

    let device = LedgerSimulator::try_connect_on(sim.apdu_addr())
        .await
        .expect("reconnect")
        .with_wallet("tr-2leaf", &policy, Some(hmac))
        .expect("with_wallet");
    let task = tokio::spawn(async move {
        let res = device.sign_tx(&mut psbt).await;
        (res, psbt)
    });
    let steps = sign_steps(ack, true, 2);
    run_steps(&sim, &sign_step_refs(&steps));

    let (api_result, psbt) = task.await.unwrap();
    match (api_result, ack) {
        (Ok(()), true) => assert!(
            psbt.inputs[0].tap_key_sig.is_some(),
            "expected tap_key_sig after ack"
        ),
        (Err(async_hwi::Error::UserRefused), false) => assert!(
            psbt.inputs[0].tap_key_sig.is_none(),
            "expected no tap_key_sig after nack"
        ),
        (other, ack) => {
            let msg = format!("tr-2leaf keypath sign (ack={ack}): {other:?}");
            panic!("{}", msg);
        }
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires SPECULOS_ELF"]
async fn speculos_sign_tr_miniscript_2leaf_keypath() {
    run_sign_tr_miniscript_2leaf_keypath(true).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires SPECULOS_ELF"]
async fn speculos_sign_tr_miniscript_2leaf_keypath_reject() {
    run_sign_tr_miniscript_2leaf_keypath(false).await;
}

async fn run_sign_tr_miniscript_2leaf_scriptpath(ack: bool) {
    let sim = fresh_speculos();
    let device = connect_to(&sim).await;
    // Device sits in leaf @1 (the older(50) recovery branch).
    let internal_key = common::cosigner_origin("c658b283", "m/48h/1h/9h/2h");
    let leaf_a = get_xpub_for_path(&device, "m/48h/1h/8h/2h").await;
    let leaf_b = common::cosigner_origin("e2e975b7", "m/48h/1h/5h/2h");
    let policy = tr_2leaf_policy(&internal_key, &leaf_a, &leaf_b);

    let hmac = register_for_hmac(
        &sim,
        device,
        "tr-2leaf-s",
        &policy,
        REGISTER_STEPS_TR_2LEAF_SCRIPTPATH_ACK,
    )
    .await;

    let device_fp = bitcoin::bip32::Fingerprint::from_hex(SPECULOS_DEFAULT_FINGERPRINT).unwrap();
    let key_origins = vec![
        common::KeyOrigin::new("c658b283", "m/48h/1h/9h/2h"),
        common::KeyOrigin {
            fingerprint: device_fp,
            account_path: DerivationPath::from_str("m/48h/1h/8h/2h").unwrap(),
        },
        common::KeyOrigin::new("e2e975b7", "m/48h/1h/5h/2h"),
    ];
    let mut psbt = common::build_tr_keypath_test_psbt_with_sequence(
        &policy,
        &key_origins,
        bitcoin::Sequence(50),
    );

    let device = LedgerSimulator::try_connect_on(sim.apdu_addr())
        .await
        .expect("reconnect")
        .with_wallet("tr-2leaf-s", &policy, Some(hmac))
        .expect("with_wallet");
    let task = tokio::spawn(async move {
        let res = device.sign_tx(&mut psbt).await;
        (res, psbt)
    });
    let steps = sign_steps(ack, true, 2);
    run_steps(&sim, &sign_step_refs(&steps));

    let (api_result, psbt) = task.await.unwrap();
    match (api_result, ack) {
        (Ok(()), true) => assert!(
            !psbt.inputs[0].tap_script_sigs.is_empty(),
            "expected tap_script_sigs after ack"
        ),
        (Err(async_hwi::Error::UserRefused), false) => assert!(
            psbt.inputs[0].tap_script_sigs.is_empty(),
            "expected no tap_script_sigs after nack"
        ),
        (other, ack) => {
            let msg = format!("tr-2leaf scriptpath sign (ack={ack}): {other:?}");
            panic!("{}", msg);
        }
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires SPECULOS_ELF"]
async fn speculos_sign_tr_miniscript_2leaf_scriptpath() {
    run_sign_tr_miniscript_2leaf_scriptpath(true).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires SPECULOS_ELF"]
async fn speculos_sign_tr_miniscript_2leaf_scriptpath_reject() {
    run_sign_tr_miniscript_2leaf_scriptpath(false).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires SPECULOS_ELF"]
async fn speculos_display_address_bip86_tr() {
    let sim = fresh_speculos();
    let device = connect_to(&sim).await;

    let path = DerivationPath::from_str("m/86h/1h/0h/0/0").unwrap();
    let task =
        tokio::spawn(async move { device.display_address(&AddressScript::P2TR(path)).await });

    run_steps(
        &sim,
        &[
            ("Verify bitcoin", Button::Right),
            ("Address (1/2)", Button::Right),
            ("Address (2/2)", Button::Right),
            ("Confirm", Button::Both),
        ],
    );

    task.await.unwrap().expect("display_address P2TR");
}

async fn run_sign_wpkh(ack: bool) {
    let sim = fresh_speculos();
    let device_for_key = connect_to(&sim).await;
    let device_key = get_xpub_for_path(&device_for_key, "m/84h/1h/0h").await;
    let policy = format!("wpkh({device_key}/**)");
    drop(device_for_key);
    let device = LedgerSimulator::try_connect_on(sim.apdu_addr())
        .await
        .expect("connect")
        .with_wallet("", &policy, None)
        .expect("with_wallet wpkh");

    let mut psbt = build_wpkh_test_psbt();
    let task = tokio::spawn(async move {
        let res = device.sign_tx(&mut psbt).await;
        (res, psbt)
    });

    let mut steps: Vec<(&str, Button)> = vec![
        ("Review transaction", Button::Right),
        ("Amount", Button::Right),
        ("To", Button::Right),
        ("Fees", Button::Right),
    ];
    if ack {
        steps.push(("Sign transaction", Button::Both));
    } else {
        steps.push(("Sign transaction", Button::Right));
        steps.push(("Reject transaction", Button::Both));
    }
    run_steps(&sim, &steps);

    let (api_result, psbt) = task.await.unwrap();
    match (api_result, ack) {
        (Ok(()), true) => {
            assert!(
                !psbt.inputs[0].partial_sigs.is_empty(),
                "expected partial_sigs to be populated after sign_tx ack",
            );
        }
        (Err(async_hwi::Error::UserRefused), false) => {
            let sigs = &psbt.inputs[0].partial_sigs;
            let detail = format!("expected no partial_sigs after sign_tx nack, got {sigs:?}");
            assert!(sigs.is_empty(), "{}", detail);
        }
        (_, _) => unreachable!(),
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires SPECULOS_ELF"]
async fn speculos_sign_wpkh() {
    run_sign_wpkh(true).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires SPECULOS_ELF"]
async fn speculos_sign_wpkh_reject() {
    run_sign_wpkh(false).await;
}

// PSBT with witness_utxo only (no non_witness_utxo): the app prefixes the
// review with a "Security risk: Unverified inputs" warning. Asserts on
// that warning sequence specifically.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires SPECULOS_ELF"]
async fn speculos_sign_wpkh_unverified_inputs() {
    let sim = fresh_speculos();
    let device_for_key = connect_to(&sim).await;
    let device_key = get_xpub_for_path(&device_for_key, "m/84h/1h/0h").await;
    let policy = format!("wpkh({device_key}/**)");
    drop(device_for_key);
    let device = LedgerSimulator::try_connect_on(sim.apdu_addr())
        .await
        .expect("connect")
        .with_wallet("", &policy, None)
        .expect("with_wallet wpkh");

    let mut psbt = common::build_wpkh_test_psbt_witness_only();

    let device_for_task = device;
    let mut psbt_for_task = psbt.clone();
    let task = tokio::spawn(async move {
        device_for_task.sign_tx(&mut psbt_for_task).await?;
        Ok::<Psbt, async_hwi::Error>(psbt_for_task)
    });

    run_steps(
        &sim,
        &[
            ("Security risk", Button::Right),
            ("Update your wallet software", Button::Right),
            ("Continue anyway", Button::Both),
            ("Review transaction", Button::Right),
            ("Amount", Button::Right),
            ("To", Button::Right),
            ("Fees", Button::Right),
            ("Sign transaction", Button::Both),
        ],
    );

    psbt = task.await.unwrap().expect("sign_tx");

    assert!(
        !psbt.inputs[0].partial_sigs.is_empty(),
        "expected partial_sigs to be populated after sign_tx"
    );
}
