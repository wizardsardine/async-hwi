//! Shared helpers for integration tests against device simulators.
//! Not specific to any particular HWI device or transport.

#![allow(dead_code)] // each test binary uses a subset of these

use std::{
    str::FromStr,
    sync::{Mutex, OnceLock},
};

use bitcoin::{
    absolute,
    bip32::{ChildNumber, DerivationPath, Fingerprint, Xpriv, Xpub},
    psbt::{Input as PsbtInput, Psbt},
    secp256k1::Secp256k1,
    taproot::{LeafVersion, TapLeafHash},
    transaction, Amount, CompressedPublicKey, NetworkKind, OutPoint, ScriptBuf, Sequence,
    Transaction, TxIn, TxOut, Witness,
};
use miniscript::{descriptor::DescriptorPublicKey, Descriptor, ForEachKey};

/// Master fingerprint produced by Speculos's default BIP39 seed.
pub const SPECULOS_DEFAULT_FINGERPRINT: &str = "f5acc2fd";

/// xpub at `m/84'/1'/0'` under Speculos's default seed.
pub const SPECULOS_BIP84_TESTNET_XPUB: &str = "tpubDCtKfsNyRhULjZ9XMS4VKKtVcPdVDi8MKUbcSD9MJDyjRu1A2ND5MiipozyyspBT9bg8upEp7a8EAgFxNxXn1d7QkdbL52Ty5jiSLcxPt1P";

/// Derive a test-only cosigner-key origin string from a fixed seed.
///
/// Returns `[fp_hex/path]xpub` ready to drop into a wallet-policy
/// `format!`. `fp_label_hex` is purely a label written into the origin
/// (Ledger does not cross-validate origin fingerprints against the xpub
/// for keys the device does not own).
///
/// The xpub is derived deterministically from a hardcoded 32-byte seed
/// distinct from speculos's default seed, so the resulting key is
/// always different from any xpub the device produces.
pub fn cosigner_origin(fp_label_hex: &str, path: &str) -> String {
    static MASTER: OnceLock<Xpriv> = OnceLock::new();
    let master = MASTER.get_or_init(|| {
        // Fixed 32-byte entropy. Different from speculos's default seed.
        let entropy = [
            0xa5, 0x5a, 0xa5, 0x5a, 0xa5, 0x5a, 0xa5, 0x5a, 0xa5, 0x5a, 0xa5, 0x5a, 0xa5, 0x5a,
            0xa5, 0x5a, 0xa5, 0x5a, 0xa5, 0x5a, 0xa5, 0x5a, 0xa5, 0x5a, 0xa5, 0x5a, 0xa5, 0x5a,
            0xa5, 0x5a, 0xa5, 0x5a,
        ];
        Xpriv::new_master(NetworkKind::Test, &entropy).expect("master xpriv")
    });
    let secp = secp_ctx();
    let derivation = DerivationPath::from_str(path).expect("valid derivation path");
    let xpriv = master.derive_priv(secp, &derivation).expect("derive xpriv");
    let xpub = Xpub::from_priv(secp, &xpriv);
    let path_in_origin = path.trim_start_matches("m/");
    format!("[{fp_label_hex}/{path_in_origin}]{xpub}")
}

/// 1-input, 1-output testnet PSBT spending a `tr(...)` policy back to
/// itself at receive index 0 via the **key-path** branch. `policy` is
/// the descriptor with inline keys; `key_origins[i]` lines up with keys
/// in their declaration order (internal key first).
pub fn build_tr_keypath_test_psbt(policy: &str, key_origins: &[KeyOrigin]) -> Psbt {
    build_tr_keypath_test_psbt_with_sequence(policy, key_origins, Sequence::ENABLE_RBF_NO_LOCKTIME)
}

pub fn build_tr_keypath_test_psbt_with_sequence(
    policy: &str,
    key_origins: &[KeyOrigin],
    sequence: Sequence,
) -> Psbt {
    let secp = secp_ctx();
    let policy_for_miniscript = expand_multipath(policy);

    let desc: Descriptor<DescriptorPublicKey> =
        Descriptor::from_str(&policy_for_miniscript).expect("parse descriptor");
    let single = desc
        .into_single_descriptors()
        .expect("split multipath")
        .into_iter()
        .next()
        .expect("single branch");
    let derived = single
        .at_derivation_index(0)
        .expect("at index")
        .derived_descriptor(secp)
        .expect("derive");
    let script_pubkey = derived.script_pubkey();

    // Per-key receive xonly pubkeys, in declaration order.
    let pks = extract_descriptor_pubkeys(policy, &key_origins.len(), 0);

    // Internal key + script-tree merkle root for the taproot input.
    let (internal_xonly, merkle_root, leaf_scripts) = match &derived {
        Descriptor::Tr(tr) => {
            let spend = tr.spend_info();
            let internal = spend.internal_key();
            let merkle = spend.merkle_root();
            // Walk the tree to collect (script, leaf_version, control_block).
            let leaves: Vec<(ScriptBuf, LeafVersion, bitcoin::taproot::ControlBlock)> = tr
                .iter_scripts()
                .map(|(_depth, ms)| {
                    let script = ms.encode();
                    let lv = LeafVersion::TapScript;
                    let cb = spend
                        .control_block(&(script.clone(), lv))
                        .expect("control block");
                    (script, lv, cb)
                })
                .collect();
            (internal, merkle, leaves)
        }
        _ => panic!("expected Tr descriptor"),
    };

    let prev_value = Amount::from_sat(10_000);
    let prev_tx = Transaction {
        version: transaction::Version::TWO,
        lock_time: absolute::LockTime::ZERO,
        input: vec![TxIn {
            previous_output: OutPoint::null(),
            script_sig: ScriptBuf::new(),
            sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
            witness: Witness::new(),
        }],
        output: vec![TxOut {
            value: prev_value,
            script_pubkey: script_pubkey.clone(),
        }],
    };
    let prev_out = OutPoint {
        txid: prev_tx.compute_txid(),
        vout: 0,
    };

    let tx = Transaction {
        version: transaction::Version::TWO,
        lock_time: absolute::LockTime::ZERO,
        input: vec![TxIn {
            previous_output: prev_out,
            script_sig: ScriptBuf::new(),
            sequence,
            witness: Witness::new(),
        }],
        output: vec![TxOut {
            value: Amount::from_sat(9_000),
            script_pubkey: script_pubkey.clone(),
        }],
    };
    let mut psbt = Psbt::from_unsigned_tx(tx).expect("psbt");

    let mut input = PsbtInput {
        witness_utxo: Some(TxOut {
            value: prev_value,
            script_pubkey: script_pubkey.clone(),
        }),
        non_witness_utxo: Some(prev_tx),
        tap_internal_key: Some(internal_xonly),
        tap_merkle_root: merkle_root,
        ..Default::default()
    };

    // tap_key_origins entries: x-only pubkey -> (leaf hashes the key
    // appears in, KeySource). Internal key has empty leaf-list; leaf
    // keys list the leaf hashes that contain them.
    for (pk, origin) in pks.iter().zip(key_origins.iter()) {
        let mut full_path = origin.account_path.clone();
        full_path = full_path.extend([
            ChildNumber::Normal { index: 0 },
            ChildNumber::Normal { index: 0 },
        ]);
        let xonly = bitcoin::secp256k1::XOnlyPublicKey::from(*pk);
        let leaf_hashes: Vec<TapLeafHash> = leaf_scripts
            .iter()
            .filter(|(script, lv, _)| script_uses_xonly(script, &xonly, *lv))
            .map(|(script, lv, _)| TapLeafHash::from_script(script, *lv))
            .collect();
        input.tap_key_origins.insert(
            xonly,
            (leaf_hashes, (origin.fingerprint, full_path.clone())),
        );
        psbt.outputs[0]
            .tap_key_origins
            .insert(xonly, (vec![], (origin.fingerprint, full_path)));
    }

    // tap_scripts: for script-path support, populate the (control_block,
    // (script, leaf_version)) map from leaf_scripts.
    for (script, lv, cb) in leaf_scripts {
        input.tap_scripts.insert(cb, (script, lv));
    }

    psbt.inputs[0] = input;
    psbt
}

/// True if `script` references `xonly` (32 raw bytes pushed by an
/// `OP_PUSHBYTES_32`). Good enough for our test fixtures whose leaves
/// are always `pk(K)` or short combinators.
fn script_uses_xonly(
    script: &ScriptBuf,
    xonly: &bitcoin::secp256k1::XOnlyPublicKey,
    _lv: LeafVersion,
) -> bool {
    let bytes = xonly.serialize();
    script.as_bytes().windows(32).any(|w| w == bytes)
}

/// async-hwi accepts `/**` shorthand in policy strings (expanded by
/// `extract_keys_and_template` into the wallet policy template).
/// miniscript-rs requires the explicit `/<0;1>/*` form. Translate.
fn expand_multipath(policy: &str) -> String {
    policy.replace("/**", "/<0;1>/*")
}

fn secp_ctx() -> &'static Secp256k1<bitcoin::secp256k1::All> {
    static CTX: OnceLock<Mutex<()>> = OnceLock::new();
    CTX.get_or_init(|| Mutex::new(()));
    // Secp256k1::new() is cheap for `All` context but we keep it static
    // so call sites don't repeatedly allocate.
    static SECP: OnceLock<Secp256k1<bitcoin::secp256k1::All>> = OnceLock::new();
    SECP.get_or_init(Secp256k1::new)
}

/// `witness_utxo`-only variant of [`build_wpkh_test_psbt`]: the input
/// carries no `non_witness_utxo`, so the device prefixes signing with a
/// "Security risk: Unverified inputs" warning. Useful for exercising the
/// warning flow itself.
pub fn build_wpkh_test_psbt_witness_only() -> Psbt {
    let mut psbt = build_wpkh_test_psbt();
    psbt.inputs[0].non_witness_utxo = None;
    psbt
}

/// Origin metadata for one key in a multi-key policy: the master
/// fingerprint and the derivation path from master to the *account*-level
/// xpub (the same path the policy carries in the `[fp/path]xpub`
/// origin string). Used by [`build_wsh_test_psbt`] to populate
/// `bip32_derivation` entries.
#[derive(Clone, Debug)]
pub struct KeyOrigin {
    pub fingerprint: Fingerprint,
    pub account_path: DerivationPath,
}

impl KeyOrigin {
    pub fn new(fp: &str, path: &str) -> Self {
        Self {
            fingerprint: Fingerprint::from_hex(fp).expect("hex fp"),
            account_path: DerivationPath::from_str(path).expect("path"),
        }
    }
}

/// 1-input, 1-output testnet PSBT spending from a wsh policy back to
/// itself at receive index 0. `policy` is the descriptor string with
/// inline keys (the same string passed to `register_wallet` /
/// `with_wallet`); `key_origins[i]` lines up with the keys as they
/// appear in the descriptor.
pub fn build_wsh_test_psbt(policy: &str, key_origins: &[KeyOrigin]) -> Psbt {
    build_wsh_test_psbt_with_sequence(policy, key_origins, Sequence::ENABLE_RBF_NO_LOCKTIME)
}

/// Variant of [`build_wsh_test_psbt`] that lets the caller pin the
/// input's `nSequence`. Used to satisfy `older(N)` miniscript
/// fragments on a recovery spending path.
pub fn build_wsh_test_psbt_with_sequence(
    policy: &str,
    key_origins: &[KeyOrigin],
    sequence: Sequence,
) -> Psbt {
    let secp = secp_ctx();
    let policy_for_miniscript = expand_multipath(policy);

    let desc: Descriptor<DescriptorPublicKey> =
        Descriptor::from_str(&policy_for_miniscript).expect("parse descriptor");
    let single = desc
        .into_single_descriptors()
        .expect("split multipath")
        .into_iter()
        .next()
        .expect("at least one branch");
    let derived = single
        .at_derivation_index(0)
        .expect("at index")
        .derived_descriptor(secp)
        .expect("derive");
    let script_pubkey = derived.script_pubkey();
    let witness_script = derived.explicit_script().expect("witness_script");

    // Receive pubkey + key_source for each key in the policy.
    let pks: Vec<bitcoin::secp256k1::PublicKey> =
        extract_descriptor_pubkeys(policy, &key_origins.len(), 0);

    let prev_value = Amount::from_sat(10_000);
    let prev_tx = Transaction {
        version: transaction::Version::TWO,
        lock_time: absolute::LockTime::ZERO,
        input: vec![TxIn {
            previous_output: OutPoint::null(),
            script_sig: ScriptBuf::new(),
            sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
            witness: Witness::new(),
        }],
        output: vec![TxOut {
            value: prev_value,
            script_pubkey: script_pubkey.clone(),
        }],
    };
    let prev_out = OutPoint {
        txid: prev_tx.compute_txid(),
        vout: 0,
    };

    let tx = Transaction {
        version: transaction::Version::TWO,
        lock_time: absolute::LockTime::ZERO,
        input: vec![TxIn {
            previous_output: prev_out,
            script_sig: ScriptBuf::new(),
            sequence,
            witness: Witness::new(),
        }],
        output: vec![TxOut {
            value: Amount::from_sat(9_000),
            script_pubkey: script_pubkey.clone(),
        }],
    };
    let mut psbt = Psbt::from_unsigned_tx(tx).expect("psbt");

    let mut input = PsbtInput {
        witness_utxo: Some(TxOut {
            value: prev_value,
            script_pubkey: script_pubkey.clone(),
        }),
        non_witness_utxo: Some(prev_tx),
        witness_script: Some(witness_script),
        ..Default::default()
    };
    for (pk, origin) in pks.iter().zip(key_origins.iter()) {
        let mut full_path = origin.account_path.clone();
        full_path = full_path.extend([
            ChildNumber::Normal { index: 0 },
            ChildNumber::Normal { index: 0 },
        ]);
        input
            .bip32_derivation
            .insert(*pk, (origin.fingerprint, full_path.clone()));
        psbt.outputs[0]
            .bip32_derivation
            .insert(*pk, (origin.fingerprint, full_path));
    }
    psbt.inputs[0] = input;

    psbt
}

/// Re-parse the descriptor and return the receive-side pubkey for each
/// key at child index `child` (under the `0` multipath branch).
fn extract_descriptor_pubkeys(
    policy: &str,
    expected_count: &usize,
    child: u32,
) -> Vec<bitcoin::secp256k1::PublicKey> {
    let secp = secp_ctx();
    let desc: Descriptor<DescriptorPublicKey> =
        Descriptor::from_str(&expand_multipath(policy)).expect("parse descriptor");
    let single = desc
        .into_single_descriptors()
        .expect("split multipath")
        .into_iter()
        .next()
        .expect("at least one branch");
    let mut pks = Vec::with_capacity(*expected_count);
    single.for_each_key(|k: &DescriptorPublicKey| {
        let derived = k.clone().at_derivation_index(child).expect("at child");
        let pk = derived.derive_public_key(secp).expect("derive_public_key");
        pks.push(pk.inner);
        true
    });
    pks
}

/// 1-input, 1-output testnet PSBT spending from the Speculos default-seed
/// wpkh wallet at `m/84'/1'/0'/0/0` back to itself, populated with
/// `non_witness_utxo` + `witness_utxo` so the device runs the canonical
/// review flow without prefixing it with a "Security risk: Unverified
/// inputs" warning.
pub fn build_wpkh_test_psbt() -> Psbt {
    let secp = Secp256k1::new();

    let xpub = Xpub::from_str(SPECULOS_BIP84_TESTNET_XPUB).expect("parse xpub");
    let recv_path = [
        ChildNumber::Normal { index: 0 },
        ChildNumber::Normal { index: 0 },
    ];
    let recv_xpub = xpub.derive_pub(&secp, &recv_path).expect("derive 0/0");
    let recv_pk = recv_xpub.public_key;
    let compressed = CompressedPublicKey(recv_pk);
    let script_pubkey = ScriptBuf::new_p2wpkh(&compressed.wpubkey_hash());

    let prev_value = Amount::from_sat(10_000);
    let prev_tx = Transaction {
        version: transaction::Version::TWO,
        lock_time: absolute::LockTime::ZERO,
        input: vec![TxIn {
            previous_output: OutPoint::null(),
            script_sig: ScriptBuf::new(),
            sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
            witness: Witness::new(),
        }],
        output: vec![TxOut {
            value: prev_value,
            script_pubkey: script_pubkey.clone(),
        }],
    };
    let prev_out = OutPoint {
        txid: prev_tx.compute_txid(),
        vout: 0,
    };

    let tx = Transaction {
        version: transaction::Version::TWO,
        lock_time: absolute::LockTime::ZERO,
        input: vec![TxIn {
            previous_output: prev_out,
            script_sig: ScriptBuf::new(),
            sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
            witness: Witness::new(),
        }],
        output: vec![TxOut {
            value: Amount::from_sat(9_000),
            script_pubkey: script_pubkey.clone(),
        }],
    };

    let mut psbt = Psbt::from_unsigned_tx(tx).expect("psbt from tx");

    let mut input = PsbtInput {
        witness_utxo: Some(TxOut {
            value: prev_value,
            script_pubkey: script_pubkey.clone(),
        }),
        non_witness_utxo: Some(prev_tx),
        ..Default::default()
    };
    let key_source = (
        Fingerprint::from_hex(SPECULOS_DEFAULT_FINGERPRINT).unwrap(),
        DerivationPath::from_str("m/84'/1'/0'/0/0").unwrap(),
    );
    input.bip32_derivation.insert(recv_pk, key_source.clone());
    psbt.inputs[0] = input;

    psbt.outputs[0].bip32_derivation.insert(recv_pk, key_source);

    psbt
}
