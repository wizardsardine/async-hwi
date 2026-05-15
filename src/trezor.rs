use crate::{utils::extract_keys_and_template, AddressScript, DeviceKind, Error as HWIError, HWI};

use std::{
    collections::HashMap,
    convert::TryInto,
    sync::{Arc, Mutex},
};

use async_trait::async_trait;
use bitcoin::{
    bip32::{ChildNumber, DerivationPath, Fingerprint, Xpub},
    hex::DisplayHex,
    psbt::Psbt,
    PublicKey,
};
use trezor_client::{protos, utils::coin_name, AvailableDevice, Trezor};

#[derive(Debug)]
pub struct WalletPolicy {
    name: String,
    policy: String,
    hmac: [u8; 32],
}

impl WalletPolicy {
    pub fn new(name: &str, policy: &str, hmac: [u8; 32]) -> Self {
        Self {
            name: name.to_owned(),
            policy: policy.to_owned(),
            hmac,
        }
    }
}

pub struct TrezorClient {
    client: Arc<Mutex<Trezor>>,
    kind: DeviceKind,
    network: bitcoin::Network,
    wallet: Option<WalletPolicy>,
}

impl From<TrezorClient> for Box<dyn HWI + Send> {
    fn from(s: TrezorClient) -> Box<dyn HWI + Send> {
        Box::new(s)
    }
}

impl std::fmt::Debug for TrezorClient {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TrezorClient")
            .field("client", &self.client.lock().unwrap().model())
            .finish()
    }
}

impl TrezorClient {
    fn new(client: Trezor, network: bitcoin::Network) -> Self {
        let kind = match client.model() {
            trezor_client::Model::TrezorEmulator => DeviceKind::TrezorSimulator,
            _ => DeviceKind::Trezor,
        };
        Self {
            client: Arc::new(Mutex::new(client)),
            kind,
            network,
            wallet: None,
        }
    }

    pub fn connect(device: AvailableDevice, network: bitcoin::Network) -> Result<Self, HWIError> {
        let mut client = device.connect()?;
        client.init_device(None)?;
        Ok(Self::new(client, network))
    }

    pub fn with_wallet(mut self, wallet: WalletPolicy) -> Result<Self, HWIError> {
        self.wallet = Some(wallet);
        Ok(self)
    }

    pub fn find_devices() -> Vec<AvailableDevice> {
        trezor_client::find_devices(false)
    }

    pub fn get_simulator() -> Trezor {
        let mut emulator = trezor_client::find_devices(false)
            .into_iter()
            .find(|t| t.model == trezor_client::Model::TrezorEmulator)
            .expect("No emulator found")
            .connect()
            .expect("Failed to connect to emulator");
        emulator
            .init_device(None)
            .expect("Failed to intialize device");
        emulator
    }

    pub fn get_network(&self) -> bitcoin::Network {
        self.network
    }

    pub fn set_network(&mut self, network: bitcoin::Network) {
        self.network = network;
    }

    fn registered_policy(&self) -> Result<protos::RegisteredPolicy, HWIError> {
        let wallet = self
            .wallet
            .as_ref()
            .ok_or_else(|| HWIError::MissingPolicy)?;

        let (template, xpubs) = extract(&wallet.policy)?;

        let mut registered = protos::RegisteredPolicy::new();
        registered.set_mac(wallet.hmac.to_vec());

        let policy = registered.policy.mut_or_insert_default();
        policy.set_name(wallet.name.clone());
        policy.set_template(template);
        policy.xpubs = xpubs;
        policy.set_coin_name(coin_name(self.network)?);
        Ok(registered)
    }
}

fn extract(policy: &str) -> Result<(String, Vec<String>), HWIError> {
    Ok(extract_keys_and_template::<String>(policy)?)
}

#[async_trait]
impl HWI for TrezorClient {
    fn device_kind(&self) -> crate::DeviceKind {
        self.kind
    }

    async fn get_version(&self) -> Result<super::Version, HWIError> {
        let client = self.client.lock().unwrap();
        let f = client.features();
        if let Some(f) = f {
            let version = super::Version {
                major: f.major_version(),
                minor: f.minor_version(),
                patch: f.patch_version(),
                prerelease: None,
            };
            Ok(version)
        } else {
            return Err(HWIError::Device(String::from("No features found")));
        }
    }

    async fn get_master_fingerprint(&self) -> Result<Fingerprint, HWIError> {
        Ok(self
            .client
            .lock()
            .unwrap()
            .get_public_key(
                &DerivationPath::default(),
                trezor_client::InputScriptType::SPENDADDRESS,
                bitcoin::Network::Bitcoin,
                false,
            )?
            .fingerprint())
    }

    async fn is_wallet_registered(&self, _name: &str, _policy: &str) -> Result<bool, HWIError> {
        return Err(HWIError::UnimplementedMethod);
    }

    async fn display_address(&self, script: &AddressScript) -> Result<(), HWIError> {
        match script {
            AddressScript::P2TR(_path) => {
                return Err(HWIError::UnimplementedMethod);
            }
            AddressScript::Miniscript { index, change } => {
                let mut client = self.client.lock().unwrap();
                let path = DerivationPath::from(vec![
                    ChildNumber::from(u32::from(*change)),
                    ChildNumber::from(*index),
                ]);
                let addr = client.get_address(
                    &path,
                    protos::InputScriptType::SPENDMINISCRIPT,
                    self.network,
                    true,
                    Some(self.registered_policy()?),
                )?;
                eprintln!("addr: {}", addr);
                Ok(())
            }
        }
    }

    async fn get_extended_pubkey(&self, path: &DerivationPath) -> Result<Xpub, HWIError> {
        self.client
            .lock()
            .unwrap()
            .get_public_key(
                path,
                trezor_client::InputScriptType::SPENDADDRESS,
                self.network,
                false,
            )
            .map_err(Into::into)
    }

    async fn register_wallet(
        &self,
        name: &str,
        policy: &str,
    ) -> Result<Option<[u8; 32]>, HWIError> {
        let (template, xpubs) = extract(policy)?;
        let registered = self.client.lock().unwrap().register_policy(
            name.to_owned(),
            template,
            xpubs,
            self.network,
        )?;
        let Some(mac) = registered.mac else {
            return Err(HWIError::Device("Missing MAC".to_owned()));
        };
        return Ok(Some(mac.try_into().map_err(|_| {
            HWIError::Device("Registration failed".to_owned())
        })?));
    }

    async fn sign_tx(&self, tx: &mut Psbt) -> Result<(), HWIError> {
        let master_fp = self.get_master_fingerprint().await?;

        let mut client = self.client.lock().unwrap();

        let signed_tx = client.sign_tx(tx, self.network, Some(self.registered_policy()?))?;

        let mut signatures = HashMap::new();
        for (i, mut sig_bytes) in signed_tx.signatures.into_iter() {
            sig_bytes.push(bitcoin::sighash::EcdsaSighashType::All as u8);
            let sig = bitcoin::ecdsa::Signature::from_slice(&sig_bytes).map_err(|_| {
                HWIError::Device(format!("Invalid signature {}: {}", i, sig_bytes.as_hex(),))
            })?;
            if signatures.insert(i, sig).is_some() {
                return Err(HWIError::Device(format!("Duplicate signature index {}", i)));
            }
        }

        for (index, input) in tx.inputs.iter_mut().enumerate() {
            let signature = signatures.remove(&index).ok_or(HWIError::Device(format!(
                "Signature for index {} not found",
                index
            )))?;
            eprintln!("sig: {}", signature.serialize().to_lower_hex_string());
            for (pk, (fp, _)) in input.bip32_derivation.iter() {
                let pk = PublicKey::from_slice(pk.serialize().as_ref()).unwrap();
                if *fp == master_fp {
                    input.partial_sigs.insert(pk, signature);
                    break;
                }
            }
        }
        return Ok(());
    }
}

impl From<trezor_client::Error> for HWIError {
    fn from(value: trezor_client::Error) -> Self {
        HWIError::Device(format!("{}", value))
    }
}
