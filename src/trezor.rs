//! # Examples
//! ```no_run
//! use async_hwi::trezor::TrezorClient;
//! use async_hwi::HWI;
//!
//! #[tokio::main]
//! pub async fn main() {
//!     let mut hwi = TrezorClient::connect_first(false).unwrap();
//!     hwi.set_network(bitcoin::Network::Bitcoin);
//!     println!("{}", hwi.get_version().await.unwrap());
//!     println!("{:?}", hwi.get_master_fingerprint().await);
//!     let path =
//!         <bitcoin::bip32::DerivationPath as std::str::FromStr>::from_str("m/44'/1'/0'/0/0")
//!             .expect("Failed to parse path");
//!     println!("{:?}", hwi.get_extended_pubkey(&path).await);
//!}
//!  ```

use std::{
    collections::HashMap,
    str::FromStr,
    sync::{Arc, Mutex},
};

use async_trait::async_trait;
use bitcoin::{
    bip32::{DerivationPath, ExtendedPubKey, Fingerprint},
    ecdsa,
    psbt::Psbt,
    PublicKey,
};
use trezor_client::{Trezor, TrezorResponse};

use crate::{DeviceKind, Error, HWI};

pub struct TrezorClient {
    client: Arc<Mutex<Trezor>>,
    kind: DeviceKind,
    network: bitcoin::Network,
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
    fn new(client: Trezor) -> Self {
        let kind = match client.model() {
            trezor_client::Model::TrezorEmulator => DeviceKind::TrezorSimulator,
            _ => DeviceKind::Trezor,
        };
        Self {
            client: Arc::new(Mutex::new(client)),
            kind,
            network: bitcoin::Network::Testnet,
        }
    }

    pub fn connect_first(debug: bool) -> Result<Self, Error> {
        let mut devices = trezor_client::find_devices(debug);
        if !devices.is_empty() {
            let mut client = devices.remove(0).connect()?;
            client.init_device(None)?;
            Ok(Self::new(client))
        } else {
            Err(Error::DeviceNotFound)
        }
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
}

#[async_trait]
impl HWI for TrezorClient {
    fn device_kind(&self) -> crate::DeviceKind {
        self.kind
    }

    async fn get_version(&self) -> Result<super::Version, Error> {
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
            return Err(Error::Device(String::from("No features found")));
        }
    }

    async fn is_connected(&self) -> Result<(), Error> {
        match self.client.lock().unwrap().ping("PINGPING")? {
            TrezorResponse::Ok(_) => Ok(()),
            _ => Err(Error::DeviceDisconnected),
        }
    }

    async fn get_master_fingerprint(&self) -> Result<Fingerprint, Error> {
        let path = DerivationPath::default();
        match self.client.lock().unwrap().get_public_key(
            &path,
            trezor_client::InputScriptType::SPENDADDRESS,
            self.network,
            false,
        ) {
            Ok(TrezorResponse::Ok(key)) => {
                let fp = key.fingerprint();
                Ok(fp)
            }
            Ok(TrezorResponse::Failure(f)) => Err(Error::Device(f.to_string())),
            Ok(result) => Err(Error::Device(result.to_string())),
            Err(e) => Err(Error::Device(e.to_string())),
        }
    }

    async fn get_extended_pubkey(&self, path: &DerivationPath) -> Result<ExtendedPubKey, Error> {
        let path = DerivationPath::from_str(&path.to_string())
            .map_err(|e| Error::Device(format!("{:?}", e)))?;
        match self.client.lock().unwrap().get_public_key(
            &path,
            trezor_client::InputScriptType::SPENDADDRESS,
            self.network,
            false,
        ) {
            Ok(TrezorResponse::Ok(key)) => return Ok(key),
            Ok(TrezorResponse::Failure(f)) => Err(Error::Device(f.to_string())),
            Ok(result) => Err(Error::Device(result.to_string())),
            Err(e) => Err(Error::Device(e.to_string())),
        }
    }

    async fn register_wallet(&self, _name: &str, _policy: &str) -> Result<Option<[u8; 32]>, Error> {
        return Err(Error::UnimplementedMethod);
    }

    async fn sign_tx(&self, tx: &mut Psbt) -> Result<(), Error> {
        let master_fp = self.get_master_fingerprint().await?;
        let mut signatures = HashMap::new();
        let mut client = self.client.lock().unwrap();
        let mut result = client.sign_tx(tx, self.network)?;

        // TODO: make this loop more elegant
        // This could be done asynchrnously
        loop {
            match result {
                TrezorResponse::Ok(progress) => {
                    if progress.has_signature() {
                        let (index, signature) = progress.get_signature().unwrap();
                        let mut signature = signature.to_vec();
                        // TODO: add support for multisig
                        signature.push(0x01); // Signature type
                        if signatures.contains_key(&index) {
                            return Err(Error::Device(format!(
                                "Signature for index {} already filled",
                                index
                            )));
                        }
                        let val = ecdsa::Signature::from_slice(&signature)
                            .map_err(|e| Error::Device(format!("{:?}", e)));
                        signatures.insert(index, val?);
                    }
                    if progress.finished() {
                        for (index, input) in tx.inputs.iter_mut().enumerate() {
                            let signature = signatures.remove(&index).ok_or(Error::Device(
                                format!("Signature for index {} not found", index),
                            ))?;
                            for (pk, (fp, _)) in input.bip32_derivation.iter() {
                                let pk = PublicKey::from_slice(pk.serialize().as_ref()).unwrap();
                                if *fp == master_fp {
                                    input.partial_sigs.insert(pk, signature);
                                    break;
                                }
                            }
                        }
                        return Ok(());
                    } else {
                        result = progress.ack_psbt(tx, self.network)?;
                    }
                }
                TrezorResponse::Failure(f) => {
                    return Err(Error::Device(f.to_string()));
                }
                TrezorResponse::ButtonRequest(req) => {
                    result = req.ack()?;
                }
                _ => {
                    return Err(Error::Device(result.to_string()));
                }
            }
        }
    }
}

impl From<trezor_client::Error> for Error {
    fn from(value: trezor_client::Error) -> Self {
        Error::Device(format!("{:#?}", value))
    }
}
