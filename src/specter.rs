use std::fmt::Debug;
use std::str::FromStr;
use std::sync::Arc;

use bitcoin::{
    bip32::{DerivationPath, Fingerprint, Xpub},
    psbt::Psbt,
    taproot, Network,
};

use miniscript::{Descriptor, DescriptorPublicKey, ForEachKey};

use serialport::{available_ports, SerialPort, SerialPortType};
use tokio::{
    io::{AsyncBufReadExt, AsyncRead, AsyncWrite, AsyncWriteExt},
    net::TcpStream,
    sync::Mutex,
};
use tokio_serial::SerialPortBuilderExt;
pub use tokio_serial::SerialStream;

use super::{AddressScript, DeviceKind, Error as HWIError, HWI};
use async_trait::async_trait;

#[derive(Debug)]
pub struct Specter<T> {
    transport: T,
    kind: DeviceKind,
    pub descriptor: Option<Descriptor<DescriptorPublicKey>>,
}

impl<T: Transport> Specter<T> {
    pub async fn fingerprint(&self) -> Result<Fingerprint, SpecterError> {
        self.transport
            .request("\r\n\r\nfingerprint\r\n")
            .await
            .and_then(|resp| {
                Fingerprint::from_str(&resp).map_err(|e| SpecterError::Device(e.to_string()))
            })
    }

    pub async fn get_extended_pubkey(&self, path: &DerivationPath) -> Result<Xpub, SpecterError> {
        self.transport
            .request(&format!("\r\n\r\nxpub {}\r\n", path))
            .await
            .and_then(|resp| Xpub::from_str(&resp).map_err(|e| SpecterError::Device(e.to_string())))
    }

    /// If the descriptor contains master public keys but doesn't contain wildcard derivations,
    /// the default derivation /{0,1}/* will be added by the device to all extended keys in the descriptor.
    /// See: https://github.com/cryptoadvance/specter-diy/blob/master/docs/descriptors.md#default-derivations
    /// If at least one of the xpubs has a wildcard derivation the descriptor will not be changed.
    /// /** is an equivalent of /{0,1}/*.
    pub async fn add_wallet(&self, name: &str, policy: &str) -> Result<(), SpecterError> {
        self.transport
            .request(&format!(
                "\r\n\r\naddwallet {}&{}\r\n",
                name,
                policy
                    .replace("/**", "/{0,1}/*")
                    // currently specter does not support <0;1> but {0,1}
                    .replace('<', "{")
                    .replace(';', ",")
                    .replace('>', "}")
            ))
            .await
            .and_then(|resp| {
                if resp.is_empty() || resp == "success" {
                    Ok(())
                } else if resp == "error: User cancelled" {
                    Err(SpecterError::UserCancelled)
                } else {
                    Err(SpecterError::Device(resp))
                }
            })
    }

    pub async fn show_addr(&self, addr: bitcoin::Address, index: u32) -> Result<(), SpecterError> {
        if let Some(descr) = &self.descriptor {
            if descr.to_string().starts_with("wsh") {
                let raw_req = format!("\r\n\r\nbitcoin:{}?index={}\r\n", addr, index);
                println!("{raw_req}");
                return self.transport.request(&raw_req).await.map(|_| ());
            }
        }
        Err(SpecterError::Descriptor)
    }

    pub async fn sign(&self, psbt: &Psbt) -> Result<Psbt, SpecterError> {
        self.transport
            .request(&format!("\r\n\r\nsign {}\r\n", psbt))
            .await
            .and_then(|resp| {
                if resp == "error: User cancelled" {
                    Err(SpecterError::UserCancelled)
                } else {
                    Psbt::from_str(&resp).map_err(|e| SpecterError::Device(e.to_string()))
                }
            })
    }

    pub fn set_descriptor(&mut self, descriptor: &str) -> Result<(), SpecterError> {
        let descriptor = Descriptor::<DescriptorPublicKey>::from_str(descriptor)
            .map_err(|_| SpecterError::Descriptor)?;
        self.descriptor = Some(descriptor);
        Ok(())
    }
}

#[async_trait]
impl<T: Transport + Sync + Send> HWI for Specter<T> {
    fn device_kind(&self) -> DeviceKind {
        self.kind
    }

    async fn get_version(&self) -> Result<super::Version, HWIError> {
        Err(HWIError::UnimplementedMethod)
    }

    async fn get_master_fingerprint(&self) -> Result<Fingerprint, HWIError> {
        Ok(self.fingerprint().await?)
    }

    async fn get_extended_pubkey(&self, path: &DerivationPath) -> Result<Xpub, HWIError> {
        Ok(self.get_extended_pubkey(path).await?)
    }

    async fn display_address(&self, script: &AddressScript) -> Result<(), HWIError> {
        match script {
            AddressScript::P2TR(_derivation_path) => Err(HWIError::UnimplementedMethod),
            AddressScript::Miniscript { index, change } => {
                if let Some(descr) = &self.descriptor {
                    let is_mainnet = descr.for_each_key(|k| {
                        if let DescriptorPublicKey::MultiXPub(xpub) = k {
                            xpub.xkey.network == Network::Bitcoin.into()
                        } else {
                            false
                        }
                    });
                    let network = match is_mainnet {
                        true => Network::Bitcoin,
                        false => Network::Signet,
                    };
                    let key_chain = match change {
                        true => 1,
                        false => 0,
                    };
                    let addr = descr
                        .clone()
                        .into_single_descriptors()
                        .map_err(|_| HWIError::Descriptor)?
                        .get(key_chain)
                        .ok_or(HWIError::Descriptor)?
                        .at_derivation_index(*index)
                        .map_err(|_| HWIError::Descriptor)?
                        .address(network)
                        .map_err(|_| HWIError::Descriptor)?;
                    self.show_addr(addr, *index).await?;
                    Ok(())
                } else {
                    Err(HWIError::Descriptor)
                }
            }
        }
    }

    async fn register_wallet(
        &self,
        name: &str,
        policy: &str,
    ) -> Result<Option<[u8; 32]>, HWIError> {
        self.add_wallet(name, policy).await?;
        Ok(None)
    }

    async fn is_wallet_registered(&self, _name: &str, _policy: &str) -> Result<bool, HWIError> {
        Err(HWIError::UnimplementedMethod)
    }

    async fn sign_tx(&self, psbt: &mut Psbt) -> Result<(), HWIError> {
        let mut new_psbt = self.sign(psbt).await?;
        // Psbt returned by specter wallet has all unnecessary fields removed,
        // only global transaction and partial signatures for all inputs remain in it.
        // In order to have the full Psbt, the partial_sigs are extracted and appended
        // to the original psbt.
        let mut has_signed = false;
        for i in 0..new_psbt.inputs.len() {
            if !new_psbt.inputs[i].partial_sigs.is_empty() {
                has_signed = true;
                psbt.inputs[i]
                    .partial_sigs
                    .append(&mut new_psbt.inputs[i].partial_sigs)
            }
            if !new_psbt.inputs[i].tap_script_sigs.is_empty() {
                has_signed = true;
                psbt.inputs[i]
                    .tap_script_sigs
                    .append(&mut new_psbt.inputs[i].tap_script_sigs)
            }
            if new_psbt.inputs[i].tap_key_sig.is_some() {
                has_signed = true;
                psbt.inputs[i].tap_key_sig = new_psbt.inputs[i].tap_key_sig;
            } else {
                // Specter does not populate PSBT_TAP_KEY_SIG at v1.9.0
                // see https://github.com/cryptoadvance/specter-diy/issues/277#issuecomment-2183906271
                if let Some(witness) = &new_psbt.inputs[i].final_script_witness {
                    if let Some(sig) = witness.nth(0) {
                        if let Ok(sig) = taproot::Signature::from_slice(sig) {
                            psbt.inputs[i].tap_key_sig = Some(sig);
                            has_signed = true;
                        }
                    }
                }
            }
        }
        if !has_signed {
            return Err(SpecterError::DeviceDidNotSign.into());
        }

        Ok(())
    }
}

impl<T: 'static + Transport + Sync + Send> From<Specter<T>> for Box<dyn HWI + Send> {
    fn from(s: Specter<T>) -> Box<dyn HWI + Send> {
        Box::new(s)
    }
}

async fn exchange<T: Unpin + AsyncRead + AsyncWrite>(
    transport: &mut T,
    req: &str,
) -> Result<String, SpecterError> {
    transport
        .write_all(req.as_bytes())
        .await
        .map_err(|e| SpecterError::Device(e.to_string()))?;

    let reader = tokio::io::BufReader::new(transport);
    let mut lines = reader.lines();
    if let Some(line) = lines
        .next_line()
        .await
        .map_err(|e| SpecterError::Device(e.to_string()))?
    {
        if line != "ACK" {
            return Err(SpecterError::Device(
                "Received an incorrect answer".to_string(),
            ));
        }
    }

    if let Some(line) = lines
        .next_line()
        .await
        .map_err(|e| SpecterError::Device(e.to_string()))?
    {
        return Ok(line);
    }
    Err(SpecterError::Device("Unexpected".to_string()))
}

#[async_trait]
pub trait Transport: Debug {
    async fn request(&self, req: &str) -> Result<String, SpecterError>;
}

#[derive(Debug)]
pub struct TcpTransport;
pub const DEFAULT_ADDRESS: &str = "127.0.0.1:8789";

#[async_trait]
impl Transport for TcpTransport {
    async fn request(&self, req: &str) -> Result<String, SpecterError> {
        let mut transport = TcpStream::connect(DEFAULT_ADDRESS)
            .await
            .map_err(|e| SpecterError::Device(e.to_string()))?;
        let res = exchange(&mut transport, req).await;
        transport
            .shutdown()
            .await
            .map_err(|e| SpecterError::Device(e.to_string()))?;
        res
    }
}

pub type SpecterSimulator = Specter<TcpTransport>;

impl SpecterSimulator {
    pub async fn try_connect() -> Result<Self, HWIError> {
        let s = SpecterSimulator {
            transport: TcpTransport {},
            kind: DeviceKind::SpecterSimulator,
            descriptor: None,
        };
        let _ = s.get_master_fingerprint().await?;
        Ok(s)
    }
}

impl Specter<SerialTransport> {
    pub fn new(port_name: String) -> Result<Self, SpecterError> {
        let transport = SerialTransport::new(port_name)?;
        Ok(Self {
            transport,
            kind: DeviceKind::Specter,
            descriptor: None,
        })
    }

    pub fn new_with_descriptor(
        port_name: String,
        descriptor: String,
    ) -> Result<Self, SpecterError> {
        let mut specter = Self::new(port_name)?;
        specter.set_descriptor(&descriptor)?;
        Ok(specter)
    }

    pub async fn enumerate() -> Result<Vec<Self>, SpecterError> {
        let mut res = Vec::new();
        for port_name in SerialTransport::enumerate_potential_ports()? {
            let specter = Specter::<SerialTransport>::new(port_name)?;
            if specter.get_master_fingerprint().await.is_ok() {
                res.push(specter);
            }
        }
        Ok(res)
    }
}

#[derive(Debug)]
pub struct SerialTransport {
    stream: Arc<Mutex<SerialStream>>,
}

impl SerialTransport {
    pub const SPECTER_VID: u16 = 61525;
    pub const SPECTER_PID: u16 = 38914;

    pub fn new(port_name: String) -> Result<Self, SpecterError> {
        let mut stream = tokio_serial::new(port_name, 9600)
            .open_native_async()
            .map_err(|e| SpecterError::Device(e.to_string()))?;
        stream
            .write_data_terminal_ready(true)
            .map_err(|e| SpecterError::Device(e.to_string()))?;
        Ok(Self {
            stream: Arc::new(Mutex::new(stream)),
        })
    }

    pub fn enumerate_potential_ports() -> Result<Vec<String>, SpecterError> {
        match available_ports() {
            Ok(ports) => Ok(ports
                .into_iter()
                .filter_map(|p| match p.port_type {
                    SerialPortType::UsbPort(info) => {
                        if info.vid == SerialTransport::SPECTER_VID
                            && info.pid == SerialTransport::SPECTER_PID
                        {
                            Some(p.port_name)
                        } else {
                            None
                        }
                    }
                    _ => None,
                })
                .collect()),
            Err(e) => Err(SpecterError::Device(format!(
                "Error listing serial ports: {}",
                e
            ))),
        }
    }
}

async fn exchange_serial(transport: &mut SerialStream, req: &str) -> Result<String, SpecterError> {
    exchange(transport, req).await
}

#[async_trait]
impl Transport for SerialTransport {
    async fn request(&self, req: &str) -> Result<String, SpecterError> {
        let mut transport = self.stream.lock().await;
        exchange_serial(&mut transport, req).await
    }
}

#[derive(Debug)]
pub enum SpecterError {
    DeviceNotFound,
    DeviceDidNotSign,
    Device(String),
    UserCancelled,
    Descriptor,
}

impl std::fmt::Display for SpecterError {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            Self::DeviceNotFound => write!(f, "Specter not found"),
            Self::DeviceDidNotSign => write!(f, "Specter did not sign the psbt"),
            Self::Device(e) => write!(f, "Specter error: {}", e),
            Self::UserCancelled => write!(f, "User cancelled operation"),
            Self::Descriptor => write!(f, "Invalid descriptor"),
        }
    }
}

impl From<SpecterError> for HWIError {
    fn from(e: SpecterError) -> HWIError {
        match e {
            SpecterError::DeviceNotFound => HWIError::DeviceNotFound,
            SpecterError::DeviceDidNotSign => HWIError::DeviceDidNotSign,
            SpecterError::Device(e) => HWIError::Device(e),
            SpecterError::UserCancelled => HWIError::UserRefused,
            SpecterError::Descriptor => HWIError::Descriptor,
        }
    }
}
