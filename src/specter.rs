use std::fmt::Debug;
use std::str::FromStr;

use bitcoin::{
    bip32::{DerivationPath, ExtendedPubKey, Fingerprint},
    psbt::PartiallySignedTransaction as Psbt,
};

use serialport::{available_ports, SerialPortType};
use tokio::io::AsyncBufReadExt;
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt};
pub use tokio::net::TcpStream;
use tokio_serial::SerialPortBuilderExt;
pub use tokio_serial::SerialStream;

use super::{DeviceKind, Error as HWIError, HWI};
use async_trait::async_trait;

#[derive(Debug)]
pub struct Specter<T> {
    transport: T,
    kind: DeviceKind,
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

    pub async fn get_extended_pubkey(
        &self,
        path: &DerivationPath,
    ) -> Result<ExtendedPubKey, SpecterError> {
        self.transport
            .request(&format!("\r\n\r\nxpub {}\r\n", path))
            .await
            .and_then(|resp| {
                ExtendedPubKey::from_str(&resp).map_err(|e| SpecterError::Device(e.to_string()))
            })
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
            .await?;
        Ok(())
    }

    pub async fn sign(&self, psbt: &Psbt) -> Result<Psbt, SpecterError> {
        self.transport
            .request(&format!(
                "\r\n\r\nsign {}\r\n",
                base64::encode(psbt.serialize())
            ))
            .await
            .and_then(|resp| base64::decode(resp).map_err(|e| SpecterError::Device(e.to_string())))
            .and_then(|bytes| {
                Psbt::deserialize(&bytes).map_err(|e| SpecterError::Device(e.to_string()))
            })
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

    async fn is_connected(&self) -> Result<(), HWIError> {
        if let Err(e) =
            tokio::time::timeout(std::time::Duration::from_millis(500), self.fingerprint())
                .await
                .map_err(|_| HWIError::DeviceNotFound)?
        {
            Err(HWIError::from(e))
        } else {
            Ok(())
        }
    }

    async fn get_master_fingerprint(&self) -> Result<Fingerprint, HWIError> {
        Ok(self.fingerprint().await?)
    }

    async fn get_extended_pubkey(&self, path: &DerivationPath) -> Result<ExtendedPubKey, HWIError> {
        Ok(self.get_extended_pubkey(path).await?)
    }

    async fn register_wallet(
        &self,
        name: &str,
        policy: &str,
    ) -> Result<Option<[u8; 32]>, HWIError> {
        self.add_wallet(name, policy).await?;
        Ok(None)
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
        };
        s.is_connected().await?;
        Ok(s)
    }
}

impl Specter<SerialTransport> {
    pub async fn enumerate() -> Result<Vec<Self>, SpecterError> {
        let mut res = Vec::new();
        for port_name in SerialTransport::enumerate_potential_ports()? {
            let transport = SerialTransport { port_name };
            let specter = Specter {
                transport,
                kind: DeviceKind::Specter,
            };
            if specter.is_connected().await.is_ok() {
                res.push(specter);
            }
        }
        Ok(res)
    }
}

#[derive(Debug)]
pub struct SerialTransport {
    port_name: String,
}

impl SerialTransport {
    pub const SPECTER_VID: u16 = 61525;
    pub const SPECTER_PID: u16 = 38914;

    pub fn enumerate_potential_ports() -> Result<Vec<String>, SpecterError> {
        match available_ports() {
            Ok(ports) => Ok(ports
                .into_iter()
                .filter_map(|p| match p.port_type {
                    SerialPortType::PciPort => Some(p.port_name),
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

#[async_trait]
impl Transport for SerialTransport {
    async fn request(&self, req: &str) -> Result<String, SpecterError> {
        let mut transport = tokio_serial::new(self.port_name.clone(), 9600)
            .open_native_async()
            .map_err(|e| SpecterError::Device(e.to_string()))?;
        exchange(&mut transport, req).await
    }
}

#[derive(Debug)]
pub enum SpecterError {
    DeviceNotFound,
    DeviceDidNotSign,
    Device(String),
}

impl std::fmt::Display for SpecterError {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            Self::DeviceNotFound => write!(f, "Specter not found"),
            Self::DeviceDidNotSign => write!(f, "Specter did not sign the psbt"),
            Self::Device(e) => write!(f, "Specter error: {}", e),
        }
    }
}

impl From<SpecterError> for HWIError {
    fn from(e: SpecterError) -> HWIError {
        match e {
            SpecterError::DeviceNotFound => HWIError::DeviceNotFound,
            SpecterError::DeviceDidNotSign => HWIError::DeviceDidNotSign,
            SpecterError::Device(e) => HWIError::Device(e),
        }
    }
}
