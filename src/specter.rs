use std::str::FromStr;

use bitcoin::{
    base64,
    consensus::encode,
    util::bip32::{DerivationPath, ExtendedPubKey},
    util::psbt::PartiallySignedTransaction as Psbt,
};

use serialport::{available_ports, SerialPortType};
use tokio::io::AsyncBufReadExt;
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt};
pub use tokio::net::TcpStream;
use tokio_serial::SerialPortBuilderExt;
pub use tokio_serial::SerialStream;

use super::{DeviceType, Error as HWIError, HWI};
use async_trait::async_trait;

#[derive(Debug)]
pub struct Specter<T> {
    transport: T,
}

impl<T: Unpin + AsyncWrite + AsyncRead> Specter<T> {
    pub async fn fingerprint(&mut self) -> Result<String, SpecterError> {
        self.request("\r\n\r\nfingerprint\r\n").await
    }

    pub async fn get_extended_pubkey(
        &mut self,
        path: &DerivationPath,
    ) -> Result<ExtendedPubKey, SpecterError> {
        self.request(&format!("\r\n\r\nxpub {}\r\n", path))
            .await
            .and_then(|resp| {
                ExtendedPubKey::from_str(&resp).map_err(|e| SpecterError::Device(e.to_string()))
            })
    }

    pub async fn sign(&mut self, psbt: &Psbt) -> Result<Psbt, SpecterError> {
        self.request(&format!(
            "\r\n\r\nsign {}\r\n",
            base64::encode(&encode::serialize(&psbt))
        ))
        .await
        .and_then(|resp| base64::decode(&resp).map_err(|e| SpecterError::Device(e.to_string())))
        .and_then(|bytes| {
            encode::deserialize(&bytes).map_err(|e| SpecterError::Device(e.to_string()))
        })
    }

    async fn request(&mut self, req: &str) -> Result<String, SpecterError> {
        self.transport
            .write_all(req.as_bytes())
            .await
            .map_err(|e| SpecterError::Device(e.to_string()))?;

        let reader = tokio::io::BufReader::new(&mut self.transport);
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
}

pub type SpecterSimulator = Specter<TcpStream>;

impl SpecterSimulator {
    pub const DEFAULT_ADDRESS: &'static str = "127.0.0.1:8789";

    pub async fn try_connect() -> Result<Self, SpecterError> {
        let transport = TcpStream::connect(Self::DEFAULT_ADDRESS)
            .await
            .map_err(|e| SpecterError::Device(e.to_string()))?;
        Ok(Specter { transport })
    }
}

#[async_trait]
impl HWI for Specter<TcpStream> {
    fn device_type(&self) -> DeviceType {
        DeviceType::SpecterSimulator
    }

    async fn is_connected(&mut self) -> Result<(), HWIError> {
        self.fingerprint().await?;
        Ok(())
    }

    async fn get_extended_pubkey(
        &mut self,
        path: &DerivationPath,
    ) -> Result<ExtendedPubKey, HWIError> {
        Ok(self.get_extended_pubkey(path).await?)
    }

    async fn sign_tx(&mut self, psbt: &mut Psbt) -> Result<(), HWIError> {
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

impl From<Specter<TcpStream>> for Box<dyn HWI + Send> {
    fn from(s: Specter<TcpStream>) -> Box<dyn HWI + Send> {
        Box::new(s)
    }
}

const SPECTER_VID: u16 = 61525;
const SPECTER_PID: u16 = 38914;

impl Specter<SerialStream> {
    pub fn get_serial_port() -> Result<String, SpecterError> {
        match available_ports() {
            Ok(ports) => ports
                .iter()
                .find_map(|p| {
                    if let SerialPortType::UsbPort(info) = &p.port_type {
                        if info.vid == SPECTER_VID && info.pid == SPECTER_PID {
                            Some(p.port_name.clone())
                        } else {
                            None
                        }
                    } else {
                        None
                    }
                })
                .ok_or(SpecterError::DeviceNotFound),
            Err(e) => Err(SpecterError::Device(format!(
                "Error listing serial ports: {}",
                e
            ))),
        }
    }
    pub fn try_connect_serial() -> Result<Self, SpecterError> {
        let tty = Self::get_serial_port()?;
        let transport = tokio_serial::new(tty, 9600)
            .open_native_async()
            .map_err(|e| SpecterError::Device(e.to_string()))?;
        Ok(Specter { transport })
    }
}

#[async_trait]
impl HWI for Specter<SerialStream> {
    fn device_type(&self) -> DeviceType {
        DeviceType::Specter
    }

    async fn is_connected(&mut self) -> Result<(), HWIError> {
        Self::get_serial_port()?;
        Ok(())
    }

    async fn get_extended_pubkey(
        &mut self,
        path: &DerivationPath,
    ) -> Result<ExtendedPubKey, HWIError> {
        Ok(self.get_extended_pubkey(path).await?)
    }

    async fn sign_tx(&mut self, psbt: &mut Psbt) -> Result<(), HWIError> {
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

impl From<Specter<SerialStream>> for Box<dyn HWI + Send> {
    fn from(s: Specter<SerialStream>) -> Box<dyn HWI + Send> {
        Box::new(s)
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
