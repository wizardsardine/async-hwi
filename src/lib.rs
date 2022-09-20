#[cfg(feature = "specter")]
pub mod specter;

use async_trait::async_trait;
use bitcoin::util::psbt::PartiallySignedTransaction as Psbt;
use std::fmt::Debug;

#[derive(Debug, Clone)]
pub enum Error {
    UnimplementedMethod,
    DeviceDisconnected,
    DeviceNotFound,
    DeviceDidNotSign,
    Device(String),
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            Error::UnimplementedMethod => write!(f, "Unimplemented method"),
            Error::DeviceDisconnected => write!(f, "Device disconnected"),
            Error::DeviceNotFound => write!(f, "Device not found"),
            Error::DeviceDidNotSign => write!(f, "Device did not sign"),
            Error::Device(e) => write!(f, "{}", e),
        }
    }
}

/// HWI is the common Hardware Wallet Interface.
#[async_trait]
pub trait HWI: Debug {
    fn device_type(&self) -> DeviceType;
    /// Check that the device is connected but not necessarily available.
    async fn is_connected(&mut self) -> Result<(), Error>;
    /// Sign a partially signed bitcoin transaction (PSBT).
    async fn sign_tx(&mut self, tx: &Psbt) -> Result<Psbt, Error>;
}

/// DeviceType is the result of the following process:
/// If it is talking like a Duck© hardware wallet it is a Duck© hardware wallet.
pub enum DeviceType {
    Specter,
    SpecterSimulator,
}

impl std::fmt::Display for DeviceType {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            DeviceType::Specter => write!(f, "specter"),
            DeviceType::SpecterSimulator => write!(f, "specter-simulator"),
        }
    }
}
