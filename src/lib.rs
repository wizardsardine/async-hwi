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
    type Error: Into<Error> + Debug;
    /// Check that the device is connected but not necessarily available.
    async fn is_connected(&mut self) -> Result<(), Self::Error>;
    /// Sign a partially signed bitcoin transaction (PSBT).
    async fn sign_tx(&mut self, tx: &Psbt) -> Result<Psbt, Self::Error>;
}
