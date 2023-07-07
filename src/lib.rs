#[cfg(feature = "bitbox")]
pub mod bitbox;
#[cfg(feature = "ledger")]
pub mod ledger;
#[cfg(feature = "specter")]
pub mod specter;
#[cfg(feature = "trezor")]
pub mod trezor;

use async_trait::async_trait;
use bitcoin::{
    bip32::{DerivationPath, ExtendedPubKey, Fingerprint},
    psbt::PartiallySignedTransaction as Psbt,
};

use std::fmt::Debug;

#[derive(Debug, Clone)]
pub enum Error {
    UnsupportedVersion,
    UnsupportedInput,
    InvalidParameter(&'static str, String),
    UnimplementedMethod,
    DeviceDisconnected,
    DeviceNotFound,
    DeviceDidNotSign,
    Device(String),
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            Error::UnsupportedVersion => write!(f, "Unsupported version"),
            Error::UnsupportedInput => write!(f, "Unsupported input"),
            Error::UnimplementedMethod => write!(f, "Unimplemented method"),
            Error::DeviceDisconnected => write!(f, "Device disconnected"),
            Error::DeviceNotFound => write!(f, "Device not found"),
            Error::DeviceDidNotSign => write!(f, "Device did not sign"),
            Error::Device(e) => write!(f, "{}", e),
            Error::InvalidParameter(param, e) => write!(f, "Invalid parameter {}: {}", param, e),
        }
    }
}

/// HWI is the common Hardware Wallet Interface.
#[async_trait]
pub trait HWI: Debug {
    /// Return the device kind
    fn device_kind(&self) -> DeviceKind;
    /// Application version or OS version.
    async fn get_version(&self) -> Result<Version, Error>;
    /// Check that the device is connected but not necessarily available.
    async fn is_connected(&self) -> Result<(), Error>;
    /// Get master fingerprint.
    async fn get_master_fingerprint(&self) -> Result<Fingerprint, Error>;
    /// Get the xpub with the given derivation path.
    async fn get_extended_pubkey(&self, path: &DerivationPath) -> Result<ExtendedPubKey, Error>;
    /// Register a new wallet policy
    async fn register_wallet(&self, name: &str, policy: &str) -> Result<Option<[u8; 32]>, Error>;
    /// Sign a partially signed bitcoin transaction (PSBT).
    async fn sign_tx(&self, tx: &mut Psbt) -> Result<(), Error>;
}

#[derive(PartialEq, Eq, Debug, Clone, Default)]
pub struct Version {
    pub major: u32,
    pub minor: u32,
    pub patch: u32,
    pub prerelease: Option<String>,
}

impl std::fmt::Display for Version {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        if let Some(prerelease) = &self.prerelease {
            write!(
                f,
                "{}.{}.{}-{}",
                self.major, self.minor, self.patch, prerelease
            )
        } else {
            write!(f, "{}.{}.{}", self.major, self.minor, self.patch)
        }
    }
}

/// DeviceType is the result of the following process:
/// If it is talking like a Duck© hardware wallet it is a Duck© hardware wallet.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DeviceKind {
    BitBox02,
    Specter,
    SpecterSimulator,
    Ledger,
    LedgerSimulator,
    Trezor,
    TrezorSimulator,
}

impl std::fmt::Display for DeviceKind {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            DeviceKind::BitBox02 => write!(f, "bitbox02"),
            DeviceKind::Specter => write!(f, "specter"),
            DeviceKind::SpecterSimulator => write!(f, "specter-simulator"),
            DeviceKind::Ledger => write!(f, "ledger"),
            DeviceKind::LedgerSimulator => write!(f, "ledger-simulator"),
            DeviceKind::Trezor => write!(f, "trezor"),
            DeviceKind::TrezorSimulator => write!(f, "trezor-simulator"),
        }
    }
}

impl std::str::FromStr for DeviceKind {
    type Err = ();

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "bitbox02" => Ok(DeviceKind::BitBox02),
            "specter" => Ok(DeviceKind::Specter),
            "specter-simulator" => Ok(DeviceKind::SpecterSimulator),
            "ledger" => Ok(DeviceKind::Ledger),
            "ledger-simulator" => Ok(DeviceKind::LedgerSimulator),
            "trezor" => Ok(DeviceKind::Trezor),
            "trezor-simulator" => Ok(DeviceKind::TrezorSimulator),
            _ => Err(()),
        }
    }
}
