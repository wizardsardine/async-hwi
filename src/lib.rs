#[cfg(feature = "ledger")]
pub mod ledger;
#[cfg(feature = "specter")]
pub mod specter;

use async_trait::async_trait;
use bitcoin::util::{
    bip32::{DerivationPath, ExtendedPubKey, Fingerprint},
    psbt::PartiallySignedTransaction as Psbt,
};

use std::fmt::Debug;
use std::str::FromStr;

#[derive(Debug, Clone)]
pub enum Error {
    UnsupportedVersion,
    UnsupportedInput,
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
    async fn get_extended_pubkey(
        &self,
        path: &DerivationPath,
        display: bool,
    ) -> Result<ExtendedPubKey, Error>;
    /// Register a new wallet policy
    async fn register_wallet(&self, name: &str, policy: &str) -> Result<Option<[u8; 32]>, Error>;
    /// Sign a partially signed bitcoin transaction (PSBT).
    async fn sign_tx(&self, tx: &mut Psbt) -> Result<(), Error>;
}

#[derive(Debug, Clone)]
pub struct Version {
    pub major: u32,
    pub minor: u32,
    pub patch: u32,
}

impl std::fmt::Display for Version {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "{}.{}.{}", self.major, self.minor, self.patch)
    }
}

impl FromStr for Version {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let numbers: Vec<&str> = s.trim_matches('v').split('.').collect();
        let (major, minor, patch) = if numbers.len() == 3 {
            (numbers[0], numbers[1], numbers[2])
        } else if numbers.len() == 2 {
            (numbers[0], numbers[1], "0")
        } else {
            return Err(Error::UnsupportedVersion);
        };

        Ok(Version {
            major: u32::from_str(major).map_err(|_| Error::UnsupportedVersion)?,
            minor: u32::from_str(minor).map_err(|_| Error::UnsupportedVersion)?,
            patch: u32::from_str(patch).map_err(|_| Error::UnsupportedVersion)?,
        })
    }
}

/// DeviceType is the result of the following process:
/// If it is talking like a Duck© hardware wallet it is a Duck© hardware wallet.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DeviceKind {
    Specter,
    SpecterSimulator,
    Ledger,
    LedgerSimulator,
}

impl std::fmt::Display for DeviceKind {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            DeviceKind::Specter => write!(f, "specter"),
            DeviceKind::SpecterSimulator => write!(f, "specter-simulator"),
            DeviceKind::Ledger => write!(f, "ledger"),
            DeviceKind::LedgerSimulator => write!(f, "ledger-simulator"),
        }
    }
}

impl std::str::FromStr for DeviceKind {
    type Err = ();

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "specter" => Ok(DeviceKind::Specter),
            "specter-simulator" => Ok(DeviceKind::SpecterSimulator),
            "ledger" => Ok(DeviceKind::Ledger),
            "ledger-simulator" => Ok(DeviceKind::LedgerSimulator),
            _ => Err(()),
        }
    }
}
