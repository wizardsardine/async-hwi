pub mod bip389;
#[cfg(feature = "bitbox")]
pub mod bitbox;
#[cfg(feature = "coldcard")]
pub mod coldcard;
#[cfg(feature = "ledger")]
pub mod ledger;
#[cfg(feature = "specter")]
pub mod specter;
pub mod utils;

use async_trait::async_trait;
use bitcoin::{
    bip32::{DerivationPath, Fingerprint, Xpub},
    psbt::Psbt,
};

use std::{fmt::Debug, str::FromStr};

#[derive(Debug, Clone)]
pub enum Error {
    ParsingPolicy(bip389::ParseError),
    MissingPolicy,
    UnsupportedVersion,
    UnsupportedInput,
    InvalidParameter(&'static str, String),
    UnimplementedMethod,
    DeviceDisconnected,
    DeviceNotFound,
    DeviceDidNotSign,
    Device(String),
    Unexpected(&'static str),
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            Error::ParsingPolicy(e) => write!(f, "{}", e),
            Error::MissingPolicy => write!(f, "Missing policy"),
            Error::UnsupportedVersion => write!(f, "Unsupported version"),
            Error::UnsupportedInput => write!(f, "Unsupported input"),
            Error::UnimplementedMethod => write!(f, "Unimplemented method"),
            Error::DeviceDisconnected => write!(f, "Device disconnected"),
            Error::DeviceNotFound => write!(f, "Device not found"),
            Error::DeviceDidNotSign => write!(f, "Device did not sign"),
            Error::Device(e) => write!(f, "{}", e),
            Error::InvalidParameter(param, e) => write!(f, "Invalid parameter {}: {}", param, e),
            Error::Unexpected(e) => write!(f, "{}", e),
        }
    }
}

impl From<bip389::ParseError> for Error {
    fn from(value: bip389::ParseError) -> Self {
        Error::ParsingPolicy(value)
    }
}

impl std::error::Error for Error {}

/// HWI is the common Hardware Wallet Interface.
#[async_trait]
pub trait HWI: Debug {
    /// Return the device kind
    fn device_kind(&self) -> DeviceKind;
    /// Application version or OS version.
    async fn get_version(&self) -> Result<Version, Error>;
    /// Get master fingerprint.
    async fn get_master_fingerprint(&self) -> Result<Fingerprint, Error>;
    /// Get the xpub with the given derivation path.
    async fn get_extended_pubkey(&self, path: &DerivationPath) -> Result<Xpub, Error>;
    /// Register a new wallet policy.
    async fn register_wallet(&self, name: &str, policy: &str) -> Result<Option<[u8; 32]>, Error>;
    /// Returns true if the wallet is registered on the device.
    async fn is_wallet_registered(&self, name: &str, policy: &str) -> Result<bool, Error>;
    /// Display address on the device screen.
    async fn display_address(&self, script: &AddressScript) -> Result<(), Error>;
    /// Sign a partially signed bitcoin transaction (PSBT).
    async fn sign_tx(&self, tx: &mut Psbt) -> Result<(), Error>;
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AddressScript {
    /// Must be a bip86 path.
    P2TR(DerivationPath),
    /// Miniscript requires the policy be loaded into the device.
    Miniscript { index: u32, change: bool },
}

#[derive(PartialEq, Eq, Debug, Clone, Default)]
pub struct Version {
    pub major: u32,
    pub minor: u32,
    pub patch: u32,
    pub prerelease: Option<String>,
}

#[cfg(feature = "regex")]
pub fn parse_version(s: &str) -> Result<Version, Error> {
    // Regex from https://semver.org/ with patch group marked as optional
    let re = regex::Regex::new(r"^(0|[1-9]\d*)\.(0|[1-9]\d*)(?:\.(0|[1-9]\d*))?(?:-((?:0|[1-9]\d*|\d*[a-zA-Z-][0-9a-zA-Z-]*)(?:\.(?:0|[1-9]\d*|\d*[a-zA-Z-][0-9a-zA-Z-]*))*))?(?:\+([0-9a-zA-Z-]+(?:\.[0-9a-zA-Z-]+)*))?$").unwrap();
    if let Some(captures) = re.captures(s.trim_start_matches('v').trim_end_matches('X')) {
        let major = if let Some(s) = captures.get(1) {
            u32::from_str(s.as_str()).map_err(|_| Error::UnsupportedVersion)?
        } else {
            0
        };
        let minor = if let Some(s) = captures.get(2) {
            u32::from_str(s.as_str()).map_err(|_| Error::UnsupportedVersion)?
        } else {
            0
        };
        let patch = if let Some(s) = captures.get(3) {
            u32::from_str(s.as_str()).map_err(|_| Error::UnsupportedVersion)?
        } else {
            0
        };
        Ok(Version {
            major,
            minor,
            patch,
            prerelease: captures.get(4).map(|s| s.as_str().to_string()),
        })
    } else {
        Err(Error::UnsupportedVersion)
    }
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
    Coldcard,
    Specter,
    SpecterSimulator,
    Ledger,
    LedgerSimulator,
}

impl std::fmt::Display for DeviceKind {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            DeviceKind::BitBox02 => write!(f, "bitbox02"),
            DeviceKind::Coldcard => write!(f, "coldcard"),
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
            "bitbox02" => Ok(DeviceKind::BitBox02),
            "specter" => Ok(DeviceKind::Specter),
            "specter-simulator" => Ok(DeviceKind::SpecterSimulator),
            "ledger" => Ok(DeviceKind::Ledger),
            "ledger-simulator" => Ok(DeviceKind::LedgerSimulator),
            _ => Err(()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(feature = "regex")]
    #[test]
    fn test_parse_version() {
        let test_cases = [
            (
                "v2.1.0",
                Version {
                    major: 2,
                    minor: 1,
                    patch: 0,
                    prerelease: None,
                },
            ),
            (
                "v1.0",
                Version {
                    major: 1,
                    minor: 0,
                    patch: 0,
                    prerelease: None,
                },
            ),
            (
                "3.0-rc2",
                Version {
                    major: 3,
                    minor: 0,
                    patch: 0,
                    prerelease: Some("rc2".to_string()),
                },
            ),
            (
                "0.1.0-ALPHA",
                Version {
                    major: 0,
                    minor: 1,
                    patch: 0,
                    prerelease: Some("ALPHA".to_string()),
                },
            ),
            (
                "6.2.1X",
                Version {
                    major: 6,
                    minor: 2,
                    patch: 1,
                    prerelease: None,
                },
            ),
        ];
        for (s, v) in test_cases {
            assert_eq!(v, parse_version(s).unwrap());
        }
    }
}
