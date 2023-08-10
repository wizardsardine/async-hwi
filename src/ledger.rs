use std::convert::TryFrom;
use std::default::Default;
use std::error::Error;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::str::FromStr;

use async_trait::async_trait;
use bitcoin::{
    bip32::{DerivationPath, ExtendedPubKey, Fingerprint},
    psbt::Psbt,
};
use ledger_bitcoin_client::psbt::PartialSignature;
use regex::Regex;

use ledger_apdu::APDUAnswer;
use ledger_transport_hid::TransportNativeHID;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpStream,
    sync::Mutex,
};

use ledger_bitcoin_client::{
    apdu::{APDUCommand, StatusWord},
    async_client::BitcoinClient,
    error::BitcoinClientError,
    wallet::Version as WalletVersion,
    WalletPolicy, WalletPubKey,
};

use super::{DeviceKind, Error as HWIError, Version, HWI};

pub use hidapi::{DeviceInfo, HidApi};
pub use ledger_bitcoin_client::async_client::Transport;

#[derive(Default)]
struct CommandOptions {
    wallet: Option<(WalletPolicy, Option<[u8; 32]>)>,
    display_xpub: bool,
}

pub struct Ledger<T: Transport> {
    client: BitcoinClient<T>,
    options: CommandOptions,
    kind: DeviceKind,
}

impl<T: Transport> Ledger<T> {
    pub fn display_xpub(mut self, display: bool) -> Result<Self, HWIError> {
        self.options.display_xpub = display;
        Ok(self)
    }

    pub fn with_wallet(
        mut self,
        name: impl Into<String>,
        policy: &str,
        hmac: Option<[u8; 32]>,
    ) -> Result<Self, HWIError> {
        let (descriptor_template, keys) = extract_keys_and_template(policy)?;
        let wallet = WalletPolicy::new(name.into(), WalletVersion::V2, descriptor_template, keys);
        self.options.wallet = Some((wallet, hmac));
        Ok(self)
    }
}

/// TODO: remove
impl<T: Transport> std::fmt::Debug for Ledger<T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Ledger").finish()
    }
}

impl<T: 'static + Transport + Sync + Send> From<Ledger<T>> for Box<dyn HWI + Send> {
    fn from(s: Ledger<T>) -> Box<dyn HWI + Send> {
        Box::new(s)
    }
}

#[async_trait]
impl<T: Transport + Sync + Send> HWI for Ledger<T> {
    fn device_kind(&self) -> DeviceKind {
        self.kind
    }

    async fn get_version(&self) -> Result<super::Version, HWIError> {
        let (_, version, _) = self.client.get_version().await?;
        Ok(extract_version(&version)?)
    }

    async fn is_connected(&self) -> Result<(), HWIError> {
        self.client.get_master_fingerprint().await?;
        Ok(())
    }

    async fn get_master_fingerprint(&self) -> Result<Fingerprint, HWIError> {
        Ok(self.client.get_master_fingerprint().await?)
    }

    async fn get_extended_pubkey(&self, path: &DerivationPath) -> Result<ExtendedPubKey, HWIError> {
        Ok(self
            .client
            .get_extended_pubkey(path, self.options.display_xpub)
            .await?)
    }

    async fn register_wallet(
        &self,
        name: &str,
        policy: &str,
    ) -> Result<Option<[u8; 32]>, HWIError> {
        let (descriptor_template, keys) = extract_keys_and_template(policy)?;
        let wallet = WalletPolicy::new(
            name.to_string(),
            WalletVersion::V2,
            descriptor_template,
            keys,
        );
        let (_id, hmac) = self.client.register_wallet(&wallet).await?;
        Ok(Some(hmac))
    }

    async fn sign_tx(&self, psbt: &mut Psbt) -> Result<(), HWIError> {
        if let Some((policy, hmac)) = &self.options.wallet {
            let sigs = self.client.sign_psbt(psbt, policy, hmac.as_ref()).await?;
            for (i, sig) in sigs {
                let input = psbt.inputs.get_mut(i).ok_or(HWIError::DeviceDidNotSign)?;
                match sig {
                    PartialSignature::Sig(key, sig) => {
                        input.partial_sigs.insert(key, sig);
                    }
                    PartialSignature::TapScriptSig(key, Some(tapleaf_hash), sig) => {
                        input.tap_script_sigs.insert((key, tapleaf_hash), sig);
                    }
                    PartialSignature::TapScriptSig(_, None, sig) => {
                        input.tap_key_sig = Some(sig);
                    }
                }
            }
            Ok(())
        } else {
            // Ledger cannot sign without policy.
            Err(HWIError::UnimplementedMethod)
        }
    }
}

pub fn extract_keys_and_template(policy: &str) -> Result<(String, Vec<WalletPubKey>), HWIError> {
    let re = Regex::new(r"((\[.+?\])?[xyYzZtuUvV]pub[1-9A-HJ-NP-Za-km-z]{79,108})").unwrap();
    let mut descriptor_template = policy.to_string();
    let mut pubkeys: Vec<WalletPubKey> = Vec::new();
    for (index, capture) in re.find_iter(policy).enumerate() {
        let pubkey =
            WalletPubKey::from_str(capture.as_str()).map_err(|_| HWIError::UnsupportedInput)?;
        if !pubkeys.contains(&pubkey) {
            pubkeys.push(pubkey);
        }
        descriptor_template = descriptor_template.replace(capture.as_str(), &format!("@{}", index));
    }

    // Do not include the hash in the descriptor template.
    if let Some((descriptor_template, _hash)) = descriptor_template.rsplit_once('#') {
        Ok((descriptor_template.to_string(), pubkeys))
    } else {
        Ok((descriptor_template, pubkeys))
    }
}

pub fn extract_version(s: &str) -> Result<Version, HWIError> {
    // Regex from https://semver.org/ with patch group marked as optional
    let re = Regex::new(r"^(0|[1-9]\d*)\.(0|[1-9]\d*)(?:\.(0|[1-9]\d*))?(?:-((?:0|[1-9]\d*|\d*[a-zA-Z-][0-9a-zA-Z-]*)(?:\.(?:0|[1-9]\d*|\d*[a-zA-Z-][0-9a-zA-Z-]*))*))?(?:\+([0-9a-zA-Z-]+(?:\.[0-9a-zA-Z-]+)*))?$").unwrap();
    if let Some(captures) = re.captures(s.trim_start_matches('v')) {
        let major = if let Some(s) = captures.get(1) {
            u32::from_str(s.as_str()).map_err(|_| HWIError::UnsupportedVersion)?
        } else {
            0
        };
        let minor = if let Some(s) = captures.get(2) {
            u32::from_str(s.as_str()).map_err(|_| HWIError::UnsupportedVersion)?
        } else {
            0
        };
        let patch = if let Some(s) = captures.get(3) {
            u32::from_str(s.as_str()).map_err(|_| HWIError::UnsupportedVersion)?
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
        Err(HWIError::UnsupportedVersion)
    }
}

impl Ledger<TransportHID> {
    pub fn enumerate(api: &HidApi) -> impl Iterator<Item = &DeviceInfo> {
        TransportNativeHID::list_ledgers(api)
    }

    pub fn connect(api: &HidApi, device: &DeviceInfo) -> Result<Self, HWIError> {
        let hid =
            TransportNativeHID::open_device(api, device).map_err(|_| HWIError::DeviceNotFound)?;
        Ok(Ledger {
            client: BitcoinClient::new(TransportHID(hid)),
            options: CommandOptions::default(),
            kind: DeviceKind::Ledger,
        })
    }

    pub fn try_connect_hid() -> Result<Self, HWIError> {
        let hid = TransportNativeHID::new(&HidApi::new().map_err(|_| HWIError::DeviceNotFound)?)
            .map_err(|_| HWIError::DeviceNotFound)?;
        Ok(Ledger {
            client: BitcoinClient::new(TransportHID(hid)),
            options: CommandOptions::default(),
            kind: DeviceKind::Ledger,
        })
    }
}

/// Transport with the Ledger device.
pub struct TransportHID(TransportNativeHID);

#[async_trait]
impl Transport for TransportHID {
    type Error = Box<dyn Error>;
    async fn exchange(&self, cmd: &APDUCommand) -> Result<(StatusWord, Vec<u8>), Self::Error> {
        self.0
            .exchange(&ledger_apdu::APDUCommand {
                ins: cmd.ins,
                cla: cmd.cla,
                p1: cmd.p1,
                p2: cmd.p2,
                data: cmd.data.clone(),
            })
            .map(|answer| {
                (
                    StatusWord::try_from(answer.retcode()).unwrap_or(StatusWord::Unknown),
                    answer.data().to_vec(),
                )
            })
            .map_err(|e| e.into())
    }
}

pub type LedgerSimulator = Ledger<TransportTcp>;

impl LedgerSimulator {
    pub async fn try_connect() -> Result<Self, HWIError> {
        let transport = TransportTcp::new()
            .await
            .map_err(|_| HWIError::DeviceNotFound)?;
        Ok(Ledger {
            client: BitcoinClient::new(transport),
            options: CommandOptions::default(),
            kind: DeviceKind::LedgerSimulator,
        })
    }
}

/// Transport to communicate with the Ledger Speculos simulator.
pub struct TransportTcp {
    connection: Mutex<TcpStream>,
}

impl TransportTcp {
    pub async fn new() -> Result<Self, Box<dyn Error>> {
        let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 9999);
        let stream = TcpStream::connect(addr).await?;
        Ok(Self {
            connection: Mutex::new(stream),
        })
    }
}

#[async_trait]
impl Transport for TransportTcp {
    type Error = Box<dyn Error>;
    async fn exchange(&self, command: &APDUCommand) -> Result<(StatusWord, Vec<u8>), Self::Error> {
        let mut stream = self.connection.lock().await;
        let command_bytes = command.encode();

        let mut req = vec![0u8; command_bytes.len() + 4];
        req[..4].copy_from_slice(&(command_bytes.len() as u32).to_be_bytes());
        req[4..].copy_from_slice(&command_bytes);
        stream.write_all(&req).await?;

        let mut buff = [0u8; 4];
        let len = match stream.read(&mut buff).await? {
            4 => u32::from_be_bytes(buff),
            _ => return Err("Invalid Length".into()),
        };

        let mut resp = vec![0u8; len as usize + 2];
        stream.read_exact(&mut resp).await?;
        let answer = APDUAnswer::from_answer(resp).map_err(|_| "Invalid Answer")?;
        Ok((
            StatusWord::try_from(answer.retcode()).unwrap_or(StatusWord::Unknown),
            answer.data().to_vec(),
        ))
    }
}

impl<T: core::fmt::Debug> From<BitcoinClientError<T>> for HWIError {
    fn from(e: BitcoinClientError<T>) -> HWIError {
        HWIError::Device(format!("{:#?}", e))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_extract_keys_and_template() {
        let res = extract_keys_and_template("wsh(or_d(pk([f5acc2fd/49'/1'/0']tpubDCbK3Ysvk8HjcF6mPyrgMu3KgLiaaP19RjKpNezd8GrbAbNg6v5BtWLaCt8FNm6QkLseopKLf5MNYQFtochDTKHdfgG6iqJ8cqnLNAwtXuP/**),and_v(v:pkh(tpubDDtb2WPYwEWw2WWDV7reLV348iJHw2HmhzvPysKKrJw3hYmvrd4jasyoioVPdKGQqjyaBMEvTn1HvHWDSVqQ6amyyxRZ5YjpPBBGjJ8yu8S/**),older(100))))").unwrap();
        assert_eq!(res.0, "wsh(or_d(pk(@0/**),and_v(v:pkh(@1/**),older(100))))");
        assert_eq!(res.1.len(), 2);
        assert_eq!(res.1[0].to_string(), "[f5acc2fd/49'/1'/0']tpubDCbK3Ysvk8HjcF6mPyrgMu3KgLiaaP19RjKpNezd8GrbAbNg6v5BtWLaCt8FNm6QkLseopKLf5MNYQFtochDTKHdfgG6iqJ8cqnLNAwtXuP".to_string());
        assert_eq!(res.1[1].to_string(), "tpubDDtb2WPYwEWw2WWDV7reLV348iJHw2HmhzvPysKKrJw3hYmvrd4jasyoioVPdKGQqjyaBMEvTn1HvHWDSVqQ6amyyxRZ5YjpPBBGjJ8yu8S".to_string());
    }
    #[test]
    fn test_extract_version() {
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
        ];
        for (s, v) in test_cases {
            assert_eq!(v, extract_version(s).unwrap());
        }
    }
}
