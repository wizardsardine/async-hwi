use std::convert::TryFrom;
use std::error::Error;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::str::FromStr;

use async_trait::async_trait;
use bitcoin::util::{
    bip32::{DerivationPath, ExtendedPubKey, Fingerprint},
    psbt::Psbt,
};
use regex::Regex;

use hidapi::HidApi;
use ledger_apdu::APDUAnswer;
use ledger_transport_hid::TransportNativeHID;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpStream,
    sync::Mutex,
};

use ledger_bitcoin_client::{
    apdu::{APDUCommand, StatusWord},
    async_client::{BitcoinClient, Transport},
    error::BitcoinClientError,
    wallet::Version,
    WalletPolicy, WalletPubKey,
};

use super::{DeviceKind, Error as HWIError, HWI};

pub struct Ledger<T: Transport> {
    client: BitcoinClient<T>,
    wallet: Option<(WalletPolicy, Option<[u8; 32]>)>,
    kind: DeviceKind,
}

impl<T: Transport> Ledger<T> {
    pub fn load_wallet(
        &mut self,
        name: impl Into<String>,
        policy: &str,
        hmac: Option<[u8; 32]>,
    ) -> Result<(), HWIError> {
        let (descriptor_template, keys) = extract_keys_and_template(policy)?;
        let wallet = WalletPolicy::new(name.into(), Version::V2, descriptor_template, keys);
        self.wallet = Some((wallet, hmac));
        Ok(())
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
        Ok(super::Version::from_str(&version)?)
    }

    async fn is_connected(&self) -> Result<(), HWIError> {
        self.client.get_master_fingerprint().await?;
        Ok(())
    }

    async fn get_master_fingerprint(&self) -> Result<Fingerprint, HWIError> {
        Ok(self.client.get_master_fingerprint().await?)
    }

    async fn get_extended_pubkey(
        &self,
        path: &DerivationPath,
        display: bool,
    ) -> Result<ExtendedPubKey, HWIError> {
        Ok(self.client.get_extended_pubkey(path, display).await?)
    }

    async fn register_wallet(
        &self,
        name: &str,
        policy: &str,
    ) -> Result<Option<[u8; 32]>, HWIError> {
        let (descriptor_template, keys) = extract_keys_and_template(policy)?;
        let wallet = WalletPolicy::new(name.to_string(), Version::V2, descriptor_template, keys);
        let (_id, hmac) = self.client.register_wallet(&wallet).await?;
        Ok(Some(hmac))
    }

    async fn sign_tx(&self, psbt: &mut Psbt) -> Result<(), HWIError> {
        if let Some((policy, hmac)) = &self.wallet {
            let sigs = self.client.sign_psbt(psbt, policy, hmac.as_ref()).await?;
            for (i, key, sig) in sigs {
                let input = psbt.inputs.get_mut(i).ok_or(HWIError::DeviceDidNotSign)?;
                input.partial_sigs.insert(key, sig);
            }
        }
        Ok(())
    }
}

pub fn extract_keys_and_template(policy: &str) -> Result<(String, Vec<WalletPubKey>), HWIError> {
    let re = Regex::new(r"((\[.+?\])?[xyYzZtuUvV]pub[1-9A-HJ-NP-Za-km-z]{79,108})").unwrap();
    let mut descriptor_template = policy.to_string();
    let mut pubkeys: Vec<WalletPubKey> = Vec::new();
    for (index, capture) in re.find_iter(policy).enumerate() {
        pubkeys.push(
            WalletPubKey::from_str(capture.as_str()).map_err(|_| HWIError::UnsupportedInput)?,
        );
        descriptor_template = descriptor_template.replace(capture.as_str(), &format!("@{}", index));
    }

    // Do not include the hash in the descriptor template.
    if let Some((descriptor_template, _hash)) = descriptor_template.rsplit_once('#') {
        Ok((descriptor_template.to_string(), pubkeys))
    } else {
        Ok((descriptor_template, pubkeys))
    }
}

impl Ledger<TransportHID> {
    pub fn try_connect_hid() -> Result<Self, HWIError> {
        let hid = TransportNativeHID::new(&HidApi::new().map_err(|_| HWIError::DeviceNotFound)?)
            .map_err(|_| HWIError::DeviceNotFound)?;
        Ok(Ledger {
            client: BitcoinClient::new(TransportHID(hid)),
            wallet: None,
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
            wallet: None,
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
}
