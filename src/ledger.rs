use std::convert::TryFrom;
use std::default::Default;
use std::error::Error;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};

use async_trait::async_trait;
use bitcoin::{
    bip32::{ChildNumber, DerivationPath, Fingerprint, Xpub},
    psbt::Psbt,
};
use ledger_bitcoin_client::psbt::PartialSignature;

use ledger_apdu::APDUAnswer;
use ledger_transport_hidapi::TransportNativeHID;
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

use crate::{parse_version, utils, AddressScript, DeviceKind, Error as HWIError, HWI};

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
        let (descriptor_template, keys) = utils::extract_keys_and_template::<WalletPubKey>(policy)?;
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
        Ok(parse_version(&version)?)
    }

    async fn get_master_fingerprint(&self) -> Result<Fingerprint, HWIError> {
        Ok(self.client.get_master_fingerprint().await?)
    }

    async fn get_extended_pubkey(&self, path: &DerivationPath) -> Result<Xpub, HWIError> {
        Ok(self
            .client
            .get_extended_pubkey(path, self.options.display_xpub)
            .await?)
    }

    async fn get_extended_pubkey_display(&self, path: &DerivationPath) -> Result<Xpub, HWIError> {
        Ok(self.client.get_extended_pubkey(path, true).await?)
    }

    async fn display_address(&self, script: &AddressScript) -> Result<(), HWIError> {
        match script {
            AddressScript::P2TR(path) => {
                let children = utils::bip86_path_child_numbers(path.clone())?;
                let (hardened_children, normal_children) = children.split_at(3);
                let path = DerivationPath::from(hardened_children);
                let fg = self.get_master_fingerprint().await?;
                let xpub = self.get_extended_pubkey(&path).await?;
                let policy = format!("tr({}/**)", key_string_from_parts(fg, path, xpub));
                let (descriptor_template, keys) =
                    utils::extract_keys_and_template::<WalletPubKey>(&policy)?;
                let wallet =
                    WalletPolicy::new("".into(), WalletVersion::V2, descriptor_template, keys);

                self.client
                    .get_wallet_address(
                        &wallet,
                        None,
                        normal_children[0] == ChildNumber::from_normal_idx(0).unwrap(),
                        normal_children[1].into(),
                        true,
                    )
                    .await?;
            }
            AddressScript::Miniscript { index, change } => {
                let (policy, hmac) = &self
                    .options
                    .wallet
                    .as_ref()
                    .ok_or_else(|| HWIError::MissingPolicy)?;
                self.client
                    .get_wallet_address(policy, hmac.as_ref(), *change, *index, true)
                    .await?;
            }
        }
        Ok(())
    }

    async fn register_wallet(
        &self,
        name: &str,
        policy: &str,
    ) -> Result<Option<[u8; 32]>, HWIError> {
        let (descriptor_template, keys) = utils::extract_keys_and_template::<WalletPubKey>(policy)?;
        let wallet = WalletPolicy::new(
            name.to_string(),
            WalletVersion::V2,
            descriptor_template,
            keys,
        );
        let (_id, hmac) = self.client.register_wallet(&wallet).await?;
        Ok(Some(hmac))
    }

    async fn is_wallet_registered(&self, name: &str, policy: &str) -> Result<bool, HWIError> {
        if let Some((wallet, hmac)) = &self.options.wallet {
            let (descriptor_template, keys) =
                utils::extract_keys_and_template::<WalletPubKey>(policy)?;
            Ok(hmac.is_some()
                && name == wallet.name
                && descriptor_template == wallet.descriptor_template
                && keys == wallet.keys)
        } else {
            Ok(false)
        }
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

fn key_string_from_parts(fg: Fingerprint, path: DerivationPath, xpub: Xpub) -> String {
    format!(
        "[{}/{}]{}",
        fg,
        path.to_string().trim_start_matches("m/"),
        xpub
    )
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
        if let BitcoinClientError::Device { status, .. } = e {
            if status == StatusWord::Deny {
                return HWIError::UserRefused;
            }
        };
        HWIError::Device(format!("{:#?}", e))
    }
}

#[cfg(test)]
mod tests {

    use super::*;
    use std::str::FromStr;

    // This is a foolproof test in case next rust-bitcoin version introduces again the m/
    #[test]
    fn test_key_string_from_parts() {
        let path = DerivationPath::from_str("m/48'/1'/0'/2'").unwrap();
        let fg = Fingerprint::from_hex("aabbccdd").unwrap();
        let xpub = Xpub::from_str("tpubDExA3EC3iAsPxPhFn4j6gMiVup6V2eH3qKyk69RcTc9TTNRfFYVPad8bJD5FCHVQxyBT4izKsvr7Btd2R4xmQ1hZkvsqGBaeE82J71uTK4N").unwrap();
        assert_eq!(key_string_from_parts(fg, path, xpub), "[aabbccdd/48'/1'/0'/2']tpubDExA3EC3iAsPxPhFn4j6gMiVup6V2eH3qKyk69RcTc9TTNRfFYVPad8bJD5FCHVQxyBT4izKsvr7Btd2R4xmQ1hZkvsqGBaeE82J71uTK4N");
    }
}
