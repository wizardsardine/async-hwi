use crate::{DeviceKind, Error as HWIError, HWI};
use async_trait::async_trait;
use bitbox_api::{
    btc::KeyOriginInfo,
    error::Error,
    pb::{self, btc_script_config::Policy, BtcScriptConfig},
    usb::UsbError,
    Keypath, PairedBitBox, PairingBitBox,
};
use bitcoin::{
    bip32::{DerivationPath, ExtendedPubKey, Fingerprint},
    psbt::Psbt,
};
use regex::Regex;
use std::{
    str::FromStr,
    sync::{Arc, Mutex},
};

pub use bitbox_api::{
    self as api,
    runtime::Runtime,
    usb::{get_any_bitbox02, is_bitbox02},
    ConfigError, NoiseConfig, NoiseConfigData, NoiseConfigNoCache,
};

#[derive(Clone)]
struct Cache(Arc<Mutex<Option<NoiseConfigData>>>);

impl bitbox_api::Threading for Cache {}

impl NoiseConfig for Cache {
    fn read_config(&self) -> Result<NoiseConfigData, ConfigError> {
        let noise_data = self.0.lock().map_err(|e| ConfigError(e.to_string()))?;
        if let Some(data) = noise_data.as_ref() {
            Ok(data.clone())
        } else {
            Ok(NoiseConfigData::default())
        }
    }
    fn store_config(&self, data: &NoiseConfigData) -> Result<(), ConfigError> {
        let mut noise_data = self.0.lock().map_err(|e| ConfigError(e.to_string()))?;
        *noise_data = Some(data.clone());
        Ok(())
    }
}

pub struct PairingBitbox02WithLocalCache<T: Runtime> {
    client: PairingBitBox<T>,
    local_cache: Cache,
}

impl<T: Runtime> PairingBitbox02WithLocalCache<T> {
    pub async fn connect(
        device: hidapi::HidDevice,
        pairing_data: Option<NoiseConfigData>,
    ) -> Result<Self, HWIError> {
        let local_cache = if let Some(data) = pairing_data {
            Cache(Arc::new(Mutex::new(Some(data))))
        } else {
            Cache(Arc::new(Mutex::new(None)))
        };
        let bitbox =
            bitbox_api::BitBox::<T>::from_hid_device(device, Box::new(local_cache.clone())).await?;
        let pairing_bitbox = bitbox.unlock_and_pair().await?;
        Ok(PairingBitbox02WithLocalCache {
            client: pairing_bitbox,
            local_cache,
        })
    }

    pub fn pairing_code(&self) -> Option<String> {
        self.client.get_pairing_code()
    }

    pub async fn wait_confirm(self) -> Result<(PairedBitBox<T>, NoiseConfigData), HWIError> {
        let client = self.client.wait_confirm().await?;
        let mut cache = self
            .local_cache
            .0
            .lock()
            .map_err(|e| HWIError::Device(e.to_string()))?;
        Ok((
            client,
            cache
                .take()
                .expect("noise config data must be in local cache"),
        ))
    }
}

pub struct PairingBitbox02<T: Runtime> {
    client: PairingBitBox<T>,
}

impl<T: Runtime> PairingBitbox02<T> {
    pub async fn connect(
        device: hidapi::HidDevice,
        pairing: Option<Box<dyn NoiseConfig>>,
    ) -> Result<Self, HWIError> {
        let noise_config = pairing.unwrap_or_else(|| Box::new(NoiseConfigNoCache {}));
        let bitbox = bitbox_api::BitBox::<T>::from_hid_device(device, noise_config).await?;
        let pairing_bitbox = bitbox.unlock_and_pair().await?;
        Ok(PairingBitbox02 {
            client: pairing_bitbox,
        })
    }

    pub fn pairing_code(&self) -> Option<String> {
        self.client.get_pairing_code()
    }

    pub async fn wait_confirm(self) -> Result<PairedBitBox<T>, HWIError> {
        self.client.wait_confirm().await.map_err(|e| e.into())
    }
}

pub struct BitBox02<T: Runtime> {
    pub network: bitcoin::Network,
    pub display_xpub: bool,
    pub client: PairedBitBox<T>,
    pub policy: Option<pb::BtcScriptConfigWithKeypath>,
}

impl<T: Runtime> std::fmt::Debug for BitBox02<T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("BitBox").finish()
    }
}

impl<T: Runtime> BitBox02<T> {
    pub fn from(paired_bitbox: PairedBitBox<T>) -> Self {
        BitBox02 {
            display_xpub: false,
            network: bitcoin::Network::Bitcoin,
            client: paired_bitbox,
            policy: None,
        }
    }

    pub fn with_network(mut self, network: bitcoin::Network) -> Self {
        self.network = network;
        self
    }

    pub fn display_xpub(mut self, value: bool) -> Self {
        self.display_xpub = value;
        self
    }

    pub fn with_policy(mut self, policy: &str) -> Result<Self, HWIError> {
        let script_config = Some(extract_script_config_policy(policy)?);
        self.policy = Some(pb::BtcScriptConfigWithKeypath {
            script_config,
            keypath: Vec::new(),
        });
        Ok(self)
    }

    pub async fn is_policy_registered(&self, policy: &str) -> Result<bool, HWIError> {
        let pb_network = coin_from_network(self.network);
        let policy = extract_script_config_policy(policy)?;
        self.client
            .btc_is_script_config_registered(pb_network, &policy, None)
            .await
            .map_err(|e| e.into())
    }
}

#[async_trait]
impl<T: Runtime + Sync + Send> HWI for BitBox02<T> {
    fn device_kind(&self) -> DeviceKind {
        DeviceKind::BitBox02
    }

    async fn get_version(&self) -> Result<super::Version, HWIError> {
        Err(HWIError::UnimplementedMethod)
    }

    async fn get_master_fingerprint(&self) -> Result<Fingerprint, HWIError> {
        let fg = self
            .client
            .root_fingerprint()
            .await
            .map_err(|e| HWIError::Device(e.to_string()))?;
        Ok(Fingerprint::from_str(&fg).map_err(|e| HWIError::Device(e.to_string()))?)
    }

    async fn get_extended_pubkey(&self, path: &DerivationPath) -> Result<ExtendedPubKey, HWIError> {
        let fg = self
            .client
            .btc_xpub(
                if self.network == bitcoin::Network::Bitcoin {
                    pb::BtcCoin::Btc
                } else {
                    pb::BtcCoin::Tbtc
                },
                &Keypath::from(path),
                if self.network == bitcoin::Network::Bitcoin {
                    pb::btc_pub_request::XPubType::Xpub
                } else {
                    pb::btc_pub_request::XPubType::Tpub
                },
                self.display_xpub,
            )
            .await
            .map_err(|e| HWIError::Device(e.to_string()))?;
        Ok(ExtendedPubKey::from_str(&fg).map_err(|e| HWIError::Device(e.to_string()))?)
    }

    async fn register_wallet(
        &self,
        name: &str,
        policy: &str,
    ) -> Result<Option<[u8; 32]>, HWIError> {
        let pb_network = coin_from_network(self.network);
        let policy = extract_script_config_policy(policy)?;
        if self
            .client
            .btc_is_script_config_registered(pb_network, &policy, None)
            .await?
        {
            return Ok(None);
        }
        self.client
            .btc_register_script_config(
                pb_network,
                &policy,
                None,
                pb::btc_register_script_config_request::XPubType::AutoXpubTpub,
                Some(name),
            )
            .await
            .map(|_| None)
            .map_err(|e| e.into())
    }

    /// Bitbox and Coldcard sign with the first bip32_derivation that matches its fingerprint.
    /// It may be useful to user utils::Bip32DerivationFilter to filter already signed derivations
    /// and derivations collusion in case of multiple spending path per outputs.
    async fn sign_tx(&self, psbt: &mut Psbt) -> Result<(), HWIError> {
        let policy: Option<pb::BtcScriptConfigWithKeypath> =
            if let Some(pb::BtcScriptConfigWithKeypath {
                script_config,
                mut keypath,
            }) = self.policy.clone()
            {
                let fg = self.get_master_fingerprint().await?;
                if let Some(pb::BtcScriptConfig {
                    config: Some(pb::btc_script_config::Config::Policy(Policy { keys, .. })),
                }) = &script_config
                {
                    for key in keys {
                        if fg.as_bytes().to_vec() == key.root_fingerprint {
                            keypath = key.keypath.clone();
                        }
                    }
                }
                Some(pb::BtcScriptConfigWithKeypath {
                    script_config,
                    keypath,
                })
            } else {
                None
            };

        self.client
            .btc_sign_psbt(
                coin_from_network(self.network),
                psbt,
                policy,
                pb::btc_sign_init_request::FormatUnit::Default,
            )
            .await?;

        Ok(())
    }
}

fn coin_from_network(network: bitcoin::Network) -> pb::BtcCoin {
    if network == bitcoin::Network::Bitcoin {
        pb::BtcCoin::Btc
    } else {
        pb::BtcCoin::Tbtc
    }
}

impl From<UsbError> for HWIError {
    fn from(value: UsbError) -> Self {
        HWIError::Device(value.to_string())
    }
}

impl From<Error> for HWIError {
    fn from(value: Error) -> Self {
        HWIError::Device(value.to_string())
    }
}

impl<T: Runtime + Sync + Send + 'static> From<BitBox02<T>> for Box<dyn HWI + Sync + Send> {
    fn from(s: BitBox02<T>) -> Box<dyn HWI + Sync + Send> {
        Box::new(s)
    }
}

impl<T: Runtime + Sync + Send + 'static> From<BitBox02<T>> for Box<dyn HWI + Send> {
    fn from(s: BitBox02<T>) -> Box<dyn HWI + Send> {
        Box::new(s)
    }
}

impl<T: Runtime + Sync + Send + 'static> From<BitBox02<T>>
    for std::sync::Arc<dyn HWI + Sync + Send>
{
    fn from(s: BitBox02<T>) -> std::sync::Arc<dyn HWI + Sync + Send> {
        std::sync::Arc::new(s)
    }
}

pub fn extract_script_config_policy(policy: &str) -> Result<BtcScriptConfig, HWIError> {
    let re = Regex::new(r"((\[.+?\])?[xyYzZtuUvV]pub[1-9A-HJ-NP-Za-km-z]{79,108})").unwrap();
    let mut descriptor_template = policy.to_string();
    let mut pubkeys_str: Vec<&str> = Vec::new();
    for capture in re.find_iter(policy) {
        if !pubkeys_str.contains(&capture.as_str()) {
            pubkeys_str.push(capture.as_str());
        }
    }

    let mut pubkeys: Vec<KeyOriginInfo> = Vec::new();
    for (i, key_str) in pubkeys_str.iter().enumerate() {
        descriptor_template = descriptor_template.replace(key_str, &format!("@{}", i));
        let pubkey = if let Ok(key) = ExtendedPubKey::from_str(key_str) {
            KeyOriginInfo {
                keypath: None,
                root_fingerprint: None,
                xpub: key,
            }
        } else {
            let (keysource_str, xpub_str) = key_str
                .strip_prefix('[')
                .and_then(|s| s.rsplit_once(']'))
                .ok_or(HWIError::InvalidParameter(
                    "policy",
                    "Invalid key source".to_string(),
                ))?;
            let (f_str, path_str) = keysource_str.split_once('/').unwrap_or((keysource_str, ""));
            let fingerprint = Fingerprint::from_str(f_str)
                .map_err(|e| HWIError::InvalidParameter("policy", e.to_string()))?;
            let derivation_path = if path_str.is_empty() {
                DerivationPath::master()
            } else {
                DerivationPath::from_str(&format!("m/{}", path_str))
                    .map_err(|e| HWIError::InvalidParameter("policy", e.to_string()))?
            };

            KeyOriginInfo {
                xpub: ExtendedPubKey::from_str(xpub_str)
                    .map_err(|e| HWIError::InvalidParameter("policy", e.to_string()))?,
                keypath: Some(Keypath::from(&derivation_path)),
                root_fingerprint: Some(fingerprint),
            }
        };
        pubkeys.push(pubkey);
    }
    // Do not include the hash in the descriptor template.
    let descriptor_template =
        if let Some((descriptor_template, _hash)) = descriptor_template.rsplit_once('#') {
            descriptor_template
        } else {
            &descriptor_template
        };
    Ok(bitbox_api::btc::make_script_config_policy(
        descriptor_template,
        &pubkeys,
    ))
}

#[cfg(test)]
mod tests {
    use bitbox_api::pb::btc_script_config::Policy;

    use super::*;

    #[test]
    fn test_extract_keys_and_template() {
        let res = extract_script_config_policy("wsh(or_d(pk([f5acc2fd/49'/1'/0']tpubDCbK3Ysvk8HjcF6mPyrgMu3KgLiaaP19RjKpNezd8GrbAbNg6v5BtWLaCt8FNm6QkLseopKLf5MNYQFtochDTKHdfgG6iqJ8cqnLNAwtXuP/**),and_v(v:pkh(tpubDDtb2WPYwEWw2WWDV7reLV348iJHw2HmhzvPysKKrJw3hYmvrd4jasyoioVPdKGQqjyaBMEvTn1HvHWDSVqQ6amyyxRZ5YjpPBBGjJ8yu8S/**),older(100))))").unwrap();
        let config = res.config.unwrap();
        assert!(matches!(
            config,
            bitbox_api::pb::btc_script_config::Config::Policy(_)
        ));
        if let bitbox_api::pb::btc_script_config::Config::Policy(Policy { policy, keys }) = config {
            assert_eq!(2, keys.len());
            assert_eq!(
                "wsh(or_d(pk(@0/**),and_v(v:pkh(@1/**),older(100))))",
                policy
            );
        }

        let res = extract_script_config_policy("wsh(or_d(multi(2,[b0822927/48'/1'/0'/2']tpubDEvZxV86Br8Knbm9tWcr5Hvmg5cYTYsg92vinqH6Bie6U8ix8CsoN9W11NQygdqVwmHUJpsHXxNsi5gXn36g4xNfLWkMqPuFhRZAmMQ7jjQ/<0;1>/*,[7fc39c07/48'/1'/0'/2']tpubDEvjgXtrUuH3Qtkapny9aE8gN847xiXsf9MDM5XueGf9nrvStqAuBSva3ajGyTvtp8Ti55FvVXsgYSXuS1tQkBeopFuodx2hRUDmQbvKxbZ/<0;1>/*),and_v(v:thresh(2,pkh([b0822927/48'/1'/0'/2']tpubDEvZxV86Br8Knbm9tWcr5Hvmg5cYTYsg92vinqH6Bie6U8ix8CsoN9W11NQygdqVwmHUJpsHXxNsi5gXn36g4xNfLWkMqPuFhRZAmMQ7jjQ/<2;3>/*),a:pkh([7fc39c07/48'/1'/0'/2']tpubDEvjgXtrUuH3Qtkapny9aE8gN847xiXsf9MDM5XueGf9nrvStqAuBSva3ajGyTvtp8Ti55FvVXsgYSXuS1tQkBeopFuodx2hRUDmQbvKxbZ/<2;3>/*),a:pkh([1a1ffd98/48'/1'/0'/2']tpubDFZqzTvGijYb13BC73CkS1er8DrP5YdzMhziN3kWCKUFaW51Yj6ggvf99YpdrkTJy4RT85mxQMHXDiFAKRxzf6BykQgT4pRRBNPshSJJcKo/<0;1>/*)),older(300))))#wp0w3hlw").unwrap();
        let config = res.config.unwrap();
        assert!(matches!(
            config,
            bitbox_api::pb::btc_script_config::Config::Policy(_)
        ));
        if let bitbox_api::pb::btc_script_config::Config::Policy(Policy { policy, keys }) = config {
            assert_eq!(3, keys.len());
            assert_eq!(
                "wsh(or_d(multi(2,@0/<0;1>/*,@1/<0;1>/*),and_v(v:thresh(2,pkh(@0/<2;3>/*),a:pkh(@1/<2;3>/*),a:pkh(@2/<0;1>/*)),older(300))))",
                policy
            );
        }
    }
}
