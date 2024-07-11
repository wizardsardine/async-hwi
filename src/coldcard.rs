use std::{
    str::FromStr,
    sync::{Arc, Mutex, MutexGuard},
};

use async_trait::async_trait;
use bitcoin::{
    bip32::{DerivationPath, Fingerprint, Xpub},
    psbt::Psbt,
};

use crate::{parse_version, AddressScript, DeviceKind, Error as HWIError, Version, HWI};
pub use coldcard as api;

#[derive(Debug)]
pub struct Coldcard {
    device: Arc<Mutex<coldcard::Coldcard>>,
    wallet_name: Option<String>,
}

impl Coldcard {
    pub fn with_wallet_name(mut self, wallet_name: String) -> Self {
        self.wallet_name = Some(wallet_name);
        self
    }

    fn device(&self) -> Result<MutexGuard<'_, coldcard::Coldcard>, HWIError> {
        self.device
            .lock()
            .map_err(|_| HWIError::Unexpected("Failed to unlock"))
    }
}

impl From<coldcard::Coldcard> for Coldcard {
    fn from(cc: coldcard::Coldcard) -> Self {
        Coldcard {
            device: Arc::new(Mutex::new(cc)),
            wallet_name: None,
        }
    }
}

#[async_trait]
impl HWI for Coldcard {
    fn device_kind(&self) -> DeviceKind {
        DeviceKind::Coldcard
    }

    /// The first semver version returned by coldcard is the firmware version.
    async fn get_version(&self) -> Result<Version, HWIError> {
        let s = self.device()?.version()?;
        for line in s.split('\n') {
            if let Ok(version) = parse_version(line) {
                return Ok(version);
            }
        }
        Err(HWIError::UnsupportedVersion)
    }

    async fn get_master_fingerprint(&self) -> Result<Fingerprint, HWIError> {
        let s = self.device()?.xpub(None)?;
        let xpub = Xpub::from_str(&s).map_err(|e| HWIError::Device(e.to_string()))?;
        Ok(xpub.fingerprint())
    }

    async fn get_extended_pubkey(&self, path: &DerivationPath) -> Result<Xpub, HWIError> {
        let path = coldcard::protocol::DerivationPath::new(&path.to_string())
            .map_err(|e| HWIError::InvalidParameter("path", format!("{:?}", e)))?;
        let s = self.device()?.xpub(Some(path))?;
        Xpub::from_str(&s).map_err(|e| HWIError::Device(e.to_string()))
    }

    async fn display_address(&self, script: &AddressScript) -> Result<(), HWIError> {
        if let Some(name) = &self.wallet_name {
            let descriptor_name = coldcard::protocol::DescriptorName::new(name)
                .map_err(|_| HWIError::UnsupportedInput)?;
            if let AddressScript::Miniscript { index, change } = script {
                self.device()?
                    .miniscript_address(descriptor_name, *change, *index)?;
                Ok(())
            } else {
                Err(HWIError::UnimplementedMethod)
            }
        } else {
            Err(HWIError::UnimplementedMethod)
        }
    }

    async fn register_wallet(
        &self,
        name: &str,
        policy: &str,
    ) -> Result<Option<[u8; 32]>, HWIError> {
        let payload = format!("{{\"name\":\"{}\",\"desc\":\"{}\"}}", name, policy);
        let _ = self.device()?.miniscript_enroll(payload.as_bytes())?;
        Ok(None)
    }

    async fn is_wallet_registered(&self, name: &str, policy: &str) -> Result<bool, HWIError> {
        let descriptor_name = coldcard::protocol::DescriptorName::new(name)
            .map_err(|_| HWIError::UnsupportedInput)?;
        let desc = self.device()?.miniscript_get(descriptor_name)?;
        if let Some(desc) = desc {
            if let Some((policy, _)) = policy.replace('\'', "h").split_once('#') {
                Ok(desc.contains(policy))
            } else {
                Ok(desc.contains(policy))
            }
        } else {
            Ok(false)
        }
    }

    async fn sign_tx(&self, psbt: &mut Psbt) -> Result<(), HWIError> {
        let mut cc = self.device()?;

        let _ = cc.sign_psbt(&psbt.serialize(), api::SignMode::Signed)?;

        let tx = loop {
            if let Some(tx) = cc.get_signed_tx()? {
                break tx;
            }
        };

        let mut new_psbt = Psbt::deserialize(&tx).map_err(|e| HWIError::Device(e.to_string()))?;

        for i in 0..new_psbt.inputs.len() {
            psbt.inputs[i]
                .partial_sigs
                .append(&mut new_psbt.inputs[i].partial_sigs);
            psbt.inputs[i]
                .tap_script_sigs
                .append(&mut new_psbt.inputs[i].tap_script_sigs);
            if let Some(sig) = new_psbt.inputs[i].tap_key_sig {
                psbt.inputs[i].tap_key_sig = Some(sig);
            }
        }

        Ok(())
    }
}

impl From<api::Error> for HWIError {
    fn from(e: api::Error) -> Self {
        if let api::Error::UnexpectedResponse(api::protocol::Response::Refused) = e {
            HWIError::UserRefused
        } else {
            HWIError::Device(e.to_string())
        }
    }
}

impl From<Coldcard> for Box<dyn HWI + Send> {
    fn from(s: Coldcard) -> Box<dyn HWI + Send> {
        Box::new(s)
    }
}

impl From<Coldcard> for Arc<dyn HWI + Sync + Send> {
    fn from(s: Coldcard) -> Arc<dyn HWI + Sync + Send> {
        Arc::new(s)
    }
}
