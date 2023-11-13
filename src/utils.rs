use std::{cmp::Ordering, collections::BTreeMap};

use bitcoin::{
    bip32::{ChildNumber, DerivationPath, KeySource},
    psbt::Psbt,
    secp256k1::PublicKey,
};

use crate::{Error, HWI};

pub struct Bip32DerivationFilter<'a> {
    psbt: &'a mut Psbt,
    ignored_bip32_derivations: Vec<BTreeMap<PublicKey, KeySource>>,
}

impl<'a> Bip32DerivationFilter<'a> {
    pub fn new(psbt: &'a mut Psbt) -> Self {
        Self {
            ignored_bip32_derivations: psbt.inputs.iter().map(|_| BTreeMap::new()).collect(),
            psbt,
        }
    }
    // Bitbox and Coldcard sign with the first bip32_derivation that matches its fingerprint.
    // In order to to multiple round of signing the bip32_derivation of keys that
    // signed the psbt must be removed then appended once the tx is signed.
    pub fn ignore_signed_key_derivation(mut self) -> Self {
        for (i, input) in self.psbt.inputs.iter_mut().enumerate() {
            for key in input.partial_sigs.keys() {
                if let Some(derivation) = input.bip32_derivation.remove(&key.inner) {
                    self.ignored_bip32_derivations[i].insert(key.inner, derivation);
                }
            }
        }
        self
    }

    // Input may have multiple derivation with the same fingerprint and different derivation
    // for example:
    // Input A: fg/0/0, fg/1/0 and Input B fg/0/1, fg/1/1.
    // We want for this first round of signature to have A: fg/0/0 and fg/0/1
    pub fn ignore_same_fg_bip32_derivations(mut self) -> Self {
        let mut priority_order = Vec::<KeySource>::new();
        for input in &self.psbt.inputs {
            for source in input.bip32_derivation.values() {
                priority_order.push(source.clone());
            }
        }
        priority_order.sort_by(|(fg1, path1), (fg2, path2)| match fg1.cmp(fg2) {
            Ordering::Less => Ordering::Less,
            Ordering::Greater => Ordering::Greater,
            Ordering::Equal => path2.cmp(path1),
        });

        for (i, input) in self.psbt.inputs.iter_mut().enumerate() {
            let mut to_remove = Vec::<PublicKey>::new();
            for (key1, source1) in &input.bip32_derivation {
                for (key2, source2) in &input.bip32_derivation {
                    if source1.0 == source2.0 && source1.1 != source2.1 {
                        if priority_order.iter().position(|s| s == source1)
                            < priority_order.iter().position(|s| s == source2)
                        {
                            to_remove.push(*key2);
                        } else {
                            to_remove.push(*key1);
                        }
                    }
                }
            }
            for key in to_remove {
                if let Some(derivation) = input.bip32_derivation.remove(&key) {
                    self.ignored_bip32_derivations[i].insert(key, derivation);
                }
            }
        }

        self
    }

    /// Signs the psbt with the HWI interface and puts back the ignored bip32 derivations
    pub async fn sign_psbt<T: HWI>(mut self, device: &T) -> Result<(), Error> {
        device.sign_tx(self.psbt).await?;

        for (i, input) in self.psbt.inputs.iter_mut().enumerate() {
            input
                .bip32_derivation
                .append(&mut self.ignored_bip32_derivations[i]);
        }

        Ok(())
    }
}

pub fn bip86_path_child_numbers(path: DerivationPath) -> Result<Vec<ChildNumber>, Error> {
    let children: Vec<ChildNumber> = path.into();
    if children.len() != 5
        || children[0] != ChildNumber::from_hardened_idx(86).unwrap()
        || children[1].is_normal()
        || children[2].is_normal()
        || children[3].is_hardened()
        || children[4].is_hardened()
    {
        Err(Error::InvalidParameter(
            "derivation_path",
            "path is not bip86 compatible".to_string(),
        ))
    } else {
        Ok(children)
    }
}

#[cfg(test)]
mod tests {
    use std::str::FromStr;

    use super::*;

    #[test]
    fn test_sort_bip32_derivations() {
        let mut psbt = Psbt::from_str("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").unwrap();
        assert_eq!(psbt.inputs[0].bip32_derivation.len(), 6);
        assert_eq!(psbt.inputs[1].bip32_derivation.len(), 6);
        let filter = Bip32DerivationFilter::new(&mut psbt).ignore_same_fg_bip32_derivations();
        assert_eq!(filter.ignored_bip32_derivations[0].len(), 4);
        assert_eq!(filter.ignored_bip32_derivations[1].len(), 4);
        assert_eq!(psbt.inputs[0].bip32_derivation.len(), 2);
        assert_eq!(psbt.inputs[1].bip32_derivation.len(), 2);
    }
}
