pub mod command {
    use async_hwi::{
        bitbox::{api::runtime, BitBox02, NoiseConfigData, PairingBitbox02WithLocalCache},
        coldcard,
        jade::{self, Jade},
        ledger::{HidApi, Ledger, LedgerSimulator, TransportHID},
        specter::{Specter, SpecterSimulator},
        DeviceKind, HWI,
    };
    use bitcoin::{bip32::Fingerprint, hashes::hex::FromHex, Network};
    use std::error::Error;

    #[derive(Clone)]
    pub struct Wallet {
        pub name: Option<String>,
        pub policy: Option<String>,
        pub hmac: Option<String>,
    }

    pub struct Device {
        pub fingerprint: Fingerprint,
        pub kind: DeviceKind,
        pub handle: Box<dyn HWI + Send>,
    }

    pub type WalletResolver<'a> =
        dyn Fn(Fingerprint, DeviceKind) -> Result<Option<Wallet>, Box<dyn Error>> + 'a;

    pub async fn list(
        network: Network,
        wallet: Option<&WalletResolver<'_>>,
        bitbox_pairing: Option<NoiseConfigData>,
    ) -> Result<(Vec<Device>, Option<NoiseConfigData>), Box<dyn Error>> {
        let mut hws = Vec::new();
        let mut updated_bitbox_pairing = None;

        if let Ok(device) = SpecterSimulator::try_connect().await {
            let fingerprint = device.get_master_fingerprint().await?;
            hws.push(Device {
                fingerprint,
                kind: DeviceKind::SpecterSimulator,
                handle: device.into(),
            });
        }

        if let Ok(devices) = Specter::enumerate().await {
            for device in devices {
                let fingerprint = device.get_master_fingerprint().await?;
                hws.push(Device {
                    fingerprint,
                    kind: DeviceKind::Specter,
                    handle: device.into(),
                });
            }
        }

        match Jade::enumerate().await {
            Err(e) => eprintln!("{e:?}"),
            Ok(devices) => {
                for device in devices {
                    let device = device.with_network(network);
                    if let Ok(info) = device.get_info().await {
                        if info.jade_state == jade::api::JadeState::Locked {
                            if let Err(e) = device.auth().await {
                                eprintln!("auth {e:?}");
                                continue;
                            }
                        }
                        let fingerprint = device.get_master_fingerprint().await?;
                        hws.push(Device {
                            fingerprint,
                            kind: DeviceKind::Jade,
                            handle: device.into(),
                        });
                    }
                }
            }
        }

        if let Ok(device) = LedgerSimulator::try_connect().await {
            let fingerprint = device.get_master_fingerprint().await?;
            hws.push(Device {
                fingerprint,
                kind: DeviceKind::LedgerSimulator,
                handle: device.into(),
            });
        }

        let api = Box::new(HidApi::new().unwrap());

        for device_info in api.device_list() {
            if async_hwi::bitbox::is_bitbox02(device_info) {
                if let Ok(device) = device_info.open_device(&api) {
                    if let Ok(device) =
                        PairingBitbox02WithLocalCache::<runtime::TokioRuntime>::connect(
                            device,
                            bitbox_pairing.clone(),
                        )
                        .await
                    {
                        if let Ok((device, pairing_data)) = device.wait_confirm().await {
                            let mut bb02 = BitBox02::from(device).with_network(network);
                            let fingerprint = bb02.get_master_fingerprint().await?;
                            if let Some(wallet) =
                                resolve_wallet(wallet, fingerprint, DeviceKind::BitBox02)?
                            {
                                if let Some(policy) = wallet.policy {
                                    bb02 = bb02.with_policy(&policy)?;
                                }
                            }
                            hws.push(Device {
                                fingerprint,
                                kind: DeviceKind::BitBox02,
                                handle: bb02.into(),
                            });
                            updated_bitbox_pairing = Some(pairing_data);
                        }
                    }
                }
            }
            if device_info.vendor_id() == coldcard::api::COINKITE_VID
                && device_info.product_id() == coldcard::api::CKCC_PID
            {
                if let Some(sn) = device_info.serial_number() {
                    if let Ok((cc, _)) = coldcard::api::Coldcard::open(&api, sn, None) {
                        let mut hw = coldcard::Coldcard::from(cc);
                        let fingerprint = hw.get_master_fingerprint().await?;
                        if let Some(wallet) =
                            resolve_wallet(wallet, fingerprint, DeviceKind::Coldcard)?
                        {
                            if let Some(name) = wallet.name {
                                hw = hw.with_wallet_name(name);
                            }
                        }
                        hws.push(Device {
                            fingerprint,
                            kind: DeviceKind::Coldcard,
                            handle: hw.into(),
                        })
                    }
                }
            }
        }

        for detected in Ledger::<TransportHID>::enumerate(&api) {
            if let Ok(mut device) = Ledger::<TransportHID>::connect(&api, detected) {
                let fingerprint = device.get_master_fingerprint().await?;
                if let Some(wallet) = resolve_wallet(wallet, fingerprint, DeviceKind::Ledger)? {
                    let hmac = if let Some(s) = wallet.hmac {
                        let mut h = [b'\0'; 32];
                        h.copy_from_slice(&Vec::from_hex(&s)?);
                        Some(h)
                    } else {
                        None
                    };
                    device = device.with_wallet(
                        wallet
                            .name
                            .as_ref()
                            .ok_or::<Box<dyn Error>>("ledger requires a wallet name".into())?,
                        wallet
                            .policy
                            .as_ref()
                            .ok_or::<Box<dyn Error>>("ledger requires a wallet policy".into())?,
                        hmac,
                    )?;
                }
                hws.push(Device {
                    fingerprint,
                    kind: DeviceKind::Ledger,
                    handle: device.into(),
                });
            }
        }

        Ok((hws, updated_bitbox_pairing))
    }

    fn resolve_wallet(
        wallet: Option<&WalletResolver<'_>>,
        fingerprint: Fingerprint,
        kind: DeviceKind,
    ) -> Result<Option<Wallet>, Box<dyn Error>> {
        if let Some(wallet) = wallet {
            wallet(fingerprint, kind)
        } else {
            Ok(None)
        }
    }
}
