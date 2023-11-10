pub mod command {
    use async_hwi::{
        bitbox::{api::runtime, BitBox02, PairingBitbox02WithLocalCache},
        ledger::{HidApi, Ledger, LedgerSimulator, TransportHID},
        specter::{Specter, SpecterSimulator},
        HWI,
    };
    use bitcoin::{hashes::hex::FromHex, Network};
    use std::error::Error;

    pub struct Wallet<'a> {
        pub name: Option<&'a String>,
        pub policy: &'a String,
        pub hmac: Option<&'a String>,
    }

    pub async fn list(
        network: Network,
        wallet: Option<Wallet<'_>>,
    ) -> Result<Vec<Box<dyn HWI + Send>>, Box<dyn Error>> {
        let mut hws = Vec::new();

        if let Ok(device) = SpecterSimulator::try_connect().await {
            hws.push(device.into());
        }

        if let Ok(devices) = Specter::enumerate().await {
            for device in devices {
                hws.push(device.into());
            }
        }

        if let Ok(device) = LedgerSimulator::try_connect().await {
            hws.push(device.into());
        }

        let api = HidApi::new().unwrap();

        for device_info in api.device_list() {
            if async_hwi::bitbox::is_bitbox02(device_info) {
                if let Ok(device) = device_info.open_device(&api) {
                    if let Ok(device) =
                        PairingBitbox02WithLocalCache::<runtime::TokioRuntime>::connect(
                            device, None,
                        )
                        .await
                    {
                        if let Ok((device, _)) = device.wait_confirm().await {
                            let mut bb02 = BitBox02::from(device).with_network(network);
                            if let Some(ref wallet) = wallet {
                                bb02 = bb02.with_policy(wallet.policy)?;
                            }
                            hws.push(bb02.into());
                        }
                    }
                }
            }
        }

        for detected in Ledger::<TransportHID>::enumerate(&api) {
            if let Ok(mut device) = Ledger::<TransportHID>::connect(&api, detected) {
                if let Some(ref wallet) = wallet {
                    let hmac = if let Some(s) = wallet.hmac {
                        let mut h = [b'\0'; 32];
                        h.copy_from_slice(&Vec::from_hex(s)?);
                        Some(h)
                    } else {
                        None
                    };
                    device = device.with_wallet(
                        wallet
                            .name
                            .ok_or::<Box<dyn Error>>("ledger requires a wallet name".into())?,
                        wallet.policy,
                        hmac,
                    )?;
                }
                hws.push(device.into());
            }
        }

        Ok(hws)
    }
}
