use async_hwi::HWI;

#[cfg(feature = "specter")]
use async_hwi::specter::{Specter, SpecterSimulator};

#[cfg(feature = "ledger")]
use async_hwi::ledger::{HidApi, Ledger, LedgerSimulator, TransportHID};

#[cfg(feature = "trezor")]
use async_hwi::trezor::TrezorClient;

#[tokio::main]
pub async fn main() {
    let list = list_hardware_wallets().await;
    eprintln!(
        "{} device{} connected",
        list.len(),
        if list.len() > 1 { "s" } else { "" }
    );

    for hw in list {
        eprintln!(
            "{} (fingerprint: {}, version: {})",
            hw.device_kind(),
            hw.get_master_fingerprint().await.unwrap(),
            hw.get_version()
                .await
                .map(|v| v.to_string())
                .unwrap_or("unknown".to_string()),
        );
    }
}

pub async fn list_hardware_wallets() -> Vec<Box<dyn HWI + Send>> {
    let mut hws = Vec::new();

    #[cfg(feature = "specter")]
    if let Ok(device) = SpecterSimulator::try_connect().await {
        hws.push(device.into());
    }

    #[cfg(feature = "specter")]
    if let Ok(devices) = Specter::enumerate().await {
        for device in devices {
            hws.push(device.into());
        }
    }

    #[cfg(feature = "ledger")]
    if let Ok(device) = LedgerSimulator::try_connect().await {
        hws.push(device.into());
    }

    #[cfg(feature = "ledger")]
    {
        let api = HidApi::new().unwrap();
        for detected in Ledger::<TransportHID>::enumerate(&api) {
            if let Ok(device) = Ledger::<TransportHID>::connect(&api, detected) {
                hws.push(device.into());
            }
        }
    }

    #[cfg(feature = "trezor")]
    {
        let client = TrezorClient::connect_first(false).unwrap();
        if client.is_connected().await.is_ok() {
            hws.push(client.into());
        }
    }

    hws
}
