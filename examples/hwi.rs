use async_hwi::HWI;
use bitcoin::util::bip32::DerivationPath;
use std::str::FromStr;

#[cfg(feature = "specter")]
use async_hwi::specter::{Specter, SpecterSimulator};

#[tokio::main]
pub async fn main() {
    let list = list_hardware_wallets().await;
    eprintln!(
        "{} device{} connected",
        list.len(),
        if list.len() > 1 { "s" } else { "" }
    );

    for mut hw in list {
        eprintln!("{}", hw.device_type());
        eprintln!("{}", hw.get_fingerprint().await.unwrap());
        let key = hw
            .get_extended_pubkey(&DerivationPath::from_str("m/0").unwrap())
            .await
            .unwrap();
        // let resp = hw.register_wallet("my wallet", "wsh(multi(1,tpubD6NzVbkrYhZ4XcB3kRJVob8bmjMvA2zBuagidVzh7ASY5FyAEtq4nTzx9wHYu5XDQAg7vdFNiF6yX38kTCK8zjVVmFTiQR2YKAqZBTGjnoD/**))").await.unwrap();
    }
}

pub async fn list_hardware_wallets() -> Vec<Box<dyn HWI + Send>> {
    let mut hws = Vec::new();

    #[cfg(feature = "specter")]
    if let Ok(device) = SpecterSimulator::try_connect().await {
        hws.push(device.into());
    }

    #[cfg(feature = "specter")]
    if let Ok(device) = Specter::try_connect_serial().await {
        hws.push(device.into());
    }

    hws
}
