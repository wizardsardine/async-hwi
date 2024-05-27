use std::error::Error;

use async_hwi::{AddressScript, DeviceKind};
use async_hwi_cli::command;

use bitcoin::{
    bip32::{DerivationPath, Fingerprint},
    psbt::Psbt,
    Network,
};
use clap::{Parser, Subcommand};

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    #[command(subcommand)]
    command: Commands,
    #[arg(long)]
    /// default will be the first connected device with the master fingerprint matching.
    #[arg(long, alias = "fg", value_parser = clap::value_parser!(bitcoin::bip32::Fingerprint))]
    fingerprint: Option<Fingerprint>,
    /// default will be the Bitcoin mainnet network.
    #[arg(long, value_parser = clap::value_parser!(bitcoin::Network), default_value_t = bitcoin::Network::Bitcoin)]
    network: Network,
}

#[derive(Debug, Subcommand)]
enum Commands {
    #[command(subcommand)]
    Address(AddressCommands),
    #[command(subcommand)]
    Device(DeviceCommands),
    #[command(subcommand)]
    Psbt(PsbtCommands),
    #[command(subcommand)]
    Wallet(WalletCommands),
    #[command(subcommand)]
    Xpub(XpubCommands),
}

#[derive(Debug, Subcommand)]
enum AddressCommands {
    Display {
        #[arg(long)]
        index: Option<u32>,
        #[arg(long)]
        wallet_name: Option<String>,
        #[arg(long)]
        wallet_policy: Option<String>,
        #[arg(long)]
        hmac: Option<String>,
        #[arg(long, value_parser = clap::value_parser!(bitcoin::bip32::DerivationPath))]
        p2tr: Option<DerivationPath>,
    },
}

#[derive(Debug, Subcommand)]
enum DeviceCommands {
    List,
}

#[derive(Debug, Subcommand)]
enum PsbtCommands {
    Sign {
        #[arg(long, alias = "fg", value_parser = clap::value_parser!(bitcoin::psbt::Psbt))]
        psbt: Psbt,
        #[arg(long)]
        wallet_name: Option<String>,
        #[arg(long)]
        wallet_policy: Option<String>,
        #[arg(long)]
        hmac: Option<String>,
    },
}

#[derive(Debug, Subcommand)]
enum WalletCommands {
    Register {
        #[arg(long)]
        name: String,
        #[arg(long)]
        policy: String,
    },
    IsRegistered {
        #[arg(long)]
        name: Option<String>,
        #[arg(long)]
        policy: String,
    },
}

#[derive(Debug, Subcommand)]
enum XpubCommands {
    Get {
        #[arg(long, value_parser = clap::value_parser!(bitcoin::bip32::DerivationPath))]
        path: DerivationPath,
    },
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    let args = Args::parse();
    match args.command {
        Commands::Address(AddressCommands::Display {
            index,
            wallet_name,
            wallet_policy,
            hmac,
            p2tr,
        }) => {
            if let Some(policy) = wallet_policy {
                for device in command::list(
                    args.network,
                    Some(command::Wallet {
                        name: wallet_name.as_ref(),
                        policy: Some(&policy),
                        hmac: hmac.as_ref(),
                    }),
                )
                .await?
                {
                    if let Some(fg) = args.fingerprint {
                        if fg != device.get_master_fingerprint().await? {
                            continue;
                        }
                    }
                    device
                        .display_address(&AddressScript::Miniscript {
                            index: index.expect("Must be present"),
                            change: false,
                        })
                        .await?;
                    break;
                }
            } else if let Some(path) = p2tr {
                for device in command::list(args.network, None).await? {
                    {
                        if let Some(fg) = args.fingerprint {
                            if fg != device.get_master_fingerprint().await? {
                                continue;
                            }
                        }
                        device.display_address(&AddressScript::P2TR(path)).await?;
                        break;
                    }
                }
            }
        }
        Commands::Device(DeviceCommands::List) => {
            for device in command::list(args.network, None).await? {
                eprint!("{}", device.get_master_fingerprint().await?);
                eprint!(" {}", device.device_kind());
                if let Ok(version) = device.get_version().await.map(|v| v.to_string()) {
                    eprint!(" {}", version);
                }
                eprintln!();
            }
        }
        Commands::Xpub(XpubCommands::Get { path }) => {
            for device in command::list(args.network, None).await? {
                if let Some(fg) = args.fingerprint {
                    if fg != device.get_master_fingerprint().await? {
                        continue;
                    }
                }
                let response = device.get_extended_pubkey(&path, false).await;
                match response {
                    Ok(r) => eprintln!("{}", r),
                    Err(e) => {
                        if device.device_kind() == DeviceKind::Ledger {
                            eprintln!("{}", device.get_extended_pubkey(&path, true).await?);
                        } else {
                            eprintln!("{}", e);
                        }
                    }
                }
            }
        }
        Commands::Wallet(WalletCommands::Register { name, policy }) => {
            for device in command::list(args.network, None).await? {
                if let Some(fg) = args.fingerprint {
                    if fg != device.get_master_fingerprint().await? {
                        continue;
                    }
                }

                if let Some(hmac) = device.register_wallet(&name, &policy).await? {
                    eprintln!("{}", hex::encode(hmac));
                }
            }
        }
        Commands::Wallet(WalletCommands::IsRegistered { name, policy }) => {
            for device in command::list(args.network, None).await? {
                if let Some(fg) = args.fingerprint {
                    if fg != device.get_master_fingerprint().await? {
                        continue;
                    }
                }
                let (name, policy) = match device.device_kind() {
                    DeviceKind::Ledger
                    | DeviceKind::LedgerSimulator
                    | DeviceKind::Coldcard
                    | DeviceKind::Jade => (name.clone().expect("name is required"), policy.clone()),
                    _ => ("".into(), policy.clone()),
                };
                let res = device.is_wallet_registered(&name, &policy).await?;
                eprintln!("{}", res);
            }
        }
        Commands::Psbt(PsbtCommands::Sign {
            mut psbt,
            wallet_name,
            wallet_policy,
            hmac,
        }) => {
            for device in command::list(
                args.network,
                Some(command::Wallet {
                    name: wallet_name.as_ref(),
                    policy: wallet_policy.as_ref(),
                    hmac: hmac.as_ref(),
                }),
            )
            .await?
            {
                if let Some(fg) = args.fingerprint {
                    if fg != device.get_master_fingerprint().await? {
                        continue;
                    }
                }
                device.sign_tx(&mut psbt).await?;
                eprintln!("{}", psbt);
            }
        }
    }
    Ok(())
}
