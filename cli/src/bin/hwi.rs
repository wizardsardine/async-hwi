use std::error::Error;

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
    Device(DeviceCommands),
    #[command(subcommand)]
    Psbt(PsbtCommands),
    #[command(subcommand)]
    Wallet(WalletCommands),
    #[command(subcommand)]
    Xpub(XpubCommands),
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
        wallet_policy: String,
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
        Commands::Device(DeviceCommands::List) => {
            for device in command::list(args.network, None).await? {
                eprintln!(
                    "{} {} {}",
                    device.device_kind(),
                    device.get_master_fingerprint().await?,
                    device.get_version().await.map(|v| v.to_string())?
                );
            }
        }
        Commands::Xpub(XpubCommands::Get { path }) => {
            for device in command::list(args.network, None).await? {
                if let Some(fg) = args.fingerprint {
                    if fg != device.get_master_fingerprint().await? {
                        continue;
                    }
                }
                eprintln!("{}", device.get_extended_pubkey(&path).await?);
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
                    policy: &wallet_policy,
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
