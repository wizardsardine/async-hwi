use std::{
    collections::BTreeMap,
    error::Error,
    ffi::OsString,
    io::{self, IsTerminal, Read},
    path::{Path, PathBuf},
};

use async_hwi::{bitbox::NoiseConfigData, xpub_with_origin, AddressScript, DeviceKind};
use async_hwi_cli::command;

use bitcoin::{
    bip32::{DerivationPath, Fingerprint},
    psbt::Psbt,
    Network,
};
use clap::{Parser, Subcommand, ValueEnum};
use serde::{Deserialize, Serialize};

const WALLET_REGISTER_ABOUT: &str = "register wallet from persisted state or --name and --policy";
const WALLET_IS_REGISTERED_ABOUT: &str =
    "check wallet registration from persisted state or wallet name and policy";
const PSBT_SIGN_ABOUT: &str = "sign psbt from --psbt or --psbt-file";

fn persist_long_about(command_help: &str) -> String {
    format!(
        "{command_help}. When persistence is enabled, wallet metadata is loaded by device fingerprint from the async-hwi state directory. Command arguments must match existing persisted values."
    )
}

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
    /// write command output to file instead of stdout.
    #[arg(short, long, global = true)]
    output: Option<PathBuf>,
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
    State(StateCommands),
    #[command(subcommand)]
    Bitbox(BitboxCommands),
    #[command(subcommand)]
    Persist(PersistCommands),
    #[command(subcommand)]
    Xpub(XpubCommands),
}

#[derive(Debug, Subcommand)]
enum AddressCommands {
    Display {
        /// address index
        #[arg(short, long)]
        index: Option<u32>,
        /// wallet name
        #[arg(long)]
        wallet_name: Option<String>,
        /// wallet policy
        #[arg(long)]
        wallet_policy: Option<String>,
        /// proof of registration, ledger only
        #[arg(long)]
        hmac: Option<String>,
        /// display a taproot address from path
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
    #[command(
        about = PSBT_SIGN_ABOUT,
        long_about = persist_long_about(
            "Sign psbt from --psbt or --psbt-file. Use persisted state or wallet name and policy to provide wallet metadata"
        )
    )]
    Sign {
        /// psbt to sign
        #[arg(long, value_parser = clap::value_parser!(bitcoin::psbt::Psbt))]
        psbt: Option<Psbt>,
        /// read psbt from file
        #[arg(long)]
        psbt_file: Option<PathBuf>,
        /// wallet name
        #[arg(long)]
        wallet_name: Option<String>,
        /// wallet policy
        #[arg(long)]
        wallet_policy: Option<String>,
        /// proof of registration, ledger only
        #[arg(long)]
        hmac: Option<String>,
    },
}

#[derive(Debug, Subcommand)]
enum WalletCommands {
    #[command(
        about = WALLET_REGISTER_ABOUT,
        long_about = persist_long_about("Register wallet from persisted state or --name and --policy")
    )]
    Register {
        /// wallet name
        #[arg(short, long)]
        name: Option<String>,
        /// wallet policy
        #[arg(short, long)]
        policy: Option<String>,
    },
    #[command(
        about = WALLET_IS_REGISTERED_ABOUT,
        long_about = persist_long_about(
            "Check wallet registration from persisted state or wallet name and policy"
        )
    )]
    IsRegistered {
        /// wallet name
        #[arg(short, long)]
        name: Option<String>,
        /// wallet policy
        #[arg(short, long)]
        policy: Option<String>,
    },
}

#[derive(Debug, Subcommand)]
enum PersistCommands {
    /// enable persistence
    Enable,
    /// disable persistence
    Disable,
    /// show persistence status
    Status,
}

#[derive(Debug, Subcommand)]
enum BitboxCommands {
    /// show bitbox pairing state
    Show,
}

#[derive(Debug, Subcommand)]
enum StateCommands {
    /// clear wallet state
    Clear,
    /// show wallet state
    Show,
    /// edit wallet state
    Edit {
        /// state field to edit
        field: StateField,
        /// field value
        value: String,
    },
    /// remove wallet state field
    Rm {
        /// state field to remove
        field: StateField,
    },
}

#[derive(Clone, Copy, Debug, ValueEnum)]
#[clap(rename_all = "snake_case")]
enum StateField {
    Name,
    Descriptor,
    Por,
}

#[derive(Debug, Subcommand)]
enum XpubCommands {
    Get {
        /// derivation path
        #[arg(long, value_parser = clap::value_parser!(bitcoin::bip32::DerivationPath))]
        path: DerivationPath,
    },
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    let Args {
        command,
        fingerprint,
        network,
        output,
    } = parse_args()?;
    let paths = Paths::new()?;
    let persist = read_config(&paths)?.persist;

    match command {
        Commands::Address(AddressCommands::Display {
            index,
            wallet_name,
            wallet_policy,
            hmac,
            p2tr,
        }) => {
            let args = WalletArgs {
                name: wallet_name,
                descriptor: wallet_policy,
                por: hmac,
            };
            let resolver = wallet_resolver(&paths, persist, args.clone());
            if args.has_any() || (persist && p2tr.is_none()) {
                for device in list_devices(&paths, persist, network, Some(&resolver)).await? {
                    if !matches_fingerprint(fingerprint, device.fingerprint) {
                        continue;
                    }
                    device
                        .handle
                        .display_address(&AddressScript::Miniscript {
                            index: index.expect("Must be present"),
                            change: false,
                        })
                        .await?;
                    break;
                }
            } else if let Some(path) = p2tr {
                for device in list_devices(&paths, persist, network, None).await? {
                    if !matches_fingerprint(fingerprint, device.fingerprint) {
                        continue;
                    }
                    device
                        .handle
                        .display_address(&AddressScript::P2TR(path))
                        .await?;
                    break;
                }
            }
        }
        Commands::Device(DeviceCommands::List) => {
            for device in list_devices(&paths, persist, network, None).await? {
                print!("{}", device.fingerprint);
                print!(" {}", device.kind);
                if let Ok(version) = device.handle.get_version().await.map(|v| v.to_string()) {
                    print!(" {version}");
                }
                println!();
            }
        }
        Commands::Xpub(XpubCommands::Get { path }) => {
            let mut res = Vec::new();
            for device in list_devices(&paths, persist, network, None).await? {
                if !matches_fingerprint(fingerprint, device.fingerprint) {
                    continue;
                }
                let xpub = device.handle.get_extended_pubkey(&path).await?;
                res.push(xpub_with_origin(device.fingerprint, &path, xpub));
            }
            output_lines(output.as_ref(), &res)?;
        }
        Commands::Wallet(WalletCommands::Register { name, policy }) => {
            let args = WalletArgs {
                name,
                descriptor: policy,
                por: None,
            };
            let mut res = Vec::new();
            for device in list_devices(&paths, persist, network, None).await? {
                if !matches_fingerprint(fingerprint, device.fingerprint) {
                    continue;
                }
                let mut wallet = resolve_wallet_state(
                    &paths,
                    persist,
                    device.fingerprint,
                    &args,
                    Some(device.kind),
                )?
                .ok_or_else(|| invalid_input("wallet policy is required"))?;
                let name = wallet
                    .name
                    .as_ref()
                    .ok_or_else(|| invalid_input("wallet name is required"))?;
                let descriptor = wallet
                    .descriptor
                    .as_ref()
                    .ok_or_else(|| invalid_input("wallet policy is required"))?;

                if let Some(por) = device.handle.register_wallet(name, descriptor).await? {
                    let por = hex::encode(por);
                    merge_state_field(&mut wallet.por, Some(por.clone()));
                    write_wallet(&paths, persist, device.fingerprint, &wallet)?;
                    res.push(por);
                } else {
                    write_wallet(&paths, persist, device.fingerprint, &wallet)?;
                }
            }
            output_lines(output.as_ref(), &res)?;
        }
        Commands::Wallet(WalletCommands::IsRegistered { name, policy }) => {
            let args = WalletArgs {
                name,
                descriptor: policy,
                por: None,
            };
            let mut res = Vec::new();
            for device in list_devices(&paths, persist, network, None).await? {
                if !matches_fingerprint(fingerprint, device.fingerprint) {
                    continue;
                }
                let wallet = resolve_wallet_state(
                    &paths,
                    persist,
                    device.fingerprint,
                    &args,
                    Some(device.kind),
                )?
                .ok_or_else(|| invalid_input("wallet policy is required"))?;
                let descriptor = wallet
                    .descriptor
                    .as_ref()
                    .ok_or_else(|| invalid_input("wallet policy is required"))?;
                let name = wallet_name_for_device(device.kind, wallet.name.as_ref())?;
                let registered = device.handle.is_wallet_registered(name, descriptor).await?;
                write_wallet(&paths, persist, device.fingerprint, &wallet)?;
                res.push(registered.to_string());
            }
            output_lines(output.as_ref(), &res)?;
        }
        Commands::Psbt(PsbtCommands::Sign {
            psbt,
            psbt_file,
            wallet_name,
            wallet_policy,
            hmac,
        }) => {
            let mut psbt = resolve_psbt(psbt, psbt_file)?;
            let args = WalletArgs {
                name: wallet_name,
                descriptor: wallet_policy,
                por: hmac,
            };
            let resolver = wallet_resolver(&paths, persist, args);
            let mut res = Vec::new();
            for device in list_devices(&paths, persist, network, Some(&resolver)).await? {
                if !matches_fingerprint(fingerprint, device.fingerprint) {
                    continue;
                }
                device.handle.sign_tx(&mut psbt).await?;
                res.push(psbt.to_string());
            }
            output_lines(output.as_ref(), &res)?;
        }
        Commands::Persist(PersistCommands::Enable) => {
            write_config(&paths, Config { persist: true })?;
        }
        Commands::Persist(PersistCommands::Disable) => {
            write_config(&paths, Config { persist: false })?;
        }
        Commands::Persist(PersistCommands::Status) => {
            println!("{}", if persist { "enabled" } else { "disabled" });
        }
        Commands::Bitbox(BitboxCommands::Show) => {
            output_lines(output.as_ref(), &bitbox_pairing_lines(&paths)?)?;
        }
        Commands::State(StateCommands::Clear) => {
            clear_wallets(&paths)?;
        }
        Commands::State(StateCommands::Show) => {
            output_lines(output.as_ref(), &wallet_state_lines(&paths)?)?;
        }
        Commands::State(StateCommands::Edit { field, value }) => {
            let fingerprint =
                resolve_state_fingerprint(&paths, persist, network, fingerprint).await?;
            let mut wallet = read_wallet(&paths, fingerprint)?.unwrap_or_default();
            wallet.set(field, Some(value));
            write_wallet(&paths, true, fingerprint, &wallet)?;
        }
        Commands::State(StateCommands::Rm { field }) => {
            let fingerprint =
                resolve_state_fingerprint(&paths, persist, network, fingerprint).await?;
            let mut wallet = read_wallet(&paths, fingerprint)?.unwrap_or_default();
            wallet.set(field, None);
            write_wallet(&paths, true, fingerprint, &wallet)?;
        }
    }
    Ok(())
}

fn parse_args() -> Result<Args, Box<dyn Error>> {
    let mut args = std::env::args_os().collect::<Vec<OsString>>();
    let mut stdin = io::stdin();
    if !stdin.is_terminal() {
        let mut input = String::new();
        stdin.read_to_string(&mut input)?;
        args.extend(input.trim_end().split_whitespace().map(OsString::from));
    }
    Ok(Args::parse_from(args))
}

fn matches_fingerprint(expected: Option<Fingerprint>, actual: Fingerprint) -> bool {
    expected.is_none_or(|expected| expected == actual)
}

#[derive(Default, Deserialize, Serialize)]
struct Config {
    persist: bool,
}

struct Paths {
    root: PathBuf,
}

impl Paths {
    fn new() -> Result<Self, Box<dyn Error>> {
        Ok(Self { root: app_dir()? })
    }

    fn config(&self) -> PathBuf {
        self.root.join("config.json")
    }

    fn bitbox(&self) -> PathBuf {
        self.root.join("bitbox.json")
    }

    fn state(&self) -> PathBuf {
        self.root.join("state.json")
    }
}

fn app_dir() -> Result<PathBuf, Box<dyn Error>> {
    #[cfg(target_os = "linux")]
    {
        dirs::home_dir()
            .map(|home| home.join(".async-hwi"))
            .ok_or_else(|| invalid_input("home directory is unavailable"))
    }

    #[cfg(not(target_os = "linux"))]
    {
        dirs::config_dir()
            .map(|dir| dir.join("async-hwi"))
            .ok_or_else(|| invalid_input("config directory is unavailable"))
    }
}

fn read_config(paths: &Paths) -> Result<Config, Box<dyn Error>> {
    read_json_or_default(&paths.config())
}

fn write_config(paths: &Paths, config: Config) -> Result<(), Box<dyn Error>> {
    write_json(&paths.config(), &config)
}

#[derive(Clone, Default)]
struct WalletArgs {
    name: Option<String>,
    descriptor: Option<String>,
    por: Option<String>,
}

impl WalletArgs {
    fn has_any(&self) -> bool {
        self.name.is_some() || self.descriptor.is_some() || self.por.is_some()
    }
}

#[derive(Clone, Default, Deserialize, Serialize)]
struct WalletState {
    #[serde(skip_serializing_if = "Option::is_none")]
    kind: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    descriptor: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    por: Option<String>,
}

impl WalletState {
    fn has_any(&self) -> bool {
        self.name.is_some() || self.descriptor.is_some() || self.por.is_some()
    }

    fn set(&mut self, field: StateField, value: Option<String>) {
        match field {
            StateField::Name => self.name = value,
            StateField::Descriptor => self.descriptor = value,
            StateField::Por => self.por = value,
        }
    }
}

fn wallet_resolver(
    paths: &Paths,
    persist: bool,
    args: WalletArgs,
) -> impl Fn(Fingerprint, DeviceKind) -> Result<Option<command::Wallet>, Box<dyn Error>> + use<'_> {
    move |fingerprint, kind| {
        resolve_wallet_state(paths, persist, fingerprint, &args, Some(kind)).map(|wallet| {
            wallet.map(|wallet| command::Wallet {
                name: wallet.name,
                policy: wallet.descriptor,
                hmac: wallet.por,
            })
        })
    }
}

fn resolve_wallet_state(
    paths: &Paths,
    persist: bool,
    fingerprint: Fingerprint,
    args: &WalletArgs,
    kind: Option<DeviceKind>,
) -> Result<Option<WalletState>, Box<dyn Error>> {
    if !persist && !args.has_any() {
        return Ok(None);
    }

    let mut wallet = if persist {
        read_wallet(paths, fingerprint)?.unwrap_or_default()
    } else {
        WalletState::default()
    };
    merge_state_field(&mut wallet.name, args.name.clone());
    merge_state_field(&mut wallet.descriptor, args.descriptor.clone());
    merge_state_field(&mut wallet.por, args.por.clone());
    set_kind(&mut wallet, kind);

    if persist && wallet.has_any() {
        write_wallet(paths, persist, fingerprint, &wallet)?;
    }

    Ok(wallet.has_any().then_some(wallet))
}

fn set_kind(wallet: &mut WalletState, kind: Option<DeviceKind>) {
    if let Some(kind) = kind {
        wallet.kind = Some(kind.to_string());
    }
}

fn read_wallet(
    paths: &Paths,
    fingerprint: Fingerprint,
) -> Result<Option<WalletState>, Box<dyn Error>> {
    let state: BTreeMap<String, WalletState> = read_json_or_default(&paths.state())?;
    Ok(state.get(&fingerprint.to_string()).cloned())
}

fn write_wallet(
    paths: &Paths,
    persist: bool,
    fingerprint: Fingerprint,
    wallet: &WalletState,
) -> Result<(), Box<dyn Error>> {
    if !persist {
        return Ok(());
    }

    let mut state: BTreeMap<String, WalletState> = read_json_or_default(&paths.state())?;
    state.insert(fingerprint.to_string(), wallet.clone());
    write_json(&paths.state(), &state)
}

fn clear_wallets(paths: &Paths) -> Result<(), Box<dyn Error>> {
    write_json(&paths.state(), &BTreeMap::<String, WalletState>::new())
}

fn wallet_state_lines(paths: &Paths) -> Result<Vec<String>, Box<dyn Error>> {
    let state: BTreeMap<String, WalletState> = read_json_or_default(&paths.state())?;
    json_lines(&state)
}

fn bitbox_pairing_lines(paths: &Paths) -> Result<Vec<String>, Box<dyn Error>> {
    let bitbox: NoiseConfigData = read_json_or_default(&paths.bitbox())?;
    json_lines(&bitbox)
}

fn read_bitbox(paths: &Paths, persist: bool) -> Result<Option<NoiseConfigData>, Box<dyn Error>> {
    if persist {
        read_json_or_default(&paths.bitbox())
    } else {
        Ok(None)
    }
}

fn write_bitbox(
    paths: &Paths,
    persist: bool,
    bitbox: Option<NoiseConfigData>,
) -> Result<(), Box<dyn Error>> {
    if persist {
        if let Some(bitbox) = bitbox {
            write_json(&paths.bitbox(), &bitbox)?;
        }
    }
    Ok(())
}

fn merge_state_field(state_value: &mut Option<String>, arg_value: Option<String>) {
    if arg_value.is_some() {
        *state_value = arg_value;
    }
}

fn wallet_name_for_device(kind: DeviceKind, name: Option<&String>) -> Result<&str, Box<dyn Error>> {
    match kind {
        DeviceKind::Ledger
        | DeviceKind::LedgerSimulator
        | DeviceKind::Coldcard
        | DeviceKind::Jade => name
            .map(String::as_str)
            .ok_or_else(|| invalid_input("wallet name is required")),
        DeviceKind::BitBox02 | DeviceKind::Specter | DeviceKind::SpecterSimulator => Ok(""),
    }
}

fn resolve_psbt(psbt: Option<Psbt>, psbt_file: Option<PathBuf>) -> Result<Psbt, Box<dyn Error>> {
    match (psbt, psbt_file) {
        (Some(_), Some(_)) | (None, None) => Err(invalid_input("use either --psbt or --psbt-file")),
        (Some(psbt), None) => Ok(psbt),
        (None, Some(path)) => Ok(std::fs::read_to_string(path)?.trim_end().parse()?),
    }
}

fn read_json_or_default<T>(path: &Path) -> Result<T, Box<dyn Error>>
where
    T: Default + for<'a> Deserialize<'a>,
{
    if !path.exists() {
        return Ok(T::default());
    }

    let content = std::fs::read_to_string(path)?;
    if content.trim().is_empty() {
        return Ok(T::default());
    }

    Ok(serde_json::from_str(&content)?)
}

fn json_lines<T: Serialize>(value: &T) -> Result<Vec<String>, Box<dyn Error>> {
    Ok(serde_json::to_string_pretty(value)?
        .lines()
        .map(str::to_string)
        .collect())
}

async fn list_devices(
    paths: &Paths,
    persist: bool,
    network: Network,
    wallet: Option<&command::WalletResolver<'_>>,
) -> Result<Vec<command::Device>, Box<dyn Error>> {
    let (devices, bitbox) = command::list(network, wallet, read_bitbox(paths, persist)?).await?;
    write_bitbox(paths, persist, bitbox)?;
    Ok(devices)
}

async fn resolve_state_fingerprint(
    paths: &Paths,
    persist: bool,
    network: Network,
    fingerprint: Option<Fingerprint>,
) -> Result<Fingerprint, Box<dyn Error>> {
    if let Some(fingerprint) = fingerprint {
        return Ok(fingerprint);
    }

    let devices = list_devices(paths, persist, network, None).await?;
    match devices.as_slice() {
        [] => Err(invalid_input("no device connected")),
        [device] => Ok(device.fingerprint),
        _ => {
            let mut lines = vec!["multiple devices connected, pass --fingerprint:".to_string()];
            lines.extend(device_lines(devices).await?);
            Err(invalid_input(lines.join("\n")))
        }
    }
}

async fn device_lines(mut devices: Vec<command::Device>) -> Result<Vec<String>, Box<dyn Error>> {
    let mut lines = Vec::new();
    for device in devices.iter_mut() {
        let mut line = format!("{} {}", device.fingerprint, device.kind);
        if let Ok(version) = device.handle.get_version().await.map(|v| v.to_string()) {
            line.push_str(&format!(" {version}"));
        }
        lines.push(line);
    }
    Ok(lines)
}

fn write_json<T: Serialize + ?Sized>(path: &PathBuf, value: &T) -> Result<(), Box<dyn Error>> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    std::fs::write(path, format!("{}\n", serde_json::to_string_pretty(value)?))?;
    Ok(())
}

fn invalid_input(msg: impl Into<String>) -> Box<dyn Error> {
    io::Error::new(io::ErrorKind::InvalidInput, msg.into()).into()
}

fn output_lines(output: Option<&PathBuf>, lines: &[String]) -> Result<(), Box<dyn Error>> {
    if let Some(output) = output {
        std::fs::write(output, lines.join("\n"))?;
    } else {
        for line in lines {
            println!("{line}");
        }
    }
    Ok(())
}
