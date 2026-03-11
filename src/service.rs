//! Hardware wallet device discovery and management service.
//!
//! Polls for connected hardware wallets every 2 seconds and maintains a shared device map.
//! Supports multiple concurrent consumers via reference-counted start/stop.

use std::{
    collections::BTreeMap,
    fmt::Debug,
    marker::PhantomData,
    sync::{
        atomic::{AtomicBool, AtomicUsize, Ordering},
        Arc, Mutex,
    },
    time::Duration,
};

use crate::{
    bitbox::{api::runtime, BitBox02, PairingBitbox02},
    coldcard,
    jade::{self, api::GetInfoResponse, Jade, SerialTransport},
    ledger, specter, AddressScript, DeviceKind, Error as HWIError, Version, HWI,
};
use bitbox_api::runtime::TokioRuntime;
use bitcoin::{
    bip32::{DerivationPath, Fingerprint, Xpub},
    psbt::Psbt,
    Network,
};
use crossbeam::channel;
use hidapi::{DeviceInfo, HidApi};
use ledger_transport_hidapi::TransportNativeHID;
use serde::{Deserialize, Serialize};
use tokio::task::JoinHandle;

#[cfg(feature = "bitbox")]
use crate::bitbox::{ConfigError, NoiseConfig, NoiseConfigData};

/// Wrapper that implements NoiseConfig by delegating to an Arc<dyn NoiseConfig>.
/// This allows cloning the Arc and converting it to Box<dyn NoiseConfig> for APIs that require Box.
#[cfg(feature = "bitbox")]
struct ArcNoiseConfig(Arc<dyn NoiseConfig>);

#[cfg(feature = "bitbox")]
impl bitbox_api::Threading for ArcNoiseConfig {}

#[cfg(feature = "bitbox")]
impl NoiseConfig for ArcNoiseConfig {
    fn read_config(&self) -> Result<NoiseConfigData, ConfigError> {
        self.0.read_config()
    }
    fn store_config(&self, data: &NoiseConfigData) -> Result<(), ConfigError> {
        self.0.store_config(data)
    }
}

#[derive(Debug, Clone)]
pub enum UnsupportedReason {
    Version {
        minimal_supported_version: &'static str,
    },
    Method(&'static str),
    NotPartOfWallet(Fingerprint),
    WrongNetwork,
    /// Ledger-specific: Bitcoin app not open.
    AppIsNotOpen,
}

pub enum LockedDevice {
    BitBox02(Box<PairingBitbox02<runtime::TokioRuntime>>),
    /// Unlocks via blind oracle (network required).
    Jade(Jade<jade::SerialTransport>),
}

impl Debug for LockedDevice {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::BitBox02(_) => f.debug_tuple("LockedDevice::BitBox02").finish(),
            Self::Jade(_) => f.debug_tuple("LockedDevice::Jade").finish(),
        }
    }
}

#[derive(Debug, Clone)]
pub struct SupportedDevice<Message, Id = ()>
where
    Message: From<SigningDeviceMsg<Id>> + Send + Clone + 'static,
    Id: Send + Clone + 'static,
{
    id: String,
    device: Arc<dyn HWI + Sync + Send>,
    kind: DeviceKind,
    fingerprint: Fingerprint,
    version: Option<Version>,
    rt: tokio::runtime::Handle,
    sender: channel::Sender<Message>,
    _phantom: PhantomData<Id>,
}

impl<Message, Id> SupportedDevice<Message, Id>
where
    Message: From<SigningDeviceMsg<Id>> + Send + Clone + 'static,
    Id: Send + Clone + 'static,
{
    pub fn device(&self) -> &Arc<dyn HWI + Sync + Send> {
        &self.device
    }

    pub fn version(&self) -> Option<&Version> {
        self.version.as_ref()
    }

    pub fn fingerprint(&self) -> &Fingerprint {
        &self.fingerprint
    }

    pub fn kind(&self) -> &DeviceKind {
        &self.kind
    }

    pub fn get_extended_pubkey(&self, id: Id, path: &DerivationPath) {
        let path = path.clone();
        let sender = self.sender.clone();
        let fg = self.fingerprint;
        let device = self.device.clone();
        tracing::debug!(
            "SupportedDevice[{}]::get_extended_pubkey: spawning task, path={:?}",
            fg,
            path
        );
        self.rt.spawn(async move {
            match (*device).get_extended_pubkey(&path).await {
                Ok(xpub) => {
                    tracing::debug!(
                        "SupportedDevice[{}]::get_extended_pubkey: success, xpub={}",
                        fg,
                        xpub
                    );
                    let _ = sender.send(SigningDeviceMsg::XPub(id, fg, path, xpub).into());
                }
                Err(e) => {
                    tracing::debug!("SupportedDevice[{}]::get_extended_pubkey: error={}", fg, e);
                    let _ = sender.send(SigningDeviceMsg::Error(Some(id), e.to_string()).into());
                }
            }
        });
    }

    pub fn register_wallet(&self, id: Id, name: &str, policy: &str) {
        let name = name.to_string();
        let policy = policy.to_string();
        let sender = self.sender.clone();
        let fg = self.fingerprint;
        let device = self.device.clone();
        tracing::debug!(
            "SupportedDevice[{}]::register_wallet: spawning task, name={}, policy={}",
            fg,
            name,
            policy
        );
        self.rt.spawn(async move {
            match (*device).register_wallet(&name, &policy).await {
                Ok(hmac) => {
                    tracing::debug!(
                        "SupportedDevice[{}]::register_wallet: success, hmac={:?}",
                        fg,
                        hmac
                    );
                    let _ =
                        sender.send(SigningDeviceMsg::WalletRegistered(id, fg, name, hmac).into());
                }
                Err(e) => {
                    tracing::debug!("SupportedDevice[{}]::register_wallet: error={}", fg, e);
                    let _ = sender.send(SigningDeviceMsg::Error(Some(id), e.to_string()).into());
                }
            }
        });
    }

    pub fn is_wallet_registered(&self, id: Id, name: &str, policy: &str) {
        let name = name.to_string();
        let policy = policy.to_string();
        let sender = self.sender.clone();
        let fg = self.fingerprint;
        let device = self.device.clone();
        tracing::debug!(
            "SupportedDevice[{}]::is_wallet_registered: spawning task, name={}, policy={}",
            fg,
            name,
            policy
        );
        self.rt.spawn(async move {
            match (*device).is_wallet_registered(&name, &policy).await {
                Ok(registered) => {
                    tracing::debug!(
                        "SupportedDevice[{}]::is_wallet_registered: success, registered={}",
                        fg,
                        registered
                    );
                    let _ = sender.send(
                        SigningDeviceMsg::WalletIsRegistered(id, fg, name, registered).into(),
                    );
                }
                Err(e) => {
                    tracing::debug!("SupportedDevice[{}]::is_wallet_registered: error={}", fg, e);
                    let _ = sender.send(SigningDeviceMsg::Error(Some(id), e.to_string()).into());
                }
            }
        });
    }

    pub fn display_address(&self, id: Id, script: &AddressScript) {
        let script = script.clone();
        let sender = self.sender.clone();
        let fg = self.fingerprint;
        let device = self.device.clone();
        tracing::debug!(
            "SupportedDevice[{}]::display_address: spawning task, script={:?}",
            fg,
            script
        );
        self.rt.spawn(async move {
            match (*device).display_address(&script).await {
                Ok(()) => {
                    tracing::debug!("SupportedDevice[{}]::display_address: success", fg);
                    let _ = sender.send(SigningDeviceMsg::AddressDisplayed(id, fg, script).into());
                }
                Err(e) => {
                    tracing::debug!("SupportedDevice[{}]::display_address: error={}", fg, e);
                    let _ = sender.send(SigningDeviceMsg::Error(Some(id), e.to_string()).into());
                }
            }
        });
    }

    pub fn sign_tx(&self, id: Id, tx: Psbt) {
        let mut tx = tx;
        let sender = self.sender.clone();
        let fg = self.fingerprint;
        let device = self.device.clone();
        tracing::debug!("SupportedDevice[{}]::sign_tx: spawning task", fg);
        self.rt.spawn(async move {
            match (*device).sign_tx(&mut tx).await {
                Ok(()) => {
                    tracing::debug!("SupportedDevice[{}]::sign_tx: success", fg);
                    let _ = sender.send(SigningDeviceMsg::TransactionSigned(id, fg, tx).into());
                }
                Err(e) => {
                    tracing::debug!("SupportedDevice[{}]::sign_tx: error={}", fg, e);
                    let _ = sender.send(SigningDeviceMsg::Error(Some(id), e.to_string()).into());
                }
            }
        });
    }
}

#[derive(Debug, Clone)]
pub enum SigningDevice<Message, Id = ()>
where
    Message: From<SigningDeviceMsg<Id>> + Send + Clone + 'static,
    Id: Send + Clone + 'static,
{
    Unsupported {
        id: String,
        kind: DeviceKind,
        version: Option<Version>,
        reason: UnsupportedReason,
    },
    /// Inner Option is None while unlock is in progress.
    Locked {
        id: String,
        device: Arc<Mutex<Option<LockedDevice>>>,
        /// BitBox02 only.
        pairing_code: Option<String>,
        kind: DeviceKind,
    },
    Supported(SupportedDevice<Message, Id>),
}

impl<Message, Id> SigningDevice<Message, Id>
where
    Message: From<SigningDeviceMsg<Id>> + Send + Clone + 'static,
    Id: Send + Clone + 'static,
{
    async fn new(
        id: String,
        device: Arc<dyn HWI + Send + Sync>,
        rt: tokio::runtime::Handle,
        sender: channel::Sender<Message>,
    ) -> Result<Self, HWIError> {
        let kind = device.device_kind();
        let fingerprint = device.get_master_fingerprint().await?;
        let version = device.get_version().await.ok();
        Ok(Self::Supported(SupportedDevice {
            id,
            device,
            kind,
            fingerprint,
            version,
            rt,
            sender,
            _phantom: PhantomData,
        }))
    }

    /// Stable device identifier (serial-based when available).
    /// Use this as the key for `set_bitbox_config`.
    pub fn id(&self) -> &str {
        match self {
            Self::Locked { id, .. } => id,
            Self::Unsupported { id, .. } => id,
            Self::Supported(SupportedDevice { id, .. }) => id,
        }
    }

    pub fn kind(&self) -> &DeviceKind {
        match self {
            Self::Locked { kind, .. } => kind,
            Self::Unsupported { kind, .. } => kind,
            Self::Supported(SupportedDevice { kind, .. }) => kind,
        }
    }

    pub fn fingerprint(&self) -> Option<Fingerprint> {
        match self {
            Self::Locked { .. } => None,
            Self::Unsupported { .. } => None,
            Self::Supported(SupportedDevice { fingerprint, .. }) => Some(*fingerprint),
        }
    }

    pub fn is_supported(&self) -> bool {
        matches!(self, Self::Supported { .. })
    }

    pub fn clone_locked(&self) -> Option<SigningDevice<Message, Id>> {
        if let SigningDevice::Locked {
            id,
            device,
            pairing_code,
            kind,
        } = self
        {
            Some(SigningDevice::Locked {
                id: id.clone(),
                device: device.clone(),
                pairing_code: pairing_code.clone(),
                kind: *kind,
            })
        } else {
            None
        }
    }
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct SigningDeviceConfig {
    pub kind: String,
    pub fingerprint: Fingerprint,
    /// Hex-encoded 32-byte token.
    pub token: String,
}

impl SigningDeviceConfig {
    pub fn new(kind: &crate::DeviceKind, fingerprint: Fingerprint, token: &[u8; 32]) -> Self {
        Self {
            kind: kind.to_string(),
            fingerprint,
            token: hex::encode(token),
        }
    }
}

#[derive(Debug, Clone)]
pub enum SigningDeviceMsg<Id = ()> {
    /// Error with optional request Id (None for polling loop errors, Some for forwarding method errors).
    Error(Option<Id>, String),
    /// Device map changed.
    Update,
    XPub(Id, Fingerprint, DerivationPath, Xpub),
    Version(Id, Fingerprint, Version),
    /// Wallet registered with name and optional HMAC.
    WalletRegistered(Id, Fingerprint, String, Option<[u8; 32]>),
    /// Wallet registration check result.
    WalletIsRegistered(Id, Fingerprint, String, bool),
    /// Address displayed on device.
    AddressDisplayed(Id, Fingerprint, AddressScript),
    /// Transaction signed.
    TransactionSigned(Id, Fingerprint, Psbt),
}

pub struct HwiService<Message, Id = ()>
where
    Message: From<SigningDeviceMsg<Id>> + Send + Clone + 'static,
    Id: Send + Clone + 'static,
{
    network: Network,
    rt: tokio::runtime::Handle,
    /// Holds the runtime if we created it internally (keeps it alive).
    _owned_runtime: Option<tokio::runtime::Runtime>,
    pub devices: Arc<Mutex<BTreeMap<String, SigningDevice<Message, Id>>>>,
    // Reference counting for multiple modal consumers
    ref_count: Arc<AtomicUsize>,
    shutdown: Arc<AtomicBool>,
    listener_handle: Arc<Mutex<Option<std::thread::JoinHandle<()>>>>,
    // BitBox02 pairing configuration. Contains the app's private key and public keys
    // of all paired devices. The NoiseConfigData can store multiple device pubkeys,
    // so a single config works for all devices.
    #[cfg(feature = "bitbox")]
    bitbox_noise_config: Arc<Mutex<Option<Arc<dyn NoiseConfig>>>>,
}

impl<Message, Id> HwiService<Message, Id>
where
    Message: From<SigningDeviceMsg<Id>> + Send + 'static + Clone,
    Id: Send + Clone + 'static,
{
    pub fn new(network: Network, rt: Option<tokio::runtime::Handle>) -> Self {
        let (rt, owned_runtime) = if let Some(handle) = rt {
            tracing::debug!("HwiService: using consumer-provided tokio runtime handle");
            (handle, None)
        } else {
            tracing::debug!("HwiService: creating new internal tokio runtime");
            let runtime = tokio::runtime::Runtime::new().expect("runtime must not fail");
            let handle = runtime.handle().clone();
            (handle, Some(runtime))
        };
        tracing::debug!("HwiService::new: network={:?}", network);
        Self {
            network,
            devices: Default::default(),
            rt,
            _owned_runtime: owned_runtime,
            ref_count: Arc::new(AtomicUsize::new(0)),
            shutdown: Arc::new(AtomicBool::new(false)),
            listener_handle: Arc::new(Mutex::new(None)),
            #[cfg(feature = "bitbox")]
            bitbox_noise_config: Arc::new(Mutex::new(None)),
        }
    }

    pub fn list(&self) -> BTreeMap<String, SigningDevice<Message, Id>> {
        self.devices.lock().expect("poisoned").clone()
    }

    /// Set the BitBox02 pairing configuration. The NoiseConfigData contains the app's
    /// private key and public keys of all paired devices, so a single config works
    /// for all BitBox02 devices.
    #[cfg(feature = "bitbox")]
    pub fn set_bitbox_noise_config(&self, noise_config: Arc<dyn NoiseConfig>) {
        tracing::debug!("Setting BitBox02 pairing configuration");
        *self.bitbox_noise_config.lock().expect("poisoned") = Some(noise_config);
    }

    /// Clear the BitBox02 pairing configuration.
    #[cfg(feature = "bitbox")]
    pub fn clear_bitbox_noise_config(&self) {
        tracing::debug!("Clearing BitBox02 pairing configuration");
        *self.bitbox_noise_config.lock().expect("poisoned") = None;
    }

    pub fn listen(&self, sender: channel::Sender<Message>, shutdown: Arc<AtomicBool>) {
        listen(
            sender,
            self.devices.clone(),
            self.network,
            self.rt.clone(),
            shutdown,
            #[cfg(feature = "bitbox")]
            self.bitbox_noise_config.clone(),
        );
    }

    /// Ref-counted start; only first caller spawns the listener thread.
    pub fn start(&self, sender: channel::Sender<Message>) {
        let prev_count = self.ref_count.fetch_add(1, Ordering::SeqCst);
        let new_count = prev_count + 1;

        if prev_count == 0 {
            // First caller - start the listener
            tracing::info!(
                "Starting HWI listener service (ref_count: {} -> {})",
                prev_count,
                new_count
            );
            self.shutdown.store(false, Ordering::SeqCst);

            let sender = sender.clone();
            let devices = self.devices.clone();
            let network = self.network;
            let rt = self.rt.clone();
            let shutdown = self.shutdown.clone();
            #[cfg(feature = "bitbox")]
            let bitbox_noise_config = self.bitbox_noise_config.clone();

            let handle = std::thread::spawn(move || {
                tracing::debug!("HWI listener thread started");
                listen(
                    sender,
                    devices,
                    network,
                    rt,
                    shutdown,
                    #[cfg(feature = "bitbox")]
                    bitbox_noise_config,
                );
                tracing::debug!("HWI listener thread stopped");
            });

            *self.listener_handle.lock().expect("poisoned") = Some(handle);
        } else {
            tracing::debug!(
                "HWI listener already running, incrementing ref_count: {} -> {}",
                prev_count,
                new_count
            );
        }
    }

    /// Ref-counted stop; only last caller joins the listener thread.
    pub fn stop(&self) {
        tracing::debug!("stop() called");
        // Use compare-and-swap loop to safely decrement only when > 0
        loop {
            let current = self.ref_count.load(Ordering::SeqCst);
            if current == 0 {
                tracing::warn!("stop() called but ref_count is already 0");
                return;
            }
            match self.ref_count.compare_exchange(
                current,
                current - 1,
                Ordering::SeqCst,
                Ordering::SeqCst,
            ) {
                Ok(prev_count) => {
                    let new_count = prev_count - 1;
                    if prev_count == 1 {
                        // Last caller - stop the listener
                        tracing::info!(
                            "Stopping HWI listener service (ref_count: {} -> {})",
                            prev_count,
                            new_count
                        );
                        self.shutdown.store(true, Ordering::SeqCst);

                        // Take the handle - the thread will stop on its own when it sees the shutdown flag
                        let _ = self.listener_handle.lock().expect("poisoned").take();
                    } else {
                        tracing::debug!(
                            "HWI listener still in use, decrementing ref_count: {} -> {}",
                            prev_count,
                            new_count
                        );
                    }
                    return;
                }
                Err(_) => {
                    // Another thread modified ref_count, retry
                    continue;
                }
            }
        }
    }
}

impl<Message, Id> Drop for HwiService<Message, Id>
where
    Message: From<SigningDeviceMsg<Id>> + Send + Clone + 'static,
    Id: Send + Clone + 'static,
{
    fn drop(&mut self) {
        if self._owned_runtime.is_some() {
            tracing::debug!(
                "HwiService dropped - internal tokio runtime will be shut down, \
                any pending async tasks will be cancelled"
            );
        } else {
            tracing::debug!("HwiService dropped (using external runtime)");
        }
    }
}

#[cfg(feature = "bitbox")]
async fn unlock_bitbox<Message, Id>(
    id: String,
    network: Network,
    bb: Box<PairingBitbox02<runtime::TokioRuntime>>,
    rt: tokio::runtime::Handle,
    sender: channel::Sender<Message>,
) -> Result<SigningDevice<Message, Id>, crate::Error>
where
    Message: From<SigningDeviceMsg<Id>> + Send + Clone + 'static,
    Id: Send + Clone + 'static,
{
    tracing::debug!("unlock_bitbox[{}]: waiting for pairing confirmation", id);
    let paired_bb = bb.wait_confirm().await?;
    tracing::debug!("unlock_bitbox[{}]: pairing confirmed", id);
    let bitbox2 = BitBox02::from(paired_bb).with_network(network);
    tracing::debug!("unlock_bitbox[{}]: getting fingerprint", id);
    let fingerprint = bitbox2.get_master_fingerprint().await?;
    tracing::debug!("unlock_bitbox[{}]: fingerprint={}", id, fingerprint);
    let version = bitbox2.get_version().await.ok();
    tracing::debug!("unlock_bitbox[{}]: version={:?}", id, version);
    tracing::debug!(
        "unlock_bitbox[{}]: returning Supported device with fingerprint={}",
        id,
        fingerprint
    );
    Ok(SigningDevice::Supported(SupportedDevice {
        id: id.clone(),
        kind: DeviceKind::BitBox02,
        fingerprint,
        device: bitbox2.into(),
        version,
        rt,
        sender,
        _phantom: PhantomData,
    }))
}

fn listen<Message, Id>(
    sender: channel::Sender<Message>,
    devices: Arc<Mutex<BTreeMap<String, SigningDevice<Message, Id>>>>,
    network: Network,
    rt: tokio::runtime::Handle,
    shutdown: Arc<AtomicBool>,
    #[cfg(feature = "bitbox")] bitbox_noise_config: Arc<Mutex<Option<Arc<dyn NoiseConfig>>>>,
) where
    Message: From<SigningDeviceMsg<Id>> + Send + Clone + 'static,
    Id: Send + Clone + 'static,
{
    tracing::info!("HWI listener starting for network: {:?}", network);

    let mut hid = match ledger::HidApi::new() {
        Ok(api) => {
            tracing::debug!("HID API initialized successfully");
            api
        }
        Err(e) => {
            tracing::error!("Failed to initialize HID API: {}", e);
            let _ = sender.send(SigningDeviceMsg::Error(None, e.to_string()).into());
            return;
        }
    };

    #[cfg(feature = "specter")]
    let mut specter_simulator_handle = None;
    #[cfg(feature = "specter")]
    let mut specter_handles = BTreeMap::<String, JoinHandle<()>>::new();
    #[cfg(feature = "jade")]
    let mut jade_handles = BTreeMap::<String, JoinHandle<()>>::new();
    #[cfg(feature = "ledger")]
    let mut ledger_simulator_handle = None;
    #[cfg(feature = "bitbox")]
    let mut bitbox02_handles = BTreeMap::<String, JoinHandle<()>>::new();
    #[cfg(feature = "coldcard")]
    let mut coldcard_handles = BTreeMap::<String, JoinHandle<()>>::new();
    #[cfg(feature = "ledger")]
    let mut ledger_handles = BTreeMap::<String, JoinHandle<()>>::new();

    loop {
        // Check for shutdown signal
        if shutdown.load(Ordering::Relaxed) {
            tracing::info!("HWI listener received shutdown signal, exiting");
            return;
        }

        tracing::debug!("HWI poll cycle starting");

        if let Err(e) = hid.refresh_devices() {
            tracing::warn!("Failed to refresh HID devices: {}", e);
            let _ = sender.send(SigningDeviceMsg::Error(None, e.to_string()).into());
            continue;
        };

        tracing::trace!("HID devices refreshed successfully");

        #[cfg(feature = "specter")]
        handle_specter_simulator(
            &rt,
            sender.clone(),
            &mut specter_simulator_handle,
            devices.clone(),
        );

        #[cfg(feature = "specter")]
        handle_specter(&rt, sender.clone(), &mut specter_handles, devices.clone());

        #[cfg(feature = "jade")]
        handle_jade(&rt, &sender, &mut jade_handles, devices.clone(), network);

        #[cfg(feature = "ledger")]
        handle_ledger_simulator(
            &rt,
            sender.clone(),
            &mut ledger_simulator_handle,
            devices.clone(),
        );

        let list = hid.device_list().collect::<Vec<_>>();
        tracing::trace!("HID device list contains {} device(s)", list.len());

        #[cfg(feature = "bitbox")]
        let bitbox_devices: Vec<_> = list
            .iter()
            .filter_map(|d| crate::bitbox::is_bitbox02(d).then_some(*d))
            .collect();
        #[cfg(feature = "bitbox")]
        tracing::trace!(
            "Filtered {} BitBox02 device(s) from HID list",
            bitbox_devices.len()
        );

        #[cfg(feature = "bitbox")]
        handle_bitbox02(
            &rt,
            &sender,
            &mut bitbox02_handles,
            devices.clone(),
            bitbox_devices,
            &hid,
            network,
            bitbox_noise_config.clone(),
        );

        #[cfg(feature = "coldcard")]
        let coldcard_devices: Vec<_> = list
            .iter()
            .filter_map(|d| crate::coldcard::is_coldcard(d).then_some(*d))
            .collect();
        #[cfg(feature = "coldcard")]
        tracing::trace!(
            "Filtered {} Coldcard device(s) from HID list",
            coldcard_devices.len()
        );

        #[cfg(feature = "coldcard")]
        handle_coldcard(
            &rt,
            &sender,
            &mut coldcard_handles,
            devices.clone(),
            coldcard_devices,
            &hid,
        );

        #[cfg(feature = "ledger")]
        let ledger_devices: Vec<_> = TransportNativeHID::list_ledgers(&hid).collect();
        #[cfg(feature = "ledger")]
        tracing::trace!("Found {} Ledger device(s)", ledger_devices.len());

        #[cfg(feature = "ledger")]
        handle_ledger(
            &rt,
            &sender,
            &mut ledger_handles,
            devices.clone(),
            ledger_devices,
            &hid,
        );

        tracing::trace!("HWI poll cycle complete, sleeping for 2 seconds");
        std::thread::sleep(Duration::from_secs(2));
    }
}

#[cfg(feature = "specter")]
fn handle_specter_simulator<Message, Id>(
    rt: &tokio::runtime::Handle,
    sender: channel::Sender<Message>,
    handle: &mut Option<tokio::task::JoinHandle<()>>,
    devices: Arc<Mutex<BTreeMap<String, SigningDevice<Message, Id>>>>,
) where
    Message: From<SigningDeviceMsg<Id>> + Send + Clone + 'static,
    Id: Send + Clone + 'static,
{
    const SPECTER_SIMULATOR_ID: &str = "specter-simulator";
    // If device is already in the map, don't poll it again
    if devices
        .lock()
        .expect("poisoned")
        .contains_key(SPECTER_SIMULATOR_ID)
    {
        tracing::trace!("handle_specter_simulator: device already in map, skipping");
        return;
    }
    let poll = if let Some(h) = handle {
        if h.is_finished() {
            tracing::trace!("handle_specter_simulator: previous handle finished, will poll");
            *handle = None;
            true
        } else {
            tracing::debug!("handle_specter_simulator: previous handle still running, skipping");
            false
        }
    } else {
        tracing::trace!("handle_specter_simulator: no handle, will poll");
        true
    };
    if poll {
        tracing::trace!("handle_specter_simulator: spawning async task");
        let rt_ = rt.clone();
        let jh = rt.spawn(async move {
            tracing::trace!("handle_specter_simulator: calling try_connect");
            match specter::SpecterSimulator::try_connect().await {
                Ok(device) => {
                    tracing::debug!("handle_specter_simulator: creating SigningDevice");
                    match SigningDevice::new(
                        SPECTER_SIMULATOR_ID.into(),
                        Arc::new(device),
                        rt_,
                        sender.clone(),
                    )
                    .await
                    {
                        Ok(hw) => {
                            tracing::debug!("handle_specter_simulator: inserting device into map");
                            devices
                                .lock()
                                .expect("poisoned")
                                .insert(SPECTER_SIMULATOR_ID.into(), hw);
                            let _ = sender.send(SigningDeviceMsg::Update.into());
                        }
                        Err(e) => {
                            tracing::debug!("Failed to initialize Specter Simulator: {}", e);
                        }
                    }
                }
                Err(HWIError::DeviceNotFound) => {
                    tracing::trace!("handle_specter_simulator: DeviceNotFound");
                    let was_present = devices
                        .lock()
                        .expect("poisoned")
                        .remove(SPECTER_SIMULATOR_ID)
                        .is_some();
                    if was_present {
                        tracing::debug!("handle_specter_simulator: removed from device map");
                        let _ = sender.send(SigningDeviceMsg::Update.into());
                    }
                }
                Err(e) => {
                    tracing::trace!("Specter Simulator not available: {}", e);
                }
            }
        });
        *handle = Some(jh);
    }
}

fn should_poll<Message, Id>(
    handles: &BTreeMap<String, JoinHandle<()>>,
    devices: &Arc<Mutex<BTreeMap<String, SigningDevice<Message, Id>>>>,
    id: &str,
) -> bool
where
    Message: From<SigningDeviceMsg<Id>> + Send + Clone + 'static,
    Id: Send + Clone + 'static,
{
    // If device is already in the map, don't poll it again
    if devices.lock().expect("poisoned").contains_key(id) {
        tracing::trace!(
            "should_poll({}): device already in map, returning false",
            id
        );
        return false;
    }

    let result = match handles.get(id) {
        Some(h) => {
            let finished = h.is_finished();
            tracing::trace!(
                "should_poll({}): handle exists, is_finished={}",
                id,
                finished
            );
            finished
        }
        None => {
            tracing::trace!("should_poll({}): no handle, returning true", id);
            true
        }
    };
    result
}

fn cleanup_disconnected<Message, Id>(
    sender: &channel::Sender<Message>,
    handles: &mut BTreeMap<String, JoinHandle<()>>,
    devices: &Arc<Mutex<BTreeMap<String, SigningDevice<Message, Id>>>>,
    connected_ids: &[String],
    prefix: &str,
) where
    Message: From<SigningDeviceMsg<Id>> + Send + Clone + 'static,
    Id: Send + Clone + 'static,
{
    tracing::trace!(
        "cleanup_disconnected: checking prefix '{}', connected_ids={:?}",
        prefix,
        connected_ids
    );

    let ids_to_remove: Vec<_> = {
        let devices_lock = devices.lock().expect("poisoned");
        let current_ids: Vec<_> = devices_lock
            .keys()
            .filter(|id| id.starts_with(prefix))
            .cloned()
            .collect();
        tracing::trace!(
            "cleanup_disconnected: current devices with prefix '{}': {:?}",
            prefix,
            current_ids
        );
        current_ids
            .into_iter()
            .filter(|id| !connected_ids.contains(id))
            .collect()
    };

    if !ids_to_remove.is_empty() {
        tracing::trace!(
            "Removing {} disconnected device(s) with prefix '{}': {:?}",
            ids_to_remove.len(),
            prefix,
            ids_to_remove
        );
        let mut devices_lock = devices.lock().expect("poisoned");
        for id in &ids_to_remove {
            tracing::debug!("cleanup_disconnected: removing device {}", id);
            devices_lock.remove(id);
            handles.remove(id);
        }
        let _ = sender.send(SigningDeviceMsg::Update.into());
    } else {
        tracing::trace!(
            "cleanup_disconnected: no devices to remove for prefix '{}'",
            prefix
        );
    }
}

#[cfg(feature = "specter")]
fn handle_specter<Message, Id>(
    rt: &tokio::runtime::Handle,
    sender: channel::Sender<Message>,
    handles: &mut BTreeMap<String, tokio::task::JoinHandle<()>>,
    devices: Arc<Mutex<BTreeMap<String, SigningDevice<Message, Id>>>>,
) where
    Message: From<SigningDeviceMsg<Id>> + Send + Clone + 'static,
    Id: Send + Clone + 'static,
{
    fn specter_id(port: &str) -> String {
        let id = format!("specter-{port}");
        id.replace("\"", "")
    }
    tracing::trace!("handle_specter: enumerating potential ports");
    match specter::SerialTransport::enumerate_potential_ports() {
        Ok(ports) => {
            if !ports.is_empty() {
                tracing::debug!("Found {} potential Specter port(s)", ports.len());
            }
            tracing::trace!("handle_specter: ports={:?}", ports);
            let connected_ids: Vec<_> = ports.iter().map(|p| specter_id(p)).collect();
            cleanup_disconnected(&sender, handles, &devices, &connected_ids, "specter-");

            for port in ports {
                let id = specter_id(&port);
                tracing::trace!("handle_specter: checking port {} (id={})", port, id);
                if !should_poll(handles, &devices, &id) {
                    tracing::trace!("handle_specter: skipping {} (should_poll=false)", id);
                    continue;
                }

                tracing::trace!("handle_specter: spawning async task for device {}", id);
                let devices = devices.clone();
                let sender = sender.clone();
                let id_ = id.clone();
                let port_clone = port.clone();
                let rt_ = rt.clone();
                let jh = rt.spawn(async move {
                    tracing::trace!(
                        "handle_specter[{}]: creating Specter device on {}",
                        id_,
                        port_clone
                    );
                    let device =
                        match specter::Specter::<specter::SerialTransport>::new(port_clone.clone())
                        {
                            Err(e) => {
                                tracing::trace!(
                                    "Failed to create Specter device on {}: {}",
                                    port_clone,
                                    e
                                );
                                return;
                            }
                            Ok(device) => device,
                        };
                    tracing::trace!("handle_specter[{}]: checking fingerprint with timeout", id_);
                    if tokio::time::timeout(
                        std::time::Duration::from_millis(500),
                        device.fingerprint(),
                    )
                    .await
                    .is_ok()
                    {
                        tracing::debug!(
                            "handle_specter[{}]: creating SigningDevice on port {}",
                            id_,
                            port_clone
                        );
                        match SigningDevice::new(id_.clone(), Arc::new(device), rt_, sender.clone())
                            .await
                        {
                            Ok(hw) => {
                                tracing::debug!(
                                    "handle_specter[{}]: inserting device into map",
                                    id_
                                );
                                devices.lock().expect("poisoned").insert(id_, hw);
                                let _ = sender.send(SigningDeviceMsg::Update.into());
                            }
                            Err(e) => {
                                tracing::error!(
                                    "Failed to initialize Specter on {}: {}",
                                    port_clone,
                                    e
                                );
                            }
                        }
                    } else {
                        tracing::trace!("Specter device timeout on port {}", port_clone);
                    }
                });
                handles.insert(id, jh);
            }
        }
        Err(e) => tracing::error!("Error while listing specter wallets: {}", e),
    }
}

#[cfg(feature = "jade")]
fn handle_jade<Message, Id>(
    rt: &tokio::runtime::Handle,
    sender: &channel::Sender<Message>,
    handles: &mut BTreeMap<String, tokio::task::JoinHandle<()>>,
    devices: Arc<Mutex<BTreeMap<String, SigningDevice<Message, Id>>>>,
    network: Network,
) where
    Message: From<SigningDeviceMsg<Id>> + Send + Clone + 'static,
    Id: Send + Clone + 'static,
{
    fn jade_id(port: &str) -> String {
        let id = format!("jade-{port}");
        id.replace("\"", "")
    }

    tracing::trace!("handle_jade: enumerating potential ports");
    match jade::SerialTransport::enumerate_potential_ports() {
        Ok(ports) => {
            if !ports.is_empty() {
                tracing::debug!("Found {} potential Jade port(s)", ports.len());
            }
            tracing::trace!("handle_jade: ports={:?}", ports);
            let connected_ids: Vec<_> = ports.iter().map(|p| jade_id(p)).collect();
            cleanup_disconnected(sender, handles, &devices, &connected_ids, "jade-");

            for port in ports {
                let id = jade_id(&port);
                tracing::trace!("handle_jade: checking port {} (id={})", port, id);
                if !should_poll(handles, &devices, &id) {
                    tracing::trace!("handle_jade: skipping {} (should_poll=false)", id);
                    continue;
                }

                tracing::trace!("handle_jade: spawning async task for device {}", id);
                let devices = devices.clone();
                let sender = sender.clone();
                let id_ = id.clone();
                let port_clone = port.clone();
                let rt_ = rt.clone();
                let jh = rt.spawn(async move {
                    // Create Jade transport inside tokio runtime context (required by tokio-serial)
                    tracing::trace!("handle_jade[{}]: creating transport on {}", id_, port_clone);
                    let transport = match jade::SerialTransport::new(port_clone.clone()) {
                        Err(e) => {
                            tracing::error!(
                                "Failed to create Jade transport on {}: {:?}",
                                port_clone,
                                e
                            );
                            return;
                        }
                        Ok(transport) => transport,
                    };
                    tracing::trace!("handle_jade[{}]: getting device info", id_);
                    let device = Jade::new(transport).with_network(network);
                    let info = match device.get_info().await {
                        Ok(i) => {
                            tracing::debug!(
                                "handle_jade[{}]: got info, state={:?}, version={}",
                                id_,
                                i.jade_state,
                                i.jade_version
                            );
                            i
                        }
                        Err(e) => {
                            tracing::error!("Failed to get Jade info on {}: {}", port_clone, e);
                            return;
                        }
                    };
                    tracing::debug!(
                        "Jade device detected on port {} (state: {:?})",
                        port_clone,
                        info.jade_state
                    );
                    let version = crate::parse_version(&info.jade_version).ok();
                    tracing::debug!("handle_jade[{}]: calling handle_jade_device", id_);
                    if let Some(dev) = handle_jade_device(
                        info,
                        network,
                        device,
                        id_.clone(),
                        version,
                        rt_.clone(),
                        sender.clone(),
                    )
                    .await
                    {
                        tracing::debug!(
                            "handle_jade[{}]: device created, variant={:?}",
                            id_,
                            match &dev {
                                SigningDevice::Supported(_) => "Supported",
                                SigningDevice::Locked { .. } => "Locked",
                                SigningDevice::Unsupported { .. } => "Unsupported",
                            }
                        );
                        let locked = dev.clone_locked();
                        devices.lock().expect("poisoned").insert(id_.clone(), dev);
                        let _ = sender.send(SigningDeviceMsg::Update.into());
                        if let Some(SigningDevice::Locked { device, .. }) = locked {
                            tracing::debug!(
                                "handle_jade[{}]: device is locked, attempting unlock",
                                id_
                            );
                            let jade = match device.lock().expect("poisoned").take() {
                                Some(LockedDevice::Jade(jade)) => Some(jade),
                                _ => None,
                            };
                            if let Some(jade) = jade {
                                handle_locked_jade(jade, id_, devices, network, rt_, sender).await
                            }
                        }
                    } else {
                        tracing::trace!("handle_jade[{}]: handle_jade_device returned None", id_);
                    }
                });
                handles.insert(id, jh);
            }
        }
        Err(e) => tracing::warn!("Error while listing jade devices: {}", e),
    }
}

#[cfg(feature = "jade")]
async fn handle_jade_device<Message, Id>(
    info: GetInfoResponse,
    network: Network,
    device: Jade<SerialTransport>,
    id: String,
    version: Option<Version>,
    rt: tokio::runtime::Handle,
    sender: channel::Sender<Message>,
) -> Option<SigningDevice<Message, Id>>
where
    Message: From<SigningDeviceMsg<Id>> + Send + Clone + 'static,
    Id: Send + Clone + 'static,
{
    tracing::debug!(
        "handle_jade_device[{}]: network={:?}, jade_networks={:?}, jade_state={:?}",
        id,
        network,
        info.jade_networks,
        info.jade_state
    );

    if (network == Network::Bitcoin
        && info.jade_networks != jade::api::JadeNetworks::Main
        && info.jade_networks != jade::api::JadeNetworks::All)
        || (network != Network::Bitcoin && info.jade_networks == jade::api::JadeNetworks::Main)
    {
        tracing::debug!(
            "handle_jade_device[{}]: network mismatch, returning Unsupported",
            id
        );
        Some(SigningDevice::Unsupported {
            id,
            kind: device.device_kind(),
            version,
            reason: UnsupportedReason::WrongNetwork,
        })
    } else {
        match info.jade_state {
            jade::api::JadeState::Locked
            | jade::api::JadeState::Temp
            | jade::api::JadeState::Uninit
            | jade::api::JadeState::Unsaved => {
                tracing::debug!(
                    "handle_jade_device[{}]: state={:?}, returning Locked",
                    id,
                    info.jade_state
                );
                Some(SigningDevice::Locked {
                    id,
                    kind: DeviceKind::Jade,
                    pairing_code: None,
                    device: Arc::new(Mutex::new(Some(LockedDevice::Jade(device)))),
                })
            }
            jade::api::JadeState::Ready => {
                tracing::debug!(
                    "handle_jade_device[{}]: state=Ready, getting fingerprint",
                    id
                );
                let kind = device.device_kind();
                let version = device.get_version().await.ok();
                let fingerprint = match device.get_master_fingerprint().await {
                    Err(HWIError::NetworkMismatch) => {
                        tracing::debug!(
                            "handle_jade_device[{}]: fingerprint returned NetworkMismatch",
                            id
                        );
                        return Some(SigningDevice::Unsupported {
                            id: id.clone(),
                            kind,
                            version,
                            reason: UnsupportedReason::WrongNetwork,
                        });
                    }
                    Err(e) => {
                        tracing::error!("{e}");
                        return None;
                    }
                    Ok(fingerprint) => {
                        tracing::debug!(
                            "handle_jade_device[{}]: got fingerprint={}",
                            id,
                            fingerprint
                        );
                        fingerprint
                    }
                };
                tracing::debug!(
                    "handle_jade_device[{}]: returning Supported with fingerprint={}",
                    id,
                    fingerprint
                );
                Some(SigningDevice::Supported(SupportedDevice {
                    id: id.clone(),
                    kind,
                    fingerprint,
                    device: Arc::new(device),
                    version,
                    rt,
                    sender,
                    _phantom: PhantomData,
                }))
            }
        }
    }
}

#[cfg(feature = "jade")]
async fn handle_locked_jade<Message, Id>(
    device: Jade<SerialTransport>,
    id: String,
    devices: Arc<Mutex<BTreeMap<String, SigningDevice<Message, Id>>>>,
    network: Network,
    rt: tokio::runtime::Handle,
    sender: channel::Sender<Message>,
) where
    Message: From<SigningDeviceMsg<Id>> + Send + Clone + 'static,
    Id: Send + Clone + 'static,
{
    tracing::debug!("Attempting to unlock Jade device {}", id);
    if let Err(e) = device.auth().await {
        tracing::error!("Failed to unlock Jade {}: {}", id, e);
        tracing::debug!(
            "handle_locked_jade[{}]: removing from device map after auth failure",
            id
        );
        devices.lock().expect("poisoned").remove(&id);
        let _ = sender.send(SigningDeviceMsg::Update.into());
        return;
    }
    tracing::info!("Jade device {} successfully unlocked", id);
    tracing::trace!(
        "handle_locked_jade[{}]: getting device info after unlock",
        id
    );
    let info = match device.get_info().await {
        Ok(i) => {
            tracing::debug!(
                "handle_locked_jade[{}]: got info, state={:?}",
                id,
                i.jade_state
            );
            i
        }
        Err(e) => {
            tracing::error!("Failed to get Jade info {}: {}", id, e);
            tracing::debug!(
                "handle_locked_jade[{}]: removing from device map after info failure",
                id
            );
            devices.lock().expect("poisoned").remove(&id);
            let _ = sender.send(SigningDeviceMsg::Update.into());
            return;
        }
    };
    tracing::trace!("handle_locked_jade[{}]: calling handle_jade_device", id);
    if let Some(jade) =
        handle_jade_device(info, network, device, id.clone(), None, rt, sender.clone()).await
    {
        tracing::debug!(
            "handle_locked_jade[{}]: inserting unlocked device into map",
            id
        );
        devices.lock().expect("poisoned").insert(id, jade);
        let _ = sender.send(SigningDeviceMsg::Update.into());
    } else {
        tracing::trace!(
            "handle_locked_jade[{}]: handle_jade_device returned None",
            id
        );
    }
}

#[cfg(feature = "ledger")]
fn handle_ledger_simulator<Message, Id>(
    rt: &tokio::runtime::Handle,
    sender: channel::Sender<Message>,
    handle: &mut Option<tokio::task::JoinHandle<()>>,
    devices: Arc<Mutex<BTreeMap<String, SigningDevice<Message, Id>>>>,
) where
    Message: From<SigningDeviceMsg<Id>> + Send + Clone + 'static,
    Id: Send + Clone + 'static,
{
    const LEDGER_SIMULATOR_ID: &str = "ledger-simulator";
    // If device is already in the map, don't poll it again
    if devices
        .lock()
        .expect("poisoned")
        .contains_key(LEDGER_SIMULATOR_ID)
    {
        tracing::trace!("handle_ledger_simulator: device already in map, skipping");
        return;
    }
    let poll = if let Some(h) = handle {
        if h.is_finished() {
            tracing::trace!("handle_ledger_simulator: previous handle finished, will poll");
            *handle = None;
            true
        } else {
            tracing::debug!("handle_ledger_simulator: previous handle still running, skipping");
            false
        }
    } else {
        tracing::trace!("handle_ledger_simulator: no handle, will poll");
        true
    };
    if poll {
        tracing::trace!("handle_ledger_simulator: spawning async task");
        let rt_ = rt.clone();
        let sender_ = sender.clone();
        let jh = rt.spawn(async move {
            tracing::trace!("handle_ledger_simulator: calling try_connect");
            match ledger::LedgerSimulator::try_connect().await {
                Ok(device) => {
                    tracing::debug!("Ledger Simulator connected");
                    tracing::trace!("handle_ledger_simulator: calling handle_ledger_device");
                    match handle_ledger_device(
                        LEDGER_SIMULATOR_ID.into(),
                        device,
                        rt_,
                        sender_.clone(),
                    )
                    .await
                    {
                        Ok(hw) => {
                            tracing::debug!("handle_ledger_simulator: inserting device into map");
                            devices
                                .lock()
                                .expect("poisoned")
                                .insert(LEDGER_SIMULATOR_ID.into(), hw);
                            let _ = sender.send(SigningDeviceMsg::Update.into());
                        }
                        Err(e) => {
                            tracing::debug!("Failed to initialize Ledger Simulator: {}", e);
                        }
                    }
                }
                Err(HWIError::DeviceNotFound) => {
                    tracing::trace!("handle_ledger_simulator: DeviceNotFound");
                    let was_present = devices
                        .lock()
                        .expect("poisoned")
                        .remove(LEDGER_SIMULATOR_ID)
                        .is_some();
                    if was_present {
                        tracing::info!("Ledger Simulator disconnected");
                        tracing::debug!("handle_ledger_simulator: removed from device map");
                        let _ = sender.send(SigningDeviceMsg::Update.into());
                    }
                }
                Err(e) => {
                    tracing::trace!("Ledger Simulator not available: {}", e);
                }
            }
        });
        *handle = Some(jh);
    }
}

#[cfg(feature = "bitbox")]
#[allow(clippy::too_many_arguments)]
fn handle_bitbox02<Message, Id>(
    rt: &tokio::runtime::Handle,
    sender: &channel::Sender<Message>,
    handles: &mut BTreeMap<String, tokio::task::JoinHandle<()>>,
    devices: Arc<Mutex<BTreeMap<String, SigningDevice<Message, Id>>>>,
    list: Vec<&DeviceInfo>,
    hid: &HidApi,
    network: Network,
    #[cfg(feature = "bitbox")] bitbox_noise_config: Arc<Mutex<Option<Arc<dyn NoiseConfig>>>>,
) where
    Message: From<SigningDeviceMsg<Id>> + Send + Clone + 'static,
    Id: Send + Clone + 'static,
{
    /// Prefer serial number for stable ID across USB ports; fall back to path.
    fn bitbox_id(device_info: &ledger::DeviceInfo) -> String {
        let id = if let Some(sn) = device_info.serial_number() {
            format!("bitbox-{sn}")
        } else {
            format!(
                "bitbox-{:?}-{}-{}",
                device_info.path(),
                device_info.vendor_id(),
                device_info.product_id()
            )
        };
        id.replace("\"", "")
    }

    tracing::trace!("handle_bitbox02: processing {} device(s)", list.len());

    if !list.is_empty() {
        tracing::trace!("Found {} potential BitBox02 device(s)", list.len());
    }

    let connected_ids: Vec<_> = list.iter().map(|d| bitbox_id(d)).collect();
    tracing::trace!("handle_bitbox02: connected_ids={:?}", connected_ids);
    cleanup_disconnected(sender, handles, &devices, &connected_ids, "bitbox-");

    for device_info in list {
        if crate::bitbox::is_bitbox02(device_info) {
            let id = bitbox_id(device_info);
            tracing::trace!(
                "handle_bitbox02: checking device {} (vid={}, pid={})",
                id,
                device_info.vendor_id(),
                device_info.product_id()
            );
            if !should_poll(handles, &devices, &id) {
                tracing::trace!("handle_bitbox02: skipping {} (should_poll=false)", id);
                continue;
            }

            tracing::trace!("handle_bitbox02: opening HID device {}", id);
            if let Ok(device) = device_info.open_device(hid) {
                tracing::trace!("handle_bitbox02: spawning async task for device {}", id);
                let devices = devices.clone();
                let id_ = id.clone();
                let sender = sender.clone();
                let rt_ = rt.clone();
                #[cfg(feature = "bitbox")]
                let bitbox_noise_config = bitbox_noise_config.clone();

                let jh = rt.spawn(async move {
                    tracing::debug!("Connecting to BitBox02 device {}", id_);

                    // Get the pairing config if available
                    #[cfg(feature = "bitbox")]
                    let pairing_config: Option<Box<dyn NoiseConfig>> = {
                        let config =
                            bitbox_noise_config
                                .lock()
                                .expect("poisoned")
                                .as_ref()
                                .map(|arc| {
                                    tracing::debug!("Using pairing config for BitBox02 {}", id_);
                                    Box::new(ArcNoiseConfig(arc.clone())) as Box<dyn NoiseConfig>
                                });
                        tracing::debug!(
                            "handle_bitbox02[{}]: pairing_config available={}",
                            id_,
                            config.is_some()
                        );
                        config
                    };

                    tracing::debug!("handle_bitbox02[{}]: calling PairingBitbox02::connect", id_);
                    match PairingBitbox02::connect(device, pairing_config).await {
                        Ok(pairing_device) => {
                            let pairing_code =
                                pairing_device.pairing_code().map(|s| s.replace('\n', " "));
                            tracing::debug!(
                                "handle_bitbox02[{}]: connected, pairing_code={}",
                                id_,
                                pairing_code.as_deref().unwrap_or("none")
                            );
                            if let Some(ref code) = pairing_code {
                                tracing::info!(
                                    "BitBox02 {} requires pairing with code: {}",
                                    id_,
                                    code
                                );
                            } else {
                                tracing::debug!("BitBox02 {} connected (already paired)", id_);
                            }
                            let locked_device = Arc::new(Mutex::new(Some(LockedDevice::BitBox02(
                                Box::new(pairing_device),
                            ))));

                            tracing::debug!(
                                "handle_bitbox02[{}]: inserting Locked device into map",
                                id_
                            );
                            devices.lock().expect("poisoned").insert(
                                id_.clone(),
                                SigningDevice::Locked {
                                    id: id_.clone(),
                                    kind: DeviceKind::BitBox02,
                                    pairing_code,
                                    device: locked_device.clone(),
                                },
                            );
                            let _ = sender.send(SigningDeviceMsg::Update.into());

                            tracing::debug!("handle_bitbox02[{}]: taking device for unlock", id_);
                            let bb = locked_device.lock().expect("poisoned").take();
                            if let Some(LockedDevice::BitBox02(bb)) = bb {
                                tracing::trace!(
                                    "handle_bitbox02[{}]: calling handle_locked_bitbox",
                                    id_
                                );
                                handle_locked_bitbox(bb, id_, devices, network, rt_, sender).await;
                            } else {
                                unreachable!()
                            }
                        }
                        Err(e) => {
                            tracing::error!("Failed to connect to BitBox02 {}: {}", id_, e);
                        }
                    }
                });
                handles.insert(id, jh);
            } else {
                tracing::trace!("handle_bitbox02: failed to open HID device {}", id);
            }
        }
    }
}

#[cfg(feature = "bitbox")]
async fn handle_locked_bitbox<Message, Id>(
    device: Box<PairingBitbox02<TokioRuntime>>,
    id: String,
    devices: Arc<Mutex<BTreeMap<String, SigningDevice<Message, Id>>>>,
    network: Network,
    rt: tokio::runtime::Handle,
    sender: channel::Sender<Message>,
) where
    Message: From<SigningDeviceMsg<Id>> + Send + Clone + 'static,
    Id: Send + Clone + 'static,
{
    tracing::debug!("Waiting for BitBox02 {} pairing confirmation", id);
    match unlock_bitbox(id.clone(), network, device, rt, sender.clone()).await {
        Ok(bb) => {
            tracing::info!("BitBox02 {} successfully unlocked", id);
            tracing::debug!(
                "handle_locked_bitbox[{}]: inserting unlocked device into map",
                id
            );
            devices.lock().expect("poisoned").insert(id, bb);
            let _ = sender.send(SigningDeviceMsg::Update.into());
        }
        Err(e) => {
            tracing::error!("Failed to unlock BitBox02 {}: {}", id, e);
            tracing::debug!(
                "handle_locked_bitbox[{}]: removing device from map after unlock failure",
                id
            );
            // Remove the device from the list since unlocking failed
            devices.lock().expect("poisoned").remove(&id);
            let _ = sender.send(SigningDeviceMsg::Update.into());
        }
    }
}

#[cfg(feature = "coldcard")]
fn handle_coldcard<Message, Id>(
    rt: &tokio::runtime::Handle,
    sender: &channel::Sender<Message>,
    handles: &mut BTreeMap<String, tokio::task::JoinHandle<()>>,
    devices: Arc<Mutex<BTreeMap<String, SigningDevice<Message, Id>>>>,
    list: Vec<&DeviceInfo>,
    hid: &HidApi,
) where
    Message: From<SigningDeviceMsg<Id>> + Send + Clone + 'static,
    Id: Send + Clone + 'static,
{
    fn coldcard_id(device_info: &ledger::DeviceInfo) -> String {
        let id = format!(
            "coldcard-{:?}-{}-{}",
            device_info.path(),
            device_info.vendor_id(),
            device_info.product_id()
        );
        id.replace("\"", "")
    }

    tracing::trace!("handle_coldcard: processing {} device(s)", list.len());

    if !list.is_empty() {
        tracing::debug!("Found {} potential Coldcard device(s)", list.len());
    }

    let connected_ids: Vec<_> = list.iter().map(|d| coldcard_id(d)).collect();
    tracing::trace!("handle_coldcard: connected_ids={:?}", connected_ids);
    cleanup_disconnected(sender, handles, &devices, &connected_ids, "coldcard-");

    for device_info in list {
        if crate::coldcard::is_coldcard(device_info) {
            let id = coldcard_id(device_info);
            tracing::trace!(
                "handle_coldcard: checking device {} (vid={}, pid={})",
                id,
                device_info.vendor_id(),
                device_info.product_id()
            );
            if !should_poll(handles, &devices, &id) {
                tracing::debug!("handle_coldcard: skipping {} (should_poll=false)", id);
                continue;
            }

            if let Some(sn) = device_info.serial_number() {
                tracing::debug!("handle_coldcard: device {} has serial_number={}", id, sn);
                let devices = devices.clone();
                let id_clone = id.clone();
                let sn = sn.to_string();
                tracing::debug!("handle_coldcard: opening Coldcard with serial {}", sn);
                if let Ok((cc, _)) =
                    coldcard::api::Coldcard::open(AsRefWrap { inner: hid }, &sn, None)
                {
                    tracing::trace!("handle_coldcard: spawning async task for device {}", id);
                    let sender = sender.clone();
                    let rt_ = rt.clone();
                    let jh = rt.spawn(async move {
                        tracing::debug!("Connecting to Coldcard device {}", id_clone);
                        let device: Arc<dyn HWI + Send + Sync> =
                            Arc::new(coldcard::Coldcard::from(cc));
                        tracing::debug!(
                            "handle_coldcard[{}]: getting fingerprint and version",
                            id_clone
                        );
                        match (
                            device.get_master_fingerprint().await,
                            device.get_version().await,
                        ) {
                            (Ok(fingerprint), Ok(version)) => {
                                tracing::debug!("Coldcard {} detected (version: {}, fingerprint: {})",
                                    id_clone, version, fingerprint);
                                let hw = if version
                                    >= (Version {
                                        major: 6,
                                        minor: 2,
                                        patch: 1,
                                        prerelease: None,
                                    }) {
                                    tracing::debug!(
                                        "handle_coldcard[{}]: version supported, creating Supported device",
                                        id_clone
                                    );
                                    SigningDevice::Supported (SupportedDevice{
                                        id: id_clone.clone(),
                                        device,
                                        kind: DeviceKind::Coldcard,
                                        fingerprint,
                                        version: Some(version),
                                        rt: rt_,
                                        sender: sender.clone(),
                                        _phantom: PhantomData,
                                    })
                                } else {
                                    tracing::debug!("Coldcard {} has unsupported version {} (requires >= 6.2.1)",
                                        id_clone, version);
                                    SigningDevice::Unsupported {
                                        id: id_clone.clone(),
                                        kind: DeviceKind::Coldcard,
                                        version: Some(version),
                                        reason: UnsupportedReason::Version {
                                            minimal_supported_version: "Edge firmware v6.2.1",
                                        },
                                    }
                                };
                                tracing::debug!(
                                    "handle_coldcard[{}]: inserting device into map",
                                    id_clone
                                );
                                devices.lock().expect("poisoned").insert(id_clone, hw);
                                let _ = sender.send(SigningDeviceMsg::Update.into());
                            }
                            (Err(e1), Err(e2)) => {
                                tracing::error!("Failed to connect to coldcard {}", id_clone);
                                tracing::debug!(
                                    "handle_coldcard[{}]: fingerprint error={}, version error={}",
                                    id_clone,
                                    e1,
                                    e2
                                );
                            }
                            (Err(e), _) => {
                                tracing::error!("Failed to connect to coldcard {}", id_clone);
                                tracing::debug!(
                                    "handle_coldcard[{}]: fingerprint error={}",
                                    id_clone,
                                    e
                                );
                            }
                            (_, Err(e)) => {
                                tracing::error!("Failed to connect to coldcard {}", id_clone);
                                tracing::debug!(
                                    "handle_coldcard[{}]: version error={}",
                                    id_clone,
                                    e
                                );
                            }
                        }
                    });
                    handles.insert(id, jh);
                } else {
                    tracing::debug!(
                        "handle_coldcard: failed to open Coldcard with serial {}",
                        sn
                    );
                }
            } else {
                tracing::trace!("handle_coldcard: device {} has no serial number", id);
            }
        }
    }
}

#[cfg(feature = "ledger")]
fn handle_ledger<Message, Id>(
    rt: &tokio::runtime::Handle,
    sender: &channel::Sender<Message>,
    handles: &mut BTreeMap<String, tokio::task::JoinHandle<()>>,
    devices: Arc<Mutex<BTreeMap<String, SigningDevice<Message, Id>>>>,
    list: Vec<&DeviceInfo>,
    hid: &HidApi,
) where
    Message: From<SigningDeviceMsg<Id>> + Send + Clone + 'static,
    Id: Send + Clone + 'static,
{
    fn ledger_id(detected: &ledger::DeviceInfo) -> String {
        let id = format!(
            "ledger-{:?}-{}-{}",
            detected.path(),
            detected.vendor_id(),
            detected.product_id()
        );
        id.replace("\"", "")
    }

    tracing::trace!("handle_ledger: processing {} device(s)", list.len());

    if !list.is_empty() {
        tracing::trace!("Found {} Ledger device(s)", list.len());
    }

    let connected_ids: Vec<_> = list.iter().map(|d| ledger_id(d)).collect();
    tracing::trace!("handle_ledger: connected_ids={:?}", connected_ids);
    cleanup_disconnected(sender, handles, &devices, &connected_ids, "ledger-");

    for detected in list {
        let id = ledger_id(detected);
        tracing::trace!(
            "handle_ledger: checking device {} (vid={}, pid={})",
            id,
            detected.vendor_id(),
            detected.product_id()
        );
        if !should_poll(handles, &devices, &id) {
            tracing::debug!("handle_ledger: skipping {} (should_poll=false)", id);
            continue;
        }

        // Connect synchronously first
        tracing::trace!("handle_ledger: connecting to device {}", id);
        match ledger::Ledger::<ledger::TransportHID>::connect(hid, detected) {
            Ok(device) => {
                tracing::trace!("handle_ledger: spawning async task for device {}", id);
                let devices = devices.clone();
                let id_clone = id.clone();
                let rt_ = rt.clone();
                let sender_ = sender.clone();
                let jh = rt.spawn(async move {
                    tracing::trace!("handle_ledger[{}]: calling handle_ledger_device", id_clone);
                    match handle_ledger_device(id_clone.clone(), device, rt_, sender_).await {
                        Ok(hw) => {
                            if let SigningDevice::Supported(SupportedDevice {
                                fingerprint,
                                version,
                                ..
                            }) = &hw
                            {
                                tracing::info!(
                                    "Ledger {} connected (version: {:?}, fingerprint: {})",
                                    id_clone,
                                    version,
                                    fingerprint
                                );
                                tracing::debug!(
                                    "handle_ledger[{}]: created Supported device",
                                    id_clone
                                );
                            } else if let SigningDevice::Unsupported { reason, .. } = &hw {
                                tracing::debug!("Ledger {} is unsupported: {:?}", id_clone, reason);
                            }
                            tracing::debug!(
                                "handle_ledger[{}]: inserting device into map",
                                id_clone
                            );
                            devices.lock().expect("poisoned").insert(id_clone, hw);
                        }
                        Err(e) => {
                            tracing::debug!("Failed to initialize Ledger {}: {:?}", id_clone, e);
                        }
                    }
                });
                handles.insert(id, jh);
                let _ = sender.send(SigningDeviceMsg::Update.into());
            }
            Err(HWIError::DeviceNotFound) => {
                tracing::trace!("handle_ledger: device {} returned DeviceNotFound", id);
            }
            Err(e) => {
                tracing::trace!("handle_ledger: device {} connect error: {:?}", id, e);
            }
        }
    }
}

#[cfg(feature = "ledger")]
async fn handle_ledger_device<Message, Id, T: crate::ledger::Transport + Sync + Send + 'static>(
    id: String,
    device: ledger::Ledger<T>,
    rt: tokio::runtime::Handle,
    sender: channel::Sender<Message>,
) -> Result<SigningDevice<Message, Id>, HWIError>
where
    Message: From<SigningDeviceMsg<Id>> + Send + Clone + 'static,
    Id: Send + Clone + 'static,
{
    tracing::debug!(
        "handle_ledger_device[{}]: getting fingerprint and version",
        id
    );
    match (
        device.get_master_fingerprint().await,
        device.get_version().await,
    ) {
        (Ok(fingerprint), Ok(version)) => {
            tracing::debug!(
                "handle_ledger_device[{}]: fingerprint={}, version={}",
                id,
                fingerprint,
                version
            );
            let supported = ledger_version_supported(&version);
            tracing::debug!(
                "handle_ledger_device[{}]: version {} supported={}",
                id,
                version,
                supported
            );
            if supported {
                tracing::debug!("handle_ledger_device[{}]: returning Supported", id);
                Ok(SigningDevice::Supported(SupportedDevice {
                    id,
                    kind: device.device_kind(),
                    fingerprint,
                    device: Arc::new(device),
                    version: Some(version),
                    rt,
                    sender,
                    _phantom: PhantomData,
                }))
            } else {
                tracing::debug!(
                    "handle_ledger_device[{}]: returning Unsupported (version too old)",
                    id
                );
                Ok(SigningDevice::Unsupported {
                    id,
                    kind: device.device_kind(),
                    version: Some(version),
                    reason: UnsupportedReason::Version {
                        minimal_supported_version: "2.1.0",
                    },
                })
            }
        }
        (Err(e1), Err(e2)) => {
            tracing::debug!(
                "handle_ledger_device[{}]: fingerprint error={}, version error={}, returning Unsupported (AppIsNotOpen)",
                id,
                e1,
                e2
            );
            Ok(SigningDevice::Unsupported {
                id,
                kind: device.device_kind(),
                version: None,
                reason: UnsupportedReason::AppIsNotOpen,
            })
        }
        (Err(e), _) => {
            tracing::debug!(
                "handle_ledger_device[{}]: fingerprint error={}, returning Unsupported (AppIsNotOpen)",
                id,
                e
            );
            Ok(SigningDevice::Unsupported {
                id,
                kind: device.device_kind(),
                version: None,
                reason: UnsupportedReason::AppIsNotOpen,
            })
        }
        (_, Err(e)) => {
            tracing::debug!(
                "handle_ledger_device[{}]: version error={}, returning Unsupported (AppIsNotOpen)",
                id,
                e
            );
            Ok(SigningDevice::Unsupported {
                id,
                kind: device.device_kind(),
                version: None,
                reason: UnsupportedReason::AppIsNotOpen,
            })
        }
    }
}

struct AsRefWrap<'a, T> {
    inner: &'a T,
}

impl<T> AsRef<T> for AsRefWrap<'_, T> {
    fn as_ref(&self) -> &T {
        self.inner
    }
}

#[cfg(feature = "ledger")]
fn ledger_version_supported(version: &Version) -> bool {
    if version.major >= 2 {
        if version.major == 2 {
            version.minor >= 1
        } else {
            true
        }
    } else {
        false
    }
}

/// (DeviceKind, min version) - None means all versions support it.
const DEVICES_COMPATIBLE_WITH_TAPMINISCRIPT: [(DeviceKind, Option<Version>); 5] = [
    (
        DeviceKind::Ledger,
        Some(Version {
            major: 2,
            minor: 2,
            patch: 0,
            prerelease: None,
        }),
    ),
    (DeviceKind::Specter, None),
    (DeviceKind::SpecterSimulator, None),
    (
        DeviceKind::Coldcard,
        Some(Version {
            major: 6,
            minor: 3,
            patch: 3,
            prerelease: None,
        }),
    ),
    (
        DeviceKind::BitBox02,
        Some(Version {
            major: 9,
            minor: 21,
            patch: 0,
            prerelease: None,
        }),
    ),
];

pub fn is_compatible_with_tapminiscript(
    device_kind: &DeviceKind,
    version: Option<&Version>,
) -> bool {
    DEVICES_COMPATIBLE_WITH_TAPMINISCRIPT
        .iter()
        .any(|(kind, minimal_version)| {
            device_kind == kind
                && match (version, minimal_version) {
                    (Some(v1), Some(v2)) => v1 >= v2,
                    (None, Some(_)) => false,
                    (Some(_), None) => true,
                    (None, None) => true,
                }
        })
}
