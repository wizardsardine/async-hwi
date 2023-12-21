# async-hwi

Current **Minimum Supported Rust Version**: v1.70.0

```rust
/// HWI is the common Hardware Wallet Interface.
#[async_trait]
pub trait HWI: Debug {
    /// Return the device kind
    fn device_kind(&self) -> DeviceKind;
    /// Application version or OS version.
    async fn get_version(&self) -> Result<Version, Error>;
    /// Get master fingerprint.
    async fn get_master_fingerprint(&self) -> Result<Fingerprint, Error>;
    /// Get the xpub with the given derivation path.
    async fn get_extended_pubkey(&self, path: &DerivationPath) -> Result<ExtendedPubKey, Error>;
    /// Register a new wallet policy
    async fn register_wallet(&self, name: &str, policy: &str) -> Result<Option<[u8; 32]>, Error>;
    /// Display an address on the device screen
    async fn display_address(&self, script: &AddressScript) -> Result<(), Error>;
    /// Sign a partially signed bitcoin transaction (PSBT).
    async fn sign_tx(&self, tx: &mut Psbt) -> Result<(), Error>;
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AddressScript {
    /// Must be a bip86 path.
    P2TR(DerivationPath),
    /// Miniscript requires the policy be loaded into the device.
    Miniscript { index: u32, change: bool },
}
```

## Supported devices

A Empty case means the method is unimplemented on the client or device side.

|                        | BitBox02[^1] | Coldcard[^2] | Ledger Nano S/S+[^3] | Specter[^4] |
|----------------------- |--------------|------------- |----------------------|-------------|
| get_version            |              | >= 6.2.1X    | >= v2.1.2            |             |
| get_master_fingerprint | >= v9.15.0   | >= 6.2.1X    | >= v2.1.2            | >= v1.8.0   |
| get_extended_pubkey    | >= v9.15.0   | >= 6.2.1X    | >= v2.1.2            | >= v1.8.0   |
| register_wallet        | >= v9.15.0   | >= 6.2.1X    | >= v2.1.2            | >= v1.8.0   |
| display_address        | >= v9.15.0   | >= 6.2.1X    | >= v2.1.2            |             |
| sign_tx                | >= v9.15.0   | >= 6.2.1X    | >= v2.1.2            | >= v1.8.0   |

[^1]: https://github.com/digitalbitbox/bitbox02-firmware
[^2]: https://github.com/alfred-hodler/rust-coldcard
[^3]: https://github.com/LedgerHQ/app-bitcoin-new  
[^4]: https://github.com/cryptoadvance/specter-diy
