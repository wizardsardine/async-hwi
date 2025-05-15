# async-hwi

Current **Minimum Supported Rust Version**: v1.81

```rust
/// HWI is the common Hardware Wallet Interface.
#[async_trait]
pub trait HWI: Debug {
    /// 0. Return the device kind
    fn device_kind(&self) -> DeviceKind;
    /// 1. Application version or OS version.
    async fn get_version(&self) -> Result<Version, Error>;
    /// 2. Get master fingerprint.
    async fn get_master_fingerprint(&self) -> Result<Fingerprint, Error>;
    /// 3. Get the xpub with the given derivation path.
    async fn get_extended_pubkey(&self, path: &DerivationPath) -> Result<Xpub, Error>;
    /// Get the xpub with the given derivation path, will ask user ACK for non "standard"
    /// derivation path on some devices.
    async fn get_extended_pubkey_display(&self, path: &DerivationPath) -> Result<Xpub, Error>;
    /// 4. Register a new wallet policy
    async fn register_wallet(&self, name: &str, policy: &str) -> Result<Option<[u8; 32]>, Error>;
    /// 5. Returns true if the wallet is registered
    async fn is_wallet_registered(&self, name: &str, policy: &str) -> Result<bool, HWIError>;
    /// 6. Display an address on the device screen
    async fn display_address(&self, script: &AddressScript) -> Result<(), Error>;
    /// 7. Sign a partially signed bitcoin transaction (PSBT).
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

| device               | 1          | 2          | 3          | 4          | 5                    | 6          | 7          |
| -------------------- | ---------- | ---------- | ---------- | ---------- | -------------------- | ---------- | ---------- |
| BitBox02[^1]         | >= v9.15.0 | >= v9.15.0 | >= v9.15.0 | >= v9.15.0 | >= v9.15.0           | >= v9.15.0 | >= v9.15.0 |
| Coldcard[^2]         | >= v6.2.1X | >= v6.2.1X | >= v6.2.1X | >= v6.2.1X | >= v6.2.1X           | >= v6.2.1X | >= v6.2.1X |
| Jade[^3]             | >= v1.0.30 | >= v1.0.30 | >= v1.0.30 | >= v1.0.30 | >= v1.0.30           | >= v1.0.30 | >= v1.0.30 |
| Ledger Nano S/S+[^4] | >= v2.1.2  | >= v2.1.2  | >= v2.1.2  | >= v2.1.2  | *check hmac presence | >= v2.1.2  | >= v2.1.2  |
| Specter[^5]          |            | >= v1.8.0  | >= v1.8.0  | >= v1.8.0  |                      |            | >= v1.8.0  |

[^1]: https://github.com/digitalbitbox/bitbox02-firmware
[^2]: https://github.com/alfred-hodler/rust-coldcard
[^3]: https://github.com/Blockstream/Jade
[^4]: https://github.com/LedgerHQ/app-bitcoin-new
[^5]: https://github.com/cryptoadvance/specter-diy
