# async_hwi

```rust
/// HWI is the common Hardware Wallet Interface.
#[async_trait]
pub trait HWI: Debug {
    fn device_type(&self) -> DeviceType;
    /// Check that the device is connected but not necessarily available.
    async fn is_connected(&self) -> Result<(), Error>;
    /// Get master fingerprint.
    async fn get_fingerprint(&self) -> Result<Fingerprint, Error>;
    /// Get the xpub with the given derivation path.
    async fn get_extended_pubkey(&self, path: &DerivationPath, display: bool) -> Result<ExtendedPubKey, Error>;
    /// Register a new wallet policy
    async fn register_wallet(&mut self, name: &str, policy: &str) -> Result<Option<[u8; 32]>, Error>;
    /// Sign a partially signed bitcoin transaction (PSBT).
    async fn sign_tx(&self, tx: &mut Psbt) -> Result<(), Error>;
}
```

## Devices supported

| name                                                    | App version |
|---------------------------------------------------------|-------------|
| [Specter](https://github.com/cryptoadvance/specter-diy) | v1.8.0      |
| [Ledger](https://github.com/LedgerHQ/app-bitcoin-new)   | v2.1.0      |

