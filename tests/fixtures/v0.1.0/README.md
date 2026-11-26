# Files written by Gerfaut 0.1.0

These files were written by the code of the `v0.1.0` tag, through its public API, the calls the apps make.
`tests/v0_1_0_compat.rs` reads them with the current code and checks that nothing is lost.
Never regenerate them with a later version: their point is to stay what 0.1.0 wrote.

They hold test data only: public test vector keys on signet and testnet4, made-up server names and certificate fingerprint, a test PIN and password.
No private key, no seed.

| File | What it is |
|---|---|
| `data/gerfaut.vault` | The encrypted vault, opened with the raw key `[7u8; 32]` |
| `data/gerfaut.attempts` | The unlock attempts beside it: one wrong PIN |
| `backup-all-with-settings.gerfaut` | The backup file of every wallet, settings included |
| `backup-all-with-settings.qr.txt` | The frames of the same backup's animated QR, one per line |
| `backup-one-address.gerfaut` | The backup file of the address wallet alone, no settings |
| `backup-one-address.qr.txt` | The frames of that backup's animated QR |

The backups are sealed under `correct horse battery staple`; the app lock PIN is `482916`.

The vault holds six wallets: a multipath `wpkh` descriptor, a single-path `wpkh` descriptor, a three-path miniscript vault, a bare tpub on testnet4, a single address, and a descriptor pair restored from a backup with an address label.
Its settings are all moved off their defaults: an own Electrum server with an accepted certificate on signet, a chosen public server on testnet4, a custom Esplora on mainnet, gap limit 35, Tor through the system proxy at a set address, sats, hidden amounts, fiat in USD from CoinGecko, notifications, an app preference, automatic update checks off, a PIN with biometric unlock.
Two wallets have an icon, one is pinned for live watching.
No wallet was ever synced: the vault holds no chain state beyond what adding a wallet stores.

## How they were made

`producer.rs` is the program, a test run once in a checkout of `v0.1.0`:

```sh
git checkout v0.1.0
cp <this directory>/producer.rs tests/make_v010_fixtures.rs
GERFAUT_FIXTURES_OUT=<output directory> cargo test --test make_v010_fixtures -- --ignored
```

It writes the files above into the output directory, `data/` included; `data/gerfaut.vault.lock` is left out, as the vault creates it when opened.
