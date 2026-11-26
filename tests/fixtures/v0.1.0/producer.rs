//! The program that wrote the files of this directory, run once in a
//! checkout of `v0.1.0` as `tests/make_v010_fixtures.rs` (see the
//! README). It compiles against the 0.1.0 API only, and is not part of
//! the test suite of later versions.

use std::path::PathBuf;

use gerfaut_core::backup::{
    self, BACKUP_VERSION, BackupOptions, BackupPayload, BackupWallet, ImportChoices,
};
use gerfaut_core::chain::BackendConfig;
use gerfaut_core::chain::tor::{TorMode, TorSettings};
use gerfaut_core::input::parse_input;
use gerfaut_core::lock::LockKind;
use gerfaut_core::prefs::{PreferencesChange, Unit};
use gerfaut_core::price::{FiatCurrency, PriceSource};
use gerfaut_core::store::VaultKey;
use gerfaut_core::wallet::meta::WalletIcon;
use gerfaut_core::{Network, WalletManager};

const PASSWORD: &str = "correct horse battery staple";
const C: &str = "[73c5da0a/84'/1'/0']tpubDC8msFGeGuwnKG9Upg7DM2b4DaRqg3CUZa5g8v2SRQ6K4NSkxUgd7HsL2XVWbVm39yBA4LAxysQAm397zwQSQoQgewGiYZqrA9DsP4zbQ1M";
const A: &str = "[a5c6b76e/48'/1'/0'/2']tpubDF5861hj6vR3iJr3aPjGJz4rNbqDCRujQ21mczzKT5SiedaQqNVgHC8HT9ceyxvMFRoPMx4P6HAcL3NZrUPhRUbwCyj3TKSa64bAfnE3sLh";
const B: &str = "[c477fd13/48'/1'/0'/2']tpubDFn7iPbFqGrTQ2aRACNsUK1MXQR4Z6dYfU2nD1WA9ifSaia642j3Wah4n5pBUEpERNWGJsyv3Dv5qwBabC9TLQrwSboKzukw9wmurGu7XVH";
const TPUB: &str = "tpubDC8msFGeGuwnKG9Upg7DM2b4DaRqg3CUZa5g8v2SRQ6K4NSkxUgd7HsL2XVWbVm39yBA4LAxysQAm397zwQSQoQgewGiYZqrA9DsP4zbQ1M";
const RECOVERY_VAULT: &str = "wsh(or_d(pk([a5c6b76e/48'/1'/0'/2']tpubDF5861hj6vR3iJr3aPjGJz4rNbqDCRujQ21mczzKT5SiedaQqNVgHC8HT9ceyxvMFRoPMx4P6HAcL3NZrUPhRUbwCyj3TKSa64bAfnE3sLh/<0;1>/*),and_v(v:pkh([c477fd13/48'/1'/0'/2']tpubDFn7iPbFqGrTQ2aRACNsUK1MXQR4Z6dYfU2nD1WA9ifSaia642j3Wah4n5pBUEpERNWGJsyv3Dv5qwBabC9TLQrwSboKzukw9wmurGu7XVH/<0;1>/*),older(3))))#8ldsjayd";
const ADDRESS: &str = "tb1qa3658sv7ndr9mkcwqy52g39snc70j5xdleavm0";
const ELECTRUM: &str = "ssl://electrum.example.org:50002";
const FINGERPRINT: &str = "AB:CD:EF:01:23:45:67:89:AB:CD:EF:01:23:45:67:89:AB:CD:EF:01:23:45:67:89:AB:CD:EF:01:23:45:67:89";

#[test]
#[ignore]
fn make_v0_1_0_fixtures() {
    let out = PathBuf::from(std::env::var("GERFAUT_FIXTURES_OUT").expect("GERFAUT_FIXTURES_OUT"));
    let data = out.join("data");
    std::fs::create_dir_all(&data).unwrap();
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    rt.block_on(async {
        let m = WalletManager::open(&data, VaultKey::Raw([7u8; 32])).unwrap();
        m.set_active_network(Network::Signet).await.unwrap();

        let three_paths = format!(
            "wsh(or_d(multi(2,{A}/<0;1>/*,{B}/<0;1>/*),or_i(and_v(v:pkh({C}/<0;1>/*),older(1000)),and_v(v:pkh({A}/<2;3>/*),older(100)))))"
        );
        let wallets: Vec<(&str, String, Network)> = vec![
            ("Savings", format!("wpkh({C}/<0;1>/*)"), Network::Signet),
            ("Spending", format!("wpkh({C}/0/*)"), Network::Signet),
            ("Vault", three_paths, Network::Signet),
            ("Cold", TPUB.to_owned(), Network::Testnet4),
            ("Donations", ADDRESS.to_owned(), Network::Signet),
        ];
        let mut ids = Vec::new();
        for (name, input, network) in &wallets {
            let parsed = parse_input(input).unwrap_or_else(|e| panic!("{name}: {e}"));
            let meta = m
                .add_wallet(name, &parsed, *network)
                .await
                .unwrap_or_else(|e| panic!("{name}: {e}"));
            ids.push(meta.id);
        }

        // Labels ride in only through a restore: a backup sealed by this
        // build, restored by this build.
        let probe = m
            .add_wallet("Recovery", &parse_input(RECOVERY_VAULT).unwrap(), Network::Signet)
            .await
            .unwrap();
        m.remove_wallet(&probe.id).await.unwrap();
        let labelled = BackupPayload {
            version: BACKUP_VERSION,
            created_at: 1_764_000_000,
            wallets: vec![BackupWallet {
                name: "Recovery".to_owned(),
                network: Network::Signet,
                kind: probe.kind.clone(),
                gap_limit: 20,
                labels: [
                    ("addr:tb1q6rz28mcfaxtmd6v789l9rrlrusdprr9pqcpvkl".to_owned(), "First deposit".to_owned()),
                ]
                .into(),
                created_at: 1_764_000_000,
                live_pinned: false,
            }],
            backends: None,
            electrum_certs: None,
            gap_limit: None,
        };
        let sealed = backup::seal(&labelled, PASSWORD).unwrap();
        let source = data_encoding::BASE64.encode(&sealed);
        let report = m.import_backup(&source, PASSWORD, &ImportChoices::default()).await.unwrap();
        ids.push(report.added[0].id.clone());

        m.set_wallet_icon(&ids[0], WalletIcon::PiggyBank).await.unwrap();
        m.set_wallet_icon(&ids[2], WalletIcon::Shield).await.unwrap();
        m.set_wallet_live_pinned(&ids[0], true).await.unwrap();

        m.set_backend_trusting(
            Network::Signet,
            BackendConfig::CustomElectrum { url: ELECTRUM.to_owned(), own_node: true },
            ELECTRUM,
            FINGERPRINT,
        )
        .await
        .unwrap();
        m.set_backend(
            Network::Testnet4,
            BackendConfig::Public { server: Some("electrum:blackie.c3-soft.com".to_owned()) },
        )
        .await
        .unwrap();
        m.set_backend(
            Network::Mainnet,
            BackendConfig::CustomEsplora { url: "https://esplora.example.org/api".to_owned(), own_node: false },
        )
        .await
        .unwrap();
        m.set_gap_limit(35).await.unwrap();
        m.set_tor_settings(TorSettings { mode: TorMode::System, socks_proxy: Some("127.0.0.1:9150".to_owned()) })
            .await
            .unwrap();
        m.set_preferences(PreferencesChange {
            unit: Some(Unit::Sats),
            masked: Some(true),
            fiat: Some(true),
            fiat_currency: Some(FiatCurrency::Usd),
            price_source: Some(PriceSource::Coingecko),
            notify_new_tx: Some(true),
            explorer_ack: Some(true),
        })
        .await
        .unwrap();
        m.set_app_pref("desktop.theme".to_owned(), "dark".to_owned()).await.unwrap();
        m.set_update_automatic(false).await.unwrap();
        m.set_app_lock(LockKind::Pin, "482916", None).await.unwrap();
        m.set_biometric_unlock(true, "482916").await.unwrap();
        // One wrong PIN, so the attempts file is written.
        let verdict = m.verify_app_lock("000000").await.unwrap();
        println!("verdict after a wrong pin: {verdict:?}");

        let all = m
            .export_backup(&BackupOptions { wallet_ids: None, include_settings: true }, PASSWORD)
            .await
            .unwrap();
        std::fs::write(out.join("backup-all-with-settings.gerfaut"), &all.data).unwrap();
        std::fs::write(out.join("backup-all-with-settings.qr.txt"), all.frames.join("\n") + "\n").unwrap();
        println!("all: {} wallets, {} bytes, {} frames", all.wallet_count, all.size_bytes, all.frames.len());

        let one = m
            .export_backup(
                &BackupOptions { wallet_ids: Some(vec![ids[4].clone()]), include_settings: false },
                PASSWORD,
            )
            .await
            .unwrap();
        std::fs::write(out.join("backup-one-address.gerfaut"), &one.data).unwrap();
        std::fs::write(out.join("backup-one-address.qr.txt"), one.frames.join("\n") + "\n").unwrap();
        println!("one: {} wallets, {} bytes, {} frames", one.wallet_count, one.size_bytes, one.frames.len());

        let listed = m.list_wallets(None).await;
        std::fs::write(out.join("manifest.json"), serde_json::to_string_pretty(&listed).unwrap()).unwrap();
        let settings = m.settings().await;
        std::fs::write(out.join("settings.json"), serde_json::to_string_pretty(&settings).unwrap()).unwrap();
    });
}
