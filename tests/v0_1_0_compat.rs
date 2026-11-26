//! What Gerfaut 0.1.0 wrote, read by this build through the calls the
//! apps make: its data directory (vault and unlock attempts), its backup
//! file and the frames of its animated backup QR. The files were written
//! by the 0.1.0 code itself: see `tests/fixtures/v0.1.0/README.md`.
//! Every value expected here is what 0.1.0 was given or answered.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use gerfaut_core::backup::{BackupOptions, ImportChoices};
use gerfaut_core::chain::BackendConfig;
use gerfaut_core::chain::tor::{TorMode, TorSettings};
use gerfaut_core::input::qr;
use gerfaut_core::input::{RecognizedKind, ScriptKind};
use gerfaut_core::lock::LockKind;
use gerfaut_core::prefs::{Preferences, Unit};
use gerfaut_core::price::{FiatCurrency, PriceSource};
use gerfaut_core::store::VaultKey;
use gerfaut_core::wallet::meta::{CachedTotals, WalletIcon, WalletKind, WalletMeta};
use gerfaut_core::{ErrorCode, Network, WalletManager};

/// The password the fixture backups were sealed under.
const PASSWORD: &str = "correct horse battery staple";
/// The PIN of the app lock set in the fixture vault.
const PIN: &str = "482916";

const SAVINGS_EXTERNAL: &str = "wpkh([73c5da0a/84'/1'/0']tpubDC8msFGeGuwnKG9Upg7DM2b4DaRqg3CUZa5g8v2SRQ6K4NSkxUgd7HsL2XVWbVm39yBA4LAxysQAm397zwQSQoQgewGiYZqrA9DsP4zbQ1M/0/*)#2ag6nxcd";
const SAVINGS_INTERNAL: &str = "wpkh([73c5da0a/84'/1'/0']tpubDC8msFGeGuwnKG9Upg7DM2b4DaRqg3CUZa5g8v2SRQ6K4NSkxUgd7HsL2XVWbVm39yBA4LAxysQAm397zwQSQoQgewGiYZqrA9DsP4zbQ1M/1/*)#mfdmwng4";
const VAULT_EXTERNAL: &str = "wsh(or_d(multi(2,[a5c6b76e/48'/1'/0'/2']tpubDF5861hj6vR3iJr3aPjGJz4rNbqDCRujQ21mczzKT5SiedaQqNVgHC8HT9ceyxvMFRoPMx4P6HAcL3NZrUPhRUbwCyj3TKSa64bAfnE3sLh/0/*,[c477fd13/48'/1'/0'/2']tpubDFn7iPbFqGrTQ2aRACNsUK1MXQR4Z6dYfU2nD1WA9ifSaia642j3Wah4n5pBUEpERNWGJsyv3Dv5qwBabC9TLQrwSboKzukw9wmurGu7XVH/0/*),or_i(and_v(v:pkh([73c5da0a/84'/1'/0']tpubDC8msFGeGuwnKG9Upg7DM2b4DaRqg3CUZa5g8v2SRQ6K4NSkxUgd7HsL2XVWbVm39yBA4LAxysQAm397zwQSQoQgewGiYZqrA9DsP4zbQ1M/0/*),older(1000)),and_v(v:pkh([a5c6b76e/48'/1'/0'/2']tpubDF5861hj6vR3iJr3aPjGJz4rNbqDCRujQ21mczzKT5SiedaQqNVgHC8HT9ceyxvMFRoPMx4P6HAcL3NZrUPhRUbwCyj3TKSa64bAfnE3sLh/2/*),older(100)))))#wc95qy0m";
const VAULT_INTERNAL: &str = "wsh(or_d(multi(2,[a5c6b76e/48'/1'/0'/2']tpubDF5861hj6vR3iJr3aPjGJz4rNbqDCRujQ21mczzKT5SiedaQqNVgHC8HT9ceyxvMFRoPMx4P6HAcL3NZrUPhRUbwCyj3TKSa64bAfnE3sLh/1/*,[c477fd13/48'/1'/0'/2']tpubDFn7iPbFqGrTQ2aRACNsUK1MXQR4Z6dYfU2nD1WA9ifSaia642j3Wah4n5pBUEpERNWGJsyv3Dv5qwBabC9TLQrwSboKzukw9wmurGu7XVH/1/*),or_i(and_v(v:pkh([73c5da0a/84'/1'/0']tpubDC8msFGeGuwnKG9Upg7DM2b4DaRqg3CUZa5g8v2SRQ6K4NSkxUgd7HsL2XVWbVm39yBA4LAxysQAm397zwQSQoQgewGiYZqrA9DsP4zbQ1M/1/*),older(1000)),and_v(v:pkh([a5c6b76e/48'/1'/0'/2']tpubDF5861hj6vR3iJr3aPjGJz4rNbqDCRujQ21mczzKT5SiedaQqNVgHC8HT9ceyxvMFRoPMx4P6HAcL3NZrUPhRUbwCyj3TKSa64bAfnE3sLh/3/*),older(100)))))#smchxywl";
const COLD_EXTERNAL: &str = "wpkh(tpubDC8msFGeGuwnKG9Upg7DM2b4DaRqg3CUZa5g8v2SRQ6K4NSkxUgd7HsL2XVWbVm39yBA4LAxysQAm397zwQSQoQgewGiYZqrA9DsP4zbQ1M/0/*)#gt9he67w";
const COLD_INTERNAL: &str = "wpkh(tpubDC8msFGeGuwnKG9Upg7DM2b4DaRqg3CUZa5g8v2SRQ6K4NSkxUgd7HsL2XVWbVm39yBA4LAxysQAm397zwQSQoQgewGiYZqrA9DsP4zbQ1M/1/*)#elqky0wk";
const RECOVERY_EXTERNAL: &str = "wsh(or_d(pk([a5c6b76e/48'/1'/0'/2']tpubDF5861hj6vR3iJr3aPjGJz4rNbqDCRujQ21mczzKT5SiedaQqNVgHC8HT9ceyxvMFRoPMx4P6HAcL3NZrUPhRUbwCyj3TKSa64bAfnE3sLh/0/*),and_v(v:pkh([c477fd13/48'/1'/0'/2']tpubDFn7iPbFqGrTQ2aRACNsUK1MXQR4Z6dYfU2nD1WA9ifSaia642j3Wah4n5pBUEpERNWGJsyv3Dv5qwBabC9TLQrwSboKzukw9wmurGu7XVH/0/*),older(3))))#nhtumqkr";
const RECOVERY_INTERNAL: &str = "wsh(or_d(pk([a5c6b76e/48'/1'/0'/2']tpubDF5861hj6vR3iJr3aPjGJz4rNbqDCRujQ21mczzKT5SiedaQqNVgHC8HT9ceyxvMFRoPMx4P6HAcL3NZrUPhRUbwCyj3TKSa64bAfnE3sLh/1/*),and_v(v:pkh([c477fd13/48'/1'/0'/2']tpubDFn7iPbFqGrTQ2aRACNsUK1MXQR4Z6dYfU2nD1WA9ifSaia642j3Wah4n5pBUEpERNWGJsyv3Dv5qwBabC9TLQrwSboKzukw9wmurGu7XVH/1/*),older(3))))#vpa5k5p6";
const DONATIONS_ADDRESS: &str = "tb1qa3658sv7ndr9mkcwqy52g39snc70j5xdleavm0";
/// The first receive address of the wpkh key above, from a public vector.
const FIRST_WPKH_ADDRESS: &str = "tb1q6rz28mcfaxtmd6v789l9rrlrusdprr9pqcpvkl";

const ELECTRUM_URL: &str = "ssl://electrum.example.org:50002";
const ELECTRUM_HOST: &str = "electrum.example.org:50002";
const FINGERPRINT: &str = "AB:CD:EF:01:23:45:67:89:AB:CD:EF:01:23:45:67:89:AB:CD:EF:01:23:45:67:89:AB:CD:EF:01:23:45:67:89";
/// When 0.1.0 added the wallets typed in, and the one it restored.
const ADDED_AT: u64 = 1_795_680_016;
const RESTORED_AT: u64 = 1_795_680_022;

fn fixture(name: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/v0.1.0")
        .join(name)
}

fn read_fixture(name: &str) -> String {
    std::fs::read_to_string(fixture(name)).unwrap()
}

/// A copy of the data directory 0.1.0 left, opened as an app opens it:
/// the fixture itself is never written.
fn open_v0_1_0_data_dir() -> (tempfile::TempDir, WalletManager) {
    let dir = tempfile::tempdir().unwrap();
    for file in ["gerfaut.vault", "gerfaut.attempts"] {
        std::fs::copy(fixture(&format!("data/{file}")), dir.path().join(file)).unwrap();
    }
    let manager = WalletManager::open(dir.path(), VaultKey::Raw([7u8; 32])).unwrap();
    (dir, manager)
}

fn empty_manager() -> (tempfile::TempDir, WalletManager) {
    let dir = tempfile::tempdir().unwrap();
    let manager = WalletManager::open(dir.path(), VaultKey::Raw([9u8; 32])).unwrap();
    (dir, manager)
}

fn descriptors(external: &str, internal: Option<&str>, script: ScriptKind) -> WalletKind {
    WalletKind::Descriptors {
        external: external.to_owned(),
        internal: internal.map(str::to_owned),
        script,
    }
}

/// A wallet as 0.1.0 listed it, with the gap limit of its settings.
fn wallet(
    id: &str,
    name: &str,
    network: Network,
    kind: WalletKind,
    recognized_as: RecognizedKind,
) -> WalletMeta {
    WalletMeta {
        id: id.to_owned(),
        name: name.to_owned(),
        icon: WalletIcon::Wallet,
        network,
        kind,
        recognized_as,
        created_at: ADDED_AT,
        gap_limit: 35,
        scan_gap: 0,
        labels: BTreeMap::new(),
        last_sync: None,
        last_failure: None,
        complete_at: None,
        cached: CachedTotals::default(),
        live_pinned: false,
    }
}

/// The six wallets of the fixture vault, in their order.
fn v0_1_0_wallets() -> Vec<WalletMeta> {
    let segwit = ScriptKind::Segwit;
    let wsh = ScriptKind::WitnessScript;
    vec![
        WalletMeta {
            icon: WalletIcon::PiggyBank,
            live_pinned: true,
            ..wallet(
                "d6c712fa-5b32-49b8-ac59-8a99676b448c",
                "Savings",
                Network::Signet,
                descriptors(SAVINGS_EXTERNAL, Some(SAVINGS_INTERNAL), segwit),
                RecognizedKind::MultipathDescriptor,
            )
        },
        wallet(
            "deebcb13-e467-4d45-9aab-5e640999d029",
            "Spending",
            Network::Signet,
            descriptors(SAVINGS_EXTERNAL, None, segwit),
            RecognizedKind::Descriptor,
        ),
        WalletMeta {
            icon: WalletIcon::Shield,
            ..wallet(
                "bca3f41e-64f7-4183-a31a-ae981259f430",
                "Vault",
                Network::Signet,
                descriptors(VAULT_EXTERNAL, Some(VAULT_INTERNAL), wsh),
                RecognizedKind::MultipathDescriptor,
            )
        },
        wallet(
            "f8b0535b-ea4e-43a6-88b0-48ab4dd34e9e",
            "Cold",
            Network::Testnet4,
            descriptors(COLD_EXTERNAL, Some(COLD_INTERNAL), segwit),
            RecognizedKind::ExtendedKey,
        ),
        wallet(
            "93002ecc-7144-4ad6-8ed3-c16f2328e17f",
            "Donations",
            Network::Signet,
            WalletKind::SingleAddress {
                address: DONATIONS_ADDRESS.to_owned(),
            },
            RecognizedKind::Address,
        ),
        WalletMeta {
            created_at: RESTORED_AT,
            labels: BTreeMap::from([(
                format!("addr:{FIRST_WPKH_ADDRESS}"),
                "First deposit".to_owned(),
            )]),
            ..wallet(
                "1d462734-3b7c-4ed3-adf3-33d498b2c35a",
                "Recovery",
                Network::Signet,
                descriptors(RECOVERY_EXTERNAL, Some(RECOVERY_INTERNAL), wsh),
                RecognizedKind::DescriptorPair,
            )
        },
    ]
}

fn v0_1_0_backends() -> BTreeMap<Network, BackendConfig> {
    BTreeMap::from([
        (
            Network::Mainnet,
            BackendConfig::CustomEsplora {
                url: "https://esplora.example.org/api".to_owned(),
                own_node: false,
            },
        ),
        (
            Network::Signet,
            BackendConfig::CustomElectrum {
                url: ELECTRUM_URL.to_owned(),
                own_node: true,
            },
        ),
        (
            Network::Testnet4,
            BackendConfig::Public {
                server: Some("electrum:blackie.c3-soft.com".to_owned()),
            },
        ),
    ])
}

fn v0_1_0_certs() -> BTreeMap<String, String> {
    BTreeMap::from([(ELECTRUM_HOST.to_owned(), FINGERPRINT.to_owned())])
}

/// Every wallet of a 0.1.0 vault as 0.1.0 listed it, and every setting
/// as it set them: nothing dropped, nothing reset to a default.
async fn assert_v0_1_0_vault(manager: &WalletManager) {
    assert_eq!(manager.list_wallets(None).await, v0_1_0_wallets());

    let settings = manager.settings().await;
    assert_eq!(settings.active_network, Network::Signet);
    assert_eq!(settings.backends, v0_1_0_backends());
    assert!(settings.retired_servers.is_empty());
    assert_eq!(settings.gap_limit, 35);
    assert_eq!(
        settings.app_prefs,
        BTreeMap::from([("desktop.theme".to_owned(), "dark".to_owned())])
    );
    assert_eq!(settings.electrum_certs, v0_1_0_certs());
    assert_eq!(
        settings.tor,
        TorSettings {
            mode: TorMode::System,
            socks_proxy: Some("127.0.0.1:9150".to_owned()),
        }
    );
    let lock = manager.app_lock().await.expect("the app lock");
    assert_eq!(lock.kind, LockKind::Pin);
    assert!(lock.biometric);

    assert_eq!(
        manager.preferences().await,
        Preferences {
            unit: Unit::Sats,
            masked: true,
            fiat: true,
            fiat_currency: FiatCurrency::Usd,
            price_source: PriceSource::Coingecko,
            notify_new_tx: true,
            explorer_ack: true,
        }
    );
    assert!(!manager.update_status("0.1.0").await.automatic);
}

#[tokio::test]
async fn a_0_1_0_data_dir_opens_whole() {
    let (_dir, manager) = open_v0_1_0_data_dir();
    assert_v0_1_0_vault(&manager).await;
}

/// The wallet engines come back from what 0.1.0 stored: the descriptor
/// wallets derive the addresses they derived there.
#[tokio::test]
async fn a_0_1_0_wallet_derives_its_addresses() {
    let (_dir, manager) = open_v0_1_0_data_dir();
    for wallet in manager.list_wallets(None).await {
        let addresses = manager.receive_addresses(&wallet.id, 1).await.unwrap();
        let first = addresses.iter().find(|entry| entry.index == 0);
        match wallet.name.as_str() {
            "Savings" | "Spending" | "Cold" => {
                assert_eq!(
                    first.unwrap().address,
                    FIRST_WPKH_ADDRESS,
                    "{}",
                    wallet.name
                )
            }
            "Donations" => assert_eq!(first.unwrap().address, DONATIONS_ADDRESS),
            _ => assert!(first.is_some(), "{}", wallet.name),
        }
    }
}

/// A 0.1.0 vault this build saved opens again whole: the upgrade writes
/// nothing away.
#[tokio::test]
async fn a_0_1_0_vault_saved_by_this_build_reopens_whole() {
    let (dir, manager) = open_v0_1_0_data_dir();
    manager.set_active_network(Network::Signet).await.unwrap();
    drop(manager);
    let manager = WalletManager::open(dir.path(), VaultKey::Raw([7u8; 32])).unwrap();
    assert_v0_1_0_vault(&manager).await;
}

/// The PIN set in 0.1.0 still unlocks, and the wrong one it recorded
/// still counts.
#[tokio::test]
async fn a_0_1_0_app_lock_and_its_failed_attempt_carry_over() {
    let (_dir, manager) = open_v0_1_0_data_dir();
    let wrong = manager.verify_app_lock("000000").await.unwrap();
    assert!(!wrong.unlocked);
    assert_eq!(wrong.failures, 2);
    let right = manager.verify_app_lock(PIN).await.unwrap();
    assert!(right.unlocked);
    assert_eq!(right.failures, 0);
}

/// Restored wallets, without what a restore makes anew: the id and the
/// date of the record.
fn restored(wallets: &[WalletMeta]) -> Vec<WalletMeta> {
    wallets
        .iter()
        .map(|wallet| WalletMeta {
            id: String::new(),
            created_at: 0,
            ..wallet.clone()
        })
        .collect()
}

/// The wallets of the fixture vault as a 0.1.0 backup of them restores
/// them, under the gap limit of the device after the restore. A 0.1.0
/// backup carries no icon, so each comes back as the generic one; a
/// backup keeps a descriptor wallet as its descriptors, and a restore
/// records it as what they are, a pair or a single descriptor, as 0.1.0
/// already did.
fn expected_restored(wallets: &[WalletMeta], gap_limit: u32) -> Vec<WalletMeta> {
    restored(wallets)
        .into_iter()
        .map(|wallet| WalletMeta {
            icon: WalletIcon::Wallet,
            gap_limit,
            recognized_as: match &wallet.kind {
                WalletKind::Descriptors {
                    internal: Some(_), ..
                } => RecognizedKind::DescriptorPair,
                WalletKind::Descriptors { internal: None, .. } => RecognizedKind::Descriptor,
                WalletKind::SingleAddress { .. } => RecognizedKind::Address,
            },
            ..wallet
        })
        .collect()
}

/// A backup with every wallet and the settings, restored on a new
/// device from the text the source gave: the file, or the QR.
async fn assert_full_backup_restores(source: &str) {
    let (_dir, manager) = empty_manager();
    let preview = manager.preview_backup(source, PASSWORD).await.unwrap();
    assert!(preview.has_settings);
    let names: Vec<_> = preview.wallets.iter().map(|w| w.name.as_str()).collect();
    assert_eq!(
        names,
        [
            "Savings",
            "Spending",
            "Vault",
            "Cold",
            "Donations",
            "Recovery"
        ]
    );
    assert!(
        preview
            .wallets
            .iter()
            .all(|w| w.refused.is_none() && !w.already_watched)
    );
    assert_eq!(preview.electrum_hosts, [ELECTRUM_HOST]);

    let report = manager
        .import_backup(
            source,
            PASSWORD,
            &ImportChoices {
                indexes: None,
                apply_settings: true,
            },
        )
        .await
        .unwrap();
    assert!(report.settings_applied);
    assert_eq!(report.skipped, 0);
    assert!(report.refused.is_empty());
    assert_eq!(
        restored(&report.added),
        expected_restored(&v0_1_0_wallets(), 35)
    );
    let listed = manager.list_wallets(None).await;
    assert_eq!(restored(&listed), expected_restored(&v0_1_0_wallets(), 35));
    assert!(listed.iter().all(|wallet| wallet.gap_limit == 35));

    let settings = manager.settings().await;
    assert_eq!(settings.backends, v0_1_0_backends());
    assert_eq!(settings.gap_limit, 35);
    assert_eq!(settings.electrum_certs, v0_1_0_certs());
}

#[tokio::test]
async fn a_0_1_0_export_file_reads_whole() {
    assert_full_backup_restores(&read_fixture("backup-all-with-settings.gerfaut")).await;
}

/// The animated QR, caught from any frame of its loop, gives the text
/// the restore screen takes, the very bytes of the file.
#[tokio::test]
async fn a_0_1_0_animated_qr_reads_whole() {
    let frames: Vec<String> = read_fixture("backup-all-with-settings.qr.txt")
        .lines()
        .map(str::to_owned)
        .collect();
    assert_eq!(frames.len(), 7);
    let file = read_fixture("backup-all-with-settings.gerfaut");
    for start in [0, 3] {
        let mut looped = frames.clone();
        looped.rotate_left(start);
        let progress = qr::assemble(&looped).unwrap();
        assert!(progress.complete);
        let text = progress.text.unwrap();
        assert_eq!(text, format!("gerfaut-backup:{}", file.trim()));
        assert_full_backup_restores(&text).await;
    }
}

/// A backup of one address without the settings, by file and by QR,
/// leaves the settings of the device as they were.
#[tokio::test]
async fn a_0_1_0_single_wallet_backup_reads_whole() {
    let frames: Vec<String> = read_fixture("backup-one-address.qr.txt")
        .lines()
        .map(str::to_owned)
        .collect();
    let scanned = qr::assemble(&frames).unwrap().text.unwrap();
    for source in [read_fixture("backup-one-address.gerfaut"), scanned] {
        let (_dir, manager) = empty_manager();
        let preview = manager.preview_backup(&source, PASSWORD).await.unwrap();
        assert!(!preview.has_settings);
        assert!(preview.backends.is_empty());
        let report = manager
            .import_backup(
                &source,
                PASSWORD,
                &ImportChoices {
                    indexes: None,
                    apply_settings: true,
                },
            )
            .await
            .unwrap();
        assert!(!report.settings_applied);
        let donations = v0_1_0_wallets()
            .into_iter()
            .filter(|wallet| wallet.name == "Donations")
            .collect::<Vec<_>>();
        assert_eq!(restored(&report.added), expected_restored(&donations, 20));
        let settings = manager.settings().await;
        assert!(settings.backends.is_empty());
        assert_eq!(settings.gap_limit, 20);
        assert!(settings.electrum_certs.is_empty());
    }
}

/// A wrong password on a 0.1.0 backup is said as one, never as a backup
/// from a newer build or a damaged file.
#[tokio::test]
async fn a_0_1_0_backup_refuses_a_wrong_password_as_such() {
    let (_dir, manager) = empty_manager();
    let error = manager
        .preview_backup(
            &read_fixture("backup-one-address.gerfaut"),
            "not the password at all",
        )
        .await
        .unwrap_err();
    assert_eq!(error.code(), ErrorCode::WrongKey);
}

/// What this build writes in a backup of the restored wallets is read
/// back the same: a 0.1.0 backup survives a round through this build.
#[tokio::test]
async fn a_0_1_0_backup_restored_then_backed_up_again_reads_whole() {
    let (_dir, manager) = empty_manager();
    let source = read_fixture("backup-all-with-settings.gerfaut");
    manager
        .import_backup(
            &source,
            PASSWORD,
            &ImportChoices {
                indexes: None,
                apply_settings: true,
            },
        )
        .await
        .unwrap();
    let again = manager
        .export_backup(
            &BackupOptions {
                wallet_ids: None,
                include_settings: true,
            },
            PASSWORD,
        )
        .await
        .unwrap();
    assert_full_backup_restores(&again.data).await;
}
