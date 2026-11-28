//! The wallets, against a vault on disk.

use super::*;
use crate::backup::{BackupOptions, ImportChoices};
use crate::input::parse_input;
use crate::manager::tests::support::{ADDRESS, BACKUP_PASSWORD, MULTIPATH, key, manager, seeded};
use crate::wallet::AddressWatchState;

#[tokio::test]
async fn add_list_snapshot_descriptor_wallet() {
    let dir = tempfile::tempdir().unwrap();
    let manager = manager(dir.path()).await;

    let parsed = parse_input(MULTIPATH).unwrap();
    let meta = manager
        .add_wallet("Signet cold", &parsed, Network::Signet)
        .await
        .unwrap();
    assert_eq!(meta.network, Network::Signet);

    let wallets = manager.list_wallets(Some(Network::Signet)).await;
    assert_eq!(wallets.len(), 1);
    assert!(
        manager
            .list_wallets(Some(Network::Mainnet))
            .await
            .is_empty()
    );

    let snapshot = manager.wallet_snapshot(&meta.id).await.unwrap();
    assert_eq!(snapshot.balance.total, 0);
    assert!(snapshot.txs.is_empty());
    assert_eq!(snapshot.tip_height, 0);
}

/// The app hands the parsed input back to be added, so what it holds
/// is read again: a hardened step after the key, which miniscript
/// panics on when asked for an address, or a descriptor nested past
/// reason, is refused in words, and nothing is stored.
#[tokio::test]
async fn a_descriptor_the_parser_would_refuse_is_refused_when_handed_back() {
    let dir = tempfile::tempdir().unwrap();
    let manager = manager(dir.path()).await;
    let tpub = "tpubDDnGNapGEY6AZAdQbfRJgMg9fvz8pUBrLwvyvUqEgcUfgzM6zc2eVK4vY9x9L5FJWdX8WumXuLEDV5zDZnTfbn87vLe9XceCFwTu9so9Kks";
    let mut parsed = parse_input(MULTIPATH).unwrap();
    for (external, refusal) in [
        (format!("wpkh({tpub}/84h/0/*)"), "key origin"),
        (format!("wpkh({tpub}/0/*h)"), "key origin"),
        (
            format!("{}{tpub}/0/*{}", "sh(".repeat(150), ")".repeat(150)),
            "nests deeper",
        ),
    ] {
        parsed.payload = ParsedPayload::Descriptors {
            external,
            internal: None,
            script: crate::input::ScriptKind::Segwit,
        };
        let error = manager
            .add_wallet("Handed back", &parsed, Network::Signet)
            .await
            .unwrap_err();
        assert!(
            matches!(&error, CoreError::Descriptor(detail) if detail.contains(refusal)),
            "{error}"
        );
    }
    assert!(manager.list_wallets(None).await.is_empty());
}

#[tokio::test]
async fn policy_of_a_descriptor_wallet_reads_its_keys() {
    let dir = tempfile::tempdir().unwrap();
    let manager = manager(dir.path()).await;
    let parsed = parse_input(MULTIPATH).unwrap();
    let meta = manager
        .add_wallet("Signet cold", &parsed, Network::Signet)
        .await
        .unwrap();

    let snapshot = manager.policy(&meta.id).await.unwrap();
    assert_eq!(snapshot.kind, policy::PolicyKind::SingleKey);
    assert_eq!(snapshot.script, crate::input::ScriptKind::Segwit);
    assert_eq!(snapshot.keys.len(), 1);
    assert_eq!(snapshot.keys[0].fingerprint.as_deref(), Some("9a6a2580"));
    assert_eq!(snapshot.keys[0].origin_path.as_deref(), Some("m/84'/1'/0'"));
    assert_eq!(snapshot.branches.len(), 1);
    assert!(snapshot.branches[0].spendable_now);
    assert_eq!(snapshot.coins, 0);
    assert_eq!(
        snapshot.tip_height, None,
        "never synced: no tip to measure from"
    );
    assert!(matches!(
        manager.policy("nope").await,
        Err(CoreError::WalletNotFound(_))
    ));
}

#[tokio::test]
async fn policy_of_a_watched_address_has_no_branches() {
    let dir = tempfile::tempdir().unwrap();
    let manager = manager(dir.path()).await;
    let address = "tb1qw508d6qejxtdg4y5r3zarvary0c5xw7kxpjzsx";
    let parsed = parse_input(address).unwrap();
    let meta = manager
        .add_wallet("Watched address", &parsed, Network::Signet)
        .await
        .unwrap();

    let snapshot = manager.policy(&meta.id).await.unwrap();
    assert_eq!(snapshot.kind, policy::PolicyKind::Address);
    assert_eq!(snapshot.script, crate::input::ScriptKind::Segwit);
    assert_eq!(snapshot.descriptor, address);
    assert_eq!(snapshot.policy, "address");
    assert!(snapshot.keys.is_empty());
    assert!(snapshot.branches.is_empty());
    assert!(!snapshot.has_timelocks);
}

#[tokio::test]
async fn receive_addresses_derive_and_persist() {
    let dir = tempfile::tempdir().unwrap();
    let manager = manager(dir.path()).await;
    let parsed = parse_input(MULTIPATH).unwrap();
    let meta = manager
        .add_wallet("Signet cold", &parsed, Network::Signet)
        .await
        .unwrap();

    let entries = manager.receive_addresses(&meta.id, 2).await.unwrap();
    assert_eq!(entries.len(), 3);
    assert!(entries[0].address.starts_with("tb1"));
    assert_eq!(entries[0].index, 0);
    assert_eq!(entries[2].index, 2);
    // Single-origin descriptor: the absolute path is unambiguous.
    assert_eq!(entries[0].derivation.as_deref(), Some("m/84'/1'/0'/0/0"));
    assert_eq!(entries[2].derivation.as_deref(), Some("m/84'/1'/0'/0/2"));

    // A fresh manager reloads the engine from the vault and derives
    // the same addresses.
    drop(manager);
    let manager = WalletManager::open(dir.path(), key()).unwrap();
    let again = manager.receive_addresses(&meta.id, 2).await.unwrap();
    assert_eq!(again[0].address, entries[0].address);
}

/// An address the receive page shows counts as handed out from then on,
/// after a restart too, whether "Next address" or "New address" brought
/// it there: the first address not revealed is one nobody was shown.
#[tokio::test]
async fn a_shown_receive_address_stays_handed_out() {
    let dir = tempfile::tempdir().unwrap();
    let manager = manager(dir.path()).await;
    let parsed = parse_input(MULTIPATH).unwrap();
    let meta = manager
        .add_wallet("Signet cold", &parsed, Network::Signet)
        .await
        .unwrap();
    let first = manager.receive_addresses(&meta.id, 3).await.unwrap();
    assert_eq!(first[0].index, 0);
    assert!(!first[2].revealed);

    // The page moved to index 2 and showed it.
    manager.reveal_receive_address(&meta.id, 2).await.unwrap();

    drop(manager);
    let manager = WalletManager::open(dir.path(), key()).unwrap();
    let listed = manager.receive_addresses(&meta.id, 4).await.unwrap();
    let revealed: Vec<(u32, bool)> = listed.iter().map(|e| (e.index, e.revealed)).collect();
    assert_eq!(
        revealed,
        [(0, true), (1, true), (2, true), (3, false), (4, false)]
    );
    // The addresses themselves are the ones shown before.
    assert_eq!(listed[2].address, first[2].address);

    // Showing one again changes nothing.
    manager.reveal_receive_address(&meta.id, 1).await.unwrap();
    let again = manager.receive_addresses(&meta.id, 4).await.unwrap();
    assert!(!again[3].revealed);
}

/// The page never shows an index past its reach: one asked for is a
/// mistake, refused rather than revealing thousands of addresses.
#[tokio::test]
async fn a_receive_address_past_the_page_reach_is_refused() {
    let dir = tempfile::tempdir().unwrap();
    let manager = manager(dir.path()).await;
    let parsed = parse_input(MULTIPATH).unwrap();
    let meta = manager
        .add_wallet("Signet cold", &parsed, Network::Signet)
        .await
        .unwrap();
    let _ = manager.receive_addresses(&meta.id, 0).await.unwrap();
    let err = manager
        .reveal_receive_address(&meta.id, 5_000)
        .await
        .unwrap_err();
    assert!(err.to_string().contains("past the addresses"), "{err}");
    let listed = manager.receive_addresses(&meta.id, 1).await.unwrap();
    assert!(!listed[1].revealed);
}

#[tokio::test]
async fn a_watched_address_has_nothing_to_reveal() {
    let dir = tempfile::tempdir().unwrap();
    let manager = manager(dir.path()).await;
    let address = "tb1qw508d6qejxtdg4y5r3zarvary0c5xw7kxpjzsx";
    let parsed = parse_input(address).unwrap();
    let meta = manager
        .add_wallet("Watched address", &parsed, Network::Signet)
        .await
        .unwrap();
    manager.reveal_receive_address(&meta.id, 0).await.unwrap();
    let listed = manager.receive_addresses(&meta.id, 0).await.unwrap();
    assert_eq!(listed[0].address, address);
    assert!(listed[0].revealed);
}

/// The receive page reads its address and the audit list at once, in
/// either order: the audit list lists the next address without revealing
/// it, so the receive page still sees one nobody was shown.
#[tokio::test]
async fn the_address_list_reveals_nothing() {
    let dir = tempfile::tempdir().unwrap();
    let manager = manager(dir.path()).await;
    let parsed = parse_input(MULTIPATH).unwrap();
    let meta = manager
        .add_wallet("Signet cold", &parsed, Network::Signet)
        .await
        .unwrap();
    let listed = manager.address_list(&meta.id).await.unwrap();
    assert_eq!(listed.external[0].index, 0);

    let offered = manager.receive_addresses(&meta.id, 0).await.unwrap();
    assert_eq!(offered[0].index, 0);
    assert!(!offered[0].revealed);
}

#[tokio::test]
async fn address_list_and_export_read_the_same_state() {
    let dir = tempfile::tempdir().unwrap();
    let manager = manager(dir.path()).await;
    let parsed = parse_input(MULTIPATH).unwrap();
    let meta = manager
        .add_wallet("Signet cold", &parsed, Network::Signet)
        .await
        .unwrap();

    // Fresh wallet: the next external address, no change yet.
    let list = manager.address_list(&meta.id).await.unwrap();
    assert_eq!(list.external.len(), 1);
    assert_eq!(list.external[0].index, 0);
    assert!(!list.external[0].used);
    assert_eq!(list.external[0].balance_sats, 0);
    assert!(list.internal.is_empty());
    assert!(!list.truncated);

    // Peeking receive addresses reveals further external rows.
    let _ = manager.receive_addresses(&meta.id, 0).await.unwrap();
    let again = manager.address_list(&meta.id).await.unwrap();
    assert!(!again.external.is_empty());
    assert_eq!(again.external[0].address, list.external[0].address);

    // An empty wallet exports a header and nothing else.
    let export = manager
        .export_transactions(&meta.id, &crate::export::ExportOptions::default())
        .await
        .unwrap();
    assert_eq!(export.rows, 0);
    assert!(export.csv.starts_with("txid,date_utc,"));
    assert_eq!(export.csv.lines().count(), 1);
}

#[tokio::test]
async fn duplicates_and_network_mismatch_are_refused() {
    let dir = tempfile::tempdir().unwrap();
    let manager = manager(dir.path()).await;
    let parsed = parse_input(MULTIPATH).unwrap();
    manager
        .add_wallet("One", &parsed, Network::Signet)
        .await
        .unwrap();

    assert!(matches!(
        manager.add_wallet("Two", &parsed, Network::Signet).await,
        Err(CoreError::DuplicateWallet(_))
    ));
    let mismatch = manager
        .add_wallet("Three", &parsed, Network::Mainnet)
        .await
        .unwrap_err();
    assert!(matches!(mismatch, CoreError::NetworkMismatch { .. }));
    assert_eq!(
        mismatch.to_string(),
        "network mismatch: input is for signet, testnet4 or regtest, expected mainnet"
    );
}

#[tokio::test]
async fn single_address_wallet_lifecycle() {
    let dir = tempfile::tempdir().unwrap();
    let manager = manager(dir.path()).await;
    let parsed = parse_input("tb1qw508d6qejxtdg4y5r3zarvary0c5xw7kxpjzsx").unwrap();
    let meta = manager
        .add_wallet("Watched address", &parsed, Network::Signet)
        .await
        .unwrap();

    let snapshot = manager.wallet_snapshot(&meta.id).await.unwrap();
    assert_eq!(snapshot.balance.total, 0);

    let entries = manager.receive_addresses(&meta.id, 5).await.unwrap();
    assert_eq!(entries.len(), 1, "a single address has a single entry");

    manager.remove_wallet(&meta.id).await.unwrap();
    assert!(manager.list_wallets(None).await.is_empty());
    assert!(matches!(
        manager.wallet_snapshot(&meta.id).await,
        Err(CoreError::WalletNotFound(_))
    ));
}

/// Coins no one can hold, as a hostile server may list them for a
/// watched address, show in its row at the largest balance there
/// is, as in its snapshot, instead of wrapping around.
#[tokio::test]
async fn an_address_row_never_overflows() {
    let dir = tempfile::tempdir().unwrap();
    let manager = manager(dir.path()).await;
    let parsed = parse_input("tb1qw508d6qejxtdg4y5r3zarvary0c5xw7kxpjzsx").unwrap();
    let meta = manager
        .add_wallet("Watched address", &parsed, Network::Signet)
        .await
        .unwrap();
    let coin = |txid: &str| crate::wallet::AddressUtxo {
        txid: txid.into(),
        vout: 0,
        value_sats: u64::MAX,
        height: Some(1),
        timestamp: None,
    };
    find_record_mut(&mut manager.state.lock().await.payload, &meta.id)
        .unwrap()
        .address_state = Some(crate::wallet::AddressWatchState {
        utxos: vec![coin("aa"), coin("bb")],
        ..Default::default()
    });

    let list = manager.address_list(&meta.id).await.unwrap();
    assert_eq!(list.external[0].balance_sats, u64::MAX);
}

/// A name is kept without the spaces around it, and a wallet is never
/// left without one, added or renamed.
#[tokio::test]
async fn a_name_is_trimmed_and_an_empty_one_refused() {
    let dir = tempfile::tempdir().unwrap();
    let manager = manager(dir.path()).await;
    let parsed = parse_input(MULTIPATH).unwrap();
    let nameless = manager
        .add_wallet("   ", &parsed, Network::Signet)
        .await
        .unwrap_err();
    assert_eq!(
        nameless.to_string(),
        "invalid wallet name: a wallet needs a name"
    );

    let meta = manager
        .add_wallet("  Cold  ", &parsed, Network::Signet)
        .await
        .unwrap();
    assert_eq!(meta.name, "Cold");
    manager.rename_wallet(&meta.id, " Vault\t").await.unwrap();
    assert_eq!(manager.list_wallets(None).await[0].name, "Vault");
    let nameless = manager.rename_wallet(&meta.id, " ").await.unwrap_err();
    assert_eq!(
        nameless.to_string(),
        "invalid wallet name: a wallet needs a name"
    );
    assert_eq!(manager.list_wallets(None).await[0].name, "Vault");
}

#[tokio::test]
async fn rename_persists() {
    let dir = tempfile::tempdir().unwrap();
    let manager = manager(dir.path()).await;
    let parsed = parse_input(MULTIPATH).unwrap();
    let meta = manager
        .add_wallet("Old name", &parsed, Network::Signet)
        .await
        .unwrap();
    manager.rename_wallet(&meta.id, "New name").await.unwrap();

    drop(manager);
    let manager = WalletManager::open(dir.path(), key()).unwrap();
    let wallets = manager.list_wallets(None).await;
    assert_eq!(wallets[0].name, "New name");
}

#[tokio::test]
async fn icon_defaults_to_the_wallet_and_persists() {
    let dir = tempfile::tempdir().unwrap();
    let manager = manager(dir.path()).await;
    let parsed = parse_input(MULTIPATH).unwrap();
    let meta = manager
        .add_wallet("Cold", &parsed, Network::Signet)
        .await
        .unwrap();
    assert_eq!(meta.icon, WalletIcon::Wallet);
    manager
        .set_wallet_icon(&meta.id, WalletIcon::Snowflake)
        .await
        .unwrap();
    assert!(matches!(
        manager.set_wallet_icon("nope", WalletIcon::Key).await,
        Err(CoreError::WalletNotFound(_))
    ));

    drop(manager);
    let manager = WalletManager::open(dir.path(), key()).unwrap();
    assert_eq!(
        manager.list_wallets(None).await[0].icon,
        WalletIcon::Snowflake
    );
}

#[tokio::test]
async fn reorder_persists_and_leaves_the_rest_alone() {
    let dir = tempfile::tempdir().unwrap();
    let manager = manager(dir.path()).await;
    let mut ids = Vec::new();
    for (name, input) in [
        ("A", MULTIPATH),
        ("B", ADDRESS),
        (
            "C",
            "tb1qrp33g0q5c5txsp9arysrx4k6zdkfs4nce4xj0gdcccefvpysxf3q0sl5k7",
        ),
    ] {
        let parsed = parse_input(input).unwrap();
        let meta = manager
            .add_wallet(name, &parsed, Network::Signet)
            .await
            .unwrap();
        ids.push(meta.id);
    }
    let names = |wallets: Vec<WalletMeta>| -> Vec<String> {
        wallets.into_iter().map(|meta| meta.name).collect()
    };

    // Only two of the three are named: they swap, the third keeps
    // its slot.
    manager
        .reorder_wallets(&[ids[2].clone(), ids[0].clone()])
        .await
        .unwrap();
    assert_eq!(names(manager.list_wallets(None).await), ["C", "B", "A"]);

    let refused = manager
        .reorder_wallets(&[ids[0].clone(), ids[0].clone()])
        .await
        .unwrap_err();
    assert!(
        matches!(refused, CoreError::InvalidInput { .. }),
        "{refused}"
    );
    assert!(matches!(
        manager.reorder_wallets(&["nope".to_owned()]).await,
        Err(CoreError::WalletNotFound(_))
    ));

    drop(manager);
    let manager = WalletManager::open(dir.path(), key()).unwrap();
    assert_eq!(names(manager.list_wallets(None).await), ["C", "B", "A"]);
}

/// A pin is kept in the vault and carried by a backup, and the live
/// watch reads it with whether each wallet holds coins.
#[tokio::test]
async fn a_pinned_wallet_stays_pinned_and_travels_in_a_backup() {
    let source_dir = tempfile::tempdir().unwrap();
    let (source, cold, watch) = seeded(source_dir.path()).await;
    assert!(matches!(
        source.set_wallet_live_pinned("nope", true).await,
        Err(CoreError::WalletNotFound(_))
    ));
    source
        .set_wallet_live_pinned(&watch.id, true)
        .await
        .unwrap();
    let flags = async |manager: &WalletManager| {
        manager
            .watch_list(Network::Signet)
            .await
            .into_iter()
            .map(|wallet| (wallet.pinned, wallet.holds_coins))
            .collect::<Vec<_>>()
    };
    assert_eq!(flags(&source).await, [(false, false), (true, false)]);

    // A coin on each: one the cold wallet's engine holds, one in the
    // state of the watched address.
    {
        let mut state = source.state.lock().await;
        let engine = ensure_engine(&mut state, &cold.id).unwrap();
        let ours = engine
            .reveal_next_address(bdk_wallet::KeychainKind::External)
            .script_pubkey()
            .to_hex_string();
        engine.apply_unconfirmed_txs([(
            crate::testkit::transaction(
                &[crate::testkit::nowhere(1, 0)],
                &[(ours.as_str(), 50_000)],
            ),
            1_700_000_000,
        )]);
        find_record_mut(&mut state.payload, &watch.id)
            .unwrap()
            .address_state = Some(AddressWatchState {
            utxos: vec![crate::wallet::AddressUtxo {
                txid: "aa".repeat(32),
                vout: 0,
                value_sats: 1_000,
                height: Some(10),
                timestamp: None,
            }],
            ..Default::default()
        });
    }
    assert_eq!(flags(&source).await, [(false, true), (true, true)]);

    // Kept on disk.
    drop(source);
    let source = WalletManager::open(source_dir.path(), key()).unwrap();
    let pinned = |wallets: Vec<WalletMeta>| {
        wallets
            .into_iter()
            .map(|meta| (meta.name, meta.live_pinned))
            .collect::<Vec<_>>()
    };
    let expected = vec![("Cold".to_owned(), false), ("Watch".to_owned(), true)];
    assert_eq!(pinned(source.list_wallets(None).await), expected);

    let options = BackupOptions {
        wallet_ids: None,
        include_settings: false,
    };
    let bundle = source
        .export_backup(&options, BACKUP_PASSWORD)
        .await
        .unwrap();
    let target_dir = tempfile::tempdir().unwrap();
    let target = manager(target_dir.path()).await;
    target
        .import_backup(&bundle.data, BACKUP_PASSWORD, &ImportChoices::default())
        .await
        .unwrap();
    assert_eq!(pinned(target.list_wallets(None).await), expected);

    source
        .set_wallet_live_pinned(&watch.id, false)
        .await
        .unwrap();
    assert!(
        source
            .list_wallets(None)
            .await
            .iter()
            .all(|meta| !meta.live_pinned)
    );
}

/// A wallet removed leaves nothing in the vault that names it: its
/// record, what was announced of it, the transactions this app
/// broadcast that touch it, even one that touches another wallet too,
/// and the app preferences that name it. What is another wallet's, and
/// a transaction of nobody's, stays.
#[tokio::test]
async fn a_removed_wallet_leaves_nothing_in_the_vault() {
    use crate::broadcast::RecentBroadcast;
    use crate::chain::proof::{ProvenCoin, proven_coin, remember_coin};
    use crate::store::{Announced, TxStage, Unclaimed, Vault};
    use crate::testkit::{nowhere, script, transaction};
    use bdk_wallet::KeychainKind::{External, Internal};
    use bdk_wallet::bitcoin::consensus::encode::serialize_hex;
    use bdk_wallet::bitcoin::hashes::Hash;
    use bdk_wallet::bitcoin::secp256k1::Secp256k1;
    use bdk_wallet::bitcoin::{Address, Witness};
    use bdk_wallet::miniscript::Descriptor;

    let dir = tempfile::tempdir().unwrap();
    let (manager, cold, watch) = seeded(dir.path()).await;
    let watched = ADDRESS
        .parse::<Address<_>>()
        .unwrap()
        .assume_checked()
        .script_pubkey();
    // A server the settings do not name: the live watch, or a backend
    // chosen before, may have proven coins there.
    let server = "tcp://elsewhere.removal-test.invalid:50001";
    // A script of nobody's, of this test alone: what is proven of it
    // stays.
    let nobodys = bdk_wallet::bitcoin::ScriptBuf::new_p2wsh(
        &bdk_wallet::bitcoin::WScriptHash::from_byte_array([0xc3; 32]),
    );
    let (cold_addresses, gone, kept) = {
        let mut state = manager.state.lock().await;
        let engine = ensure_engine(&mut state, &cold.id).unwrap();
        let cold_addresses: Vec<String> = [External, Internal]
            .into_iter()
            .flat_map(|keychain| (0..30).map(move |index| (keychain, index)))
            .flat_map(|(keychain, index)| {
                let address = engine.peek_address(keychain, index);
                [address.to_string(), address.script_pubkey().to_hex_string()]
            })
            .collect();
        // In its history alone: it pays and spends nothing of it.
        let history_only = transaction(&[nowhere(1, 0)], &[(script(1).as_str(), 1_000)]);
        let mut update = bdk_wallet::Update::default();
        update
            .tx_update
            .txs
            .push(std::sync::Arc::new(history_only.clone()));
        engine.apply_update(update).unwrap();
        // Paying an address it never revealed.
        let unrevealed = engine.peek_address(External, 5).script_pubkey();
        let pays_cold = transaction(
            &[nowhere(2, 0)],
            &[(unrevealed.to_hex_string().as_str(), 2_000)],
        );
        // Spending a coin of it the device never saw, known by the key
        // its witness reveals, and paying the other wallet.
        let secp = Secp256k1::verification_only();
        let Descriptor::Wpkh(change) = engine
            .public_descriptor(Internal)
            .at_derivation_index(2)
            .unwrap()
            .derived_descriptor(&secp)
            .unwrap()
        else {
            panic!("the test wallet is wpkh");
        };
        let mut both = transaction(
            &[nowhere(3, 0)],
            &[(watched.to_hex_string().as_str(), 3_000)],
        );
        both.input[0].witness =
            Witness::from_slice(&[vec![0x30; 71], change.as_inner().to_bytes()]);
        let pays_watch = transaction(
            &[nowhere(4, 0)],
            &[(watched.to_hex_string().as_str(), 4_000)],
        );
        let foreign = transaction(&[nowhere(5, 0)], &[(script(5).as_str(), 5_000)]);

        let txid = |tx: &bdk_wallet::bitcoin::Transaction| tx.compute_txid().to_string();
        let (cold_id, watch_id) = (cold.id.clone(), watch.id.clone());
        let announced = |wallet_id: &str, tx| Announced {
            wallet_id: wallet_id.to_owned(),
            txid: txid(tx),
            stage: TxStage::Mempool,
            replaces: None,
        };
        let unclaimed = |wallet_id: &str, tx| Unclaimed {
            wallet_id: wallet_id.to_owned(),
            txid: txid(tx),
            net_sats: 1,
            stage: TxStage::Mempool,
            found_at: 1,
            replaces: None,
        };
        let txs = [&history_only, &pays_cold, &both, &pays_watch, &foreign];
        state
            .commit(|payload| {
                for tx in txs {
                    payload.remember_broadcast(RecentBroadcast {
                        txid: txid(tx),
                        network: Network::Signet,
                        hex: serialize_hex(tx),
                        backend: server.to_owned(),
                        at: 1,
                    });
                }
                payload.announced.extend([
                    announced(&cold_id, &pays_cold),
                    announced(&watch_id, &pays_watch),
                    // Written before announcements were by wallet.
                    announced("", &history_only),
                    announced("", &foreign),
                ]);
                payload.unclaimed.extend([
                    unclaimed(&cold_id, &both),
                    unclaimed(&watch_id, &pays_watch),
                ]);
                let prefs = &mut payload.settings.app_prefs;
                prefs.insert(
                    "test.order".into(),
                    serde_json::to_string(&[&cold_id, &watch_id]).unwrap(),
                );
                prefs.insert("test.listed".into(), format!("{watch_id},{cold_id}"));
                prefs.insert("test.last".into(), cold_id.clone());
                prefs.insert(format!("test.icon.{cold_id}"), "vault".into());
                prefs.insert("desktop.theme".into(), "dark".into());
                Ok(())
            })
            .unwrap();
        let proven = |script: &bdk_wallet::bitcoin::ScriptBuf| ProvenCoin {
            script: script.clone(),
            value: 1,
            height: 1,
            time: None,
        };
        remember_coin(Network::Signet, server, nowhere(6, 0), proven(&unrevealed));
        remember_coin(Network::Signet, server, nowhere(7, 0), proven(&nobodys));

        let gone: Vec<String> = [&history_only, &pays_cold, &both]
            .into_iter()
            .flat_map(|tx| [txid(tx), serialize_hex(tx)])
            .collect();
        let kept: Vec<String> = [&pays_watch, &foreign]
            .into_iter()
            .flat_map(|tx| [txid(tx), serialize_hex(tx)])
            .collect();
        (cold_addresses, gone, kept)
    };

    manager.remove_wallet(&cold.id).await.unwrap();

    // Forgotten in memory too.
    let proven = |script: &bdk_wallet::bitcoin::ScriptBuf, n| {
        let coin = ProvenCoin {
            script: script.clone(),
            value: 1,
            height: 1,
            time: None,
        };
        proven_coin(Network::Signet, server, nowhere(n, 0), &coin)
    };
    let unrevealed = cold_addresses[10]
        .parse::<Address<_>>()
        .unwrap()
        .assume_checked()
        .script_pubkey();
    assert!(proven(&unrevealed, 6).is_none());
    assert!(proven(&nobodys, 7).is_some());

    drop(manager);
    let (_vault, payload) = Vault::open_or_create(dir.path().join("gerfaut.vault"), key()).unwrap();
    let json = serde_json::to_string(&payload).unwrap();
    let tpub = MULTIPATH
        .split(']')
        .nth(1)
        .unwrap()
        .split('/')
        .next()
        .unwrap();
    for named in [&cold.id, &tpub.to_owned()]
        .into_iter()
        .chain(&cold_addresses)
        .chain(&gone)
    {
        assert!(
            !json.contains(named.as_str()),
            "{named} is still in the vault"
        );
    }
    for owned in [&watch.id, &ADDRESS.to_owned()].into_iter().chain(&kept) {
        assert!(json.contains(owned.as_str()), "{owned} left the vault");
    }
    let prefs = &payload.settings.app_prefs;
    assert_eq!(
        prefs.get("test.order"),
        Some(&serde_json::to_string(&[&watch.id]).unwrap())
    );
    assert_eq!(prefs.get("test.listed"), Some(&watch.id));
    assert_eq!(prefs.get("desktop.theme").map(String::as_str), Some("dark"));
    assert_eq!(prefs.len(), 3, "{prefs:?}");
}

/// The preferences an app wrote lose what names a removed wallet, and
/// keep the rest: a list loses its item, anything else goes whole.
#[test]
fn the_app_preferences_forget_a_removed_wallet() {
    let descriptor = "wsh(multi(2,tpubA/0/*,tpubB/0/*))#checksum";
    let names = vec!["id-gone".to_owned(), descriptor.to_owned()];
    let mut prefs: std::collections::BTreeMap<String, String> = [
        ("order", r#"["id-kept","id-gone"]"#.to_owned()),
        (
            "icons",
            r#"{"id-gone":"vault","id-kept":"coin"}"#.to_owned(),
        ),
        ("listed", "id-gone,id-kept".to_owned()),
        ("only", "id-gone".to_owned()),
        ("pasted", descriptor.to_owned()),
        ("pasted.list", format!("{descriptor},id-kept")),
        ("per.id-gone", "1".to_owned()),
        ("theme", "dark".to_owned()),
    ]
    .into_iter()
    .map(|(key, value)| (key.to_owned(), value))
    .collect();
    forget_in_prefs(&mut prefs, &names);
    let kept: Vec<(&str, &str)> = prefs
        .iter()
        .map(|(key, value)| (key.as_str(), value.as_str()))
        .collect();
    assert_eq!(
        kept,
        [
            ("icons", r#"{"id-kept":"coin"}"#),
            ("listed", "id-kept"),
            ("order", r#"["id-kept"]"#),
            ("theme", "dark"),
        ]
    );
}

/// A wallet whose engine no longer loads still goes, and the
/// transactions broadcast to its scripts with it: they are read from its
/// descriptors.
#[tokio::test]
async fn a_wallet_whose_engine_does_not_load_still_leaves_nothing() {
    use crate::broadcast::RecentBroadcast;
    use crate::testkit::{nowhere, transaction};
    use bdk_wallet::bitcoin::consensus::encode::serialize_hex;

    let dir = tempfile::tempdir().unwrap();
    let (manager, cold, _) = seeded(dir.path()).await;
    {
        let mut state = manager.state.lock().await;
        let ours = ensure_engine(&mut state, &cold.id)
            .unwrap()
            .peek_address(bdk_wallet::KeychainKind::External, 3)
            .script_pubkey()
            .to_hex_string();
        let paying = transaction(&[nowhere(1, 0)], &[(ours.as_str(), 1_000)]);
        state.engines.remove(&cold.id);
        state.payload.remember_broadcast(RecentBroadcast {
            txid: paying.compute_txid().to_string(),
            network: Network::Signet,
            hex: serialize_hex(&paying),
            backend: String::new(),
            at: 1,
        });
        find_record_mut(&mut state.payload, &cold.id)
            .unwrap()
            .changeset = None;
    }
    manager.remove_wallet(&cold.id).await.unwrap();
    assert!(manager.recent_broadcasts(Network::Signet).await.is_empty());
    assert_eq!(manager.list_wallets(None).await.len(), 1);
}

/// A payment to an address past what the engine looks ahead, within the
/// gap limit, is the wallet's all the same: it goes with it.
#[tokio::test]
async fn a_payment_within_the_gap_limit_goes_with_its_wallet() {
    use crate::broadcast::RecentBroadcast;
    use crate::testkit::{nowhere, transaction};
    use bdk_wallet::bitcoin::consensus::encode::serialize_hex;

    let dir = tempfile::tempdir().unwrap();
    let (manager, cold, _) = seeded(dir.path()).await;
    manager.set_gap_limit(60).await.unwrap();
    {
        let mut state = manager.state.lock().await;
        let engine = ensure_engine(&mut state, &cold.id).unwrap();
        let far = engine
            .peek_address(bdk_wallet::KeychainKind::External, 50)
            .script_pubkey();
        assert!(
            !engine
                .spk_index()
                .inner()
                .all_spks()
                .values()
                .any(|known| *known == far),
            "the engine does not look that far ahead"
        );
        let paying = transaction(&[nowhere(1, 0)], &[(far.to_hex_string().as_str(), 1_000)]);
        state.payload.remember_broadcast(RecentBroadcast {
            txid: paying.compute_txid().to_string(),
            network: Network::Signet,
            hex: serialize_hex(&paying),
            backend: String::new(),
            at: 1,
        });
    }
    manager.remove_wallet(&cold.id).await.unwrap();
    assert!(manager.recent_broadcasts(Network::Signet).await.is_empty());
}
