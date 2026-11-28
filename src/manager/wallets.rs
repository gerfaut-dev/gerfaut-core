//! The wallets: adding, naming, ordering and removing them, and what
//! the screens read of each one.

use bdk_wallet::bitcoin::address::NetworkUnchecked;
use bdk_wallet::bitcoin::consensus::encode;
use bdk_wallet::bitcoin::{Address, OutPoint, Transaction, Txid};

use crate::broadcast::RecentBroadcast;
use crate::broadcast::traces::Traces;
use crate::error::{CoreError, CoreResult};
use crate::export::{ExportOptions, ExportResult};
use crate::input::{ParsedInput, ParsedPayload};
use crate::network::Network;
use crate::now_secs;
use crate::store::WalletRecord;
use crate::wallet::meta::{WalletIcon, WalletKind, WalletMeta};
use crate::wallet::policy::{self, PolicySnapshot};
use crate::wallet::snapshot::{AddressEntry, AddressList, TxDetail, UtxoInfo, WalletSnapshot};
use crate::wallet::views;

use super::{
    WalletManager, build_record, ensure_engine, find_record, find_record_mut, find_watched,
    fresh_meta, merge_changeset,
};

impl WalletManager {
    // --- wallet lifecycle ---------------------------------------------

    /// Lists wallet metadata, optionally restricted to one network.
    pub async fn list_wallets(&self, network: Option<Network>) -> Vec<WalletMeta> {
        let state = self.state.lock().await;
        let gap_limit = state.payload.settings.gap_limit;
        state
            .payload
            .wallets
            .iter()
            .filter(|record| network.is_none_or(|n| record.meta.network == n))
            .map(|record| record.meta.clone().presented(gap_limit))
            .collect()
    }

    /// Adds a wallet from classified input, on an explicit network the
    /// user confirmed among the input's candidates.
    pub async fn add_wallet(
        &self,
        name: &str,
        parsed: &ParsedInput,
        network: Network,
    ) -> CoreResult<WalletMeta> {
        let result: CoreResult<WalletMeta> = async {
            if !parsed.networks.contains(&network) {
                return Err(super::network_mismatch(network, &parsed.networks));
            }
            let name = clean_name(name)?;

            let kind = match &parsed.payload {
                ParsedPayload::Descriptors {
                    external,
                    internal,
                    script,
                } => WalletKind::Descriptors {
                    external: external.clone(),
                    internal: internal.clone(),
                    script: *script,
                },
                ParsedPayload::Address { address } => WalletKind::SingleAddress {
                    address: address.clone(),
                },
            };

            let mut state = self.state.lock().await;
            if let Some(existing) = find_watched(&state.payload, network, &kind) {
                return Err(CoreError::DuplicateWallet(existing.meta.name.clone()));
            }

            let meta = fresh_meta(name, network, kind, parsed.kind);
            let (record, engine) = build_record(meta.clone())?;
            state.commit(|payload| {
                payload.wallets.push(record);
                Ok(())
            })?;
            if let Some(engine) = engine {
                state.engines.insert(meta.id.clone(), engine);
            }
            Ok(meta.presented(state.payload.settings.gap_limit))
        }
        .await;
        self.live_refresh().await;
        result
    }

    pub async fn rename_wallet(&self, id: &str, name: &str) -> CoreResult<()> {
        let name = clean_name(name)?;
        self.state.lock().await.commit(|payload| {
            find_record_mut(payload, id)?.meta.name = name.to_owned();
            Ok(())
        })
    }

    /// Changes the glyph a wallet shows next to its name.
    pub async fn set_wallet_icon(&self, id: &str, icon: WalletIcon) -> CoreResult<()> {
        self.state.lock().await.commit(|payload| {
            find_record_mut(payload, id)?.meta.icon = icon;
            Ok(())
        })
    }

    /// Pins a wallet to the live watch, or unpins it. The scripts of the
    /// pinned wallets are watched before any other wallet's, up to what
    /// a watch takes of one wallet; the others share what is left, the
    /// wallets holding coins first. An advanced setting, off unless set,
    /// kept in the vault and carried by a backup.
    pub async fn set_wallet_live_pinned(&self, id: &str, pinned: bool) -> CoreResult<()> {
        let result = self.state.lock().await.commit(|payload| {
            find_record_mut(payload, id)?.meta.live_pinned = pinned;
            Ok(())
        });
        self.live_refresh().await;
        result
    }

    /// Puts the named wallets in the given order. Only the slots those
    /// wallets occupy are rearranged: a list shown for one network can
    /// be reordered without moving the wallets of another. Every id must
    /// name a wallet, and none may repeat.
    pub async fn reorder_wallets(&self, ids: &[String]) -> CoreResult<()> {
        self.state.lock().await.commit(|payload| {
            let mut seen = std::collections::HashSet::with_capacity(ids.len());
            for id in ids {
                if !seen.insert(id.as_str()) {
                    return Err(CoreError::InvalidInput {
                        kind: "wallet order",
                        detail: format!("wallet {id} is listed twice"),
                    });
                }
                if !payload.wallets.iter().any(|record| &record.meta.id == id) {
                    return Err(CoreError::WalletNotFound(id.clone()));
                }
            }
            // Take the moving records out, keep every other record where
            // it stands, and pour the movers back into the freed slots in
            // the requested order.
            let slots: Vec<usize> = payload
                .wallets
                .iter()
                .enumerate()
                .filter(|(_, record)| seen.contains(record.meta.id.as_str()))
                .map(|(index, _)| index)
                .collect();
            let mut movers: Vec<Option<WalletRecord>> = Vec::with_capacity(ids.len());
            for id in ids {
                let position = payload
                    .wallets
                    .iter()
                    .position(|record| &record.meta.id == id)
                    .expect("checked above");
                movers.push(Some(payload.wallets[position].clone()));
            }
            for (slot, mover) in slots.into_iter().zip(movers.iter_mut()) {
                payload.wallets[slot] = mover.take().expect("one mover per slot");
            }
            Ok(())
        })
    }

    /// Removes a wallet from this device, and everything the core kept
    /// that names it: its record, what the vault kept to announce about
    /// it, the transactions this app broadcast that touch it (one that
    /// touches another wallet too goes all the same: it says something
    /// of this one), the app preferences that name it, and what the
    /// session holds of it in memory.
    pub async fn remove_wallet(&self, id: &str) -> CoreResult<()> {
        let result: CoreResult<(Network, Traces)> = async {
            let mut state = self.state.lock().await;
            // Read before the engine goes: its scripts, coins and history
            // are what the broadcasts are held against.
            let (network, traces) = traces_of(&mut state, id)?;
            let names = names_of(&find_record(&state.payload, id)?.meta.kind, id);
            state.commit(|payload| {
                payload.wallets.retain(|record| record.meta.id != id);
                payload.unclaimed.retain(|news| news.wallet_id != id);
                // A record kept before announcements were by wallet
                // stands for every wallet: it goes when it names one of
                // this wallet's transactions.
                payload.announced.retain(|told| {
                    told.wallet_id != id
                        && !(told.wallet_id.is_empty() && names_a_txid(&traces, &told.txid))
                });
                payload.vanishing.retain(|missed| missed.wallet_id != id);
                payload
                    .broadcasts
                    .retain(|sent| !touches(sent, network, &traces));
                forget_in_prefs(&mut payload.settings.app_prefs, &names);
                Ok(())
            })?;
            state.engines.remove(id);
            state
                .orders
                .retain(|script, _| !traces.scripts.contains(script));
            Ok((network, traces))
        }
        .await;
        let result = result.map(|(network, traces)| {
            if let Ok(mut slots) = self.syncing.lock() {
                slots.remove(id);
            }
            if let Ok(mut done) = self.complete_here.lock() {
                done.remove(id);
            }
            crate::chain::proof::forget_proven_on(network, &traces.scripts);
        });
        self.live_refresh().await;
        result
    }

    // --- views ---------------------------------------------------------

    pub async fn wallet_snapshot(&self, id: &str) -> CoreResult<WalletSnapshot> {
        let mut state = self.state.lock().await;
        let record = find_record(&state.payload, id)?.clone();
        let gap_limit = state.payload.settings.gap_limit;
        match &record.meta.kind {
            WalletKind::Descriptors { .. } => {
                let engine = ensure_engine(&mut state, id)?;
                Ok(WalletSnapshot {
                    balance: views::balance(engine),
                    txs: views::tx_summaries(engine),
                    tip_height: views::tip_height(engine),
                    truncated: false,
                    meta: record.meta.presented(gap_limit),
                })
            }
            WalletKind::SingleAddress { .. } => {
                let watch = record.address_state.clone().unwrap_or_default();
                Ok(WalletSnapshot {
                    balance: views::address_balance(&watch),
                    txs: views::address_tx_summaries(&watch),
                    tip_height: watch.tip_height,
                    truncated: watch.truncated,
                    meta: record.meta.presented(gap_limit),
                })
            }
        }
    }

    pub async fn tx_detail(&self, id: &str, txid: &str) -> CoreResult<TxDetail> {
        let mut state = self.state.lock().await;
        let record = find_record(&state.payload, id)?.clone();
        match &record.meta.kind {
            WalletKind::Descriptors { .. } => {
                let network = record.meta.network;
                let engine = ensure_engine(&mut state, id)?;
                views::tx_detail(engine, network, txid)
            }
            WalletKind::SingleAddress { .. } => {
                let watch = record.address_state.clone().unwrap_or_default();
                views::address_tx_detail(&watch, txid)
            }
        }
    }

    pub async fn utxos(&self, id: &str) -> CoreResult<Vec<UtxoInfo>> {
        let mut state = self.state.lock().await;
        let record = find_record(&state.payload, id)?.clone();
        match &record.meta.kind {
            WalletKind::Descriptors { .. } => {
                let network = record.meta.network;
                let engine = ensure_engine(&mut state, id)?;
                Ok(views::utxos(engine, network))
            }
            WalletKind::SingleAddress { address } => {
                let watch = record.address_state.clone().unwrap_or_default();
                Ok(views::address_utxos(&watch, address))
            }
        }
    }

    /// The wallet's spending policy: its keys, its branches, and where
    /// every timelock stands against the tip and the coins. A watched
    /// address has no descriptor to read.
    pub async fn policy(&self, id: &str) -> CoreResult<PolicySnapshot> {
        let mut state = self.state.lock().await;
        let record = find_record(&state.payload, id)?.clone();
        // Before the first sync the engine's tip is zero, which would
        // put every height lock the whole chain away: no tip is given
        // until one has been seen.
        let synced = record.meta.last_sync.is_some();
        match &record.meta.kind {
            WalletKind::Descriptors {
                external, script, ..
            } => {
                let engine = ensure_engine(&mut state, id)?;
                policy::analyze(policy::PolicyInput {
                    external_descriptor: external,
                    script: *script,
                    coins: views::coins(engine),
                    tip_height: synced.then(|| views::tip_height(engine)),
                    now_unix: now_secs(),
                })
            }
            WalletKind::SingleAddress { address } => {
                let watch = record.address_state.clone().unwrap_or_default();
                Ok(policy::address_snapshot(
                    address,
                    synced.then_some(watch.tip_height),
                    watch.utxos.len() as u32,
                    now_secs(),
                ))
            }
        }
    }

    /// The next unused receive address plus `lookahead` upcoming ones.
    ///
    /// Single-address wallets return their one address.
    pub async fn receive_addresses(
        &self,
        id: &str,
        lookahead: u32,
    ) -> CoreResult<Vec<AddressEntry>> {
        let mut state = self.state.lock().await;
        let record = find_record(&state.payload, id)?.clone();
        match &record.meta.kind {
            WalletKind::Descriptors { .. } => {
                let engine = ensure_engine(&mut state, id)?;
                let entries = views::receive_addresses(engine, lookahead);
                // Revealing may stage a change set; persist it.
                let staged = engine.take_staged();
                if let Some(staged) = staged {
                    merge_changeset(&mut state, id, staged)?;
                    let state = &mut *state;
                    state.vault.save(&state.payload)?;
                }
                Ok(entries)
            }
            WalletKind::SingleAddress { address } => {
                Ok(vec![single_address_entry(&record, address)])
            }
        }
    }

    /// Keeps every receive address up to `index` revealed: the receive
    /// page shows it, so it counts as handed out, a sync watches it, and
    /// "New address" never offers it again. A single-address wallet has
    /// nothing to reveal.
    pub async fn reveal_receive_address(&self, id: &str, index: u32) -> CoreResult<()> {
        let mut state = self.state.lock().await;
        let record = find_record(&state.payload, id)?.clone();
        if let WalletKind::Descriptors { .. } = &record.meta.kind {
            let engine = ensure_engine(&mut state, id)?;
            views::reveal_receive_address(engine, index)?;
            let staged = engine.take_staged();
            if let Some(staged) = staged {
                merge_changeset(&mut state, id, staged)?;
                let state = &mut *state;
                state.vault.save(&state.payload)?;
            }
        }
        Ok(())
    }

    /// Revealed addresses of a wallet, by keychain, with usage and the
    /// balance on each. Capped: an audit view, not an infinite scroll.
    pub async fn address_list(&self, id: &str) -> CoreResult<AddressList> {
        let mut state = self.state.lock().await;
        let record = find_record(&state.payload, id)?.clone();
        match &record.meta.kind {
            WalletKind::Descriptors { .. } => {
                let engine = ensure_engine(&mut state, id)?;
                Ok(views::address_list(engine))
            }
            WalletKind::SingleAddress { address } => {
                let (used, balance_sats) = record
                    .address_state
                    .as_ref()
                    .map(|s| (!s.txs.is_empty(), views::address_balance(s).total))
                    .unwrap_or((false, 0));
                Ok(AddressList {
                    external: vec![crate::wallet::snapshot::AddressRow {
                        index: 0,
                        address: address.clone(),
                        used,
                        balance_sats,
                    }],
                    internal: Vec::new(),
                    truncated: false,
                })
            }
        }
    }

    /// Builds a CSV export of one wallet's transactions: exactly the
    /// rows the screens show, filtered. Everything stays local.
    pub async fn export_transactions(
        &self,
        id: &str,
        options: &ExportOptions,
    ) -> CoreResult<ExportResult> {
        let snapshot = self.wallet_snapshot(id).await?;
        Ok(crate::export::transactions_csv(&snapshot.txs, options))
    }
}

/// The one address of a single-address wallet, as the receive page
/// lists it: given out from the start.
fn single_address_entry(record: &WalletRecord, address: &str) -> AddressEntry {
    AddressEntry {
        index: 0,
        address: address.to_owned(),
        used: record
            .address_state
            .as_ref()
            .is_some_and(|s| !s.txs.is_empty()),
        derivation: None,
        revealed: true,
    }
}

// --- what a removed wallet leaves behind ----------------------------------

/// The network of a wallet, and what it left on the chain as far as the
/// device knows it: its scripts, revealed or not yet, its coins and its
/// history. A descriptor wallet's scripts are the ones its engine
/// recognises, look-ahead included, and those of every index up to the
/// gap limit past the last one revealed. An engine whose change set no
/// longer loads never keeps a wallet from going: its scripts are then
/// read from its descriptors alone, and its history is not known.
fn traces_of(state: &mut super::ManagerState, id: &str) -> CoreResult<(Network, Traces)> {
    let record = find_record(&state.payload, id)?.clone();
    let network = record.meta.network;
    let gap_limit = state.payload.settings.gap_limit;
    let mut traces = Traces::default();
    match &record.meta.kind {
        WalletKind::Descriptors {
            external, internal, ..
        } => match ensure_engine(state, id) {
            Ok(engine) => engine_traces(engine, gap_limit, &mut traces),
            Err(error) => {
                log::warn!("a removed wallet's history could not be read: {error}");
                match super::create_engine(external, internal.as_deref(), network) {
                    Ok(engine) => engine_traces(&engine, gap_limit, &mut traces),
                    Err(error) => {
                        log::warn!("a removed wallet's scripts could not be read: {error}");
                    }
                }
            }
        },
        WalletKind::SingleAddress { address } => {
            if let Ok(address) = address.parse::<Address<NetworkUnchecked>>() {
                traces
                    .scripts
                    .insert(address.assume_checked().script_pubkey());
            }
            let watch = record.address_state.unwrap_or_default();
            for coin in &watch.utxos {
                if let Ok(txid) = coin.txid.parse::<Txid>() {
                    traces.coins.insert(OutPoint::new(txid, coin.vout));
                }
            }
            for tx in &watch.txs {
                let Ok(txid) = tx.txid.parse::<Txid>() else {
                    continue;
                };
                traces.txids.insert(txid);
                for (vout, output) in tx.outputs.iter().enumerate() {
                    if output.is_mine {
                        traces.coins.insert(OutPoint::new(txid, vout as u32));
                    }
                }
                for input in tx.inputs.iter().filter(|input| input.is_mine) {
                    if let (Some(prev), Some(vout)) = (&input.prev_txid, input.prev_vout)
                        && let Ok(prev) = prev.parse::<Txid>()
                    {
                        traces.coins.insert(OutPoint::new(prev, vout));
                    }
                }
            }
        }
    }
    Ok((network, traces))
}

/// What a descriptor wallet's engine knows of it: see [`traces_of`].
fn engine_traces(engine: &bdk_wallet::Wallet, gap_limit: u32, traces: &mut Traces) {
    let index = engine.spk_index();
    traces
        .scripts
        .extend(index.inner().all_spks().values().cloned());
    for (keychain, scripts) in index.all_unbounded_spk_iters() {
        let past = index
            .last_revealed_index(keychain)
            .map_or(0, |last| last.saturating_add(1));
        let upto = past.saturating_add(gap_limit) as usize;
        traces
            .scripts
            .extend(scripts.take(upto).map(|(_, script)| script));
    }
    let graph = engine.tx_graph();
    traces.txids.extend(graph.full_txs().map(|node| node.txid));
    traces.coins.extend(
        graph
            .all_txouts()
            .filter(|(_, txout)| traces.scripts.contains(&txout.script_pubkey))
            .map(|(outpoint, _)| outpoint),
    );
}

/// Whether a transaction this app broadcast on `network` touches the
/// wallet whose traces these are. One that does not read says nothing.
fn touches(sent: &RecentBroadcast, network: Network, traces: &Traces) -> bool {
    sent.network == network
        && (names_a_txid(traces, &sent.txid)
            || encode::deserialize_hex::<Transaction>(&sent.hex)
                .is_ok_and(|tx| traces.touched_by(&tx)))
}

fn names_a_txid(traces: &Traces, txid: &str) -> bool {
    txid.parse::<Txid>()
        .is_ok_and(|txid| traces.txids.contains(&txid))
}

/// What names a wallet in a preference an app wrote: its id, its
/// descriptors, its address.
fn names_of(kind: &WalletKind, id: &str) -> Vec<String> {
    let mut names = vec![id.to_owned()];
    match kind {
        WalletKind::Descriptors {
            external, internal, ..
        } => names.extend(std::iter::once(external.clone()).chain(internal.clone())),
        WalletKind::SingleAddress { address } => names.push(address.clone()),
    }
    names
}

/// Takes a wallet out of the preferences the apps wrote. One whose key
/// names it goes. One whose value is a list (a JSON array or object, or
/// words between commas, an order of wallets for one) loses the items
/// that name it, and keeps the others. Any other value that names it
/// goes whole, and so does a list whose items, taken apart, still do: a
/// descriptor holds commas of its own.
fn forget_in_prefs(prefs: &mut std::collections::BTreeMap<String, String>, names: &[String]) {
    let named = |text: &str| names.iter().any(|name| text.contains(name.as_str()));
    prefs.retain(|key, value| {
        if named(key) {
            return false;
        }
        if !named(value) {
            return true;
        }
        match without(value, &named) {
            Some(rest) if !named(&rest) => {
                *value = rest;
                true
            }
            _ => false,
        }
    });
}

/// `value` without the items `named` finds a wallet in, when it is a
/// list; `None` when it is not one.
fn without(value: &str, named: &dyn Fn(&str) -> bool) -> Option<String> {
    use serde_json::Value;
    match serde_json::from_str::<Value>(value) {
        Ok(Value::Array(items)) => {
            let kept: Vec<Value> = items
                .into_iter()
                .filter(|item| !named(&item.to_string()))
                .collect();
            serde_json::to_string(&kept).ok()
        }
        Ok(Value::Object(fields)) => {
            let kept: serde_json::Map<String, Value> = fields
                .into_iter()
                .filter(|(key, item)| !named(key) && !named(&item.to_string()))
                .collect();
            serde_json::to_string(&kept).ok()
        }
        Ok(_) => None,
        Err(_) if value.contains(',') => {
            let kept: Vec<&str> = value.split(',').filter(|item| !named(item)).collect();
            Some(kept.join(","))
        }
        Err(_) => None,
    }
}

/// The name a wallet is kept under: the one given, without the spaces
/// around it. A wallet needs one, whether it is added, renamed or restored.
pub(super) fn clean_name(name: &str) -> CoreResult<&str> {
    let name = name.trim();
    if name.is_empty() {
        return Err(CoreError::InvalidInput {
            kind: "wallet name",
            detail: "a wallet needs a name".to_owned(),
        });
    }
    Ok(name)
}

#[cfg(test)]
mod tests;
