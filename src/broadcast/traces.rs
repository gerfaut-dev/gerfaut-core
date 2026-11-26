//! What a transaction says of a wallet: it is in the wallet's history,
//! it pays one of the wallet's scripts, or it spends one of its coins.
//! Read when a wallet is removed, so that the transactions this app
//! broadcast that name it leave with it.
//!
//! A coin the device never saw is still recognised where the input
//! carries its script: the public key of a P2WPKH or P2PKH spend, the
//! witness script of a P2WSH spend, the redeem script of a P2SH spend
//! (nested segwit included, which names its P2SH coin alone), and the leaf script and control block of a
//! taproot script-path spend, from which the output key is computed. A
//! taproot key-path spend carries a signature alone and names no
//! script: such an input is recognised by its coin or not at all.

use std::collections::HashSet;

use bdk_wallet::bitcoin::key::TapTweak;
use bdk_wallet::bitcoin::opcodes::all::{OP_PUSHNUM_1, OP_PUSHNUM_16, OP_PUSHNUM_NEG1};
use bdk_wallet::bitcoin::script::Instruction;
use bdk_wallet::bitcoin::secp256k1::Secp256k1;
use bdk_wallet::bitcoin::taproot::{ControlBlock, TapNodeHash};
use bdk_wallet::bitcoin::{
    CompressedPublicKey, OutPoint, PublicKey, Script, ScriptBuf, Transaction, TxIn, Txid, Witness,
};

/// What a wallet left on the chain, as far as this device knows it.
#[derive(Debug, Default)]
pub(crate) struct Traces {
    /// Its scripts: every one it may have been paid on.
    pub scripts: HashSet<ScriptBuf>,
    /// Its coins, spent or not.
    pub coins: HashSet<OutPoint>,
    /// The transactions of its history.
    pub txids: HashSet<Txid>,
}

impl Traces {
    /// Whether `tx` says something of the wallet: in its history,
    /// paying one of its scripts, or spending one of its coins.
    pub(crate) fn touched_by(&self, tx: &Transaction) -> bool {
        self.txids.contains(&tx.compute_txid())
            || tx
                .output
                .iter()
                .any(|output| self.scripts.contains(&output.script_pubkey))
            || tx.input.iter().any(|input| {
                self.coins.contains(&input.previous_output)
                    || spent_scripts(input)
                        .iter()
                        .any(|script| self.scripts.contains(script))
            })
    }
}

/// The scripts the coin an input spends may be locked by, read from
/// what the input carries. Each is a candidate: the reading does not
/// know which kind of spend the input is, and tries every one. The
/// witness alone names a native segwit or taproot coin only when the
/// signature script is empty: one that is not spends a P2SH coin, the
/// witness of nested segwit, whose script is the redeem script's and
/// not the one the same key or witness script makes natively.
pub(crate) fn spent_scripts(input: &TxIn) -> Vec<ScriptBuf> {
    let mut scripts = Vec::new();
    let witness = &input.witness;
    let native = input.script_sig.is_empty();
    if native && let Some(script) = taproot_script_path(witness) {
        scripts.push(script);
    }
    if native && let Some(last) = witness.last() {
        // P2WPKH: a signature, then the public key.
        if witness.len() == 2
            && let Ok(key) = CompressedPublicKey::from_slice(last)
        {
            scripts.push(ScriptBuf::new_p2wpkh(&key.wpubkey_hash()));
        }
        // P2WSH: the witness script comes last.
        scripts.push(ScriptBuf::new_p2wsh(
            &Script::from_bytes(last).wscript_hash(),
        ));
    }
    if let Some(last) = last_push(&input.script_sig) {
        // P2SH, nested segwit among it: the redeem script comes last.
        scripts.push(ScriptBuf::new_p2sh(&Script::from_bytes(last).script_hash()));
        // P2PKH: a signature, then the public key.
        if let Ok(key) = PublicKey::from_slice(last) {
            scripts.push(ScriptBuf::new_p2pkh(&key.pubkey_hash()));
        }
    }
    scripts
}

/// The output a taproot script-path spend comes from: its leaf script
/// hashed up the control block's branch to the root, the internal key
/// tweaked by it. `None` for a witness that is not one.
fn taproot_script_path(witness: &Witness) -> Option<ScriptBuf> {
    let leaf = witness.taproot_leaf_script()?;
    let control = ControlBlock::decode(witness.taproot_control_block()?).ok()?;
    let mut node = TapNodeHash::from_script(leaf.script, control.leaf_version);
    for branch in &control.merkle_branch {
        node = TapNodeHash::from_node_hashes(node, *branch);
    }
    let (output_key, _) = control
        .internal_key
        .tap_tweak(&Secp256k1::verification_only(), Some(node));
    Some(ScriptBuf::new_p2tr_tweaked(output_key))
}

/// The last push of data of a script made of pushes alone, as a
/// signature script is: a small number pushed by its own opcode, the
/// branch a spend takes for one, is a push too, of no script.
fn last_push(script: &Script) -> Option<&[u8]> {
    let mut last = None;
    for instruction in script.instructions() {
        match instruction.ok()? {
            Instruction::PushBytes(bytes) => last = Some(bytes.as_bytes()),
            Instruction::Op(op)
                if op == OP_PUSHNUM_NEG1
                    || (OP_PUSHNUM_1.to_u8()..=OP_PUSHNUM_16.to_u8()).contains(&op.to_u8()) =>
            {
                last = None;
            }
            Instruction::Op(_) => return None,
        }
    }
    last
}

#[cfg(test)]
mod tests {
    use bdk_wallet::bitcoin::absolute::LockTime;
    use bdk_wallet::bitcoin::hashes::Hash;
    use bdk_wallet::bitcoin::opcodes::all::{OP_CHECKSIG, OP_CHECKSIGVERIFY};
    use bdk_wallet::bitcoin::script::Builder;
    use bdk_wallet::bitcoin::taproot::{LeafVersion, TaprootBuilder};
    use bdk_wallet::bitcoin::transaction::Version;
    use bdk_wallet::bitcoin::{Amount, Sequence, TxOut, XOnlyPublicKey};

    use super::*;

    /// The secp256k1 generator and its double, public points nobody
    /// holds a secret for that matters here.
    const KEY_A: &str = "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798";
    const KEY_B: &str = "02c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5";

    fn key(hex: &str) -> PublicKey {
        hex.parse().unwrap()
    }

    /// A signature's worth of bytes: its contents are never read.
    fn signature() -> Vec<u8> {
        vec![0x30; 71]
    }

    fn spending(witness: Witness, script_sig: ScriptBuf) -> TxIn {
        TxIn {
            previous_output: OutPoint::new(Txid::from_byte_array([7; 32]), 0),
            script_sig,
            sequence: Sequence::MAX,
            witness,
        }
    }

    fn tx(input: Vec<TxIn>, output: Vec<ScriptBuf>) -> Transaction {
        Transaction {
            version: Version::TWO,
            lock_time: LockTime::ZERO,
            input,
            output: output
                .into_iter()
                .map(|script_pubkey| TxOut {
                    value: Amount::from_sat(10_000),
                    script_pubkey,
                })
                .collect(),
        }
    }

    fn holding(scripts: &[&ScriptBuf]) -> Traces {
        Traces {
            scripts: scripts.iter().map(|script| (*script).clone()).collect(),
            ..Traces::default()
        }
    }

    fn two_of_two() -> ScriptBuf {
        Builder::new()
            .push_key(&key(KEY_A))
            .push_opcode(OP_CHECKSIGVERIFY)
            .push_key(&key(KEY_B))
            .push_opcode(OP_CHECKSIG)
            .into_script()
    }

    /// A coin of a P2WSH wallet the device never saw spent: the witness
    /// script it reveals is the wallet's.
    #[test]
    fn a_p2wsh_input_is_known_by_its_witness_script() {
        let witness_script = two_of_two();
        let ours = ScriptBuf::new_p2wsh(&witness_script.wscript_hash());
        let mut witness = Witness::new();
        witness.push(signature());
        witness.push(signature());
        witness.push(witness_script.as_bytes());
        let spend = tx(vec![spending(witness, ScriptBuf::new())], vec![]);
        assert!(holding(&[&ours]).touched_by(&spend));
        let other = ScriptBuf::new_p2wsh(&ScriptBuf::new().wscript_hash());
        assert!(!holding(&[&other]).touched_by(&spend));
    }

    #[test]
    fn a_p2wpkh_and_a_p2pkh_input_are_known_by_their_key() {
        let key = key(KEY_A);
        let compressed = CompressedPublicKey::try_from(key).unwrap();
        let segwit = ScriptBuf::new_p2wpkh(&compressed.wpubkey_hash());
        let legacy = ScriptBuf::new_p2pkh(&key.pubkey_hash());
        let mut witness = Witness::new();
        witness.push(signature());
        witness.push(key.to_bytes());
        let segwit_spend = tx(vec![spending(witness, ScriptBuf::new())], vec![]);
        assert!(holding(&[&segwit]).touched_by(&segwit_spend));
        let script_sig = Builder::new()
            .push_slice(
                <&bdk_wallet::bitcoin::script::PushBytes>::try_from(&signature()[..]).unwrap(),
            )
            .push_key(&key)
            .into_script();
        let legacy_spend = tx(vec![spending(Witness::new(), script_sig)], vec![]);
        assert!(holding(&[&legacy]).touched_by(&legacy_spend));
    }

    /// Nested segwit: the redeem script in the signature script is what
    /// the P2SH output committed to.
    #[test]
    fn a_nested_segwit_input_is_known_by_its_redeem_script() {
        let compressed = CompressedPublicKey::try_from(key(KEY_A)).unwrap();
        let redeem = ScriptBuf::new_p2wpkh(&compressed.wpubkey_hash());
        let ours = ScriptBuf::new_p2sh(&redeem.script_hash());
        let script_sig = Builder::new()
            .push_slice(
                <&bdk_wallet::bitcoin::script::PushBytes>::try_from(redeem.as_bytes()).unwrap(),
            )
            .into_script();
        let mut witness = Witness::new();
        witness.push(signature());
        witness.push(compressed.to_bytes());
        let spend = tx(vec![spending(witness, script_sig)], vec![]);
        assert!(holding(&[&ours]).touched_by(&spend));
    }

    /// A legacy P2SH spend that picks a branch with a small number, as
    /// an `or_i` does: the redeem script still comes last.
    #[test]
    fn a_p2sh_input_that_picks_a_branch_is_known_by_its_redeem_script() {
        let redeem = two_of_two();
        let ours = ScriptBuf::new_p2sh(&redeem.script_hash());
        let script_sig = Builder::new()
            .push_slice(
                <&bdk_wallet::bitcoin::script::PushBytes>::try_from(&signature()[..]).unwrap(),
            )
            .push_int(1)
            .push_slice(
                <&bdk_wallet::bitcoin::script::PushBytes>::try_from(redeem.as_bytes()).unwrap(),
            )
            .into_script();
        let spend = tx(vec![spending(Witness::new(), script_sig)], vec![]);
        assert!(holding(&[&ours]).touched_by(&spend));
    }

    /// The witness of a nested segwit spend carries the same key as a
    /// native one, but the coin it spends is the P2SH one: a wallet of
    /// the native script is not named by it.
    #[test]
    fn a_nested_segwit_input_does_not_name_the_native_script() {
        let compressed = CompressedPublicKey::try_from(key(KEY_A)).unwrap();
        let native = ScriptBuf::new_p2wpkh(&compressed.wpubkey_hash());
        let script_sig = Builder::new()
            .push_slice(
                <&bdk_wallet::bitcoin::script::PushBytes>::try_from(native.as_bytes()).unwrap(),
            )
            .into_script();
        let mut witness = Witness::new();
        witness.push(signature());
        witness.push(compressed.to_bytes());
        let spend = tx(vec![spending(witness.clone(), script_sig)], vec![]);
        assert!(!holding(&[&native]).touched_by(&spend));
        // The same with a witness script: a `wsh` wallet is not named by
        // a spend of its `sh(wsh)` twin.
        let witness_script = two_of_two();
        let native = ScriptBuf::new_p2wsh(&witness_script.wscript_hash());
        let script_sig = Builder::new()
            .push_slice(
                <&bdk_wallet::bitcoin::script::PushBytes>::try_from(native.as_bytes()).unwrap(),
            )
            .into_script();
        let mut witness = Witness::new();
        witness.push(signature());
        witness.push(witness_script.as_bytes());
        let spend = tx(vec![spending(witness, script_sig)], vec![]);
        assert!(!holding(&[&native]).touched_by(&spend));
        assert!(holding(&[&ScriptBuf::new_p2sh(&native.script_hash())]).touched_by(&spend));
    }

    /// A taproot script-path spend: the output key is computed from the
    /// internal key, the leaf and the branch of the control block.
    #[test]
    fn a_taproot_script_path_input_is_known_by_its_output_key() {
        let secp = Secp256k1::verification_only();
        let internal = XOnlyPublicKey::from(key(KEY_A).inner);
        let leaf = Builder::new()
            .push_x_only_key(&XOnlyPublicKey::from(key(KEY_B).inner))
            .push_opcode(OP_CHECKSIG)
            .into_script();
        let sibling = Builder::new()
            .push_x_only_key(&internal)
            .push_opcode(OP_CHECKSIG)
            .into_script();
        let info = TaprootBuilder::new()
            .add_leaf(1, leaf.clone())
            .unwrap()
            .add_leaf(1, sibling)
            .unwrap()
            .finalize(&secp, internal)
            .unwrap();
        let ours = ScriptBuf::new_p2tr_tweaked(info.output_key());
        let control = info
            .control_block(&(leaf.clone(), LeafVersion::TapScript))
            .unwrap();
        let mut witness = Witness::new();
        witness.push([0x01; 64]);
        witness.push(leaf.as_bytes());
        witness.push(control.serialize());
        let spend = tx(vec![spending(witness, ScriptBuf::new())], vec![]);
        assert!(holding(&[&ours]).touched_by(&spend));
        // A key-path spend names no script: nothing is said of it.
        let mut key_path = Witness::new();
        key_path.push([0x01; 64]);
        let spend = tx(vec![spending(key_path, ScriptBuf::new())], vec![]);
        assert!(!holding(&[&ours]).touched_by(&spend));
    }

    #[test]
    fn an_output_a_coin_or_the_history_is_enough() {
        let ours = ScriptBuf::new_p2wsh(&two_of_two().wscript_hash());
        let elsewhere = ScriptBuf::new_p2wsh(&ScriptBuf::new().wscript_hash());
        let paying = tx(
            vec![spending(Witness::new(), ScriptBuf::new())],
            vec![elsewhere.clone(), ours.clone()],
        );
        assert!(holding(&[&ours]).touched_by(&paying));

        let unrelated = tx(
            vec![spending(Witness::new(), ScriptBuf::new())],
            vec![elsewhere],
        );
        assert!(!holding(&[&ours]).touched_by(&unrelated));
        let coin = unrelated.input[0].previous_output;
        let spends_ours = Traces {
            coins: HashSet::from([coin]),
            ..Traces::default()
        };
        assert!(spends_ours.touched_by(&unrelated));
        let in_history = Traces {
            txids: HashSet::from([unrelated.compute_txid()]),
            ..Traces::default()
        };
        assert!(in_history.touched_by(&unrelated));
    }
}
