//! The test a settings screen runs on a backend it just saved: can the
//! server be reached the way a sync will reach it, does it follow the
//! network of the wallets, and how high is its chain. A failure is named
//! for what the person has to change, not for the layer it happened in:
//! a name that does not resolve, a port nothing listens on, TLS turned
//! on for a server without it, a certificate not accepted, Tor not to be
//! had, another network.
//!
//! The kind is read from the error itself, never from its words: an I/O
//! error's kind, the reply code of the Tor proxy, the TLS library's own
//! error, an HTTP status. TLS turned the wrong way on an Electrum port
//! has no error of its own (a server without TLS waits for a line the
//! handshake never sends, one with TLS hangs up on a plain line), so it
//! is told by trying the other way once on the same port, and only
//! after the first one failed.

use std::time::{Duration, Instant};

use bdk_wallet::bitcoin::BlockHash;
use bdk_wallet::bitcoin::block::Header;
use bdk_wallet::bitcoin::consensus::encode::deserialize_hex;
use serde::{Deserialize, Serialize};

use super::Endpoint;
use crate::network::Network;

/// What testing a backend found, for the screen that saved it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "outcome", rename_all = "snake_case")]
pub enum BackendCheck {
    /// The server answered as a backend of this network.
    Reached {
        /// `host` or `host:port` of the server that answered: the one a
        /// rotation of public servers settled on.
        host: String,
        /// The height of its chain's tip, checked the way a sync checks
        /// it.
        height: u32,
        /// What it says it runs, an Electrum server only: `Fulcrum
        /// 2.1.3`, `electrs/0.10.9`.
        software: Option<String>,
        /// Reached through Tor.
        tor: bool,
        /// How long the test took, connection included.
        millis: u64,
    },
    /// It did not: what stands in the way, the core's words on it, and
    /// the network the server follows when it is another.
    Failed {
        host: String,
        problem: BackendProblem,
        detail: String,
        /// Set with [`BackendProblem::AnotherNetwork`] when the server's
        /// genesis block is that of a network Gerfaut knows.
        server_network: Option<Network>,
        tor: bool,
    },
    /// Stopped before it ended, by the person or by a newer test of the
    /// same network: the backend is saved, and untested.
    Cancelled,
}

/// What stands between a saved backend and a working one.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BackendProblem {
    /// The name of the host does not resolve.
    HostNotFound,
    /// The host refused the connection: nothing listens on that port,
    /// or the server is not running.
    Refused,
    /// No answer in time: the host is down, out of this device's reach,
    /// or behind a firewall; an onion service that is offline.
    NoAnswer,
    /// The address is an onion, and Tor cannot be had.
    Tor,
    /// TLS is on, and the server answers on that port without it.
    NotTls,
    /// TLS is off, and the server on that port expects it.
    NeedsTls,
    /// The server's certificate is not accepted: no public authority
    /// vouches for it and it was not accepted here, or it changed since.
    Certificate,
    /// Something answers, but not an Electrum server.
    NotElectrum,
    /// Something answers, but not an Esplora API.
    NotEsplora,
    /// The server follows another network than the backend's.
    AnotherNetwork,
    /// The server's chain does not hold: a height no chain has reached,
    /// a tip no one mined, latest blocks that do not chain.
    BadChain,
    /// The server answered with a refusal of its own.
    ServerRefused,
    /// Anything else, in the core's words.
    Failed,
}

/// One server's failure, before the host is put on it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Trouble {
    pub problem: BackendProblem,
    pub detail: String,
    pub server_network: Option<Network>,
}

impl Trouble {
    pub(crate) fn new(problem: BackendProblem, detail: impl Into<String>) -> Self {
        Trouble {
            problem,
            detail: detail.into(),
            server_network: None,
        }
    }

    /// A server whose genesis block is `genesis`, not `network`'s.
    pub(crate) fn another_network(genesis: BlockHash) -> Self {
        let theirs = Network::ALL
            .into_iter()
            .find(|candidate| super::is_genesis_of(*candidate, genesis));
        Trouble {
            problem: BackendProblem::AnotherNetwork,
            detail: super::ANOTHER_NETWORK.to_owned(),
            server_network: theirs,
        }
    }
}

/// What one server answered when it answered.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Answer {
    pub height: u32,
    pub software: Option<String>,
}

/// The longest a test of one server may take, every step together, and
/// through Tor, where a circuit to an onion service alone can take most
/// of a minute.
const DEADLINE: Duration = Duration::from_secs(45);
const TOR_DEADLINE: Duration = Duration::from_secs(150);

/// Tests `endpoints` in the order a sync tries them, and stops at the
/// first that answers: what a rotation of public servers does too. When
/// none does, the last failure is told. `proxy` is the Tor route the
/// caller resolved, needed for an onion and handed to no other host.
pub(crate) async fn check(
    endpoints: &[Endpoint],
    network: Network,
    proxy: Option<&str>,
) -> BackendCheck {
    let mut last = None;
    for endpoint in endpoints {
        let host = endpoint.label_with_port();
        let tor = endpoint.is_onion();
        let started = Instant::now();
        let deadline = if tor { TOR_DEADLINE } else { DEADLINE };
        let tested = tokio::time::timeout(deadline, one(endpoint, network, proxy))
            .await
            .unwrap_or_else(|_| {
                Err(Trouble::new(
                    BackendProblem::NoAnswer,
                    format!("no answer within {} s", deadline.as_secs()),
                ))
            });
        match tested {
            Ok(answer) => {
                return BackendCheck::Reached {
                    host,
                    height: answer.height,
                    software: answer.software,
                    tor,
                    millis: u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX),
                };
            }
            Err(trouble) => {
                last = Some(BackendCheck::Failed {
                    host,
                    problem: trouble.problem,
                    detail: trouble.detail,
                    server_network: trouble.server_network,
                    tor,
                });
            }
        }
    }
    last.unwrap_or_else(|| BackendCheck::Failed {
        host: String::new(),
        problem: BackendProblem::Failed,
        detail: "no server to test".to_owned(),
        server_network: None,
        tor: false,
    })
}

async fn one(
    endpoint: &Endpoint,
    network: Network,
    proxy: Option<&str>,
) -> Result<Answer, Trouble> {
    match endpoint {
        Endpoint::Electrum(target) => super::electrum::check::run(target, network, proxy).await,
        Endpoint::Esplora(url) => super::esplora::check::run(url, network, proxy).await,
    }
}

/// The genesis block a server sent, as a header in hex, read and held
/// against `network`.
pub(crate) fn genesis_of(network: Network, header_hex: &str) -> Result<(), Trouble> {
    let header: Header = deserialize_hex(header_hex).map_err(|_| unexpected())?;
    let hash = header.block_hash();
    if super::is_genesis_of(network, hash) {
        Ok(())
    } else {
        Err(Trouble::another_network(hash))
    }
}

/// An answer that is not the protocol, once the connection is up.
pub(crate) fn unexpected() -> Trouble {
    Trouble::new(BackendProblem::Failed, "unexpected response")
}

/// What an I/O error on the way to a server, before any answer, says of
/// it by its kind: refused, or not answering.
pub(crate) fn of_connect(error: &std::io::Error) -> Trouble {
    use super::fault::IoOutage;
    let detail = super::Fault::of_io(error, None).to_string();
    match error.kind() {
        std::io::ErrorKind::ConnectionRefused => Trouble::new(BackendProblem::Refused, detail),
        kind if IoOutage::of(kind).is_some() => Trouble::new(BackendProblem::NoAnswer, detail),
        _ => Trouble::new(BackendProblem::NoAnswer, error.to_string()),
    }
}

#[cfg(test)]
mod tests;
