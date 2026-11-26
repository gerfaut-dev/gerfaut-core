//! The test of an Electrum server: see [`crate::chain::check`]. The
//! connection is opened one step at a time, the way [`super::rpc`] opens
//! it, so each step's failure is told for what it is: the name, the
//! socket, the way through Tor, TLS, the protocol.

use std::time::Duration;

use serde::Deserialize;
use serde_json::{Value, json};
use tokio_rustls::TlsConnector;

use super::rpc::{CallError, Connection};
use super::{TIMEOUT, TOR_TIMEOUT, Target, is_onion, parse};
use crate::chain::check::{Answer, BackendProblem, Trouble, genesis_of, of_connect, unexpected};
use crate::chain::net::{BoxStream, SOCKS_REFUSED, SocksFailure, through_socks};
use crate::chain::tls::{self, ConnectError};
use crate::network::Network;

/// How long the other way of TLS gets, once the first failed: a server
/// that speaks it answers within a round trip.
const OTHER_WAY: Duration = Duration::from_secs(8);
const TOR_OTHER_WAY: Duration = Duration::from_secs(30);

/// Connects to `target` the way a sync does, asks for its genesis block
/// and its tip, and checks both.
pub(crate) async fn run(
    target: &Target,
    network: Network,
    proxy: Option<&str>,
) -> Result<Answer, Trouble> {
    let (tls_on, host, port) =
        parse(&target.url).map_err(|e| Trouble::new(BackendProblem::Failed, e))?;
    let onion = is_onion(target, &host);
    let proxy = if onion {
        // The manager resolves a route before any onion is tested.
        Some(proxy.ok_or_else(|| {
            Trouble::new(
                BackendProblem::Tor,
                crate::chain::tor::no_route(&target.url),
            )
        })?)
    } else {
        None
    };
    let way = Way {
        host: &host,
        port,
        onion,
        proxy,
        timeout: if onion { TOR_TIMEOUT } else { TIMEOUT },
    };
    let mut connection = match way.open(tls_on, target.pin.as_deref()).await {
        Ok(connection) => connection,
        Err(Opened::Trouble(trouble)) => return Err(trouble),
        // TLS on, and no handshake: a server without TLS on that port
        // answers a plain request.
        Err(Opened::NoHandshake(detail)) => {
            return Err(if way.speaks_plain().await {
                Trouble::new(BackendProblem::NotTls, detail)
            } else {
                Trouble::new(BackendProblem::NotElectrum, detail)
            });
        }
    };
    let version = match connection.version().await {
        Ok(version) => version,
        Err(CallError::Refused { words, .. } | CallError::Busy(words)) => {
            return Err(Trouble::new(BackendProblem::ServerRefused, words));
        }
        // Connected, and no Electrum answer: a TLS server hangs up on
        // a plain line, anything else is not Electrum.
        Err(error) => {
            let detail = error.to_string();
            return Err(if !tls_on && way.speaks_tls().await {
                Trouble::new(BackendProblem::NeedsTls, detail)
            } else {
                Trouble::new(BackendProblem::NotElectrum, detail)
            });
        }
    };
    let software = version
        .get(0)
        .and_then(Value::as_str)
        .map(crate::chain::server_words)
        .filter(|words| !words.is_empty());

    let genesis: String = connection
        .call("blockchain.block.header", json!([0]))
        .await
        .map_err(asked)?;
    genesis_of(network, &genesis)?;

    #[derive(Deserialize)]
    struct Tip {
        height: u32,
        hex: String,
    }
    let tip: Tip = connection
        .call("blockchain.headers.subscribe", json!([]))
        .await
        .map_err(asked)?;
    let header = deserialize_header(&tip.hex)?;
    let height = crate::chain::checked_tip(network, tip.height, &header)
        .map_err(|fault| Trouble::new(BackendProblem::BadChain, fault.to_string()))?;
    Ok(Answer { height, software })
}

fn deserialize_header(hex: &str) -> Result<bdk_wallet::bitcoin::block::Header, Trouble> {
    bdk_wallet::bitcoin::consensus::encode::deserialize_hex(hex).map_err(|_| unexpected())
}

/// A call after the protocol was agreed on, failed.
fn asked(error: CallError) -> Trouble {
    match error {
        CallError::Refused { words, .. } | CallError::Busy(words) => {
            Trouble::new(BackendProblem::ServerRefused, words)
        }
        CallError::TooLong => Trouble::new(BackendProblem::Failed, error.to_string()),
        CallError::Failed(fault) => Trouble::new(BackendProblem::Failed, fault.to_string()),
    }
}

/// Why a connection did not open.
enum Opened {
    /// Told for what it is.
    Trouble(Trouble),
    /// The TLS handshake failed for no reason of the certificate's: the
    /// server may not speak TLS on that port.
    NoHandshake(String),
}

/// The way to one server, and what each step gets.
struct Way<'a> {
    host: &'a str,
    port: u16,
    onion: bool,
    proxy: Option<&'a str>,
    timeout: Duration,
}

impl Way<'_> {
    /// A socket to the server: through Tor for an onion, straight
    /// otherwise, each failure of its kind.
    async fn socket(&self, timeout: Duration) -> Result<tokio::net::TcpStream, Trouble> {
        let opening = async {
            match self.proxy {
                Some(proxy) => through_socks(proxy, self.host, self.port)
                    .await
                    .map_err(of_socks),
                None => {
                    let addresses = crate::chain::dial::resolve_async(self.host, self.port)
                        .await
                        .map_err(|_| not_found(self.host))?;
                    if addresses.is_empty() {
                        return Err(not_found(self.host));
                    }
                    crate::chain::dial::connect_addresses_async(addresses, timeout)
                        .await
                        .map_err(|error| of_connect(&error))
                }
            }
        };
        let socket = tokio::time::timeout(timeout, opening)
            .await
            .unwrap_or_else(|_| {
                Err(Trouble::new(
                    BackendProblem::NoAnswer,
                    format!("could not connect within {} s", timeout.as_secs()),
                ))
            })?;
        let _ = socket.set_nodelay(true);
        Ok(socket)
    }

    /// The connection a sync would open, TLS as asked, before any call.
    async fn open(&self, tls_on: bool, pin: Option<&str>) -> Result<Connection, Opened> {
        let socket = self.socket(self.timeout).await.map_err(Opened::Trouble)?;
        let stream: BoxStream = if !tls_on {
            Box::new(socket)
        } else {
            let failed = |e: ConnectError| {
                Opened::Trouble(Trouble::new(BackendProblem::Failed, e.to_string()))
            };
            let name = tls::server_name(self.host).map_err(failed)?;
            let handshake = if self.onion {
                // The onion address is the server's identity: its
                // certificate vouches for nothing ([`tls::onion_config`]).
                let config = tls::onion_config().map_err(failed)?;
                tokio::time::timeout(
                    self.timeout,
                    TlsConnector::from(config).connect(name, socket),
                )
                .await
                .map_err(|_| Opened::NoHandshake(self.handshake_timeout()))?
                .map_err(|e| Opened::NoHandshake(tls::handshake_failed(&e)))
            } else {
                let checked = tls::Handshake::new(pin).map_err(failed)?;
                match tokio::time::timeout(
                    self.timeout,
                    TlsConnector::from(checked.config.clone()).connect(name, socket),
                )
                .await
                {
                    Err(_) => Err(Opened::NoHandshake(self.handshake_timeout())),
                    Ok(Ok(stream)) => Ok(stream),
                    Ok(Err(error)) => Err(match checked.refusal(&error) {
                        refusal @ ConnectError::Certificate(_) => Opened::Trouble(Trouble::new(
                            BackendProblem::Certificate,
                            refusal.to_string(),
                        )),
                        other => Opened::NoHandshake(other.to_string()),
                    }),
                }
            }?;
            Box::new(handshake)
        };
        Ok(Connection::over(stream, self.timeout))
    }

    fn handshake_timeout(&self) -> String {
        format!("no TLS handshake within {} s", self.timeout.as_secs())
    }

    fn other_way(&self) -> Duration {
        if self.onion { TOR_OTHER_WAY } else { OTHER_WAY }
    }

    /// Whether the server answers `server.version` without TLS.
    async fn speaks_plain(&self) -> bool {
        let budget = self.other_way();
        let Ok(socket) = self.socket(budget).await else {
            return false;
        };
        let mut connection = Connection::over(Box::new(socket), budget);
        matches!(
            tokio::time::timeout(budget, connection.version()).await,
            Ok(Ok(_) | Err(CallError::Refused { .. } | CallError::Busy(_)))
        )
    }

    /// Whether the server takes a TLS handshake: one that completes, or
    /// that only its certificate stops, both say it speaks TLS.
    async fn speaks_tls(&self) -> bool {
        let budget = self.other_way();
        let Ok(socket) = self.socket(budget).await else {
            return false;
        };
        let Ok(name) = tls::server_name(self.host) else {
            return false;
        };
        let Ok(checked) = tls::Handshake::new(None) else {
            return false;
        };
        match tokio::time::timeout(
            budget,
            TlsConnector::from(checked.config.clone()).connect(name, socket),
        )
        .await
        {
            Ok(Ok(_)) => true,
            Ok(Err(error)) => matches!(checked.refusal(&error), ConnectError::Certificate(_)),
            Err(_) => false,
        }
    }
}

fn not_found(host: &str) -> Trouble {
    Trouble::new(
        BackendProblem::HostNotFound,
        format!("{host} does not resolve"),
    )
}

/// A connection through Tor that did not open: the proxy's own failure
/// is Tor's, the host refusing is a port nothing listens on, anything
/// else an onion service that does not answer.
fn of_socks(failure: SocksFailure) -> Trouble {
    let problem = match failure {
        SocksFailure::Proxy(_) => BackendProblem::Tor,
        SocksFailure::Reply(SOCKS_REFUSED) => BackendProblem::Refused,
        SocksFailure::Reply(_) => BackendProblem::NoAnswer,
    };
    Trouble::new(problem, failure.to_string())
}
