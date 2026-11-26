//! Tor for `.onion` backends: the Tor already running on the device when
//! there is one, the client built into this library when there is not.
//!
//! Both chain backends only ever need a SOCKS5 proxy that resolves names
//! itself; whether it is a system daemon or the embedded client makes no
//! difference to them. So the choice is made here, once per operation
//! that touches an onion host, and the proxy address is handed down.
//! Clearnet-only operations never come through here at all.
//!
//! The embedded client is arti, the Tor Project's Rust implementation,
//! started lazily and kept for the life of the process behind a loopback
//! SOCKS5 listener ([`socks`]) on a port the system picks, guarded by
//! credentials drawn for the process: loopback is shared by every app on
//! Android, and this proxy carries this wallet's traffic only.

// Built and tested in every configuration, like `socks`.
#[cfg_attr(
    not(feature = "embedded-tor"),
    allow(
        dead_code,
        reason = "only the embedded client uses it, yet it is built and tested in every configuration"
    )
)]
mod attempts;
#[cfg(feature = "embedded-tor")]
mod embedded;
mod owner;
// Only the embedded client runs the server; it is built and tested in
// every configuration so the feature never drifts from what CI sees.
#[cfg_attr(
    not(feature = "embedded-tor"),
    allow(
        dead_code,
        reason = "only the embedded client runs the server, yet it is built and tested in every configuration"
    )
)]
pub(crate) mod socks;

use std::collections::BTreeMap;
use std::net::SocketAddr;
use std::path::Path;
use std::sync::Mutex;
use std::time::Duration;

use serde::{Deserialize, Serialize};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

use crate::error::{CoreError, CoreResult};

pub use owner::LoopbackOwner;

/// Where a Tor daemon, Orbot and the Tor Browser expert bundle listen
/// by default.
pub const DEFAULT_SYSTEM_SOCKS: &str = "127.0.0.1:9050";

/// Whether this build carries the embedded client.
pub const EMBEDDED_AVAILABLE: bool = cfg!(feature = "embedded-tor");

/// Whether a proxy answering on loopback may be taken for the system's
/// Tor without being asked for. On a desktop, it may when this account
/// or the system holds it ([`LoopbackOwner`]): a proxy of either knows
/// nothing the app does not. Another account of the same computer can
/// open 127.0.0.1:9050 while no Tor runs, so a proxy held by anyone else,
/// or by someone the core cannot name, is passed over. On Android every
/// app holding the INTERNET permission can bind that port and answer the
/// greeting, and on iOS the core cannot name who holds a socket at all,
/// so nothing found there is trusted on its own: `Auto` goes straight to
/// the built-in client, and the system proxy carries traffic only when
/// the user chose it by name in the settings.
pub const TRUST_LOOPBACK_SOCKS: bool = !cfg!(any(target_os = "android", target_os = "ios"));

/// How long the system proxy gets to answer the greeting. A proxy on
/// loopback answers within a millisecond; the budget only bounds what
/// a dead port costs, once per onion operation.
const PROBE_BUDGET: Duration = Duration::from_millis(300);

/// How `.onion` hosts are reached.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TorMode {
    /// The system proxy when it answers, the embedded client otherwise.
    /// Users who run their own Tor keep their own guards and circuits;
    /// everyone else gets Tor without installing anything. A proxy on
    /// loopback is taken only when this account or the system holds it.
    /// Where loopback is shared ([`TRUST_LOOPBACK_SOCKS`] is false) the
    /// system proxy is not even looked for, and this is the embedded
    /// client.
    #[default]
    Auto,
    /// The system proxy only; the embedded client is never started.
    System,
    /// The embedded client only; the system proxy is never looked for.
    Embedded,
}

/// The Tor part of the settings.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct TorSettings {
    #[serde(default)]
    pub mode: TorMode,
    /// The system proxy, `host:port`. `None` is [`DEFAULT_SYSTEM_SOCKS`].
    #[serde(default)]
    pub socks_proxy: Option<String>,
}

impl TorSettings {
    /// The system proxy address in effect.
    pub fn system_socks(&self) -> &str {
        self.socks_proxy.as_deref().unwrap_or(DEFAULT_SYSTEM_SOCKS)
    }
}

/// Which Tor a route goes through.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TorVia {
    System,
    Embedded,
}

/// A SOCKS5 proxy ready to carry onion traffic.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TorRoute {
    /// `host:port` of the proxy: what a settings screen may show.
    pub socks: String,
    pub via: TorVia,
    /// What the embedded proxy asks a client for. Kept out of the
    /// serialized form, so the apps never see or show them; the chain
    /// layer gets them through [`TorRoute::proxy`].
    #[serde(skip)]
    credentials: Option<socks::Credentials>,
}

impl TorRoute {
    /// A route that asks no credentials, built by a test.
    #[cfg(test)]
    pub(crate) fn without_credentials(socks: &str, via: TorVia) -> Self {
        TorRoute {
            socks: socks.to_owned(),
            via,
            credentials: None,
        }
    }

    /// The proxy as the chain layer takes it: `user:password@host:port`
    /// when the proxy asks for credentials, `host:port` otherwise. Never
    /// for display; [`Self::socks`] is.
    pub(crate) fn proxy(&self) -> String {
        match &self.credentials {
            Some(credentials) => format!(
                "{}:{}@{}",
                credentials.username(),
                credentials.password(),
                self.socks
            ),
            None => self.socks.clone(),
        }
    }
}

/// Splits a proxy string the chain layer was handed into its
/// credentials, if any, and its `host:port`. The inverse of
/// [`TorRoute::proxy`], for the client that takes them apart rather than
/// as a URL.
pub(crate) fn split_proxy(proxy: &str) -> (Option<(&str, &str)>, &str) {
    match proxy.rsplit_once('@') {
        Some((userinfo, address)) => match userinfo.split_once(':') {
            Some((username, password)) => (Some((username, password)), address),
            None => (Some((userinfo, "")), address),
        },
        None => (None, proxy),
    }
}

/// What a settings screen shows about Tor.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TorStatus {
    pub mode: TorMode,
    /// The system proxy address in effect.
    pub socks_proxy: String,
    /// The Tor the last onion operation went through, if any yet.
    pub via: Option<TorVia>,
    /// The proxy address that operation used.
    pub socks: Option<String>,
    /// The embedded client has been started in this process.
    pub running: bool,
    /// The embedded client has reached the network.
    pub bootstrapped: bool,
    pub bootstrap_percent: u8,
    /// Why the embedded client's last start failed, until the next one.
    pub error: Option<String>,
    pub embedded_available: bool,
    /// Whether `Auto` may use a proxy found on loopback
    /// ([`TRUST_LOOPBACK_SOCKS`]). False on Android and iOS, where the
    /// System option is worth a word of caution: any app can answer
    /// there, or nobody can tell who does.
    pub system_socks_trusted: bool,
    /// Who holds the proxy that answered at [`Self::socks_proxy`] the
    /// last time it was probed, when it is on loopback. `None` until a
    /// proxy there answers, after one stops answering, for an address
    /// away from loopback, and on Android and iOS. In `Auto`, `other_account` and
    /// `unknown` mean that proxy was passed over for the built-in client;
    /// in `System`, `other_account` means another account carries the
    /// traffic.
    pub system_socks_owner: Option<LoopbackOwner>,
}

/// The last route taken, for the settings screen to name. Process-wide,
/// like the embedded client.
static LAST_ROUTE: Mutex<Option<TorRoute>> = Mutex::new(None);

/// Who held the proxy at each system address the last time one answered
/// there on loopback: a settings screen names the one of the address in
/// effect.
static SYSTEM_SOCKS_OWNERS: Mutex<BTreeMap<String, LoopbackOwner>> = Mutex::new(BTreeMap::new());

/// Keeps what a resolution saw of the system proxy at `address`.
fn note_system_owner(address: &str, owner: Option<LoopbackOwner>) {
    if let Ok(mut seen) = SYSTEM_SOCKS_OWNERS.lock() {
        match owner {
            Some(owner) => seen.insert(address.to_owned(), owner),
            None => seen.remove(address),
        };
    }
}

/// Where the embedded client stands in this process. One value, so
/// the settings screen never reads a percentage left by a start that
/// failed, or by one that finished.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
enum EmbeddedTor {
    /// Never started in this process.
    #[default]
    Idle,
    /// Bootstrapping; `percent` is arti's estimate, below 100.
    Starting { percent: u8 },
    /// Reached the network, its proxy listening.
    Ready,
    /// The last start gave up, and why, until the next one.
    Failed { error: String },
}

static EMBEDDED: Mutex<EmbeddedTor> = Mutex::new(EmbeddedTor::Idle);

#[cfg_attr(
    not(feature = "embedded-tor"),
    allow(dead_code, reason = "only the embedded client moves it")
)]
impl EmbeddedTor {
    /// A start begins: whatever an earlier one left is dropped.
    fn begin(&mut self) {
        *self = EmbeddedTor::Starting { percent: 0 };
    }

    /// arti's estimate moved. Read only while starting, where the shown
    /// percentage never goes back and stays below 100 until the start
    /// returns; one that arrives once the start settled is dropped.
    fn advance(&mut self, estimate: u8) {
        if let EmbeddedTor::Starting { percent } = self {
            *percent = (*percent).max(estimate.min(99));
        }
    }

    /// The bootstrap returned and the proxy listens.
    fn finish(&mut self) {
        *self = EmbeddedTor::Ready;
    }

    /// The start failed, and says why until the next one.
    fn fail(&mut self, error: String) {
        *self = EmbeddedTor::Failed { error };
    }
}

fn embedded_tor() -> EmbeddedTor {
    EMBEDDED
        .lock()
        .map(|embedded| embedded.clone())
        .unwrap_or_default()
}

#[cfg(feature = "embedded-tor")]
fn update(change: impl FnOnce(&mut EmbeddedTor)) {
    if let Ok(mut embedded) = EMBEDDED.lock() {
        change(&mut embedded);
    }
}

/// The proxy to reach onion hosts through, per the settings.
///
/// `System` probes the system proxy and refuses when nothing answers.
/// `Auto` probes it too where loopback is trusted
/// ([`TRUST_LOOPBACK_SOCKS`]), takes it when it is away from loopback or
/// held by this account or the system, and falls back to the embedded
/// client otherwise; where loopback is not trusted, `Auto` is the
/// embedded client. `Embedded` never
/// probes and starts the client if it is not running: up to about 90
/// seconds on a first run, a few on later ones. Call it only when an
/// onion host is about to be reached.
pub async fn resolve(settings: &TorSettings, data_dir: &Path) -> CoreResult<TorRoute> {
    #[cfg(feature = "embedded-tor")]
    let embedded = Some(async || embedded::socks_access(data_dir).await);
    #[cfg(not(feature = "embedded-tor"))]
    let embedded = {
        let _ = data_dir;
        None::<NoEmbedded>
    };
    let route = resolve_with(
        settings,
        TRUST_LOOPBACK_SOCKS,
        probe,
        async |candidates: &[SocketAddr]| owner::of(candidates.to_vec()).await,
        |seen| note_system_owner(settings.system_socks(), seen),
        embedded,
    )
    .await?;
    if let Ok(mut last) = LAST_ROUTE.lock() {
        *last = Some(route.clone());
    }
    Ok(route)
}

/// [`resolve`] without starting anything: the system proxy where the
/// settings let it be probed and it answers, the embedded client only
/// once something else brought it up. For a request the app makes on
/// its own, which waits for a sync or the live watch to start Tor
/// rather than start it for itself: a bootstrap takes up to a minute
/// and a half, and the client then runs for the life of the process.
pub async fn resolve_running(settings: &TorSettings) -> CoreResult<TorRoute> {
    #[cfg(feature = "embedded-tor")]
    let embedded = {
        let running = embedded::running_access();
        Some(async move || already_running(running))
    };
    #[cfg(not(feature = "embedded-tor"))]
    let embedded = None::<NoEmbedded>;
    let route = resolve_with(
        settings,
        TRUST_LOOPBACK_SOCKS,
        probe,
        async |candidates: &[SocketAddr]| owner::of(candidates.to_vec()).await,
        |seen| note_system_owner(settings.system_socks(), seen),
        embedded,
    )
    .await?;
    if let Ok(mut last) = LAST_ROUTE.lock() {
        *last = Some(route.clone());
    }
    Ok(route)
}

/// What a starter that starts nothing hands back: the proxy of the
/// embedded client when it runs, a Tor error when it does not.
#[cfg_attr(
    not(feature = "embedded-tor"),
    allow(
        dead_code,
        reason = "only the build with the embedded client calls it outside tests"
    )
)]
fn already_running(access: Option<socks::Access>) -> CoreResult<socks::Access> {
    access.ok_or_else(|| CoreError::Tor("the built-in Tor is not running yet".to_owned()))
}

/// What a resolution found at the system address.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SystemProxy {
    /// Nothing answers there.
    Silent,
    /// A proxy answers away from loopback: an address the person typed,
    /// believed as typed.
    Elsewhere,
    /// A proxy answers on loopback, held by this owner.
    Loopback(LoopbackOwner),
}

/// The type of a starter this build does not have.
#[cfg(not(feature = "embedded-tor"))]
type NoEmbedded = fn() -> std::future::Ready<CoreResult<socks::Access>>;

/// The policy on its own: `trust_loopback_socks` says whether `Auto` may
/// take a proxy found on loopback for Tor, `probe` says whether a proxy
/// answers at an address, `owner_of` who holds the loopback addresses a
/// connection to it may land on ([`owner::loopback_addresses`]), `note`
/// is told what was seen of the system proxy each time it is probed
/// where loopback is trusted (who holds it when it answers on loopback,
/// `None` otherwise), and `embedded` starts the built-in client and
/// returns how to reach its proxy, or is `None` in a build without one.
async fn resolve_with(
    settings: &TorSettings,
    trust_loopback_socks: bool,
    probe: impl AsyncFn(&str) -> bool,
    owner_of: impl AsyncFn(&[SocketAddr]) -> LoopbackOwner,
    mut note: impl FnMut(Option<LoopbackOwner>),
    embedded: Option<impl AsyncFnOnce() -> CoreResult<socks::Access>>,
) -> CoreResult<TorRoute> {
    let system = settings.system_socks();
    let via_system = || TorRoute {
        socks: system.to_owned(),
        via: TorVia::System,
        credentials: None,
    };
    let via_embedded = |access: socks::Access| TorRoute {
        socks: access.address,
        via: TorVia::Embedded,
        credentials: Some(access.credentials),
    };
    // What answers at the system address, and who holds it when that is
    // on loopback. Asked only where loopback is trusted: on Android and
    // iOS nobody is, and nothing there is looked into.
    let mut look = async || {
        let found = if !probe(system).await {
            SystemProxy::Silent
        } else {
            match owner::loopback_addresses(system).await {
                None => SystemProxy::Elsewhere,
                Some(candidates) => SystemProxy::Loopback(owner_of(&candidates).await),
            }
        };
        note(match found {
            SystemProxy::Loopback(owner) => Some(owner),
            SystemProxy::Silent | SystemProxy::Elsewhere => None,
        });
        found
    };
    match settings.mode {
        TorMode::System => {
            // Chosen by name, the proxy is used whoever holds it: the
            // person vouches for it. Who that is is still noted.
            let answers = if trust_loopback_socks {
                !matches!(look().await, SystemProxy::Silent)
            } else {
                probe(system).await
            };
            if answers {
                Ok(via_system())
            } else {
                Err(CoreError::Tor(format!(
                    "no Tor proxy answers at {system}; start Tor, or let Gerfaut use its \
                     built-in one"
                )))
            }
        }
        TorMode::Auto => {
            // Where loopback is shared, a proxy found there is anyone's:
            // it is not probed, let alone used, unless chosen by name.
            let found = if trust_loopback_socks {
                look().await
            } else {
                SystemProxy::Silent
            };
            match found {
                SystemProxy::Elsewhere => return Ok(via_system()),
                SystemProxy::Loopback(owner) if owner.is_trusted() => return Ok(via_system()),
                SystemProxy::Loopback(_) | SystemProxy::Silent => {}
            }
            match (embedded, found) {
                (Some(start), _) => start().await.map(via_embedded),
                (None, SystemProxy::Loopback(LoopbackOwner::OtherAccount)) => {
                    Err(CoreError::Tor(format!(
                        "another account on this computer runs the proxy at {system}, and this \
                         build has no built-in Tor; if that proxy is yours, choose System Tor"
                    )))
                }
                (None, SystemProxy::Loopback(_)) => Err(CoreError::Tor(format!(
                    "Gerfaut can't tell which account runs the proxy at {system}, and this \
                     build has no built-in Tor; if that proxy is yours, choose System Tor"
                ))),
                (None, _) if trust_loopback_socks => Err(CoreError::Tor(format!(
                    "Tor is not running on this device ({system} does not answer) and this \
                     build has no built-in Tor"
                ))),
                (None, _) => Err(CoreError::Tor(format!(
                    "this build has no built-in Tor; to use a Tor app running on this device, \
                     choose it in the settings ({system})"
                ))),
            }
        }
        TorMode::Embedded => match embedded {
            Some(start) => start().await.map(via_embedded),
            None => Err(CoreError::Tor(
                "this build has no built-in Tor; use the Tor running on this device instead"
                    .to_owned(),
            )),
        },
    }
}

/// Whether a SOCKS5 proxy answers at `address`: connect, offer "no
/// authentication", expect it accepted. Anything else, silence past the
/// budget included, is a no.
pub(crate) async fn probe(address: &str) -> bool {
    let greeting = async {
        let mut stream = TcpStream::connect(address).await.ok()?;
        stream
            .write_all(&[socks::VERSION, 1, socks::NO_AUTH])
            .await
            .ok()?;
        let mut answer = [0u8; 2];
        stream.read_exact(&mut answer).await.ok()?;
        Some(answer == [socks::VERSION, socks::NO_AUTH])
    };
    matches!(
        tokio::time::timeout(PROBE_BUDGET, greeting).await,
        Ok(Some(true))
    )
}

/// Where Tor stands, for a settings screen. Reads only: nothing is
/// probed or started.
pub async fn status(settings: &TorSettings) -> TorStatus {
    status_with(settings, embedded_tor())
}

fn status_with(settings: &TorSettings, embedded: EmbeddedTor) -> TorStatus {
    let last = LAST_ROUTE.lock().ok().and_then(|route| route.clone());
    let (running, bootstrapped, bootstrap_percent, error) = match embedded {
        EmbeddedTor::Idle => (false, false, 0, None),
        EmbeddedTor::Starting { percent } => (true, false, percent, None),
        EmbeddedTor::Ready => (true, true, 100, None),
        EmbeddedTor::Failed { error } => (false, false, 0, Some(error)),
    };
    TorStatus {
        mode: settings.mode,
        socks_proxy: settings.system_socks().to_owned(),
        via: last.as_ref().map(|route| route.via),
        socks: last.map(|route| route.socks),
        running,
        bootstrapped,
        bootstrap_percent,
        error,
        embedded_available: EMBEDDED_AVAILABLE,
        system_socks_trusted: TRUST_LOOPBACK_SOCKS,
        system_socks_owner: system_socks_owner(settings.system_socks()),
    }
}

/// Who held the proxy at `address` when it last answered on loopback.
fn system_socks_owner(address: &str) -> Option<LoopbackOwner> {
    SYSTEM_SOCKS_OWNERS
        .lock()
        .ok()
        .and_then(|seen| seen.get(address).copied())
}

/// Checks a proxy address the user typed, `host:port` with the port in
/// range, and returns it trimmed. A typo fails here, at the settings
/// screen, not at the next sync. A private key or a seed phrase typed
/// in its place is refused as private material, as in a server address,
/// and a space unquoted: stored, the words would go to the resolver. An
/// IPv6 address typed without its brackets is read as a connection reads
/// it, the port after the last colon, and stored between brackets, the
/// one form every client of the core reads the same way.
pub fn parse_socks_address(value: &str) -> CoreResult<String> {
    let invalid = |detail: &str| CoreError::InvalidInput {
        kind: "tor proxy",
        detail: detail.to_owned(),
    };
    super::connect::refuse_typed_secret(value, "tor proxy")?;
    let value = value.trim();
    let (host, port) = value
        .rsplit_once(':')
        .ok_or_else(|| invalid("expected host:port"))?;
    if host.trim_matches(['[', ']']).is_empty() {
        return Err(invalid("the address has no host"));
    }
    let port = match port.parse::<u16>() {
        Ok(port) if port > 0 => port,
        _ => return Err(invalid("the port must be between 1 and 65535")),
    };
    let bracketed = host.starts_with('[') || host.ends_with(']');
    if bracketed && !(host.starts_with('[') && host.ends_with(']')) {
        return Err(invalid("a bracket of the address is not closed"));
    }
    if !bracketed && host.contains(':') {
        return match host.parse::<std::net::Ipv6Addr>() {
            Ok(_) => Ok(format!("[{host}]:{port}")),
            Err(_) => Err(invalid(
                "an IPv6 address goes between brackets, as in [::1]:9050",
            )),
        };
    }
    Ok(value.to_owned())
}

/// What a backend reports when handed an onion host and no proxy. The
/// manager resolves a route before any onion operation, so this is a
/// bug when it shows; it must still never turn into a lookup of the
/// onion name.
pub(crate) fn no_route(url: &str) -> String {
    let host = super::host_of(url).unwrap_or_else(|| url.to_owned());
    CoreError::Tor(format!("no Tor proxy to reach {host} through")).to_string()
}

#[cfg(test)]
mod tests {
    use std::cell::Cell;
    use std::future::Ready;
    use std::net::Ipv4Addr;
    use std::time::Instant;

    use tokio::net::TcpListener;

    use super::*;

    /// A loopback port nothing listens on.
    async fn closed_port() -> String {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        let address = listener.local_addr().unwrap();
        drop(listener);
        address.to_string()
    }

    /// A server that answers the SOCKS5 greeting the way Tor does.
    async fn fake_tor() -> String {
        fake_tor_on(Ipv4Addr::LOCALHOST.into()).await.unwrap()
    }

    /// [`fake_tor`] at `ip`, when it can be bound there.
    async fn fake_tor_on(ip: std::net::IpAddr) -> Option<String> {
        let listener = TcpListener::bind((ip, 0)).await.ok()?;
        let address = listener.local_addr().unwrap().to_string();
        tokio::spawn(async move {
            while let Ok((mut stream, _)) = listener.accept().await {
                let mut greeting = [0u8; 3];
                if stream.read_exact(&mut greeting).await.is_ok() {
                    let _ = stream.write_all(&[socks::VERSION, socks::NO_AUTH]).await;
                }
            }
        });
        Some(address)
    }

    fn settings(mode: TorMode, socks_proxy: Option<&str>) -> TorSettings {
        TorSettings {
            mode,
            socks_proxy: socks_proxy.map(str::to_owned),
        }
    }

    /// A starter that records being called and hands out a fixed
    /// address; the real one is never run by these tests.
    fn starter(called: &Cell<bool>) -> Option<impl AsyncFnOnce() -> CoreResult<socks::Access>> {
        Some(async || {
            called.set(true);
            Ok(socks::Access {
                address: "127.0.0.1:1".to_owned(),
                credentials: socks::Credentials::new("user", "pass"),
            })
        })
    }

    const NO_STARTER: Option<fn() -> Ready<CoreResult<socks::Access>>> = None;

    /// A proxy this account opened, wherever it is asked about.
    async fn this_account(_: &[SocketAddr]) -> LoopbackOwner {
        LoopbackOwner::ThisAccount
    }

    /// A test that does not look at what was noted.
    fn unseen(_: Option<LoopbackOwner>) {}

    /// Auto, a proxy answering on loopback held by `owner`, the default
    /// address: the route, the error, what was noted, and whether the
    /// built-in client was asked for.
    async fn auto_with_owner(
        owner: LoopbackOwner,
        with_embedded: bool,
    ) -> (CoreResult<TorRoute>, Vec<Option<LoopbackOwner>>, bool) {
        let called = Cell::new(false);
        let mut noted = Vec::new();
        let starter = starter(&called).filter(|_| with_embedded);
        let route = resolve_with(
            &settings(TorMode::Auto, None),
            true,
            async |_: &str| true,
            async |_: &[SocketAddr]| owner,
            |seen| noted.push(seen),
            starter,
        )
        .await;
        (route, noted, called.get())
    }

    /// Another account of this computer can open 127.0.0.1:9050 while no
    /// Tor runs: `Auto` does not hand it the wallet's onion traffic.
    #[tokio::test]
    async fn auto_passes_over_a_proxy_another_account_holds() {
        let (route, noted, called) = auto_with_owner(LoopbackOwner::OtherAccount, true).await;
        assert_eq!(route.unwrap().via, TorVia::Embedded);
        assert!(called);
        assert_eq!(noted, vec![Some(LoopbackOwner::OtherAccount)]);
    }

    /// Where the core cannot tell who holds the proxy, it does not
    /// believe it either.
    #[tokio::test]
    async fn auto_passes_over_a_proxy_nobody_can_name() {
        let (route, noted, called) = auto_with_owner(LoopbackOwner::Unknown, true).await;
        assert_eq!(route.unwrap().via, TorVia::Embedded);
        assert!(called);
        assert_eq!(noted, vec![Some(LoopbackOwner::Unknown)]);
    }

    #[tokio::test]
    async fn auto_takes_a_proxy_this_account_or_the_system_holds() {
        for owner in [LoopbackOwner::ThisAccount, LoopbackOwner::System] {
            let (route, noted, called) = auto_with_owner(owner, true).await;
            let route = route.unwrap();
            assert_eq!(route.via, TorVia::System, "{owner:?}");
            assert_eq!(route.socks, DEFAULT_SYSTEM_SOCKS);
            assert!(!called, "{owner:?}");
            assert_eq!(noted, vec![Some(owner)]);
        }
    }

    /// An address away from loopback was typed by the person: it is
    /// believed as typed, and nobody is asked who holds it.
    #[tokio::test]
    async fn auto_believes_a_proxy_away_from_loopback() {
        let asked = Cell::new(false);
        let called = Cell::new(false);
        let mut noted = Vec::new();
        let route = resolve_with(
            &settings(TorMode::Auto, Some("192.168.1.10:9050")),
            true,
            async |_: &str| true,
            async |_: &[SocketAddr]| {
                asked.set(true);
                LoopbackOwner::OtherAccount
            },
            |seen| noted.push(seen),
            starter(&called),
        )
        .await
        .unwrap();
        assert_eq!(route.via, TorVia::System);
        assert_eq!(route.socks, "192.168.1.10:9050");
        assert!(!asked.get());
        assert!(!called.get());
        assert_eq!(noted, vec![None]);
    }

    /// `System` chosen by name: the person vouches for the proxy, which
    /// is used whoever holds it, and who that is is noted for the screen.
    #[tokio::test]
    async fn system_uses_a_proxy_another_account_holds_and_notes_it() {
        let called = Cell::new(false);
        let mut noted = Vec::new();
        let route = resolve_with(
            &settings(TorMode::System, None),
            true,
            async |_: &str| true,
            async |_: &[SocketAddr]| LoopbackOwner::OtherAccount,
            |seen| noted.push(seen),
            starter(&called),
        )
        .await
        .unwrap();
        assert_eq!(route.via, TorVia::System);
        assert_eq!(route.socks, DEFAULT_SYSTEM_SOCKS);
        assert!(!called.get());
        assert_eq!(noted, vec![Some(LoopbackOwner::OtherAccount)]);
    }

    /// Without a built-in client, a proxy passed over leaves no route,
    /// and the error says why it was not taken.
    #[tokio::test]
    async fn auto_without_an_embedded_client_says_why_the_proxy_was_passed_over() {
        let (route, _, _) = auto_with_owner(LoopbackOwner::OtherAccount, false).await;
        match route.unwrap_err() {
            CoreError::Tor(detail) => {
                assert!(detail.contains(DEFAULT_SYSTEM_SOCKS), "{detail}");
                assert!(detail.contains("another account"), "{detail}");
                assert!(detail.contains("System Tor"), "{detail}");
            }
            other => panic!("expected a tor error, got {other:?}"),
        }
        let (route, _, _) = auto_with_owner(LoopbackOwner::Unknown, false).await;
        match route.unwrap_err() {
            CoreError::Tor(detail) => {
                assert!(detail.contains("can't tell which account"), "{detail}");
                assert!(detail.contains("System Tor"), "{detail}");
            }
            other => panic!("expected a tor error, got {other:?}"),
        }
    }

    /// A proxy that stops answering forgets who held it.
    #[tokio::test]
    async fn a_silent_proxy_is_noted_as_nobody() {
        let mut noted = Vec::new();
        let called = Cell::new(false);
        resolve_with(
            &settings(TorMode::Auto, None),
            true,
            async |_: &str| false,
            this_account,
            |seen| noted.push(seen),
            starter(&called),
        )
        .await
        .unwrap();
        assert_eq!(noted, vec![None]);
    }

    /// Every way of writing an address that a connection takes to
    /// loopback is loopback: the IPv6 one without brackets, the short and
    /// numeric spellings of IPv4, and the names the system resolves there
    /// (`ip6-localhost`, `localhost.localdomain`, the machine's own name,
    /// which Debian puts at 127.0.1.1). A proxy held by another account
    /// there is passed over, not believed as typed.
    #[tokio::test]
    async fn auto_asks_who_holds_every_writing_of_loopback() {
        use std::net::{IpAddr, Ipv6Addr};
        let mut writings: Vec<String> = Vec::new();
        let v4 = fake_tor().await;
        let (_, port) = v4.rsplit_once(':').unwrap();
        for host in ["127.1", "2130706433", "0x7f000001"] {
            writings.push(format!("{host}:{port}"));
        }
        if let Some(v6) = fake_tor_on(IpAddr::V6(Ipv6Addr::LOCALHOST)).await {
            let (_, port) = v6.rsplit_once(':').unwrap();
            writings.push(format!("::1:{port}"));
        }
        #[cfg_attr(
            not(unix),
            allow(unused_mut, reason = "only Unix adds the machine's own name")
        )]
        let mut names = vec![
            "ip6-localhost".to_owned(),
            "localhost.localdomain".to_owned(),
        ];
        #[cfg(unix)]
        {
            let mut buffer = [0u8; 256];
            // SAFETY: the buffer is writable for its whole length, which
            // is what the call is given.
            if unsafe { libc::gethostname(buffer.as_mut_ptr().cast(), buffer.len()) } == 0 {
                let end = buffer.iter().position(|byte| *byte == 0).unwrap_or(0);
                names.extend(std::str::from_utf8(&buffer[..end]).ok().map(str::to_owned));
            }
        }
        for name in names {
            // Where the system puts the name on loopback, a proxy there.
            let Ok(resolved) = tokio::net::lookup_host((name.as_str(), 9)).await else {
                continue;
            };
            let Some(ip) = resolved.map(|at| at.ip()).find(IpAddr::is_loopback) else {
                continue;
            };
            if let Some(tor) = fake_tor_on(ip).await {
                let (_, port) = tor.rsplit_once(':').unwrap();
                writings.push(format!("{name}:{port}"));
            }
        }
        for written in &writings {
            let called = Cell::new(false);
            let route = resolve_with(
                &settings(TorMode::Auto, Some(written)),
                true,
                probe,
                async |_: &[SocketAddr]| LoopbackOwner::OtherAccount,
                unseen,
                starter(&called),
            )
            .await
            .unwrap();
            assert_eq!(route.via, TorVia::Embedded, "{written}");
            assert!(called.get(), "{written}");
        }
        assert!(writings.len() >= 3, "{writings:?}");
    }

    /// The screen names the holder only for the address still in effect.
    #[test]
    fn the_status_names_the_holder_of_the_proxy_in_effect() {
        note_system_owner("127.0.0.1:19050", Some(LoopbackOwner::OtherAccount));
        let status = status_with(
            &settings(TorMode::Auto, Some("127.0.0.1:19050")),
            EmbeddedTor::Idle,
        );
        assert_eq!(status.system_socks_owner, Some(LoopbackOwner::OtherAccount));
        let elsewhere = status_with(
            &settings(TorMode::Auto, Some("127.0.0.1:19150")),
            EmbeddedTor::Idle,
        );
        assert_eq!(elsewhere.system_socks_owner, None);
        note_system_owner("127.0.0.1:19050", None);
        let status = status_with(
            &settings(TorMode::Auto, Some("127.0.0.1:19050")),
            EmbeddedTor::Idle,
        );
        assert_eq!(status.system_socks_owner, None);
    }

    #[tokio::test]
    async fn the_probe_says_no_quickly_on_a_closed_port() {
        let address = closed_port().await;
        let started = Instant::now();
        assert!(!probe(&address).await);
        assert!(started.elapsed() < Duration::from_secs(2));
    }

    #[tokio::test]
    async fn the_probe_says_yes_to_a_socks5_greeting_only() {
        assert!(probe(&fake_tor().await).await);

        // Something listening that speaks no SOCKS is not a proxy.
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        let address = listener.local_addr().unwrap().to_string();
        tokio::spawn(async move {
            while let Ok((mut stream, _)) = listener.accept().await {
                let _ = stream.write_all(b"HTTP/1.1 400 Bad Request").await;
            }
        });
        assert!(!probe(&address).await);
    }

    #[tokio::test]
    async fn auto_takes_the_system_proxy_when_it_answers() {
        let called = Cell::new(false);
        let route = resolve_with(
            &settings(TorMode::Auto, Some("127.0.0.1:9150")),
            true,
            async |address: &str| address == "127.0.0.1:9150",
            this_account,
            unseen,
            starter(&called),
        )
        .await
        .unwrap();
        assert_eq!(
            route,
            TorRoute {
                socks: "127.0.0.1:9150".to_owned(),
                via: TorVia::System,
                credentials: None,
            }
        );
        // A system proxy takes no credentials: the string is the address.
        assert_eq!(route.proxy(), "127.0.0.1:9150");
        assert!(!called.get(), "the embedded client stays off");
    }

    #[tokio::test]
    async fn auto_falls_back_to_the_embedded_client() {
        let called = Cell::new(false);
        let route = resolve_with(
            &settings(TorMode::Auto, None),
            true,
            async |_: &str| false,
            this_account,
            unseen,
            starter(&called),
        )
        .await
        .unwrap();
        assert_eq!(route.via, TorVia::Embedded);
        assert_eq!(route.socks, "127.0.0.1:1");
        assert!(called.get());
    }

    /// The embedded proxy's credentials reach the chain layer and
    /// nothing else: not the serialized route the apps receive, not a
    /// debug print, not the address shown in the settings.
    #[tokio::test]
    async fn the_embedded_credentials_never_leave_the_process() {
        let called = Cell::new(false);
        let route = resolve_with(
            &settings(TorMode::Embedded, None),
            true,
            async |_: &str| false,
            this_account,
            unseen,
            starter(&called),
        )
        .await
        .unwrap();
        assert_eq!(route.proxy(), "user:pass@127.0.0.1:1");
        assert_eq!(route.socks, "127.0.0.1:1");
        let json = serde_json::to_string(&route).unwrap();
        assert_eq!(json, r#"{"socks":"127.0.0.1:1","via":"embedded"}"#);
        let shown = format!("{route:?}");
        assert!(!shown.contains("pass"), "{shown}");
        // What the apps send back reads without the field.
        let back: TorRoute = serde_json::from_str(&json).unwrap();
        assert_eq!(back.socks, route.socks);
        assert_eq!(back.proxy(), "127.0.0.1:1");

        // And the chain layer takes the string apart again.
        assert_eq!(
            split_proxy("user:pass@127.0.0.1:1"),
            (Some(("user", "pass")), "127.0.0.1:1")
        );
        assert_eq!(split_proxy("127.0.0.1:9050"), (None, "127.0.0.1:9050"));
        assert_eq!(split_proxy("[::1]:9050"), (None, "[::1]:9050"));
    }

    #[tokio::test]
    async fn auto_without_an_embedded_client_says_what_is_missing() {
        let error = resolve_with(
            &settings(TorMode::Auto, None),
            true,
            async |_: &str| false,
            this_account,
            unseen,
            NO_STARTER,
        )
        .await
        .unwrap_err();
        match error {
            CoreError::Tor(detail) => {
                assert!(detail.contains(DEFAULT_SYSTEM_SOCKS), "{detail}");
                assert!(detail.contains("no built-in Tor"), "{detail}");
            }
            other => panic!("expected a tor error, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn system_never_starts_the_embedded_client() {
        let called = Cell::new(false);
        let error = resolve_with(
            &settings(TorMode::System, Some("localhost:9050")),
            true,
            async |_: &str| false,
            this_account,
            unseen,
            starter(&called),
        )
        .await
        .unwrap_err();
        assert!(matches!(&error, CoreError::Tor(detail) if detail.contains("localhost:9050")));
        assert!(!called.get());

        let route = resolve_with(
            &settings(TorMode::System, None),
            true,
            async |_: &str| true,
            this_account,
            unseen,
            starter(&called),
        )
        .await
        .unwrap();
        assert_eq!(route.via, TorVia::System);
        assert_eq!(route.socks, DEFAULT_SYSTEM_SOCKS);
        assert!(!called.get());
    }

    /// Android and iOS: loopback is every app's, or nobody's that the
    /// core can name. `Auto` does not ask what is
    /// listening there, and goes straight to the built-in client.
    #[tokio::test]
    async fn auto_on_a_shared_loopback_never_probes() {
        let probed = Cell::new(false);
        let called = Cell::new(false);
        let route = resolve_with(
            &settings(TorMode::Auto, None),
            false,
            async |_: &str| {
                probed.set(true);
                true
            },
            this_account,
            unseen,
            starter(&called),
        )
        .await
        .unwrap();
        assert_eq!(route.via, TorVia::Embedded);
        assert!(!probed.get(), "whatever answers on loopback is not asked");
        assert!(called.get());

        // Without a built-in client there is no automatic route at all;
        // the error points at the explicit choice.
        let error = resolve_with(
            &settings(TorMode::Auto, None),
            false,
            async |_: &str| {
                probed.set(true);
                true
            },
            this_account,
            unseen,
            NO_STARTER,
        )
        .await
        .unwrap_err();
        match error {
            CoreError::Tor(detail) => {
                assert!(detail.contains("settings"), "{detail}");
                assert!(detail.contains("no built-in Tor"), "{detail}");
            }
            other => panic!("expected a tor error, got {other:?}"),
        }
        assert!(!probed.get());
    }

    /// The explicit choice stands wherever it is made: `System` probes
    /// the proxy the user named, shared loopback or not.
    #[tokio::test]
    async fn system_still_probes_on_a_shared_loopback() {
        let probed = Cell::new(false);
        let called = Cell::new(false);
        let route = resolve_with(
            &settings(TorMode::System, Some("127.0.0.1:9050")),
            false,
            async |address: &str| {
                probed.set(true);
                address == "127.0.0.1:9050"
            },
            this_account,
            unseen,
            starter(&called),
        )
        .await
        .unwrap();
        assert_eq!(route.via, TorVia::System);
        assert!(probed.get());
        assert!(!called.get());
    }

    #[test]
    fn loopback_is_trusted_everywhere_but_android_and_ios() {
        assert_eq!(
            TRUST_LOOPBACK_SOCKS,
            !cfg!(any(target_os = "android", target_os = "ios"))
        );
    }

    #[tokio::test]
    async fn embedded_never_probes() {
        let probed = Cell::new(false);
        let called = Cell::new(false);
        let route = resolve_with(
            &settings(TorMode::Embedded, None),
            true,
            async |_: &str| {
                probed.set(true);
                true
            },
            this_account,
            unseen,
            starter(&called),
        )
        .await
        .unwrap();
        assert_eq!(route.via, TorVia::Embedded);
        assert!(!probed.get());
        assert!(called.get());

        let error = resolve_with(
            &settings(TorMode::Embedded, None),
            true,
            async |_: &str| true,
            this_account,
            unseen,
            NO_STARTER,
        )
        .await
        .unwrap_err();
        assert!(matches!(error, CoreError::Tor(_)));
        assert!(!probed.get());
    }

    #[test]
    fn a_proxy_address_is_host_and_port() {
        assert_eq!(
            parse_socks_address(" 127.0.0.1:9150 ").unwrap(),
            "127.0.0.1:9150"
        );
        assert_eq!(parse_socks_address("[::1]:9050").unwrap(), "[::1]:9050");
        assert_eq!(parse_socks_address("orbot:9050").unwrap(), "orbot:9050");
        // An IPv6 address without its brackets, read as a connection
        // reads it, the port last, is stored with them.
        assert_eq!(parse_socks_address("::1:9050").unwrap(), "[::1]:9050");
        assert_eq!(
            parse_socks_address("fe80::1:9150").unwrap(),
            "[fe80::1]:9150"
        );
        for wrong in [
            "",
            "9050",
            "::1",
            "tor:lan:9050",
            "[::1:9050",
            ":9050",
            "[]:9050",
            "host:",
            "host:0",
            "host:65536",
            "host:tor",
            "127.0.0.1 :9050",
        ] {
            assert!(
                matches!(
                    parse_socks_address(wrong),
                    Err(CoreError::InvalidInput {
                        kind: "tor proxy",
                        ..
                    })
                ),
                "{wrong:?} must be refused"
            );
        }
    }

    /// A seed phrase or a private key typed into the proxy field, port
    /// and all, is refused as private material, and none is quoted.
    #[test]
    fn a_secret_typed_as_a_proxy_is_refused_unquoted() {
        let seed = ["abandon"; 11].join(" ") + " about";
        let tprv = "tprv8ZgxMBicQKsPdy6LMhUtFHAgpocR8GC6QmwMSFpZs7h6Eziw3SpThFfczTDh5rW2krkqffa11UpX3XkeTTB2FvzZKWXqPY54Y6Rq4AQ5R8L";
        let wif = "5HueCGU8rMjxEXxiPuD5BDku4MkFqeZyd4dZ1jvhTVqvbTLvyTJ";
        for text in [
            format!("{seed}:9050"),
            format!("[{seed}]:9050"),
            format!("socks5h://{seed}:9050"),
            format!("{}:9050", seed.replace(' ', "%20")),
            format!("{tprv}:9050"),
            format!("{wif}:9150"),
        ] {
            let error = parse_socks_address(&text).unwrap_err();
            assert!(
                matches!(error, CoreError::PrivateMaterialRejected),
                "{text}: {error}"
            );
        }
        let near = format!("{}:9050", ["abandon"; 11].join(" "));
        let error = parse_socks_address(&near).unwrap_err().to_string();
        assert!(error.contains("has a space in it"), "{error}");
        assert!(!error.contains("abandon"), "{error}");
    }

    #[test]
    fn settings_read_and_write_as_snake_case() {
        let stored: TorSettings = serde_json::from_str("{}").unwrap();
        assert_eq!(stored, TorSettings::default());
        assert_eq!(stored.mode, TorMode::Auto);
        assert_eq!(stored.system_socks(), DEFAULT_SYSTEM_SOCKS);

        let chosen = TorSettings {
            mode: TorMode::Embedded,
            socks_proxy: Some("127.0.0.1:9150".to_owned()),
        };
        let json = serde_json::to_string(&chosen).unwrap();
        assert_eq!(
            json,
            r#"{"mode":"embedded","socks_proxy":"127.0.0.1:9150"}"#
        );
        assert_eq!(serde_json::from_str::<TorSettings>(&json).unwrap(), chosen);
    }

    /// What starts nothing takes the embedded client only once it runs,
    /// in every mode that would otherwise start it, and still takes a
    /// system proxy that answers where the settings let it be probed.
    #[tokio::test]
    async fn a_route_that_starts_nothing_takes_a_running_tor_only() {
        let access = || socks::Access {
            address: "127.0.0.1:1".to_owned(),
            credentials: socks::Credentials::new("user", "pass"),
        };
        for (mode, trusted) in [
            (TorMode::Auto, false),
            (TorMode::Auto, true),
            (TorMode::Embedded, false),
            (TorMode::Embedded, true),
        ] {
            let refused = resolve_with(
                &settings(mode, None),
                trusted,
                async |_: &str| false,
                this_account,
                unseen,
                Some(async || already_running(None)),
            )
            .await
            .unwrap_err();
            assert!(matches!(refused, CoreError::Tor(_)), "{mode:?}: {refused}");
            let route = resolve_with(
                &settings(mode, None),
                trusted,
                async |_: &str| false,
                this_account,
                unseen,
                Some(async || already_running(Some(access()))),
            )
            .await
            .unwrap();
            assert_eq!(route.via, TorVia::Embedded, "{mode:?}");
            assert_eq!(route.socks, "127.0.0.1:1");
        }
        let system = resolve_with(
            &settings(TorMode::Auto, Some("127.0.0.1:9150")),
            true,
            async |address: &str| address == "127.0.0.1:9150",
            this_account,
            unseen,
            Some(async || already_running(None)),
        )
        .await
        .unwrap();
        assert_eq!(system.via, TorVia::System);
    }

    #[tokio::test]
    async fn status_reads_without_touching_anything() {
        let status = status(&settings(TorMode::System, Some("127.0.0.1:9150"))).await;
        assert_eq!(status.mode, TorMode::System);
        assert_eq!(status.socks_proxy, "127.0.0.1:9150");
        assert_eq!(status.embedded_available, cfg!(feature = "embedded-tor"));
        assert_eq!(status.system_socks_trusted, TRUST_LOOPBACK_SOCKS);
        assert!(!status.bootstrapped);
    }

    /// A start that fails partway leaves nothing of its progress: the
    /// four fields say "failed", and nothing else.
    #[test]
    fn a_failed_start_shows_no_progress() {
        let mut embedded = EmbeddedTor::default();
        embedded.begin();
        embedded.advance(40);
        embedded.fail("Tor did not reach the network within 90 seconds".to_owned());
        let status = status_with(&settings(TorMode::Embedded, None), embedded);
        assert!(!status.running);
        assert!(!status.bootstrapped);
        assert_eq!(status.bootstrap_percent, 0);
        assert_eq!(
            status.error.as_deref(),
            Some("Tor did not reach the network within 90 seconds")
        );
    }

    /// A late estimate from arti, after the start settled, moves
    /// nothing.
    #[test]
    fn an_estimate_after_the_start_settled_is_dropped() {
        let mut failed = EmbeddedTor::default();
        failed.begin();
        failed.fail("Tor could not start".to_owned());
        failed.advance(60);
        let status = status_with(&settings(TorMode::Embedded, None), failed);
        assert_eq!(status.bootstrap_percent, 0);

        let mut ready = EmbeddedTor::default();
        ready.begin();
        ready.finish();
        ready.advance(60);
        let status = status_with(&settings(TorMode::Embedded, None), ready);
        assert!(status.running && status.bootstrapped);
        assert_eq!(status.bootstrap_percent, 100);
        assert_eq!(status.error, None);
    }

    /// While starting, the percentage only climbs, stops short of 100,
    /// and a new start forgets the last failure.
    #[test]
    fn a_start_climbs_below_100_and_forgets_the_last_failure() {
        let mut embedded = EmbeddedTor::default();
        embedded.begin();
        embedded.fail("Tor could not start".to_owned());
        embedded.begin();
        embedded.advance(50);
        embedded.advance(30);
        let status = status_with(&settings(TorMode::Embedded, None), embedded.clone());
        assert!(status.running && !status.bootstrapped);
        assert_eq!(status.bootstrap_percent, 50);
        assert_eq!(status.error, None);
        embedded.advance(100);
        assert_eq!(embedded, EmbeddedTor::Starting { percent: 99 });
    }

    #[test]
    fn a_missing_route_is_a_tor_error_naming_the_host() {
        let detail = no_route("http://abc.onion/api");
        assert!(detail.starts_with("tor: "), "{detail}");
        assert!(detail.contains("abc.onion"), "{detail}");
    }

    /// Live. Bootstraps the embedded client for real and reads the tip
    /// height of a public onion Esplora through its proxy, the way a
    /// sync would. Ignored: it needs the network, and a first bootstrap
    /// takes up to a minute.
    #[cfg(feature = "embedded-tor")]
    #[tokio::test(flavor = "multi_thread")]
    #[ignore = "bootstraps Tor and talks to an onion service"]
    async fn the_embedded_client_reaches_an_onion_esplora() {
        const MEMPOOL_ONION: &str =
            "http://mempoolhqx4isw62xs7abwphsq7ldayuidyx2v2oethdhhj6mlo2r6ad.onion/api";
        let dir = tempfile::tempdir().unwrap();
        let settings = settings(TorMode::Embedded, None);
        let route = resolve(&settings, dir.path())
            .await
            .expect("the embedded client bootstraps");
        assert_eq!(route.via, TorVia::Embedded);
        assert!(route.socks.starts_with("127.0.0.1:"));

        let client = crate::chain::esplora::client(MEMPOOL_ONION, Some(&route.proxy())).unwrap();
        let height = client
            .height()
            .await
            .expect("the onion Esplora answers over Tor");
        assert!(height > 900_000, "{height}");

        let after = status(&settings).await;
        assert!(after.running && after.bootstrapped);
        assert_eq!(after.bootstrap_percent, 100);
        assert_eq!(after.via, Some(TorVia::Embedded));
        assert_eq!(after.socks, Some(route.socks.clone()));
        assert!(std::fs::read_dir(dir.path().join("tor").join("cache")).is_ok());

        // A second resolution reuses the running client.
        assert_eq!(resolve(&settings, dir.path()).await.unwrap(), route);
    }
}
