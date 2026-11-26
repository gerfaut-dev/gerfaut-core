//! The route of the price, against a vault on disk and a stand-in for
//! a system Tor. Nothing here reaches a price source: the proxy writes
//! down the host it was asked for and refuses to connect.

use std::net::Ipv4Addr;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

use crate::chain::BackendConfig;
use crate::chain::tor::{TorMode, TorSettings, socks};
use crate::error::CoreError;
use crate::manager::tests::support::{closed_port, manager};
use crate::network::Network;
use crate::prefs::PreferencesChange;
use crate::price::{
    FiatCurrency, PriceRange, PriceReading, PriceSource, PriceTrouble, TroubleKind,
};

const ONION: &str = "tcp://gerfautexample000000000000000000000000000000000000000.onion:50001";

/// A system Tor that answers the probe, writes down every host a
/// request names, and refuses to connect: what was asked of it is all
/// there is to see, and nothing leaves this machine.
async fn refusing_tor() -> (String, Arc<Mutex<Vec<(String, u16)>>>) {
    let asked: Arc<Mutex<Vec<(String, u16)>>> = Arc::default();
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let proxy = listener.local_addr().unwrap().to_string();
    let seen = asked.clone();
    tokio::spawn(async move {
        while let Ok((mut client, _)) = listener.accept().await {
            let seen = seen.clone();
            tokio::spawn(async move {
                let mut greeting = [0u8; 2];
                client.read_exact(&mut greeting).await.ok()?;
                let mut methods = vec![0u8; usize::from(greeting[1])];
                client.read_exact(&mut methods).await.ok()?;
                client
                    .write_all(&[socks::VERSION, socks::NO_AUTH])
                    .await
                    .ok()?;
                // A probe hangs up here; a request names its host.
                let mut head = [0u8; 5];
                client.read_exact(&mut head).await.ok()?;
                let mut name = vec![0u8; usize::from(head[4]) + 2];
                client.read_exact(&mut name).await.ok()?;
                let port = u16::from_be_bytes([name[name.len() - 2], name[name.len() - 1]]);
                name.truncate(name.len() - 2);
                seen.lock()
                    .unwrap()
                    .push((String::from_utf8_lossy(&name).into_owned(), port));
                // Connection refused.
                client
                    .write_all(&[socks::VERSION, 5, 0, 1, 0, 0, 0, 0, 0, 0])
                    .await
                    .ok()?;
                Some(())
            });
        }
    });
    (proxy, asked)
}

/// A manager whose mainnet backend is an onion, while the network on
/// screen is signet, and whose Tor is the system one at `proxy`.
async fn onion_manager(dir: &std::path::Path, proxy: String) -> crate::WalletManager {
    let manager = manager(dir).await;
    manager
        .set_backend(
            Network::Mainnet,
            BackendConfig::CustomElectrum {
                url: ONION.to_owned(),
                own_node: false,
            },
        )
        .await
        .unwrap();
    manager.set_active_network(Network::Signet).await.unwrap();
    manager
        .set_tor_settings(TorSettings {
            mode: TorMode::System,
            socks_proxy: Some(proxy),
        })
        .await
        .unwrap();
    manager
}

fn is_price_failure(error: &CoreError) -> bool {
    matches!(error, CoreError::Sync { backend, .. } if backend == "price")
}

/// What a reading says went wrong, when it is not a price.
fn trouble(reading: &PriceReading) -> Option<&PriceTrouble> {
    match reading {
        PriceReading::Kept { trouble, .. } | PriceReading::Missing { trouble } => Some(trouble),
        PriceReading::Fresh { .. } => None,
    }
}

/// A source that could not be reached: no quote, and the reason.
fn unreached(reading: &PriceReading) -> bool {
    matches!(reading, PriceReading::Missing { trouble } if trouble.kind == TroubleKind::Unreachable)
}

/// With clearnet backends only, nothing goes through Tor and nothing
/// probes for it, even with a system Tor set that is not there.
#[tokio::test]
async fn without_an_onion_backend_the_price_goes_straight() {
    let dir = tempfile::tempdir().unwrap();
    let manager = manager(dir.path()).await;
    manager
        .set_tor_settings(TorSettings {
            mode: TorMode::System,
            socks_proxy: Some(closed_port().await),
        })
        .await
        .unwrap();
    assert!(!manager.uses_tor().await);
    assert_eq!(manager.beside_syncs_proxy().await.unwrap(), None);
}

/// Prices in `currency` from `source`: what a price follows.
async fn price_by(manager: &crate::WalletManager, source: PriceSource, currency: FiatCurrency) {
    manager
        .set_preferences(PreferencesChange {
            fiat_currency: Some(currency),
            price_source: Some(source),
            ..PreferencesChange::default()
        })
        .await
        .unwrap();
}

/// An onion backend on any network, even one that is not on screen,
/// sends every price request through the Tor proxy, by name.
#[tokio::test]
async fn with_an_onion_backend_the_price_goes_through_tor() {
    let (proxy, asked) = refusing_tor().await;
    let dir = tempfile::tempdir().unwrap();
    let manager = onion_manager(dir.path(), proxy).await;
    assert!(manager.uses_tor().await);

    for source in PriceSource::ALL {
        price_by(&manager, source, FiatCurrency::Usd).await;
        let reading = manager.fetch_price().await.unwrap();
        assert!(unreached(&reading), "{source:?}: {reading:?}");
    }
    // Each source's history too.
    price_by(&manager, PriceSource::MempoolSpace, FiatCurrency::Usd).await;
    let error = manager
        .fetch_price_history(PriceRange::Year)
        .await
        .unwrap_err();
    assert!(is_price_failure(&error), "{error}");
    price_by(&manager, PriceSource::Coingecko, FiatCurrency::Usd).await;
    let error = manager
        .fetch_price_history(PriceRange::Week)
        .await
        .unwrap_err();
    assert!(is_price_failure(&error), "{error}");

    assert_eq!(
        *asked.lock().unwrap(),
        vec![
            ("mempool.space".to_owned(), 443),
            ("api.coingecko.com".to_owned(), 443),
            ("mempool.space".to_owned(), 443),
            ("api.coingecko.com".to_owned(), 443),
        ],
        "every host went to the proxy, by name, and nowhere else"
    );
}

/// Tor is needed and is not there: a Tor error, before any request.
#[tokio::test]
async fn without_the_tor_it_needs_no_price_goes() {
    let dir = tempfile::tempdir().unwrap();
    let manager = onion_manager(dir.path(), closed_port().await).await;
    price_by(&manager, PriceSource::Coingecko, FiatCurrency::Eur).await;

    let started = Instant::now();
    let reading = manager.fetch_price().await.unwrap();
    assert!(
        matches!(&reading, PriceReading::Missing { trouble } if trouble.kind == TroubleKind::Tor && trouble.lasting),
        "{reading:?}"
    );
    let refused = manager
        .fetch_price_history(PriceRange::Week)
        .await
        .unwrap_err();
    assert!(matches!(refused, CoreError::Tor(_)), "{refused}");
    assert!(
        started.elapsed() < Duration::from_secs(5),
        "no price source is contacted, let alone looked up"
    );
}

/// The price follows the preferences: a currency only CoinGecko quotes
/// is asked of CoinGecko, whichever source was picked before it.
#[tokio::test]
async fn the_price_follows_the_preferences() {
    let (proxy, asked) = refusing_tor().await;
    let dir = tempfile::tempdir().unwrap();
    let manager = onion_manager(dir.path(), proxy).await;
    price_by(&manager, PriceSource::MempoolSpace, FiatCurrency::Usd).await;
    manager
        .set_preferences(PreferencesChange {
            fiat_currency: Some(FiatCurrency::Ngn),
            ..PreferencesChange::default()
        })
        .await
        .unwrap();

    assert!(unreached(&manager.fetch_price().await.unwrap()));
    assert_eq!(
        *asked.lock().unwrap(),
        vec![("api.coingecko.com".to_owned(), 443)]
    );
}

/// A range the source cannot serve is refused before a route is
/// resolved: no Tor started for a request that would not go anyway.
#[tokio::test]
async fn an_unserved_range_is_refused_before_any_route() {
    let (proxy, asked) = refusing_tor().await;
    let dir = tempfile::tempdir().unwrap();
    let manager = onion_manager(dir.path(), proxy).await;
    price_by(&manager, PriceSource::Coingecko, FiatCurrency::Usd).await;

    let error = manager
        .fetch_price_history(PriceRange::Max)
        .await
        .unwrap_err();
    assert!(is_price_failure(&error), "{error}");
    assert!(asked.lock().unwrap().is_empty());
}

// --- a price source of our own ------------------------------------------

/// One scripted answer of [`FakeSource`].
#[derive(Clone)]
enum Answer {
    /// A status line, headers and a body.
    Http(&'static str, &'static str, &'static str),
    /// The connection is taken and never answered.
    Silence,
}

const EUR_PRICE: Answer = Answer::Http("200 OK", "", r#"{"bitcoin":{"eur":84000.5}}"#);

/// A stand-in for a price source on this machine: it answers each
/// request with the next scripted answer, the last one again once the
/// script runs out, and counts the requests it got.
struct FakeSource {
    base: String,
    requests: Arc<Mutex<usize>>,
}

async fn fake_source(script: Vec<Answer>) -> FakeSource {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let base = format!("http://{}/api/v3", listener.local_addr().unwrap());
    let requests: Arc<Mutex<usize>> = Arc::default();
    let counted = requests.clone();
    tokio::spawn(async move {
        while let Ok((mut client, _)) = listener.accept().await {
            let answer = {
                let mut count = counted.lock().unwrap();
                *count += 1;
                script[(*count - 1).min(script.len() - 1)].clone()
            };
            tokio::spawn(async move {
                let mut head = Vec::new();
                let mut byte = [0u8; 1];
                while !head.ends_with(b"\r\n\r\n") {
                    if client.read_exact(&mut byte).await.is_err() {
                        return;
                    }
                    head.push(byte[0]);
                }
                match answer {
                    Answer::Http(status, headers, body) => {
                        let reply = format!(
                            "HTTP/1.1 {status}\r\ncontent-type: application/json\r\n{headers}content-length: {}\r\nconnection: close\r\n\r\n{body}",
                            body.len()
                        );
                        let _ = client.write_all(reply.as_bytes()).await;
                    }
                    Answer::Silence => {
                        let _ = tokio::time::sleep(Duration::from_secs(3600)).await;
                    }
                }
            });
        }
    });
    FakeSource { base, requests }
}

impl FakeSource {
    fn requests(&self) -> usize {
        *self.requests.lock().unwrap()
    }
}

/// A manager with clearnet backends that prices in euros from CoinGecko
/// played by `source`.
async fn priced_by(dir: &std::path::Path, source: &FakeSource) -> crate::WalletManager {
    let manager = manager(dir).await;
    price_by(&manager, PriceSource::Coingecko, FiatCurrency::Eur).await;
    manager.prices.lock().await.endpoints.coingecko = source.base.clone();
    manager
}

/// Leaves the reuse window behind: the keeper forgets the time a quote
/// was asked at by moving it back, which is the clock moving forward.
async fn age_quotes(manager: &crate::WalletManager, secs: u64) {
    manager.prices.lock().await.age_by(secs);
}

/// The user's case: a price on screen, then a source that rate-limits.
/// The quote stays, the failure is quiet at first, the named wait is
/// kept, and no ask in between reaches the source.
#[tokio::test]
async fn a_rate_limit_keeps_the_price_and_its_wait() {
    let source = fake_source(vec![
        EUR_PRICE,
        Answer::Http("429 Too Many Requests", "retry-after: 120\r\n", "{}"),
    ])
    .await;
    let dir = tempfile::tempdir().unwrap();
    let manager = priced_by(dir.path(), &source).await;

    let first = manager.fetch_price().await.unwrap();
    assert!(
        matches!(&first, PriceReading::Fresh { quote } if quote.rate == 84_000.5),
        "{first:?}"
    );
    age_quotes(&manager, 60).await;

    let limited = manager.fetch_price().await.unwrap();
    let PriceReading::Kept { quote, trouble } = &limited else {
        panic!("{limited:?}");
    };
    assert_eq!(quote.rate, 84_000.5, "the last price stays");
    assert_eq!(trouble.kind, TroubleKind::RateLimited);
    assert!(!trouble.lasting, "one failure is not said");
    assert_eq!(trouble.next_try - trouble.since, 120, "the named wait");
    assert_eq!(source.requests(), 2);

    // The screens ask again, and a person presses "Try again": the
    // source asked to wait, so nothing reaches it.
    for _ in 0..5 {
        assert_eq!(manager.fetch_price().await.unwrap(), limited);
    }
    assert_eq!(manager.retry_price().await.unwrap(), limited);
    assert_eq!(source.requests(), 2, "no burst against a rate limit");

    // A chart from that source waits too, without a request.
    let error = manager
        .fetch_price_history(PriceRange::Week)
        .await
        .unwrap_err();
    assert!(is_price_failure(&error), "{error}");
    assert_eq!(source.requests(), 2);
}

/// A server error is a source that does not answer: the last price
/// stays, a second failure in a row is said, and "Try again" asks at
/// once, since nothing asked to wait.
#[tokio::test]
async fn a_server_error_is_said_on_the_second_try_and_try_again_asks() {
    let source = fake_source(vec![
        EUR_PRICE,
        Answer::Http("503 Service Unavailable", "", "<html>down</html>"),
    ])
    .await;
    let dir = tempfile::tempdir().unwrap();
    let manager = priced_by(dir.path(), &source).await;
    manager.fetch_price().await.unwrap();
    age_quotes(&manager, 60).await;

    let first = manager.fetch_price().await.unwrap();
    let quiet = trouble(&first).expect("a trouble");
    assert_eq!(quiet.kind, TroubleKind::Unreachable);
    assert!(!quiet.lasting);

    let second = manager.retry_price().await.unwrap();
    let PriceReading::Kept { trouble, .. } = &second else {
        panic!("{second:?}");
    };
    assert!(trouble.lasting, "a second failure in a row is said");
    assert_eq!(trouble.since, quiet.since);
    assert_eq!(source.requests(), 3);
}

/// A source that refuses (a 403, as a Tor exit often gets) is said as
/// a refusal, not as silence.
#[tokio::test]
async fn a_refusal_is_told_from_silence() {
    let source = fake_source(vec![Answer::Http(
        "403 Forbidden",
        "",
        "<html>blocked</html>",
    )])
    .await;
    let dir = tempfile::tempdir().unwrap();
    let manager = priced_by(dir.path(), &source).await;
    let reading = manager.fetch_price().await.unwrap();
    assert!(
        matches!(&reading, PriceReading::Missing { trouble } if trouble.kind == TroubleKind::Refused),
        "{reading:?}"
    );
}

/// A source that takes the connection and never answers fails within
/// the request's time, as a source that did not answer.
#[tokio::test(start_paused = true)]
async fn a_silent_source_times_out_as_unreachable() {
    let source = fake_source(vec![Answer::Silence]).await;
    let dir = tempfile::tempdir().unwrap();
    let manager = priced_by(dir.path(), &source).await;
    let reading = manager.fetch_price().await.unwrap();
    assert!(unreached(&reading), "{reading:?}");
}

/// No source at all, a closed port: the same.
#[tokio::test]
async fn a_closed_port_is_unreachable() {
    let dir = tempfile::tempdir().unwrap();
    let manager = manager(dir.path()).await;
    price_by(&manager, PriceSource::Coingecko, FiatCurrency::Eur).await;
    manager.prices.lock().await.endpoints.coingecko =
        format!("http://{}/api/v3", closed_port().await);
    assert!(unreached(&manager.fetch_price().await.unwrap()));
}

/// Screens that ask together share one request, and a quote seconds
/// old answers the next ask.
#[tokio::test]
async fn asks_that_come_together_share_one_request() {
    let source = fake_source(vec![EUR_PRICE]).await;
    let dir = tempfile::tempdir().unwrap();
    let manager = priced_by(dir.path(), &source).await;
    let (a, b, c) = tokio::join!(
        manager.fetch_price(),
        manager.fetch_price(),
        manager.fetch_price()
    );
    assert_eq!(a.unwrap(), b.unwrap());
    assert!(matches!(c.unwrap(), PriceReading::Fresh { .. }));
    assert_eq!(source.requests(), 1);
}
