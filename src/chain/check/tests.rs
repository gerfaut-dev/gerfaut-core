use std::net::{Ipv4Addr, SocketAddr};

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

use super::*;
use crate::chain::electrum::Target;
use crate::testkit::{FakeElectrum, FakeMempool};

fn electrum(url: String) -> Vec<Endpoint> {
    vec![Endpoint::Electrum(Target::new(url, None))]
}

async fn failed(endpoints: &[Endpoint], proxy: Option<&str>) -> (BackendProblem, Option<Network>) {
    match check(endpoints, Network::Signet, proxy).await {
        BackendCheck::Failed {
            problem,
            server_network,
            ..
        } => (problem, server_network),
        reached => panic!("expected a failure, got {reached:?}"),
    }
}

/// A port nothing listens on any more.
async fn closed_port() -> SocketAddr {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    listener.local_addr().unwrap()
}

/// A server that answers whatever it is sent with `reply`, then hangs up.
async fn answering(reply: &'static [u8]) -> SocketAddr {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let address = listener.local_addr().unwrap();
    tokio::spawn(async move {
        while let Ok((mut stream, _)) = listener.accept().await {
            tokio::spawn(async move {
                let mut buffer = [0u8; 1024];
                let _ = stream.read(&mut buffer).await;
                let _ = stream.write_all(reply).await;
            });
        }
    });
    address
}

/// In front of `upstream`, a port that hangs up on a TLS handshake and
/// carries anything else through: a plain Electrum server, as far as a
/// client can tell, that does not wait for a line end to give up.
async fn hanging_up_on_tls(upstream: SocketAddr) -> SocketAddr {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let address = listener.local_addr().unwrap();
    tokio::spawn(async move {
        while let Ok((mut stream, _)) = listener.accept().await {
            tokio::spawn(async move {
                let mut first = [0u8; 1];
                if stream.peek(&mut first).await.is_err() || first[0] == 0x16 {
                    return;
                }
                let Ok(mut server) = tokio::net::TcpStream::connect(upstream).await else {
                    return;
                };
                let _ = tokio::io::copy_bidirectional(&mut stream, &mut server).await;
            });
        }
    });
    address
}

/// An Electrum server of the network is reached: its height, and the
/// software it names.
#[tokio::test]
async fn an_electrum_server_of_the_network_is_reached() {
    let server = FakeElectrum::start().await;
    let checked = check(
        &electrum(format!("tcp://{}", server.address)),
        Network::Signet,
        None,
    )
    .await;
    match checked {
        BackendCheck::Reached {
            host,
            height,
            software,
            tor,
            ..
        } => {
            assert_eq!(host, server.address.to_string());
            assert_eq!(height, 100);
            assert_eq!(software.as_deref(), Some("fake 1.0"));
            assert!(!tor);
        }
        failed => panic!("{failed:?}"),
    }
}

/// A server of another network is named for the network it follows.
#[tokio::test]
async fn a_server_of_another_network_says_which() {
    let server = FakeElectrum::start().await;
    server.state.lock().unwrap().genesis = Some(bdk_wallet::bitcoin::Network::Bitcoin);
    let endpoints = electrum(format!("tcp://{}", server.address));
    assert_eq!(
        failed(&endpoints, None).await,
        (BackendProblem::AnotherNetwork, Some(Network::Mainnet))
    );
}

/// A tip higher than any chain has reached is no chain to follow.
#[tokio::test]
async fn an_impossible_tip_is_a_bad_chain() {
    let server = FakeElectrum::start().await;
    server.state.lock().unwrap().height = 50_000_000;
    let endpoints = electrum(format!("tcp://{}", server.address));
    assert_eq!(failed(&endpoints, None).await.0, BackendProblem::BadChain);
}

/// Nothing listening on the port: refused, not silent.
#[tokio::test]
async fn a_port_nothing_listens_on_is_refused() {
    let address = closed_port().await;
    let endpoints = electrum(format!("tcp://{address}"));
    assert_eq!(failed(&endpoints, None).await.0, BackendProblem::Refused);
}

/// TLS asked of a server that answers in plain: told as TLS to turn off.
#[tokio::test]
async fn tls_on_a_plain_server_is_told() {
    let server = FakeElectrum::start().await;
    let front = hanging_up_on_tls(server.address).await;
    let endpoints = electrum(format!("ssl://{front}"));
    assert_eq!(failed(&endpoints, None).await.0, BackendProblem::NotTls);
}

/// Something that is not Electrum on the port, a web server say.
#[tokio::test]
async fn a_web_server_is_not_electrum() {
    let address = answering(b"HTTP/1.1 400 Bad Request\r\nConnection: close\r\n\r\n").await;
    let endpoints = electrum(format!("tcp://{address}"));
    assert_eq!(
        failed(&endpoints, None).await.0,
        BackendProblem::NotElectrum
    );
}

/// A server that refuses the protocol says so in its own words.
#[tokio::test]
async fn a_refused_handshake_is_the_servers_refusal() {
    let server = FakeElectrum::start().await;
    server
        .state
        .lock()
        .unwrap()
        .refuse
        .insert("server.version", "unsupported protocol version".to_owned());
    match check(
        &electrum(format!("tcp://{}", server.address)),
        Network::Signet,
        None,
    )
    .await
    {
        BackendCheck::Failed {
            problem, detail, ..
        } => {
            assert_eq!(problem, BackendProblem::ServerRefused);
            assert!(detail.contains("unsupported protocol version"), "{detail}");
        }
        reached => panic!("{reached:?}"),
    }
}

/// An onion is reached through the proxy; one whose port the service
/// does not serve is refused, one that does not answer is silent.
#[tokio::test]
async fn an_onion_is_told_by_the_proxys_reply() {
    use crate::chain::tor::socks;
    const ONION: &str = "gerfautexample000000000000000000000000000000000000000.onion";
    let server = FakeElectrum::start().await;
    let upstream = server.address;
    let (listener, address) = socks::bind().await.unwrap();
    tokio::spawn(socks::serve(
        listener,
        socks::Credentials::new("user", "pass"),
        move |_host, port| async move {
            match port {
                50001 => tokio::net::TcpStream::connect(upstream).await,
                50002 => Err(std::io::Error::from(std::io::ErrorKind::ConnectionRefused)),
                _ => Err(std::io::Error::from(std::io::ErrorKind::TimedOut)),
            }
        },
    ));
    let proxy = format!("user:pass@{address}");
    let at = |port: u16| electrum(format!("tcp://{ONION}:{port}"));
    match check(&at(50001), Network::Signet, Some(&proxy)).await {
        BackendCheck::Reached { tor, height, .. } => {
            assert!(tor);
            assert_eq!(height, 100);
        }
        failed => panic!("{failed:?}"),
    }
    assert_eq!(
        failed(&at(50002), Some(&proxy)).await.0,
        BackendProblem::Refused
    );
    assert_eq!(
        failed(&at(50003), Some(&proxy)).await.0,
        BackendProblem::NoAnswer
    );
    // A proxy that is not there is Tor's failure, not the server's.
    let gone = closed_port().await;
    assert_eq!(
        failed(&at(50001), Some(&gone.to_string())).await.0,
        BackendProblem::Tor
    );
}

/// A rotation is tested in order, and the first server that answers is
/// the one named.
#[tokio::test]
async fn the_first_server_that_answers_is_named() {
    let down = closed_port().await;
    let server = FakeElectrum::start().await;
    let endpoints = vec![
        Endpoint::Electrum(Target::new(format!("tcp://{down}"), None)),
        Endpoint::Electrum(Target::new(format!("tcp://{}", server.address), None)),
    ];
    match check(&endpoints, Network::Signet, None).await {
        BackendCheck::Reached { host, .. } => assert_eq!(host, server.address.to_string()),
        failed => panic!("{failed:?}"),
    }
}

/// An Esplora API of the network is reached, at its tip.
#[tokio::test]
async fn an_esplora_api_of_the_network_is_reached() {
    let mempool = FakeMempool::start(false, usize::MAX).await;
    let endpoints = vec![Endpoint::Esplora(format!("http://{}/api", mempool.address))];
    match check(&endpoints, Network::Signet, None).await {
        BackendCheck::Reached {
            height, software, ..
        } => {
            assert_eq!(height, 500);
            assert_eq!(software, None);
        }
        failed => panic!("{failed:?}"),
    }
}

/// The wrong path, or a server of another network, over Esplora.
#[tokio::test]
async fn an_esplora_address_that_is_wrong_is_named() {
    let not_found =
        answering(b"HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
            .await;
    let wrong_path = vec![Endpoint::Esplora(format!("http://{not_found}/nothing"))];
    assert_eq!(
        failed(&wrong_path, None).await.0,
        BackendProblem::NotEsplora
    );

    let mempool = FakeMempool::start(false, usize::MAX).await;

    mempool.state.lock().unwrap().genesis = Some(bdk_wallet::bitcoin::Network::Testnet4);
    let other = vec![Endpoint::Esplora(format!("http://{}/api", mempool.address))];
    assert_eq!(
        failed(&other, None).await,
        (BackendProblem::AnotherNetwork, Some(Network::Testnet4))
    );

    let down = closed_port().await;
    let refused = vec![Endpoint::Esplora(format!("http://{down}/api"))];
    assert_eq!(failed(&refused, None).await.0, BackendProblem::Refused);
}
