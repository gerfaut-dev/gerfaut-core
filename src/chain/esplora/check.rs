//! The test of an Esplora API: see [`crate::chain::check`]. The genesis
//! block first, asked once without the retries of a sync, so the failure
//! of the request is read as it came; then the tip, checked as a sync
//! checks it.

use bdk_wallet::bitcoin::BlockHash;

use super::{Client, client, find_cause};
use crate::chain::check::{Answer, BackendProblem, Trouble};
use crate::chain::fault::IoOutage;
use crate::network::Network;

/// The most of the genesis answer read: a block hash and a line end.
const GENESIS_MAX: usize = 1024;

pub(crate) async fn run(
    url: &str,
    network: Network,
    proxy: Option<&str>,
) -> Result<Answer, Trouble> {
    let onion = crate::chain::is_onion(url);
    let proxy = proxy.filter(|_| onion);
    if onion && proxy.is_none() {
        return Err(Trouble::new(
            BackendProblem::Tor,
            crate::chain::tor::no_route(url),
        ));
    }
    let api = client(url, proxy)
        .map_err(|fault| Trouble::new(BackendProblem::Failed, fault.to_string()))?;
    let genesis = match genesis(&api).await {
        Ok(genesis) => genesis,
        // Plain HTTP, and the server hung up or answered garbage: an
        // HTTPS server on that port takes a handshake.
        Err(trouble)
            if trouble.problem == BackendProblem::NotEsplora
                && url.to_ascii_lowercase().starts_with("http://")
                && speaks_https(url, proxy).await =>
        {
            return Err(Trouble::new(BackendProblem::NeedsTls, trouble.detail));
        }
        Err(trouble) => return Err(trouble),
    };
    if !crate::chain::is_genesis_of(network, genesis) {
        return Err(Trouble::another_network(genesis));
    }
    let height = super::sync::proven_tip(&api, network)
        .await
        .map_err(|fault| {
            let detail = fault.to_string();
            let unsound = [
                crate::chain::IMPOSSIBLE_TIP,
                crate::chain::UNWORKED_TIP,
                super::sync::UNCHAINED,
            ];
            let problem = if unsound.contains(&detail.as_str()) {
                BackendProblem::BadChain
            } else {
                BackendProblem::Failed
            };
            Trouble::new(problem, detail)
        })?;
    Ok(Answer {
        height,
        software: None,
    })
}

/// The hash the server gives for block 0.
async fn genesis(api: &Client) -> Result<BlockHash, Trouble> {
    let response = api
        .http
        .get(format!("{}/block-height/0", api.base))
        .send()
        .await
        .map_err(|error| of_request(&error))?;
    let status = response.status().as_u16();
    match status {
        200 => {}
        401 | 403 | 429 | 500..=599 => {
            return Err(Trouble::new(
                BackendProblem::ServerRefused,
                super::describe_status(status).to_string(),
            ));
        }
        _ => {
            return Err(Trouble::new(
                BackendProblem::NotEsplora,
                super::describe_status(status).to_string(),
            ));
        }
    }
    let body = api
        .body(response, GENESIS_MAX)
        .await
        .map_err(|fault| Trouble::new(BackendProblem::NotEsplora, fault.to_string()))?;
    std::str::from_utf8(&body)
        .ok()
        .and_then(|text| text.trim().parse().ok())
        .ok_or_else(|| Trouble::new(BackendProblem::NotEsplora, "unexpected response"))
}

/// A request that got no answer, by what its error is.
fn of_request(error: &reqwest::Error) -> Trouble {
    let detail = super::describe_failure(error);
    if error.is_timeout() {
        return Trouble::new(BackendProblem::NoAnswer, "no answer in time");
    }
    if error.is_connect() {
        if let Some(cause) = find_cause(error, &mut |cause| cause.is::<rustls::Error>())
            && let Some(tls) = cause.downcast_ref::<rustls::Error>()
        {
            return Trouble::new(
                match tls {
                    rustls::Error::InvalidCertificate(_) => BackendProblem::Certificate,
                    rustls::Error::InvalidMessage(_) => BackendProblem::NotTls,
                    _ => BackendProblem::Failed,
                },
                detail,
            );
        }
        if find_cause(error, &mut |cause| cause.to_string() == "dns error").is_some() {
            return Trouble::new(BackendProblem::HostNotFound, detail);
        }
        let refused = find_cause(error, &mut |cause| {
            cause
                .downcast_ref::<std::io::Error>()
                .is_some_and(|io| io.kind() == std::io::ErrorKind::ConnectionRefused)
        });
        if refused.is_some() {
            return Trouble::new(BackendProblem::Refused, detail);
        }
        return Trouble::new(BackendProblem::NoAnswer, detail);
    }
    // Connected, and no HTTP answer: the server hung up, or sent what
    // is not HTTP.
    let closed = find_cause(error, &mut |cause| {
        cause
            .downcast_ref::<std::io::Error>()
            .is_some_and(|io| IoOutage::of(io.kind()) == Some(IoOutage::Closed))
    });
    if closed.is_some() || error.is_request() || error.is_body() || error.is_decode() {
        return Trouble::new(BackendProblem::NotEsplora, detail);
    }
    Trouble::new(BackendProblem::Failed, detail)
}

/// Whether the host of an `http://` address answers a TLS handshake on
/// the same port: a request that reaches HTTP at all, or that only the
/// certificate stops.
async fn speaks_https(url: &str, proxy: Option<&str>) -> bool {
    let Ok(mut parsed) = url::Url::parse(url) else {
        return false;
    };
    let port = parsed.port_or_known_default();
    if parsed.set_scheme("https").is_err() || parsed.set_port(port).is_err() {
        return false;
    }
    let Ok(api) = client(parsed.as_str(), proxy) else {
        return false;
    };
    match api
        .http
        .get(format!("{}/block-height/0", api.base))
        .send()
        .await
    {
        Ok(_) => true,
        Err(error) => of_request(&error).problem == BackendProblem::Certificate,
    }
}
