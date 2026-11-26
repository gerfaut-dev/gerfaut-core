//! The fiat price, by the preferences and by the route the syncs take:
//! see [`crate::price`].

use crate::error::{CoreError, CoreResult};
use crate::now_secs;
use crate::price::{
    self, Endpoints, Failure, PriceHistory, PriceKeeper, PriceRange, PriceReading, TroubleKind,
};

use super::WalletManager;

/// What the manager keeps of the price.
#[derive(Debug, Default)]
pub(crate) struct PriceDesk {
    /// The last quotes and the holds of failing sources, and where the
    /// sources answer. Held for a few instructions, never across an
    /// await: a chart never waits on a price request under way.
    books: std::sync::Mutex<Books>,
    /// Held by the one price request under way, across it: asks that
    /// come together wait for it, then read what it brought.
    asking: tokio::sync::Mutex<()>,
}

#[derive(Debug, Default)]
struct Books {
    keeper: PriceKeeper,
    endpoints: Endpoints,
}

impl PriceDesk {
    fn books(&self) -> std::sync::MutexGuard<'_, Books> {
        self.books
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }
}

#[cfg(test)]
impl PriceDesk {
    /// Puts a source of the test's own in place of a public one.
    pub(crate) fn point(&self, change: impl FnOnce(&mut Endpoints)) {
        change(&mut self.books().endpoints);
    }

    /// The clock moving on for the quotes kept: see
    /// [`PriceKeeper::age_by`].
    pub(crate) fn age_by(&self, secs: u64) {
        self.books().keeper.age_by(secs);
    }
}

impl WalletManager {
    /// The BTC price, in the currency and from the source the
    /// preferences name ([`crate::prefs::Preferences`]), as the screens
    /// should show it. The apps ask every [`price::REFRESH_SECS`], and
    /// only while something on screen shows it: the fiat value, or a
    /// widget placed for it.
    ///
    /// The source is not asked at each call. A quote seconds old is
    /// answered again, and a source that failed is left alone for a
    /// wait that doubles at each failure, or the one it named: the
    /// reading then says why, and keeps the last quote for a while
    /// ([`PriceReading::Kept`]). Calls that come together share one
    /// request.
    ///
    /// It takes the route the update check takes: through the Tor proxy
    /// a sync would resolve when [`Self::uses_tor`] says so; when that
    /// proxy cannot be had nothing is sent, and the reading says
    /// [`TroubleKind::Tor`].
    pub async fn fetch_price(&self) -> CoreResult<PriceReading> {
        self.read_price(false).await
    }

    /// [`Self::fetch_price`] at a person's request, the "Try again" of
    /// the settings: the source is asked now, however long it was left
    /// alone, unless it asked for the wait itself (a rate limit), which
    /// is kept.
    pub async fn retry_price(&self) -> CoreResult<PriceReading> {
        self.read_price(true).await
    }

    async fn read_price(&self, forced: bool) -> CoreResult<PriceReading> {
        let _turn = self.prices.asking.lock().await;
        // Read once the turn is ours: an ask that waited on another
        // prices what the preferences say now, not what they said when
        // it began to wait.
        let preferences = self.preferences().await;
        let (source, currency) = (preferences.price_source, preferences.fiat_currency);
        price::check_quote(source, currency)?;
        let endpoints = {
            let books = self.prices.books();
            if let Some(reading) =
                books
                    .keeper
                    .answer_without_asking(source, currency, now_secs(), forced)
            {
                return Ok(reading);
            }
            books.endpoints.clone()
        };
        let asked = match self.beside_syncs_proxy().await {
            Ok(proxy) => price::fetch_price(source, currency, proxy.as_deref(), &endpoints).await,
            Err(CoreError::Tor(detail)) => Err(Failure {
                kind: TroubleKind::Tor,
                retry_after: None,
                detail,
            }),
            Err(other) => return Err(other),
        };
        let mut books = self.prices.books();
        Ok(match asked {
            Ok(quote) => books.keeper.answered(quote),
            Err(failure) => books.keeper.failed(source, currency, &failure, now_secs()),
        })
    }

    /// A BTC price series over `range`, by the same preferences and the
    /// same route as [`Self::fetch_price`]. A range the source cannot
    /// serve is refused first, with nothing resolved and nothing sent;
    /// so is a series from a source that asked to be left alone, until
    /// its wait is over. A rate limit met here holds the price too.
    ///
    /// mempool.space's hourly series is closed by the last quote the
    /// price kept, at its own time, rather than by a request of its own
    /// that nothing would hold back.
    pub async fn fetch_price_history(&self, range: PriceRange) -> CoreResult<PriceHistory> {
        let preferences = self.preferences().await;
        let (source, currency) = (preferences.price_source, preferences.fiat_currency);
        price::check_history(source, currency, range)?;
        let (endpoints, closing) = {
            let books = self.prices.books();
            let now = now_secs();
            if let Some(until) = books.keeper.source_wait(source, now) {
                return Err(price::waiting_error(source, until.saturating_sub(now)));
            }
            (
                books.endpoints.clone(),
                books.keeper.latest(source, currency, now),
            )
        };
        let proxy = self.beside_syncs_proxy().await?;
        match price::fetch_price_history(
            source,
            currency,
            range,
            proxy.as_deref(),
            &endpoints,
            closing.as_ref(),
        )
        .await
        {
            Ok(history) => Ok(history),
            Err(failure) => {
                if failure.kind == TroubleKind::RateLimited {
                    self.prices
                        .books()
                        .keeper
                        .note_wait(source, &failure, now_secs());
                }
                Err(failure.into())
            }
        }
    }
}

#[cfg(test)]
mod tests;
