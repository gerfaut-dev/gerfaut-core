//! What the core remembers of the price between two asks: the last
//! quote each pair got, and how long each source is left alone after
//! it failed.
//!
//! A source that fails is not a price that disappears. The last quote
//! stays on screen with its age for [`KEEP_SECS`], the source is asked
//! again later and later ([`backoff_secs`]), never sooner than its
//! `Retry-After`, and the screens only call it trouble once a second
//! try failed too ([`PriceTrouble::lasting`]). However many screens
//! ask, at most one request goes out per wait.
//!
//! Every function takes the time: the rules are tested on a clock the
//! tests hold.

use serde::{Deserialize, Serialize};

use super::{FiatCurrency, PriceQuote, PriceSource, REFRESH_SECS};

/// How long the last quote of a pair stands in for the price while its
/// source fails. Past it the amounts show no fiat: a price that old is
/// no longer a fair guess at what bitcoin is worth.
pub const KEEP_SECS: u64 = 6 * 3600;

/// Longest wait between two asks of a source that keeps failing.
pub const MAX_BACKOFF_SECS: u64 = 30 * 60;

/// Longest wait a `Retry-After` is followed for. A source that names a
/// longer one is asked again after this: one request an hour is
/// nothing to a rate limit.
pub const MAX_RETRY_AFTER_SECS: u64 = 3600;

/// How many failures in a row make trouble worth saying. One is a blip
/// (a timeout, a phone back from sleep before its network): the next
/// ask, a minute later, usually goes through.
const FAILURES_TO_SAY: u32 = 2;

/// A quote younger than this is answered again rather than asked again:
/// two screens, or an app that comes back to the front twice in a few
/// seconds, never cost two requests.
const REUSE_SECS: u64 = 30;

/// The longest hold the keeper ever sets.
const LONGEST_WAIT_SECS: u64 = if MAX_RETRY_AFTER_SECS > MAX_BACKOFF_SECS {
    MAX_RETRY_AFTER_SECS
} else {
    MAX_BACKOFF_SECS
};

/// The price as the screens should show it.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "state", rename_all = "snake_case")]
pub enum PriceReading {
    /// The source answered at the last ask.
    Fresh { quote: PriceQuote },
    /// The source fails; the last quote it gave, younger than
    /// [`KEEP_SECS`], stands in, its age in `quote.at`.
    Kept {
        quote: PriceQuote,
        trouble: PriceTrouble,
    },
    /// The source fails and no quote stands in: amounts show no fiat.
    Missing { trouble: PriceTrouble },
}

impl PriceReading {
    /// The quote an amount may be priced with.
    pub fn quote(&self) -> Option<&PriceQuote> {
        match self {
            PriceReading::Fresh { quote } | PriceReading::Kept { quote, .. } => Some(quote),
            PriceReading::Missing { .. } => None,
        }
    }
}

/// Why the source failed, since when, and when it is asked again.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PriceTrouble {
    pub kind: TroubleKind,
    /// Unix seconds of the first failure in a row.
    pub since: u64,
    /// Unix seconds before which the core does not ask the source
    /// again: an ask before it answers this reading.
    pub next_try: u64,
    /// Whether the screens say it: the source failed twice in a row, or
    /// Tor, which no wait fixes, is missing. A single failure is quiet.
    pub lasting: bool,
}

/// What went wrong with the last ask.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TroubleKind {
    /// The source said too many requests (HTTP 429). Its limit counts
    /// by address: a shared one (a mobile carrier, a VPN, a Tor exit)
    /// reaches it with requests that are not ours.
    RateLimited,
    /// No answer: no connection, a timeout, or a server error (5xx).
    Unreachable,
    /// An answer that is no price: refused (403, often to a Tor exit),
    /// not found, or a body that does not read as a price.
    Refused,
    /// A backend is an onion, so the price goes through Tor, and Tor
    /// cannot be had: nothing was sent.
    Tor,
}

/// One failed ask, as the fetch saw it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Failure {
    pub kind: TroubleKind,
    /// The wait the source named, in seconds.
    pub retry_after: Option<u64>,
    pub detail: String,
}

/// How long a source is left alone after its `failures`-th failure in
/// a row: the refresh cadence, doubled at each failure, up to
/// [`MAX_BACKOFF_SECS`].
pub fn backoff_secs(failures: u32) -> u64 {
    let doublings = failures.saturating_sub(1).min(16);
    (REFRESH_SECS << doublings).min(MAX_BACKOFF_SECS)
}

/// A source that failed, until it answers again.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Hold {
    failures: u32,
    kind: TroubleKind,
    since: u64,
    next_try: u64,
    /// The source asked for the wait (a 429, or a `Retry-After`): a
    /// "Try again" does not cut it short.
    asked_by_source: bool,
}

/// The last quote of each pair and the hold of each failing source.
#[derive(Debug, Default)]
pub(crate) struct PriceKeeper {
    quotes: Vec<PriceQuote>,
    holds: Vec<(PriceSource, Hold)>,
}

impl PriceKeeper {
    fn quote(&self, source: PriceSource, currency: FiatCurrency) -> Option<&PriceQuote> {
        self.quotes
            .iter()
            .find(|quote| quote.source == source && quote.currency == currency)
    }

    fn hold(&self, source: PriceSource) -> Option<&Hold> {
        self.holds
            .iter()
            .find(|(held, _)| *held == source)
            .map(|(_, hold)| hold)
    }

    /// The hold of `source` as it stands at `now`. One that ends further
    /// off than any wait the keeper sets was set before the clock went
    /// back: it is not followed, or the price would freeze for as long
    /// as the clock jumped.
    fn hold_at(&self, source: PriceSource, now: u64) -> Option<&Hold> {
        self.hold(source)
            .filter(|hold| hold.next_try <= now.saturating_add(LONGEST_WAIT_SECS))
    }

    /// The last quote of the pair, while it may still stand in for the
    /// price: [`KEEP_SECS`] either side of `now`, so a clock that went
    /// back does not keep a quote for ever.
    pub fn latest(
        &self,
        source: PriceSource,
        currency: FiatCurrency,
        now: u64,
    ) -> Option<PriceQuote> {
        self.quote(source, currency)
            .filter(|quote| quote.at.abs_diff(now) <= KEEP_SECS)
            .cloned()
    }

    /// The reading of a pair under the hold of its source.
    fn reading_under(
        &self,
        hold: &Hold,
        source: PriceSource,
        currency: FiatCurrency,
        now: u64,
    ) -> PriceReading {
        let trouble = PriceTrouble {
            kind: hold.kind,
            since: hold.since,
            next_try: hold.next_try,
            lasting: hold.failures >= FAILURES_TO_SAY || hold.kind == TroubleKind::Tor,
        };
        match self.latest(source, currency, now) {
            Some(quote) => PriceReading::Kept { quote, trouble },
            None => PriceReading::Missing { trouble },
        }
    }

    /// The answer to an ask at `now` that needs no request, or `None`
    /// when the source is to be asked. `forced`, a person asked: only
    /// a wait the source asked for holds it back.
    pub fn answer_without_asking(
        &self,
        source: PriceSource,
        currency: FiatCurrency,
        now: u64,
        forced: bool,
    ) -> Option<PriceReading> {
        if let Some(hold) = self.hold_at(source, now) {
            let waiting = now < hold.next_try && (!forced || hold.asked_by_source);
            return waiting.then(|| self.reading_under(hold, source, currency, now));
        }
        self.quote(source, currency)
            .filter(|quote| quote.at <= now && now - quote.at < REUSE_SECS)
            .map(|quote| PriceReading::Fresh {
                quote: quote.clone(),
            })
    }

    /// The source answered: its hold ends, the quote is kept.
    pub fn answered(&mut self, quote: PriceQuote) -> PriceReading {
        self.holds.retain(|(held, _)| *held != quote.source);
        self.quotes
            .retain(|kept| !(kept.source == quote.source && kept.currency == quote.currency));
        self.quotes.push(quote.clone());
        PriceReading::Fresh { quote }
    }

    /// The source failed at `now`: it is left alone for the backoff, or
    /// for the wait it named when that is longer.
    pub fn failed(
        &mut self,
        source: PriceSource,
        currency: FiatCurrency,
        failure: &Failure,
        now: u64,
    ) -> PriceReading {
        self.hold_source(source, failure, now);
        let hold = self.hold(source).expect("just held").clone();
        self.reading_under(&hold, source, currency, now)
    }

    /// Records the failure of a price ask of `source`.
    fn hold_source(&mut self, source: PriceSource, failure: &Failure, now: u64) {
        let (failures, since) = match self.hold(source) {
            Some(hold) => (hold.failures.saturating_add(1), hold.since.min(now)),
            None => (1, now),
        };
        // Tor is a matter of this machine, which no wait on a source
        // fixes: asked again at the cadence, as soon as Tor may be back.
        let backoff = match failure.kind {
            TroubleKind::Tor => REFRESH_SECS,
            _ => backoff_secs(failures),
        };
        let named = named_wait(failure);
        let hold = Hold {
            failures,
            kind: failure.kind,
            since,
            next_try: now + backoff.max(named.unwrap_or(0)),
            asked_by_source: failure.kind == TroubleKind::RateLimited || named.is_some(),
        };
        self.put_hold(source, hold);
    }

    /// A rate limit met by a price series at `now`: the price waits for
    /// it too, as long as the source asked, without counting as a failed
    /// price ask. A chart is no price on screen, and its rate limit does
    /// not make the price's trouble worth saying any sooner.
    pub fn note_wait(&mut self, source: PriceSource, failure: &Failure, now: u64) {
        let until = now + named_wait(failure).unwrap_or(0).max(REFRESH_SECS);
        let hold = match self.hold_at(source, now) {
            Some(hold) => Hold {
                next_try: hold.next_try.max(until),
                asked_by_source: true,
                ..hold.clone()
            },
            // No failed price ask yet: the next price ask that fails is
            // the first one, and is quiet.
            None => Hold {
                failures: 0,
                kind: failure.kind,
                since: now,
                next_try: until,
                asked_by_source: true,
            },
        };
        self.put_hold(source, hold);
    }

    fn put_hold(&mut self, source: PriceSource, hold: Hold) {
        self.holds.retain(|(held, _)| *held != source);
        self.holds.push((source, hold));
    }

    /// Makes every quote `secs` older: the clock moving on, for tests
    /// that run on the real one.
    #[cfg(test)]
    pub fn age_by(&mut self, secs: u64) {
        for quote in &mut self.quotes {
            quote.at = quote.at.saturating_sub(secs);
        }
    }

    /// When the source asked to be left alone until, if it did and that
    /// time is not past: a price series waits for it too.
    pub fn source_wait(&self, source: PriceSource, now: u64) -> Option<u64> {
        self.hold_at(source, now)
            .filter(|hold| hold.asked_by_source && now < hold.next_try)
            .map(|hold| hold.next_try)
    }
}

/// The wait a failure's source named, within [`MAX_RETRY_AFTER_SECS`].
fn named_wait(failure: &Failure) -> Option<u64> {
    failure
        .retry_after
        .map(|secs| secs.min(MAX_RETRY_AFTER_SECS))
}

#[cfg(test)]
mod tests {
    use super::*;

    const T0: u64 = 1_800_000_000;

    fn quote(at: u64) -> PriceQuote {
        PriceQuote {
            rate: 84_000.0,
            currency: FiatCurrency::Eur,
            source: PriceSource::Coingecko,
            at,
        }
    }

    fn failure(kind: TroubleKind, retry_after: Option<u64>) -> Failure {
        Failure {
            kind,
            retry_after,
            detail: String::new(),
        }
    }

    const CG: PriceSource = PriceSource::Coingecko;
    const EUR: FiatCurrency = FiatCurrency::Eur;

    /// The bug a user met: one failed ask after a good one, and the
    /// price was gone. Now the quote stays, with its age, and the
    /// failure is quiet.
    #[test]
    fn one_failure_keeps_the_last_quote_quietly() {
        let mut keeper = PriceKeeper::default();
        keeper.answered(quote(T0));
        let reading = keeper.failed(CG, EUR, &failure(TroubleKind::Unreachable, None), T0 + 60);
        let PriceReading::Kept {
            quote: kept,
            trouble,
        } = reading
        else {
            panic!("{reading:?}");
        };
        assert_eq!(kept, quote(T0));
        assert!(!trouble.lasting);
        assert_eq!(trouble.since, T0 + 60);
    }

    /// A second failure in a row is trouble the screens say.
    #[test]
    fn a_second_failure_in_a_row_is_said() {
        let mut keeper = PriceKeeper::default();
        let first = keeper.failed(CG, EUR, &failure(TroubleKind::Unreachable, None), T0);
        assert!(matches!(first, PriceReading::Missing { ref trouble } if !trouble.lasting));
        let second = keeper.failed(CG, EUR, &failure(TroubleKind::Unreachable, None), T0 + 60);
        let PriceReading::Missing { trouble } = second else {
            panic!("{second:?}");
        };
        assert!(trouble.lasting);
        assert_eq!(
            trouble.since, T0,
            "the trouble dates from the first failure"
        );
    }

    /// Tor missing is said at once: waiting does not bring it.
    #[test]
    fn tor_missing_is_said_at_once() {
        let mut keeper = PriceKeeper::default();
        let reading = keeper.failed(CG, EUR, &failure(TroubleKind::Tor, None), T0);
        let PriceReading::Missing { trouble } = reading else {
            panic!("{reading:?}");
        };
        assert!(trouble.lasting);
        assert_eq!(trouble.next_try, T0 + REFRESH_SECS);
    }

    /// Past [`KEEP_SECS`] the quote no longer stands in.
    #[test]
    fn a_quote_too_old_stands_in_no_longer() {
        let mut keeper = PriceKeeper::default();
        keeper.answered(quote(T0));
        let kept = keeper.failed(
            CG,
            EUR,
            &failure(TroubleKind::Unreachable, None),
            T0 + KEEP_SECS,
        );
        assert!(matches!(kept, PriceReading::Kept { .. }), "{kept:?}");
        let gone = keeper.failed(
            CG,
            EUR,
            &failure(TroubleKind::Unreachable, None),
            T0 + KEEP_SECS + 1,
        );
        assert!(matches!(gone, PriceReading::Missing { .. }), "{gone:?}");
    }

    /// The waits double from the cadence and stop at the cap.
    #[test]
    fn the_waits_double_up_to_the_cap() {
        let waits: Vec<u64> = (1..=8).map(backoff_secs).collect();
        assert_eq!(waits, [60, 120, 240, 480, 960, 1800, 1800, 1800]);
        assert_eq!(backoff_secs(u32::MAX), MAX_BACKOFF_SECS);
    }

    /// Until the wait is over, an ask is answered without a request;
    /// after it, the source is asked.
    #[test]
    fn nothing_is_asked_before_the_wait_is_over() {
        let mut keeper = PriceKeeper::default();
        keeper.failed(CG, EUR, &failure(TroubleKind::Unreachable, None), T0);
        assert!(
            keeper
                .answer_without_asking(CG, EUR, T0 + 59, false)
                .is_some()
        );
        assert!(
            keeper
                .answer_without_asking(CG, EUR, T0 + 60, false)
                .is_none()
        );
        keeper.failed(CG, EUR, &failure(TroubleKind::Unreachable, None), T0 + 60);
        assert!(
            keeper
                .answer_without_asking(CG, EUR, T0 + 179, false)
                .is_some()
        );
        assert!(
            keeper
                .answer_without_asking(CG, EUR, T0 + 180, false)
                .is_none()
        );
    }

    /// A `Retry-After` longer than the backoff is the wait, up to an
    /// hour; a "Try again" does not cut it short.
    #[test]
    fn a_named_wait_is_followed() {
        let mut keeper = PriceKeeper::default();
        let reading = keeper.failed(CG, EUR, &failure(TroubleKind::RateLimited, Some(600)), T0);
        assert_eq!(reading_trouble(&reading).next_try, T0 + 600);
        assert!(
            keeper
                .answer_without_asking(CG, EUR, T0 + 599, true)
                .is_some()
        );
        assert!(
            keeper
                .answer_without_asking(CG, EUR, T0 + 600, false)
                .is_none()
        );
        assert_eq!(keeper.source_wait(CG, T0 + 10), Some(T0 + 600));

        let mut keeper = PriceKeeper::default();
        let reading = keeper.failed(
            CG,
            EUR,
            &failure(TroubleKind::RateLimited, Some(86_400)),
            T0,
        );
        assert_eq!(
            reading_trouble(&reading).next_try,
            T0 + MAX_RETRY_AFTER_SECS
        );
    }

    /// A 429 without a named wait holds for the backoff, and a person
    /// cannot cut it short either.
    #[test]
    fn a_rate_limit_holds_even_a_try_again() {
        let mut keeper = PriceKeeper::default();
        keeper.failed(CG, EUR, &failure(TroubleKind::RateLimited, None), T0);
        assert!(
            keeper
                .answer_without_asking(CG, EUR, T0 + 5, true)
                .is_some()
        );
        assert_eq!(keeper.source_wait(CG, T0 + 5), Some(T0 + 60));
    }

    /// A source that did not answer may be tried again at once by a
    /// person: nothing asked it to wait.
    #[test]
    fn try_again_goes_out_when_nothing_asked_to_wait() {
        let mut keeper = PriceKeeper::default();
        keeper.failed(CG, EUR, &failure(TroubleKind::Unreachable, None), T0);
        assert!(
            keeper
                .answer_without_asking(CG, EUR, T0 + 5, true)
                .is_none()
        );
        assert_eq!(keeper.source_wait(CG, T0 + 5), None);
    }

    /// An answer ends the trouble: the next failure is a first one.
    #[test]
    fn an_answer_ends_the_trouble() {
        let mut keeper = PriceKeeper::default();
        keeper.failed(CG, EUR, &failure(TroubleKind::Unreachable, None), T0);
        keeper.failed(CG, EUR, &failure(TroubleKind::Unreachable, None), T0 + 60);
        keeper.answered(quote(T0 + 180));
        let reading = keeper.failed(CG, EUR, &failure(TroubleKind::Unreachable, None), T0 + 240);
        let trouble = reading_trouble(&reading);
        assert!(!trouble.lasting);
        assert_eq!(trouble.next_try, T0 + 240 + REFRESH_SECS);
    }

    /// A quote seconds old answers a second ask; after that the source
    /// is asked.
    #[test]
    fn a_quote_seconds_old_answers_again() {
        let mut keeper = PriceKeeper::default();
        keeper.answered(quote(T0));
        assert_eq!(
            keeper.answer_without_asking(CG, EUR, T0 + 29, false),
            Some(PriceReading::Fresh { quote: quote(T0) })
        );
        assert!(
            keeper
                .answer_without_asking(CG, EUR, T0 + 30, false)
                .is_none()
        );
    }

    /// The hold is the source's, the quotes the pair's: another
    /// currency from the same failing source waits too, but has no
    /// quote to stand in.
    #[test]
    fn the_hold_is_the_sources_and_the_quote_the_pairs() {
        let mut keeper = PriceKeeper::default();
        keeper.answered(quote(T0));
        keeper.failed(CG, EUR, &failure(TroubleKind::RateLimited, None), T0 + 60);
        let usd = keeper.answer_without_asking(CG, FiatCurrency::Usd, T0 + 61, false);
        assert!(matches!(usd, Some(PriceReading::Missing { .. })), "{usd:?}");
        let other = keeper.answer_without_asking(PriceSource::MempoolSpace, EUR, T0 + 61, false);
        assert_eq!(other, None, "the other source is not held");
    }

    /// A clock set back by a day neither freezes the price on a quote
    /// "from the future" nor holds the source for the day.
    #[test]
    fn a_clock_set_back_freezes_nothing() {
        let day = 86_400;
        let mut keeper = PriceKeeper::default();
        keeper.answered(quote(T0));
        assert_eq!(
            keeper.answer_without_asking(CG, EUR, T0 - day, false),
            None,
            "a quote from the future is not reused"
        );
        assert_eq!(keeper.latest(CG, EUR, T0 - day), None);

        keeper.failed(CG, EUR, &failure(TroubleKind::RateLimited, Some(600)), T0);
        assert_eq!(keeper.answer_without_asking(CG, EUR, T0 - day, true), None);
        assert_eq!(keeper.source_wait(CG, T0 - day), None);
        // Within the hold, it holds.
        assert!(
            keeper
                .answer_without_asking(CG, EUR, T0 + 5, true)
                .is_some()
        );
    }

    /// A rate limit met by a chart holds the price for the wait it
    /// named, without counting as a failed price ask: the next one that
    /// fails is still quiet.
    #[test]
    fn a_charts_rate_limit_holds_the_price_quietly() {
        let mut keeper = PriceKeeper::default();
        keeper.answered(quote(T0));
        keeper.note_wait(CG, &failure(TroubleKind::RateLimited, Some(300)), T0 + 60);
        assert_eq!(keeper.source_wait(CG, T0 + 61), Some(T0 + 360));
        let held = keeper
            .answer_without_asking(CG, EUR, T0 + 61, true)
            .expect("held");
        assert!(!reading_trouble(&held).lasting);
        assert!(matches!(held, PriceReading::Kept { .. }), "{held:?}");

        let first = keeper.failed(CG, EUR, &failure(TroubleKind::Unreachable, None), T0 + 360);
        assert!(!reading_trouble(&first).lasting, "the first price failure");

        // A wait shorter than the one in place does not shorten it.
        let mut keeper = PriceKeeper::default();
        keeper.failed(CG, EUR, &failure(TroubleKind::RateLimited, Some(600)), T0);
        keeper.note_wait(CG, &failure(TroubleKind::RateLimited, None), T0 + 10);
        assert_eq!(keeper.source_wait(CG, T0 + 10), Some(T0 + 600));
    }

    fn reading_trouble(reading: &PriceReading) -> &PriceTrouble {
        match reading {
            PriceReading::Kept { trouble, .. } | PriceReading::Missing { trouble } => trouble,
            PriceReading::Fresh { .. } => panic!("no trouble in {reading:?}"),
        }
    }
}
