//! Exercise 9: a hedged race with tokio (futures, select!, cancellation).
//! Modelled on `hedged_race` in myotis-net/src/el/reader.rs.

use std::future::Future;
use std::time::Duration;

use futures::stream::{FuturesUnordered, StreamExt};

/// Try up to `attempts` peers. Start attempt 0 at once. Start the NEXT attempt
/// (alongside the ones still running, never instead of them) whenever `delay`
/// passes without a result, and immediately whenever an attempt fails.
/// Return the first `Ok` as `(index, value)`, or `None` once every attempt
/// has failed. Returning drops the attempts still in flight: that is how
/// the losers are cancelled.
pub async fn hedged<T, F, Fut>(attempts: usize, delay: Duration, mut make: F) -> Option<(usize, T)>
where
    F: FnMut(usize) -> Fut,
    Fut: Future<Output = Result<T, String>>,
{
    todo!("your code here")
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::time::Instant;

    #[derive(Clone)]
    enum Peer {
        Answers(Duration, u32),
        FailsNow,
    }

    async fn race(plan: Vec<Peer>) -> Option<(usize, u32)> {
        let n = plan.len();
        hedged(n, Duration::from_secs(3), |i| {
            let p = plan[i].clone(); // each future owns its copy
            async move {
                match p {
                    Peer::Answers(d, v) => {
                        tokio::time::sleep(d).await;
                        Ok(v)
                    }
                    Peer::FailsNow => Err("peer failed".to_string()),
                }
            }
        })
        .await
    }

    #[tokio::test(start_paused = true)]
    async fn slow_peer_still_wins_when_others_fail() {
        let t = Instant::now();
        let out = race(vec![Peer::Answers(Duration::from_secs(4), 7), Peer::FailsNow, Peer::FailsNow]).await;
        assert_eq!(out, Some((0, 7)));
        assert_eq!(t.elapsed(), Duration::from_secs(4));
    }

    #[tokio::test(start_paused = true)]
    async fn silent_peer_does_not_hold_the_read() {
        let t = Instant::now();
        let out = race(vec![Peer::Answers(Duration::from_secs(600), 1), Peer::Answers(Duration::from_millis(50), 2)]).await;
        assert_eq!(out, Some((1, 2)));
        assert_eq!(t.elapsed(), Duration::from_millis(3050));
    }

    #[tokio::test(start_paused = true)]
    async fn all_fail() {
        assert_eq!(race(vec![Peer::FailsNow, Peer::FailsNow]).await, None);
    }
}
