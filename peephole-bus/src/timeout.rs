//! The bound on every bus call.

use std::future::{Future, poll_fn};
use std::pin::{Pin, pin};
use std::task::Poll;
use std::time::Duration;

/// How long any one call to the bus or the unit manager may take before the answer is "no": a
/// peer that does not answer must not wedge the one asking.
pub const BUS_TIMEOUT: Duration = Duration::from_secs(2);

/// The call did not finish within [`BUS_TIMEOUT`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct TimedOut;

/// Runs `work` for at most [`BUS_TIMEOUT`]; the call is dropped, and so cancelled at its next
/// await, when the time passes. The timer is runtime-free, so this works under any executor.
pub(crate) async fn bounded<T>(work: impl Future<Output = T>) -> Result<T, TimedOut> {
    let mut work = pin!(work);
    let mut timer = futures_timer::Delay::new(BUS_TIMEOUT);
    poll_fn(move |cx| {
        if let Poll::Ready(done) = work.as_mut().poll(cx) {
            return Poll::Ready(Ok(done));
        }
        match Pin::new(&mut timer).poll(cx) {
            Poll::Ready(()) => Poll::Ready(Err(TimedOut)),
            Poll::Pending => Poll::Pending,
        }
    })
    .await
}
