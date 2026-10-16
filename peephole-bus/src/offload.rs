//! Where the blocking part of a probe runs. A probe is a handful of small `/proc` reads; a caller
//! on a busy async executor moves it to a blocking pool by choosing [`Tokio`].

use std::future::Future;

/// The blocking work could not be run (the runtime shut down, or the work panicked).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Cancelled;

/// Runs a closure somewhere and returns its result.
pub trait Offload: Send + Sync {
    /// Runs `work` and yields its result.
    fn run<T, F>(&self, work: F) -> impl Future<Output = Result<T, Cancelled>> + Send
    where
        F: FnOnce() -> T + Send + 'static,
        T: Send + 'static;
}

/// Runs the work on the polling thread: right for a program that is mostly idle.
#[derive(Debug, Clone, Copy, Default)]
pub struct Inline;

impl Offload for Inline {
    async fn run<T, F>(&self, work: F) -> Result<T, Cancelled>
    where
        F: FnOnce() -> T + Send + 'static,
        T: Send + 'static,
    {
        Ok(work())
    }
}

/// Runs the work on tokio's blocking pool.
#[cfg(feature = "tokio")]
#[derive(Debug, Clone, Copy, Default)]
pub struct Tokio;

#[cfg(feature = "tokio")]
impl Offload for Tokio {
    async fn run<T, F>(&self, work: F) -> Result<T, Cancelled>
    where
        F: FnOnce() -> T + Send + 'static,
        T: Send + 'static,
    {
        tokio::task::spawn_blocking(work)
            .await
            .map_err(|_| Cancelled)
    }
}
