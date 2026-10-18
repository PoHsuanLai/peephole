//! Where the blocking part of a probe runs. A probe is a handful of small `/proc` reads; a caller
//! on a busy async executor moves it to a blocking pool by choosing [`Offload::Tokio`].

/// The blocking work could not be run (the runtime shut down, or the work panicked).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Cancelled;

/// Where a closure runs. The set is closed by the crate's features.
#[derive(Debug, Clone, Copy, Default)]
#[non_exhaustive]
pub enum Offload {
    /// On the polling thread: right for a program that is mostly idle.
    #[default]
    Inline,
    /// On tokio's blocking pool.
    #[cfg(feature = "tokio")]
    Tokio,
}

impl Offload {
    /// Runs `work` and yields its result.
    pub(crate) async fn run<T, F>(self, work: F) -> Result<T, Cancelled>
    where
        F: FnOnce() -> T + Send + 'static,
        T: Send + 'static,
    {
        match self {
            Offload::Inline => Ok(work()),
            #[cfg(feature = "tokio")]
            Offload::Tokio => tokio::task::spawn_blocking(work)
                .await
                .map_err(|_| Cancelled),
        }
    }
}
