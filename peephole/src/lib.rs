//! Which program is calling: the I/O half of peephole.
//!
//! [`Pinned`] holds a process by pidfd; [`Prober`] reads what `/proc` says of it through a
//! [`ProcFs`] (the real one, or a fixture tree under feature `fake`) and [`peephole_core::judge`] decides.
//! The crate is synchronous: a probe is a few small reads, and an async caller wraps it in
//! its own blocking pool (`peephole-bus` offers the seam). It contains no `unsafe`; the pidfd
//! comes from rustix.

#[cfg(feature = "dev-rows")]
mod devfile;
mod error;
mod pin;
mod probe;
mod procfs;
mod tablefile;
mod unix;
mod walk;

#[cfg(feature = "fake")]
pub mod fake;
#[cfg(feature = "fake")]
mod fixture;

#[cfg(feature = "dev-rows")]
pub use devfile::{NodeInfo, NodeKind};
pub use error::{LoadError, PinError, ProbeError};
#[cfg(feature = "fake")]
pub use fixture::{FixtureImage, FixtureProc, FixtureProcess};
pub use peephole_core;
pub use pin::{Alive, Pinned};
pub use probe::{PROBE_MAX_READS, PROBE_READ_CAP, Prober};
pub use procfs::{ProcFs, RealProc, trust_of_mode};
pub use tablefile::{DROP_IN_FILES_MAX, TABLE_FILE_CAP, TableFiles};
pub use walk::{WALK_MAX, dirs_trust, weaker};
