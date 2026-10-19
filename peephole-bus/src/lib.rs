//! Which program is calling, over a bus: the adapter half of peephole.
//!
//! [`BusPeers`] turns a message's sender into a [`peephole::Standing`]: it asks the bus for the
//! sender's process (the bus daemon's pidfd when it offers one), holds it, reads `/proc`
//! through [`peephole::Prober`], asks the systemd manager about the unit when the table names
//! one, and judges. A method then calls [`BusPeers::require`] with the roles it accepts.
//!
//! Every call to the bus has a two-second bound ([`BUS_TIMEOUT`]) and fails closed. zbus runs on
//! its own executor by default (feature `async-io`); a tokio program enables `tokio` instead.

mod attest;
mod error;
mod manager;
mod offload;
mod owner;
mod timeout;
mod who;

pub use error::{UnitError, WhoError, access_denied};
pub use manager::{DROP_INS_MAX, ManagerLink, SYSTEMD, SYSTEMD_MANAGER, SYSTEMD_PATH, UnitSource};
pub use offload::{Cancelled, Offload};
pub use owner::OwnerWatch;
pub use peephole;
pub use peephole_core;
pub use timeout::BUS_TIMEOUT;
pub use who::{BusPeers, ManagerCheck};
