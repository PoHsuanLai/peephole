//! Which program is calling: the pure half of peephole.
//!
//! This crate holds the vocabulary (ids, the facts read about a process, the caller table) and
//! the judgement over them. It does no I/O and reads no clock, environment or fixed path: the
//! `peephole` crate reads `/proc` through a pidfd and fills in [`Facts`]; [`judge`] turns facts
//! and a [`Table`] into a [`Standing`]; a method says what it accepts with [`Requirement`]s and
//! [`Standing::holds`].

mod cgroup;
mod error;
mod facts;
mod ids;
mod judge;
mod requirement;
mod standing;
mod table;

pub mod procinfo;
#[cfg(feature = "desktop")]
pub mod roles;

pub use cgroup::{CgroupPath, escape_unit, flatpak_scope_in, scope_app, unescape_unit};
pub use error::{IdError, Refused, RowFault, TableError};
pub use facts::{
    DropIns, Engine, Exe, Facts, FileTrust, Fragment, LOADER_VARIABLES, Loader, Pin, PinNeed,
    SandboxFacts, Transient, UnitFacts, Writer,
};
pub use ids::{AppKey, ExePath, ExePattern, Pid, RoleName, Uid, UnitName};
pub use judge::judge;
pub use requirement::Requirement;
pub use standing::{Proof, Standing, WhyNot};
pub use table::{NAME_MAX, Row, TABLE_BYTES_MAX, TABLE_ROWS_MAX, Table};
