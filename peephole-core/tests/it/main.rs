//! The integration tests of peephole-core: one binary, a module per concept.

mod cgroup;
mod common;
mod ids;
mod judge;
mod procinfo;
mod requirement;
#[cfg(feature = "desktop")]
mod roles;
mod table;
