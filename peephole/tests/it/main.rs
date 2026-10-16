//! The integration tests of peephole: one binary (it needs the `fake` feature), a module per concept.

#[cfg(feature = "dev-rows")]
mod devfile;
mod pin;
mod probe;
mod tablefile;
mod trust;
