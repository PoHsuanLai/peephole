//! The errors of the I/O crate.

use std::io;

/// A process that could not be held.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum PinError {
    /// The process is gone.
    #[error("the process has exited")]
    PeerGone,
    /// The peer's credentials could not be read from the socket.
    #[error("the socket's peer could not be read")]
    Credentials(#[source] io::Error),
    /// The kernel refused to hold the process.
    #[error("the process could not be held")]
    Open(#[source] io::Error),
    /// The process number is zero or out of range.
    #[error("not a process number")]
    BadPid,
    /// The peer's number or user changed between two looks, or a descriptor is not the
    /// process it was offered for.
    #[error("the process is not the one that was offered")]
    Mismatch,
    /// A file about the process could not be read.
    #[error("the process's files could not be read")]
    Proc(#[source] io::Error),
}

/// The facts about a process that could not be read.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum ProbeError {
    /// The process left before or while its facts were read.
    #[error("the process has exited")]
    PeerGone,
    /// A file could not be read.
    #[error("{what} could not be read")]
    Unreadable {
        /// Which fact.
        what: &'static str,
        /// The cause.
        #[source]
        source: io::Error,
    },
    /// A file does not say what a file of its kind says, or is over a limit.
    #[error("{what} is malformed")]
    Malformed {
        /// Which fact.
        what: &'static str,
    },
}

/// The caller table files that could not be loaded.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum LoadError {
    /// A file could not be read.
    #[error("{path}: could not be read")]
    Unreadable {
        /// The file.
        path: String,
        /// The cause.
        #[source]
        source: io::Error,
    },
    /// A file is not root-only, so nothing it says is believed.
    #[error("{path}: not owned by root alone")]
    NotRootOnly {
        /// The file.
        path: String,
    },
    /// A file is not a table.
    #[error("{path}: {source}")]
    Table {
        /// The file.
        path: String,
        /// What is wrong with it.
        #[source]
        source: peephole_core::TableError,
    },
}
