//! The errors of the I/O crate.

use peephole_core::WhyNot;
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

impl PinError {
    /// Why a peer that could not be held is unknown: gone, or unreadable. A new variant fails as
    /// unreadable until it is given its own reason.
    pub fn why_not(&self) -> WhyNot {
        match self {
            PinError::PeerGone => WhyNot::PeerGone,
            _ => WhyNot::Unreadable,
        }
    }
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

impl ProbeError {
    /// Why a process that could not be probed is unknown: gone, or unreadable. A new variant
    /// fails as unreadable until it is given its own reason.
    pub fn why_not(&self) -> WhyNot {
        match self {
            ProbeError::PeerGone => WhyNot::PeerGone,
            _ => WhyNot::Unreadable,
        }
    }
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
    /// Only with feature `dev-rows`: a developer rows file that is a link or not a plain file.
    #[cfg(feature = "dev-rows")]
    #[error("{path}: not a plain file")]
    NotAFile {
        /// The file.
        path: String,
    },
    /// Only with feature `dev-rows`: a developer rows file that is not the person's own, or that
    /// group or others can write.
    #[cfg(feature = "dev-rows")]
    #[error("{path}: not the person's own file, or others can write it")]
    NotTheirs {
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
