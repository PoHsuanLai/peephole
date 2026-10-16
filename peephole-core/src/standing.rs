//! The result of judging a process: who it is, as far as it can be shown.

use crate::facts::{Engine, Pin};
use crate::ids::{AppKey, ExePath, RoleName};

/// How much was shown about a service. Ordered: each level includes the one below it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[non_exhaustive]
pub enum Proof {
    /// Pinned, uid known, the cgroup names the unit. A same-user process can move itself into a
    /// delegated cgroup, so this is a speed bump, never a boundary. It is all that can be had
    /// when the image cannot be read.
    Cgroup,
    /// The image was read, it is root-owned all the way up and the row's `exe` patterns match it.
    Exe,
    /// `Exe`, and the unit is real: the manager says it is this process's unit, from a root-owned
    /// fragment with no user-writable drop-in, not transient, and running this program.
    Full,
}

/// Why nothing can be remembered about a process.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum WhyNot {
    /// The process was gone before its facts were read.
    PeerGone,
    /// The image, or a directory above it, can be written by someone other than root.
    ImageWritable,
    /// The image could not be read and no row names the cgroup.
    ImageHidden,
    /// A sandbox's metadata and its cgroup disagree, or the metadata is unusable.
    SandboxDisagrees,
    /// The process's facts could not be read.
    Unreadable,
}

/// Who a process is.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum Standing {
    /// A table row matched on every check its proof level needs.
    Service {
        /// The row's app.
        app: AppKey,
        /// The row's role.
        role: RoleName,
        /// What was shown.
        proof: Proof,
        /// How firmly the process was held.
        pin: Pin,
    },
    /// A sandbox attested by the kernel or the runtime (never by a name).
    Sandboxed {
        /// The sandbox's application.
        app: AppKey,
        /// The sandbox engine.
        engine: Engine,
    },
    /// A root-owned image that is in no row. `scope_app` is the launcher's scope name: a claim.
    Program {
        /// The image.
        exe: ExePath,
        /// The app the launcher's scope name claims, for display and grouping only.
        scope_app: Option<AppKey>,
    },
    /// Nothing that can be remembered: a user-writable image, a hidden image, a peer that left.
    Unverified {
        /// The image's file name, when it was read.
        exe_name: Option<String>,
        /// Why nothing is known.
        why: WhyNot,
    },
}
