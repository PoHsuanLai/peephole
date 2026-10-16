//! What was read about a process, before anything is decided from it. The prober fills these in;
//! `judge` reads them. Nothing here does I/O.

use crate::cgroup::CgroupPath;
use crate::ids::{ExePath, Pid, Uid, UnitName};
use std::path::PathBuf;

/// How firmly the process was held when its facts were read.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum Pin {
    /// The kernel handed a descriptor of the process made at connect time (`SO_PEERPIDFD`, or the
    /// bus's `ProcessFD`). The process cannot have been replaced.
    AtConnect,
    /// The process was opened by its number afterwards and the number was checked again. This
    /// closes everything except "the connecting process died and its pid was reused before we
    /// looked", a window of milliseconds that needs a wrapped pid space.
    Reopened,
}

/// What a consumer demands of the pin.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum PinNeed {
    /// Either pin.
    Any,
    /// Only a pin made at connect time.
    AtConnect,
}

impl PinNeed {
    /// Whether `pin` is firm enough.
    pub fn satisfied_by(self, pin: Pin) -> bool {
        match self {
            PinNeed::Any => true,
            PinNeed::AtConnect => pin == Pin::AtConnect,
        }
    }
}

/// Who can write to a file or directory that is not root-only.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum Writer {
    /// A user other than root owns it.
    Owner(Uid),
    /// Root owns it and its group can write.
    Group,
    /// Root owns it and everyone can write.
    Other,
}

/// Whether a file or directory could have been changed by someone other than root.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum FileTrust {
    /// Owned by root and not writable by group or others.
    RootOnly,
    /// Someone else can write it.
    Writable(Writer),
}

/// A process's image.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum Exe {
    /// The image was read. `trust` covers the file and every directory above it.
    Read {
        /// The image's path, without a `(deleted)` marker.
        path: ExePath,
        /// How far the path can be trusted.
        trust: FileTrust,
    },
    /// The image could not be read (another user's process without the right to look, a sandbox,
    /// a kernel thread), or is not a path of this file system.
    Hidden,
}

/// The engine of a sandbox, as the kernel or the runtime attests it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum Engine {
    /// A Flatpak sandbox.
    Flatpak,
    /// A Snap confinement.
    Snap,
}

/// What a process's sandbox says of it.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum SandboxFacts {
    /// No sandbox metadata.
    Native,
    /// `/proc/<pid>/root/.flatpak-info` as read.
    Flatpak {
        /// `[Application] name`.
        app: String,
        /// `[Instance] instance-id`.
        instance: String,
    },
    /// The kernel security label of a snap (`snap.<name>.<app>`).
    Snap {
        /// The label's first word.
        label: String,
    },
}

/// What the unit manager says of a unit's fragment file.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum Fragment {
    /// The file and every directory above it are root-only.
    RootOwned(PathBuf),
    /// Someone other than root can change the file or a directory above it.
    Writable(PathBuf),
    /// The unit has no fragment file.
    Missing,
}

/// What the unit manager says of a unit's drop-in files.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum DropIns {
    /// There are none.
    None,
    /// All are root-only.
    RootOwned,
    /// At least one can be changed by someone other than root.
    Writable,
}

/// Whether the unit was made at run time (`systemd-run`) rather than from a file.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum Transient {
    /// It was made at run time.
    Yes,
    /// It comes from a file.
    No,
}

/// What the unit manager says of the unit a process sits in.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UnitFacts {
    /// The unit's name.
    pub name: UnitName,
    /// The manager's `MainPID`.
    pub main_pid: Option<Pid>,
    /// The fragment file.
    pub fragment: Fragment,
    /// The drop-in files.
    pub drop_ins: DropIns,
    /// Whether the unit was made at run time.
    pub transient: Transient,
    /// The program of the first `ExecStart`.
    pub exec: Option<ExePath>,
}

/// Everything read about a pinned process.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Facts {
    /// The process.
    pub pid: Pid,
    /// Its effective user.
    pub uid: Uid,
    /// Its cgroup.
    pub cgroup: CgroupPath,
    /// Its image.
    pub exe: Exe,
    /// What its sandbox says.
    pub sandbox: SandboxFacts,
    /// What the unit manager says of its unit, when it was asked.
    pub unit: Option<UnitFacts>,
    /// How firmly it was held.
    pub pin: Pin,
}
