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

/// The variables that make a process load code the image does not name: the dynamic loader's,
/// and the search paths of the libraries a desktop program opens (GLib, GTK, GStreamer, Mesa,
/// EGL, GBM, VA-API, Vulkan). `systemctl --user set-environment` and
/// `~/.config/environment.d` put them in the environment of every user unit, so a root-owned
/// image is fixed but the code it loads is not. A unit proves `Full` only when its
/// `UnsetEnvironment=` holds every one of them.
///
/// systemd.exec(5) applies `UnsetEnvironment=` last, after the manager's environment,
/// `Environment=` and `EnvironmentFile=`, so nothing set anywhere else survives it. A unit
/// should carry exactly this line:
///
/// ```text
/// UnsetEnvironment=LD_PRELOAD LD_LIBRARY_PATH LD_AUDIT GCONV_PATH GIO_EXTRA_MODULES GTK_MODULES GTK_PATH GST_PLUGIN_PATH GST_PLUGIN_SYSTEM_PATH LIBGL_DRIVERS_PATH MESA_LOADER_DRIVER_OVERRIDE __EGL_VENDOR_LIBRARY_DIRS __EGL_VENDOR_LIBRARY_FILENAMES GBM_BACKENDS_PATH LIBVA_DRIVERS_PATH VK_ICD_FILENAMES VK_DRIVER_FILES VK_ADD_DRIVER_FILES VK_LAYER_PATH VK_ADD_LAYER_PATH VK_INSTANCE_LAYERS VK_LOADER_LAYERS_ENABLE
/// ```
pub const LOADER_VARIABLES: [&str; 22] = [
    "LD_PRELOAD",
    "LD_LIBRARY_PATH",
    "LD_AUDIT",
    "GCONV_PATH",
    "GIO_EXTRA_MODULES",
    "GTK_MODULES",
    "GTK_PATH",
    "GST_PLUGIN_PATH",
    "GST_PLUGIN_SYSTEM_PATH",
    "LIBGL_DRIVERS_PATH",
    "MESA_LOADER_DRIVER_OVERRIDE",
    "__EGL_VENDOR_LIBRARY_DIRS",
    "__EGL_VENDOR_LIBRARY_FILENAMES",
    "GBM_BACKENDS_PATH",
    "LIBVA_DRIVERS_PATH",
    "VK_ICD_FILENAMES",
    "VK_DRIVER_FILES",
    "VK_ADD_DRIVER_FILES",
    "VK_LAYER_PATH",
    "VK_ADD_LAYER_PATH",
    "VK_INSTANCE_LAYERS",
    "VK_LOADER_LAYERS_ENABLE",
];

/// Whether a unit's `UnsetEnvironment=` removes every name of [`LOADER_VARIABLES`].
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum Loader {
    /// Every loader variable is unset for the unit.
    Cleared,
    /// These loader variables are not unset (all of them when the list could not be read).
    Kept(Vec<String>),
}

impl Loader {
    /// What a unit whose `UnsetEnvironment` is `unset` does about the loader variables. An entry
    /// of the form `NAME=value` unsets only that exact assignment, so it does not count.
    pub fn from_unset(unset: &[String]) -> Loader {
        let missing: Vec<String> = LOADER_VARIABLES
            .iter()
            .filter(|name| !unset.iter().any(|entry| entry == *name))
            .map(|name| (*name).to_owned())
            .collect();
        if missing.is_empty() {
            Loader::Cleared
        } else {
            Loader::Kept(missing)
        }
    }

    /// What a failed read of `UnsetEnvironment` counts as: nothing is unset.
    pub fn unknown() -> Loader {
        Loader::from_unset(&[])
    }

    /// The variables not unset, as one line for a log or a message; `None` when cleared.
    pub fn reason(&self) -> Option<String> {
        match self {
            Loader::Cleared => None,
            Loader::Kept(names) => Some(format!(
                "UnsetEnvironment lacks the loader variables {}",
                names.join(" ")
            )),
        }
    }
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
    /// Whether the unit unsets the loader variables.
    pub loader: Loader,
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
