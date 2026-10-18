//! A process held by a pidfd. Everything read from `/proc/<pid>` afterwards belongs to the held
//! process: a process cannot be replaced while it is alive, and [`Pinned::alive`] says whether it
//! still is.

use crate::error::PinError;
use peephole_core::procinfo::{parse_fdinfo_pid, parse_status_euid};
use peephole_core::{Pid, Pin, Uid};
use rustix::event::{PollFd, PollFlags, Timespec, poll};
use rustix::io::Errno;
use rustix::process::{PidfdFlags, pidfd_open};
use std::io::{self, Read};
use std::os::fd::{AsFd, AsRawFd, BorrowedFd, OwnedFd};

/// The most of a `/proc` status or fdinfo file read: the real ones are a few kilobytes.
const PROC_TEXT_CAP: u64 = 64 * 1024;

/// Whether a held process is still running.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Alive {
    /// It has not exited.
    Yes,
    /// It has exited (or the question could not be asked, which is treated the same).
    Gone,
}

#[derive(Debug)]
pub(crate) enum Hold {
    Fd(OwnedFd),
    /// A test's claim that a process exists; never made by a shipped binary.
    #[cfg(feature = "fake")]
    Fixed(Alive),
}

/// A process held by a pidfd, with its effective user and how firmly it was held.
#[derive(Debug)]
pub struct Pinned {
    pub(crate) pid: Pid,
    pub(crate) uid: Uid,
    pub(crate) pin: Pin,
    pub(crate) hold: Hold,
}

fn open_error(error: Errno) -> PinError {
    if error == Errno::SRCH {
        PinError::PeerGone
    } else {
        PinError::Open(error.into())
    }
}

fn proc_text(path: &str) -> io::Result<String> {
    let mut text = String::new();
    std::fs::File::open(path)?
        .take(PROC_TEXT_CAP)
        .read_to_string(&mut text)?;
    Ok(text)
}

pub(crate) fn open_pidfd(pid: Pid) -> Result<OwnedFd, PinError> {
    let raw = i32::try_from(pid.get())
        .ok()
        .and_then(rustix::process::Pid::from_raw)
        .ok_or(PinError::BadPid)?;
    pidfd_open(raw, PidfdFlags::empty()).map_err(open_error)
}

impl Pinned {
    /// Holds process `pid`, whose effective user the caller already knows (the bus states it):
    /// the pidfd is opened by number, so the pin is [`Pin::Reopened`] and nothing firmer.
    pub fn from_pid_with_uid(pid: Pid, uid: Uid) -> Result<Pinned, PinError> {
        let fd = open_pidfd(pid)?;
        Ok(Pinned {
            pid,
            uid,
            pin: Pin::Reopened,
            hold: Hold::Fd(fd),
        })
    }

    /// Holds process `pid` and reads its effective user from `/proc/<pid>/status` after the
    /// pidfd is open. A process that exits meanwhile is [`PinError::PeerGone`]. The pin is
    /// [`Pin::Reopened`].
    pub fn from_pid(pid: Pid) -> Result<Pinned, PinError> {
        let fd = open_pidfd(pid)?;
        let status = proc_text(&format!("/proc/{pid}/status")).map_err(PinError::Proc)?;
        let uid = parse_status_euid(&status).ok_or(PinError::Mismatch)?;
        let held = Pinned {
            pid,
            uid,
            pin: Pin::Reopened,
            hold: Hold::Fd(fd),
        };
        match held.alive() {
            Alive::Yes => Ok(held),
            Alive::Gone => Err(PinError::PeerGone),
        }
    }

    /// Holds the process behind `fd`, a pidfd the kernel or the bus made at connect time. The
    /// descriptor must be a pidfd of `pid` (its fdinfo says so), or it is [`PinError::Mismatch`].
    pub fn from_fd(fd: OwnedFd, pid: Pid, uid: Uid) -> Result<Pinned, PinError> {
        let info =
            proc_text(&format!("/proc/self/fdinfo/{}", fd.as_raw_fd())).map_err(PinError::Proc)?;
        if parse_fdinfo_pid(&info) != Some(pid) {
            return Err(PinError::Mismatch);
        }
        Ok(Pinned {
            pid,
            uid,
            pin: Pin::AtConnect,
            hold: Hold::Fd(fd),
        })
    }

    /// The process.
    pub fn pid(&self) -> Pid {
        self.pid
    }

    /// Its effective user.
    pub fn uid(&self) -> Uid {
        self.uid
    }

    /// How firmly it was held.
    pub fn pin(&self) -> Pin {
        self.pin
    }

    /// The pidfd that holds the process, for a caller that acts on the same process later (a
    /// signal through `pidfd_send_signal`, a wait). `None` only for a test's claim (`fake`).
    pub fn pidfd(&self) -> Option<BorrowedFd<'_>> {
        match &self.hold {
            Hold::Fd(fd) => Some(fd.as_fd()),
            #[cfg(feature = "fake")]
            Hold::Fixed(_) => None,
        }
    }

    /// Whether the process is still running: a pidfd turns readable when its process exits.
    /// Check this after reading its facts; a process that is gone makes them worth nothing.
    pub fn alive(&self) -> Alive {
        match &self.hold {
            Hold::Fd(fd) => {
                let mut fds = [PollFd::new(fd, PollFlags::IN)];
                match poll(&mut fds, Some(&Timespec::default())) {
                    Ok(0) => Alive::Yes,
                    _ => Alive::Gone,
                }
            }
            #[cfg(feature = "fake")]
            Hold::Fixed(alive) => *alive,
        }
    }
}
