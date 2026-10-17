//! The entry point for a unix-socket peer (the Wayland socket, turnstile's socket, keycap's).

use crate::error::PinError;
use crate::pin::{Hold, Pinned, open_pidfd};
use crate::probe::Prober;
use crate::procfs::ProcFs;
use nix::errno::Errno;
use nix::sys::socket::{getsockopt, sockopt::PeerPidfd};
use peephole_core::{Pid, Pin, Standing, Table, Uid, WhyNot};
use rustix::event::{PollFd, PollFlags, Timespec, poll};
use rustix::net::UCred;
use rustix::net::sockopt::socket_peercred;
use std::os::fd::{AsFd, OwnedFd};

impl Pinned {
    /// Holds the process on the other end of the connected unix socket `stream`.
    ///
    /// The pin is `SO_PEERPIDFD` (Linux 6.5): a descriptor of the process the kernel made at
    /// connect time, giving [`Pin::AtConnect`]; a peer that has exited since is
    /// [`PinError::PeerGone`], never another process that took its pid. On a kernel without the
    /// option the pin is [`Pin::Reopened`]: the pid from `SO_PEERCRED`, a pidfd opened at once,
    /// and `SO_PEERCRED` read again to check it still names that process and user. That closes
    /// everything except "the connecting process died and its pid was reused before we looked".
    pub fn of_stream(stream: &impl AsFd) -> Result<Pinned, PinError> {
        let first = socket_peercred(stream).map_err(|e| PinError::Credentials(e.into()))?;
        let pid = u32::try_from(first.pid.as_raw_pid())
            .ok()
            .and_then(Pid::new)
            .ok_or(PinError::BadPid)?;
        let uid = Uid::new(first.uid.as_raw());
        match getsockopt(stream, PeerPidfd) {
            Ok(fd) => at_connect(fd, pid, uid),
            Err(Errno::ESRCH) => Err(PinError::PeerGone),
            Err(_) => reopened(stream, &first, pid, uid),
        }
    }
}

/// The kernel's own pidfd of the peer: alive now, and of the pid `SO_PEERCRED` states.
fn at_connect(fd: OwnedFd, pid: Pid, uid: Uid) -> Result<Pinned, PinError> {
    let mut fds = [PollFd::new(&fd, PollFlags::IN)];
    match poll(&mut fds, Some(&Timespec::default())) {
        Ok(0) => Pinned::from_fd(fd, pid, uid),
        _ => Err(PinError::PeerGone),
    }
}

/// A pidfd opened by the pid, kept only if the socket's credentials did not change meanwhile.
fn reopened(stream: &impl AsFd, first: &UCred, pid: Pid, uid: Uid) -> Result<Pinned, PinError> {
    let fd = open_pidfd(pid)?;
    let second = socket_peercred(stream).map_err(|e| PinError::Credentials(e.into()))?;
    if second != *first {
        return Err(PinError::Mismatch);
    }
    Ok(Pinned {
        pid,
        uid,
        pin: Pin::Reopened,
        hold: Hold::Fd(fd),
    })
}

impl<P: ProcFs> Prober<P> {
    /// The standing of the process on the other end of `stream`: held, probed and judged. A peer
    /// that cannot be held is `Unverified`.
    pub fn stand_stream(&self, stream: &impl AsFd, table: &Table) -> Standing {
        match Pinned::of_stream(stream) {
            Ok(who) => self.stand(&who, table),
            Err(PinError::PeerGone) => Standing::Unverified {
                exe_name: None,
                scope_app: None,
                why: WhyNot::PeerGone,
            },
            Err(_) => Standing::Unverified {
                exe_name: None,
                scope_app: None,
                why: WhyNot::Unreadable,
            },
        }
    }
}
