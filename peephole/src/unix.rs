//! The entry point for a unix-socket peer (the Wayland socket, turnstile's socket, keycap's).

use crate::error::PinError;
use crate::pin::{Hold, Pinned, open_pidfd};
use crate::probe::Prober;
use crate::procfs::ProcFs;
use peephole_core::{Pid, Pin, Standing, Table, Uid, WhyNot};
use rustix::net::sockopt::socket_peercred;
use std::os::fd::AsFd;

impl Pinned {
    /// Holds the process on the other end of the connected unix socket `stream`.
    ///
    /// The ideal pin is `SO_PEERPIDFD` (Linux 6.5): a descriptor of the process made at connect
    /// time, giving [`Pin::AtConnect`]. rustix 1.1 has no safe wrapper for it, and this crate
    /// forbids `unsafe`, so the pin made here is [`Pin::Reopened`]: the pid from `SO_PEERCRED`,
    /// a pidfd opened at once, and `SO_PEERCRED` read again to check it still names that process
    /// and user. That closes everything except "the connecting process died and its pid was
    /// reused before we looked". [`Pinned::from_fd`] makes an `AtConnect` pin from a descriptor
    /// the caller already holds.
    pub fn of_stream(stream: &impl AsFd) -> Result<Pinned, PinError> {
        let first = socket_peercred(stream).map_err(|e| PinError::Credentials(e.into()))?;
        let pid = u32::try_from(first.pid.as_raw_pid())
            .ok()
            .and_then(Pid::new)
            .ok_or(PinError::BadPid)?;
        let fd = open_pidfd(pid)?;
        let second = socket_peercred(stream).map_err(|e| PinError::Credentials(e.into()))?;
        if second != first {
            return Err(PinError::Mismatch);
        }
        let uid = Uid::new(first.uid.as_raw());
        Ok(Pinned {
            pid,
            uid,
            pin: Pin::Reopened,
            hold: Hold::Fd(fd),
        })
    }
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
