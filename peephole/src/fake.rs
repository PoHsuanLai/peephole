//! Test seams, behind the `fake` feature. A shipped binary never enables this module: the desktop
//! gate greps `cargo tree -e features` for it, as it does for `debug-inject`.

use crate::pin::{Alive, Hold, Pinned};
use peephole_core::{AppKey, ExePath, Pid, Pin, Proof, RoleName, Standing, Uid, WhyNot};

impl Pinned {
    /// A process that is only a claim: no pidfd stands behind it, it is alive until the test says
    /// otherwise. For tests of code that takes a [`Pinned`]; the probe still reads whatever
    /// file-system view it is given for that pid.
    pub fn introduced(pid: Pid, uid: Uid, pin: Pin) -> Pinned {
        Pinned {
            pid,
            uid,
            pin,
            hold: Hold::Fixed(Alive::Yes),
        }
    }

    /// As [`Pinned::introduced`], for a process that has already exited.
    pub fn introduced_gone(pid: Pid, uid: Uid, pin: Pin) -> Pinned {
        Pinned {
            pid,
            uid,
            pin,
            hold: Hold::Fixed(Alive::Gone),
        }
    }
}

/// A service standing, as if a table row had matched. `None` when `app` or `role` is not valid.
pub fn introduced_service(app: &str, role: &str, proof: Proof, pin: Pin) -> Option<Standing> {
    Some(Standing::Service {
        app: AppKey::new(app).ok()?,
        role: RoleName::new(role).ok()?,
        proof,
        pin,
    })
}

/// A program standing for the image `path`. `None` when `path` is not a valid image path.
pub fn introduced_program(path: &str) -> Option<Standing> {
    Some(Standing::Program {
        exe: ExePath::new(path).ok()?,
        scope_app: None,
    })
}

/// An unverified standing.
pub fn introduced_unverified(why: WhyNot) -> Standing {
    Standing::Unverified {
        exe_name: None,
        scope_app: None,
        why,
    }
}
