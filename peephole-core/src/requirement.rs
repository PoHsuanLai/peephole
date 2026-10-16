//! What a method asks of its caller, and the check ("require") that a standing meets it.

use crate::error::Refused;
use crate::facts::PinNeed;
use crate::ids::RoleName;
use crate::standing::{Proof, Standing};

/// One way to be allowed: a role, held at least at a proof level, pinned at least this firmly.
/// A method that several roles may call lists several requirements; any one is enough.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Requirement {
    /// The role the caller must hold.
    pub role: RoleName,
    /// The weakest proof accepted.
    pub at_least: Proof,
    /// The weakest pin accepted.
    pub pin: PinNeed,
}

impl Requirement {
    /// The role `role`, proved at least `at_least`, with either pin.
    pub fn new(role: RoleName, at_least: Proof) -> Requirement {
        Requirement {
            role,
            at_least,
            pin: PinNeed::Any,
        }
    }

    /// Only with feature `dev-rows`: the role `role` at any proof, `Proof::Dev` included. A
    /// consumer lists it beside its real requirement in its own debug builds, so a stand-in
    /// built in a checkout is let in; a shipped build never lists it. It also lets in the real
    /// service at any of the higher proofs, which is the point of a debug build.
    #[cfg(feature = "dev-rows")]
    pub fn dev(role: RoleName) -> Requirement {
        Requirement::new(role, Proof::Dev)
    }

    /// The same, demanding the stated pin.
    pub fn pinned(self, pin: PinNeed) -> Requirement {
        Requirement { pin, ..self }
    }

    fn met_by(&self, standing: &Standing) -> bool {
        match standing {
            Standing::Service {
                role, proof, pin, ..
            } => *role == self.role && *proof >= self.at_least && self.pin.satisfied_by(*pin),
            _ => false,
        }
    }
}

impl Standing {
    /// `Ok` with this standing when it meets at least one of `need`; otherwise the refusal: an
    /// unverified process is `Unknown`, any other is `NotAllowed`. An empty `need` refuses all.
    pub fn holds(&self, need: &[Requirement]) -> Result<&Standing, Refused> {
        if need.iter().any(|r| r.met_by(self)) {
            return Ok(self);
        }
        match self {
            Standing::Unverified { .. } => Err(Refused::Unknown),
            _ => Err(Refused::NotAllowed),
        }
    }
}
