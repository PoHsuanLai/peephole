//! Who is the sender of a bus message: the pinned process behind its connection, its unit as the
//! manager states it, and the judgement against the table.

use crate::error::{WhoError, access_denied};
use crate::manager::{ManagerLink, SYSTEMD, UnitSource};
use crate::offload::{Inline, Offload};
use crate::timeout::bounded;
use peephole::{Alive, Pinned, ProbeError, Prober, ProcFs, RealProc};
use peephole_core::procinfo::parse_security_label;
use peephole_core::{
    Facts, Pid, Pin, Proof, Refused, Requirement, SandboxFacts, Standing, Table, Uid, UnitFacts,
    UnitName, WhyNot, judge,
};
use std::os::fd::AsFd;
use std::sync::Arc;
use zbus::Connection;
use zbus::fdo::{self, ConnectionCredentials, DBusProxy};
use zbus::names::BusName;

/// How the unit manager's own identity is checked before its answers about units are believed.
#[derive(Debug, Clone)]
pub enum ManagerCheck {
    /// The owner of the manager's bus name must hold this requirement (the desktop uses the
    /// `manager` role at `Exe`: the system's `systemd` image, root-owned). A manager that fails
    /// it is not asked, and no caller reaches `Full`.
    Verified(Requirement),
    /// The manager is taken as it is. For a private test bus with a stand-in manager; never for
    /// the person's real bus.
    Unchecked,
}

/// Whether the unit manager is asked while a sender is identified.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum UnitUse {
    Ask,
    Skip,
}

/// A looked-at sender: its held process and what was read of it, or why nothing was.
struct Observed {
    held: Arc<Pinned>,
    facts: Result<Facts, WhyNot>,
}

/// Identifies bus senders. Cheap to share by reference; all methods take `&self`.
#[derive(Debug)]
pub struct BusPeers<P = RealProc, O = Inline, U = ManagerLink<P>> {
    pub(crate) connection: Connection,
    prober: Arc<Prober<P>>,
    table: Arc<Table>,
    units: U,
    offload: O,
    manager: ManagerCheck,
    #[cfg(feature = "fake")]
    introduced: std::sync::Mutex<std::collections::HashMap<String, Standing>>,
}

impl BusPeers {
    /// Identifies senders on `connection` by reading the system's `/proc` and asking the unit
    /// manager on the same bus, judging against `table`.
    pub fn new(connection: Connection, table: Table, manager: ManagerCheck) -> BusPeers {
        BusPeers::with_proc(connection, table, manager, RealProc::system())
    }
}

impl<P: ProcFs + Clone + 'static> BusPeers<P, Inline, ManagerLink<P>> {
    /// As [`BusPeers::new`], reading `fs` instead of the system's `/proc` (a fixture tree in tests).
    pub fn with_proc(connection: Connection, table: Table, manager: ManagerCheck, fs: P) -> Self {
        let units = ManagerLink::new(connection.clone(), fs.clone());
        BusPeers {
            connection,
            prober: Arc::new(Prober::new(fs)),
            table: Arc::new(table),
            units,
            offload: Inline,
            manager,
            #[cfg(feature = "fake")]
            introduced: Default::default(),
        }
    }
}

impl<P, O, U> BusPeers<P, O, U> {
    /// The same, running the blocking probe through `offload`.
    pub fn with_offload<O2: Offload>(self, offload: O2) -> BusPeers<P, O2, U> {
        BusPeers {
            connection: self.connection,
            prober: self.prober,
            table: self.table,
            units: self.units,
            offload,
            manager: self.manager,
            #[cfg(feature = "fake")]
            introduced: self.introduced,
        }
    }

    /// The same, taking unit facts from `units` instead of the manager on the bus.
    pub fn with_units<U2: UnitSource>(self, units: U2) -> BusPeers<P, O, U2> {
        BusPeers {
            connection: self.connection,
            prober: self.prober,
            table: self.table,
            units,
            offload: self.offload,
            manager: self.manager,
            #[cfg(feature = "fake")]
            introduced: self.introduced,
        }
    }

    #[cfg(feature = "fake")]
    fn introduced_for(&self, sender: &str) -> Option<Standing> {
        self.introduced
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .get(sender)
            .cloned()
    }

    #[cfg(not(feature = "fake"))]
    fn introduced_for(&self, _sender: &str) -> Option<Standing> {
        None
    }

    /// Makes `sender` (a unique name) stand as `standing` without looking at it. For tests.
    #[cfg(feature = "fake")]
    pub fn introduce(&self, sender: &str, standing: Standing) {
        self.introduced
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .insert(sender.to_owned(), standing);
    }
}

fn unverified(why: WhyNot) -> Standing {
    Standing::Unverified {
        exe_name: None,
        scope_app: None,
        why,
    }
}

impl<P: ProcFs + 'static, O: Offload, U: UnitSource> BusPeers<P, O, U> {
    /// Who the sender is: its pin, the manager's facts about its unit when a row names one, and
    /// the judgement. Every bus call is bounded; any failure to identify is an error, and a caller
    /// treats an error as an unknown peer.
    pub async fn who(&self, sender: &str) -> Result<Standing, WhoError> {
        self.standing(sender, UnitUse::Ask).await
    }

    /// The check a method makes: `Ok` with the sender's standing when it meets one of `need`.
    /// A message with no sender, an unidentifiable sender and a sender that holds nothing asked
    /// for are all refusals; the unit manager is asked only if a requirement wants `Full`.
    pub async fn require(
        &self,
        sender: Option<&str>,
        need: &[Requirement],
    ) -> Result<Standing, Refused> {
        let sender = sender.ok_or(Refused::NoSender)?;
        let units = match need.iter().any(|r| r.at_least == Proof::Full) {
            true => UnitUse::Ask,
            false => UnitUse::Skip,
        };
        let standing = self
            .standing(sender, units)
            .await
            .map_err(|_| Refused::Unknown)?;
        standing.holds(need).cloned()
    }

    /// As [`BusPeers::require`], for the refusal a method returns directly.
    pub async fn require_or_deny(
        &self,
        sender: Option<&str>,
        need: &[Requirement],
    ) -> fdo::Result<Standing> {
        self.require(sender, need).await.map_err(access_denied)
    }

    async fn standing(&self, sender: &str, units: UnitUse) -> Result<Standing, WhoError> {
        if let Some(standing) = self.introduced_for(sender) {
            return Ok(standing);
        }
        let observed = self.observe(sender).await?;
        let mut facts = match observed.facts {
            Ok(facts) => facts,
            Err(why) => return Ok(unverified(why)),
        };
        if units == UnitUse::Ask {
            facts.unit = self.unit_facts(&facts).await;
        }
        match observed.held.alive() {
            Alive::Yes => Ok(judge(&facts, &self.table)),
            Alive::Gone => Ok(unverified(WhyNot::PeerGone)),
        }
    }

    /// The manager's account of the unit the sender's cgroup names, when a table row names that
    /// unit and the manager is itself the real one. `None` is not an error: the sender then
    /// cannot reach `Full`.
    async fn unit_facts(&self, facts: &Facts) -> Option<UnitFacts> {
        let unit: UnitName = facts.cgroup.unit_leaf()?;
        self.table.row_for_unit(&unit)?;
        if !self.manager_is_real().await {
            return None;
        }
        bounded(self.units.unit(&unit)).await.ok()?.ok()
    }

    async fn manager_is_real(&self) -> bool {
        let ManagerCheck::Verified(need) = &self.manager else {
            return true;
        };
        let Ok(owner) = self.owner_name(SYSTEMD).await else {
            return false;
        };
        let Ok(observed) = self.observe(&owner).await else {
            return false;
        };
        let Ok(facts) = observed.facts else {
            return false;
        };
        judge(&facts, &self.table)
            .holds(std::slice::from_ref(need))
            .is_ok()
    }

    /// The unique name that owns `name` on the bus.
    pub(crate) async fn owner_name(&self, name: &str) -> Result<String, WhoError> {
        let name = BusName::try_from(name).map_err(|_| WhoError::BadName)?;
        let bus = DBusProxy::new(&self.connection)
            .await
            .map_err(WhoError::Bus)?;
        let owner = bounded(bus.get_name_owner(name))
            .await
            .map_err(|_| WhoError::Timeout)?
            .map_err(bus_error)?;
        Ok(owner.as_str().to_owned())
    }

    /// Holds the sender's process and reads its facts (without the unit manager).
    async fn observe(&self, sender: &str) -> Result<Observed, WhoError> {
        let (held, label) = self.pin_of(sender).await?;
        let held = Arc::new(held);
        let (prober, who) = (Arc::clone(&self.prober), Arc::clone(&held));
        let probed = self
            .offload
            .run(move || prober.probe(&who, None))
            .await
            .map_err(|_| WhoError::Offload)?;
        let facts = match probed {
            Ok(mut facts) => {
                if let (SandboxFacts::Native, Some(snap)) = (&facts.sandbox, label) {
                    facts.sandbox = snap;
                }
                Ok(facts)
            }
            Err(ProbeError::PeerGone) => Err(WhyNot::PeerGone),
            Err(_) => Err(WhyNot::Unreadable),
        };
        Ok(Observed { held, facts })
    }

    async fn credentials(
        &self,
        bus: &DBusProxy<'_>,
        name: &BusName<'_>,
    ) -> Result<ConnectionCredentials, WhoError> {
        bounded(bus.get_connection_credentials(name.clone()))
            .await
            .map_err(|_| WhoError::Timeout)?
            .map_err(bus_error)
    }

    /// The pinned process of `sender`, and the sandbox its kernel security label states.
    ///
    /// With `ProcessFD` the bus daemon's own pidfd is used (`AtConnect`). Without it the pidfd is
    /// opened by the reported pid at once and the bus is asked again: the same pid and user
    /// must still be behind the connection (`Reopened`).
    async fn pin_of(&self, sender: &str) -> Result<(Pinned, Option<SandboxFacts>), WhoError> {
        let name = BusName::try_from(sender).map_err(|_| WhoError::BadName)?;
        let bus = DBusProxy::new(&self.connection)
            .await
            .map_err(WhoError::Bus)?;
        let creds = self.credentials(&bus, &name).await?;
        let pid = creds
            .process_id()
            .and_then(Pid::new)
            .ok_or(WhoError::NoCredentials)?;
        let uid = creds
            .unix_user_id()
            .map(Uid::new)
            .ok_or(WhoError::NoCredentials)?;
        let label = creds
            .linux_security_label()
            .and_then(|l| parse_security_label(l));
        let offered = creds
            .process_fd()
            .map(|fd| fd.as_fd().try_clone_to_owned())
            .transpose()
            .map_err(|_| WhoError::NoCredentials)?;
        let held = match offered {
            Some(fd) => Pinned::from_fd(fd, pid, uid)?,
            None => {
                let held = Pinned::from_pid_with_uid(pid, uid, Pin::Reopened)?;
                let again = self.credentials(&bus, &name).await?;
                let same = again.process_id() == creds.process_id()
                    && again.unix_user_id() == creds.unix_user_id();
                if !same {
                    return Err(WhoError::Changed);
                }
                held
            }
        };
        Ok((held, label))
    }
}

fn bus_error(error: fdo::Error) -> WhoError {
    if let fdo::Error::NameHasNoOwner(_) = error {
        WhoError::NoSuchPeer
    } else {
        WhoError::Bus(error.into())
    }
}
