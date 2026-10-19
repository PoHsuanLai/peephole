//! The system manager's word on who a person's user manager is.
//!
//! A unit's facts on the session bus come from the person's user manager, so they are believed
//! only once that manager is known to be the real one. Its image is the first proof, but the image
//! can be out of reach: systemd gives user managers `CAP_WAKE_ALARM` (systemd 254 and later), and the
//! kernel then hides `/proc/<pid>/exe` from every process of the same user that lacks it. The second
//! proof asks the system manager, which only root can be: process 1 owns `org.freedesktop.systemd1`
//! on the system bus, and its `user@<uid>.service` has the user manager as its main process.

use crate::error::UnitError;
use crate::manager::{SYSTEMD, SYSTEMD_MANAGER, SYSTEMD_PATH};
use crate::timeout::bounded;
use peephole_core::{Pid, Uid};
use std::sync::Mutex;
use zbus::Connection;
use zbus::fdo::{DBusProxy, PropertiesProxy};
use zbus::names::{BusName, InterfaceName};
use zbus::zvariant::{OwnedObjectPath, Value};

const UNIT_INTERFACE: &str = "org.freedesktop.systemd1.Unit";
const SERVICE_INTERFACE: &str = "org.freedesktop.systemd1.Service";

/// The system manager on the system bus, connected to when first asked.
#[derive(Debug, Default)]
pub(crate) struct SystemManager {
    connection: Mutex<Option<Connection>>,
}

impl SystemManager {
    async fn connection(&self) -> Result<Connection, UnitError> {
        let held = self
            .connection
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone();
        if let Some(connection) = held {
            return Ok(connection);
        }
        let connection = bounded(Connection::system())
            .await
            .map_err(|_| UnitError::Timeout)?
            .map_err(UnitError::Bus)?;
        *self
            .connection
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = Some(connection.clone());
        Ok(connection)
    }

    fn forget(&self) {
        *self
            .connection
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = None;
    }

    /// The main process of `user@<uid>.service`, as process 1 states it.
    async fn user_manager(&self, uid: Uid) -> Result<Pid, UnitError> {
        let connection = self.connection().await?;
        let bus = DBusProxy::new(&connection).await.map_err(UnitError::Bus)?;
        let name = BusName::try_from(SYSTEMD).map_err(|e| UnitError::Bus(e.into()))?;
        let owner = bounded(bus.get_name_owner(name))
            .await
            .map_err(|_| UnitError::Timeout)?
            .map_err(|e| UnitError::Bus(e.into()))?;
        let owner_pid = bounded(bus.get_connection_unix_process_id(owner.clone().into()))
            .await
            .map_err(|_| UnitError::Timeout)?
            .map_err(|e| UnitError::Bus(e.into()))?;
        if owner_pid != 1 {
            return Err(UnitError::Malformed(
                "the system bus's unit manager is not process 1",
            ));
        }
        // Every further call goes to that unique name, so a later owner of the well-known name
        // cannot answer them.
        let unit = format!("user@{}.service", uid.get());
        let args = (unit.as_str(),);
        let call = connection.call_method(
            Some(owner.as_str()),
            SYSTEMD_PATH,
            Some(SYSTEMD_MANAGER),
            "GetUnit",
            &args,
        );
        let path: OwnedObjectPath = bounded(call)
            .await
            .map_err(|_| UnitError::Timeout)?
            .map_err(|_| UnitError::NotLoaded)?
            .body()
            .deserialize()
            .map_err(UnitError::Bus)?;
        let owner = owner.to_string();
        let properties = PropertiesProxy::builder(&connection)
            .destination(owner)
            .and_then(|b| b.path(path))
            .map_err(UnitError::Bus)?
            .build()
            .await
            .map_err(UnitError::Bus)?;
        let id = property(&properties, UNIT_INTERFACE, "Id").await?;
        if !matches!(&id, Value::Str(text) if text.as_str() == unit) {
            return Err(UnitError::Malformed(
                "the unit's Id is not the name asked for",
            ));
        }
        match property(&properties, SERVICE_INTERFACE, "MainPID").await? {
            Value::U32(raw) => Pid::new(raw).ok_or(UnitError::NotLoaded),
            _ => Err(UnitError::Malformed("MainPID is not a number")),
        }
    }
}

async fn property(
    properties: &PropertiesProxy<'_>,
    interface: &'static str,
    name: &str,
) -> Result<Value<'static>, UnitError> {
    let interface =
        InterfaceName::from_static_str(interface).map_err(|e| UnitError::Bus(e.into()))?;
    let value = bounded(properties.get(interface, name))
        .await
        .map_err(|_| UnitError::Timeout)?
        .map_err(|e| UnitError::Bus(e.into()))?;
    Ok(Value::from(value))
}

/// Where the word on a user manager comes from: the system manager, or in a test a fixed answer.
#[derive(Debug)]
pub(crate) enum Attest {
    /// Process 1 on the system bus.
    System(SystemManager),
    /// A fixed answer, for tests on a private bus.
    #[cfg(feature = "fake")]
    Fixed(Option<Pid>),
}

impl Default for Attest {
    fn default() -> Self {
        Attest::System(SystemManager::default())
    }
}

impl Attest {
    /// The user manager of `uid`, or `None` when it cannot be had; `None` proves nothing.
    pub(crate) async fn user_manager(&self, uid: Uid) -> Option<Pid> {
        match self {
            Attest::System(system) => {
                let answer = bounded(system.user_manager(uid))
                    .await
                    .ok()
                    .and_then(Result::ok);
                if answer.is_none() {
                    // A system bus that restarted leaves a dead connection behind; the next
                    // question connects again.
                    system.forget();
                }
                answer
            }
            #[cfg(feature = "fake")]
            Attest::Fixed(answer) => *answer,
        }
    }
}
