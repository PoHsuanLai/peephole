//! What the systemd manager says of a unit: where its definition comes from and who runs it.
//! On the session bus the manager is the person's user manager; on the system bus, the system
//! one. (Which `GetUnit` and properties it answers is systemd's interface, read here as documented.)

use crate::error::UnitError;
use crate::timeout::bounded;
use peephole::{ProcFs, dirs_trust, weaker};
use peephole_core::{DropIns, ExePath, FileTrust, Fragment, Pid, Transient, UnitFacts, UnitName};
use std::collections::HashMap;
use std::future::Future;
use std::path::{Path, PathBuf};
use zbus::Connection;
use zbus::fdo::PropertiesProxy;
use zbus::names::InterfaceName;
use zbus::zvariant::{OwnedObjectPath, OwnedValue, Value};

/// The manager's bus name.
pub const SYSTEMD: &str = "org.freedesktop.systemd1";
/// The manager's object.
pub const SYSTEMD_PATH: &str = "/org/freedesktop/systemd1";
/// The interface of the manager's object.
pub const SYSTEMD_MANAGER: &str = "org.freedesktop.systemd1.Manager";
const UNIT_INTERFACE: &str = "org.freedesktop.systemd1.Unit";
const SERVICE_INTERFACE: &str = "org.freedesktop.systemd1.Service";

/// The most drop-in files looked at for one unit. More than this is as bad as a writable one.
pub const DROP_INS_MAX: usize = 32;

/// Where unit facts come from.
pub trait UnitSource: Send + Sync {
    /// The facts of the loaded unit `name`.
    fn unit(&self, name: &UnitName) -> impl Future<Output = Result<UnitFacts, UnitError>> + Send;
}

/// The unit manager on a bus connection. The ownership of the fragment and drop-in files is read
/// through the same [`ProcFs`] the prober uses.
#[derive(Debug, Clone)]
pub struct ManagerLink<P> {
    connection: Connection,
    fs: P,
}

impl<P: ProcFs> ManagerLink<P> {
    /// The manager reachable on `connection`.
    pub fn new(connection: Connection, fs: P) -> ManagerLink<P> {
        ManagerLink { connection, fs }
    }

    async fn unit_path(&self, name: &UnitName) -> Result<OwnedObjectPath, UnitError> {
        let args = (name.as_str(),);
        let call = self.connection.call_method(
            Some(SYSTEMD),
            SYSTEMD_PATH,
            Some(SYSTEMD_MANAGER),
            "GetUnit",
            &args,
        );
        let reply = bounded(call)
            .await
            .map_err(|_| UnitError::Timeout)?
            .map_err(UnitError::Bus)?;
        reply.body().deserialize().map_err(UnitError::Bus)
    }

    async fn properties(
        &self,
        path: &OwnedObjectPath,
        interface: &'static str,
    ) -> Result<HashMap<String, OwnedValue>, UnitError> {
        let proxy = PropertiesProxy::builder(&self.connection)
            .destination(SYSTEMD)
            .map_err(UnitError::Bus)?
            .path(path.clone())
            .map_err(UnitError::Bus)?
            .build()
            .await
            .map_err(UnitError::Bus)?;
        let interface = InterfaceName::try_from(interface).map_err(|e| UnitError::Bus(e.into()))?;
        bounded(proxy.get_all(interface))
            .await
            .map_err(|_| UnitError::Timeout)?
            .map_err(|e| UnitError::Bus(e.into()))
    }

    /// The trust of `path` and of every directory above it. A path that cannot be looked at is
    /// not trusted (`None` for a file that is not there).
    fn trust_of_path(&self, path: &Path) -> Option<FileTrust> {
        let dirs = dirs_trust(&self.fs, path).ok()?;
        let file = self.fs.trust_of(path).ok()?;
        Some(weaker(dirs, file))
    }

    fn fragment(&self, text: &str) -> Fragment {
        if text.is_empty() {
            return Fragment::Missing;
        }
        let path = PathBuf::from(text);
        match self.trust_of_path(&path) {
            Some(FileTrust::RootOnly) => Fragment::RootOwned(path),
            _ => Fragment::Writable(path),
        }
    }

    fn drop_ins(&self, paths: &[String]) -> DropIns {
        if paths.is_empty() {
            return DropIns::None;
        }
        let all_root = paths.len() <= DROP_INS_MAX
            && paths
                .iter()
                .all(|p| self.trust_of_path(Path::new(p)) == Some(FileTrust::RootOnly));
        if all_root {
            DropIns::RootOwned
        } else {
            DropIns::Writable
        }
    }
}

impl<P: ProcFs> UnitSource for ManagerLink<P> {
    async fn unit(&self, name: &UnitName) -> Result<UnitFacts, UnitError> {
        let path = self.unit_path(name).await?;
        let unit = self.properties(&path, UNIT_INTERFACE).await?;
        if text(&unit, "LoadState") != Some("loaded") {
            return Err(UnitError::NotLoaded);
        }
        if text(&unit, "Id") != Some(name.as_str()) {
            return Err(UnitError::Malformed(
                "the unit's Id is not the name asked for",
            ));
        }
        let service = match name.as_str().ends_with(".service") {
            true => self.properties(&path, SERVICE_INTERFACE).await?,
            false => HashMap::new(),
        };
        Ok(UnitFacts {
            name: name.clone(),
            main_pid: number(&service, "MainPID").and_then(Pid::new),
            fragment: self.fragment(text(&unit, "FragmentPath").unwrap_or_default()),
            drop_ins: self.drop_ins(&texts(&unit, "DropInPaths")),
            // A manager that does not say is assumed to have made the unit at run time.
            transient: match flag(&unit, "Transient") {
                Some(false) => Transient::No,
                _ => Transient::Yes,
            },
            exec: first_exec(&service),
        })
    }
}

fn value<'a>(map: &'a HashMap<String, OwnedValue>, key: &str) -> Option<&'a Value<'static>> {
    map.get(key).map(|v| &**v)
}

fn text<'a>(map: &'a HashMap<String, OwnedValue>, key: &str) -> Option<&'a str> {
    match value(map, key)? {
        Value::Str(s) => Some(s.as_str()),
        _ => None,
    }
}

fn texts(map: &HashMap<String, OwnedValue>, key: &str) -> Vec<String> {
    match value(map, key) {
        Some(Value::Array(items)) => items
            .inner()
            .iter()
            .filter_map(|item| match item {
                Value::Str(s) => Some(s.as_str().to_owned()),
                _ => None,
            })
            .collect(),
        _ => Vec::new(),
    }
}

fn flag(map: &HashMap<String, OwnedValue>, key: &str) -> Option<bool> {
    match value(map, key)? {
        Value::Bool(b) => Some(*b),
        _ => None,
    }
}

fn number(map: &HashMap<String, OwnedValue>, key: &str) -> Option<u32> {
    match value(map, key)? {
        Value::U32(n) => Some(*n),
        _ => None,
    }
}

/// The program of the first `ExecStart` entry (`a(sasbttttuii)`: the path is the first field).
fn first_exec(service: &HashMap<String, OwnedValue>) -> Option<ExePath> {
    let Some(Value::Array(entries)) = value(service, "ExecStart") else {
        return None;
    };
    match entries.inner().first()? {
        Value::Structure(entry) => match entry.fields().first()? {
            Value::Str(path) => ExePath::new(path.as_str()).ok(),
            _ => None,
        },
        _ => None,
    }
}
