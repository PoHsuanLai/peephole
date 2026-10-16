//! A stand-in for the systemd user manager, served on the private bus under its own name.

use zbus::fdo;
use zbus::zvariant::OwnedObjectPath;

const UNIT_PATH: &str = "/org/freedesktop/systemd1/unit/sill_2eservice";

/// What the stand-in says of `sill.service`.
#[derive(Debug, Clone)]
pub struct FakeUnit {
    pub fragment: String,
    pub drop_ins: Vec<String>,
    pub transient: bool,
    pub main_pid: u32,
    pub exec: String,
    pub unset: Vec<String>,
}

/// The shape of systemd's `ExecStart`: `a(sasbttttuii)`.
type ExecStart = Vec<(String, Vec<String>, bool, u64, u64, u64, u64, u32, i32)>;

struct Manager;

#[zbus::interface(name = "org.freedesktop.systemd1.Manager")]
impl Manager {
    fn get_unit(&self, name: &str) -> fdo::Result<OwnedObjectPath> {
        match name {
            "sill.service" => {
                OwnedObjectPath::try_from(UNIT_PATH).map_err(|e| fdo::Error::Failed(e.to_string()))
            }
            other => Err(fdo::Error::Failed(format!("no such unit {other}"))),
        }
    }
}

struct UnitProps(FakeUnit);

#[zbus::interface(name = "org.freedesktop.systemd1.Unit")]
impl UnitProps {
    #[zbus(property)]
    fn id(&self) -> String {
        "sill.service".to_owned()
    }

    #[zbus(property)]
    fn load_state(&self) -> String {
        "loaded".to_owned()
    }

    #[zbus(property)]
    fn fragment_path(&self) -> String {
        self.0.fragment.clone()
    }

    #[zbus(property)]
    fn drop_in_paths(&self) -> Vec<String> {
        self.0.drop_ins.clone()
    }

    #[zbus(property)]
    fn transient(&self) -> bool {
        self.0.transient
    }
}

struct ServiceProps(FakeUnit);

#[zbus::interface(name = "org.freedesktop.systemd1.Service")]
impl ServiceProps {
    #[zbus(property, name = "MainPID")]
    fn main_pid(&self) -> u32 {
        self.0.main_pid
    }

    #[zbus(property)]
    fn unset_environment(&self) -> Vec<String> {
        self.0.unset.clone()
    }

    #[zbus(property)]
    fn exec_start(&self) -> ExecStart {
        vec![(self.0.exec.clone(), Vec::new(), false, 0, 0, 0, 0, 0, 0)]
    }
}

/// Serves the stand-in on `connection` and takes the manager's bus name.
pub async fn serve(connection: &zbus::Connection, unit: FakeUnit) {
    let server = connection.object_server();
    server
        .at("/org/freedesktop/systemd1", Manager)
        .await
        .expect("serve the manager");
    server
        .at(UNIT_PATH, UnitProps(unit.clone()))
        .await
        .expect("serve the unit");
    server
        .at(UNIT_PATH, ServiceProps(unit))
        .await
        .expect("serve the service");
    connection
        .request_name("org.freedesktop.systemd1")
        .await
        .expect("take the manager's name");
}
