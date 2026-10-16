//! Builders shared by the modules.

use peephole_core::{
    CgroupPath, DropIns, Exe, ExePath, Facts, FileTrust, Fragment, Loader, Pid, Pin, SandboxFacts,
    Table, Transient, Uid, UnitFacts, UnitName, Writer,
};
use std::path::PathBuf;

pub const PID: u32 = 4242;

/// A small table: one service with a unit, one program without.
pub const TABLE: &str = r#"
[[peer]]
app  = "org.quire.Shell"
unit = "sill.service"
exe  = ["/opt/quire/releases/*/bin/sill", "/usr/bin/sill"]
role = "shell"

[[peer]]
app  = "org.quire.Updater"
exe  = ["/usr/bin/slipway"]
role = "updater_cli"
"#;

pub fn table() -> Table {
    Table::from_toml(TABLE).expect("the sample table reads")
}

pub fn pid() -> Pid {
    Pid::new(PID).expect("a pid")
}

pub fn exe_path(text: &str) -> ExePath {
    ExePath::new(text).expect("an image path")
}

pub fn read(path: &str, trust: FileTrust) -> Exe {
    Exe::Read {
        path: exe_path(path),
        trust,
    }
}

pub fn root_only(path: &str) -> Exe {
    read(path, FileTrust::RootOnly)
}

pub fn user_writable(path: &str) -> Exe {
    read(path, FileTrust::Writable(Writer::Owner(Uid::new(1000))))
}

pub fn in_sill_unit() -> &'static str {
    "/user.slice/user-1000.slice/user@1000.service/app.slice/sill.service"
}

pub fn facts(cgroup: &str, exe: Exe) -> Facts {
    Facts {
        pid: pid(),
        uid: Uid::new(1000),
        cgroup: CgroupPath::new(cgroup).expect("a cgroup path"),
        exe,
        sandbox: SandboxFacts::Native,
        unit: None,
        pin: Pin::AtConnect,
    }
}

/// What the manager says of a healthy sill.service.
pub fn sill_unit() -> UnitFacts {
    UnitFacts {
        name: UnitName::new("sill.service").expect("a unit"),
        main_pid: Some(pid()),
        fragment: Fragment::RootOwned(PathBuf::from("/usr/lib/systemd/user/sill.service")),
        drop_ins: DropIns::None,
        transient: Transient::No,
        exec: Some(exe_path("/usr/bin/sill")),
        loader: Loader::Cleared,
    }
}
