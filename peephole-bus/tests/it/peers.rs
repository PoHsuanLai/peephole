//! Identifying a bus sender: the real pidfd of this process, a fixture tree for what `/proc`
//! says, and a stand-in unit manager for the proof that needs it.

use crate::bus::{PrivateBus, name_of};
use crate::manager::{FakeUnit, serve};
use peephole::fake::introduced_service;
use peephole::{FixtureImage, FixtureProc, FixtureProcess};
use peephole_bus::{BusPeers, ManagerCheck};
use peephole_core::{
    FileTrust, Pid, Pin, Proof, Refused, Requirement, RoleName, Standing, Table, Uid, WhyNot,
    Writer,
};

const IMAGE: &str = "/usr/bin/sill";
const FRAGMENT: &str = "/usr/lib/systemd/user/sill.service";
const CGROUP: &str = "0::/user.slice/user-1000.slice/user@1000.service/app.slice/sill.service\n";

const TABLE: &str = r#"
[[peer]]
app  = "org.quire.Shell"
unit = "sill.service"
exe  = ["/usr/bin/sill"]
role = "shell"
"#;

fn me() -> Pid {
    Pid::new(std::process::id()).expect("our pid")
}

fn shell() -> RoleName {
    RoleName::new("shell").expect("a role")
}

/// A tree in which this very process is the shell: its pidfd is real, its files are the fixture's.
fn tree() -> FixtureProc {
    FixtureProc::new()
        .file(FRAGMENT, "", FileTrust::RootOnly)
        .process(FixtureProcess {
            pid: me(),
            cgroup: CGROUP,
            image: FixtureImage::Present(IMAGE, FileTrust::RootOnly),
            flatpak_info: None,
        })
}

fn healthy() -> FakeUnit {
    FakeUnit {
        fragment: FRAGMENT.to_owned(),
        drop_ins: Vec::new(),
        transient: false,
        main_pid: std::process::id(),
        exec: IMAGE.to_owned(),
    }
}

fn peers(watcher: zbus::Connection, fs: FixtureProc) -> BusPeers<FixtureProc> {
    let table = Table::from_toml(TABLE).expect("a table");
    BusPeers::with_proc(watcher, table, ManagerCheck::Unchecked, fs)
}

async fn who_with(unit: Option<FakeUnit>, fs: FixtureProc) -> Standing {
    let bus = PrivateBus::start();
    let (service, asker, manager) = (
        bus.connect().await,
        bus.connect().await,
        bus.connect().await,
    );
    if let Some(unit) = unit {
        serve(&manager, unit).await;
    }
    peers(asker, fs)
        .who(&name_of(&service))
        .await
        .expect("the sender is identified")
}

fn proof_of(standing: &Standing) -> Option<Proof> {
    match standing {
        Standing::Service { role, proof, .. } if *role == shell() => Some(*proof),
        _ => None,
    }
}

#[test]
fn the_shell_is_full_when_the_manager_confirms_its_unit() {
    let standing = zbus::block_on(who_with(Some(healthy()), tree()));
    assert_eq!(proof_of(&standing), Some(Proof::Full), "{standing:?}");
}

#[test]
fn without_a_manager_the_shell_tops_out_at_exe() {
    let standing = zbus::block_on(who_with(None, tree()));
    assert_eq!(proof_of(&standing), Some(Proof::Exe), "{standing:?}");
}

#[test]
fn a_manager_that_disagrees_leaves_the_shell_at_exe() {
    let cases = [
        // The definition is the person's.
        FakeUnit {
            fragment: "/home/p/.config/systemd/user/sill.service".to_owned(),
            ..healthy()
        },
        // A user drop-in.
        FakeUnit {
            drop_ins: vec!["/home/p/.config/systemd/user/sill.service.d/x.conf".to_owned()],
            ..healthy()
        },
        // Made with systemd-run.
        FakeUnit {
            transient: true,
            ..healthy()
        },
        // Someone else is the main process.
        FakeUnit {
            main_pid: 1,
            ..healthy()
        },
        // The unit runs another program.
        FakeUnit {
            exec: "/home/p/sill".to_owned(),
            ..healthy()
        },
    ];
    for unit in cases {
        let fs = tree()
            .dir(
                "/home/p/.config/systemd/user",
                FileTrust::Writable(Writer::Owner(Uid::new(1000))),
            )
            .file(
                "/home/p/.config/systemd/user/sill.service",
                "",
                FileTrust::Writable(Writer::Owner(Uid::new(1000))),
            )
            .file(
                "/home/p/.config/systemd/user/sill.service.d/x.conf",
                "",
                FileTrust::Writable(Writer::Owner(Uid::new(1000))),
            );
        let standing = zbus::block_on(who_with(Some(unit.clone()), fs));
        assert_eq!(
            proof_of(&standing),
            Some(Proof::Exe),
            "{unit:?} gave {standing:?}"
        );
    }
}

#[test]
fn a_user_writable_image_is_unverified_whatever_the_manager_says() {
    let fs = FixtureProc::new()
        .file(FRAGMENT, "", FileTrust::RootOnly)
        .process(FixtureProcess {
            pid: me(),
            cgroup: CGROUP,
            image: FixtureImage::Present(IMAGE, FileTrust::Writable(Writer::Owner(Uid::new(1000)))),
            flatpak_info: None,
        });
    let standing = zbus::block_on(who_with(Some(healthy()), fs));
    assert_eq!(
        standing,
        Standing::Unverified {
            exe_name: Some("sill".to_owned()),
            why: WhyNot::ImageWritable
        }
    );
}

#[test]
fn the_real_proc_never_makes_a_test_binary_the_shell() {
    let standing = zbus::block_on(async {
        let bus = PrivateBus::start();
        let (service, asker) = (bus.connect().await, bus.connect().await);
        let table = Table::from_toml(TABLE).expect("a table");
        BusPeers::new(asker, table, ManagerCheck::Unchecked)
            .who(&name_of(&service))
            .await
            .expect("identified")
    });
    assert!(
        !matches!(standing, Standing::Service { .. }),
        "{standing:?}"
    );
}

#[test]
fn require_refuses_without_a_sender_an_unknown_sender_and_a_wrong_role() {
    zbus::block_on(async {
        let bus = PrivateBus::start();
        let (service, asker) = (bus.connect().await, bus.connect().await);
        let peers = peers(asker, tree());
        let need = [Requirement::new(shell(), Proof::Exe)];
        assert_eq!(peers.require(None, &need).await, Err(Refused::NoSender));
        assert_eq!(
            peers.require(Some("not a name"), &need).await,
            Err(Refused::Unknown)
        );
        assert_eq!(
            peers.require(Some(":1.99999"), &need).await,
            Err(Refused::Unknown)
        );
        let other = [Requirement::new(
            RoleName::new("portal").expect("a role"),
            Proof::Exe,
        )];
        assert_eq!(
            peers.require(Some(&name_of(&service)), &other).await,
            Err(Refused::NotAllowed)
        );
        let standing = peers
            .require(Some(&name_of(&service)), &need)
            .await
            .expect("the shell passes");
        assert_eq!(proof_of(&standing), Some(Proof::Exe));
    });
}

#[test]
fn an_introduced_standing_stands_for_its_sender_and_for_nobody_else() {
    zbus::block_on(async {
        let bus = PrivateBus::start();
        let (service, other, asker) = (
            bus.connect().await,
            bus.connect().await,
            bus.connect().await,
        );
        let peers = peers(asker, FixtureProc::new());
        let standing = introduced_service("org.quire.Shell", "shell", Proof::Full, Pin::AtConnect)
            .expect("valid");
        peers.introduce(&name_of(&service), standing);
        let need = [Requirement::new(shell(), Proof::Full)];
        assert!(peers.require(Some(&name_of(&service)), &need).await.is_ok());
        // The other connection is looked at for real, in an empty tree: nobody.
        assert_eq!(
            peers.require(Some(&name_of(&other)), &need).await,
            Err(Refused::Unknown)
        );
    });
}
