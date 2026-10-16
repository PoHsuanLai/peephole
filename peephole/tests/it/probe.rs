//! The prober over fixture trees: every fact it reads and every way a read can fail.

use peephole::{Alive, FixtureImage, FixtureProc, FixtureProcess, Pinned, ProbeError, Prober};
use peephole_core::{Exe, FileTrust, Pid, Pin, SandboxFacts, Standing, Table, Uid, WhyNot, Writer};

const PID: u32 = 4242;
const SILL_CGROUP: &str =
    "0::/user.slice/user-1000.slice/user@1000.service/app.slice/sill.service\n";
const IMAGE: &str = "/opt/quire/releases/1/bin/sill";

const TABLE: &str = r#"
[[peer]]
app  = "org.quire.Shell"
unit = "sill.service"
exe  = ["/opt/quire/releases/*/bin/sill"]
role = "shell"
"#;

fn pid() -> Pid {
    Pid::new(PID).expect("a pid")
}

fn held() -> Pinned {
    Pinned::introduced(pid(), Uid::new(1000), Pin::AtConnect)
}

fn process<'a>(cgroup: &'a str, image: FixtureImage<'a>) -> FixtureProcess<'a> {
    FixtureProcess {
        pid: pid(),
        cgroup,
        image,
        flatpak_info: None,
    }
}

fn probe(tree: FixtureProc) -> Result<peephole_core::Facts, ProbeError> {
    Prober::new(tree).probe(&held(), None)
}

fn exe_of(tree: FixtureProc) -> Exe {
    probe(tree).expect("the probe reads").exe
}

fn writable_by_owner() -> FileTrust {
    FileTrust::Writable(Writer::Owner(Uid::new(1000)))
}

#[test]
fn a_root_owned_image_in_a_unit_reads_as_such() {
    let tree = FixtureProc::new().process(process(
        SILL_CGROUP,
        FixtureImage::Present(IMAGE, FileTrust::RootOnly),
    ));
    let facts = probe(tree).expect("the probe reads");
    assert_eq!(facts.cgroup.leaf(), "sill.service");
    assert_eq!(facts.pid, pid());
    assert_eq!(facts.uid, Uid::new(1000));
    assert_eq!(facts.pin, Pin::AtConnect);
    assert_eq!(facts.sandbox, SandboxFacts::Native);
    assert_eq!(
        facts.exe,
        Exe::Read {
            path: peephole_core::ExePath::new(IMAGE).expect("a path"),
            trust: FileTrust::RootOnly
        }
    );
}

#[test]
fn a_deleted_image_is_judged_by_the_running_inode_not_the_path() {
    // A package update replaced the file: the path now holds a root-owned file, the running
    // inode is the user's old copy. The link reads "<path> (deleted)".
    let tree = FixtureProc::new().process(process(
        SILL_CGROUP,
        FixtureImage::Deleted(IMAGE, writable_by_owner()),
    ));
    match exe_of(tree) {
        Exe::Read { path, trust } => {
            assert_eq!(path.to_text(), IMAGE);
            assert_eq!(trust, writable_by_owner());
        }
        other => panic!("expected a read image, got {other:?}"),
    }
    let tree = FixtureProc::new().process(process(
        SILL_CGROUP,
        FixtureImage::Deleted(IMAGE, FileTrust::RootOnly),
    ));
    assert!(matches!(
        exe_of(tree),
        Exe::Read {
            trust: FileTrust::RootOnly,
            ..
        }
    ));
}

#[test]
fn the_walk_stops_at_the_first_directory_that_is_not_root_only() {
    // /opt/quire/releases is the person's: the image below it is root-owned and still untrusted.
    let tree = FixtureProc::new()
        .dir("/opt/quire/releases", writable_by_owner())
        .process(process(
            SILL_CGROUP,
            FixtureImage::Present(IMAGE, FileTrust::RootOnly),
        ));
    assert!(matches!(
        exe_of(tree),
        Exe::Read {
            trust: FileTrust::Writable(Writer::Owner(_)),
            ..
        }
    ));
    // A group-writable root directory counts too.
    let tree = FixtureProc::new()
        .dir("/opt", FileTrust::Writable(Writer::Group))
        .process(process(
            SILL_CGROUP,
            FixtureImage::Present(IMAGE, FileTrust::RootOnly),
        ));
    assert!(matches!(
        exe_of(tree),
        Exe::Read {
            trust: FileTrust::Writable(Writer::Group),
            ..
        }
    ));
}

#[test]
fn a_writable_file_in_root_directories_is_writable() {
    let tree = FixtureProc::new().process(process(
        SILL_CGROUP,
        FixtureImage::Present(IMAGE, writable_by_owner()),
    ));
    assert!(matches!(
        exe_of(tree),
        Exe::Read {
            trust: FileTrust::Writable(_),
            ..
        }
    ));
}

#[test]
fn an_unreadable_image_link_is_hidden_not_an_error() {
    let tree = FixtureProc::new().process(process(SILL_CGROUP, FixtureImage::Hidden));
    assert_eq!(exe_of(tree), Exe::Hidden);
}

#[test]
fn a_path_of_another_mount_namespace_is_hidden() {
    // The link reads a path this file system has no file for: the host cannot judge it.
    let tree =
        FixtureProc::new().process(process(SILL_CGROUP, FixtureImage::Elsewhere("/app/bin/x")));
    assert_eq!(exe_of(tree), Exe::Hidden);
    // No exe link at all (a kernel thread).
    let tree = FixtureProc::new().file("/proc/4242/cgroup", SILL_CGROUP, FileTrust::RootOnly);
    assert_eq!(exe_of(tree), Exe::Hidden);
    // A target that is not an absolute plain path (an anonymous inode) names no image.
    let tree = FixtureProc::new().process(process(
        SILL_CGROUP,
        FixtureImage::Elsewhere("anon_inode:[pidfd]"),
    ));
    assert_eq!(exe_of(tree), Exe::Hidden);
}

#[test]
fn flatpak_metadata_makes_a_flatpak_sandbox_and_hides_the_host_path() {
    let info = "[Application]\nname=org.mozilla.firefox\n[Instance]\ninstance-id=5\n";
    let mut p = process(
        "0::/user.slice/app.slice/app-flatpak-org.mozilla.firefox-4242.scope\n",
        FixtureImage::Present("/app/bin/firefox", FileTrust::RootOnly),
    );
    p.flatpak_info = Some(info);
    let facts = probe(FixtureProc::new().process(p)).expect("the probe reads");
    assert_eq!(
        facts.sandbox,
        SandboxFacts::Flatpak {
            app: "org.mozilla.firefox".into(),
            instance: "5".into()
        }
    );
    assert_eq!(facts.exe, Exe::Hidden);
    let table = Table::from_toml(TABLE).expect("a table");
    let mut p = process(
        "0::/user.slice/app.slice/app-flatpak-org.mozilla.firefox-4242.scope\n",
        FixtureImage::Hidden,
    );
    p.flatpak_info = Some(info);
    let standing = Prober::new(FixtureProc::new().process(p)).stand(&held(), &table);
    assert!(
        matches!(standing, Standing::Sandboxed { .. }),
        "{standing:?}"
    );
}

#[test]
fn malformed_files_are_errors_and_a_missing_cgroup_is_a_gone_process() {
    let bad_cgroup = FixtureProc::new().file("/proc/4242/cgroup", "garbage\n", FileTrust::RootOnly);
    assert!(matches!(
        probe(bad_cgroup),
        Err(ProbeError::Malformed { .. })
    ));
    assert!(matches!(
        probe(FixtureProc::new()),
        Err(ProbeError::PeerGone)
    ));
    let huge = vec![b'x'; 64 * 1024 + 1];
    let tree = FixtureProc::new().file("/proc/4242/cgroup", huge, FileTrust::RootOnly);
    assert!(matches!(probe(tree), Err(ProbeError::Malformed { .. })));
    let not_text =
        FixtureProc::new().file("/proc/4242/cgroup", vec![0xff, 0xfe], FileTrust::RootOnly);
    assert!(matches!(probe(not_text), Err(ProbeError::Malformed { .. })));
}

#[test]
fn a_process_that_left_while_it_was_read_is_gone() {
    let tree = FixtureProc::new().process(process(
        SILL_CGROUP,
        FixtureImage::Present(IMAGE, FileTrust::RootOnly),
    ));
    let gone = Pinned::introduced_gone(pid(), Uid::new(1000), Pin::AtConnect);
    assert_eq!(gone.alive(), Alive::Gone);
    assert!(matches!(
        Prober::new(tree.clone()).probe(&gone, None),
        Err(ProbeError::PeerGone)
    ));
    let table = Table::from_toml(TABLE).expect("a table");
    assert_eq!(
        Prober::new(tree).stand(&gone, &table),
        Standing::Unverified {
            exe_name: None,
            why: WhyNot::PeerGone
        }
    );
}

#[test]
fn stand_judges_without_the_manager_so_a_service_tops_out_at_exe() {
    let table = Table::from_toml(TABLE).expect("a table");
    let tree = FixtureProc::new().process(process(
        SILL_CGROUP,
        FixtureImage::Present(IMAGE, FileTrust::RootOnly),
    ));
    match Prober::new(tree).stand(&held(), &table) {
        Standing::Service {
            role, proof, pin, ..
        } => {
            assert_eq!(role.as_str(), "shell");
            assert_eq!(proof, peephole_core::Proof::Exe);
            assert_eq!(pin, Pin::AtConnect);
        }
        other => panic!("expected the shell, got {other:?}"),
    }
    // The same image under a user-writable directory is nobody.
    let tree = FixtureProc::new()
        .dir("/opt/quire", writable_by_owner())
        .process(process(
            SILL_CGROUP,
            FixtureImage::Present(IMAGE, FileTrust::RootOnly),
        ));
    assert_eq!(
        Prober::new(tree).stand(&held(), &table),
        Standing::Unverified {
            exe_name: Some("sill".into()),
            why: WhyNot::ImageWritable
        }
    );
}

#[test]
fn a_very_deep_path_is_refused_rather_than_walked() {
    let deep = format!("/{}/sill", vec!["d"; peephole::WALK_MAX + 1].join("/"));
    let tree = FixtureProc::new().process(process(
        SILL_CGROUP,
        FixtureImage::Present(&deep, FileTrust::RootOnly),
    ));
    assert!(matches!(probe(tree), Err(ProbeError::Malformed { .. })));
}
