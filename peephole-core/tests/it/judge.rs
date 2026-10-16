//! The judgement, one row of the trust rules at a time.

use crate::common::{facts, in_sill_unit, read, root_only, sill_unit, table, user_writable};
use peephole_core::{
    AppKey, DropIns, Engine, Exe, FileTrust, Fragment, Pin, Proof, RoleName, SandboxFacts,
    Standing, Transient, WhyNot, Writer, judge,
};
use std::path::PathBuf;

const SILL_IMAGE: &str = "/opt/quire/releases/1.2.3/bin/sill";

fn service(role: &str, proof: Proof, pin: Pin) -> Standing {
    let app = match role {
        "shell" => "org.quire.Shell",
        _ => "org.quire.Updater",
    };
    Standing::Service {
        app: AppKey::new(app).expect("an app"),
        role: RoleName::new(role).expect("a role"),
        proof,
        pin,
    }
}

fn unverified(name: Option<&str>, why: WhyNot) -> Standing {
    Standing::Unverified {
        exe_name: name.map(str::to_owned),
        why,
    }
}

fn with_unit(change: impl FnOnce(&mut peephole_core::UnitFacts)) -> Standing {
    let mut f = facts(in_sill_unit(), root_only(SILL_IMAGE));
    let mut unit = sill_unit();
    change(&mut unit);
    f.unit = Some(unit);
    judge(&f, &table())
}

#[test]
fn the_real_unit_is_full() {
    assert_eq!(
        with_unit(|_| {}),
        service("shell", Proof::Full, Pin::AtConnect)
    );
}

#[test]
fn anything_the_manager_cannot_confirm_stops_at_exe() {
    let exe = service("shell", Proof::Exe, Pin::AtConnect);
    // The definition comes from a user-writable place (a user-level override of the unit).
    assert_eq!(
        with_unit(|u| u.fragment =
            Fragment::Writable(PathBuf::from("/home/p/.config/systemd/user/sill.service"))),
        exe
    );
    assert_eq!(with_unit(|u| u.fragment = Fragment::Missing), exe);
    // A drop-in the person can write; a root-owned one is the administrator's.
    assert_eq!(with_unit(|u| u.drop_ins = DropIns::Writable), exe);
    assert_eq!(
        with_unit(|u| u.drop_ins = DropIns::RootOwned),
        service("shell", Proof::Full, Pin::AtConnect)
    );
    // A unit made with systemd-run.
    assert_eq!(with_unit(|u| u.transient = Transient::Yes), exe);
    // Someone else is the unit's main process.
    assert_eq!(with_unit(|u| u.main_pid = None), exe);
    assert_eq!(with_unit(|u| u.main_pid = peephole_core::Pid::new(1)), exe);
    // The unit starts some other program than the table's.
    assert_eq!(with_unit(|u| u.exec = None), exe);
    assert_eq!(
        with_unit(|u| u.exec = peephole_core::ExePath::new("/home/p/bin/sill").ok()),
        exe
    );
    // The manager answered for a different unit.
    assert_eq!(
        with_unit(|u| u.name = peephole_core::UnitName::new("other.service").expect("a unit")),
        exe
    );
}

#[test]
fn without_the_manager_a_service_is_at_most_exe() {
    let f = facts(in_sill_unit(), root_only(SILL_IMAGE));
    assert_eq!(
        judge(&f, &table()),
        service("shell", Proof::Exe, Pin::AtConnect)
    );
}

#[test]
fn the_pin_is_carried_through() {
    let mut f = facts(in_sill_unit(), root_only(SILL_IMAGE));
    f.pin = Pin::Reopened;
    assert_eq!(
        judge(&f, &table()),
        service("shell", Proof::Exe, Pin::Reopened)
    );
}

#[test]
fn an_image_someone_can_write_is_never_remembered() {
    for trust in [
        FileTrust::Writable(Writer::Group),
        FileTrust::Writable(Writer::Other),
        FileTrust::Writable(Writer::Owner(peephole_core::Uid::new(1000))),
    ] {
        // Even in the right unit, with the right name, a copied binary is nobody.
        let f = facts(in_sill_unit(), read("/home/p/bin/sill", trust));
        assert_eq!(
            judge(&f, &table()),
            unverified(Some("sill"), WhyNot::ImageWritable)
        );
        let f = facts(in_sill_unit(), read("/usr/bin/sill", trust));
        assert_eq!(
            judge(&f, &table()),
            unverified(Some("sill"), WhyNot::ImageWritable)
        );
    }
}

#[test]
fn a_hidden_image_is_a_service_only_at_the_cgroup() {
    let f = facts(in_sill_unit(), Exe::Hidden);
    assert_eq!(
        judge(&f, &table()),
        service("shell", Proof::Cgroup, Pin::AtConnect)
    );
    let f = facts("/user.slice/app.slice/other.service", Exe::Hidden);
    assert_eq!(judge(&f, &table()), unverified(None, WhyNot::ImageHidden));
    let f = facts("/user.slice/app.slice/app-sill-1.scope", Exe::Hidden);
    assert_eq!(judge(&f, &table()), unverified(None, WhyNot::ImageHidden));
}

#[test]
fn a_service_unit_name_alone_is_not_enough() {
    // A transient unit or a moved cgroup spelling sill.service, around some other program.
    let f = facts(in_sill_unit(), root_only("/usr/bin/python3"));
    assert_eq!(
        judge(&f, &table()),
        Standing::Program {
            exe: crate::common::exe_path("/usr/bin/python3"),
            scope_app: None
        }
    );
}

#[test]
fn the_real_image_outside_its_unit_is_a_program_not_the_service() {
    // `systemd-run --user --scope -u app-org.quire.Shell-1 /usr/bin/sill`
    let f = facts(
        "/user.slice/app.slice/app-org.quire.Shell-1.scope",
        root_only("/usr/bin/sill"),
    );
    assert_eq!(
        judge(&f, &table()),
        Standing::Program {
            exe: crate::common::exe_path("/usr/bin/sill"),
            scope_app: AppKey::new("org.quire.Shell").ok(),
        }
    );
    // From a terminal.
    let f = facts(
        "/user.slice/app.slice/vte-spawn-1.scope",
        root_only("/usr/bin/sill"),
    );
    assert!(matches!(
        judge(&f, &table()),
        Standing::Program {
            scope_app: None,
            ..
        }
    ));
}

#[test]
fn a_program_row_matches_by_image_alone_and_tops_out_at_exe() {
    let f = facts(
        "/user.slice/app.slice/vte-spawn-1.scope",
        root_only("/usr/bin/slipway"),
    );
    assert_eq!(
        judge(&f, &table()),
        service("updater_cli", Proof::Exe, Pin::AtConnect)
    );
    let f = facts(
        "/user.slice/app.slice/vte-spawn-1.scope",
        user_writable("/home/p/slipway"),
    );
    assert_eq!(
        judge(&f, &table()),
        unverified(Some("slipway"), WhyNot::ImageWritable)
    );
}

#[test]
fn an_empty_table_makes_nobody_a_service() {
    let f = facts(in_sill_unit(), root_only(SILL_IMAGE));
    assert!(matches!(
        judge(&f, &peephole_core::Table::empty()),
        Standing::Program { .. }
    ));
}

fn flatpak(cgroup: &str, app: &str) -> Standing {
    let mut f = facts(cgroup, Exe::Hidden);
    f.sandbox = SandboxFacts::Flatpak {
        app: app.into(),
        instance: "7".into(),
    };
    judge(&f, &table())
}

#[test]
fn a_flatpak_app_is_sandboxed_only_when_its_scope_agrees() {
    let ok = Standing::Sandboxed {
        app: AppKey::new("org.mozilla.firefox").expect("an app"),
        engine: Engine::Flatpak,
    };
    assert_eq!(
        flatpak(
            "/user.slice/app.slice/app-flatpak-org.mozilla.firefox-4242.scope",
            "org.mozilla.firefox"
        ),
        ok
    );
    let disagree = unverified(None, WhyNot::SandboxDisagrees);
    // The metadata says Firefox, the cgroup says another app, a service, or a plain scope.
    assert_eq!(
        flatpak(
            "/user.slice/app.slice/app-flatpak-org.other.App-4242.scope",
            "org.mozilla.firefox"
        ),
        disagree
    );
    assert_eq!(flatpak(in_sill_unit(), "org.mozilla.firefox"), disagree);
    assert_eq!(
        flatpak(
            "/user.slice/app.slice/app-org.mozilla.firefox-4242.scope",
            "org.mozilla.firefox"
        ),
        disagree
    );
    // The metadata names something that is not an app key.
    assert_eq!(
        flatpak("/user.slice/app.slice/app-flatpak-x-1.scope", "a b"),
        disagree
    );
}

#[test]
fn a_sandboxed_peer_never_holds_a_service_role() {
    // A Flatpak app whose metadata claims to be the shell, inside the shell's unit.
    let standing = flatpak(in_sill_unit(), "org.quire.Shell");
    assert!(!matches!(standing, Standing::Service { .. }));
}

#[test]
fn a_snap_is_known_by_its_kernel_label() {
    let mut f = facts(
        "/user.slice/app.slice/snap.firefox.firefox-1.scope",
        Exe::Hidden,
    );
    f.sandbox = SandboxFacts::Snap {
        label: "snap.firefox.firefox".into(),
    };
    assert_eq!(
        judge(&f, &table()),
        Standing::Sandboxed {
            app: AppKey::new("firefox").expect("an app"),
            engine: Engine::Snap
        }
    );
    f.sandbox = SandboxFacts::Snap {
        label: "snap.firefox".into(),
    };
    assert_eq!(
        judge(&f, &table()),
        unverified(None, WhyNot::SandboxDisagrees)
    );
}
