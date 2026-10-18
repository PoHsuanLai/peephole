//! The judgement, one row of the trust rules at a time.

use crate::common::{facts, in_sill_unit, read, root_only, sill_unit, table, user_writable};
use peephole_core::{
    AppKey, DropIns, Engine, Exe, FileTrust, Fragment, LOADER_VARIABLES, Loader, Pin, Proof,
    RoleName, SandboxFacts, Standing, Transient, WhyNot, Writer, judge,
};

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
        scope_app: None,
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
    assert_eq!(with_unit(|u| u.fragment = Fragment::Writable), exe);
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

fn unset(names: &[&str]) -> Vec<String> {
    names.iter().map(|n| (*n).to_owned()).collect()
}

#[test]
fn a_unit_proves_full_only_when_it_unsets_every_loader_variable() {
    let full = service("shell", Proof::Full, Pin::AtConnect);
    let exe = service("shell", Proof::Exe, Pin::AtConnect);
    // Every name present, in any order, with extras.
    let mut all = unset(&LOADER_VARIABLES);
    all.reverse();
    all.push("SOMETHING_ELSE".to_owned());
    assert_eq!(with_unit(|u| u.loader = Loader::from_unset(&all)), full);
    // Each name missing in turn gives the lower proof and names exactly that variable.
    for name in LOADER_VARIABLES {
        let rest: Vec<String> = LOADER_VARIABLES
            .iter()
            .filter(|n| **n != name)
            .map(|n| (*n).to_owned())
            .collect();
        let loader = Loader::from_unset(&rest);
        assert_eq!(loader, Loader::Kept(vec![name.to_owned()]));
        assert!(loader.reason().expect("a reason").contains(name));
        assert_eq!(with_unit(|u| u.loader = loader.clone()), exe);
    }
    // Nothing unset, or a read that failed: all names are kept.
    let none = Loader::from_unset(&[]);
    assert_eq!(none, Loader::unknown());
    assert_eq!(none, Loader::Kept(unset(&LOADER_VARIABLES)));
    assert_eq!(with_unit(|u| u.loader = none.clone()), exe);
    // `LD_PRELOAD=` unsets one assignment, not the variable.
    assert_ne!(
        Loader::from_unset(&unset(&["LD_PRELOAD=x"])),
        Loader::Cleared
    );
    assert_eq!(Loader::Cleared.reason(), None);
}

#[test]
fn the_loader_variables_are_the_agreed_twenty_two() {
    assert_eq!(LOADER_VARIABLES.len(), 22);
    assert_eq!(LOADER_VARIABLES[0], "LD_PRELOAD");
    assert_eq!(LOADER_VARIABLES[21], "VK_LOADER_LAYERS_ENABLE");
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
    f.sandbox = SandboxFacts::Flatpak { app: app.into() };
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

/// A user-writable image keeps its launcher's scope name as a claim, and only that: no role, no
/// service, and an image that is hidden or a process that is gone carries none.
#[test]
fn a_writable_image_carries_its_scope_as_a_claim_and_nothing_else_does() {
    let scope =
        "/user.slice/user-1000.slice/user@1000.service/app.slice/app-org.quire.Mail-4242.scope";
    let f = facts(scope, user_writable("/home/p/src/mailo/target/debug/mailo"));
    assert_eq!(
        judge(&f, &table()),
        Standing::Unverified {
            exe_name: Some("mailo".to_owned()),
            scope_app: Some(AppKey::new("org.quire.Mail").expect("an app")),
            why: WhyNot::ImageWritable,
        }
    );
    // Without a scope there is no claim to carry.
    let f = facts(
        "/user.slice/user-1000.slice/session-2.scope",
        user_writable("/home/p/bin/mailo"),
    );
    assert_eq!(
        judge(&f, &table()),
        unverified(Some("mailo"), WhyNot::ImageWritable)
    );
    // A hidden image in the same scope claims nothing: no row names it, so it is nobody.
    let f = facts(scope, Exe::Hidden);
    assert_eq!(judge(&f, &table()), unverified(None, WhyNot::ImageHidden));
}
