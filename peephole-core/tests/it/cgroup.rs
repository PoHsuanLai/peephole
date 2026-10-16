//! Cgroup paths, unit-name escapes and the names a scope claims.

use peephole_core::{AppKey, CgroupPath, escape_unit, flatpak_scope_in, scope_app, unescape_unit};

fn cg(text: &str) -> CgroupPath {
    CgroupPath::new(text).expect("a cgroup path")
}

#[test]
fn the_unified_line_is_picked_out_of_a_hybrid_file() {
    let text = "12:cpu:/x\n1:name=systemd:/y\n0::/user.slice/sill.service\n";
    let path = CgroupPath::from_proc(text).expect("a path");
    assert_eq!(path.as_str(), "/user.slice/sill.service");
    assert_eq!(path.leaf(), "sill.service");
    assert!(CgroupPath::from_proc("1:name=systemd:/y\n").is_err());
    assert!(CgroupPath::from_proc("0::relative\n").is_err());
}

#[test]
fn only_a_unit_name_is_a_unit_leaf() {
    assert_eq!(
        cg("/a/b/sill.service").unit_leaf().map(|u| u.to_string()),
        Some("sill.service".to_owned())
    );
    assert_eq!(
        cg("/a/b/session-3.scope")
            .unit_leaf()
            .map(|u| u.to_string()),
        Some("session-3.scope".to_owned())
    );
    assert!(cg("/a/b/app.slice").unit_leaf().is_none());
    assert!(cg("/a/b/sill.service (deleted)").unit_leaf().is_none());
}

#[test]
fn escapes_round_trip_and_dashes_are_escaped() {
    assert_eq!(escape_unit("org.gnome.Foo-Bar"), "org.gnome.Foo\\x2dBar");
    assert_eq!(escape_unit(".hidden"), "\\x2ehidden");
    for text in ["org.gnome.Foo-Bar", "a_b:c", "x\\y", "plain"] {
        assert_eq!(unescape_unit(&escape_unit(text)).as_deref(), Some(text));
    }
    assert!(unescape_unit("\\x2").is_none());
    assert!(unescape_unit("\\q").is_none());
}

#[test]
fn a_launchers_scope_names_an_app_as_a_claim() {
    let cases = [
        (
            "/user.slice/app.slice/app-org.gnome.Calculator-4242.scope",
            Some("org.gnome.Calculator"),
        ),
        (
            "/user.slice/app.slice/app-gnome-org.gnome.Calculator-4242.scope",
            Some("org.gnome.Calculator"),
        ),
        (
            "/user.slice/app.slice/app-org.x.Foo\\x2dBar-4242.scope",
            Some("org.x.Foo-Bar"),
        ),
        // Flatpak's own scopes name nobody here: the sandbox metadata does.
        (
            "/user.slice/app.slice/app-flatpak-org.mozilla.firefox-4242.scope",
            None,
        ),
        ("/user.slice/app.slice/sill.service", None),
        ("/user.slice/app.slice/app-org.x.Foo-notaword!.scope", None),
    ];
    for (path, want) in cases {
        let got = scope_app(&cg(path)).map(|k| k.to_string());
        assert_eq!(got.as_deref(), want, "{path}");
    }
}

#[test]
fn a_flatpak_scope_must_spell_the_apps_own_id_and_a_number() {
    let app = AppKey::new("org.mozilla.firefox").expect("an app");
    let cases = [
        (
            "/user.slice/app.slice/app-flatpak-org.mozilla.firefox-1234.scope",
            true,
        ),
        (
            "/user.slice/app.slice/app-flatpak-org.mozilla.firefox-.scope",
            false,
        ),
        (
            "/user.slice/app.slice/app-flatpak-org.mozilla.firefox-12a.scope",
            false,
        ),
        (
            "/user.slice/app.slice/app-flatpak-org.mozilla.thunderbird-1234.scope",
            false,
        ),
        (
            "/user.slice/app.slice/app-org.mozilla.firefox-1234.scope",
            false,
        ),
        ("/user.slice/app.slice/sill.service", false),
    ];
    for (path, want) in cases {
        assert_eq!(flatpak_scope_in(&cg(path), &app), want, "{path}");
    }
    let dashed = AppKey::new("org.x.Foo-Bar").expect("an app");
    assert!(flatpak_scope_in(
        &cg("/a/app-flatpak-org.x.Foo\\x2dBar-9.scope"),
        &dashed
    ));
}
