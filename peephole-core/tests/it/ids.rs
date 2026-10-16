//! The ids refuse what they should, and a pattern matches only what it describes.

use peephole_core::{AppKey, ExePath, ExePattern, Pid, RoleName, UnitName};

fn pattern(text: &str) -> ExePattern {
    ExePattern::new(text).expect("a pattern")
}

fn path(text: &str) -> ExePath {
    ExePath::new(text).expect("a path")
}

#[test]
fn a_pattern_matches_whole_segments_and_one_star_per_segment() {
    let cases = [
        ("/usr/bin/sill", "/usr/bin/sill", true),
        ("/usr/bin/sill", "/usr/bin/sill2", false),
        (
            "/opt/quire/releases/*/bin/sill",
            "/opt/quire/releases/0.4.1/bin/sill",
            true,
        ),
        // A star never crosses a slash.
        (
            "/opt/quire/releases/*/bin/sill",
            "/opt/quire/releases/0.4/evil/bin/sill",
            false,
        ),
        (
            "/opt/quire/releases/*/bin/sill",
            "/opt/quire/releases/bin/sill",
            false,
        ),
        ("/opt/*/bin/sill", "/opt/x/bin/sill", true),
        ("/usr/bin/sill-*", "/usr/bin/sill-helper", true),
        ("/usr/bin/sill-*", "/usr/bin/sill", false),
        ("/usr/bin/*-sill", "/usr/bin/a-sill", true),
        ("/usr/bin/s*ll", "/usr/bin/sill", true),
        ("/usr/bin/s*ll", "/usr/bin/sl", false),
    ];
    for (pat, text, want) in cases {
        assert_eq!(
            pattern(pat).matches(&path(text)),
            want,
            "{pat} against {text}"
        );
    }
}

#[test]
fn patterns_that_could_match_too_much_are_refused() {
    for bad in [
        "relative/bin/x",
        "/opt/**/x",
        "/opt/a*b*c/x",
        "/opt/../x",
        "/opt//x",
        "/opt/./x",
        "/",
        "",
        "/a/\0",
    ] {
        assert!(ExePattern::new(bad).is_err(), "{bad:?}");
    }
}

#[test]
fn image_paths_are_absolute_plain_and_never_deleted() {
    for bad in [
        "bin/x",
        "/opt/../x",
        "/opt//x",
        "/opt/x/",
        "/opt/x (deleted)",
        "",
        "/",
    ] {
        assert!(ExePath::new(bad).is_err(), "{bad:?}");
    }
    assert_eq!(path("/usr/bin/sill").file_name(), Some("sill"));
}

#[test]
fn small_ids_check_their_alphabets() {
    assert!(UnitName::new("sill.service").is_ok());
    assert!(UnitName::new("app-org.x.Y-123.scope").is_ok());
    assert!(UnitName::new("user@1000.service").is_ok());
    for bad in [
        "sill",
        "sill.timer",
        ".service",
        "a/b.service",
        "a b.service",
    ] {
        assert!(UnitName::new(bad).is_err(), "{bad:?}");
    }
    assert!(AppKey::new("org.quire.Shell").is_ok());
    for bad in ["", "a b", "a/b"] {
        assert!(AppKey::new(bad).is_err(), "{bad:?}");
    }
    assert!(AppKey::new(&"x".repeat(256)).is_err());
    assert!(RoleName::new("pad_daemon").is_ok());
    for bad in ["", "Shell", "a-b"] {
        assert!(RoleName::new(bad).is_err(), "{bad:?}");
    }
    assert!(RoleName::new(&"x".repeat(65)).is_err());
    assert_eq!(
        RoleName::from_static("shell"),
        RoleName::new("shell").expect("a role")
    );
}

#[test]
fn a_pid_is_positive_and_fits_the_kernels_signed_type() {
    assert!(Pid::new(0).is_none());
    assert!(Pid::new(u32::MAX).is_none());
    assert_eq!(Pid::new(7).map(Pid::get), Some(7));
}
