//! The text parsers.

use peephole_core::SandboxFacts;
use peephole_core::procinfo::{
    parse_fdinfo_pid, parse_flatpak_info, parse_security_label, parse_status_euid,
};

#[test]
fn the_effective_user_is_the_second_uid() {
    let status = "Name:\tx\nUid:\t1000\t1001\t1000\t1001\nGid:\t1\t1\t1\t1\n";
    assert_eq!(parse_status_euid(status).map(|u| u.get()), Some(1001));
    assert!(parse_status_euid("Name:\tx\n").is_none());
    assert!(parse_status_euid("Uid:\tx\ty\n").is_none());
}

#[test]
fn a_pidfds_pid_is_read_and_an_exited_process_is_none() {
    assert_eq!(
        parse_fdinfo_pid("pos:\t0\nflags:\t02000002\nPid:\t1234\nNSpid:\t1234\n").map(|p| p.get()),
        Some(1234)
    );
    assert!(parse_fdinfo_pid("Pid:\t-1\n").is_none());
    assert!(parse_fdinfo_pid("pos:\t0\n").is_none());
}

#[test]
fn flatpak_metadata_names_an_app_or_nobody() {
    let info = "[Application]\nname=org.mozilla.firefox\nruntime=x\n\n[Instance]\ninstance-id=99\n";
    assert_eq!(
        parse_flatpak_info(info),
        Some(SandboxFacts::Flatpak {
            app: "org.mozilla.firefox".into()
        })
    );
    assert_eq!(parse_flatpak_info("[Instance]\ninstance-id=1\n"), None);
    // A key in the wrong section is ignored.
    assert_eq!(parse_flatpak_info("[Other]\nname=org.x.Y\n"), None);
}

#[test]
fn a_snap_is_a_label_that_starts_snap_dot() {
    assert_eq!(
        parse_security_label(b"snap.firefox.firefox (enforce)\0"),
        Some(SandboxFacts::Snap {
            label: "snap.firefox.firefox".into()
        })
    );
    assert_eq!(parse_security_label(b"unconfined\0"), None);
    assert_eq!(parse_security_label(b"system_u:system_r:init_t:s0\0"), None);
    assert_eq!(parse_security_label(&[0xff, 0xfe, 0]), None);
}
