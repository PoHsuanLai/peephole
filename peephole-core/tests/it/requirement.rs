//! What a method asks of its caller.

use peephole_core::{
    AppKey, ExePath, Pin, PinNeed, Proof, Refused, Requirement, RoleName, Standing, WhyNot,
};

fn role(name: &str) -> RoleName {
    RoleName::new(name).expect("a role")
}

fn service(name: &str, proof: Proof, pin: Pin) -> Standing {
    Standing::Service {
        app: AppKey::new("org.quire.X").expect("an app"),
        role: role(name),
        proof,
        pin,
    }
}

#[test]
fn a_caller_needs_the_role_the_proof_and_the_pin() {
    let need = [Requirement::new(role("shell"), Proof::Full).pinned(PinNeed::AtConnect)];
    let cases = [
        (service("shell", Proof::Full, Pin::AtConnect), true),
        (service("shell", Proof::Exe, Pin::AtConnect), false),
        (service("shell", Proof::Full, Pin::Reopened), false),
        (service("portal", Proof::Full, Pin::AtConnect), false),
    ];
    for (standing, allowed) in cases {
        assert_eq!(standing.holds(&need).is_ok(), allowed, "{standing:?}");
    }
}

#[test]
fn proofs_are_ordered_and_any_one_requirement_is_enough() {
    assert!(Proof::Cgroup < Proof::Exe && Proof::Exe < Proof::Full);
    let need = [
        Requirement::new(role("shell"), Proof::Full),
        Requirement::new(role("settings"), Proof::Exe),
    ];
    assert!(
        service("settings", Proof::Full, Pin::Reopened)
            .holds(&need)
            .is_ok()
    );
    assert!(
        service("settings", Proof::Cgroup, Pin::Reopened)
            .holds(&need)
            .is_err()
    );
}

#[test]
fn refusals_do_not_say_which_check_failed() {
    let need = [Requirement::new(role("shell"), Proof::Exe)];
    let unknown = Standing::Unverified {
        exe_name: None,
        why: WhyNot::ImageWritable,
    };
    let program = Standing::Program {
        exe: ExePath::new("/usr/bin/x").expect("a path"),
        scope_app: None,
    };
    assert_eq!(unknown.holds(&need), Err(Refused::Unknown));
    assert_eq!(program.holds(&need), Err(Refused::NotAllowed));
    assert_eq!(
        service("portal", Proof::Full, Pin::AtConnect).holds(&need),
        Err(Refused::NotAllowed)
    );
    assert_eq!(program.holds(&[]), Err(Refused::NotAllowed));
    assert_eq!(Refused::NoSender.to_string(), "no sender");
    assert_eq!(Refused::Unknown.to_string(), "unknown caller");
    assert_eq!(
        Refused::NotAllowed.to_string(),
        "not the caller this method answers"
    );
}
