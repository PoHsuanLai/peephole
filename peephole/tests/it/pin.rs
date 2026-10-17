//! Holding real processes: the test's own, a socket's peer and a child that exits. No fixtures
//! here, but nothing leaves the process: a socketpair, and a `sleep` child killed by handle.

use peephole::{Alive, PinError, Pinned};
use peephole_core::{Pid, Pin, Uid};
use std::os::unix::net::UnixStream;
use std::process::{Command, Stdio};

fn own_pid() -> Pid {
    Pid::new(std::process::id()).expect("our pid")
}

fn own_uid() -> Uid {
    Uid::new(rustix::process::geteuid().as_raw())
}

#[test]
fn a_socketpairs_peer_is_this_process_and_is_alive() {
    let (a, _b) = UnixStream::pair().expect("a socketpair");
    let held = Pinned::of_stream(&a).expect("pinned");
    assert_eq!(held.pid(), own_pid());
    assert_eq!(held.uid(), own_uid());
    // The kernel's own pidfd (SO_PEERPIDFD, Linux 6.5; every supported distro has it).
    assert_eq!(held.pin(), Pin::AtConnect);
    assert_eq!(held.alive(), Alive::Yes);
}

#[test]
fn a_pid_is_held_and_its_user_read_from_proc() {
    let held = Pinned::from_pid(own_pid(), Pin::Reopened).expect("pinned");
    assert_eq!(held.uid(), own_uid());
    assert_eq!(held.alive(), Alive::Yes);
    let given = Pinned::from_pid_with_uid(own_pid(), Uid::new(7), Pin::Reopened).expect("pinned");
    assert_eq!(given.uid(), Uid::new(7));
}

#[test]
fn a_process_that_exits_reads_as_gone_and_cannot_be_pinned_again() {
    let mut child = Command::new("sleep")
        .arg("30")
        .stdin(Stdio::null())
        .spawn()
        .expect("a sleep child");
    let pid = Pid::new(child.id()).expect("its pid");
    let held = Pinned::from_pid(pid, Pin::Reopened).expect("pinned");
    assert_eq!(held.alive(), Alive::Yes);
    child.kill().expect("kill the child by handle");
    child.wait().expect("reap it");
    assert_eq!(held.alive(), Alive::Gone);
    assert!(matches!(
        Pinned::from_pid(pid, Pin::Reopened),
        Err(PinError::PeerGone)
    ));
}

#[test]
fn a_descriptor_is_a_pidfd_of_the_pid_it_is_offered_for_or_it_is_refused() {
    let (a, _b) = UnixStream::pair().expect("a socketpair");
    // A socket is not a pidfd: its fdinfo has no `Pid:` line.
    assert!(matches!(
        Pinned::from_fd(a.into(), own_pid(), own_uid()),
        Err(PinError::Mismatch)
    ));
}
