//! "The owner of this name must hold this role", and the watch for the name changing hands.

use crate::bus::{PrivateBus, name_of};
use peephole::FixtureProc;
use peephole::fake::introduced_service;
use peephole_bus::{BusPeers, ManagerCheck};
use peephole_core::{Pin, Proof, Refused, Requirement, RoleName, Table};

const NAME: &str = "org.example.Shell";

fn shell() -> RoleName {
    RoleName::new("shell").expect("a role")
}

fn peers(asker: zbus::Connection) -> BusPeers<FixtureProc> {
    BusPeers::with_proc(
        asker,
        Table::empty(),
        ManagerCheck::Unchecked,
        FixtureProc::new(),
    )
}

#[test]
fn a_name_nobody_owns_passes_nothing() {
    zbus::block_on(async {
        let bus = PrivateBus::start();
        let peers = peers(bus.connect().await);
        let need = [Requirement::new(shell(), Proof::Exe)];
        assert_eq!(
            peers.owner_of(NAME, &need).await.err(),
            Some(Refused::Unknown)
        );
        assert_eq!(
            peers.owner_of("not a name", &need).await.err(),
            Some(Refused::Unknown)
        );
    });
}

#[test]
fn the_owner_must_hold_the_role_and_is_returned_by_its_unique_name() {
    zbus::block_on(async {
        let bus = PrivateBus::start();
        let (owner, squatter, asker) = (
            bus.connect().await,
            bus.connect().await,
            bus.connect().await,
        );
        owner.request_name(NAME).await.expect("take the name");
        let peers = peers(asker);
        let need = [Requirement::new(shell(), Proof::Exe)];
        // The owner is not the shell: an empty table and an empty tree make it nobody.
        assert_eq!(
            peers.owner_of(NAME, &need).await.err(),
            Some(Refused::Unknown)
        );
        let standing = introduced_service("org.quire.Shell", "shell", Proof::Full, Pin::AtConnect)
            .expect("valid");
        peers.introduce(&name_of(&owner), standing.clone());
        let got = peers
            .owner_of(NAME, &need)
            .await
            .expect("the shell owns the name");
        assert_eq!(got.as_str(), name_of(&owner));
        // A connection that introduced itself but does not own the name changes nothing.
        peers.introduce(&name_of(&squatter), standing);
        let got = peers.owner_of(NAME, &need).await.expect("still the owner");
        assert_eq!(got.as_str(), name_of(&owner));
    });
}

#[test]
fn a_watch_sees_the_name_change_hands() {
    zbus::block_on(async {
        let bus = PrivateBus::start();
        let (first, asker) = (bus.connect().await, bus.connect().await);
        let peers = peers(asker);
        let mut watch = peers.watch_owner(NAME).await.expect("subscribed");
        first.request_name(NAME).await.expect("take the name");
        assert_eq!(watch.changed().await, Some(()));
        first.release_name(NAME).await.expect("release the name");
        assert_eq!(watch.changed().await, Some(()));
    });
}
