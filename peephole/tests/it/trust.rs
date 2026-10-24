//! The mode bits that make a file root-only.

use peephole::trust_of_mode;
use peephole_core::{FileTrust, Uid, Writer};

#[test]
fn only_root_owned_files_nobody_else_can_write_are_root_only() {
    let cases = [
        (0, 0o755, FileTrust::RootOnly),
        (0, 0o644, FileTrust::RootOnly),
        (0, 0o775, FileTrust::Writable(Writer::Group)),
        (0, 0o664, FileTrust::Writable(Writer::Group)),
        (0, 0o757, FileTrust::Writable(Writer::Other)),
        // A sticky world-writable directory such as /tmp is still writable.
        (0, 0o1777, FileTrust::Writable(Writer::Other)),
        (
            1000,
            0o755,
            FileTrust::Writable(Writer::Owner(Uid::new(1000))),
        ),
        (
            1000,
            0o555,
            FileTrust::Writable(Writer::Owner(Uid::new(1000))),
        ),
    ];
    for (uid, mode, want) in cases {
        assert_eq!(trust_of_mode(uid, mode), want, "uid {uid} mode {mode:o}");
    }
}

/// A user service's namespace (`PrivateUsers=self`) maps only the person: root's files show as
/// the overflow uid and are taken as root's there, and nowhere else.
#[test]
fn the_overflow_uid_is_root_only_where_root_is_not_mapped() {
    use peephole::OwnerView;
    let unmapped = OwnerView::RootUnmapped { overflow: 65534 };
    // name, uid_map, overflowuid, want
    let views = [
        (
            "the initial namespace",
            "         0          0 4294967295\n",
            "65534\n",
            OwnerView::AsSeen,
        ),
        (
            "a user service: only the person",
            "      1000       1000          1\n",
            "65534\n",
            unmapped,
        ),
        (
            "a container that maps its own root elsewhere and not the real one",
            "         0     100000        100\n      1000       1000          1\n",
            "65534\n",
            unmapped,
        ),
        (
            "a container whose own range holds the overflow uid",
            "         0     100000      65536\n",
            "65534\n",
            OwnerView::AsSeen,
        ),
        (
            "root mapped in a second line",
            "      1000       1000          1\n         0          0          1\n",
            "65534\n",
            OwnerView::AsSeen,
        ),
        (
            "the overflow uid is a real account here",
            "      1000       1000          1\n     65534      65534          1\n",
            "65534\n",
            OwnerView::AsSeen,
        ),
        ("an unreadable map", "", "65534\n", OwnerView::AsSeen),
        ("a garbled map", "0 0\n", "65534\n", OwnerView::AsSeen),
        (
            "an unreadable overflow uid",
            "      1000       1000          1\n",
            "",
            OwnerView::AsSeen,
        ),
    ];
    for (name, uid_map, overflow, want) in views {
        assert_eq!(OwnerView::of(uid_map, overflow), want, "{name}");
    }
    // name, view, uid, mode, want
    let files = [
        (
            "root's file in a user service",
            unmapped,
            65534,
            0o755,
            FileTrust::RootOnly,
        ),
        (
            "group-writable still shows through",
            unmapped,
            65534,
            0o775,
            FileTrust::Writable(Writer::Group),
        ),
        (
            "the person's file is still theirs",
            unmapped,
            1000,
            0o755,
            FileTrust::Writable(Writer::Owner(Uid::new(1000))),
        ),
        (
            "65534 in the initial namespace is nobody",
            OwnerView::AsSeen,
            65534,
            0o755,
            FileTrust::Writable(Writer::Owner(Uid::new(65534))),
        ),
    ];
    for (name, view, uid, mode, want) in files {
        assert_eq!(trust_of_mode(view.owner(uid), mode), want, "{name}");
    }
}
