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
