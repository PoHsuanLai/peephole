//! Small parsers for the text files of `/proc` and for what a sandbox writes about itself. Each
//! takes the text and returns what it states, or `None` when it states nothing usable.

use crate::facts::SandboxFacts;
use crate::ids::{Pid, Uid};

/// The effective user id in the text of `/proc/<pid>/status` (`Uid:` real, effective, saved, fs).
pub fn parse_status_euid(status: &str) -> Option<Uid> {
    let line = status.lines().find_map(|l| l.strip_prefix("Uid:"))?;
    line.split_whitespace().nth(1)?.parse().ok().map(Uid::new)
}

/// The process a pidfd refers to, from the text of `/proc/self/fdinfo/<fd>` (`Pid:`). A process
/// that has exited reads `-1`, which is `None`.
pub fn parse_fdinfo_pid(fdinfo: &str) -> Option<Pid> {
    let line = fdinfo.lines().find_map(|l| l.strip_prefix("Pid:"))?;
    Pid::new(line.trim().parse().ok()?)
}

/// What a Flatpak `.flatpak-info` key file states: `[Application] name`. `None` when it names
/// no application.
pub fn parse_flatpak_info(info: &str) -> Option<SandboxFacts> {
    let mut section = "";
    let mut app = None;
    for line in info.lines().map(str::trim) {
        if let Some(name) = line.strip_prefix('[').and_then(|l| l.strip_suffix(']')) {
            section = name;
            continue;
        }
        let Some((key, value)) = line.split_once('=') else {
            continue;
        };
        match (section, key.trim()) {
            ("Application", "name") => app = Some(value.trim().to_owned()),
            _ => {}
        }
    }
    Some(SandboxFacts::Flatpak {
        app: app.filter(|a| !a.is_empty())?,
    })
}

/// The snap a kernel security label names: the AppArmor label of a snap starts `snap.` (for
/// example `snap.firefox.firefox (enforce)`). The bus hands the label as bytes with a final NUL.
/// Other labels (SELinux contexts, `unconfined`) state no sandbox of ours.
pub fn parse_security_label(label: &[u8]) -> Option<SandboxFacts> {
    let end = label.iter().position(|b| *b == 0).unwrap_or(label.len());
    let text = std::str::from_utf8(&label[..end]).ok()?;
    let name = text.split(' ').next()?;
    name.starts_with("snap.").then(|| SandboxFacts::Snap {
        label: name.to_owned(),
    })
}
