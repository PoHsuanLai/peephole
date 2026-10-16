//! A process's place in the cgroup tree, and the unit names that path spells.

use crate::error::IdError;
use crate::ids::{AppKey, UnitName};

/// The cgroup path of a process: absolute, on one line.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct CgroupPath(String);

impl CgroupPath {
    /// The path `text`.
    pub fn new(text: &str) -> Result<CgroupPath, IdError> {
        if text.starts_with('/') && !text.contains(['\n', '\0']) {
            Ok(CgroupPath(text.to_owned()))
        } else {
            Err(IdError::new("cgroup path", "not absolute on one line"))
        }
    }

    /// The unified-hierarchy path in `contents`, the text of `/proc/<pid>/cgroup`. A system with
    /// only version 1 hierarchies has no such line, and the contents are refused.
    pub fn from_proc(contents: &str) -> Result<CgroupPath, IdError> {
        contents
            .lines()
            .find_map(|line| line.strip_prefix("0::"))
            .ok_or(IdError::new("cgroup path", "no unified hierarchy line"))
            .and_then(Self::new)
    }

    /// The path's text.
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// The path's components, root first.
    pub fn segments(&self) -> impl Iterator<Item = &str> {
        self.0.split('/').filter(|s| !s.is_empty())
    }

    /// The last component: the unit, or the delegated child of one, the process sits in.
    pub fn leaf(&self) -> &str {
        self.0.rsplit('/').next().unwrap_or_default()
    }

    /// The leaf as a unit name, when it is one.
    pub fn unit_leaf(&self) -> Option<UnitName> {
        UnitName::new(self.leaf()).ok()
    }
}

/// `text` as a systemd unit-name component: a byte other than `[A-Za-z0-9:_]`, or a `.` at the
/// start, becomes `\xHH` (so `-` becomes `\x2d` and a dash in a unit name is a separator).
pub fn escape_unit(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    for (i, byte) in text.bytes().enumerate() {
        let plain =
            byte.is_ascii_alphanumeric() || matches!(byte, b':' | b'_') || (byte == b'.' && i > 0);
        if plain {
            out.push(char::from(byte));
        } else {
            out.push_str(&format!("\\x{byte:02x}"));
        }
    }
    out
}

/// `text` with its `\xHH` escapes undone, or `None` for a broken escape or non-UTF-8 result.
pub fn unescape_unit(text: &str) -> Option<String> {
    let mut bytes = Vec::with_capacity(text.len());
    let mut rest = text.as_bytes();
    while let Some((&first, tail)) = rest.split_first() {
        rest = match (first, tail) {
            (b'\\', [b'x', high, low, after @ ..]) => {
                bytes.push((hex(*high)? << 4) | hex(*low)?);
                after
            }
            (b'\\', _) => return None,
            _ => {
                bytes.push(first);
                tail
            }
        };
    }
    String::from_utf8(bytes).ok()
}

fn hex(byte: u8) -> Option<u8> {
    char::from(byte)
        .to_digit(16)
        .and_then(|d| u8::try_from(d).ok())
}

/// The launcher tag Flatpak writes into its own scopes' names.
const FLATPAK_LAUNCHER: &str = "flatpak";

fn is_word(text: &str) -> bool {
    !text.is_empty() && text.bytes().all(|b| b.is_ascii_alphanumeric())
}

/// The app a launcher's scope names, as a **claim**: `app-[<launcher>-]<id>-<n>.scope` anywhere
/// in the path. Anyone may run `systemd-run --user --scope -u app-<id>-1`, so this is for display
/// and grouping, never for authorisation. Flatpak's own scopes name nobody here.
pub fn scope_app(cgroup: &CgroupPath) -> Option<AppKey> {
    cgroup.segments().find_map(|segment| {
        let unit = segment.strip_prefix("app-")?.strip_suffix(".scope")?;
        let parts: Vec<&str> = unit.split('-').collect();
        let (id, random) = match parts.as_slice() {
            [id, random] => (*id, *random),
            [launcher, id, random] if is_word(launcher) && *launcher != FLATPAK_LAUNCHER => {
                (*id, *random)
            }
            _ => return None,
        };
        if !is_word(random) {
            return None;
        }
        AppKey::new(&unescape_unit(id)?).ok()
    })
}

/// Whether the path holds the scope Flatpak makes for a run of `app`:
/// `app-flatpak-<escaped id>-<number>.scope`.
pub fn flatpak_scope_in(cgroup: &CgroupPath, app: &AppKey) -> bool {
    let prefix = format!("app-{FLATPAK_LAUNCHER}-{}-", escape_unit(app.as_str()));
    cgroup.segments().any(|segment| {
        segment
            .strip_prefix(&prefix)
            .and_then(|rest| rest.strip_suffix(".scope"))
            .is_some_and(|n| !n.is_empty() && n.bytes().all(|b| b.is_ascii_digit()))
    })
}
