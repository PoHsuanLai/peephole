//! The ids of the vocabulary. Each one is checked where it is made, so a value of the type is a
//! valid one and nothing downstream re-checks it.

use crate::error::IdError;
use serde::{Deserialize, Serialize};
use std::borrow::Cow;
use std::fmt;
use std::num::NonZeroU32;
use std::path::{Path, PathBuf};

/// The longest path accepted anywhere (the kernel's `PATH_MAX`).
const PATH_MAX: usize = 4096;

/// A process id: positive and representable as the kernel's signed `pid_t`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Pid(NonZeroU32);

impl Pid {
    /// The pid `raw`, or `None` for zero or a number the kernel cannot hold.
    pub const fn new(raw: u32) -> Option<Pid> {
        if raw > i32::MAX as u32 {
            return None;
        }
        match NonZeroU32::new(raw) {
            Some(n) => Some(Pid(n)),
            None => None,
        }
    }

    /// The number.
    pub const fn get(self) -> u32 {
        self.0.get()
    }
}

impl fmt::Display for Pid {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(&self.0, f)
    }
}

/// A user id.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Uid(u32);

impl Uid {
    /// The superuser.
    pub const ROOT: Uid = Uid(0);

    /// The user `raw`.
    pub const fn new(raw: u32) -> Uid {
        Uid(raw)
    }

    /// The number.
    pub const fn get(self) -> u32 {
        self.0
    }
}

impl fmt::Display for Uid {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(&self.0, f)
    }
}

fn all_bytes(text: &str, ok: impl Fn(u8) -> bool) -> bool {
    text.bytes().all(ok)
}

/// A systemd unit name: `<name>.service` or `<name>.scope`, at most 255 bytes, no `/`.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct UnitName(String);

impl UnitName {
    /// The longest unit name systemd accepts.
    pub const MAX_LEN: usize = 255;

    /// The unit named `text`.
    pub fn new(text: &str) -> Result<UnitName, IdError> {
        let stem = text
            .strip_suffix(".service")
            .or_else(|| text.strip_suffix(".scope"))
            .ok_or(IdError::new("unit name", "not a .service or .scope"))?;
        let plain = |b: u8| {
            b.is_ascii_alphanumeric() || matches!(b, b':' | b'-' | b'_' | b'.' | b'\\' | b'@')
        };
        if stem.is_empty() || text.len() > Self::MAX_LEN || !all_bytes(stem, plain) {
            return Err(IdError::new("unit name", "empty, too long or not plain"));
        }
        Ok(UnitName(text.to_owned()))
    }

    /// The name's text.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for UnitName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl TryFrom<String> for UnitName {
    type Error = IdError;
    fn try_from(text: String) -> Result<Self, IdError> {
        Self::new(&text)
    }
}

impl From<UnitName> for String {
    fn from(name: UnitName) -> String {
        name.0
    }
}

/// An application key: 1 to 255 bytes of `[A-Za-z0-9._-]` (a reverse-DNS id, a snap name).
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct AppKey(String);

impl AppKey {
    /// The longest key accepted.
    pub const MAX_LEN: usize = 255;

    /// The key `text`.
    pub fn new(text: &str) -> Result<AppKey, IdError> {
        let plain = |b: u8| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-');
        if text.is_empty() || text.len() > Self::MAX_LEN || !all_bytes(text, plain) {
            return Err(IdError::new("app key", "empty, too long or not plain"));
        }
        Ok(AppKey(text.to_owned()))
    }

    /// The key's text.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for AppKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl TryFrom<String> for AppKey {
    type Error = IdError;
    fn try_from(text: String) -> Result<Self, IdError> {
        Self::new(&text)
    }
}

impl From<AppKey> for String {
    fn from(key: AppKey) -> String {
        key.0
    }
}

/// A role name: 1 to 64 bytes of `[a-z0-9_]`. Roles come from the table and from code that names
/// the roles it accepts; a role is never read from a peer.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct RoleName(Cow<'static, str>);

impl RoleName {
    /// The longest role name accepted.
    pub const MAX_LEN: usize = 64;

    const fn plain(b: u8) -> bool {
        b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_'
    }

    /// The role `text`.
    pub fn new(text: &str) -> Result<RoleName, IdError> {
        if text.is_empty() || text.len() > Self::MAX_LEN || !all_bytes(text, Self::plain) {
            return Err(IdError::new(
                "role name",
                "empty, too long or not [a-z0-9_]",
            ));
        }
        Ok(RoleName(Cow::Owned(text.to_owned())))
    }

    /// A role written in code. Checked at compile time when used in a `const`, so a typo in a
    /// role constant is a build error.
    pub const fn from_static(text: &'static str) -> RoleName {
        let bytes = text.as_bytes();
        assert!(
            !bytes.is_empty() && bytes.len() <= Self::MAX_LEN,
            "a role is 1 to 64 bytes"
        );
        let mut i = 0;
        while i < bytes.len() {
            assert!(Self::plain(bytes[i]), "a role is [a-z0-9_]");
            i += 1;
        }
        RoleName(Cow::Borrowed(text))
    }

    /// The role's text.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for RoleName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl TryFrom<String> for RoleName {
    type Error = IdError;
    fn try_from(text: String) -> Result<Self, IdError> {
        Self::new(&text)
    }
}

impl From<RoleName> for String {
    fn from(role: RoleName) -> String {
        role.0.into_owned()
    }
}

/// The segments of an absolute path with no empty, `.` or `..` segment and no NUL, or `None`.
fn plain_segments(text: &str) -> Option<Vec<&str>> {
    let rest = text.strip_prefix('/')?;
    if text.len() > PATH_MAX || text.contains('\0') || rest.is_empty() {
        return None;
    }
    let segments: Vec<&str> = rest.split('/').collect();
    let clean = segments
        .iter()
        .all(|s| !s.is_empty() && *s != "." && *s != "..");
    clean.then_some(segments)
}

/// The path of a program's image: absolute, no `..`, no `.`, no empty segment and no
/// ` (deleted)` marker (the prober strips the marker and checks the inode instead).
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct ExePath(PathBuf);

impl ExePath {
    /// The path `text`.
    pub fn new(text: &str) -> Result<ExePath, IdError> {
        if plain_segments(text).is_none() || text.ends_with(" (deleted)") {
            return Err(IdError::new("image path", "not absolute and plain"));
        }
        Ok(ExePath(PathBuf::from(text)))
    }

    /// The path.
    pub fn as_path(&self) -> &Path {
        &self.0
    }

    /// The file's name.
    pub fn file_name(&self) -> Option<&str> {
        self.0.file_name().and_then(|n| n.to_str())
    }

    /// The path's text (always UTF-8: it was made from a `str`).
    pub fn to_text(&self) -> String {
        self.0.to_string_lossy().into_owned()
    }
}

impl TryFrom<String> for ExePath {
    type Error = IdError;
    fn try_from(text: String) -> Result<Self, IdError> {
        Self::new(&text)
    }
}

impl From<ExePath> for String {
    fn from(path: ExePath) -> String {
        path.to_text()
    }
}

/// An image path pattern: absolute, at most one `*` per segment, never `**`. A `*` stands for
/// any run of characters inside one segment.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct ExePattern(String);

impl ExePattern {
    /// The pattern `text`.
    pub fn new(text: &str) -> Result<ExePattern, IdError> {
        let segments =
            plain_segments(text).ok_or(IdError::new("image pattern", "not absolute and plain"))?;
        if segments.iter().any(|s| s.matches('*').count() > 1) {
            return Err(IdError::new(
                "image pattern",
                "more than one `*` in a segment",
            ));
        }
        Ok(ExePattern(text.to_owned()))
    }

    /// The pattern's text.
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Whether `path` is one of the paths the pattern describes: the same number of segments,
    /// each equal, or equal around its one `*`.
    pub fn matches(&self, path: &ExePath) -> bool {
        let text = path.to_text();
        let (Some(pat), Some(real)) = (plain_segments(&self.0), plain_segments(&text)) else {
            return false;
        };
        pat.len() == real.len() && pat.iter().zip(&real).all(|(p, r)| segment_matches(p, r))
    }
}

fn segment_matches(pattern: &str, segment: &str) -> bool {
    match pattern.split_once('*') {
        None => pattern == segment,
        Some((head, tail)) => {
            segment.len() >= head.len() + tail.len()
                && segment.starts_with(head)
                && segment.ends_with(tail)
        }
    }
}

impl TryFrom<String> for ExePattern {
    type Error = IdError;
    fn try_from(text: String) -> Result<Self, IdError> {
        Self::new(&text)
    }
}

impl From<ExePattern> for String {
    fn from(pattern: ExePattern) -> String {
        pattern.0
    }
}
