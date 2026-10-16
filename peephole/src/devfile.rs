//! Loading a developer rows file (feature `dev-rows`). The file is the person's own, so unlike the
//! shipped table it is not root-only; it is still a plain file, not a link, and nobody else can
//! write it. Its rows are `Proof::Dev` at best (see `peephole_core::Proof::Dev`).

use crate::error::LoadError;
use crate::procfs::ProcFs;
use crate::tablefile::{TableFiles, read_text, unreadable};
use peephole_core::{Table, Uid};
use std::path::Path;

/// What a path is, without following a final link.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum NodeKind {
    /// A plain file.
    File,
    /// A symbolic link.
    Link,
    /// A directory or anything else.
    Other,
}

/// What a file-system view says of a path itself: kind, owner and permission bits.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub struct NodeInfo {
    /// What the path is.
    pub kind: NodeKind,
    /// The user that owns it.
    pub owner: Uid,
    /// Its permission bits (`st_mode`).
    pub mode: u32,
}

/// Group and others may write: a file with either bit is not one person's.
const SHARED_WRITE: u32 = 0o022;

impl TableFiles {
    /// Only with feature `dev-rows`: the developer rows in `path`, every row marked
    /// `RowOrigin::Dev`. The file must be a plain file (a link is refused), owned by `person` or
    /// by root, and not writable by group or others; it is read within [`crate::TABLE_FILE_CAP`]
    /// bytes. Any other state fails the whole load, and the caller then has no developer rows.
    /// Merge the result after the shipped table: `shipped.merge(rows)`.
    pub fn load_dev<P: ProcFs>(fs: &P, path: &Path, person: Uid) -> Result<Table, LoadError> {
        let info = fs.info_of(path).map_err(|e| unreadable(path, e))?;
        if info.kind != NodeKind::File {
            return Err(LoadError::NotAFile {
                path: path.display().to_string(),
            });
        }
        let theirs = info.owner == person || info.owner == Uid::ROOT;
        if !theirs || info.mode & SHARED_WRITE != 0 {
            return Err(LoadError::NotTheirs {
                path: path.display().to_string(),
            });
        }
        let text = read_text(fs, path)?;
        Table::from_toml_dev(&text).map_err(|source| LoadError::Table {
            path: path.display().to_string(),
            source,
        })
    }
}
