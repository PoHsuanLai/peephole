//! The ownership walk: a path is only as trustworthy as the least-trusted directory above it.

use crate::procfs::{Follow, ProcFs};
use peephole_core::FileTrust;
use std::io;
use std::path::Path;

/// The most directories walked above one file. A path deeper than this is refused rather than
/// walked: the walk is a handful of `lstat`s, bounded.
pub const WALK_MAX: usize = 32;

/// The trust of the directories above `path`, root first, stopping at the first one that is not
/// root-only. `Err(InvalidData)` for a path deeper than [`WALK_MAX`].
pub fn dirs_trust<P: ProcFs + ?Sized>(fs: &P, path: &Path) -> io::Result<FileTrust> {
    let mut above: Vec<&Path> = path.ancestors().skip(1).collect();
    if above.len() > WALK_MAX {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "path too deep"));
    }
    above.reverse();
    for dir in above {
        match fs.trust_of(dir, Follow::No)? {
            FileTrust::RootOnly => {}
            writable => return Ok(writable),
        }
    }
    Ok(FileTrust::RootOnly)
}

/// The trust of `path` itself and of every directory above it: the weaker of the two. Either
/// look failing fails the whole (`Err(InvalidData)` for a path deeper than [`WALK_MAX`]).
pub fn path_trust<P: ProcFs + ?Sized>(fs: &P, path: &Path) -> io::Result<FileTrust> {
    let file = fs.trust_of(path, Follow::No)?;
    Ok(dirs_trust(fs, path)?.weaker(file))
}
