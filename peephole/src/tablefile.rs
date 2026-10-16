//! Loading the caller table from the root-owned files that ship it. peephole reads no user file:
//! nothing a person's file says makes a process more trusted.

use crate::error::LoadError;
use crate::procfs::ProcFs;
use crate::walk::{dirs_trust, weaker};
use peephole_core::{FileTrust, Table};
use std::io;
use std::path::{Path, PathBuf};

/// The largest table file read.
pub const TABLE_FILE_CAP: u64 = 64 * 1024;
/// The most files read from the drop-in directory.
pub const DROP_IN_FILES_MAX: usize = 64;

/// Where the table lives: one main file and a directory of additions.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TableFiles {
    main: PathBuf,
    drop_ins: PathBuf,
}

impl TableFiles {
    /// A table in `main`, with additions in the `*.toml` files of `drop_ins`.
    pub fn new(main: PathBuf, drop_ins: PathBuf) -> TableFiles {
        TableFiles { main, drop_ins }
    }

    /// The desktop's own place: `/etc/quire/desktop-callers.toml` and `/etc/quire/desktop-callers.d`.
    pub fn desktop() -> TableFiles {
        TableFiles::new(
            PathBuf::from("/etc/quire/desktop-callers.toml"),
            PathBuf::from("/etc/quire/desktop-callers.d"),
        )
    }

    /// The table: the main file, then the drop-ins in name order, merged so that the main file's
    /// units win. Any file that is not root-only (the file or a directory above it is writable by
    /// anyone else), is unreadable, or is not a table, fails the whole load: the caller then runs
    /// with [`Table::empty`], where nobody is a service.
    pub fn load<P: ProcFs>(&self, fs: &P) -> Result<Table, LoadError> {
        let mut table = read_table(fs, &self.main)?;
        for path in self.drop_in_files(fs)? {
            table = table.merge(read_table(fs, &path)?);
        }
        Ok(table)
    }

    fn drop_in_files<P: ProcFs>(&self, fs: &P) -> Result<Vec<PathBuf>, LoadError> {
        let mut files = match fs.list_dir(&self.drop_ins) {
            Ok(files) => files,
            Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(Vec::new()),
            Err(source) => return Err(unreadable(&self.drop_ins, source)),
        };
        files.retain(|p| p.extension().is_some_and(|e| e == "toml"));
        files.sort();
        files.truncate(DROP_IN_FILES_MAX);
        Ok(files)
    }
}

pub(crate) fn unreadable(path: &Path, source: io::Error) -> LoadError {
    LoadError::Unreadable {
        path: path.display().to_string(),
        source,
    }
}

fn read_table<P: ProcFs>(fs: &P, path: &Path) -> Result<Table, LoadError> {
    let file = fs.trust_of(path).map_err(|e| unreadable(path, e))?;
    let dirs = dirs_trust(fs, path).map_err(|e| unreadable(path, e))?;
    if weaker(dirs, file) != FileTrust::RootOnly {
        return Err(LoadError::NotRootOnly {
            path: path.display().to_string(),
        });
    }
    let text = read_text(fs, path)?;
    Table::from_toml(&text).map_err(|source| LoadError::Table {
        path: path.display().to_string(),
        source,
    })
}

/// The text of the table file `path`, within [`TABLE_FILE_CAP`] and UTF-8.
pub(crate) fn read_text<P: ProcFs>(fs: &P, path: &Path) -> Result<String, LoadError> {
    let bytes = fs
        .read_file_capped(path, TABLE_FILE_CAP)
        .map_err(|e| unreadable(path, e))?;
    String::from_utf8(bytes).map_err(|_| {
        unreadable(
            path,
            io::Error::new(io::ErrorKind::InvalidData, "not UTF-8"),
        )
    })
}
