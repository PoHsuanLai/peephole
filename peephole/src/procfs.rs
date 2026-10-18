//! The file system as the prober sees it: `/proc` and the files its answers point at. A trait,
//! so the tests read a fixture tree and the real one reads the kernel.

#[cfg(feature = "dev-rows")]
use crate::devfile::{NodeInfo, NodeKind};
use peephole_core::Uid;
use peephole_core::{FileTrust, Writer};
use std::io::{self, Read};
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};

/// Whether [`ProcFs::trust_of`] looks at a final link itself or at what it points to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Follow {
    /// The path itself: a final link is not followed.
    No,
    /// The file behind the path, taken from the open inode (so a deleted image is judged by the
    /// file that is running, not by whatever is at its path).
    Yes,
}

/// The file-system view the prober and the table loader read through.
///
/// Every path is a path of the file system. The process files live under [`ProcFs::proc_root`]
/// (`<root>/1234/cgroup`). Callers build every path themselves from numbers and fixed names;
/// nothing here is handed a path by a peer.
pub trait ProcFs: Send + Sync {
    /// Where `/proc` is mounted: the system's, or a fixture's.
    fn proc_root(&self) -> &Path;
    /// The bytes of the file `path`, failing with `InvalidData` over `cap` bytes.
    fn read_capped(&self, path: &Path, cap: u64) -> io::Result<Vec<u8>>;
    /// Where the link `path` points.
    fn read_link(&self, path: &Path) -> io::Result<PathBuf>;
    /// The trust of `path`, looking at a final link or through it as `follow` says.
    fn trust_of(&self, path: &Path, follow: Follow) -> io::Result<FileTrust>;
    /// The entries of the directory `path`, as paths.
    fn list_dir(&self, path: &Path) -> io::Result<Vec<PathBuf>>;
    /// Only with feature `dev-rows`: what the path `path` itself is (a final link is not
    /// followed), who owns it and its permission bits. The default refuses, so a view that does
    /// not know cannot load a developer file.
    #[cfg(feature = "dev-rows")]
    fn info_of(&self, _path: &Path) -> io::Result<NodeInfo> {
        Err(io::Error::from(io::ErrorKind::Unsupported))
    }
}

/// The trust of a file owned by `uid` with permission bits `mode`: root-only when root owns it
/// and neither group nor others can write.
pub fn trust_of_mode(uid: u32, mode: u32) -> FileTrust {
    const GROUP_WRITE: u32 = 0o020;
    const OTHER_WRITE: u32 = 0o002;
    if uid != 0 {
        FileTrust::Writable(Writer::Owner(Uid::new(uid)))
    } else if mode & OTHER_WRITE != 0 {
        FileTrust::Writable(Writer::Other)
    } else if mode & GROUP_WRITE != 0 {
        FileTrust::Writable(Writer::Group)
    } else {
        FileTrust::RootOnly
    }
}

fn trust_of_meta(meta: &std::fs::Metadata) -> FileTrust {
    trust_of_mode(meta.uid(), meta.mode())
}

fn capped(path: &Path, cap: u64) -> io::Result<Vec<u8>> {
    let mut bytes = Vec::new();
    std::fs::File::open(path)?
        .take(cap.saturating_add(1))
        .read_to_end(&mut bytes)?;
    if u64::try_from(bytes.len()).is_ok_and(|n| n > cap) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "larger than the cap",
        ));
    }
    Ok(bytes)
}

/// The real thing: a `/proc` mount and the machine's file system.
#[derive(Debug, Clone)]
pub struct RealProc {
    root: PathBuf,
}

impl RealProc {
    /// The system's `/proc`: the one fixed path of the crate, named here and nowhere else.
    pub fn system() -> RealProc {
        RealProc {
            root: PathBuf::from("/proc"),
        }
    }

    /// A `/proc` mounted at `root`.
    pub fn at(root: PathBuf) -> RealProc {
        RealProc { root }
    }
}

impl ProcFs for RealProc {
    fn proc_root(&self) -> &Path {
        &self.root
    }

    fn read_capped(&self, path: &Path, cap: u64) -> io::Result<Vec<u8>> {
        capped(path, cap)
    }

    fn read_link(&self, path: &Path) -> io::Result<PathBuf> {
        std::fs::read_link(path)
    }

    fn trust_of(&self, path: &Path, follow: Follow) -> io::Result<FileTrust> {
        match follow {
            Follow::No => std::fs::symlink_metadata(path),
            Follow::Yes => std::fs::metadata(path),
        }
        .map(|m| trust_of_meta(&m))
    }

    fn list_dir(&self, path: &Path) -> io::Result<Vec<PathBuf>> {
        std::fs::read_dir(path)?
            .map(|entry| entry.map(|e| e.path()))
            .collect()
    }

    #[cfg(feature = "dev-rows")]
    fn info_of(&self, path: &Path) -> io::Result<NodeInfo> {
        let meta = std::fs::symlink_metadata(path)?;
        let kind = match meta.file_type() {
            t if t.is_symlink() => NodeKind::Link,
            t if t.is_file() => NodeKind::File,
            _ => NodeKind::Other,
        };
        Ok(NodeInfo {
            kind,
            owner: Uid::new(meta.uid()),
            mode: meta.mode(),
        })
    }
}
