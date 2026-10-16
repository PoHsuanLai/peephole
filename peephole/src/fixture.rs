//! A tree standing for `/proc` and for the file system, for tests: files with owners, links,
//! directories, and a builder for a whole fake process.

use crate::procfs::ProcFs;
use peephole_core::{FileTrust, Pid};
use std::collections::BTreeMap;
use std::io;
use std::path::{Path, PathBuf};

const PROC: &str = "/proc";

#[derive(Debug, Clone)]
enum Node {
    File {
        bytes: Vec<u8>,
        trust: FileTrust,
    },
    Dir {
        trust: FileTrust,
    },
    /// A link; `followed` is the trust of the open inode when it differs from the target path's
    /// (a deleted image).
    Link {
        target: PathBuf,
        followed: Option<FileTrust>,
    },
    /// A node the reader may not look at.
    Denied,
}

/// An in-memory tree. Paths are absolute; `/proc/<pid>/...` is what the prober reads as
/// proc-relative `<pid>/...`.
#[derive(Debug, Clone, Default)]
pub struct FixtureProc {
    nodes: BTreeMap<PathBuf, Node>,
}

/// How a fake process's image appears.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FixtureImage<'a> {
    /// A file at `path` with the given trust (the directories above it default to root-only,
    /// unless the tree already names them).
    Present(&'a str, FileTrust),
    /// The file was replaced or removed: the link reads `<path> (deleted)` and the open inode has
    /// the given trust.
    Deleted(&'a str, FileTrust),
    /// The link reads a path this tree has no file for (a path of another mount namespace).
    Elsewhere(&'a str),
    /// The link cannot be read.
    Hidden,
}

/// One fake process of a [`FixtureProc`].
#[derive(Debug, Clone)]
pub struct FixtureProcess<'a> {
    /// The process number.
    pub pid: Pid,
    /// The text of its `/proc/<pid>/cgroup` (`0::/user.slice/...`).
    pub cgroup: &'a str,
    /// Its image.
    pub image: FixtureImage<'a>,
    /// The text of its `/.flatpak-info`, when it is in a Flatpak sandbox.
    pub flatpak_info: Option<&'a str>,
}

impl FixtureProc {
    /// An empty tree.
    pub fn new() -> FixtureProc {
        FixtureProc::default()
    }

    /// A directory with the given trust.
    pub fn dir(mut self, abs: &str, trust: FileTrust) -> FixtureProc {
        self.nodes.insert(PathBuf::from(abs), Node::Dir { trust });
        self
    }

    /// A file with the given contents and trust. Directories above it that the tree does not
    /// name yet are made root-only.
    pub fn file(mut self, abs: &str, bytes: impl Into<Vec<u8>>, trust: FileTrust) -> FixtureProc {
        self = self.ensure_dirs(abs);
        self.nodes.insert(
            PathBuf::from(abs),
            Node::File {
                bytes: bytes.into(),
                trust,
            },
        );
        self
    }

    /// Adds the process `process`.
    pub fn process(mut self, process: FixtureProcess<'_>) -> FixtureProc {
        let base = format!("{PROC}/{}", process.pid);
        self = self.file(
            &format!("{base}/cgroup"),
            process.cgroup.as_bytes(),
            FileTrust::RootOnly,
        );
        if let Some(info) = process.flatpak_info {
            self = self.file(
                &format!("{base}/root/.flatpak-info"),
                info.as_bytes(),
                FileTrust::RootOnly,
            );
        }
        let exe = PathBuf::from(format!("{base}/exe"));
        match process.image {
            FixtureImage::Present(path, trust) => {
                self = self.file(path, Vec::new(), trust);
                self.nodes.insert(
                    exe,
                    Node::Link {
                        target: PathBuf::from(path),
                        followed: None,
                    },
                );
            }
            FixtureImage::Deleted(path, trust) => {
                self = self.ensure_dirs(path);
                let target = PathBuf::from(format!("{path} (deleted)"));
                self.nodes.insert(
                    exe,
                    Node::Link {
                        target,
                        followed: Some(trust),
                    },
                );
            }
            FixtureImage::Elsewhere(path) => {
                self.nodes.insert(
                    exe,
                    Node::Link {
                        target: PathBuf::from(path),
                        followed: None,
                    },
                );
            }
            FixtureImage::Hidden => {
                self.nodes.insert(exe, Node::Denied);
                // As the kernel does for another user's process: its root is closed too.
                if process.flatpak_info.is_none() {
                    self.nodes.insert(
                        PathBuf::from(format!("{base}/root/.flatpak-info")),
                        Node::Denied,
                    );
                }
            }
        }
        self
    }

    fn ensure_dirs(mut self, abs: &str) -> FixtureProc {
        for ancestor in Path::new(abs).ancestors().skip(1) {
            self.nodes
                .entry(ancestor.to_path_buf())
                .or_insert(Node::Dir {
                    trust: FileTrust::RootOnly,
                });
        }
        self
    }

    fn node(&self, abs: &Path) -> io::Result<&Node> {
        self.nodes
            .get(abs)
            .ok_or_else(|| io::Error::from(io::ErrorKind::NotFound))
    }

    fn proc_node(&self, rel: &Path) -> io::Result<&Node> {
        self.node(&Path::new(PROC).join(rel))
    }

    fn trust_of_node(&self, node: &Node) -> io::Result<FileTrust> {
        match node {
            Node::File { trust, .. } | Node::Dir { trust } => Ok(*trust),
            Node::Link { target, followed } => match followed {
                Some(trust) => Ok(*trust),
                None => self.trust_of_node(self.node(target)?),
            },
            Node::Denied => Err(io::Error::from(io::ErrorKind::PermissionDenied)),
        }
    }
}

fn bytes_of(node: &Node, cap: u64) -> io::Result<Vec<u8>> {
    match node {
        Node::File { bytes, .. } if u64::try_from(bytes.len()).is_ok_and(|n| n <= cap) => {
            Ok(bytes.clone())
        }
        Node::File { .. } => Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "larger than the cap",
        )),
        Node::Denied => Err(io::Error::from(io::ErrorKind::PermissionDenied)),
        _ => Err(io::Error::from(io::ErrorKind::InvalidInput)),
    }
}

impl ProcFs for FixtureProc {
    fn read_capped(&self, rel: &Path, cap: u64) -> io::Result<Vec<u8>> {
        bytes_of(self.proc_node(rel)?, cap)
    }

    fn readlink(&self, rel: &Path) -> io::Result<PathBuf> {
        match self.proc_node(rel)? {
            Node::Link { target, .. } => Ok(target.clone()),
            Node::Denied => Err(io::Error::from(io::ErrorKind::PermissionDenied)),
            _ => Err(io::Error::from(io::ErrorKind::InvalidInput)),
        }
    }

    fn trust_of(&self, abs: &Path) -> io::Result<FileTrust> {
        self.trust_of_node(self.node(abs)?)
    }

    fn trust_of_followed(&self, rel: &Path) -> io::Result<FileTrust> {
        self.trust_of_node(self.proc_node(rel)?)
    }

    fn read_file_capped(&self, abs: &Path, cap: u64) -> io::Result<Vec<u8>> {
        bytes_of(self.node(abs)?, cap)
    }

    fn list_dir(&self, abs: &Path) -> io::Result<Vec<PathBuf>> {
        match self.node(abs)? {
            Node::Dir { .. } => Ok(self
                .nodes
                .keys()
                .filter(|p| p.parent() == Some(abs))
                .cloned()
                .collect()),
            _ => Err(io::Error::from(io::ErrorKind::InvalidInput)),
        }
    }
}
