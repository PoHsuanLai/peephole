# Architecture

peephole answers one question for a Linux desktop service: which program is on the other end of
this connection? It holds the caller by a pidfd, reads what `/proc` says of it afterwards, asks the
systemd manager about its unit when the table names one, and judges the result against a
root-owned table of the desktop's own programs. Consumers (a compositor, a portal backend, an
updater, a root input service) then say which roles a method accepts.

## 1. Crates and allowed edges

| Crate | Layer | Contents | Depends on |
| --- | --- | --- | --- |
| `peephole-core` | pure | ids, `Table` (TOML codec), `Facts`, `Standing`, `judge`, `Requirement`, `Refused`, the text parsers of `procinfo`, the `roles` constants (feature `desktop`) | serde, toml, thiserror |
| `peephole` | sync I/O | `Pinned` (pidfd), `ProcFs` (`RealProc`; the fixture tree under `fake`), `Prober`, the ownership walk, `TableFiles` (the loader), `fake` | peephole-core, rustix, thiserror |
| `peephole-bus` | async adapter | `BusPeers`: credentials, the manager's unit facts (`UnitSource`, `ManagerLink`), `require`, `owner_of`, `watch_owner`, `Offload` | peephole, peephole-core, zbus 5, futures-timer, thiserror |

`peephole-core` reaches no bus, system-call layer, runtime or executor; `peephole` reaches no bus or
executor (`scripts/check-boundary.sh`). Every crate sets `unsafe_code = "forbid"`: the pidfd comes
from rustix.

## 2. Layout

```
peephole-core/src/{lib, ids, cgroup, procinfo, facts, standing, requirement, table, judge, error, roles}.rs
peephole/src/{lib, pin, unix, procfs, probe, walk, tablefile, error, fixture, fake}.rs
peephole-bus/src/{lib, who, owner, manager, offload, timeout, error}.rs
dist/desktop-callers.toml   scripts/check-boundary.sh   deny.toml   .github/workflows/ci.yml
```

`fixture.rs` and `fake.rs` exist only with feature `fake`.

## 3. The trust rules

A `Pinned` peer is a process held by a pidfd. Everything read from `/proc/<pid>` is read after
pinning, and the pidfd is checked to be still alive at the end (`Pinned::alive()` polls it: readable
means exited). A process cannot be replaced while it is alive, so the facts belong to the pinned
process. A peer gone before the facts are read is `Unverified { why: PeerGone }`.

How the pin is obtained:

| Source | Pin | Strength | Made by |
|---|---|---|---|
| bus, the daemon offers `ProcessFD` in `GetConnectionCredentials` | that fd, checked against the reported pid by its `fdinfo` | `AtConnect` | `peephole-bus` |
| bus, no `ProcessFD` | `pidfd_open(ProcessID)` at once, then the credentials are asked again: same pid and user | `Reopened` | `peephole-bus` |
| unix socket | `SO_PEERCRED` pid, `pidfd_open`, `SO_PEERCRED` again | `Reopened` | `Pinned::of_stream` |
| a descriptor the caller holds | the fd, checked against the offered pid by its `fdinfo` | `AtConnect` | `Pinned::from_fd` |

`SO_PEERPIDFD` (kernel 6.5) would make a socket's pin `AtConnect`. rustix 1.1 has no safe wrapper for
it and the crates forbid `unsafe`, so `of_stream` makes the reopened pin; see FINDINGS. A `Requirement`
may demand `AtConnect`; a consumer of a socket that does must wait for that item.

The proof ladder (`Proof`, ordered `Cgroup < Exe < Full`; with feature `dev-rows`, `Dev < Cgroup < Exe < Full`, see section 8):

1. `Cgroup`: pinned, the cgroup path is read and its leaf names a unit the table has. Reachable only
   when the image cannot be read. A same-user process can move itself into a delegated cgroup: a
   speed bump, never a boundary.
2. `Exe`: the image is read (`readlink /proc/<pid>/exe`, a ` (deleted)` suffix stripped and the file
   judged through the open `/proc/<pid>/exe` inode), the file and every directory above it are
   root-owned and not group or world writable (the walk stops at the first directory that is not;
   at most 32 components), and the path matches one of the row's `exe` patterns.
3. `Full`: `Exe`, and the unit is real: the manager says `MainPID == pid`, the fragment is under
   root-owned directories and is root-owned, every drop-in is root-owned, `Transient == false`,
   `LoadState == loaded`, and `ExecStart` is one of the row's images. (`ExecStart` is matched
   against the row's patterns, not against the image: a unit may start a program through a stable
   symlink such as `/opt/quire/current/bin/x` while the running image is the resolved release path.)
   Nothing is taken from a transient unit name or from an `app-*.scope` name for a service role.

The rules of `judge`, in order: a sandbox makes the peer `Sandboxed` and never a service; a hidden
image is a service only at `Cgroup`; an image or a directory anyone else can write is `Unverified`;
a root-owned image of a row with a unit, running in that unit's cgroup, is that service; a
root-owned image of a row without a unit is that program (`Exe` ceiling); anything else root-owned
is a `Program`. The scope name of a launcher (`app-<id>-<n>.scope`) is only a **claim**, carried in
`Program.scope_app` for display and never used to authorise.

Sandboxes: a Flatpak is read from `/proc/<pid>/root/.flatpak-info` and accepted only if the cgroup
also holds `app-flatpak-<escaped id>-<n>.scope`; a disagreement is `Unverified { SandboxDisagrees }`.
A Snap is read from the bus's `LinuxSecurityLabel` (`snap.<name>.<app>`). A sandboxed peer's image
path belongs to another mount namespace, so it is not read: its exe is `Hidden`.

## 4. The table

`dist/desktop-callers.toml` is the sample (and this desktop's) table, installed root-owned at
`/etc/quire/desktop-callers.toml` with additions in `/etc/quire/desktop-callers.d/*.toml`.
`TableFiles::load` merges the main file first and the drop-ins after it in name order; the first
row for a unit wins, so a later file adds programs and cannot take over a unit. A file is refused
whole unless the file and every directory above it are root-only. The format is refused whole for:
an unknown key, a row without `exe`, a relative or `..` path, `**` or two `*` in a segment, a
malformed id, two rows for one unit, more than 256 rows or 256 KiB. **peephole reads no user file** (the opt-in `dev-rows` feature, section 8, is the one exception).

## 5. API shape

- `peephole-core`: `Pid`, `Uid`, `UnitName`, `AppKey`, `RoleName`, `ExePath`, `ExePattern`,
  `CgroupPath`, `Facts`, `Table`, `Row`, `Standing`, `Proof`, `Requirement`, `Refused`,
  `judge(&Facts, &Table) -> Standing`, `Standing::holds(&[Requirement])`.
- `peephole`: `Pinned::{of_stream, from_pid, from_pid_with_uid, from_fd, alive}`,
  `Prober::{probe, stand, stand_stream}`, `ProcFs`, `RealProc`, `TableFiles`.
- `peephole-bus`: `BusPeers::{who, require, require_or_deny, owner_of, watch_owner}`,
  `ManagerCheck`, `UnitSource`, `ManagerLink`, `Offload` (`Inline`, `Tokio`), `access_denied`,
  `BUS_TIMEOUT` (2 s on every bus call).

No `bool` fields or parameters; enums that will grow are `#[non_exhaustive]`; errors are typed; a
library function reads no environment and no fixed path.

## 6. Recipes

- **Guarding a bus method:** build `BusPeers` once, then in the method
  `peers.require(sender, &[Requirement::new(roles::SHELL, Proof::Full)]).await.map_err(access_denied)?`.
  The manager is asked only if a requirement wants `Full`.
- **Guarding a socket:** `Prober::stand_stream(&stream, &table)` right after `accept`, in the same
  loop turn, and never look again (a client may hand its socket on and exit).
- **A name that must be owned by a particular program:** `watch_owner` first, then `owner_of`;
  end the open work when the watch fires.
- **Testing a consumer:** enable `fake`; `BusPeers::introduce(unique_name, standing)` or build a
  `FixtureProc` tree and pass it to `BusPeers::with_proc`.
- **Adding a role:** add a constant to `roles` (and to `ALL`), a row to the table; the roles test
  checks both agree.

## 7. Residual risks

1. Same-user persistence in the user's systemd configuration or environment (README).
2. A native program is known by its root-owned image; `LD_PRELOAD` and ptrace ride on its standing.
3. `Pin::Reopened`.
4. A client that connects, hands its socket on and exits before the first look is `Unverified`.

## 8. Developer rows (feature `dev-rows`)

A checkout-built stand-in has a user-writable image and no real unit, so it is `Unverified` by rule 3
and tops out below `Full`. The desktop's developer and acceptance scripts need a seam, and it must
not exist in a shipped build. Feature `dev-rows` (`peephole-core`, forwarded by `peephole` and
`peephole-bus`; off by default; the desktop gate greps `cargo tree -e features` for it) adds:

| Piece | Where | What |
|---|---|---|
| `RowOrigin::{Shipped, Dev}`, `Row::origin` | `peephole-core` (`dev.rs`, `table.rs`) | where a row came from |
| `Table::from_toml_dev(text)` | `peephole-core` | the same format, rows marked `Dev` |
| `Table::merge` | `peephole-core` | developer rows after shipped ones; a shipped unit is never taken, in either merge order |
| `Proof::Dev` | `peephole-core` | lowest proof, below `Cgroup` |
| `Requirement::dev(role)` | `peephole-core` | what a consumer lists in its debug builds to accept `Dev` |
| `judge` rule 2b | `peephole-core` | a native process whose image matches a developer row (and whose cgroup leaf is the row's unit, when it has one), and that no shipped row claims by image, is that service at `Dev`; before rule 3 |
| `TableFiles::load_dev(fs, path, person)`, `NodeInfo`, `NodeKind`, `ProcFs::info_of`, `LoadError::{NotAFile, NotTheirs}` | `peephole` | a plain file (no link), owned by `person` or root, not group- or world-writable, within `TABLE_FILE_CAP` |

Rules that keep the seam from widening: only shipped rows are consulted for `Cgroup`, `Exe` and
`Full` (a developer row never names a unit or a program for those); a sandboxed process never
reaches the rule; a hidden image never matches. `Dev` meets no requirement of `Cgroup`, `Exe` or
`Full`. Without the feature the API is identical to a build that never had it: the `Dev` variant,
the `origin` field, the loader and the trait method are all `cfg`-gated, not stubs. Rows from a
person-owned file let that person's programs take a service's role; this is acceptable only in a
program's own debug builds.
