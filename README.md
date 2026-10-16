# peephole

Which program is calling: pinned process identity for Linux desktop services (pidfd, systemd unit, sandbox), judged against a root-owned table.

A service that does something only the desktop's own programs may ask for (take a screenshot, create an input device, install an update) needs to know who is on the other end of its socket or its bus message. A process id is not an answer: it can be reused, and the name of the cgroup a process sits in can be set by the process itself. peephole holds the caller by a pidfd, reads what `/proc` says of it afterwards, optionally asks the systemd manager about its unit, and judges the result against one table that says which program is the shell, the portal, the updater and so on.

Licensed under either of MIT or Apache-2.0, at your option.

## Crates

| Crate | Layer | Contents |
|---|---|---|
| `peephole-core` | pure, no I/O | ids, the caller table (TOML), the facts read about a process, `judge`, `Requirement`, `Standing` |
| `peephole` | sync I/O | `Pinned` (pidfd), `Prober` over a `ProcFs` (real `/proc`, or a fixture tree under feature `fake`), the ownership walk, the table loader |
| `peephole-bus` | async adapter | `BusPeers` over zbus: the sender's process, the unit manager's facts, `require`, `owner_of`, `watch_owner` |

```rust
// In a bus method: who may call this?
let need = [Requirement::new(roles::SHELL, Proof::Full)];
let caller = peers.require(header.sender().map(|s| s.as_str()), &need).await
    .map_err(peephole_bus::access_denied)?;
```

## What a proof is

A caller is first held by a pidfd, and everything read from `/proc/<pid>` is read after that. The result is a `Standing`:

- `Service`: a row of the table matched, at a proof level: `Cgroup` (the cgroup names the unit; a speed bump, never a boundary), `Exe` (the image is root-owned all the way up and matches the row) or `Full` (and the systemd manager confirms the unit: root-owned definition, no user-writable drop-in, not transient, this process as its main process).
- `Sandboxed`: a Flatpak (its metadata, cross-checked against its cgroup's scope) or a Snap (its kernel label).
- `Program`: a root-owned image that is in no row.
- `Unverified`: nothing that can be remembered (an image the user can write, a hidden image, a caller that left).

The scope name of an application launcher is only ever a claim, carried for display; it never authorises anything. Roles come from the table and from the code that names the roles it accepts, never from a peer.

What this stops: a same-user process that does not touch the user's systemd configuration or environment cannot pass as `sill.service` (`systemd-run -u`, a moved cgroup, a copied binary, a user-level unit override, a drop-in). What it cannot stop: a same-user attacker who edits `~/.config/systemd/user` or `systemctl --user set-environment LD_PRELOAD=...` and waits for the next start of a trusted service (persistence in the user's own manager; the boundary CASW-05 names). Hardening for our own units: `UnsetEnvironment=LD_PRELOAD LD_LIBRARY_PATH LD_AUDIT` in `sill.service`, `casement.service`, `transom.service`, `palmrest.service` (unit lanes), and a drop-in under the user's directory makes `Full` fail rather than pass.

Other limits, stated rather than hidden:

- A native program is known by its root-owned image. Anything that can run the same image with `LD_PRELOAD` or ptrace (Yama scope 1 lets a parent trace its child) rides on that program's standing.
- `Pin::Reopened` (a pidfd opened by pid, then the pid checked again) leaves one window: the connecting process died and its pid was reused before we looked. The bus daemon's own pidfd (`ProcessFD`) and `SO_PEERPIDFD` close it; see `ARCHITECTURE.md` for which of them this release makes.
- A client that connects, hands its socket to another process and exits before the first look is `Unverified`.

## The table

`dist/desktop-callers.toml` is a sample of the format and of this desktop's own table. A row has `app`, `exe` (a non-empty list of absolute patterns; one `*` per segment, never `**`), `role`, and optionally `unit` and `name`. A row with a `unit` is a service; a row without is a program matched by its image alone, whose ceiling is `Exe`. The loader refuses a file that is not owned by root alone, or whose directory anyone else can write. peephole reads no user file: nothing a person's file says makes a process more trusted.

## Building

`cargo test --workspace --all-features` needs `dbus-daemon` on the PATH (the bus tests start a private one). The Linux kernel must have `pidfd_open` (5.3). `unsafe` is forbidden in every crate; the pidfd comes through rustix.

## Tests and features

| Feature | Crate | What it does | Shipped? |
|---|---|---|---|
| `fake` | `peephole`, `peephole-bus` | `Pinned::introduced`, the fixture tree, `BusPeers::introduce` | never |
| `desktop` | `peephole-core` | the `roles` module of this desktop's own roles | by the desktop |
| `tokio` | `peephole-bus` | `Offload::Tokio` and zbus on tokio | optional |
