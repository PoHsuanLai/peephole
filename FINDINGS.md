# Findings

Departures from the plan, standing facts and open items. An entry names the condition that closes it.

## Decisions and departures

1. **`Pinned::of_stream` makes `Pin::Reopened`, not `AtConnect`.** rustix 1.1.5 has `socket_peercred`
   and `pidfd_open` but no safe `SO_PEERPIDFD` wrapper (`net/sockopt.rs`), and every crate forbids
   `unsafe`. The pin is the reopened one (pid from `SO_PEERCRED`, pidfd at once, `SO_PEERCRED`
   again). Closes when rustix gains the wrapper (then `of_stream` returns `AtConnect` on kernels with
   it and falls back). A consumer that demands `PinNeed::AtConnect` of a socket peer (the plan's
   turnstile does) cannot be satisfied until then; the bus path and `Pinned::from_fd` do give `AtConnect`.
2. **No `From<Refused> for fdo::Error`.** Both types are foreign to `peephole-bus` (orphan rule).
   `access_denied(Refused) -> fdo::Error` and `BusPeers::require_or_deny` do the same job.
3. **`watch_owner` is `async` and returns a `Result`.** Subscribing is a bus call. The watch yields
   `Option<()>` per change; the consumer re-runs `owner_of`.
4. **The manager's own identity is checked by `BusPeers`, not by `ManagerLink`.** `ManagerCheck::Verified`
   asks `owner_of(org.freedesktop.systemd1)` to hold a requirement (the desktop uses role `manager`,
   `Exe`); `Unchecked` is for a private test bus. A custom `UnitSource` thus gets the same check.
5. **`ExecStart` is matched against the row's patterns, not equal to the image** (ARCHITECTURE 3).
6. **`FixtureProc` is behind `fake`.** The plan listed it as public; as a test helper it follows the
   convention "test helpers are not API".
7. **`peephole::peephole_core` and `peephole_bus::peephole` are crate re-exports,** not glob re-exports.
8. **Roles added to the plan's list:** `updater` (slipway.service), `memory` (memoryd.service) and
   `manager` (the systemd image). The plan's DETENT-05 row names `updater` and `memory`.
9. **`Cgroup` proof is reachable only with a hidden image.** A readable but user-writable image is
   `Unverified`, whatever its cgroup says, so no `Cgroup` standing exists for a hostile image.

## Open items

1. **Snap from a socket.** The Snap label comes only from the bus's `LinuxSecurityLabel`; `SO_PEERSEC`
   is not read for sockets (no safe rustix wrapper checked). A Snap on a unix socket is a hidden-image
   `Unverified`. Closes with a consumer that needs it (nothing in wave 2 does).
2. **xdg-dbus-proxy.** A proxied app is the proxy's process (`Program`); no special case exists.
3. **Per-distro `exe` paths** in `dist/desktop-callers.toml` are the plan's guesses (portal frontend
   `/usr/libexec` vs `/usr/lib`, `systemd` under `/usr/lib` and `/lib`). Closes at the desktop gate
   per distro (plan section 7, fact 13).
4. **The unit manager calls do blocking `lstat`s inline** (a fragment and a handful of drop-ins).
   Bounded and tiny; `Offload` covers only the `/proc` probe. Closes if a profile says otherwise.
5. **`Pin::AtConnect` on the bus depends on the bus daemon offering `ProcessFD`** (dbus-daemon 1.14.10
   and dbus-broker are believed to). Unverified; without it the pin is `Reopened`.
6. **No `Cargo.lock` is committed** by the first lane; the gate session generates it.
