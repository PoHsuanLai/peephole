# Findings

Departures from the plan, standing facts and open items. An entry names the condition that closes it.

## Decisions and departures

1. **`Pinned::of_stream` makes `Pin::AtConnect` through nix (0.1.5; was `Reopened`).** rustix 1.1.5
   has `socket_peercred` and `pidfd_open` but no safe `SO_PEERPIDFD` wrapper (`net/sockopt.rs`), and
   every crate forbids `unsafe`, so 0.1.4 and earlier reopened the pid (pid from `SO_PEERCRED`, pidfd
   at once, `SO_PEERCRED` again), which a recycled pid could pass. The owner allowed nix (2026-10-17):
   `getsockopt(stream, sockopt::PeerPidfd)` is the kernel's descriptor of the connector, checked
   against `SO_PEERCRED`'s pid by its `fdinfo` and polled alive. `ESRCH` (the connector has exited) is
   `PeerGone`; any other error (a kernel before 6.5 says `ENOPROTOOPT`) falls back to the reopened pin.
   This closes casement's NEW-CASB-7 once casement holds its Wayland clients through `of_stream`;
   `Pinned::pidfd` (0.1.6) lends the held descriptor so casement signals the same process it judged.
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

10. **Developer rows are a cargo feature, not a table key or a runtime switch (0.1.4).** The
    desktop's developer scripts run stand-ins from the checkout; a runtime switch could be turned on
    in a shipped binary, a feature cannot (the gate greps for it). `Proof::Dev` and the `origin`
    field are `cfg`-gated, so a build without the feature has the same API as 0.1.3: `Proof` is
    already `#[non_exhaustive]`, and the new variant sits first so the derived order puts it below
    `Cgroup`. A developer row may name an app or role a shipped row names (a stand-in for the
    accounts service is `org.quire.Accounts` in both); what it never does is replace a shipped row,
    hold a shipped unit, or give a proof above `Dev`. `Requirement::dev` accepts every proof, so a
    consumer's debug build lets in the real service too; "only Dev or Full" is not expressible
    without a new `Requirement` field. `TableFiles::load_dev` takes the person's uid as an argument
    because `ProcFs` has no notion of the current user. `RealProc::info_of` is read, not run in a
    test (no scratch-directory test in this crate).

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
