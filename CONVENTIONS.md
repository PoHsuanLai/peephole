# Conventions

peephole follows the program's shared conventions: small typed structs, enums instead of `bool`
fields and parameters, typed errors (`thiserror`), no `unsafe`, short files, doc comments on every
public item, tests that never touch the real system. `ARCHITECTURE.md` here has the crate map, the
trust rules and the seams. Where the two disagree, `ARCHITECTURE.md` wins for this repo.

1. **Library first.** Every crate is usable on its own: `peephole-core` is pure and `peephole` is
   synchronous. The bus is an adapter on top; nothing below it names it.
2. **One home per concept.** Ids and the judgement live in `peephole-core`; reading `/proc` and
   holding a pidfd in `peephole`; the bus in `peephole-bus`. A lower crate never names a higher one
   (`scripts/check-boundary.sh`).
3. **Wire values stay at the edge.** The table's text, the bus's integers and the kernel's file
   contents become enums and newtypes where they are read (`Pid`, `Uid`, `UnitName`, `AppKey`,
   `RoleName`, `ExePath`, `ExePattern`); the judgement never sees a raw string or number that means
   something.
4. **No `bool` fields or parameters.** Use a two-state enum (`Alive`, `Pin`, `PinNeed`,
   `Transient`, `UnitUse`). A private helper may return `bool` where it reads as a predicate.
5. **Fail closed.** An error while identifying is an unknown peer, never a trusted one. A read that
   cannot be completed, a cap that is exceeded or a peer that does not answer in time is a refusal.
   Every caller-facing refusal has fixed text that does not say which check failed.
6. **Limits are named.** Each cap and timeout is a `pub const` with a one-line reason
   (`PROBE_MAX_READS`, `PROBE_READ_CAP`, `WALK_MAX`, `TABLE_BYTES_MAX`, `BUS_TIMEOUT`).
7. **Nothing ambient.** A library function reads no environment and no fixed path: the table, the
   `/proc` root and the clock are passed in. The only fixed paths are `RealProc::system()` and
   `TableFiles::desktop()`, each named in one place.
8. **No panics on external data.** `unwrap` and `expect` only in tests. A malformed table, file or
   message is an error value.
9. **No `unsafe`.** `unsafe_code = "forbid"` at the workspace. A call with no safe rustix API is
   not made; record it in `FINDINGS.md` instead.
10. **Test seams are features, not API.** `fake` holds everything that can forge a standing
    (`Pinned::introduced`, `BusPeers::introduce`, the fixture tree). A shipped binary never turns it
    on; the desktop gate greps `cargo tree -e features` for it.
11. **One test binary per crate** (`tests/it/main.rs`, a module per concept), tables over one-off
    cases. The bus tests start a private `dbus-daemon` with a scratch directory and the real
    session's environment removed.
12. **Plain language.** Nothing a person sees names a protocol or a developer term. peephole shows
    nothing itself; its errors are for logs and carry no such wording in anything it hands a caller
    to display.
13. **No glob re-exports,** one path per public item. `peephole` and `peephole-bus` re-export the
    crates below them whole (`peephole::peephole_core`), not item by item.
14. **`#[non_exhaustive]`** on public enums that will grow; `Copy` only for heap-free values of at
    most two words.
15. **Licence hygiene.** MIT OR Apache-2.0. Dependencies must pass `deny.toml`; no copyleft code is
    linked or copied, and MPL-2.0 source is never pasted in.
16. **`cargo fmt -p <crate>`** writes; the gate runs `cargo fmt --all --check`.
