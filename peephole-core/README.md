# peephole-core

Which program is calling: the pure half of [peephole](https://github.com/PoHsuanLai/peephole).

This crate holds the vocabulary (ids, the facts read about a process, the caller table) and the
judgement over them. It does no I/O and reads no clock, environment or fixed path: the `peephole`
crate reads `/proc` through a pidfd and fills in `Facts`; `judge` turns facts and a `Table` into a
`Standing`; a method says what it accepts with `Requirement`s and `Standing::holds`.

```rust
use peephole_core::{CgroupPath, scope_app};

let path = CgroupPath::new(
    "/user.slice/user-1000.slice/user@1000.service/app.slice/app-gnome-org.gnome.Nautilus-4821.scope",
)?;
assert_eq!(path.leaf(), "app-gnome-org.gnome.Nautilus-4821.scope");
// A launcher's scope names an app as a claim, for display and grouping only.
assert_eq!(scope_app(&path).map(|app| app.as_str().to_owned()).as_deref(), Some("org.gnome.Nautilus"));
# Ok::<(), peephole_core::IdError>(())
```

## Features

- `toml` (default): `Table::from_toml`, the caller table's text format. A crate that only names
  the types turns default features off.
- `desktop`: the role names of this desktop's own processes.
- `dev-rows`: rows from a file a person owns, at `Proof::Dev`. A shipped program never enables it.

## License

MIT OR Apache-2.0.
