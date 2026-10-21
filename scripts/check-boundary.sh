#!/usr/bin/env bash
# Crate boundaries, mechanically enforced (ARCHITECTURE.md section 1 is the table; this is its
# mechanical form).
#
# `cargo tree -i <dep>` exits 101 when the dependency is absent, which is precisely the state we
# want. Checking the exit status would therefore fail whenever the boundary holds, so this checks
# the OUTPUT of `cargo tree -p <crate>` instead: any line naming a forbidden dependency is a leak.
set -uo pipefail
cd "$(dirname "$0")/.."

# What each crate reaches through ANY path (transitive, every feature turned on).
#   peephole-core: pure. No bus, no system-call layer, no async runtime, no executor.
#   peephole:      sync I/O. No bus, no async runtime, no executor.
#   peephole-bus:  the adapter. May reach all of those, but never an HTTP client or a TLS stack.
EFFECTS="zbus zvariant rustix nix libc tokio async-io futures-timer"
RULES=(
  "peephole-core: $EFFECTS"
  "peephole: zbus zvariant tokio async-io futures-timer"
  "peephole-bus: reqwest hyper ureq rustls openssl openssl-sys"
)
fail=0

for rule in "${RULES[@]}"; do
  crate="${rule%%:*}"
  read -r -a forbidden <<<"${rule#*:}"
  # A crate that cargo cannot find would make every check below pass vacuously.
  if ! cargo tree -p "$crate" --depth 0 >/dev/null 2>&1; then
    echo "ERROR: cargo tree cannot resolve $crate; the boundary was not checked"
    fail=1
    continue
  fi
  tree=$(cargo tree -p "$crate" -e normal --all-features --prefix none 2>/dev/null)
  for dep in "${forbidden[@]}"; do
    if grep -E "^${dep} " <<<"$tree" >/dev/null; then
      echo "BOUNDARY: $crate reaches $dep"
      fail=1
    fi
  done
done

# Every crate forbids unsafe: the workspace lint is the rule, and each crate must inherit it.
for manifest in peephole-core/Cargo.toml peephole/Cargo.toml peephole-bus/Cargo.toml; do
  if ! grep -q '^workspace = true' "$manifest"; then
    echo "BOUNDARY: $manifest does not inherit the workspace lints (unsafe_code = forbid)"
    fail=1
  fi
done

# Without its default `toml` feature peephole-core reaches no TOML parser, so a vocabulary crate
# (porter-core, which re-exports CgroupPath) can name its types and stay parser-free.
if [ -n "$(cargo tree -p peephole-core --no-default-features -e normal,build -i toml 2>/dev/null)" ]; then
  echo "BOUNDARY: peephole-core without default features reaches toml"
  fail=1
else
  echo "boundary holds: peephole-core --no-default-features reaches no toml"
fi

if [ "$fail" -ne 0 ]; then
  exit 1
fi
echo "check-boundary: ok"
