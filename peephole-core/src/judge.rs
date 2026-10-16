//! The judgement: facts and a table in, a standing out. Pure, total, no I/O.
//!
//! The rules, in the order they apply:
//!
//! 1. A sandbox (Flatpak by its metadata cross-checked against the cgroup's scope, Snap by its
//!    kernel label) makes the peer `Sandboxed`, never a service. A disagreement is `Unverified`.
//! 2. A native process whose image cannot be read is a service at `Cgroup` proof only when a row
//!    names the unit its cgroup leaf spells, and `Unverified` otherwise.
//! 3. A native process whose image, or a directory above it, can be written by someone other than
//!    root is `Unverified`: nothing about it may be remembered.
//! 4. A root-owned image in a row with a unit is that service when the cgroup leaf is the unit
//!    (`Exe`, or `Full` when the manager's facts all agree); a root-owned image in a row without a
//!    unit is that program (`Exe`).
//! 5. Any other root-owned image is a `Program`, carrying the launcher's scope name as a claim.

use crate::cgroup::{flatpak_scope_in, scope_app};
use crate::facts::{
    DropIns, Engine, Exe, Facts, FileTrust, Fragment, SandboxFacts, Transient, UnitFacts,
};
use crate::ids::AppKey;
use crate::standing::{Proof, Standing, WhyNot};
use crate::table::{Row, Table};

/// Who `facts` describe, judged against `table`.
pub fn judge(facts: &Facts, table: &Table) -> Standing {
    match &facts.sandbox {
        SandboxFacts::Native => judge_native(facts, table),
        SandboxFacts::Flatpak { app, .. } => judge_flatpak(facts, app),
        SandboxFacts::Snap { label } => judge_snap(label),
    }
}

fn disagrees() -> Standing {
    Standing::Unverified {
        exe_name: None,
        why: WhyNot::SandboxDisagrees,
    }
}

fn judge_flatpak(facts: &Facts, app: &str) -> Standing {
    match AppKey::new(app) {
        Ok(key) if flatpak_scope_in(&facts.cgroup, &key) => Standing::Sandboxed {
            app: key,
            engine: Engine::Flatpak,
        },
        _ => disagrees(),
    }
}

/// `snap.<name>.<app>`: the snap's name is the key.
fn judge_snap(label: &str) -> Standing {
    let name = label
        .strip_prefix("snap.")
        .and_then(|rest| rest.split_once('.'));
    match name {
        Some((name, app)) if !app.is_empty() => match AppKey::new(name) {
            Ok(key) => Standing::Sandboxed {
                app: key,
                engine: Engine::Snap,
            },
            Err(_) => disagrees(),
        },
        _ => disagrees(),
    }
}

fn service(row: &Row, proof: Proof, facts: &Facts) -> Standing {
    Standing::Service {
        app: row.app.clone(),
        role: row.role.clone(),
        proof,
        pin: facts.pin,
    }
}

fn judge_native(facts: &Facts, table: &Table) -> Standing {
    let leaf_row = facts
        .cgroup
        .unit_leaf()
        .and_then(|unit| table.row_for_unit(&unit));
    let (path, trust) = match &facts.exe {
        Exe::Read { path, trust } => (path, trust),
        Exe::Hidden => {
            return match leaf_row {
                Some(row) => service(row, Proof::Cgroup, facts),
                None => Standing::Unverified {
                    exe_name: None,
                    why: WhyNot::ImageHidden,
                },
            };
        }
    };
    if let FileTrust::Writable(_) = trust {
        let exe_name = path.file_name().map(str::to_owned);
        return Standing::Unverified {
            exe_name,
            why: WhyNot::ImageWritable,
        };
    }
    if let Some(row) = leaf_row.filter(|row| row.matches_image(path)) {
        let proof = match unit_is_real(facts, row) {
            UnitCheck::Real => Proof::Full,
            UnitCheck::NotShown => Proof::Exe,
        };
        return service(row, proof, facts);
    }
    let program_row = table
        .rows()
        .iter()
        .find(|row| row.unit.is_none() && row.matches_image(path));
    match program_row {
        Some(row) => service(row, Proof::Exe, facts),
        None => Standing::Program {
            exe: path.clone(),
            scope_app: scope_app(&facts.cgroup),
        },
    }
}

enum UnitCheck {
    Real,
    NotShown,
}

/// Whether the manager's facts show that the process is the main process of a real unit: the
/// unit is the row's, the process is its `MainPID`, the fragment is root-owned, no drop-in is
/// user-writable, the unit is not transient, and its `ExecStart` program is one of the row's.
/// `ExecStart` is matched against the row's patterns, not against the image: a unit may start
/// the program through a stable symlink (`/opt/quire/current/bin/x`) while the image is the
/// resolved release path.
fn unit_is_real(facts: &Facts, row: &Row) -> UnitCheck {
    let Some(unit) = &facts.unit else {
        return UnitCheck::NotShown;
    };
    let real = Some(&unit.name) == row.unit.as_ref()
        && unit.main_pid == Some(facts.pid)
        && root_fragment(unit)
        && matches!(unit.drop_ins, DropIns::None | DropIns::RootOwned)
        && unit.transient == Transient::No
        && unit
            .exec
            .as_ref()
            .is_some_and(|exec| row.matches_image(exec));
    if real {
        UnitCheck::Real
    } else {
        UnitCheck::NotShown
    }
}

fn root_fragment(unit: &UnitFacts) -> bool {
    matches!(unit.fragment, Fragment::RootOwned(_))
}
