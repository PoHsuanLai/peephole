//! The shipped sample table and the role constants agree.

use peephole_core::{Table, roles};

const SHIPPED: &str = include_str!("../../../dist/desktop-callers.toml");

#[test]
fn the_shipped_table_reads() {
    let table = Table::from_toml(SHIPPED).expect("dist/desktop-callers.toml reads");
    assert!(!table.rows().is_empty());
}

#[test]
fn every_role_constant_is_in_the_table_and_every_table_role_is_a_constant() {
    let table = Table::from_toml(SHIPPED).expect("the shipped table reads");
    for role in roles::ALL {
        assert!(
            table.has_role(&role),
            "the shipped table has no row for {role}"
        );
    }
    for row in table.rows() {
        assert!(
            roles::ALL.contains(&row.role),
            "{} is not a role constant",
            row.role
        );
    }
}

#[test]
fn units_are_services_and_unitless_rows_are_programs() {
    let table = Table::from_toml(SHIPPED).expect("the shipped table reads");
    let program_roles: Vec<&str> = table
        .rows()
        .iter()
        .filter(|r| r.unit.is_none())
        .map(|r| r.role.as_str())
        .collect();
    assert_eq!(
        program_roles,
        ["updater_cli", "sandbox_launcher", "manager"]
    );
}
