//! The table format: a golden reading and the files it refuses.

use peephole_core::{ExePath, RoleName, Table, TableError, UnitName};

const GOLDEN: &str = r#"
# A comment.
[[peer]]
app  = "org.quire.Shell"
unit = "sill.service"
exe  = ["/opt/quire/releases/*/bin/sill", "/usr/bin/sill"]
role = "shell"
name = "The shell"

[[peer]]
app  = "org.quire.Updater"
exe  = ["/usr/bin/slipway"]
role = "updater_cli"
"#;

fn refused(text: &str) -> TableError {
    Table::from_toml(text).expect_err("the table must be refused")
}

fn row(unit: &str) -> String {
    format!(
        "[[peer]]\napp = \"org.x.{unit}\"\nunit = \"{unit}.service\"\nexe = [\"/usr/bin/{unit}\"]\nrole = \"r\"\n"
    )
}

#[test]
fn the_golden_table_reads_into_typed_rows() {
    let table = Table::from_toml(GOLDEN).expect("the golden table reads");
    let rows = table.rows();
    assert_eq!(rows.len(), 2);
    assert_eq!(rows[0].app.as_str(), "org.quire.Shell");
    assert_eq!(rows[0].unit, UnitName::new("sill.service").ok());
    assert_eq!(rows[0].role, RoleName::from_static("shell"));
    assert_eq!(rows[0].name.as_deref(), Some("The shell"));
    assert_eq!(rows[0].exe.len(), 2);
    assert!(
        rows[0].matches_image(&ExePath::new("/opt/quire/releases/9/bin/sill").expect("a path"))
    );
    assert!(!rows[0].matches_image(&ExePath::new("/usr/bin/slipway").expect("a path")));
    assert_eq!(rows[1].unit, None);
    assert!(table.has_role(&RoleName::from_static("updater_cli")));
    assert!(
        table
            .row_for_unit(&UnitName::new("sill.service").expect("a unit"))
            .is_some()
    );
    assert!(Table::from_toml("").expect("empty").rows().is_empty());
}

#[test]
fn a_row_with_no_image_is_refused_because_a_unit_name_proves_nothing() {
    let text = "[[peer]]\napp = \"org.x.A\"\nunit = \"a.service\"\nrole = \"r\"\n";
    assert!(matches!(refused(text), TableError::Row { index: 1, .. }));
    let text = "[[peer]]\napp = \"org.x.A\"\nunit = \"a.service\"\nexe = []\nrole = \"r\"\n";
    assert!(matches!(refused(text), TableError::Row { index: 1, .. }));
}

#[test]
fn images_that_could_match_too_much_or_too_little_are_refused() {
    for exe in [
        "/opt/**/sill",
        "relative/sill",
        "/opt/../sill",
        "/opt/a*b*c/sill",
        "/",
    ] {
        let text = format!("[[peer]]\napp = \"org.x.A\"\nexe = [\"{exe}\"]\nrole = \"r\"\n");
        assert!(matches!(refused(&text), TableError::Row { .. }), "{exe}");
    }
}

#[test]
fn bad_ids_and_unknown_keys_are_refused() {
    for line in [
        "role = \"Not A Role\"",
        "app = \"\"",
        "unit = \"sill\"",
        "extra = 1",
        "name = \"\"",
    ] {
        let text =
            format!("[[peer]]\napp = \"org.x.A\"\nexe = [\"/usr/bin/a\"]\nrole = \"r\"\n{line}\n");
        // A repeated key is a syntax error, a new one an unknown field, a bad value a bad row.
        assert!(Table::from_toml(&text).is_err(), "{line}");
    }
    assert!(matches!(refused("peer = 3"), TableError::Syntax(_)));
    assert!(matches!(refused("[other]\nx = 1"), TableError::Syntax(_)));
}

#[test]
fn two_rows_may_not_name_one_unit() {
    let text = format!("{}{}", row("a"), row("a"));
    assert_eq!(
        refused(&text),
        TableError::DuplicateUnit(UnitName::new("a.service").expect("a unit"))
    );
}

#[test]
fn a_later_table_adds_programs_and_cannot_take_over_a_unit() {
    let shipped = Table::from_toml(&row("a")).expect("shipped");
    let local = Table::from_toml(&format!(
        "{}{}",
        "[[peer]]\napp = \"org.evil.A\"\nunit = \"a.service\"\nexe = [\"/home/p/a\"]\nrole = \"r\"\n",
        row("b")
    ))
    .expect("local");
    let merged = shipped.merge(local);
    let apps: Vec<&str> = merged.rows().iter().map(|r| r.app.as_str()).collect();
    assert_eq!(apps, ["org.x.a", "org.x.b"]);
}

#[test]
fn an_enormous_table_is_refused_before_it_is_parsed() {
    let text = "#".repeat(peephole_core::TABLE_BYTES_MAX + 1);
    assert!(matches!(refused(&text), TableError::TooLong { .. }));
    let many: String = (0..=peephole_core::TABLE_ROWS_MAX)
        .map(|i| format!("[[peer]]\napp = \"org.x.A{i}\"\nexe = [\"/usr/bin/a\"]\nrole = \"r\"\n"))
        .collect();
    assert!(matches!(refused(&many), TableError::TooManyRows { .. }));
}
