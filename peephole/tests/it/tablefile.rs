//! Loading the table from root-owned files, and refusing the rest.

use peephole::{FixtureProc, LoadError, TableFiles};
use peephole_core::{FileTrust, Uid, Writer};
use std::path::PathBuf;

const MAIN: &str = "/etc/quire/desktop-callers.toml";
const DIR: &str = "/etc/quire/desktop-callers.d";

const SHELL: &str = "[[peer]]\napp = \"org.quire.Shell\"\nunit = \"sill.service\"\nexe = [\"/usr/bin/sill\"]\nrole = \"shell\"\n";
const EVIL_SHELL: &str = "[[peer]]\napp = \"org.evil.Shell\"\nunit = \"sill.service\"\nexe = [\"/tmp/sill\"]\nrole = \"shell\"\n";
const EXTRA: &str =
    "[[peer]]\napp = \"org.local.Tool\"\nexe = [\"/usr/local/bin/tool\"]\nrole = \"tool\"\n";

fn files() -> TableFiles {
    TableFiles::new(PathBuf::from(MAIN), PathBuf::from(DIR))
}

fn tree() -> FixtureProc {
    FixtureProc::new()
        .file(MAIN, SHELL, FileTrust::RootOnly)
        .dir(DIR, FileTrust::RootOnly)
}

fn apps(tree: &FixtureProc) -> Result<Vec<String>, LoadError> {
    files()
        .load(tree)
        .map(|t| t.rows().iter().map(|r| r.app.to_string()).collect())
}

#[test]
fn the_main_file_and_the_drop_ins_are_merged_in_name_order_and_the_main_units_win() {
    let tree = tree()
        .file(
            &format!("{DIR}/20-evil.toml"),
            EVIL_SHELL,
            FileTrust::RootOnly,
        )
        .file(&format!("{DIR}/10-local.toml"), EXTRA, FileTrust::RootOnly)
        .file(
            &format!("{DIR}/notes.txt"),
            "not a table",
            FileTrust::RootOnly,
        );
    assert_eq!(
        apps(&tree).expect("loads"),
        ["org.quire.Shell", "org.local.Tool"]
    );
}

#[test]
fn a_missing_drop_in_directory_is_fine_and_a_missing_main_file_is_not() {
    let tree = FixtureProc::new().file(MAIN, SHELL, FileTrust::RootOnly);
    assert_eq!(apps(&tree).expect("loads"), ["org.quire.Shell"]);
    assert!(matches!(
        apps(&FixtureProc::new()),
        Err(LoadError::Unreadable { .. })
    ));
}

#[test]
fn a_file_that_is_not_root_only_is_refused_whatever_it_says() {
    let owned = FileTrust::Writable(Writer::Owner(Uid::new(1000)));
    for trust in [
        owned,
        FileTrust::Writable(Writer::Group),
        FileTrust::Writable(Writer::Other),
    ] {
        let main = FixtureProc::new().file(MAIN, SHELL, trust);
        assert!(
            matches!(apps(&main), Err(LoadError::NotRootOnly { .. })),
            "{trust:?}"
        );
        let drop_in = tree().file(&format!("{DIR}/10-x.toml"), EXTRA, trust);
        assert!(
            matches!(apps(&drop_in), Err(LoadError::NotRootOnly { .. })),
            "{trust:?}"
        );
    }
}

#[test]
fn a_directory_above_the_file_that_anyone_can_write_refuses_it_too() {
    let tree = FixtureProc::new()
        .dir("/etc", FileTrust::Writable(Writer::Other))
        .file(MAIN, SHELL, FileTrust::RootOnly);
    assert!(matches!(apps(&tree), Err(LoadError::NotRootOnly { .. })));
    let tree = FixtureProc::new()
        .dir("/etc/quire", FileTrust::Writable(Writer::Group))
        .file(MAIN, SHELL, FileTrust::RootOnly);
    assert!(matches!(apps(&tree), Err(LoadError::NotRootOnly { .. })));
}

#[test]
fn a_file_that_is_not_a_table_fails_the_whole_load() {
    let tree = tree().file(
        &format!("{DIR}/10-bad.toml"),
        "[[peer]]\napp = \"x\"\n",
        FileTrust::RootOnly,
    );
    assert!(matches!(apps(&tree), Err(LoadError::Table { .. })));
    let huge = FixtureProc::new().file(
        MAIN,
        vec![b'#'; peephole::TABLE_FILE_CAP as usize + 1],
        FileTrust::RootOnly,
    );
    assert!(matches!(apps(&huge), Err(LoadError::Unreadable { .. })));
}
