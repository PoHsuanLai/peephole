//! Loading a developer rows file (feature `dev-rows`): the person's own plain file, nobody else's.

use peephole::{FixtureProc, LoadError, TABLE_FILE_CAP, TableFiles};
use peephole_core::{FileTrust, RowOrigin, Table, Uid, Writer};
use std::path::Path;

const FILE: &str = "/home/p/scratch/dev-callers.toml";
const ROWS: &str = "[[peer]]\napp = \"org.quire.Accounts\"\nexe = [\"/home/p/proj/target/debug/standin\"]\nrole = \"accounts\"\n";
const SHIPPED: &str = "[[peer]]\napp = \"org.quire.Shell\"\nunit = \"sill.service\"\nexe = [\"/usr/bin/sill\"]\nrole = \"shell\"\n";
const PERSON: Uid = Uid::new(1000);

fn own() -> FileTrust {
    FileTrust::Writable(Writer::Owner(PERSON))
}

fn load(tree: &FixtureProc) -> Result<Table, LoadError> {
    TableFiles::load_dev(tree, Path::new(FILE), PERSON)
}

#[test]
fn the_persons_own_plain_file_loads_as_dev_rows_and_merges_after_the_shipped_table() {
    let tree = FixtureProc::new().file(FILE, ROWS, own());
    let rows = load(&tree).expect("loads");
    assert_eq!(rows.rows().len(), 1);
    assert_eq!(rows.rows()[0].origin, RowOrigin::Dev);
    let shipped = Table::from_toml(SHIPPED).expect("shipped");
    let merged = shipped.merge(rows);
    let origins: Vec<RowOrigin> = merged.rows().iter().map(|r| r.origin).collect();
    assert_eq!(origins, [RowOrigin::Shipped, RowOrigin::Dev]);
    // A root-owned file is fine too.
    let root = FixtureProc::new().file(FILE, ROWS, FileTrust::RootOnly);
    assert!(load(&root).is_ok());
}

#[test]
fn a_link_someone_elses_file_or_a_file_others_can_write_is_refused() {
    let link = FixtureProc::new()
        .file("/home/p/real.toml", ROWS, own())
        .link(FILE, "/home/p/real.toml");
    assert!(matches!(load(&link), Err(LoadError::NotAFile { .. })));
    let dir = FixtureProc::new().dir(FILE, own());
    assert!(matches!(load(&dir), Err(LoadError::NotAFile { .. })));
    for trust in [
        FileTrust::Writable(Writer::Owner(Uid::new(1001))),
        FileTrust::Writable(Writer::Group),
        FileTrust::Writable(Writer::Other),
    ] {
        let tree = FixtureProc::new().file(FILE, ROWS, trust);
        assert!(
            matches!(load(&tree), Err(LoadError::NotTheirs { .. })),
            "{trust:?}"
        );
    }
}

#[test]
fn a_missing_oversized_or_malformed_file_is_refused_with_the_same_caps_as_the_shipped_table() {
    assert!(matches!(
        load(&FixtureProc::new()),
        Err(LoadError::Unreadable { .. })
    ));
    let huge = FixtureProc::new().file(FILE, vec![b'#'; TABLE_FILE_CAP as usize + 1], own());
    assert!(matches!(load(&huge), Err(LoadError::Unreadable { .. })));
    let bad = FixtureProc::new().file(FILE, "[[peer]]\napp = \"x\"\n", own());
    assert!(matches!(load(&bad), Err(LoadError::Table { .. })));
}
