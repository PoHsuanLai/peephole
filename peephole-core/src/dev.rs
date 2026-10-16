//! Developer rows (feature `dev-rows`). A checkout-built stand-in has an image its author can
//! write and no real unit, so `judge` can never give it a service's role; a developer row says
//! "this image is that service" and nothing else.
//!
//! **The risk, plainly.** Rows from a file a person owns let that person's programs take a
//! service's role. They are safe only because the standing they produce, `Proof::Dev`, is below
//! every real proof and a consumer accepts it only when it asks for it, in its own debug builds.
//! No shipped program turns this feature on.

use crate::facts::Facts;
use crate::ids::ExePath;
use crate::table::{Row, Table};

/// Where a row came from.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[non_exhaustive]
pub enum RowOrigin {
    /// A row of the root-owned table that ships with the desktop.
    Shipped,
    /// A row of a developer's own file ([`Table::from_toml_dev`]).
    Dev,
}

/// The developer row that makes the process with `facts` and image `image` a service at
/// `Proof::Dev`: its image matches, its unit (when it names one) is the cgroup's leaf, and no
/// shipped row claims the image, so a developer row never outranks a shipped one.
pub(crate) fn dev_row<'t>(facts: &Facts, table: &'t Table, image: &ExePath) -> Option<&'t Row> {
    let claimed = table
        .rows()
        .iter()
        .any(|row| row.proves() && row.matches_image(image));
    if claimed {
        return None;
    }
    let leaf = facts.cgroup.unit_leaf();
    table.rows().iter().find(|row| {
        row.origin == RowOrigin::Dev
            && row.matches_image(image)
            && row
                .unit
                .as_ref()
                .is_none_or(|unit| leaf.as_ref() == Some(unit))
    })
}

/// Before `incoming` is added: a shipped row that names a unit removes the developer rows that
/// name it, so the order of a merge never lets a developer row hold a shipped unit.
pub(crate) fn make_room(rows: &mut Vec<Row>, incoming: &Row) {
    if incoming.origin != RowOrigin::Shipped {
        return;
    }
    if let Some(unit) = &incoming.unit {
        rows.retain(|row| !(row.origin == RowOrigin::Dev && row.unit.as_ref() == Some(unit)));
    }
}

/// Shipped rows first, developer rows after, each group in its own order.
pub(crate) fn shipped_first(rows: &mut [Row]) {
    rows.sort_by_key(|row| row.origin);
}
