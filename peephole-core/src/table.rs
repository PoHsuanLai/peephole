//! The caller table: which programs are the desktop's own, and what role each plays. One shipped,
//! root-owned file. A row with a `unit` is a service; a row without one is a program known by its
//! image alone. Reading the file is the I/O crate's job; this is the text format and the rows.

use crate::error::{IdError, RowFault, TableError};
use crate::ids::{AppKey, ExePath, ExePattern, RoleName, UnitName};
use serde::Deserialize;

/// The longest table text read. A real table is a few kilobytes.
pub const TABLE_BYTES_MAX: usize = 256 * 1024;
/// The most rows a table may hold.
pub const TABLE_ROWS_MAX: usize = 256;
/// The longest free-text row name.
pub const NAME_MAX: usize = 128;

/// One program of the desktop.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Row {
    /// The program's app key (`org.quire.Shell`).
    pub app: AppKey,
    /// The service unit it runs as. `None` for a program matched by its image alone.
    pub unit: Option<UnitName>,
    /// The image paths it may run from; at least one.
    pub exe: Vec<ExePattern>,
    /// The role it plays.
    pub role: RoleName,
    /// A label for logs.
    pub name: Option<String>,
    /// Where the row came from. Only with feature `dev-rows`; without it every row is shipped.
    #[cfg(feature = "dev-rows")]
    pub origin: crate::dev::RowOrigin,
}

impl Row {
    /// Whether this row can give a real proof (`Cgroup`, `Exe` or `Full`): always, except that a
    /// developer row (feature `dev-rows`) never can.
    #[cfg(feature = "dev-rows")]
    pub(crate) fn proves(&self) -> bool {
        self.origin == crate::dev::RowOrigin::Shipped
    }

    /// Whether this row can give a real proof: every row of a build without `dev-rows`.
    #[cfg(not(feature = "dev-rows"))]
    pub(crate) fn proves(&self) -> bool {
        true
    }

    /// Whether the image `path` is one of this row's.
    pub fn matches_image(&self, path: &ExePath) -> bool {
        self.exe.iter().any(|pattern| pattern.matches(path))
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawFile {
    #[serde(default)]
    peer: Vec<RawRow>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawRow {
    app: String,
    unit: Option<String>,
    #[serde(default)]
    exe: Vec<String>,
    role: String,
    name: Option<String>,
}

impl RawRow {
    fn typed(&self) -> Result<Row, RowFault> {
        if self.exe.is_empty() {
            return Err(RowFault::NoExe);
        }
        let exe = self
            .exe
            .iter()
            .map(|text| ExePattern::new(text))
            .collect::<Result<Vec<_>, IdError>>()?;
        if self
            .name
            .as_ref()
            .is_some_and(|n| n.is_empty() || n.len() > NAME_MAX)
        {
            return Err(RowFault::BadName { max: NAME_MAX });
        }
        Ok(Row {
            app: AppKey::new(&self.app)?,
            unit: self.unit.as_deref().map(UnitName::new).transpose()?,
            exe,
            role: RoleName::new(&self.role)?,
            name: self.name.clone(),
            #[cfg(feature = "dev-rows")]
            origin: crate::dev::RowOrigin::Shipped,
        })
    }
}

/// The rows of the caller table. Within one table a unit appears once; across tables the first
/// row for a unit wins ([`Table::merge`]).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Table {
    rows: Vec<Row>,
}

impl Table {
    /// A table with no rows: nobody is a service.
    pub fn empty() -> Table {
        Table::default()
    }

    /// The table written as `text`: `[[peer]]` rows with `app`, `exe` (a non-empty list), `role`
    /// and optionally `unit` and `name`. A file is refused whole for: an unknown key, a row
    /// without `exe`, a relative or `..` path, a `**` or two `*` in a segment, a malformed id,
    /// or two rows naming one unit.
    pub fn from_toml(text: &str) -> Result<Table, TableError> {
        if text.len() > TABLE_BYTES_MAX {
            return Err(TableError::TooLong {
                max: TABLE_BYTES_MAX,
            });
        }
        let file: RawFile = toml::from_str(text).map_err(|e| TableError::Syntax(e.to_string()))?;
        if file.peer.len() > TABLE_ROWS_MAX {
            return Err(TableError::TooManyRows {
                max: TABLE_ROWS_MAX,
            });
        }
        let mut rows: Vec<Row> = Vec::with_capacity(file.peer.len());
        for (i, raw) in file.peer.iter().enumerate() {
            let row = raw.typed().map_err(|fault| TableError::Row {
                index: i + 1,
                app: raw.app.clone(),
                fault,
            })?;
            if let Some(unit) = &row.unit
                && rows.iter().any(|r| r.unit.as_ref() == Some(unit))
            {
                return Err(TableError::DuplicateUnit(unit.clone()));
            }
            rows.push(row);
        }
        Ok(Table { rows })
    }

    /// Only with feature `dev-rows`: the table written as `text`, every row marked
    /// [`RowOrigin::Dev`](crate::RowOrigin::Dev). Same format and same refusals as
    /// [`Table::from_toml`]. Merge it after the shipped table ([`Table::merge`]).
    #[cfg(feature = "dev-rows")]
    pub fn from_toml_dev(text: &str) -> Result<Table, TableError> {
        let mut table = Table::from_toml(text)?;
        for row in &mut table.rows {
            row.origin = crate::dev::RowOrigin::Dev;
        }
        Ok(table)
    }

    /// This table's rows, then the rows of `other` whose unit this table does not already name.
    /// Load the shipped file first and the administrator's files after it: a later file adds
    /// programs and units, and cannot take over a unit the shipped table names. With feature
    /// `dev-rows`, developer rows always end up after the shipped ones, whatever the order of
    /// the merge, and a shipped row displaces a developer row that names its unit.
    pub fn merge(mut self, other: Table) -> Table {
        for row in other.rows {
            #[cfg(feature = "dev-rows")]
            crate::dev::make_room(&mut self.rows, &row);
            let taken = row
                .unit
                .as_ref()
                .is_some_and(|unit| self.rows.iter().any(|r| r.unit.as_ref() == Some(unit)));
            if !taken && self.rows.len() < TABLE_ROWS_MAX {
                self.rows.push(row);
            }
        }
        #[cfg(feature = "dev-rows")]
        crate::dev::shipped_first(&mut self.rows);
        self
    }

    /// The rows, in order.
    pub fn rows(&self) -> &[Row] {
        &self.rows
    }

    /// The row for the unit `unit`.
    pub fn row_for_unit(&self, unit: &UnitName) -> Option<&Row> {
        self.rows.iter().find(|r| r.unit.as_ref() == Some(unit))
    }

    /// The row for the unit `unit` among the rows that can give a real proof.
    pub(crate) fn proving_row_for_unit(&self, unit: &UnitName) -> Option<&Row> {
        self.rows
            .iter()
            .find(|r| r.proves() && r.unit.as_ref() == Some(unit))
    }

    /// Whether any row names `role`.
    pub fn has_role(&self, role: &RoleName) -> bool {
        self.rows.iter().any(|r| &r.role == role)
    }
}
