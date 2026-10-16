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
}

impl Row {
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

    /// This table's rows, then the rows of `other` whose unit this table does not already name.
    /// Load the shipped file first and the administrator's files after it: a later file adds
    /// programs and units, and cannot take over a unit the shipped table names.
    pub fn merge(mut self, other: Table) -> Table {
        for row in other.rows {
            let taken = row
                .unit
                .as_ref()
                .is_some_and(|unit| self.rows.iter().any(|r| r.unit.as_ref() == Some(unit)));
            if !taken && self.rows.len() < TABLE_ROWS_MAX {
                self.rows.push(row);
            }
        }
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

    /// Whether any row names `role`.
    pub fn has_role(&self, role: &RoleName) -> bool {
        self.rows.iter().any(|r| &r.role == role)
    }
}
