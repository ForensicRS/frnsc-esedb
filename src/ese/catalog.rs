//! Catalog parser for ESE databases.
//!
//! Every ESE database stores table and column metadata in the system table
//! **MSysObjects**, which is rooted at B-tree page 4.  Parsing the catalog is
//! required before typed decoding of user-table records is possible.
//!
//! The MSysObjects schema is fixed by the ESE engine and never changes between
//! database versions, so the column definitions are hardcoded here rather than
//! being bootstrapped from a higher-level catalog page.

use std::collections::HashMap;

use forensic_rs::err::ForensicResult;
use forensic_rs::traits::db::ForensicColumnDef;

use crate::ese::{
    column::{ColumnDef, ColumnType, ColumnValue, TableSchema},
    header::Header,
    reader::PageReader,
    tree,
};

/// The catalog B-tree root page — always page 4 (the first page after the
/// two header shadow pages and the DbTime page).
const CATALOG_ROOT_PAGE: u32 = 4;

// ─── MSysObjects column IDs and schema ──────────────────────────────────────

/// MSysObjects row type discriminator.
#[repr(i16)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CatalogObjectType {
    Table      = 1,
    Column     = 2,
    Index      = 3,
    LongValue  = 4,
    Callback   = 5,
    Other(i16),
}

impl CatalogObjectType {
    fn from_i16(v: i16) -> Self {
        match v {
            1 => CatalogObjectType::Table,
            2 => CatalogObjectType::Column,
            3 => CatalogObjectType::Index,
            4 => CatalogObjectType::LongValue,
            5 => CatalogObjectType::Callback,
            other => CatalogObjectType::Other(other),
        }
    }
}

/// Build the hardcoded `TableSchema` for MSysObjects.
///
/// Column IDs come from the ESE specification; they are invariant across all
/// ESE versions.
fn msys_objects_schema() -> TableSchema {
    TableSchema {
        name: "MSysObjects".to_owned(),
        columns: vec![
            ColumnDef { id: 1,  col_type: ColumnType::Long,          name: "ObjidTable".into(),      flags: 0, codepage: 0 },
            ColumnDef { id: 2,  col_type: ColumnType::Short,         name: "Type".into(),             flags: 0, codepage: 0 },
            ColumnDef { id: 3,  col_type: ColumnType::Long,          name: "Id".into(),               flags: 0, codepage: 0 },
            ColumnDef { id: 4,  col_type: ColumnType::Long,          name: "ColtypOrPgnoFDP".into(),  flags: 0, codepage: 0 },
            ColumnDef { id: 5,  col_type: ColumnType::Long,          name: "SpaceUsage".into(),       flags: 0, codepage: 0 },
            ColumnDef { id: 6,  col_type: ColumnType::Long,          name: "Flags".into(),            flags: 0, codepage: 0 },
            ColumnDef { id: 7,  col_type: ColumnType::Long,          name: "PagesOrLocale".into(),    flags: 0, codepage: 0 },
            ColumnDef { id: 8,  col_type: ColumnType::Bit,           name: "RootFlag".into(),         flags: 0, codepage: 0 },
            ColumnDef { id: 9,  col_type: ColumnType::Short,         name: "RecordOffset".into(),     flags: 0, codepage: 0 },
            ColumnDef { id: 10, col_type: ColumnType::Long,          name: "LCMapFlags".into(),       flags: 0, codepage: 0 },
            ColumnDef { id: 11, col_type: ColumnType::UnsignedShort, name: "KeyMost".into(),          flags: 0, codepage: 0 },
            // Variable columns (IDs 128+)
            ColumnDef { id: 128, col_type: ColumnType::Text,   name: "Name".into(),          flags: 0, codepage: 1252 },
            ColumnDef { id: 129, col_type: ColumnType::Text,   name: "TemplateTable".into(), flags: 0, codepage: 1252 },
            // Tagged columns (IDs 256+)
            ColumnDef { id: 256, col_type: ColumnType::Binary, name: "Stats".into(),         flags: 0, codepage: 0 },
            ColumnDef { id: 258, col_type: ColumnType::Binary, name: "DefaultValue".into(),  flags: 0, codepage: 0 },
            ColumnDef { id: 259, col_type: ColumnType::Binary, name: "KeyFldIDs".into(),     flags: 0, codepage: 0 },
            ColumnDef { id: 270, col_type: ColumnType::Binary, name: "CallbackData".into(),  flags: 0, codepage: 0 },
        ],
    }
}

// ─── Public types ────────────────────────────────────────────────────────────

/// A fully resolved table definition extracted from MSysObjects.
#[derive(Debug, Clone)]
pub struct TableDef {
    /// Table name.
    pub name: String,
    /// FDP (Father Data Page) — the root B-tree page number of this table.
    pub fdp_page: u32,
    /// Object ID of this table (the `Id` column in MSysObjects).
    /// Column/index/LV rows reference their owning table via `ObjidTable == table_id`.
    pub table_id: u32,
    /// Root page of this table's Long-Value B-tree, if one exists.
    pub lv_fdp_page: Option<u32>,
    /// Decoded column definitions for this table, sorted by column ID.
    pub columns: Vec<ColumnDef>,
    /// `columns`, mapped to `forensic_rs`'s column-type vocabulary and
    /// index-aligned with it. Precomputed once here (rather than per-call in
    /// `ForensicTable::columns()`) since that trait method returns a `&[_]`
    /// slice and so needs a stable owner.
    pub(crate) forensic_columns: Vec<ForensicColumnDef>,
    /// Decoded index definitions (names only; full key spec not decoded here).
    pub indexes: Vec<String>,
}

impl TableDef {
    /// Build a `TableSchema` suitable for passing to `TableSchema::decode_record`.
    pub fn schema(&self) -> TableSchema {
        TableSchema {
            name: self.name.clone(),
            columns: self.columns.clone(),
        }
    }
}

/// Parsed ESE catalog: all user tables with their column definitions.
#[derive(Debug, Clone)]
pub struct Catalog {
    pub tables: Vec<TableDef>,
}

impl Catalog {
    /// Parse the catalog from a raw database byte slice.
    ///
    /// `header` must already have been parsed with `Header::from_buff`.
    ///
    /// The catalog B-tree is always rooted at page 4 (the first page after the
    /// two header shadow pages and the DbTime page).
    pub fn from_db(reader: &dyn PageReader, header: &Header) -> ForensicResult<Self> {
        let schema = msys_objects_schema();

        // Collect all leaf entries from the catalog B-tree (rooted at page 4).
        let mut leaf_entries: Vec<OwnedRow> = Vec::new();
        tree::visit_leaves(reader, header, CATALOG_ROOT_PAGE, |entry| {
            if let crate::ese::page::entries::PageEntry::TableValue(tv) = entry {
                let decoded = schema.decode_record(tv, None);
                if let Some(row) = OwnedRow::from_decoded(&decoded) {
                    leaf_entries.push(row);
                }
            }
        })?;

        // Build the catalog: first pass = tables, second pass = columns / indexes.
        let mut tables: Vec<TableDef> = Vec::new();

        // First pass: table rows (Type == 1).
        for row in &leaf_entries {
            if row.obj_type != CatalogObjectType::Table {
                continue;
            }
            if row.name.is_empty() {
                continue; // skip unnamed internal/shadow entries
            }
            tables.push(TableDef {
                name: row.name.clone(),
                fdp_page: row.coltyp_or_pgno as u32,
                table_id: row.col_id as u32,
                lv_fdp_page: None,
                columns: Vec::new(),
                forensic_columns: Vec::new(),
                indexes: Vec::new(),
            });
        }
        // Index tables by ID for O(1) lookup during the second pass, instead
        // of a linear `iter_mut().find()` scan per catalog row.
        let table_index: HashMap<u32, usize> = tables
            .iter()
            .enumerate()
            .map(|(i, t)| (t.table_id, i))
            .collect();

        // Second pass: column rows (Type == 2), index rows, LV rows.
        for row in &leaf_entries {
            let Some(&idx) = table_index.get(&(row.objid_table as u32)) else { continue };
            match row.obj_type {
                CatalogObjectType::Column => {
                    match ColumnType::from_u8(row.coltyp_or_pgno as u8) {
                        Some(ct) => {
                            tables[idx].columns.push(ColumnDef {
                                id: row.col_id as u16,
                                col_type: ct,
                                name: row.name.clone(),
                                flags: row.flags as u32,
                                codepage: row.pages_or_locale as u32,
                            });
                        }
                        None => {
                            forensic_rs::warn!(
                                "ESE: table '{}' column '{}' has unrecognized type byte {:#04x}; column dropped",
                                tables[idx].name, row.name, row.coltyp_or_pgno as u8
                            );
                        }
                    }
                }
                CatalogObjectType::Index => {
                    tables[idx].indexes.push(row.name.clone());
                }
                CatalogObjectType::LongValue => {
                    // Associate LV B-tree root page with its owning table.
                    tables[idx].lv_fdp_page = Some(row.coltyp_or_pgno as u32);
                }
                _ => {}
            }
        }

        // Sort columns by ID for deterministic lookup, then precompute the
        // forensic-rs column-type projection alongside.
        for tbl in &mut tables {
            tbl.columns.sort_by_key(|c| c.id);
            tbl.forensic_columns = tbl
                .columns
                .iter()
                .map(|c| ForensicColumnDef {
                    name: c.name.clone(),
                    col_type: c.col_type.forensic_type(),
                    // ESE catalog flags encode nullability, but the exact bit
                    // (JET_bitColumnNotNULL) is unverified against a primary
                    // source in this codebase; default to `true` (nullable)
                    // rather than assert a constraint that might be wrong.
                    nullable: true,
                })
                .collect();
        }

        Ok(Catalog { tables })
    }

    /// Find a table definition by name (case-insensitive).
    pub fn table(&self, name: &str) -> Option<&TableDef> {
        self.tables.iter().find(|t| t.name.eq_ignore_ascii_case(name))
    }
}

// ─── Internal: one decoded MSysObjects row ───────────────────────────────────

#[derive(Debug)]
struct OwnedRow {
    objid_table:       i32,
    obj_type:          CatalogObjectType,
    col_id:            i32,   // "Id" column — column ID for column rows
    coltyp_or_pgno:    i32,   // column type (for column rows) or pgnoFDP (for table rows)
    flags:             i32,
    pages_or_locale:   i32,
    name:              String,
}

impl OwnedRow {
    fn from_decoded(row: &[(String, ColumnValue<'_>)]) -> Option<Self> {
        let get = |name: &str| row.iter().find(|(n, _)| n == name).map(|(_, v)| v);

        let objid_table = match get("ObjidTable") {
            Some(ColumnValue::Long(v)) => *v,
            _ => 0,
        };
        let obj_type = match get("Type") {
            Some(ColumnValue::Short(v)) => CatalogObjectType::from_i16(*v),
            _ => return None,
        };
        let col_id = match get("Id") {
            Some(ColumnValue::Long(v)) => *v,
            _ => 0,
        };
        let coltyp_or_pgno = match get("ColtypOrPgnoFDP") {
            Some(ColumnValue::Long(v)) => *v,
            _ => 0,
        };
        let flags = match get("Flags") {
            Some(ColumnValue::Long(v)) => *v,
            _ => 0,
        };
        let pages_or_locale = match get("PagesOrLocale") {
            Some(ColumnValue::Long(v)) => *v,
            _ => 0,
        };
        let name = match get("Name") {
            Some(ColumnValue::Text(bytes)) => {
                String::from_utf8_lossy(bytes).into_owned()
            }
            _ => String::new(),
        };

        Some(OwnedRow {
            objid_table,
            obj_type,
            col_id,
            coltyp_or_pgno,
            flags,
            pages_or_locale,
            name,
        })
    }
}

// ─── Tests ──────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tst {
    use super::*;
    use crate::ese::tst::*;

    #[test]
    fn catalog_from_system_identity() {
        let Some((db, header)) = get_mdb_and_header() else { return };
        let reader = crate::ese::reader::SliceReader::new(db);
        let catalog = Catalog::from_db(&reader, &header)
            .expect("catalog parse should succeed");
        assert!(
            !catalog.tables.is_empty(),
            "expected at least one table in SystemIdentity.mdb catalog"
        );
        for tbl in &catalog.tables {
            assert!(!tbl.name.is_empty(), "table name must not be empty");
            assert_eq!(tbl.columns.len(), tbl.forensic_columns.len());
        }
    }

    #[test]
    fn catalog_from_ual_current() {
        let Some((db, header)) = get_mdb_and_header_ual() else { return };
        let reader = crate::ese::reader::SliceReader::new(db);
        let catalog = Catalog::from_db(&reader, &header)
            .expect("catalog parse should succeed for UAL/Current.mdb");
        assert!(
            !catalog.tables.is_empty(),
            "expected at least one table in UAL Current.mdb catalog"
        );
        for tbl in &catalog.tables {
            println!("  table: {} (fdp_page={}) columns={}", tbl.name, tbl.fdp_page, tbl.columns.len());
        }
    }
}
