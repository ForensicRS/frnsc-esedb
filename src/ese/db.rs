//! High-level entry point for reading ESE databases.
//!
//! # Example
//!
//! ```rust,no_run
//! use frnsc_esedb::ese::db::EseDb;
//!
//! let db = EseDb::open("path/to/file.mdb").unwrap();
//! for name in db.table_names() {
//!     println!("{name}");
//! }
//! if let Some(table) = db.table("CLIENTS") {
//!     for row in table.iter_rows() {
//!         if let Some(v) = row.get("Address") {
//!             println!("{v}");
//!         }
//!     }
//! }
//! ```

use std::collections::HashMap;
use std::path::Path;

use forensic_rs::err::{ForensicError, ForensicResult};
use forensic_rs::utils::time::Filetime;

use crate::ese::{
    catalog::{Catalog, TableDef},
    column::{ColumnDef, OwnedColumnValue, TableSchema},
    header::Header,
    lv::LongValueStore,
    page::{entries::PageEntry, root::RootEntry, Page, TreePage},
    reader::{FileReader, PageReader, SliceReader},
};

/// An open ESE database.  Holds a page reader, parsed header, and catalog.
pub struct EseDb {
    reader: Box<dyn PageReader>,
    pub(crate) header: Header,
    pub(crate) catalog: Catalog,
}

impl EseDb {
    /// Open an ESE database file from disk and parse its header and catalog.
    ///
    /// Pages are read on demand — the entire file is never loaded into memory.
    pub fn open(path: impl AsRef<Path>) -> ForensicResult<Self> {
        let reader = FileReader::open(path.as_ref()).map_err(|e| {
            ForensicError::bad_format_string(format!("Cannot open ESE file: {e}"))
        })?;
        let header = {
            let buf = reader.read_page(0, 4096.min(reader.total_size()))?;
            Header::from_buff(&buf)?
        };
        let catalog = Catalog::from_db(&reader, &header)?;
        Ok(Self { reader: Box::new(reader), header, catalog })
    }

    /// Parse an ESE database from an in-memory byte vector.
    pub fn from_bytes(data: Vec<u8>) -> ForensicResult<Self> {
        let reader = SliceReader(data);
        let header = {
            let buf = reader.read_page(0, reader.total_size())?;
            Header::from_buff(&buf)?
        };
        let catalog = Catalog::from_db(&reader, &header)?;
        Ok(Self { reader: Box::new(reader), header, catalog })
    }

    /// Reference to the parsed file header.
    pub fn header(&self) -> &Header {
        &self.header
    }

    /// Reference to the parsed catalog.
    pub fn catalog(&self) -> &Catalog {
        &self.catalog
    }

    /// Names of all user tables found in the catalog.
    pub fn table_names(&self) -> Vec<&str> {
        self.catalog.tables.iter().map(|t| t.name.as_str()).collect()
    }

    /// Get a table by name (case-insensitive).  Returns `None` if not found.
    pub fn table(&self, name: &str) -> Option<Table<'_>> {
        self.catalog.table(name).map(|def| Table { db: self, def })
    }

    /// Create a [`RowIter`] and column defs for a table directly from `EseDb`,
    /// without going through a temporary `Table` handle.  Used by the SqlDb
    /// bridge where the `Table` local cannot outlive `prepare()`.
    pub(crate) fn iter_table_rows(
        &self,
        name: &str,
    ) -> Option<(Vec<ColumnDef>, RowIter<'_>)> {
        let def = self.catalog.table(name)?;
        let schema = def.schema();
        let lv_store = def.lv_fdp_page.and_then(|lv_page| {
            LongValueStore::from_db(self.reader.as_ref(), &self.header, lv_page).ok()
        });
        Some((
            def.columns.clone(),
            RowIter {
                db: self,
                schema,
                lv_store,
                stack: vec![def.fdp_page],
                pending: Vec::new(),
            },
        ))
    }
}

// ─── Table ───────────────────────────────────────────────────────────────────

/// A handle to one table within an [`EseDb`].
pub struct Table<'db> {
    db: &'db EseDb,
    def: &'db TableDef,
}

impl<'db> Table<'db> {
    /// The table name.
    pub fn name(&self) -> &str {
        &self.def.name
    }

    /// Column definitions for this table.
    pub fn columns(&self) -> &[ColumnDef] {
        &self.def.columns
    }

    /// Iterate over all rows in this table.
    ///
    /// Long-value columns (LongText, LongBinary) are automatically resolved
    /// from the table's LV B-tree when one exists.
    pub fn iter_rows(&self) -> RowIter<'_> {
        let lv_store = self.def.lv_fdp_page.and_then(|lv_page| {
            LongValueStore::from_db(self.db.reader.as_ref(), &self.db.header, lv_page).ok()
        });
        RowIter {
            db: self.db,
            schema: self.def.schema(),
            lv_store,
            stack: vec![self.def.fdp_page],
            pending: Vec::new(),
        }
    }
}

// ─── RowIter ─────────────────────────────────────────────────────────────────

/// Iterator that traverses a table's B-tree and yields decoded [`Row`]s.
pub struct RowIter<'db> {
    db: &'db EseDb,
    schema: TableSchema,
    lv_store: Option<LongValueStore>,
    /// Pages still to be visited (acts as a DFS stack).
    stack: Vec<u32>,
    /// Rows decoded from the current leaf page, waiting to be yielded.
    pending: Vec<Row>,
}

impl<'db> Iterator for RowIter<'db> {
    type Item = Row;

    fn next(&mut self) -> Option<Row> {
        loop {
            // Yield any buffered rows first.
            if let Some(row) = self.pending.pop() {
                return Some(row);
            }

            let page_n = self.stack.pop()?;
            let page = match load_page(self.db.reader.as_ref(), &self.db.header, page_n) {
                Ok(p) => p,
                Err(_) => continue,
            };
            if !page.valid_page() || page.empty_page() {
                continue;
            }

            match page.process_page() {
                Err(_) => continue,
                Ok(tree) => self.process_tree_page(tree),
            }
        }
    }
}

impl<'db> RowIter<'db> {
    fn decode_tv(
        schema: &TableSchema,
        lv_store: Option<&LongValueStore>,
        tv: &crate::ese::page::entries::table_value::TableValueEntry<'_>,
    ) -> Row {
        let cols: Vec<(String, OwnedColumnValue)> = schema
            .decode_record(tv, lv_store)
            .into_iter()
            .map(|(n, v)| (n, v.into()))
            .collect();
        Row::from_pairs(cols)
    }

    fn process_tree_page(&mut self, tree: TreePage<'_>) {
        match tree {
            TreePage::Leaf(leaf) => {
                for entry in leaf.entries.iter().rev() {
                    if let PageEntry::TableValue(ref tv) = entry.data {
                        self.pending
                            .push(Self::decode_tv(&self.schema, self.lv_store.as_ref(), tv));
                    }
                }
            }
            TreePage::Branch(branch) => {
                for entry in branch.entries.iter().rev() {
                    self.stack.push(entry.child_page_number);
                }
            }
            TreePage::Root(root) => {
                for entry in root.entries.iter().rev() {
                    match entry {
                        RootEntry::Branch(b) => self.stack.push(b.child_page_number),
                        RootEntry::Leaf(leaf_entry) => {
                            if let PageEntry::TableValue(ref tv) = leaf_entry.data {
                                self.pending.push(Self::decode_tv(
                                    &self.schema,
                                    self.lv_store.as_ref(),
                                    tv,
                                ));
                            }
                        }
                    }
                }
            }
        }
    }
}

// ─── Row ─────────────────────────────────────────────────────────────────────

/// A single decoded table row with owned column values.
///
/// Column values are stored in insertion order (matching the schema) and indexed
/// by lowercased column name for O(1) case-insensitive lookups.
#[derive(Debug, Clone)]
pub struct Row {
    names: Vec<String>,
    values: Vec<OwnedColumnValue>,
    /// Maps lowercased column name → index into `names`/`values`.
    index: HashMap<String, usize>,
}

impl Row {
    /// Build a `Row` from an ordered list of `(name, value)` pairs.
    pub(crate) fn from_pairs(pairs: Vec<(String, OwnedColumnValue)>) -> Self {
        let mut names = Vec::with_capacity(pairs.len());
        let mut values = Vec::with_capacity(pairs.len());
        let mut index = HashMap::with_capacity(pairs.len());
        for (i, (name, value)) in pairs.into_iter().enumerate() {
            index.insert(name.to_lowercase(), i);
            names.push(name);
            values.push(value);
        }
        Row { names, values, index }
    }

    /// Look up a column value by name (case-insensitive).
    pub fn get(&self, name: &str) -> Option<&OwnedColumnValue> {
        self.index.get(&name.to_lowercase()).map(|&i| &self.values[i])
    }

    /// Number of columns in this row.
    pub fn len(&self) -> usize {
        self.values.len()
    }

    /// Returns `true` if the row has no columns.
    pub fn is_empty(&self) -> bool {
        self.values.is_empty()
    }

    /// Iterate over `(column_name, value)` pairs in schema order.
    pub fn iter(&self) -> impl Iterator<Item = (&str, &OwnedColumnValue)> {
        self.names.iter().zip(self.values.iter()).map(|(n, v)| (n.as_str(), v))
    }

    /// Look up a column value by position (0-based, schema order).
    pub fn get_by_index(&self, i: usize) -> Option<&OwnedColumnValue> {
        self.values.get(i)
    }

    /// Return the column name at the given position.
    pub fn column_name(&self, i: usize) -> Option<&str> {
        self.names.get(i).map(|s| s.as_str())
    }

    // ── Typed accessors ──────────────────────────────────────────────────────

    /// Get a text column's decoded string value (case-insensitive lookup).
    ///
    /// Returns `Some` for `Text` and `LongText` variants; returns `None` for
    /// all other types or if the column is absent.
    pub fn get_str(&self, name: &str) -> Option<String> {
        self.get(name).and_then(|v| v.as_string())
    }

    /// Get a column as `i64`, coercing from any integer type (case-insensitive).
    pub fn get_i64(&self, name: &str) -> Option<i64> {
        self.get(name).and_then(|v| v.as_i64())
    }

    /// Get a column as `f64`, coercing from float types (case-insensitive).
    pub fn get_f64(&self, name: &str) -> Option<f64> {
        self.get(name).and_then(|v| v.as_f64())
    }

    /// Get raw bytes from a `Binary` or `LongBinary` column (case-insensitive).
    pub fn get_bytes(&self, name: &str) -> Option<&[u8]> {
        self.get(name).and_then(|v| v.as_bytes())
    }

    /// Get a boolean value from a `Bit` column (case-insensitive).
    pub fn get_bool(&self, name: &str) -> Option<bool> {
        self.get(name).and_then(|v| v.as_bool())
    }

    /// Get a `Filetime` from a `DateTime` column (case-insensitive).
    pub fn get_datetime(&self, name: &str) -> Option<Filetime> {
        self.get(name).and_then(|v| v.as_datetime())
    }

    /// Get a 16-byte GUID from a `GUID` column (case-insensitive).
    pub fn get_guid(&self, name: &str) -> Option<[u8; 16]> {
        self.get(name).and_then(|v| v.as_guid())
    }
}

// ─── Internal helpers ────────────────────────────────────────────────────────

fn load_page<'r>(reader: &'r dyn PageReader, header: &Header, page_n: u32) -> ForensicResult<Page<'r>> {
    let offset = header.page_to_file_offset(page_n as u64) as usize;
    let size = header.page_size as usize;
    let data = reader.read_page(offset, size)?;
    Page::new(data, page_n, header)
}

// ─── Tests ───────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tst {
    use super::*;
    use crate::ese::tst::*;

    #[test]
    fn esedb_from_system_identity() {
        let (data, _) = get_mdb_and_header();
        let db = EseDb::from_bytes(data).expect("EseDb::from_bytes should succeed");
        let names = db.table_names();
        assert!(!names.is_empty(), "expected at least one table");
        for name in &names {
            let table = db.table(name).expect("table() should find table from table_names()");
            assert_eq!(*name, table.name());
        }
    }

    #[test]
    fn esedb_iterate_ual_clients() {
        let (data, _) = get_mdb_and_header_ual();
        let db = EseDb::from_bytes(data).expect("EseDb::from_bytes should succeed for UAL");
        let names = db.table_names();
        assert!(!names.is_empty());
        // Iterate the first table to confirm the iterator works without panic.
        let first = db.table(names[0]).expect("first table should exist");
        let rows: Vec<Row> = first.iter_rows().take(10).collect();
        // We just need the iterator to not panic; a table may be empty.
        let _ = rows;
    }
}
