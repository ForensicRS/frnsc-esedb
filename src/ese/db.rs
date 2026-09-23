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
//! if let Ok(table) = db.table("CLIENTS") {
//!     for row in table.iter_rows() {
//!         if let Some(v) = row.get("Address") {
//!             println!("{v}");
//!         }
//!     }
//! }
//! ```

use std::collections::HashMap;
use std::path::Path;
use std::sync::{Arc, RwLock};

use forensic_rs::err::{ForensicError, ForensicResult};
use forensic_rs::utils::time::ForensicTimestamp;

use crate::ese::{
    catalog::{Catalog, TableDef},
    column::{ColumnDef, OwnedColumnValue, TableSchema},
    header::Header,
    lv::LongValueStore,
    page::entries::PageEntry,
    reader::{FileReader, PageReader, SliceReader},
    tree::{self, TreeStats, TreeWalker},
};

/// An open ESE database.  Holds a page reader, parsed header, and catalog.
///
/// `Send + Sync`: `forensic_rs::traits::db::ForensicDb` requires it, since a
/// mounted database is cached and shared across parallel pipeline workers.
/// `PageReader` implementations are `Send + Sync` (see `reader.rs`), `Header`/
/// `Catalog` are plain data, and `lv_cache` is an `RwLock`, so `EseDb` gets
/// this for free.
pub struct EseDb {
    reader: Box<dyn PageReader>,
    pub(crate) header: Header,
    pub(crate) catalog: Catalog,
    /// Long-value B-trees, memoized per LV root page. Without this, every
    /// `iter_rows()` call on a table with long text/binary columns re-walked
    /// the entire LV B-tree from scratch.
    lv_cache: RwLock<HashMap<u32, Arc<LongValueStore>>>,
}

impl EseDb {
    /// Open an ESE database file from disk and parse its header and catalog.
    ///
    /// Pages are read on demand — the entire file is never loaded into memory.
    pub fn open(path: impl AsRef<Path>) -> ForensicResult<Self> {
        let reader = FileReader::open(path.as_ref()).map_err(|e| {
            ForensicError::io_error_with_source(e, "Cannot open ESE file")
        })?;
        Self::from_reader(Box::new(reader))
    }

    /// Parse an ESE database from an in-memory byte vector.
    pub fn from_bytes(data: Vec<u8>) -> ForensicResult<Self> {
        Self::from_reader(Box::new(SliceReader::new(data)))
    }

    /// Parse an ESE database from an already-open `forensic_rs` `VirtualFile`
    /// (used by [`crate::ese::format::EseFormatFactory`]).
    pub fn from_virtual_file(file: Box<dyn forensic_rs::traits::vfs::VirtualFile>) -> ForensicResult<Self> {
        Self::from_reader(Box::new(crate::ese::reader::VirtualFileReader::new(file)?))
    }

    /// Shared constructor: parse the header (from the first
    /// `min(4096, total_size)` bytes — enough for the fixed-size header
    /// struct without reading the whole file) and the catalog, then wrap
    /// them with the given page reader.
    pub(crate) fn from_reader(reader: Box<dyn PageReader>) -> ForensicResult<Self> {
        let header = {
            let buf = reader.read_page(0, 4096.min(reader.total_size()))?;
            Header::from_buff(&buf)?
        };
        let catalog = Catalog::from_db(reader.as_ref(), &header)?;
        Ok(Self {
            reader,
            header,
            catalog,
            lv_cache: RwLock::new(HashMap::new()),
        })
    }

    /// Reference to the parsed file header.
    pub fn header(&self) -> &Header {
        &self.header
    }

    /// Reference to the parsed catalog.
    pub fn catalog(&self) -> &Catalog {
        &self.catalog
    }

    /// The underlying page reader. Crate-internal: lets sibling modules
    /// (currently [`crate::ese::recovery`]) drive their own B-tree walks
    /// with [`crate::ese::tree::TreeWalker`] the same way [`RowIter`] does,
    /// without duplicating `EseDb`'s construction logic.
    pub(crate) fn reader(&self) -> &dyn PageReader {
        self.reader.as_ref()
    }

    /// Names of all user tables found in the catalog.
    pub fn table_names(&self) -> Vec<&str> {
        self.catalog.tables.iter().map(|t| t.name.as_str()).collect()
    }

    /// Get a table by name (case-insensitive).
    pub fn table(&self, name: &str) -> ForensicResult<Table<'_>> {
        let def = self.catalog.table(name).ok_or_else(|| {
            ForensicError::missing_data("table", "table not found in ESE database".into())
        })?;
        Ok(Table { db: self, def })
    }

    /// Row cursor for `name`, bound to the database's own lifetime rather
    /// than to any intermediate `Table` handle — this is what lets
    /// `SrumDatabase`'s per-table accessors (and any `Box<dyn ForensicRows>`
    /// caller) return just a cursor.
    pub fn rows(&self, name: &str) -> ForensicResult<RowIter<'_>> {
        Ok(self.table(name)?.iter_rows())
    }

    /// Rows for `table` still addressable via the page tag array but marked
    /// deleted (`TAG_DEFUNCT`). See [`crate::ese::recovery`] for the scope
    /// and soundness policy, and [`Self::recovered_slack_rows`] for the
    /// second (riskier) recovery source.
    pub fn recovered_rows(
        &self,
        table: &str,
    ) -> ForensicResult<(Vec<crate::ese::recovery::RecoveredRow>, crate::ese::recovery::RecoveryStats)> {
        crate::ese::recovery::defunct::recover_defunct_rows(self, table)
    }

    /// Candidate rows for `table` found in live pages' unallocated slack
    /// (the region between a page's used data and its tag array). See
    /// [`crate::ese::recovery::slack`] for why this source applies a
    /// stricter admission bar than [`Self::recovered_rows`].
    pub fn recovered_slack_rows(
        &self,
        table: &str,
    ) -> ForensicResult<(Vec<crate::ese::recovery::RecoveredRow>, crate::ese::recovery::RecoveryStats)> {
        crate::ese::recovery::slack::recover_slack_rows(self, table)
    }

    /// Group `table`'s live and recovered rows by `key_columns`, so every
    /// version of "the same" logical row (current, deleted, slack-carved)
    /// is visible together, with disagreement surfaced rather than
    /// resolved. See [`crate::ese::recovery::history`] for why the key is
    /// caller-supplied rather than auto-detected, and for the scan
    /// diagnostics and per-source skip counts the returned report carries
    /// alongside the groupings themselves.
    pub fn row_history(
        &self,
        table: &str,
        key_columns: &[&str],
    ) -> ForensicResult<crate::ese::recovery::history::RowHistoryReport> {
        crate::ese::recovery::history::row_history(self, table, key_columns)
    }

    /// Look up (or build and cache) the long-value store rooted at `lv_page`.
    fn long_values(&self, lv_page: u32) -> Option<Arc<LongValueStore>> {
        if let Some(store) = self.lv_cache.read().unwrap_or_else(|e| e.into_inner()).get(&lv_page) {
            return Some(store.clone());
        }
        let store = match LongValueStore::from_db(self.reader.as_ref(), &self.header, lv_page) {
            Ok(s) => Arc::new(s),
            Err(e) => {
                forensic_rs::warn!(
                    "ESE: long-value tree at page {lv_page} unreadable ({e}); LongText/LongBinary columns for this table will be NULL"
                );
                return None;
            }
        };
        self.lv_cache
            .write()
            .unwrap_or_else(|e| e.into_inner())
            .insert(lv_page, store.clone());
        Some(store)
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
    pub fn columns(&self) -> &'db [ColumnDef] {
        &self.def.columns
    }

    /// `forensic_rs`-shaped column definitions, precomputed in
    /// `Catalog::from_db` and index-aligned with [`Table::columns`].
    pub(crate) fn forensic_columns(&self) -> &'db [forensic_rs::traits::db::ForensicColumnDef] {
        &self.def.forensic_columns
    }

    /// Iterate over all rows in this table.
    ///
    /// Long-value columns (LongText, LongBinary) are automatically resolved
    /// from the table's LV B-tree when one exists (cached across calls — see
    /// `EseDb`'s internal long-value cache).
    ///
    /// The returned [`RowIter`] borrows from the underlying [`EseDb`] (`'db`),
    /// not from this `Table` handle, so the iterator remains valid even after
    /// the `Table` value is dropped.
    pub fn iter_rows(&self) -> RowIter<'db> {
        let lv_store = self.def.lv_fdp_page.and_then(|lv_page| self.db.long_values(lv_page));
        RowIter {
            db: self.db,
            schema: self.def.schema(),
            lv_store,
            walker: TreeWalker::new(self.def.fdp_page),
            pending: Vec::new(),
            current_locus: None,
        }
    }
}

// ─── RowIter ─────────────────────────────────────────────────────────────────

/// Iterator that traverses a table's B-tree and yields decoded [`Row`]s.
///
/// Cycle-safe: driven by [`TreeWalker`], which tracks visited page numbers
/// directly rather than bounding recursion depth, so a branch page that
/// (accidentally or adversarially) points back at an already-visited page
/// terminates instead of looping.
pub struct RowIter<'db> {
    db: &'db EseDb,
    schema: TableSchema,
    lv_store: Option<Arc<LongValueStore>>,
    walker: TreeWalker,
    /// Rows decoded from the current leaf page, waiting to be yielded, each
    /// with the `(page, tag)` it was decoded from.
    pending: Vec<(Row, u32, u16)>,
    /// `(page, tag)` of the row most recently returned by `next()`.
    current_locus: Option<(u32, u16)>,
}

impl<'db> Iterator for RowIter<'db> {
    type Item = Row;

    fn next(&mut self) -> Option<Row> {
        loop {
            // Yield any buffered rows first.
            if let Some((row, page, tag)) = self.pending.pop() {
                self.current_locus = Some((page, tag));
                return Some(row);
            }

            let page = self.walker.next_page(self.db.reader.as_ref(), &self.db.header)?;
            let page_number = page.page_number;
            match page.process_page() {
                Ok(tree) => {
                    self.walker.push_children(&tree);
                    self.process_tree_page(&tree, page_number);
                }
                Err(e) => {
                    forensic_rs::debug!("ESE: cannot process page {}: {e}", page.page_number);
                    self.walker.record_unparsable();
                }
            }
        }
    }
}

impl<'db> RowIter<'db> {
    /// Diagnostic counters for this cursor's traversal so far (pages skipped
    /// as unreadable/invalid/revisited/unparsable).
    pub fn stats(&self) -> TreeStats {
        self.walker.stats()
    }

    /// `(page, tag)` the row most recently returned by `next()` was decoded
    /// from — the address a `Locus::Record` needs. `None` before the first
    /// `next()`.
    pub fn current_locus(&self) -> Option<(u32, u16)> {
        self.current_locus
    }

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

    fn process_tree_page(&mut self, tree: &crate::ese::page::TreePage<'_>, page_number: u32) {
        // Leaf entries decode in reverse so `pending.pop()` yields them in
        // forward (on-disk) order.
        let mut decoded = Vec::new();
        tree::for_each_leaf_page_entry(tree, |entry| {
            // Defunct-tagged entries are deleted rows the engine has not yet
            // reclaimed. `leaf_entries()` still decodes them (the recovery
            // sources need exactly these), but ordinary iteration must be an
            // allocated-only view: yielding them here would let a
            // `ForensicRows` cursor report `allocated() == true` for a
            // deleted row, which grades it as trustworthy as a live read.
            // Reach them through `EseDb::as_recovery()` instead.
            if entry.defunct {
                return;
            }
            if let PageEntry::TableValue(tv) = &entry.data {
                decoded.push((
                    Self::decode_tv(&self.schema, self.lv_store.as_deref(), tv),
                    page_number,
                    entry.tag_index,
                ));
            }
        });
        decoded.reverse();
        self.pending.extend(decoded);
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

    /// Get a `ForensicTimestamp` from a `DateTime` column (case-insensitive).
    pub fn get_datetime(&self, name: &str) -> Option<ForensicTimestamp> {
        self.get(name).and_then(|v| v.as_datetime())
    }

    /// Get a 16-byte GUID from a `GUID` column (case-insensitive).
    pub fn get_guid(&self, name: &str) -> Option<[u8; 16]> {
        self.get(name).and_then(|v| v.as_guid())
    }
}

// ─── Tests ───────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tst {
    use super::*;
    use crate::ese::tst::*;

    fn assert_send_sync<T: Send + Sync>() {}

    #[test]
    fn esedb_is_send_sync() {
        assert_send_sync::<EseDb>();
    }

    #[test]
    fn esedb_from_system_identity() {
        let Some((data, _)) = get_mdb_and_header() else { return };
        let db = EseDb::from_bytes(data).expect("EseDb::from_bytes should succeed");
        let names = db.table_names();
        assert!(!names.is_empty(), "expected at least one table");
        for name in &names {
            let table = db.table(name).expect("table() should find table from table_names()");
            assert_eq!(*name, table.name());
        }
        assert!(db.table("does-not-exist-anywhere").is_err());
    }

    #[test]
    fn esedb_iterate_ual_clients() {
        let Some((data, _)) = get_mdb_and_header_ual() else { return };
        let db = EseDb::from_bytes(data).expect("EseDb::from_bytes should succeed for UAL");
        let names = db.table_names();
        assert!(!names.is_empty());
        // Iterate the first table to confirm the iterator works without panic.
        let first = db.table(names[0]).expect("first table should exist");
        let rows: Vec<Row> = first.iter_rows().take(10).collect();
        // We just need the iterator to not panic; a table may be empty.
        let _ = rows;
    }

    #[test]
    fn long_value_store_is_cached_across_iter_rows_calls() {
        let Some(bytes) = get_srum_bytes() else { return };
        let db = EseDb::from_bytes(bytes).expect("SRUDB.dat should parse");
        // Find any table with an LV tree.
        let Some(def) = db.catalog.tables.iter().find(|t| t.lv_fdp_page.is_some()) else { return };
        let lv_page = def.lv_fdp_page.unwrap();
        assert!(db.lv_cache.read().unwrap().is_empty());
        let table = db.table(&def.name).unwrap();
        let _ = table.iter_rows().count();
        assert!(db.lv_cache.read().unwrap().contains_key(&lv_page));
        let cached = db.lv_cache.read().unwrap().get(&lv_page).unwrap().clone();
        let _ = table.iter_rows().count();
        // Second call must reuse the same Arc, not rebuild.
        assert!(Arc::ptr_eq(&cached, db.lv_cache.read().unwrap().get(&lv_page).unwrap()));
    }
}
