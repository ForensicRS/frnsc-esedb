//! `forensic_rs::traits::db` bridge for ESE databases.
//!
//! Implements `ForensicDb`/`ForensicTable`/`ForensicRows` on top of [`EseDb`],
//! allowing ESE databases to be consumed by any tool that works with the
//! framework's unified database trait — the replacement for the pre-0.14
//! `SqlDb`/`SqlStatement` pair (deleted upstream; see the 0.14 CHANGELOG).
//!
//! `SqlCapable` (real SQL-statement execution) is deliberately **not**
//! implemented here: the old `SELECT * FROM <table>` pseudo-parser existed
//! only because `SqlDb::prepare` was the sole way to get rows in 0.13.
//! `ForensicDb::table(name)` now expresses that directly, with no string
//! parsing (and no parsing bugs — the old bridge's `to_uppercase`/byte-index
//! mismatch is gone along with it).

use std::borrow::Cow;

use forensic_rs::err::ForensicResult;
use forensic_rs::provenance::{Locus, Recovery};
use forensic_rs::traits::db::{
    ForensicColumnType, ForensicDb, ForensicRows, ForensicTable, ForensicValueRef, RecoverRows,
};

use crate::ese::column::{ColumnDef, ColumnType, OwnedColumnValue};
use crate::ese::db::{EseDb, Row, RowIter, Table};
use crate::ese::recovery::RecoveredRow;

impl ForensicDb for EseDb {
    fn list_tables(&self) -> ForensicResult<Vec<String>> {
        Ok(self.table_names().into_iter().map(str::to_owned).collect())
    }

    fn table(&self, name: &str) -> ForensicResult<Box<dyn ForensicTable + '_>> {
        Ok(Box::new(EseDb::table(self, name)?))
    }

    fn as_recovery(&self) -> Option<&dyn RecoverRows> {
        Some(self)
    }
}

impl RecoverRows for EseDb {
    /// Rows still addressable via a page's tag array but marked deleted
    /// (`TAG_DEFUNCT`). See [`crate::ese::recovery::defunct`] for the
    /// admission gate every candidate is decoded through.
    fn recovered_rows(&self, table: &str) -> ForensicResult<Box<dyn ForensicRows + '_>> {
        let columns = EseDb::table(self, table)?.columns();
        let (rows, stats) = crate::ese::recovery::defunct::recover_defunct_rows(self, table)?;
        Ok(Box::new(RecoveredEseRows::new(rows, columns, Recovery::DeletedMetadata, stats)))
    }

    /// Candidate rows found in a live page's unallocated slack. See
    /// [`crate::ese::recovery::slack`] for why this source applies a
    /// stricter admission bar than [`Self::recovered_rows`].
    ///
    /// `row_history` is left at the trait's `EmptyRows` default: it is
    /// documented as rows recovered by replaying a transaction log, which
    /// this crate deliberately does not attempt (see `src/ese/log/mod.rs`'s
    /// module documentation). The caller-keyed grouping this crate does
    /// support (`EseDb::row_history`) is a different operation -- multi-source
    /// version history, not log replay -- and stays an inherent method rather
    /// than overloading a trait method whose contract it doesn't match.
    fn slack_rows(&self, table: &str) -> ForensicResult<Box<dyn ForensicRows + '_>> {
        let columns = EseDb::table(self, table)?.columns();
        let (rows, stats) = crate::ese::recovery::slack::recover_slack_rows(self, table)?;
        Ok(Box::new(RecoveredEseRows::new(rows, columns, Recovery::Slack, stats)))
    }
}

impl<'db> ForensicTable for Table<'db> {
    fn name(&self) -> &str {
        Table::name(self)
    }

    fn columns(&self) -> &[forensic_rs::traits::db::ForensicColumnDef] {
        Table::forensic_columns(self)
    }

    fn iter_rows(&self) -> ForensicResult<Box<dyn ForensicRows + '_>> {
        Ok(Box::new(EseRows {
            inner: Table::iter_rows(self),
            columns: Table::columns(self),
            current: None,
        }))
    }

    // `row_count`: left at the trait's `None` default. MSysObjects'
    // `PagesOrLocale`/`Stats` fields are engine estimates, not exact counts —
    // returning one through an API documented as a row count would fabricate
    // a precision the data doesn't have.
}

/// Adapts [`RowIter`]'s "advance-and-fetch" shape to `ForensicRows`'s
/// two-phase "advance, then read by index" protocol.
struct EseRows<'db> {
    inner: RowIter<'db>,
    columns: &'db [ColumnDef],
    current: Option<Row>,
}

impl<'db> ForensicRows for EseRows<'db> {
    fn column_count(&self) -> usize {
        self.columns.len()
    }

    fn column_name(&self, i: usize) -> Option<&str> {
        self.columns.get(i).map(|c| c.name.as_str())
    }

    fn column_names(&self) -> Vec<&str> {
        self.columns.iter().map(|c| c.name.as_str()).collect()
    }

    fn column_type(&self, i: usize) -> ForensicColumnType {
        self.columns
            .get(i)
            .map(|c| c.col_type.forensic_type())
            .unwrap_or(ForensicColumnType::Null)
    }

    fn next(&mut self) -> ForensicResult<bool> {
        self.current = self.inner.next();
        Ok(self.current.is_some())
    }

    fn read_ref(&self, i: usize) -> ForensicResult<ForensicValueRef<'_>> {
        let row = self.current.as_ref().ok_or_else(|| {
            forensic_rs::err::ForensicError::missing_data("row", "call next() before read_ref()".into())
        })?;
        let col_type = self.columns.get(i).map(|c| c.col_type);
        let value = row.get_by_index(i).ok_or_else(|| {
            forensic_rs::err::ForensicError::missing_data("column", "column index out of range".into())
        })?;
        Ok(to_value_ref(value, col_type))
    }

    // `read_multi_ref` is left at the trait's default (wraps the single value
    // in a one-element `Vec`). ESE tagged columns can carry more than one
    // value per row, but the current decoder (`TableSchema::decode_record`)
    // only surfaces the first match for a given tagged column ID — extending
    // it to collect every match is a decoder change, not a migration change,
    // and is tracked as a follow-up rather than folded in here.

    // `allocated`/`recovery`/`locus` are overridden explicitly, not left at
    // the trait's defaults, even though the defaults already agree with the
    // answer here: `RowIter` skips `TAG_DEFUNCT` entries (see `db.rs`), so
    // every row this cursor yields really is a live, allocated read. Stating
    // it explicitly means a future default change upstream can't silently
    // relabel these rows.
    fn allocated(&self) -> bool {
        true
    }

    fn recovery(&self) -> Recovery {
        Recovery::Allocated
    }

    fn locus(&self) -> Option<Locus> {
        let (page, tag) = self.inner.current_locus()?;
        Some(crate::ese::recovery::tagged_locus(page, tag))
    }
}

/// Convert a decoded [`OwnedColumnValue`] to the framework's borrowed value
/// type. `Binary`/`LongBinary` borrow zero-copy; `Text`/`LongText` must
/// decode the raw bytes (codepage-aware), so those allocate.
fn to_value_ref(value: &OwnedColumnValue, col_type: Option<ColumnType>) -> ForensicValueRef<'_> {
    match value {
        OwnedColumnValue::Nil => ForensicValueRef::Null,
        OwnedColumnValue::Bit(v) => ForensicValueRef::Bool(*v),
        OwnedColumnValue::UnsignedByte(v) => ForensicValueRef::U64(*v as u64),
        OwnedColumnValue::UnsignedShort(v) => ForensicValueRef::U64(*v as u64),
        OwnedColumnValue::UnsignedLong(v) => ForensicValueRef::U64(*v as u64),
        OwnedColumnValue::Short(v) => ForensicValueRef::I64(*v as i64),
        OwnedColumnValue::Long(v) => ForensicValueRef::I64(*v as i64),
        OwnedColumnValue::Currency(v) => ForensicValueRef::I64(*v),
        OwnedColumnValue::LongLong(v) => ForensicValueRef::I64(*v),
        OwnedColumnValue::IEEESingle(v) => ForensicValueRef::F64(*v as f64),
        OwnedColumnValue::IEEEDouble(v) => ForensicValueRef::F64(*v),
        OwnedColumnValue::DateTime(v) => ForensicValueRef::DateTime(*v),
        OwnedColumnValue::GUID(b) => ForensicValueRef::Guid(*b),
        OwnedColumnValue::Binary(b) | OwnedColumnValue::LongBinary(b) => {
            ForensicValueRef::Binary(Cow::Borrowed(b.as_slice()))
        }
        OwnedColumnValue::Text(b) | OwnedColumnValue::LongText(b) => {
            let _ = col_type; // reserved: codepage-aware decode lives on `bytes_to_string`
            ForensicValueRef::Text(Cow::Owned(crate::ese::column::bytes_to_string(b)))
        }
    }
}

/// Adapts an already-materialized batch of [`RecoveredRow`]s (from
/// [`crate::ese::recovery::defunct::recover_defunct_rows`] or
/// [`crate::ese::recovery::slack::recover_slack_rows`]) to the
/// `ForensicRows` cursor protocol.
///
/// Unlike [`EseRows`], this owns its rows outright rather than driving a
/// lazy walk -- both recovery sources already return a `Vec` -- so `next()`
/// just advances through it.
struct RecoveredEseRows<'db> {
    columns: &'db [ColumnDef],
    rows: std::vec::IntoIter<RecoveredRow>,
    /// This cursor's rows all come from one recovery source
    /// (`recovered_rows` or `slack_rows`), so `recovery()` is one constant
    /// value for the whole cursor, set at construction -- see
    /// [`RecoverRows::recovered_rows`]/[`RecoverRows::slack_rows`].
    recovery: Recovery,
    /// How much ground the scan behind this cursor's rows covered -- see
    /// `scan_report()`. Unlike `recovery`, this is diagnostic, not part of
    /// any row's own trustworthiness; it answers "how hard did the scan
    /// look", which the previous inherent API dropped on the floor
    /// (`let (rows, _stats) = ...`) for lack of anywhere to put it.
    stats: crate::ese::recovery::RecoveryStats,
    current: Option<RecoveredRow>,
}

impl<'db> RecoveredEseRows<'db> {
    fn new(
        rows: Vec<RecoveredRow>,
        columns: &'db [ColumnDef],
        recovery: Recovery,
        stats: crate::ese::recovery::RecoveryStats,
    ) -> Self {
        Self { columns, rows: rows.into_iter(), recovery, stats, current: None }
    }
}

impl<'db> ForensicRows for RecoveredEseRows<'db> {
    fn column_count(&self) -> usize {
        self.columns.len()
    }

    fn column_name(&self, i: usize) -> Option<&str> {
        self.columns.get(i).map(|c| c.name.as_str())
    }

    fn column_names(&self) -> Vec<&str> {
        self.columns.iter().map(|c| c.name.as_str()).collect()
    }

    fn column_type(&self, i: usize) -> ForensicColumnType {
        self.columns
            .get(i)
            .map(|c| c.col_type.forensic_type())
            .unwrap_or(ForensicColumnType::Null)
    }

    fn next(&mut self) -> ForensicResult<bool> {
        self.current = self.rows.next();
        Ok(self.current.is_some())
    }

    fn read_ref(&self, i: usize) -> ForensicResult<ForensicValueRef<'_>> {
        let recovered = self.current.as_ref().ok_or_else(|| {
            forensic_rs::err::ForensicError::missing_data("row", "call next() before read_ref()".into())
        })?;
        let col_type = self.columns.get(i).map(|c| c.col_type);
        let value = recovered.value().get_by_index(i).ok_or_else(|| {
            forensic_rs::err::ForensicError::missing_data("column", "column index out of range".into())
        })?;
        Ok(to_value_ref(value, col_type))
    }

    fn allocated(&self) -> bool {
        false
    }

    fn recovery(&self) -> Recovery {
        self.recovery
    }

    fn locus(&self) -> Option<Locus> {
        self.current.as_ref().map(RecoveredRow::locus)
    }

    fn scan_report(&self) -> Option<forensic_rs::recovery::RecoveryReport> {
        Some(self.stats.to_report())
    }
}
