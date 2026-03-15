//! [`SqlDb`] / [`SqlStatement`] bridge for ESE databases.
//!
//! Implements the forensic-rs SQL traits on top of [`EseDb`], allowing ESE
//! databases to be consumed by any tool that works with `SqlDb`.
//!
//! Only `SELECT * FROM <table>` is supported — ESE is not a SQL engine.

use std::io::Read;

use forensic_rs::err::{ForensicError, ForensicResult};
use forensic_rs::traits::sql::{
    ColumnType as SqlColumnType, ColumnValue as SqlColumnValue, SqlDb, SqlStatement,
};
use forensic_rs::traits::vfs::VirtualFile;

use crate::ese::column::{ColumnDef, OwnedColumnValue};
use crate::ese::db::{EseDb, Row, RowIter};

// ─── SqlDb for EseDb ─────────────────────────────────────────────────────────

impl SqlDb for EseDb {
    fn list_tables(&self) -> ForensicResult<Vec<String>> {
        Ok(self.table_names().into_iter().map(|s| s.to_owned()).collect())
    }

    fn prepare<'a>(
        &'a self,
        statement: &'a str,
    ) -> ForensicResult<Box<dyn SqlStatement + 'a>> {
        let table_name = parse_select_star(statement)?;
        let (column_defs, iter) = self.iter_table_rows(&table_name).ok_or_else(|| {
            ForensicError::missing_str("Table not found in ESE database")
        })?;
        Ok(Box::new(EseStatement {
            column_defs,
            iter,
            current_row: None,
        }))
    }

    fn from_file(&self, mut file: Box<dyn VirtualFile>) -> ForensicResult<Box<dyn SqlDb>> {
        let mut buf = Vec::new();
        file.read_to_end(&mut buf)
            .map_err(|e| ForensicError::bad_format_string(format!("Failed to read ESE file: {e}")))?;
        let db = EseDb::from_bytes(buf)?;
        Ok(Box::new(db))
    }
}

// ─── EseStatement ────────────────────────────────────────────────────────────

/// A pseudo-SQL statement wrapping a [`RowIter`] over one ESE table.
pub struct EseStatement<'db> {
    column_defs: Vec<ColumnDef>,
    iter: RowIter<'db>,
    current_row: Option<Row>,
}

impl<'db> SqlStatement for EseStatement<'db> {
    fn column_count(&self) -> usize {
        self.column_defs.len()
    }

    fn column_name(&self, i: usize) -> Option<&str> {
        self.column_defs.get(i).map(|c| c.name.as_str())
    }

    fn column_names(&self) -> Vec<&str> {
        self.column_defs.iter().map(|c| c.name.as_str()).collect()
    }

    fn column_type(&self, i: usize) -> SqlColumnType {
        match self.column_defs.get(i) {
            Some(c) => ese_to_sql_column_type(c.col_type),
            None => SqlColumnType::Null,
        }
    }

    fn next(&mut self) -> ForensicResult<bool> {
        match self.iter.next() {
            Some(row) => {
                self.current_row = Some(row);
                Ok(true)
            }
            None => {
                self.current_row = None;
                Ok(false)
            }
        }
    }

    fn read(&self, i: usize) -> ForensicResult<SqlColumnValue> {
        let row = self.current_row.as_ref().ok_or_else(|| {
            ForensicError::missing_str("No current row — call next() first")
        })?;
        match row.get_by_index(i) {
            Some(v) => Ok(owned_to_sql_value(v)),
            None => Ok(SqlColumnValue::Null),
        }
    }
}

// ─── Helpers ─────────────────────────────────────────────────────────────────

/// Parse `SELECT * FROM <table_name>` (case-insensitive, ignoring leading/trailing whitespace).
fn parse_select_star(stmt: &str) -> ForensicResult<String> {
    let s = stmt.trim();
    let upper = s.to_uppercase();
    if upper.starts_with("SELECT * FROM ") || upper.starts_with("SELECT * FROM\t") {
        let rest = s[14..].trim();
        // Strip optional trailing semicolon
        let name = rest.trim_end_matches(';').trim();
        if name.is_empty() {
            return Err(ForensicError::bad_format_str(
                "Empty table name in SELECT statement",
            ));
        }
        Ok(name.to_owned())
    } else {
        Err(ForensicError::bad_format_str(
            "Only 'SELECT * FROM <table>' is supported for ESE databases",
        ))
    }
}

/// Map an ESE `ColumnType` to a forensic-rs `SqlColumnType`.
fn ese_to_sql_column_type(ct: crate::ese::column::ColumnType) -> SqlColumnType {
    use crate::ese::column::ColumnType as Ct;
    match ct {
        Ct::Nil => SqlColumnType::Null,
        Ct::Bit | Ct::UnsignedByte | Ct::Short | Ct::Long | Ct::Currency
        | Ct::UnsignedLong | Ct::LongLong | Ct::UnsignedShort => SqlColumnType::Integer,
        Ct::IEEESingle | Ct::IEEEDouble => SqlColumnType::Float,
        Ct::Text | Ct::LongText => SqlColumnType::String,
        Ct::Binary | Ct::LongBinary | Ct::GUID | Ct::DateTime => SqlColumnType::Binary,
    }
}

/// Convert an `OwnedColumnValue` to a forensic-rs `SqlColumnValue`.
fn owned_to_sql_value(v: &OwnedColumnValue) -> SqlColumnValue {
    use crate::ese::column::bytes_to_string;
    match v {
        OwnedColumnValue::Nil => SqlColumnValue::Null,
        OwnedColumnValue::Bit(b) => SqlColumnValue::Integer(*b as i64),
        OwnedColumnValue::UnsignedByte(b) => SqlColumnValue::Integer(*b as i64),
        OwnedColumnValue::Short(n) => SqlColumnValue::Integer(*n as i64),
        OwnedColumnValue::Long(n) => SqlColumnValue::Integer(*n as i64),
        OwnedColumnValue::Currency(n) => SqlColumnValue::Integer(*n),
        OwnedColumnValue::UnsignedLong(n) => SqlColumnValue::Integer(*n as i64),
        OwnedColumnValue::LongLong(n) => SqlColumnValue::Integer(*n),
        OwnedColumnValue::UnsignedShort(n) => SqlColumnValue::Integer(*n as i64),
        OwnedColumnValue::IEEESingle(f) => SqlColumnValue::Float(*f as f64),
        OwnedColumnValue::IEEEDouble(f) => SqlColumnValue::Float(*f),
        OwnedColumnValue::Text(b) | OwnedColumnValue::LongText(b) => {
            SqlColumnValue::String(bytes_to_string(b))
        }
        OwnedColumnValue::Binary(b) | OwnedColumnValue::LongBinary(b) => {
            SqlColumnValue::Binary(b.clone())
        }
        OwnedColumnValue::DateTime(ft) => {
            SqlColumnValue::Binary(ft.filetime().to_le_bytes().to_vec())
        }
        OwnedColumnValue::GUID(g) => SqlColumnValue::Binary(g.to_vec()),
    }
}

// ─── Tests ───────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tst {
    use super::*;

    #[test]
    fn parse_select_star_valid() {
        assert_eq!("CLIENTS", parse_select_star("SELECT * FROM CLIENTS").unwrap());
        assert_eq!("CLIENTS", parse_select_star("select * from CLIENTS").unwrap());
        assert_eq!("CLIENTS", parse_select_star("  SELECT * FROM CLIENTS  ").unwrap());
        assert_eq!("CLIENTS", parse_select_star("SELECT * FROM CLIENTS;").unwrap());
    }

    #[test]
    fn parse_select_star_invalid() {
        assert!(parse_select_star("SELECT col FROM CLIENTS").is_err());
        assert!(parse_select_star("INSERT INTO CLIENTS").is_err());
        assert!(parse_select_star("SELECT * FROM ").is_err());
    }

    #[test]
    fn sqldb_list_tables() {
        let data = crate::ese::tst::load_mdb_to_memory();
        let db = EseDb::from_bytes(data).unwrap();
        let tables = SqlDb::list_tables(&db).unwrap();
        assert!(!tables.is_empty());
    }

    #[test]
    fn sqldb_prepare_and_iterate() {
        let data = crate::ese::tst::load_mdb_to_memory();
        let db = EseDb::from_bytes(data).unwrap();
        let mut stmt = SqlDb::prepare(&db, "SELECT * FROM SYSTEM_IDENTITY").unwrap();
        assert!(stmt.column_count() > 0);
        let mut count = 0;
        while stmt.next().unwrap() {
            for i in 0..stmt.column_count() {
                let _ = stmt.read(i).unwrap();
            }
            count += 1;
        }
        assert!(count > 0);
    }
}
