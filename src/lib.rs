//! Native Rust parser for Microsoft ESE (Extensible Storage Engine) databases
//! (`.mdb`/`.edb`/`.dat`/`.jfm` files), built from scratch with zero C
//! dependencies. Targets the Windows SRUM, UAL, and Windows Search artifacts.
//!
//! Implements [`forensic_rs::traits::db::ForensicDb`]/`ForensicTable`/
//! `ForensicRows` (see [`ese::forensic_db`]) and
//! [`forensic_rs::traits::format::FormatFactory`] (see [`ese::format`]), so
//! any tool built on `forensic-rs` can consume an ESE database without
//! knowing this crate exists.

pub mod ese;
pub mod srum;

// Re-export key types at crate root for ergonomic imports.
pub use ese::column::{ColumnDef, ColumnType, ColumnValue, OwnedColumnValue};
pub use ese::db::{EseDb, Row, RowIter, Table};
pub use ese::format::EseFormatFactory;
