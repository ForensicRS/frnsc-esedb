//! Native Rust parser for Microsoft ESE (Extensible Storage Engine) databases
//! (`.mdb`/`.edb`/`.dat` files), built from scratch with zero C dependencies.
//! Targets the Windows SRUM, UAL, and Windows Search artifacts.
//!
//! `.jfm` is **not** a mountable ESE database in its own right (confirmed:
//! its magic word at offset 4 is `3`, not the `0x89abcdef` ESE header
//! signature) — it is the flush map belonging to a database, parsed
//! separately by [`ese::log::flushmap`].
//!
//! Implements [`forensic_rs::traits::db::ForensicDb`]/`ForensicTable`/
//! `ForensicRows` (see [`ese::forensic_db`]) and
//! [`forensic_rs::traits::format::FormatFactory`] (see [`ese::format`]), so
//! any tool built on `forensic-rs` can consume an ESE database without
//! knowing this crate exists.
//!
//! Beyond the database file itself, [`ese::log`] parses the surrounding file
//! set -- transaction logs, checkpoint, flush map, and reserved logs -- and
//! [`ese::log::set::EseLogSet`] aggregates them into a file-set integrity
//! report.

pub mod ese;
pub mod srum;

// Re-export key types at crate root for ergonomic imports.
pub use ese::column::{ColumnDef, ColumnType, ColumnValue, OwnedColumnValue};
pub use ese::db::{EseDb, Row, RowIter, Table};
pub use ese::format::{EseFormatFactory, EseLogSetFactory};
pub use ese::lgpos::Lgpos;
pub use ese::signature::{ComputerName, LogTimestamp, Signature};
pub use ese::log::{LogFile, EseLogSet};
