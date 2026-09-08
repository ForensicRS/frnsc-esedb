# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.2.0] - Unreleased

### Added

- `forensic_rs::traits::db::{ForensicDb, ForensicTable, ForensicRows}` implementation for `EseDb` (`src/ese/forensic_db.rs`), replacing the pre-0.14 `SqlDb`/`SqlStatement` bridge that forensic-rs 0.14 removed.
- `EseFormatFactory` (`forensic_rs::traits::format::FormatFactory`) — content-sniffs and mounts ESE files as `Mounted::Database` without the caller needing to know the format in advance. Streams pages on demand for files larger than the resolver's in-memory budget; slurps smaller files for zero-copy access.
- `EseDb::from_virtual_file` and a `VirtualFileReader` `PageReader` implementation over `forensic_rs::traits::vfs::VirtualFile`.
- `SrumDatabase::from_db` to build a SRUM view from an already-open `EseDb` (e.g. one mounted through `EseFormatFactory`).
- `ColumnType::forensic_type()` mapping to `forensic_rs::traits::db::ForensicColumnType`.
- A shared, cycle-safe B-tree traversal (`src/ese/tree.rs`) used by the catalog, long-value store, and table row iterator, replacing three independent, recursion-depth-bounded (but not visited-set-bounded) traversals.
- Byte-literal unit tests for every untrusted-input parser reachable from `EseDb::open()` (leaf/branch entry bounds, header signature/page-size validation, page-header checksum extension, B-tree cycle termination).
- `LICENSE`, this `CHANGELOG.md`, `AGENTS.md`, and a 3-OS CI workflow (`.github/workflows/rust.yml`).

### Changed

- **Breaking**: bumped to `forensic-rs = "0.14"`, Rust edition 2024, `rust-version = "1.87"`.
- **Breaking**: `EseDb::table()`, `SrumDatabase::open()`, and all 8 `SrumDatabase` per-table accessors now return `ForensicResult<_>` instead of `Option<_>`, so a caller can distinguish "file unreadable" from "table not found" from "database corrupt" instead of a bare `None`.
- **Breaking**: `Filetime` replaced by `forensic_rs::utils::time::ForensicTimestamp` throughout the public API (`Header`'s date fields, `ColumnValue`/`OwnedColumnValue::DateTime`, `Row::get_datetime`, every SRUM record's `timestamp` field, `TimelineEvent::timestamp()`).
- **Breaking**: `Header::page_to_file_offset` returns `ForensicResult<u64>` (checked arithmetic) instead of an unchecked `u64`.
- **Fixed (critical, forensic-soundness)**: ESE `DateTime` columns (`JET_coltypDateTime`) were decoded as a raw Win32 FILETIME 64-bit integer. Per the JET/ESE specification this column type is actually an 8-byte IEEE-754 double — an OLE Automation date (days since 1899-12-30). This silently produced wildly wrong timestamps (e.g. a real SRUM record's `TimeStamp` decoded to the year 16419 instead of 2020) for every SRUM/UAL/any-ESE-table row with a `DateTime` column, since the crate's first commit. Fixed via `ForensicTimestamp::try_from_ole_date`; an out-of-range value now degrades to an absent column instead of fabricating a substitute.
- **Fixed (critical, forensic-soundness)**: the ESE header's `LogTime` → timestamp conversion (`shutdown_datetime`/`attach_datetime`/etc.) treated `day` and `month` as 0-based; both are 1-based (verified against `artifacts/sru/SRUDB.dat`'s real header). This shifted every header timestamp by up to a month and a day, and rejected December (`month >= 12`) outright.
- **Fixed**: `PageHeader::from_buff` tested `version == 0x602`; the real ESE version is `0x620` (confirmed in the fixture), so the entire Win7 checksum/extended-header refinement was dead code for every real database. 16 KiB/32 KiB pages now correctly read the 40-byte Win7 extension and set `header_size = 80`; a stray `buffer[4..9]` slice into a 4-byte array (always failing, so both fields read as 0) is now `buffer[4..8]`.
- **Fixed**: `LeafPageEntry::new` and `BranchPageEntry::new` no longer panic (unchecked slice/overflow) on a maliciously or accidentally oversized key-size field read from untrusted page bytes.
- **Fixed**: `Header::from_buff` now validates the ESE magic signature and page size; previously any sufficiently long file parsed as a "valid" ESE header.
- **Fixed**: `RowIter`'s B-tree walk (and the catalog/long-value traversals) is now cycle-safe via a visited-page set, not just a recursion-depth counter — a self-referencing or cyclic branch page terminates instead of looping or doing exponential redundant work.
- **Fixed**: `root.rs`'s `number_of_pages` field read `data[0..4]` unconditionally, ignoring the leading alignment byte present on revision ≥ 0x14 (25-byte) root headers — every field after it was already offset-adjusted except this one.
- **Fixed**: a long-value B-tree with a segment gap or overlap no longer silently concatenates across the discontinuity (which would fabricate evidence); it now stops at the gap and logs a warning.
- **Fixed**: `sql_bridge.rs`'s `SELECT * FROM <table>` parser validated its prefix against an uppercased copy of the input but sliced the original string at a fixed byte offset — not length-preserving for non-ASCII input, and could panic on a non-char-boundary. Removed entirely (see below).
- Long-value B-trees are now cached per root page (`EseDb::lv_cache`) instead of being re-walked in full on every `iter_rows()` call.
- `EseDb` is now `Send + Sync` (required by `ForensicDb`): `FileReader` uses positioned reads (`pread`/`ReadFile`+offset) instead of a `RefCell<BufReader<File>>`, so no interior mutability is needed at all on that path.

### Removed

- `src/ese/sql_bridge.rs` (`SqlDb`/`SqlStatement` impl) — `forensic_rs::traits::sql` was removed upstream in 0.14. `ForensicDb::table(name)` now expresses the same access pattern natively, with no SQL-string parsing.
- `src/ese/page/key.rs` (`PageKeyRef`) and `Page::get_page_keys_if_root` — dead code with no live constructor path.
- The three unreferenced `PageHeader{Exchange2003,WinVista,Win7Ext}Repr` structs.
- `notify_low!`/`NotificationType` (removed upstream in 0.14) — per-entry parse-skip diagnostics now go through `forensic_rs::debug!`.

### Deprecated

- None new; the crate no longer uses forensic-rs's deprecated `ForensicError::bad_format_str`/`bad_format_string`/`missing_str` constructors, migrating to `ensure_format!`/`ensure_min_length!`/`invalid_format`/`missing_data`.

## [0.1.0]

Initial release: native ESE/JET Blue page and B-tree parser, SRUM reader, `forensic-rs` 0.13 `SqlDb` bridge.
