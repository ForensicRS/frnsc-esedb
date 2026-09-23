# ForensicRS EseDB

[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![Rust](https://img.shields.io/badge/rust-2024-orange.svg)](https://www.rust-lang.org)
[![Status](https://img.shields.io/badge/status-work%20in%20progress-yellow.svg)]()

A fully native Rust library for forensic parsing of Microsoft ESE (Extensible Storage Engine) databases (`.mdb`/`.edb`/`.dat` files). Built from scratch with **zero C dependencies**, it runs on Windows, Linux, and macOS — enabling forensic analysis workflows across platforms without relying on platform-specific bindings.

Target Windows artifacts: **SRUM** (System Resource Usage Monitor), **UAL** (User Access Logging), and **Windows Search**.

Implements [`forensic-rs`](https://github.com/ForensicRS/forensic-rs)'s `ForensicDb`/`ForensicTable`/`ForensicRows` traits and `FormatFactory` (see [Framework Integration](#framework-integration) below), so any tool built on the framework can read an ESE database without knowing this crate exists — the same analyzer runs unmodified against a live file, an in-memory buffer, or a mounted evidence item.

> **Work in Progress** — This library is under active development (v0.3.0). The core parsing engine is functional and well-tested, but the API may evolve before reaching a stable 1.0 release. It will be published to [crates.io](https://crates.io) once stable.

Beyond the database file itself, `frnsc_esedb::ese::log` parses the surrounding **file set** — transaction logs (`.log`/`.jrs`), the checkpoint (`.chk`), and the flush map (`.jfm`) — and aggregates them into a log-set integrity report (`EseLogSet::report()`): which generations are present, whether the database needs log replay, and any anomalies found, each paired with the benign explanation an examiner should rule out first. `frnsc_esedb::ese::recovery` recovers rows absent from ordinary iteration — rows still addressable via a page's tag array but marked deleted, and candidates carved from a live page's unallocated slack — each citing the exact bytes it came from, and can group a table's live and recovered rows into a per-key history (`EseDb::row_history`) or export recovered rows to an opt-in JSONL sidecar. See `docs/internals.md` §11 and `examples/log_set.rs`/`examples/recover_rows.rs`/`examples/row_history.rs`.

## Installation

The library is not yet published to crates.io. Add it as a git dependency in your `Cargo.toml`:

```toml
[dependencies]
frnsc-esedb = { git = "https://github.com/ForensicRS/frnsc-esedb" }
```

The only runtime dependency is [`forensic-rs`](https://crates.io/crates/forensic-rs) (v0.14), which provides shared forensic types (`ForensicError`, `ForensicTimestamp`, the `ForensicDb`/`FormatFactory` traits, etc.).

## Quick Start

### List tables and columns

```rust
use frnsc_esedb::EseDb;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let db = EseDb::open("path/to/database.mdb")?;

    // Inspect the database header
    println!("Format: {:?}", db.header().fingerprint());
    println!("State:  {:?}", db.header().state());
    println!("Page size: {} bytes", db.header().page_size);

    // Enumerate all tables and their columns
    for name in db.table_names() {
        let table = db.table(name)?;
        println!("── {} ({} columns) ──", name, table.columns().len());
        for col in table.columns() {
            println!("  {:>4}  {:20} {:?}", col.id, col.name, col.col_type);
        }
    }
    Ok(())
}
```

### Read rows with typed accessors

```rust
use frnsc_esedb::EseDb;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let db = EseDb::open("path/to/ual.mdb")?;
    let table = db.table("CLIENTS")?;

    for (i, row) in table.iter_rows().enumerate() {
        let user     = row.get_str("AuthenticatedUserName").unwrap_or_default();
        let addr     = row.get_str("Address").unwrap_or_default();
        let accesses = row.get_i64("TotalAccesses").unwrap_or(0);
        let inserted = row.get_datetime("InsertDate")
            .map(|ts| format!("{:04}-{:02}-{:02}", ts.year(), ts.month(), ts.day()))
            .unwrap_or_else(|| "-".into());

        println!("[{i}] user={user} addr={addr} accesses={accesses} inserted={inserted}");
    }
    Ok(())
}
```

### SRUM

```rust
use frnsc_esedb::srum::SrumDatabase;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let db = SrumDatabase::open(r"C:\Windows\System32\sru\SRUDB.dat")?;

    for record in db.app_resource_usage()? {
        if let Some(app) = db.index.resolve_app(record.app_id) {
            println!("{}: cpu_fg={:?}", app.name(), record.foreground_cycle_time);
        }
    }

    // Cross-table timeline, sorted by timestamp:
    for event in db.timeline().with_all().sorted()? {
        println!("{:?} app_id={:?}", event.timestamp(), event.app_id());
    }
    Ok(())
}
```

> See the [`examples/`](examples/) directory for runnable versions of these snippets.

## Framework integration

`EseDb` implements three `forensic-rs` traits, so it plugs directly into a triage pipeline or any tool written against the framework rather than against this crate:

- **`ForensicDb` / `ForensicTable` / `ForensicRows`** (`forensic_rs::traits::db`) — the unified database-access trait. `db.list_tables()`, `db.table(name)?.iter_rows()?`, and `row.read_ref(i)` work exactly as they would for any other `ForensicDb` implementor (e.g. a SQLite backend).
- **`RecoverRows`** (`forensic_rs::traits::db`) — `db.as_recovery()` always returns `Some(self)`; `recovered_rows(table)`/`slack_rows(table)` return an ordinary `ForensicRows` cursor whose rows report `allocated() == false` and a real `recovery()`/`locus()`, so recovered rows are reachable without knowing `EseDb`'s concrete type.
- **`FormatFactory`** ([`EseFormatFactory`], `forensic_rs::traits::format`) — content-sniffs a file (checking the ESE magic signature and a sanity-checked header) and mounts it as `Mounted::Database`, without the caller needing to know in advance that a given file is an ESE database. Small files are slurped into memory for zero-copy page access; files larger than the resolver's in-memory budget stream pages on demand instead. [`EseLogSetFactory`] is a second, independent `FormatFactory` over the same file, yielding `Mounted::FileSet` — the database's transaction logs, checkpoint, flush map, and reserved logs grouped by filename shape.

## API Overview

All key types are re-exported at the crate root:

```rust
use frnsc_esedb::{EseDb, Table, Row, RowIter, ColumnDef, ColumnType, ColumnValue, OwnedColumnValue, EseFormatFactory, EseLogSetFactory};
```

### `EseDb` — Database Handle

| Method | Description |
|--------|-------------|
| `open(path)` | Open an ESE database from disk |
| `from_bytes(data)` | Parse from an in-memory byte buffer |
| `from_virtual_file(file)` | Parse from a `forensic_rs::traits::vfs::VirtualFile` |
| `table(name)` | Get a table by name (case-insensitive); `ForensicResult<Table<'_>>` |
| `rows(name)` | Row cursor for a table, without an intermediate `Table` handle |
| `table_names()` | List all user table names |
| `header()` | Access the parsed file header (format, state, page size) |
| `catalog()` | Access the parsed MSysObjects catalog |

### `Table` — Table Handle

| Method | Description |
|--------|-------------|
| `name()` | Table name |
| `columns()` | Column definitions (`&[ColumnDef]`) |
| `iter_rows()` | Iterate all rows as `RowIter` |

### `Row` — Decoded Table Row

Column lookups are **case-insensitive**. The `get()` method returns `Option<&OwnedColumnValue>`, and typed accessors provide convenient direct access:

| Accessor | Returns | Matches column types |
|----------|---------|---------------------|
| `get(name)` | `Option<&OwnedColumnValue>` | Any |
| `get_str(name)` | `Option<String>` | Text, LongText |
| `get_i64(name)` | `Option<i64>` | All integer types |
| `get_f64(name)` | `Option<f64>` | IEEESingle, IEEEDouble |
| `get_bytes(name)` | `Option<&[u8]>` | Binary, LongBinary |
| `get_bool(name)` | `Option<bool>` | Bit |
| `get_datetime(name)` | `Option<ForensicTimestamp>` | DateTime |
| `get_guid(name)` | `Option<[u8; 16]>` | GUID |

Additional methods: `len()`, `is_empty()`, `iter()`, `get_by_index(i)`, `column_name(i)`.

### `ColumnDef` — Column Metadata

Each column exposes: `id` (u16), `col_type` (`ColumnType`), `name` (String), `flags` (u32), `codepage` (u32).
Helpers: `is_fixed()`, `is_variable()`, `is_tagged()`.

### `OwnedColumnValue` / `ColumnValue`

Enum with 17 variants matching all ESE column types. `OwnedColumnValue` owns its data (for long-lived `Row` structs); `ColumnValue` borrows from page buffers. Both implement `Display` for human-readable output.

Conversion methods on `OwnedColumnValue`: `as_string()`, `as_i64()`, `as_f64()`, `as_bytes()`, `as_bool()`, `as_datetime()`, `as_guid()`, `is_null()`.

**A note on `DateTime` columns:** ESE's `JET_coltypDateTime` stores an 8-byte IEEE-754 double — an *OLE Automation date* (days since 1899-12-30) per the JET/ESE specification, not a raw Win32 `FILETIME` integer. This crate decodes it correctly via `ForensicTimestamp::try_from_ole_date`; an out-of-range value degrades to an absent column rather than fabricating a substitute timestamp.

## Supported Column Types

| Type | Rust mapping |
|------|-------------|
| `Nil` | Unit (null) |
| `Bit` | `bool` |
| `UnsignedByte` | `u8` |
| `Short` | `i16` |
| `UnsignedShort` | `u16` |
| `Long` | `i32` |
| `UnsignedLong` | `u32` |
| `LongLong` | `i64` |
| `Currency` | `i64` |
| `IEEESingle` | `f32` |
| `IEEEDouble` | `f64` |
| `DateTime` | `ForensicTimestamp` |
| `Binary` | `&[u8]` / `Vec<u8>` |
| `LongBinary` | `Vec<u8>` |
| `Text` | `&[u8]` / `Vec<u8>` |
| `LongText` | `Vec<u8>` |
| `GUID` | `[u8; 16]` |

## Supported Databases

The library has been tested with the following ESE database types:

- **UAL (User Access Logging)** — `SystemIdentity.mdb`, `Current.mdb`, yearly GUID archives
- **SystemIdentity** — `SYSTEM_IDENTITY`, `CHAINED_DATABASES`, `ROLE_IDS` tables
- **SRUM (System Resource Usage Monitor)** — `SRUDB.dat`: app resource/network/energy usage, push notifications, and a unified cross-table timeline (see [`src/srum/`](src/srum/))

Additional target artifacts (in progress):

- **Windows Search** index databases

## Build & Test

```sh
cargo build
cargo test
cargo clippy --all-targets
```

Test fixtures live in the gitignored `artifacts/` directory and are not committed. Tests that need a fixture (`tests/systemidentity.rs`, `tests/ual.rs`) print `SKIP: fixture '...' unavailable` and pass trivially when it's absent, rather than failing a fresh checkout — place the corresponding `.mdb`/`.dat` file under `artifacts/` to actually exercise them. Byte-level parser tests (bounds checks, cycle protection, header validation) are unit tests with inline byte literals and always run.

Run the examples:

```sh
cargo run --example list_tables -- path/to/database.mdb
cargo run --example read_ual -- path/to/ual.mdb
cargo run --example read_srum -- path/to/SRUDB.dat
```

## Architecture

```
src/
├── lib.rs                        # Crate root — re-exports EseDb, Row, Table, EseFormatFactory, etc.
├── ese/
│   ├── mod.rs                    # ESE top-level module
│   ├── catalog.rs                # MSysObjects catalog parser
│   ├── column.rs                 # Column types, value decoding, typed accessors
│   ├── db.rs                     # High-level API: EseDb, Table, RowIter, Row
│   ├── forensic_db.rs            # ForensicDb / ForensicTable / ForensicRows bridge
│   ├── format.rs                 # EseFormatFactory (probe/mount as Mounted::Database)
│   ├── header.rs                 # Database file header parsing
│   ├── lv.rs                     # LongValue B-tree traversal and reassembly
│   ├── reader.rs                 # PageReader trait + FileReader / SliceReader / VirtualFileReader
│   ├── tag.rs                    # Page slot-array tag parsing
│   ├── tree.rs                   # Shared, cycle-safe B-tree traversal (catalog/lv/table data)
│   └── page/
│       ├── mod.rs                # Page struct, PageHeader, TreePage dispatch
│       ├── branch.rs             # B-tree interior nodes
│       ├── leaf.rs               # B-tree leaf nodes
│       ├── root.rs               # B-tree root nodes
│       └── entries/
│           ├── mod.rs            # PageEntry enum dispatcher
│           ├── index.rs          # IndexEntry
│           ├── long_value.rs     # LongValueEntry
│           ├── space_tree.rs     # SpaceTreeEntry
│           └── table_value.rs    # TableValueEntry, RecordData
└── srum/
    ├── mod.rs                    # SrumDatabase entry point; per-table accessors
    ├── index.rs                  # SrumIdIndex — SruDbIdMapTable ID→app/SID map
    ├── timeline.rs               # TimelineBuilder / TimelineEvent — cross-table sorted view
    ├── volume.rs                 # VolumeMap: \Device\HarddiskVolumeN → drive letter
    ├── enrichment.rs             # SrumEnrichment / WinEventEnrichment trait seams
    └── tables/                   # One record + iterator pair per SRUM table
```

## References

- [ESE Deep Dive Part 1: The Anatomy of an ESE Database](https://techcommunity.microsoft.com/t5/ask-the-directory-services-team/ese-deep-dive-part-1-the-anatomy-of-an-ese-database/ba-p/400496) — Microsoft TechCommunity
- [ForensicRS](https://github.com/ForensicRS) — Parent project and shared forensic types

## License

This project is licensed under the [MIT License](LICENSE).
