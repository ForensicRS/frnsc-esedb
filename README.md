# ForensicRS EseDB

[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![Rust](https://img.shields.io/badge/rust-2021-orange.svg)](https://www.rust-lang.org)
[![Status](https://img.shields.io/badge/status-work%20in%20progress-yellow.svg)]()

A fully native Rust library for forensic parsing of Microsoft ESE (Extensible Storage Engine) databases (`.mdb` files). Built from scratch with **zero C dependencies**, it runs on Windows, Linux, and macOS — enabling forensic analysis workflows across platforms without relying on platform-specific bindings.

Target Windows artifacts: **SRUM**, **UAL** (User Access Logging), and **Windows Search**.

> **Work in Progress** — This library is under active development (v0.1.0). The core parsing engine is functional and well-tested, but the API may evolve before reaching a stable 1.0 release. It will be published to [crates.io](https://crates.io) once stable.

## Installation

The library is not yet published to crates.io. Add it as a git dependency in your `Cargo.toml`:

```toml
[dependencies]
frnsc-esedb = { git = "https://github.com/ForensicRS/frnsc-esedb" }
```

The only runtime dependency is [`forensic-rs`](https://crates.io/crates/forensic-rs) (v0.13), which provides shared forensic types (`ForensicError`, `Filetime`, etc.).

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
        let table = db.table(name).unwrap();
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
    let table = db.table("CLIENTS").expect("CLIENTS table not found");

    for (i, row) in table.iter_rows().enumerate() {
        let user     = row.get_str("AuthenticatedUserName").unwrap_or_default();
        let addr     = row.get_str("Address").unwrap_or_default();
        let accesses = row.get_i64("TotalAccesses").unwrap_or(0);
        let inserted = row.get_datetime("InsertDate")
            .map(|ft| format!("{ft:?}"))
            .unwrap_or_else(|| "-".into());

        println!("[{i}] user={user} addr={addr} accesses={accesses} inserted={inserted}");
    }
    Ok(())
}
```

> See the [`examples/`](examples/) directory for runnable versions of these snippets.

## API Overview

All key types are re-exported at the crate root:

```rust
use frnsc_esedb::{EseDb, Table, Row, RowIter, ColumnDef, ColumnType, ColumnValue, OwnedColumnValue};
```

### `EseDb` — Database Handle

| Method | Description |
|--------|-------------|
| `open(path)` | Open an ESE database from disk |
| `from_bytes(data)` | Parse from an in-memory byte buffer |
| `table(name)` | Get a table by name (case-insensitive) |
| `table_names()` | List all user table names |
| `header()` | Access the parsed file header (format, state, page size) |
| `catalog()` | Access the parsed MSysObjects catalog |

### `Table` — Table Handle

| Method | Description |
|--------|-------------|
| `name()` | Table name |
| `columns()` | Column definitions (`Vec<ColumnDef>`) |
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
| `get_datetime(name)` | `Option<Filetime>` | DateTime |
| `get_guid(name)` | `Option<[u8; 16]>` | GUID |

Additional methods: `len()`, `is_empty()`, `iter()`, `get_by_index(i)`, `column_name(i)`.

### `ColumnDef` — Column Metadata

Each column exposes: `id` (u16), `col_type` (`ColumnType`), `name` (String), `flags` (u32), `codepage` (u32).  
Helpers: `is_fixed()`, `is_variable()`, `is_tagged()`.

### `OwnedColumnValue` / `ColumnValue`

Enum with 17 variants matching all ESE column types. `OwnedColumnValue` owns its data (for long-lived `Row` structs); `ColumnValue` borrows from page buffers. Both implement `Display` for human-readable output.

Conversion methods on `OwnedColumnValue`: `as_string()`, `as_i64()`, `as_f64()`, `as_bytes()`, `as_bool()`, `as_datetime()`, `as_guid()`, `is_null()`.

### SqlDb Bridge

`EseDb` implements the `forensic_rs::traits::sql::SqlDb` trait, allowing integration with the broader ForensicRS ecosystem:

```rust
use forensic_rs::traits::sql::SqlDb;

let db = EseDb::open("database.mdb")?;
let tables = db.list_tables()?;
let mut stmt = db.prepare("SELECT * FROM CLIENTS")?;
```

> **Note:** Only `SELECT * FROM <table>` is supported — ESE is not a SQL engine.

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
| `DateTime` | `Filetime` |
| `Binary` | `&[u8]` / `Vec<u8>` |
| `LongBinary` | `Vec<u8>` |
| `Text` | `&[u8]` / `Vec<u8>` |
| `LongText` | `Vec<u8>` |
| `GUID` | `[u8; 16]` |

## Supported Databases

The library has been tested with the following ESE database types:

- **UAL (User Access Logging)** — `SystemIdentity.mdb`, `Current.mdb`, yearly GUID archives
- **SystemIdentity** — `SYSTEM_IDENTITY`, `CHAINED_DATABASES`, `ROLE_IDS` tables

Additional target artifacts (in progress):

- **SRUM** (System Resource Usage Monitor)
- **Windows Search** index databases

## Build & Test

```sh
cargo build
cargo test
```

Test fixtures live in the `artifacts/` directory. Integration tests cover header parsing, catalog loading, schema extraction, row iteration, and typed value decoding across multiple database files.

Run the examples:

```sh
cargo run --example list_tables -- path/to/database.mdb
cargo run --example read_ual -- path/to/ual.mdb
```

## Architecture

```
src/
├── lib.rs                        # Crate root — re-exports EseDb, Row, Table, etc.
└── ese/
    ├── mod.rs                    # ESE top-level module
    ├── catalog.rs                # MSysObjects catalog parser
    ├── column.rs                 # Column types, value decoding, typed accessors
    ├── db.rs                     # High-level API: EseDb, Table, RowIter, Row
    ├── header.rs                 # Database file header parsing
    ├── lv.rs                     # LongValue B-tree traversal and reassembly
    ├── reader.rs                 # PageReader trait + FileReader / SliceReader
    ├── sql_bridge.rs             # SqlDb / SqlStatement bridge for forensic-rs
    ├── tag.rs                    # Page slot-array tag parsing
    └── page/
        ├── mod.rs                # Page struct, PageHeader, TreePage dispatch
        ├── branch.rs             # B-tree interior nodes
        ├── leaf.rs               # B-tree leaf nodes
        ├── root.rs               # B-tree root nodes
        ├── key.rs                # Page key (prefix/suffix) parsing
        └── entries/
            ├── mod.rs            # PageEntry enum dispatcher
            ├── index.rs          # IndexEntry
            ├── long_value.rs     # LongValueEntry
            ├── space_tree.rs     # SpaceTreeEntry
            └── table_value.rs    # TableValueEntry, RecordData
```

## References

- [ESE Deep Dive Part 1: The Anatomy of an ESE Database](https://techcommunity.microsoft.com/t5/ask-the-directory-services-team/ese-deep-dive-part-1-the-anatomy-of-an-ese-database/ba-p/400496) — Microsoft TechCommunity
- [ForensicRS](https://github.com/ForensicRS) — Parent project and shared forensic types

## License

This project is licensed under the [MIT License](LICENSE).