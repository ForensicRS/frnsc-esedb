# ForensicRS EseDB — Copilot Instructions

A fully native Rust library for forensic parsing of Microsoft ESE (Extensible Storage Engine) databases (`.mdb` files). Targets cross-platform forensic analysis of Windows artifacts: SRUM, UAL, Windows Search.

Single dependency: `forensic-rs = "0.13"` (provides `ForensicError`, `ForensicResult`, `Filetime`, and telemetry macros).

## Architecture

```
src/
├── lib.rs                        # crate root — re-exports key types (EseDb, Row, Table, etc.)
└── ese/
    ├── mod.rs                    # ESE top-level module
    ├── catalog.rs                # MSysObjects catalog parser (TableDef, Catalog)
    ├── column.rs                 # Column types, value decoding, Display, OwnedColumnValue + convenience methods
    ├── db.rs                     # High-level public API: EseDb, Table, RowIter, Row (case-insensitive, typed accessors)
    ├── header.rs                 # Database file header (HeaderRpr → Header)
    ├── lv.rs                     # LongValueStore (LV B-tree traversal and reassembly)
    ├── reader.rs                 # PageReader trait + FileReader / SliceReader impls
    ├── sql_bridge.rs             # SqlDb / SqlStatement impl for EseDb (SELECT * FROM <table>)
    ├── tag.rs                    # Page slot-array tag parsing (Tag, TagReader)
    ├── time.rs                   # ESE LogTime → Windows Filetime
    ├── tst.rs                    # Test helpers (cfg(test) only)
    └── page/
        ├── mod.rs                # Page struct, PageHeader, TreePage dispatch
        ├── branch.rs             # B-tree interior nodes (BranchPage)
        ├── leaf.rs               # B-tree leaf nodes (LeafPage)
        ├── root.rs               # B-tree root nodes (RootPage)
        ├── key.rs                # Page key (prefix/suffix) parsing
        └── entries/
            ├── mod.rs            # PageEntry enum dispatcher
            ├── index.rs          # IndexEntry
            ├── long_value.rs     # LongValueEntry
            ├── space_tree.rs     # SpaceTreeEntry
            └── table_value.rs    # TableValueEntry, RecordData (with raw_overflow)
```

- **Parsing flow:** `Header::from_buff` → `Page::new` (per page offset = `(N+1) * page_size`) → `Page::process_page` → `TreePage::{Root, Branch, Leaf}` → `Catalog::from_db` (MSysObjects page 4) → `EseDb` high-level API.

## Conventions

- **Zero-copy repr overlay**: Raw bytes are cast using `align_to::<ReprType>()` (unsafe) from `#[repr(packed)]` structs, then converted to safe Rust types via `From`/`TryFrom`. Never bypass this pattern.
- **Lifetime-heavy slices**: Parsed page types (`BranchPage<'a>`, `LeafPage<'a>`, etc.) borrow directly from the owning `Page`'s `data: Vec<u8>`. Preserve this zero-copy design.
- **Error handling**: Use `ForensicResult<T>` everywhere. Use `ForensicError::bad_format_str()` for parse failures, `ForensicError::missing_str()` for bounds violations. Soft-skip individual entry failures with `forensic_rs::notify_low!` rather than aborting the page.
- **Preserved naming quirks**: `preffix` (not `prefix`), `service_pack_nmber`, `DAABASE_DIRTY_SHUTDOWN` exist in the public API. Do not rename without a coordinated refactor.
- **Variable column overflow**: In ESE revision 20 databases, variable column data (e.g., `Name` in MSysObjects) is stored in the overflow/tagged area as `[len: u16 LE][bytes]` blobs in column-ID order. `RecordData.raw_overflow` holds this region; `overflow_var_col()` in `column.rs` decodes it.
- **Crate-root re-exports**: Key types are re-exported at crate root — `use frnsc_esedb::{EseDb, Row, Table, OwnedColumnValue, ColumnType, ColumnDef, ColumnValue}`. Internal fields (`EseDb.header`, `EseDb.catalog`) are `pub(crate)`; use `header()` and `catalog()` getters.
- **Case-insensitive Row**: `Row.get(name)` is case-insensitive, matching `EseDb.table(name)`. Typed accessors: `get_str()`, `get_i64()`, `get_f64()`, `get_bytes()`, `get_bool()`, `get_datetime()`, `get_guid()`.
- **SqlDb bridge**: `EseDb` implements `forensic_rs::traits::sql::SqlDb`. Only `SELECT * FROM <table>` is supported.

## Build and Test

```sh
cargo build
cargo test
```

Test fixtures live in `artifacts/` and are accessed via relative paths from `src/ese/tst.rs`. Key fixtures:
- `artifacts/SystemIdentity.mdb` — primary header/page tests
- `artifacts/UAL/UAL/Current.mdb` — full page iteration tests (`should_load_full_page`)

Unit tests are inline (`mod tst` inside each module).  Integration tests live in `tests/systemidentity.rs` and `tests/ual.rs`.  Examples in `examples/list_tables.rs` and `examples/read_ual.rs`.

## Key Reference

ESE format: https://techcommunity.microsoft.com/t5/ask-the-directory-services-team/ese-deep-dive-part-1-the-anatomy-of-an-ese-database/ba-p/400496

## Keeping These Instructions Updated

Update this file whenever any of the following change:

- **New module added** — add an entry to the architecture tree with a one-line description of its purpose.
- **New entry type** — add a row under the `entries/` subtree; note if it is TODO/WIP.
- **Convention changes** — if a naming quirk is fixed, a new error-handling pattern is adopted, or the zero-copy repr strategy is revised, update the relevant bullet in **Conventions**.
- **New test fixture** — add it to the fixtures list under **Build and Test**.
- **Dependency added or version bumped** — update the dependency line in the header.
- **WIP promoted to complete** — remove the WIP/TODO note for that module once it is fully implemented.

Do **not** add implementation detail (algorithm internals, field offsets, bit masks) — link to the ESE reference instead. Keep every entry concise: one line per module, one bullet per convention.
