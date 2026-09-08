# ForensicRS EseDB — Copilot Instructions

A fully native Rust library for forensic parsing of Microsoft ESE (Extensible Storage Engine) databases (`.mdb`/`.edb`/`.dat` files). Targets cross-platform forensic analysis of Windows artifacts: SRUM, UAL, Windows Search.

Single dependency: `forensic-rs = "0.14"` (provides `ForensicError`, `ForensicResult`, `ForensicTimestamp`, the `ForensicDb`/`FormatFactory` traits, and logging macros).

See also [`AGENTS.md`](../AGENTS.md) for the fuller agent guide, including the forensic-soundness review discipline and two timestamp bugs worth knowing about before touching date/time code.

## Architecture

```
src/
├── lib.rs                        # crate root — re-exports key types (EseDb, Row, Table, EseFormatFactory, etc.)
└── ese/
    ├── mod.rs                    # ESE top-level module
    ├── catalog.rs                # MSysObjects catalog parser (TableDef, Catalog)
    ├── column.rs                 # Column types, value decoding, Display, OwnedColumnValue + convenience methods
    ├── db.rs                     # High-level public API: EseDb, Table, RowIter, Row (case-insensitive, typed accessors)
    ├── forensic_db.rs            # ForensicDb / ForensicTable / ForensicRows impl for EseDb
    ├── format.rs                 # EseFormatFactory: probe/mount ESE files as Mounted::Database
    ├── header.rs                 # Database file header (HeaderRpr → Header); validates signature + page size
    ├── lv.rs                     # LongValueStore (LV B-tree traversal and reassembly)
    ├── reader.rs                 # PageReader trait + FileReader / SliceReader / VirtualFileReader impls
    ├── tag.rs                    # Page slot-array tag parsing (Tag, TagReader)
    ├── time.rs                   # ESE LogTime → ForensicTimestamp (header timestamps only; 1-based day/month)
    ├── tree.rs                   # Shared, cycle-safe B-tree traversal (TreeWalker, visit_leaves)
    ├── tst.rs                    # Test helpers (cfg(test) only) — fixture loaders return Option, never panic
    └── page/
        ├── mod.rs                # Page struct, PageHeader, TreePage dispatch
        ├── branch.rs             # B-tree interior nodes (BranchPage)
        ├── leaf.rs               # B-tree leaf nodes (LeafPage)
        ├── root.rs               # B-tree root nodes (RootPage)
        └── entries/
            ├── mod.rs            # PageEntry enum dispatcher
            ├── index.rs          # IndexEntry
            ├── long_value.rs     # LongValueEntry
            ├── space_tree.rs     # SpaceTreeEntry
            └── table_value.rs    # TableValueEntry, RecordData (with raw_overflow)
└── srum/                         # SRUM (System Resource Usage Monitor) reader — see AGENTS.md for its module map
```

- **Parsing flow:** `Header::from_buff` (validates ESE signature + page size) → `Page::new` (per page offset = `(N+1) * page_size`, via `Header::page_to_file_offset` → `ForensicResult<u64>`) → `Page::process_page` → `TreePage::{Root, Branch, Leaf}` → `Catalog::from_db` (MSysObjects page 4, via `tree::visit_leaves`) → `EseDb` high-level API.

## Conventions

- **Zero-copy repr overlay**: Raw bytes are cast using `align_to::<ReprType>()` (unsafe, with a `// SAFETY:` comment) from `#[repr(C, packed)]` structs, then converted to safe Rust types via `From`/`TryFrom`. Every call site is preceded by an explicit length check (`ensure_min_length!`) — `head.is_empty()` alone does not validate length, since these packed types have alignment 1. Never bypass this pattern.
- **Lifetime-heavy slices**: Parsed page types (`BranchPage<'a>`, `LeafPage<'a>`, etc.) borrow directly from the owning `Page`'s `data: Cow<'a, [u8]>`. Preserve this zero-copy design.
- **Error handling**: Use `ForensicResult<T>` everywhere. Prefer `ensure_format!`/`ensure_min_length!`/`ensure_buffer_size!`/`ensure_buffer_range!` and `ForensicError::invalid_format()`/`missing_data()` over the deprecated `bad_format_str()`/`missing_str()` constructors. Soft-skip individual entry failures with `forensic_rs::debug!` rather than aborting the page.
- **Preserved naming quirks**: `service_pack_nmber`, `DAABASE_DIRTY_SHUTDOWN` exist in the public API. Do not rename without a coordinated refactor.
- **Variable column overflow**: In ESE revision 20 databases, variable column data (e.g., `Name` in MSysObjects) is stored in the overflow/tagged area as `[len: u16 LE][bytes]` blobs in column-ID order. `RecordData.raw_overflow` holds this region; `overflow_var_col()` in `column.rs` decodes it.
- **Crate-root re-exports**: Key types are re-exported at crate root — `use frnsc_esedb::{EseDb, Row, Table, OwnedColumnValue, ColumnType, ColumnDef, ColumnValue, EseFormatFactory}`. Internal fields (`EseDb.header`, `EseDb.catalog`) are `pub(crate)`; use `header()` and `catalog()` getters.
- **Case-insensitive Row**: `Row.get(name)` is case-insensitive, matching `EseDb.table(name)`. Typed accessors: `get_str()`, `get_i64()`, `get_f64()`, `get_bytes()`, `get_bool()`, `get_datetime()` (returns `ForensicTimestamp`), `get_guid()`.
- **Framework bridge, not a parallel SQL layer**: `EseDb`/`Table`/`RowIter` implement `forensic_rs::traits::db::{ForensicDb, ForensicTable, ForensicRows}` directly (`forensic_db.rs`). There is deliberately no `SqlCapable`/SQL-string-parsing layer — `ForensicDb::table(name)` already expresses "get me this table's rows" natively, and the pre-0.14 `SELECT * FROM <table>` bridge is gone.
- **B-tree traversal is centralized**: `tree.rs`'s `TreeWalker`/`visit_leaves` track visited page numbers directly, not just recursion depth — a cyclic or self-referencing branch page must terminate, not loop or do exponential redundant work. `catalog.rs`, `lv.rs`, and `db.rs`'s `RowIter` all drive it; do not add another hand-rolled traversal.

## Build and Test

```sh
cargo build
cargo test
cargo clippy --all-targets
```

Test fixtures live in the gitignored `artifacts/` directory and are accessed via relative paths from `src/ese/tst.rs`. Key fixtures:
- `artifacts/sru/SRUDB.dat` — SRUM integration tests (`tests/srum.rs`) — present in this checkout
- `artifacts/SystemIdentity.mdb` — primary header/page/catalog tests (`tests/systemidentity.rs`)
- `artifacts/UAL/UAL/Current.mdb` and the GUID-named archive — full page iteration tests (`tests/ual.rs`)

A missing fixture is not a test failure: `tst.rs`'s loaders return `Option`, and every fixture-dependent test does `let Some(x) = helper() else { return };` — it prints `SKIP: fixture '...' unavailable` and passes trivially. Byte-level parser tests (bounds checks, cycle protection, header validation) use inline byte literals and need no fixture at all.

Unit tests are inline (`mod tst`/bare `#[test]` inside each module). Integration tests live in `tests/systemidentity.rs`, `tests/ual.rs`, `tests/srum.rs`. Examples in `examples/list_tables.rs`, `examples/read_ual.rs`, `examples/read_srum.rs`.

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
