# frnsc-esedb Agent Guide

## Project Overview

`frnsc-esedb` implements the `forensic-rs` `ForensicDb`/`ForensicTable`/`ForensicRows` traits (`src/ese/forensic_db.rs`) and `FormatFactory` (`src/ese/format.rs`) for Microsoft ESE / JET Blue databases (`.mdb`/`.edb`/`.dat`/`.jfm`) — SRUM (`SRUDB.dat`), UAL (`Current.mdb` and yearly GUID archives), and Windows Search index files. It is a from-scratch, zero-C-dependency binary parser: page layout, B-tree traversal, catalog decoding, and column typing are all implemented directly against the on-disk format (see [`docs/internals.md`](docs/internals.md)).

**Depends on:** [`forensic-rs`](https://github.com/ForensicRS/forensic-rs) 0.14

## Review discipline

Apply the `forensic-rs-tool-review` skill (copy it from `../forensic-rs/docs/agent-guide/skills/forensic-rs-tool-review/` into `.claude/skills/` if it isn't there) to every change here: it covers the trait-layering contract (Core vs. `Ext`), forensic soundness (never fabricate a missing timestamp, source divergence is evidence not noise, the Finding/log/error three-way split), and adversarial-input robustness (no panics on evidence bytes, bounds-checked parsing). Don't restate that content in this file.

Two forensic-soundness bugs found and fixed during the 0.14 migration are worth knowing about if you're touching timestamp or B-tree code:

- **ESE `DateTime` columns are an OLE Automation date (f64 days since 1899-12-30), not a raw FILETIME.** This is a JET/ESE specification quirk, easy to get wrong again if this code is ever rewritten — see the comment at `src/ese/column.rs`'s `ColumnType::DateTime` arm in `ColumnValue::from_fixed`.
- **`LogTime` (the ESE *header's* ad-hoc packed timestamp, distinct from column-typed `DateTime`) uses 1-based day/month**, not 0-based — see `src/ese/time.rs`.

Both were verified directly against real bytes in `artifacts/sru/SRUDB.dat` before being changed; if you touch either conversion again, re-verify against a real fixture rather than trusting the arithmetic in isolation — this is exactly the kind of bug arithmetic review alone won't catch.

## Module structure

```
src/
├── lib.rs              — crate root; re-exports EseDb, Row, Table, EseFormatFactory, etc.
└── ese/
    ├── header.rs        — file header (HeaderRpr → Header); validates ESE signature + page size
    ├── column.rs        — ColumnType (17 variants), ColumnValue/OwnedColumnValue, TableSchema, forensic_type()
    ├── catalog.rs        — MSysObjects catalog parser (rooted at page 4) → Catalog, TableDef
    ├── db.rs             — public API: EseDb, Table, RowIter, Row (case-insensitive typed accessors)
    ├── forensic_db.rs    — ForensicDb/ForensicTable/ForensicRows impl (the framework bridge)
    ├── format.rs         — EseFormatFactory (probe/mount as Mounted::Database)
    ├── reader.rs         — PageReader trait + SliceReader / FileReader / VirtualFileReader
    ├── tree.rs           — shared, cycle-safe B-tree traversal (TreeWalker, visit_leaves)
    ├── tag.rs            — page slot-array tag parsing
    ├── time.rs           — ESE LogTime → ForensicTimestamp (header timestamps only)
    ├── lv.rs             — LongValueStore: long-value B-tree traversal + segment reassembly
    └── page/
        ├── mod.rs        — Page, PageHeader (checksum variants by version/revision), TreePage dispatch
        ├── root.rs       — RootPage / RootHeader
        ├── branch.rs     — B-tree interior nodes (BranchPage)
        ├── leaf.rs       — B-tree leaf nodes (LeafPage)
        └── entries/      — PageEntry dispatch: IndexEntry, LongValueEntry, SpaceTreeEntry, TableValueEntry
└── srum/
    ├── mod.rs           — SrumDatabase entry point; per-table accessors (all ForensicResult)
    ├── index.rs         — SrumIdIndex — SruDbIdMapTable ID→app/SID map
    ├── timeline.rs       — TimelineBuilder / TimelineEvent — cross-table sorted view
    ├── volume.rs         — VolumeMap: \Device\HarddiskVolumeN → drive letter
    ├── enrichment.rs     — SrumEnrichment / WinEventEnrichment trait seams
    └── tables/           — one record + iterator pair per SRUM table (GUID-named)
```

- **Parsing flow:** `Header::from_buff` → per-page `Page::new` (offset = `(N+1) * page_size`, validated in `Header::from_buff`) → `Page::process_page` → `TreePage::{Root, Branch, Leaf}` → `Catalog::from_db` (MSysObjects, page 4) → `EseDb` high-level API.
- **B-tree traversal is centralized in `tree.rs`.** Do not hand-roll another recursive/depth-bounded walk — `TreeWalker`/`visit_leaves` track visited page numbers directly (a depth counter alone bounds recursion depth, not the number of pages visited, so a cyclic branch page still causes exponential re-exploration). `catalog.rs`, `lv.rs`, and `db.rs`'s `RowIter` all drive the same walker.

## Conventions

- **Zero-copy repr overlay for fixed headers**: `HeaderRpr`/`PageHeaderRepr` are cast from raw bytes via `align_to::<ReprType>()` (documented `unsafe`, with a `// SAFETY:` comment) from `#[repr(C, packed)]` structs, then converted to safe Rust types via `TryFrom`. Every `align_to` call is guarded by an explicit length check (`ensure_min_length!`) — the `head.is_empty()` check alone is not sufficient, since these `repr(packed)` types have alignment 1 and `head` is trivially always empty.
- **Lifetime-heavy slices**: Parsed page types (`BranchPage<'a>`, `LeafPage<'a>`, etc.) borrow directly from the owning `Page`'s `data: Cow<'a, [u8]>`. Preserve this zero-copy design.
- **Error handling**: Use `ForensicResult<T>` everywhere. Prefer `ensure_format!`/`ensure_min_length!`/`ensure_buffer_size!`/`ensure_buffer_range!` and `ForensicError::invalid_format`/`missing_data` over the deprecated `bad_format_str`/`missing_str` constructors. Soft-skip individual entry failures with `forensic_rs::debug!` rather than aborting the whole page; anything an analyst would want to see in a case report should go through a count/log at minimum (full `Finding` routing is not yet wired up — see `EseDb::lv_cache`'s `warn!` sites for the current pattern).
- **Preserved naming quirks**: `service_pack_nmber`, `DAABASE_DIRTY_SHUTDOWN` exist in the public API. Do not rename without a coordinated refactor.
- **Variable column overflow**: In ESE revision 20 databases, variable column data (e.g., `Name` in MSysObjects) is stored in the overflow/tagged area as `[len: u16 LE][bytes]` blobs in column-ID order. `RecordData.raw_overflow` holds this region; `overflow_var_col()` in `column.rs` decodes it.
- **Crate-root re-exports**: Key types are re-exported at crate root — `use frnsc_esedb::{EseDb, Row, Table, OwnedColumnValue, ColumnType, ColumnDef, ColumnValue, EseFormatFactory}`. Internal fields (`EseDb.header`, `EseDb.catalog`) are `pub(crate)`; use `header()` and `catalog()` getters.
- **Case-insensitive Row**: `Row.get(name)` is case-insensitive, matching `EseDb.table(name)`. Typed accessors: `get_str()`, `get_i64()`, `get_f64()`, `get_bytes()`, `get_bool()`, `get_datetime()`, `get_guid()`.
- **Framework bridge, not a parallel SQL layer**: `EseDb`/`Table`/`RowIter` implement `ForensicDb`/`ForensicTable`/`ForensicRows` directly (`forensic_db.rs`); there is deliberately no `SqlCapable`/SQL-string-parsing layer — `ForensicDb::table(name)` already expresses "get me this table's rows" natively.

## Testing

```sh
cargo test
cargo clippy --all-targets
```

Test fixtures live in the gitignored `artifacts/` directory (not committed — `artifacts/sru/SRUDB.dat` for SRUM, `artifacts/SystemIdentity.mdb` and `artifacts/UAL/UAL/*.mdb` for the other two integration suites). Fixture-dependent tests check `Path::exists()` first and print `SKIP: fixture '...' unavailable` + return early rather than failing when a fixture is missing — preserve this pattern in new fixture-dependent tests (`let Some(db) = open_db() else { return };`, where `open_db()` does the existence check).

Byte-level parser tests (bounds checks on untrusted page bytes, cycle-protection, header signature/page-size validation) use inline byte literals — no fixture needed, and these are exactly the tests that catch the parser panicking on hostile input. Add one whenever you touch a function that indexes into or slices bytes sourced from evidence.
