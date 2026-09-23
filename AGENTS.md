# frnsc-esedb Agent Guide

## Project Overview

`frnsc-esedb` implements the `forensic-rs` `ForensicDb`/`ForensicTable`/`ForensicRows` traits (`src/ese/forensic_db.rs`) and `FormatFactory` (`src/ese/format.rs`) for Microsoft ESE / JET Blue databases (`.mdb`/`.edb`/`.dat`) — SRUM (`SRUDB.dat`), UAL (`Current.mdb` and yearly GUID archives), and Windows Search index files. It is a from-scratch, zero-C-dependency binary parser: page layout, B-tree traversal, catalog decoding, and column typing are all implemented directly against the on-disk format (see [`docs/internals.md`](docs/internals.md)).

Beyond the database file itself, `src/ese/log/` parses the surrounding **file set** — transaction logs (`.log`/`.jrs`), the checkpoint (`.chk`), and the flush map (`.jfm`, which is *not* a mountable database — see below) — and aggregates them into a log-set integrity report. `src/ese/recovery/` recovers rows absent from ordinary iteration (defunct-tagged rows still linked into a live B-tree, and candidate rows carved from a live page's unallocated slack), groups live + recovered rows into a per-key history, and can export recovered rows to an opt-in JSONL sidecar.

**Depends on:** [`forensic-rs`](https://github.com/ForensicRS/forensic-rs) 0.14

## Review discipline

Apply the `forensic-rs-tool-review` skill (copy it from `../forensic-rs/docs/agent-guide/skills/forensic-rs-tool-review/` into `.claude/skills/` if it isn't there) to every change here: it covers the trait-layering contract (Core vs. `Ext`), forensic soundness (never fabricate a missing timestamp, source divergence is evidence not noise, the Finding/log/error three-way split), and adversarial-input robustness (no panics on evidence bytes, bounds-checked parsing). Don't restate that content in this file.

Two forensic-soundness bugs found and fixed during the 0.14 migration are worth knowing about if you're touching timestamp or B-tree code:

- **ESE `DateTime` columns are an OLE Automation date (f64 days since 1899-12-30), not a raw FILETIME.** This is a JET/ESE specification quirk, easy to get wrong again if this code is ever rewritten — see the comment at `src/ese/column.rs`'s `ColumnType::DateTime` arm in `ColumnValue::from_fixed`.
- **`LogTime` (the ESE *header's* ad-hoc packed timestamp, distinct from column-typed `DateTime`) uses 1-based day/month**, not 0-based — see `src/ese/time.rs`.

Both were verified directly against real bytes in `artifacts/sru/SRUDB.dat` before being changed; if you touch either conversion again, re-verify against a real fixture rather than trusting the arithmetic in isolation — this is exactly the kind of bug arithmetic review alone won't catch.

Three more, found while building the log/checkpoint/recovery layer, worth knowing if you touch that code:

- **A log data sector's own generation must be tested before its `isec`** in `LogSector::classify` (`src/ese/log/sector.rs`). `artifacts/sru/SRU000B8.log` sector 15 has `isec == 14` (which looks exactly like the benign torn-write shadow every other archived log's last sector shows) but `generation == 174`, sixteen generations stale. Testing `isec` first silently relabels verified residual evidence as a harmless shadow.
- **`SRU.chk` (8192 bytes) is two byte-identical 4096-byte halves** — the checkpoint file's own torn-write guard, the same idea as a log sector's shadow copy, just at whole-file granularity. `LogParams::scan` honestly finds every `ATTACHINFO` record twice when both halves are present and identical; this is not a scanner bug, and code consuming `CheckpointFile::params` must not assume attachments are deduplicated.
- **`LeafPageEntry::leaf_entries` (`src/ese/page/leaf.rs`) still does not filter on `TAG_DEFUNCT`** — it decodes every tag on a leaf page, live or defunct, into `entries`, tagging each with its `tag_index`/`defunct` flag. That is deliberate: it stays the faithful "every tag on the page" primitive `recovery::defunct` needs. **`RowIter` (`db.rs`) is what filters** — it skips `defunct` entries, so `Table::iter_rows()`/`EseDb`'s `ForensicRows` cursor (`EseRows`) is an allocated-only view, matching the `ForensicRows::allocated()`/`recovery()`/`locus()` contract (a row that leaked through unfiltered would falsely report `allocated() == true`). Verified on `artifacts/sru/SRUDB.dat`: zero defunct tags are reachable from any live tree, so this changed no row counts on this fixture, but it is still a breaking behavior change for a database that does have live defunct tags — see `CHANGELOG.md`.

A fourth, confirmed twice over: on `artifacts/sru/SRUDB.dat`, a whole-file byte scan for `TAG_DEFUNCT` tags finds 14 pages that look defunct-tagged, and a separate whole-file scan finds 537 KB of non-zero page slack — but *none* of either is reachable from any table's data tree, LV tree, or the catalog tree (verified with `TreeWalker`; every tree together accounts for only 145,818 bytes of slack, all of it zero). Both are fully unlinked (freed) pages, or pages belonging to untracked trees (secondary indexes), whose old leaf content the engine never wiped — a materially different, riskier recovery source (page-slack/carving-at-the-freed-page-level: it needs a linear file scan, and honest table attribution without guessing a schema against an orphaned page is unsolved) than "a page still linked into a live tree", which is what `recovery::defunct` and `recovery::slack` both implement. See `defunct`'s `real_srum_fixture_has_zero_defunct_tags_in_any_live_tree` and `slack`'s `real_srum_fixture_live_tree_slack_is_entirely_zero_filled` for the verified, honest (zero) results on this fixture, and each module's synthetic tests for proof the mechanisms themselves work.

## Module structure

```
src/
├── lib.rs              — crate root; re-exports EseDb, Row, Table, EseFormatFactory, etc.
└── ese/
    ├── header.rs        — file header (HeaderRpr → Header); validates ESE signature + page size
    ├── column.rs        — ColumnType (17 variants), ColumnValue/OwnedColumnValue, TableSchema, forensic_type()
    ├── catalog.rs        — MSysObjects catalog parser (rooted at page 4) → Catalog, TableDef
    ├── db.rs             — public API: EseDb, Table, RowIter, Row (case-insensitive typed accessors)
    ├── forensic_db.rs    — ForensicDb/RecoverRows/ForensicTable/ForensicRows impl (the framework bridge)
    ├── format.rs         — EseFormatFactory (Mounted::Database) + EseLogSetFactory (Mounted::FileSet)
    ├── reader.rs         — PageReader trait + SliceReader / FileReader / VirtualFileReader
    ├── tree.rs           — shared, cycle-safe B-tree traversal (TreeWalker, visit_leaves)
    ├── tag.rs            — page slot-array tag parsing
    ├── time.rs           — ESE LogTime → ForensicTimestamp (header timestamps only)
    ├── lv.rs             — LongValueStore: long-value B-tree traversal + segment reassembly
    ├── lgpos.rs          — Lgpos {generation, sector, byte}: the log-position type shared by header.rs and log/
    ├── signature.rs      — LogTimestamp (3-state: Unset/Present/Invalid) + Signature (28-byte instance identity)
    ├── checksum.rs       — xor32_le + the two verified log/checkpoint checksum algorithms; ChecksumVerdict
    ├── page/
    │   ├── mod.rs        — Page, PageHeader (checksum variants by version/revision), TreePage dispatch
    │   ├── root.rs       — RootPage / RootHeader
    │   ├── branch.rs     — B-tree interior nodes (BranchPage)
    │   ├── leaf.rs       — B-tree leaf nodes (LeafPage)
    │   └── entries/      — PageEntry dispatch: IndexEntry, LongValueEntry, SpaceTreeEntry, TableValueEntry
    ├── log/              — the file SET around a database: transaction logs, checkpoint, flush map, reserved logs
    │   ├── mod.rs        — LogFile (open/from_bytes/from_virtual_file), probe_log_file()
    │   ├── header.rs     — LogFileHeaderRpr (0x00..0x48) → LogFileHeader; the verified checksum + geometry checks
    │   ├── sector.rs     — LogSector, SectorClass (Live/Shadow/Stale/Unwritten/Unrecognized), LogSectorIter
    │   ├── params.rs     — DBMS_PARAM/ATTACHINFO bounded structural scan, shared by log headers AND checkpoints
    │   ├── checkpoint.rs — Checkpoint / CheckpointFile (whole-file checksum, eager/owned, no held fd)
    │   ├── flushmap.rs   — FlushMap (.jfm) header only; no bitmap (layout not determined)
    │   ├── set.rs        — EseLogSet: discovery (signature-first, filename-second) via MountContext/FileSystem
    │   └── report.rs     — LogSetReport, LogAnomaly (each variant carries observed-vs-expected + benign_explanation())
    └── recovery/         — rows absent from ordinary iteration but still recoverable from intact bytes
        ├── mod.rs        — RecoveredRow = forensic_rs::recovery::Recovered<Row>; RecoveryStats; tagged_locus/slack_locus
        ├── validate.rs   — decode_and_admit(): the one admission gate every source funnels through; is_meaningful()
        ├── defunct.rs    — recover_defunct_rows(): TAG_DEFUNCT rows still linked into a live B-tree
        ├── slack.rs      — recover_slack_rows(): candidates in a live page's unallocated slack (stricter admission bar)
        ├── history.rs    — row_history(): group live + recovered rows by a caller-supplied key; RowHistory::is_disputed()
        └── sidecar.rs    — export_recovered()/export_recovered_to_files(): ProvenanceJsonlSink-backed, opt-in JSONL + side table
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
- **Crate-root re-exports**: Key types are re-exported at crate root — `use frnsc_esedb::{EseDb, Row, Table, OwnedColumnValue, ColumnType, ColumnDef, ColumnValue, EseFormatFactory, EseLogSetFactory}`. Internal fields (`EseDb.header`, `EseDb.catalog`) are `pub(crate)`; use `header()` and `catalog()` getters.
- **Case-insensitive Row**: `Row.get(name)` is case-insensitive, matching `EseDb.table(name)`. Typed accessors: `get_str()`, `get_i64()`, `get_f64()`, `get_bytes()`, `get_bool()`, `get_datetime()`, `get_guid()`.
- **Framework bridge, not a parallel SQL layer**: `EseDb`/`Table`/`RowIter` implement `ForensicDb`/`ForensicTable`/`ForensicRows` directly (`forensic_db.rs`); there is deliberately no `SqlCapable`/SQL-string-parsing layer — `ForensicDb::table(name)` already expresses "get me this table's rows" natively.

## Log set (`src/ese/log/`)

- **`Lgpos`/`Signature`/`checksum::*` live above `log/`** (directly under `ese/`), not inside it, so `header.rs` can use them without `ese::header` reaching down into `ese::log` — this is what keeps the module graph acyclic. `Header::position`/`attach_position`/`detach_position` are `Lgpos` (retyped from a flat `u64` in `0.3.0` — a deliberate breaking change; see `CHANGELOG.md`), and `Header::log_signature`/`database_signature` are `Signature`.
- **Never degrade a log/checkpoint timestamp to a default instant.** `LogTimestamp` is three-state (`Unset`/`Present`/`Invalid`) specifically so this layer never repeats `Header::log_time_or_epoch`'s trade-off (defensible there for noisy ECC/scrub fields; wrong here, since these values land in case-facing summaries). `instant()` returns `Option` — no code path can produce a fabricated time.
- **`ChecksumVerdict::NotVerified` is not optional decoration.** Both verified algorithms (`checksum::log_file_header_checksum`, `checksum::checkpoint_checksum`) are confirmed byte-exactly against every fixture in `artifacts/sru/`; anything without a verified algorithm (a `.jfm` header, a log data sector) must return `NotVerified`, never a fabricated `Match`.
- **`log/params.rs`'s `ATTACHINFO` scan is a bounded structural scan, not a fixed offset**, because the base→`ATTACHINFO` delta differs between a `.log` header (568) and a `.chk` file (600). Every admission gate matters — in particular, requiring the embedded `LOGTIME` to be `Present` (not merely "not `Invalid`") is load-bearing: accepting `Unset` was verified to manufacture a second, spurious attachment out of ordinary zero-padding.
- **`EseLogSet` discovery groups by `signLog` first, filename second.** A database's log-set base name (e.g. `SRU`) is not derivable from the database's own filename (`SRUDB.dat`) — see `set.rs`'s `strip_log_role`. That grouping rule is the only ESE-specific part left in `set.rs`: directory listing and locator construction are `forensic_rs::traits::format::MountContext`'s job (`parent_dir()`/`siblings()`/`sibling_locator()`), reached via `EseLogSet::discover`/`discover_in`/`discover_via_mount_context`. There is no `log/source.rs` anymore — the old `LogSetSource` trait and its `Dir`/`Vfs`/`InMemory` implementations were exactly what `MountContext` replaces; tests use `forensic_rs::prelude::testing::InMemoryVirtualFileSystem` instead of a bespoke `InMemoryLogSetSource`.
- **`EseLogSetFactory` (`format.rs`) is a second, independent `FormatFactory`** over the same candidate file as `EseFormatFactory`, yielding `MountKind::FileSet` instead of `MountKind::Database` — a real resolver registers both and calls `resolve` twice. It reports only filename-shape membership as a `Mounted::FileSet` (addresses via `ctx.sibling_locator()`, no header parsing) — deliberately lighter than `EseLogSet`'s signature-verified discovery, which stays available directly for a caller wanting the full integrity report.
- **A directory holding more than one distinct `signLog` leaves every set's `flush_maps`/`reserves` empty**, rather than duplicating them into every bucket. Neither a `.jfm` nor a `.jrs` carries its own signature, so there is no honest way to attribute one to a specific set when more than one shares the directory — see `set.rs`'s `from_names`.
- **`LogAnomaly::benign_explanation()` is not optional.** Every variant must state, in the type, the innocent explanation an examiner should rule out before treating it as tampering evidence — losing that between analysis and report is the failure mode this type exists to prevent. See `report.rs` for the confirmed benign cases (a zero-filled `.jrs` fails no checksum rule; a temp file recycling an old generation is never `DuplicateGeneration`; a generation gap below the required range is `Info`, not `Medium`).

## Recovery (`src/ese/recovery/`)

- **`EseDb` implements `forensic_rs::traits::db::RecoverRows`, not a bespoke API.** `as_recovery()` always returns `Some(self)` (every ESE table can be asked for defunct/slack rows, even when the honest answer is empty); `recovered_rows`/`slack_rows` return an ordinary `Box<dyn ForensicRows>` whose cursor (`RecoveredEseRows`, `forensic_db.rs`) reports `allocated() == false` and a real `recovery()`/`locus()` per row — there is no separate "recovered row" type a caller has to special-case. `row_history` is deliberately left at the trait's `EmptyRows` default: the trait documents it as *log-replay-derived* prior versions, which this crate does not do (see below) — claiming that mechanism via the caller-keyed grouping this crate *does* support would be dishonest, so that grouping stays the inherent `EseDb::row_history` method instead.
- **`RecoveredRow` is a type alias for `forensic_rs::recovery::Recovered<Row>`**, not a crate-local struct — it has no `Deref`, so a caller must go through `.value()`/`.into_value()` to see the row, keeping the recovery mode visible at every use site. The old `RowSource` enum is gone; `recovery::tagged_locus(page, tag)`/`recovery::slack_locus(page, offset)` build the equivalent `Locus::Record`/`Locus::PageOffset`. A slack candidate's locus is `PageOffset`, not `RawOffset`: it has a real page (found while walking that page's own slack), just no tag, and `PageOffset` is the shape core added for exactly this — keeping the page means never needing `Header::page_to_file_offset` just to report an address, and no fallible conversion that could silently drop a candidate.
- **`RecoveryStats` reaches the caller through `ForensicRows::scan_report()`**, not just internally. `RecoveredEseRows` (`forensic_db.rs`) carries the `RecoveryStats` each scan produced and converts it via `RecoveryStats::to_report()` into `forensic_rs::recovery::RecoveryReport` on demand — before this seam existed the counts were computed and then dropped (`let (rows, _stats) = ...`), which is exactly the gap that method exists to close. An ordinary `iter_rows()` cursor correctly still reports `None`: it never ran a scan.
- **Strict validation over recall.** Every recovery source decodes a candidate through the exact same path the live row iterator uses (`TableSchema::decode_record`), validated against *only* the schema of the table that owns the page — never "try every schema and pick the best fit". A candidate that fails to parse, or that decodes to all-null columns, is silently dropped, not reported with lower confidence. This policy (and its wording) comes from this crate's closest precedent, `frnsc-hive`'s deleted-cell carving (`recovery.rs` there) — read that module's doc comment before extending this one.
- **Never resolve a recovered row's long-value columns.** The row's recorded LVID may since have been reused by an unrelated, currently-live long value; attaching that value to a deleted row would fabricate a connection the bytes do not support. `recover_defunct_rows` always passes `lv_store: None`.
- **`slack.rs`'s region-finding is `forensic_rs::recovery::slack_regions`**, not hand-rolled arithmetic — it clips/sorts/merges the page's live tag extents and returns every disjoint unallocated region, including interior gaps *between* two live records (a real capability gain over the single-trailing-gap-only version this replaced). `looks_like_padding` is a pre-decode gate applied to each region before spending a schema decode on it.
- **`validate::is_meaningful` is still needed alongside `looks_like_padding` — they are not redundant.** `looks_like_padding` is a byte-level, pre-decode check (all-zero/all-0xFF/too-short); `is_meaningful` is a post-decode, per-column-type check that catches what padding detection cannot: a byte window straddling a real record and its trailing zero padding is not uniformly zero, yet every column in it can still decode to zero. Keep both.
- **Use `forensic_rs::provenance::Recovery` for the `recovery` field**, not a crate-local enum — it already models exactly this axis (`Allocated`/`DeletedMetadata`/`Slack`/`LogReplayed`/`DirtyChunk`/`Carved`), and `forensic_rs::provenance::Confidence` grades each for free from `(Acquisition, Recovery)`.
- **`defunct.rs` and `slack.rs` (both scoped to live, tree-reachable pages) are implemented; log-borne row recovery is not.** Log-borne recovery would require decoding at least enough of a log record's structure to locate a row image within it — the same LR-decoding capability `src/ese/log/mod.rs`'s module doc explicitly defers pending an `esentutl /ml` ground-truth fixture. Implementing a "lighter" version without that fixture would carry the identical fabrication risk; don't.
- **Page-slack carving needed a stricter bar than defunct-tag recovery, discovered by a failing test, not by inspection.** A synthetic test with one genuinely-populated fixed column and one absent column was admitted anyway — because `decode_and_admit`'s original gate only checked "not `Nil`", and a zero-valued numeric decode (from bytes that were actually the previous record's trailing padding) is not `Nil`. Fixed by `validate::is_meaningful`, which additionally excludes a decoded *zero* (numeric, GUID, or all-zero bytes) from counting toward admission — a zero is byte-for-byte indistinguishable from unwritten memory reinterpreted as that column type. `Bit(false)` is deliberately exempted (a boolean has no "unwritten" reading). `slack.rs` also requires **two** meaningful columns, not [`defunct`'s] one, since there is no governing tag to lean on. Re-verify both properties (zero-exclusion, two-column bar) if you touch `validate.rs` or add a new recovery source.
- **`sidecar.rs` exports through `forensic_rs::pipeline::sinks::ProvenanceJsonlSink`**, minting a real `ProvenanceId`/`ProvenanceStore` per export rather than the honest-but-reduced structured `source` field the old hand-rolled JSONL used — that reduction was a deliberate, documented stopgap (see `CHANGELOG.md`), lifted now that a real provenance identity is available. Each record's `Locus` is still emitted as explicit fields (`ese.page`/`ese.slot`/`ese.offset`) plus a deterministic `EventId`, since `Locus` itself never reaches the side table (by core's own design).
- **Orphaned/freed pages need their own admission gate before recovery is extended there.** See the "forensic-soundness bugs" section above: honest table attribution without guessing a schema against an untracked page is unsolved, and that's exactly the population where this fixture's actual recoverable content lives.

## Testing

```sh
cargo test
cargo clippy --all-targets
```

Test fixtures live in the gitignored `artifacts/` directory (not committed — `artifacts/sru/SRUDB.dat` for SRUM, plus its full log set in the same directory: `SRU.log`/`SRU000B6.log`/`SRU000B7.log`/`SRU000B8.log`/`SRUtmp.log` (generations 185/182/183/184/181), `SRU.chk`, `SRUDB.jfm`, `SRUres00001.jrs`/`SRUres00002.jrs`; `artifacts/SystemIdentity.mdb` and `artifacts/UAL/UAL/*.mdb` for the other two integration suites). Fixture-dependent tests check `Path::exists()` first and print `SKIP: fixture '...' unavailable` + return early rather than failing when a fixture is missing — preserve this pattern in new fixture-dependent tests (`let Some(db) = open_db() else { return };`, where `open_db()` does the existence check).

Byte-level parser tests (bounds checks on untrusted page bytes, cycle-protection, header signature/page-size validation) use inline byte literals — no fixture needed, and these are exactly the tests that catch the parser panicking on hostile input. Add one whenever you touch a function that indexes into or slices bytes sourced from evidence.
