# ESE Database Internals — Format & Crate Mapping

This document explains the on-disk layout of the Microsoft Extensible Storage
Engine (ESE / JET Blue) database format and maps every structural concept to the
Rust types in this crate.  It is aimed at developers who need to understand how
the parsing pipeline works or want to extend the crate.

**External reference:**  
https://techcommunity.microsoft.com/t5/ask-the-directory-services-team/ese-deep-dive-part-1-the-anatomy-of-an-ese-database/ba-p/400496

---

## 1. File Overview

An ESE database file (typically `.mdb` or `.edb`) has the following high-level
layout:

```
┌──────────────────────────────────────────┐
│  Page 0  — Database header (4 KB)        │
│  Page 0' — Header shadow copy  (4 KB)    │
│  Page 1  — DbTime / backup page (4 KB)   │
│  Page 2  — First user/system page        │
│  Page 3  — (reserved / system)           │
│  Page 4  — MSysObjects root (catalog)    │
│  Page N  — User table B-tree pages       │
└──────────────────────────────────────────┘
```

- The **header** is stored in the first `page_size` bytes (page 0).
- A redundant **shadow copy** of the header occupies the immediately following
  `page_size` bytes.
- Data pages 1 … N are indexed by the formula:

  ```
  file_offset(page_n) = (page_n + 1) × page_size
  ```

  Implemented in [`Header::page_to_file_offset`](../src/ese/header.rs).

- **Page size** is stored in the header (`HeaderRpr::page_size`).  Common values
  are 4 096, 8 192, 16 384, and 32 768 bytes.

---

## 2. Database Header

### 2.1 On-disk repr: `HeaderRpr`

```rust
// src/ese/header.rs
#[repr(C, packed)]
pub struct HeaderRpr { … }
```

`HeaderRpr` is a `repr(C, packed)` overlay that maps the raw 4 KB header bytes
directly via `align_to::<HeaderRpr>()`.  Because it is `packed`, every field is
read at its exact offset with no padding.  The overlay is then converted to the
safe `Header` struct via `TryFrom<&HeaderRpr>`.

Key fields and their offsets (all little-endian unless noted):

| Offset | Size | Field | Description |
|--------|------|-------|-------------|
| 0 | 4 | `checksum` | XOR/ECC signature over the header page |
| 4 | 4 | `file_signature` | Must be `0x89ABCDEF` to be a valid ESE file |
| 8 | 4 | `version` | Format version (e.g. `0x620` or `0x623`) |
| 12 | 4 | `type` | Header type (1 = database header, 2 = log) |
| 16 | 8 | `time` | Last modification time (LogTime encoding) |
| 28 | 4 | `state` | Database state code |
| 68 | 4 | `last_object_id` | Highest object ID allocated |
| 72 | 4 | `major_version`, `minor_version` | Engine version |
| 84 | 4 | `file_format_revision` | Format revision (determines page layout) |
| 88 | 4 | `page_size` | Page size in bytes |

The constant `ESE_HEADER_SIGNATURE = 0x89ABCDEF` is the magic number checked to
confirm the file is a valid ESE database.

### 2.2 Safe type: `Header`

```rust
pub struct Header {
    pub page_size: u32,
    pub version: u32,
    pub file_format_revision: u32,
    pub state: u32,
    // … timestamps as Filetime, backup ranges, ECC counters …
}
```

`Header` replaces all raw `u64` LogTime fields with `Filetime` (from
`forensic-rs`) and drops the fields that are not relevant to parsing.

### 2.3 Format fingerprint

`Header::fingerprint()` maps the `(version, file_format_revision)` pair to a
human-readable `FileFormatFingerprint` variant:

| Version | Revision | `FileFormatFingerprint` |
|---------|----------|-------------------------|
| `0x620` | `0x00` | `OriginalOperatingSystemBetaFormat` |
| `0x620` | `0x09` | `WindowsXPSP3` |
| `0x620` | `0x0b` | `ExchangeWithEcc` |
| `0x620` | `0x0c` | `WindowsVista` |
| `0x620` | `0x11` | `Windows7SP0` |
| `0x620` | `0x14` | `Exchange2013Ad2016` |
| `0x620` | `0xc8` | `Windows11_21H2` |
| `0x620` | `0xe6` | `Windows11` |
| `0x623` | `0x00` | `NewSpaceManager` |

### 2.4 Database state

`Header::state()` maps the raw state integer to:

| Constant | Value | `DatabaseState` |
|----------|-------|-----------------|
| `DATABASE_JUST_CREATED` | 1 | `JustCreated` |
| `DAABASE_DIRTY_SHUTDOWN` | 2 | `DirtyShutdown` |
| `DATABASE_CLEAN_SHUTDOWN` | 3 | `CleanShutdown` |
| `DATABASE_BEING_CONVERTED` | 4 | `BeingConverted` |
| `DATABASE_FORCE_DETACH` | 5 | `ForceDetach` |

> **Note:** `DAABASE_DIRTY_SHUTDOWN` is a preserved (intentional) typo from the
> public API.

### 2.5 Time encoding: `LogTime`

ESE stores timestamps in a compact 8-byte format packed as:

```
byte[0] = seconds (0–59)
byte[1] = minutes (0–59)
byte[2] = hours   (0–23)
byte[3] = day     (1–31)
byte[4] = month   (0–11, 0 = January)
byte[5] = year − 1900
byte[6] = weekday
byte[7] = reserved
```

`LogTime(u64)` in `src/ese/time.rs` implements `TryFrom<LogTime> for Filetime`,
converting to Windows FILETIME (100-nanosecond intervals since 1601-01-01).

---

## 3. Page Layout

### 3.1 Page header variants

The page header occupies the first `header_size` bytes of each page.  The layout
depends on the database format revision:

| Revision | Header repr | Checksum type | `header_size` |
|----------|-------------|---------------|---------------|
| `< 0x0b` | `PageHeaderExchange2003Repr` | XOR + page number | 32 |
| `0x0b – 0x10` | `PageHeaderWinVistaRepr` | XOR + ECC | 32 |
| `≥ 0x11`, 4/8 KB page | `PageHeaderRepr` | 64-bit checksum | 40 |
| `≥ 0x11`, 16/32 KB page | `PageHeaderWin7ExtRepr` | 64-bit + 3 ext checksums | 80 |

All three repr types map to the single safe `PageHeader` struct:

```rust
pub struct PageHeader {
    pub checksum: PageChecksum,              // Exchange2003 / WinVista / Win7
    pub last_modification_time: u64,
    pub previous_page_number: u32,
    pub next_page_number: u32,
    pub father_data_page_id: u32,           // FDP — owning B-tree root page
    pub available_data_size: u16,
    pub available_uncommited_data_size: u16,
    pub available_data_offset: u16,         // end of used data region
    pub available_page_tag: u16,            // number of tag slots at end of page
    pub page_flags: u32,
    pub extension: Option<PageExtension>,   // Win7 large-page extension
    pub header_size: u32,                   // 40 or 80 bytes
    // … version / revision stored privately for tag decoding
}
```

### 3.2 Page flags

`page_flags` is a bitfield. The constants and their helper methods on `PageHeader`:

| Constant | Value | Method |
|----------|-------|--------|
| `ROOT_PAGE_FLAG` | `0x001` | `is_root()` |
| `LEAF_PAGE_FLAG` | `0x002` | `is_leaf()` |
| `PARENT_PAGE_FLAG` | `0x004` | `is_parent()` |
| `EMPTY_PAGE_FLAG` | `0x008` | `is_empty_flag()` |
| `SPACE_TREE_PAGE_FLAG` | `0x020` | `is_space_tree()` |
| `INDEX_PAGE_FLAG` | `0x040` | `is_index()` |
| `LONG_VALUE_PAGE_FLAG` | `0x080` | `is_long_value()` |
| `PRIMARY_PAGE_FLAG` | `0x800` | `is_primary()` |
| `ERASED_PAGE_FLAG` | `0x4000` | `is_erased()` |
| `REPAIRED_PAGE_FLAG` | `0x200000` | `is_repaired()` |

A page with **none** of `ROOT`, `LEAF`, `INDEX`, `SPACE_TREE`, or `LONG_VALUE`
set and no `PARENT` or `EMPTY` flag is a **branch** page identified by
`PageHeader::is_branch()`.

### 3.3 Tag array

Entries within a page are addressed by a **tag array** that grows backwards from
the end of the page.  Each tag occupies 4 bytes and is located at:

```
tag_offset = page_size - (tag_index + 1) * 4
```

`Tag` fields depend on the revision and page size:

```rust
pub struct Tag {
    pub value_offset: u16,   // offset relative to end of page header
    pub tag_flags: u8,       // flags word (3 bits or 1 bit depending on page size)
    pub value_size: u16,     // byte length of the entry
}
```

For revision ≥ 17 with 16 KB or 32 KB pages, the offset uses 15 significant bits
and the flag occupies the top 1 bit of the offset word.  For smaller pages / older
revision, 13 bits for offset and 3 bits for flags.  `TagReader::from_buff` encodes
this logic.

**Tag 0** (the first tag, at the end of the page) is always reserved for the
**page-level external header** payload — not a data record.

The `Page` struct owns a `Vec<Tag>` parsed at construction time:

```rust
pub struct Page {
    pub page_number: u32,
    pub data: Vec<u8>,          // full page bytes
    pub header: PageHeader,
    pub tags: Vec<Tag>,
}
```

`Page::get_tag_data(n)` returns a sub-slice into `data` for tag `n`,
bounded-checking via `ForensicError::missing_str`.

---

## 4. B-Tree Structure

ESE organises all data in B-trees.  Every B-tree has:

- Exactly one **root page** (may also contain data records or branch pointers).
- Zero or more **branch pages** (interior nodes with child-page pointers only).
- One or more **leaf pages** (contain the actual data records).

The `TreePage` enum dispatches page processing:

```rust
pub enum TreePage<'a> {
    Root(RootPage<'a>),
    Branch(BranchPage<'a>),
    Leaf(LeafPage<'a>),
}
```

`Page::process_page()` selects the variant based on `page_flags`.

### 4.1 Root page — `RootPage`

```rust
pub struct RootPage<'a> {
    pub header: RootHeader,          // from tag 0
    pub entries: Vec<RootEntry<'a>>, // Branch or Leaf entries from tag 1+
}

pub struct RootHeader {
    pub header_size: u16,
    pub number_of_pages: u32,
    pub parent_father_data_page: u32,
    pub extent_space: u32,
    pub space_tree_page_number: u32,
}
```

The `RootHeader` is read from **tag 0** data.  For revision ≥ 0x14 the payload
is 25 bytes (1-byte prefix + 24 bytes of fields); for older revisions it is
16 bytes.

`RootEntry` is an enum that wraps either a `BranchPageEntry` or a `LeafPageEntry`
depending on whether the root also holds leaf rows.

### 4.2 Branch page — `BranchPage`

```rust
pub struct BranchPage<'a> {
    pub header: BranchPageHeader<'a>, // common page key from tag 0
    pub entries: Vec<BranchPageEntry<'a>>,
}

pub struct BranchPageEntry<'a> {
    pub page_key_size: u16,
    pub page_key: &'a [u8],
    pub child_page_number: u32,  // the page to follow
}
```

Each `BranchPageEntry` holds a separator key and a **child page number**.  To
traverse the B-tree, recursively load each `child_page_number`.

### 4.3 Leaf page — `LeafPage`

```rust
pub struct LeafPage<'a> {
    pub header: LeafPageHeader<'a>,    // common page key from tag 0
    pub entries: Vec<LeafPageEntry<'a>>,
}

pub struct LeafPageEntry<'a> {
    pub common_key_size: u16,
    pub page_key: &'a [u8],
    pub child_page_number: u32,  // always 0 for leaf entries
    pub data: PageEntry<'a>,
}
```

The `data` field is a `PageEntry` variant determined by the page's flags:

```rust
pub enum PageEntry<'a> {
    Index(IndexEntry<'a>),
    LongValue(LongValueEntry<'a>),
    SpaceTree(SpaceTreeEntry<'a>),
    TableValue(TableValueEntry<'a>),
}
```

### 4.4 Page key — `PageKeyRef`

```rust
pub struct PageKeyRef<'a> {
    pub suffix: &'a [u8],
    pub preffix: &'a [u8],  // note: preserved spelling
    pub page_number: u32,
}
```

The page key payload is `[suffix_len: u8][prefix_len: u8][suffix…][prefix…][page_number: u32 LE]`.
Used in root-page navigation (`Page::get_page_keys_if_root`).

---

## 5. Data Records

### 5.1 Record header — `RecordHeader`

Every data record on a leaf page begins with a 4-byte header:

```
byte[0]  last_fixed_column_id       (highest fixed col ID present; 0 = none)
byte[1]  last_variable_column_id    (highest variable col ID present; 127 = none)
byte[2–3] variable_data_offset      (LE u16; first byte of tagged-column region)
```

### 5.2 Record layout

```
┌─────────────────────────────────────────────────────────────────────────┐
│ [0]   last_fixed_column_id                                              │
│ [1]   last_variable_column_id                                           │
│ [2–3] variable_data_offset  (offset in record to start of tagged data)  │
│ [4 .. var_offsets_start-1]  fixed + variable column bytes               │
│       └─ [4 .. fixed_data_size-1]  fixed-size column bytes (packed)     │
│       └─ [fixed_data_size .. var_offsets_start-1] variable column bytes │
│ [var_offsets_start .. variable_data_offset-1]  variable offset array    │
│       (num_var × u16 LE, cumulative byte ends from start of var bytes)  │
│ [variable_data_offset ..]  tagged-column descriptor block + overflow    │
└─────────────────────────────────────────────────────────────────────────┘
```

This maps to:

```rust
pub struct RecordData<'a> {
    pub pre_tagged_data: &'a [u8],    // fixed + variable bytes (unsplit)
    pub var_column_offsets: &'a [u8], // num_var × u16 LE
    pub tagged_columns: Vec<TaggedColumn<'a>>,
    pub raw_overflow: &'a [u8],       // overflow/tagged region verbatim
}
```

All slices borrow from the owning `Page::data` buffer — zero allocations until a
`ColumnValue` is decoded.

### 5.3 Variable column overflow

In revision-0x14 (Exchange 2013 / AD 2016) databases, variable columns whose
inline offset array indicates no data may store their bytes in `raw_overflow` as
a sequence of `[len: u16 LE][bytes…]` blobs in column-ID order.  The function
`overflow_var_col(raw_overflow, idx, col_type)` in `column.rs` handles this case.

### 5.4 Tagged column descriptor

The tagged-column block starts at `variable_data_offset` and contains a sequence
of 4-byte descriptors:

```
[col_id: u16 LE][flags_and_offset: u16 LE]
```

The count is derived from the first descriptor's offset field (bits 13:0 =
`num_tags * 4`).

```rust
pub struct TaggedColumn<'a> {
    pub id: u16,     // column ID (≥ 256)
    pub flags: u8,   // bit 0 = multi-value, bit 1 = long-value reference
    pub data: &'a [u8],
}
```

---

## 6. Column Types

### 6.1 `ColumnType` enum

Maps the JET API `JET_coltyp` values:

| Value | Variant | Fixed size | Description |
|-------|---------|-----------|-------------|
| `0x01` | `Bit` | 1 | Boolean (0 or non-zero) |
| `0x02` | `UnsignedByte` | 1 | Unsigned 8-bit integer |
| `0x03` | `Short` | 2 | Signed 16-bit integer |
| `0x04` | `Long` | 4 | Signed 32-bit integer |
| `0x05` | `Currency` | 8 | Signed 64-bit (currency) |
| `0x06` | `IEEESingle` | 4 | 32-bit IEEE float |
| `0x07` | `IEEEDouble` | 8 | 64-bit IEEE float |
| `0x08` | `DateTime` | 8 | OLE Automation `DATE` (stored as Filetime) |
| `0x09` | `Binary` | — | Variable-length bytes (≤255 inline) |
| `0x0a` | `Text` | — | Variable-length text (≤255 inline) |
| `0x0b` | `LongBinary` | — | Large binary (LV B-tree or inline) |
| `0x0c` | `LongText` | — | Large text (LV B-tree or inline) |
| `0x0e` | `UnsignedLong` | 4 | Unsigned 32-bit integer |
| `0x0f` | `LongLong` | 8 | Signed 64-bit integer |
| `0x10` | `GUID` | 16 | 128-bit GUID |
| `0x11` | `UnsignedShort` | 2 | Unsigned 16-bit integer |

`ColumnType::fixed_size()` returns the byte width for fixed-size types; variable
types return `None`.

### 6.2 Column ID ranges and `ColumnDef`

```rust
pub struct ColumnDef {
    pub id: u16,          // 1–127 fixed, 128–255 variable, ≥256 tagged
    pub col_type: ColumnType,
    pub name: String,
    pub flags: u32,       // ESE column flags (cbMax, NotNull, AutoIncrement, …)
    pub codepage: u32,    // 1200 = UTF-16LE, 1252 = Windows-1252, 0 = binary
}
```

The three ranges are enforced by helpers `is_fixed()`, `is_variable()`,
`is_tagged()`.  The range boundaries come from the ESE specification.

### 6.3 `ColumnValue<'a>` and `OwnedColumnValue`

`ColumnValue<'a>` is a **lifetime-bound** decoded value that borrows bytes zero-copy
from the underlying page data.  It is used inside `TableSchema::decode_record` and
lives only as long as the page's byte buffer.

`OwnedColumnValue` is the **owned** variant (obtained via `From<ColumnValue>`)
stored in `Row::columns`.  It is suitable for long-lived structures that outlive
the page read.

`Display` implementations for both types:
- `GUID` → `xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx` (mixed-endian Windows format)
- `Text` / `LongText` → UTF-16LE when the bytes look like it (>50% high bytes
  are zero), otherwise UTF-8 lossy
- `Binary` / `LongBinary` → lowercase hex string

---

## 7. Catalog (MSysObjects)

### 7.1 MSysObjects schema

ESE stores table and column metadata in the **MSysObjects** system table, always
rooted at **B-tree page 4**.  Its schema is fixed by the engine and never changes,
so it is hardcoded in `catalog.rs` via `msys_objects_schema()`.

Notable column IDs (illustrating the fixed/variable/tagged ranges):

| ID | Name | Type | Range |
|----|------|------|-------|
| 1 | `ObjidTable` | `Long` | Fixed |
| 2 | `Type` | `Short` | Fixed |
| 3 | `Id` | `Long` | Fixed |
| 4 | `ColtypOrPgnoFDP` | `Long` | Fixed |
| 5 | `SpaceUsage` | `Long` | Fixed |
| 6 | `Flags` | `Long` | Fixed |
| 7 | `PagesOrLocale` | `Long` | Fixed |
| 8 | `RootFlag` | `Bit` | Fixed |
| 128 | `Name` | `Text` | Variable |
| 129 | `TemplateTable` | `Text` | Variable |
| 256 | `Stats` | `Binary` | Tagged |
| 258 | `DefaultValue` | `Binary` | Tagged |
| 259 | `KeyFldIDs` | `Binary` | Tagged |

### 7.2 Row type discriminator — `CatalogObjectType`

Each MSysObjects row has a `Type` column (`i16`):

| Value | `CatalogObjectType` | Meaning |
|-------|---------------------|---------|
| 1 | `Table` | Table definition row |
| 2 | `Column` | Column definition row |
| 3 | `Index` | Index definition row |
| 4 | `LongValue` | LV B-tree root row |
| 5 | `Callback` | Callback definition |

### 7.3 `TableDef` — resolved table definition

After `Catalog::from_db` performs a two-pass scan of all catalog leaf entries, each
user table is represented by:

```rust
pub struct TableDef {
    pub name: String,
    pub fdp_page: u32,            // root B-tree page of this table's data
    pub table_id: u32,            // object ID (used to join column rows)
    pub lv_fdp_page: Option<u32>, // root page of the LV B-tree, if any
    pub columns: Vec<ColumnDef>,  // sorted by column ID
    pub indexes: Vec<String>,     // index names only
}
```

**First pass**: collects all `Type == Table` rows, building skeleton `TableDef`
entries with empty `columns` and `indexes`.

**Second pass**: for every `Type == Column` row, matches `ObjidTable` against the
`table_id` of the corresponding `TableDef` and appends the `ColumnDef`.
Similarly handles `Index` and `LongValue` rows.

`Catalog::table(name)` does a case-insensitive lookup.

---

## 8. Long-Value Storage

### 8.1 Concept

Columns of type `LongBinary` and `LongText` that exceed the inline threshold are
stored in a **dedicated LV B-tree** per table.  Their leaf entry in the main data
record holds only a 4-byte **Long-Value ID (LVID)** reference.

### 8.2 LV B-tree key structure

Each LV B-tree leaf entry's page key is:

```
[lvid: u32 BE][segment_offset: u32 BE]
```

- `lvid` uniquely identifies the large value within the table.
- `segment_offset` is the byte offset of this chunk within the reassembled value.
  For single-chunk values the offset is 0.

```rust
pub struct LongValueEntry<'a> {
    pub lvid: u32,
    pub data: &'a [u8],
    pub segment_offset: u32,
}
```

### 8.3 `LongValueStore` — reassembly

```rust
pub struct LongValueStore {
    values: HashMap<u32, Vec<u8>>,  // LVID → reassembled bytes
}
```

`LongValueStore::from_db(db, header, lv_page)`:

1. Recursively traverses the LV B-tree (DFS, depth-limited to 32).
2. Collects all `LongValueEntry` items, grouped by `lvid`.
3. Sorts each group by `segment_offset` and concatenates.

`LongValueStore::get(lvid)` returns the reassembled bytes or `None`.

### 8.4 LV resolution in `TableSchema::decode_record`

When decoding a `TaggedColumn` whose type is `LongText` or `LongBinary` and whose
data is exactly 4 bytes, the decoder interprets those bytes as an LVID and calls
`lv_store.get(lvid)`.  Callers that do not have an LV store (e.g. when reading the
catalog itself) receive `ColumnValue::Nil` in that case.

---

## 9. High-Level API

The `db` module exposes a straightforward API that hides the B-tree mechanics:

```
EseDb  ──open──►  reads file, parses Header + Catalog
  │
  ├── table_names() → Vec<&str>
  │
  └── table(name) → Option<Table>
        │
        └── iter_rows() → RowIter (implements Iterator<Item = Row>)
              │
              └── Row::get(col_name) → Option<&OwnedColumnValue>
```

### 9.1 `EseDb`

```rust
pub struct EseDb {
    data: Vec<u8>,         // full raw file bytes
    pub header: Header,
    pub catalog: Catalog,
}
```

`EseDb::open(path)` reads the file, then delegates to `EseDb::from_bytes(data)`.
`EseDb::from_bytes(data)` calls `Header::from_buff` and then `Catalog::from_db`,
returning an `EseDb` that owns the raw bytes and both parsed structures.

### 9.2 `RowIter` — DFS traversal

`RowIter` maintains two pieces of state:

- `stack: Vec<u32>` — page numbers still to be visited (acts as a DFS stack,
  seeded with `TableDef::fdp_page`).
- `pending: Vec<Row>` — rows decoded from the most-recently-processed leaf page.

On each `Iterator::next()` call:

1. Pop from `pending` first (fast path — no page I/O).
2. Otherwise pop a page number from `stack`, load and process it.
3. Branch pages push their children onto `stack`.
4. Leaf pages decode all `TableValue` entries and push them onto `pending`
   (in reverse, so that `pop()` yields original order).

Long-value columns are resolved via a `LongValueStore` built once when
`Table::iter_rows()` is called (if the table has `lv_fdp_page`).

### 9.3 `Row`

```rust
pub struct Row {
    pub columns: Vec<(String, OwnedColumnValue)>,
}
```

`Row::get(name)` does a linear search by exact column name.  All values are
`OwnedColumnValue`, fully decoded and independent of the page bytes.

---

## 10. Forensic Artifact Mapping

### 10.1 UAL — User Access Logging (`Current.mdb`)

| Table | Key columns | Purpose |
|-------|-------------|---------|
| `CLIENTS` | `Address`, `AuthenticatedUserName`, `LastSeen`, … | Per-client access log |
| `DNS` | `HostName`, … | DNS name resolution records |
| `ROLE_ACCESS` | `RoleGuid`, … | Per-role access summary |
| `VIRTUALMACHINES` | … | Hyper-V guest tracking |

### 10.2 UAL — System Identity (`SystemIdentity.mdb`)

| Table | Key columns | Purpose |
|-------|-------------|---------|
| `SYSTEM_IDENTITY` | `SystemDNSHostName`, `SystemDomainName`, `OSBuildNumber`, `OSLastBootUpTime`, `SystemSMBIOSUUID`, … | System fingerprint at log creation time |
| `CHAINED_DATABASES` | `Year`, `FileName` | Yearly archive chain |
| `ROLE_IDS` | `RoleGuid`, `ProductName`, `RoleName` | Windows role definitions |

---

## 11. Zero-Copy Design & Lifetimes

All page-derived types carry a `'a` lifetime tied to the owning `Page::data`
buffer:

```
Page { data: Vec<u8> }          ← owns raw bytes
 └─ BranchPage<'a>              ← borrows &'a [u8] slices
 └─ LeafPage<'a>
     └─ LeafPageEntry<'a>
         └─ TableValueEntry<'a>
             └─ RecordData<'a>  ← pre_tagged_data, var_column_offsets, raw_overflow
                 └─ ColumnValue<'a>::Text(&'a [u8])  ← zero-copy text slice
```

Once a `ColumnValue<'a>` is promoted to `OwnedColumnValue` (via `Row`), the
lifetime dependency is severed and the data is heap-allocated.

**Invariant**: never store a `ColumnValue<'a>` (or any borrow of `RecordData`)
beyond the scope of the `Page` that produced it.  Use `OwnedColumnValue` for
long-lived storage.
