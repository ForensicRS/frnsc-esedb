use std::fmt;
use forensic_rs::traits::db::ForensicColumnType;
use forensic_rs::utils::time::ForensicTimestamp;

/// ESE column type identifiers as defined in the JET API specification.
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ColumnType {
    Nil           = 0x00,
    Bit           = 0x01,
    UnsignedByte  = 0x02,
    Short         = 0x03,
    Long          = 0x04,
    Currency      = 0x05,
    IEEESingle    = 0x06,
    IEEEDouble    = 0x07,
    DateTime      = 0x08,
    Binary        = 0x09,
    Text          = 0x0a,
    LongBinary    = 0x0b,
    LongText      = 0x0c,
    UnsignedLong  = 0x0e,
    LongLong      = 0x0f,
    GUID          = 0x10,
    UnsignedShort = 0x11,
}

impl ColumnType {
    /// Returns the fixed byte size for fixed-size column types, or `None` for
    /// variable-length types (Binary, Text, LongBinary, LongText).
    pub fn fixed_size(self) -> Option<usize> {
        match self {
            ColumnType::Nil           => Some(0),
            ColumnType::Bit           => Some(1),
            ColumnType::UnsignedByte  => Some(1),
            ColumnType::Short         => Some(2),
            ColumnType::Long          => Some(4),
            ColumnType::Currency      => Some(8),
            ColumnType::IEEESingle    => Some(4),
            ColumnType::IEEEDouble    => Some(8),
            ColumnType::DateTime      => Some(8),
            ColumnType::Binary        => None,
            ColumnType::Text          => None,
            ColumnType::LongBinary    => None,
            ColumnType::LongText      => None,
            ColumnType::UnsignedLong  => Some(4),
            ColumnType::LongLong      => Some(8),
            ColumnType::GUID          => Some(16),
            ColumnType::UnsignedShort => Some(2),
        }
    }

    pub fn from_u8(v: u8) -> Option<Self> {
        match v {
            0x00 => Some(ColumnType::Nil),
            0x01 => Some(ColumnType::Bit),
            0x02 => Some(ColumnType::UnsignedByte),
            0x03 => Some(ColumnType::Short),
            0x04 => Some(ColumnType::Long),
            0x05 => Some(ColumnType::Currency),
            0x06 => Some(ColumnType::IEEESingle),
            0x07 => Some(ColumnType::IEEEDouble),
            0x08 => Some(ColumnType::DateTime),
            0x09 => Some(ColumnType::Binary),
            0x0a => Some(ColumnType::Text),
            0x0b => Some(ColumnType::LongBinary),
            0x0c => Some(ColumnType::LongText),
            0x0e => Some(ColumnType::UnsignedLong),
            0x0f => Some(ColumnType::LongLong),
            0x10 => Some(ColumnType::GUID),
            0x11 => Some(ColumnType::UnsignedShort),
            _    => None,
        }
    }

    /// Map to `forensic_rs`'s column-type vocabulary.
    ///
    /// A fidelity upgrade over the pre-0.14 SQL bridge, which flattened
    /// `DateTime` and `GUID` into `Binary`: `ForensicColumnType` carries both
    /// natively.
    pub fn forensic_type(self) -> ForensicColumnType {
        match self {
            ColumnType::Nil           => ForensicColumnType::Null,
            ColumnType::Bit           => ForensicColumnType::Bool,
            ColumnType::UnsignedByte  => ForensicColumnType::U8,
            ColumnType::Short         => ForensicColumnType::I16,
            ColumnType::Long          => ForensicColumnType::I32,
            ColumnType::Currency      => ForensicColumnType::I64,
            ColumnType::IEEESingle    => ForensicColumnType::F32,
            ColumnType::IEEEDouble    => ForensicColumnType::F64,
            ColumnType::DateTime      => ForensicColumnType::DateTime,
            ColumnType::Binary        => ForensicColumnType::Binary,
            ColumnType::Text          => ForensicColumnType::Text,
            ColumnType::LongBinary    => ForensicColumnType::Binary,
            ColumnType::LongText      => ForensicColumnType::Text,
            ColumnType::UnsignedLong  => ForensicColumnType::U32,
            ColumnType::LongLong      => ForensicColumnType::I64,
            ColumnType::GUID          => ForensicColumnType::Guid,
            ColumnType::UnsignedShort => ForensicColumnType::U16,
        }
    }
}

/// A typed column value decoded from an ESE data record.
#[derive(Debug, Clone)]
pub enum ColumnValue<'a> {
    Nil,
    Bit(bool),
    UnsignedByte(u8),
    Short(i16),
    Long(i32),
    Currency(i64),
    IEEESingle(f32),
    IEEEDouble(f64),
    DateTime(ForensicTimestamp),
    /// Variable-length binary data stored inline (≤255 bytes).
    Binary(&'a [u8]),
    /// Variable-length text stored inline (≤255 bytes), raw bytes (encoding
    /// depends on the column's code-page attribute).
    Text(&'a [u8]),
    /// Long binary value reassembled from long-value pages.
    LongBinary(Vec<u8>),
    /// Long text value reassembled from long-value pages.
    LongText(Vec<u8>),
    UnsignedLong(u32),
    LongLong(i64),
    GUID([u8; 16]),
    UnsignedShort(u16),
}

impl<'a> ColumnValue<'a> {
    /// Decode a fixed-size column value from a raw byte slice.
    pub fn from_fixed(coltyp: ColumnType, data: &'a [u8]) -> Option<Self> {
        match coltyp {
            ColumnType::Nil           => Some(ColumnValue::Nil),
            ColumnType::Bit           => data.first().map(|&b| ColumnValue::Bit(b != 0)),
            ColumnType::UnsignedByte  => data.first().map(|&b| ColumnValue::UnsignedByte(b)),
            ColumnType::Short         => data.get(..2).map(|b| ColumnValue::Short(i16::from_le_bytes(b.try_into().unwrap()))),
            ColumnType::Long          => data.get(..4).map(|b| ColumnValue::Long(i32::from_le_bytes(b.try_into().unwrap()))),
            ColumnType::Currency      => data.get(..8).map(|b| ColumnValue::Currency(i64::from_le_bytes(b.try_into().unwrap()))),
            ColumnType::IEEESingle    => data.get(..4).map(|b| ColumnValue::IEEESingle(f32::from_le_bytes(b.try_into().unwrap()))),
            ColumnType::IEEEDouble    => data.get(..8).map(|b| ColumnValue::IEEEDouble(f64::from_le_bytes(b.try_into().unwrap()))),
            // JET_coltypDateTime stores an 8-byte IEEE-754 double: an OLE
            // Automation date (days since 1899-12-30, per the JET/ESE
            // specification) — *not* a raw Win32 FILETIME integer. Verified
            // against `artifacts/sru/SRUDB.dat`: reinterpreting a real
            // AppResourceUsage.TimeStamp value's bit pattern as f64 yields
            // ~44117.84 (≈ 2020-10-29), matching the fixture's known era;
            // reading the same bytes as a raw FILETIME u64 (the pre-existing,
            // and until now unnoticed, decoder bug) yields year 16419. An
            // out-of-range double degrades to `None` (column reads as absent)
            // rather than fabricating an epoch substitute.
            ColumnType::DateTime      => data.get(..8).and_then(|b| {
                let ole_date = f64::from_le_bytes(b.try_into().unwrap());
                ForensicTimestamp::try_from_ole_date(ole_date).ok()
            }).map(ColumnValue::DateTime),
            ColumnType::UnsignedLong  => data.get(..4).map(|b| ColumnValue::UnsignedLong(u32::from_le_bytes(b.try_into().unwrap()))),
            ColumnType::LongLong      => data.get(..8).map(|b| ColumnValue::LongLong(i64::from_le_bytes(b.try_into().unwrap()))),
            ColumnType::GUID          => data.get(..16).map(|b| {
                let mut arr = [0u8; 16];
                arr.copy_from_slice(b);
                ColumnValue::GUID(arr)
            }),
            ColumnType::UnsignedShort => data.get(..2).map(|b| ColumnValue::UnsignedShort(u16::from_le_bytes(b.try_into().unwrap()))),
            _ => None,
        }
    }

    /// Decode an inline variable-length column value.
    pub fn from_variable(coltyp: ColumnType, data: &'a [u8]) -> Self {
        match coltyp {
            ColumnType::Text       => ColumnValue::Text(data),
            ColumnType::Binary     => ColumnValue::Binary(data),
            ColumnType::LongText   => ColumnValue::LongText(data.to_vec()),
            ColumnType::LongBinary => ColumnValue::LongBinary(data.to_vec()),
            _                      => ColumnValue::Binary(data),
        }
    }
}

impl fmt::Display for ColumnValue<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ColumnValue::Nil           => write!(f, "<nil>"),
            ColumnValue::Bit(v)        => write!(f, "{v}"),
            ColumnValue::UnsignedByte(v) => write!(f, "{v}"),
            ColumnValue::Short(v)      => write!(f, "{v}"),
            ColumnValue::Long(v)       => write!(f, "{v}"),
            ColumnValue::Currency(v)   => write!(f, "{v}"),
            ColumnValue::IEEESingle(v) => write!(f, "{v}"),
            ColumnValue::IEEEDouble(v) => write!(f, "{v}"),
            ColumnValue::DateTime(v)   => write!(f, "{v}"),
            ColumnValue::UnsignedLong(v)  => write!(f, "{v}"),
            ColumnValue::LongLong(v)   => write!(f, "{v}"),
            ColumnValue::UnsignedShort(v) => write!(f, "{v}"),
            ColumnValue::GUID(b)       => write!(f, "{}", format_guid(b)),
            ColumnValue::Binary(b)     => write!(f, "{}", bytes_to_hex(b)),
            ColumnValue::Text(b)       => write!(f, "{}", bytes_to_string(b)),
            ColumnValue::LongBinary(b) => write!(f, "{}", bytes_to_hex(b)),
            ColumnValue::LongText(b)   => write!(f, "{}", bytes_to_string(b)),
        }
    }
}

/// Metadata for a single ESE column, typically obtained from the catalog.
#[derive(Debug, Clone)]
pub struct ColumnDef {
    /// Column ID (fixed: 1–127, variable: 128–255, tagged: ≥ 256).
    pub id: u16,
    pub col_type: ColumnType,
    pub name: String,
    /// ESE column flags (cbMax, fNotNull, fVersion, fAutoIncrement, …).
    pub flags: u32,
    /// Code page (relevant for Text / LongText columns; 1200 = UTF-16LE, 1252 = Windows-1252).
    pub codepage: u32,
}

impl ColumnDef {
    pub fn is_fixed(&self) -> bool {
        self.id >= 1 && self.id <= 127
    }
    pub fn is_variable(&self) -> bool {
        self.id >= 128 && self.id <= 255
    }
    pub fn is_tagged(&self) -> bool {
        self.id >= 256
    }
}

/// Schema for one ESE table: its name and an ordered list of column definitions.
#[derive(Debug, Clone)]
pub struct TableSchema {
    pub name: String,
    /// All columns sorted by `id` ascending.
    pub columns: Vec<ColumnDef>,
}

impl TableSchema {
    /// Decode a data record into `(column_name, value)` pairs.
    ///
    /// Pass an `lv_store` to resolve `LongText`/`LongBinary` columns whose
    /// values are stored in the table's long-value B-tree.  Pass `None` when
    /// iterating the catalog itself (MSysObjects has no LV tree).
    ///
    /// Columns not present in this schema are silently skipped.
    /// Fixed columns with IDs beyond `last_fixed_column_id` are returned as `Nil`.
    pub fn decode_record<'a>(
        &self,
        entry: &'a crate::ese::page::entries::table_value::TableValueEntry<'a>,
        lv_store: Option<&crate::ese::lv::LongValueStore>,
    ) -> Vec<(String, ColumnValue<'a>)> {
        let hdr = &entry.header;
        let rec = &entry.data;

        // Step 1: compute the total byte size of fixed-size columns that are
        // present in this record.  We need this to locate the start of
        // variable-size data within `pre_tagged_data`.
        let fixed_data_size: usize = self
            .columns
            .iter()
            .filter(|c| c.is_fixed() && c.id <= hdr.last_fixed_column_id as u16)
            .filter_map(|c| c.col_type.fixed_size())
            .sum();

        let fixed_data = &rec.pre_tagged_data[..fixed_data_size.min(rec.pre_tagged_data.len())];
        let var_data = &rec.pre_tagged_data[fixed_data_size.min(rec.pre_tagged_data.len())..];

        // Pre-compute byte offset of each fixed column within fixed_data.
        let mut fixed_offset = 0usize;
        let mut fixed_offsets: std::collections::HashMap<u16, usize> =
            std::collections::HashMap::new();
        for col in self.columns.iter().filter(|c| c.is_fixed()) {
            fixed_offsets.insert(col.id, fixed_offset);
            if let Some(sz) = col.col_type.fixed_size() {
                fixed_offset += sz;
            }
        }

        // Pre-decode variable column offsets (cumulative from start of var_data).
        let offsets = rec.var_column_offsets;
        let num_var = offsets.len() / 2;

        let mut result = Vec::with_capacity(self.columns.len());

        for col in &self.columns {
            let value = if col.is_fixed() {
                if col.id > hdr.last_fixed_column_id as u16 {
                    ColumnValue::Nil
                } else {
                    let off = match fixed_offsets.get(&col.id) {
                        Some(&o) => o,
                        None => { result.push((col.name.clone(), ColumnValue::Nil)); continue; }
                    };
                    let sz = col.col_type.fixed_size().unwrap_or(0);
                    let end = off + sz;
                    if end > fixed_data.len() {
                        ColumnValue::Nil
                    } else {
                        ColumnValue::from_fixed(col.col_type, &fixed_data[off..end])
                            .unwrap_or(ColumnValue::Nil)
                    }
                }
            } else if col.is_variable() {
                if col.id > hdr.last_variable_column_id as u16 {
                    ColumnValue::Nil
                } else {
                    // Variable column index within the offset array (0-based, col ID 128 = index 0).
                    let idx = (col.id - 128) as usize;
                    if idx >= num_var || offsets.len() < (idx + 1) * 2 {
                        ColumnValue::Nil
                    } else {
                        let raw = u16::from_le_bytes([offsets[idx * 2], offsets[idx * 2 + 1]]);
                        let is_null = (raw & 0x8000) != 0;
                        let end = (raw & 0x7FFF) as usize;
                        let start = if idx == 0 {
                            0
                        } else {
                            let prev_raw = u16::from_le_bytes([
                                offsets[(idx - 1) * 2],
                                offsets[(idx - 1) * 2 + 1],
                            ]);
                            (prev_raw & 0x7FFF) as usize
                        };
                        if !is_null && end > start && end <= var_data.len() {
                            ColumnValue::from_variable(col.col_type, &var_data[start..end])
                        } else {
                            // Inline variable data is absent or out-of-range.  Some ESE
                            // writers store variable-column data in the overflow region
                            // (after variable_data_offset) with a u16 length prefix per
                            // non-null column, ordered by column ID.
                            overflow_var_col(rec.raw_overflow, idx, col.col_type)
                        }
                    }
                }
            } else {
                // Tagged columns (id >= 256).
                match rec.tagged_columns.iter().find(|tc| tc.id == col.id) {
                    Some(tc) => {
                        // If this is a LongText/LongBinary column with a 4-byte LVID
                        // reference, resolve from the LV store when one is available.
                        let is_lv_type = matches!(
                            col.col_type,
                            ColumnType::LongText | ColumnType::LongBinary
                        );
                        if is_lv_type && tc.data.len() == 4 {
                            if let Some(store) = lv_store {
                                let lvid = u32::from_le_bytes([
                                    tc.data[0], tc.data[1], tc.data[2], tc.data[3],
                                ]);
                                match store.get(lvid) {
                                    Some(lv_data) => {
                                        if col.col_type == ColumnType::LongText {
                                            ColumnValue::LongText(lv_data.to_vec())
                                        } else {
                                            ColumnValue::LongBinary(lv_data.to_vec())
                                        }
                                    }
                                    None => ColumnValue::Nil,
                                }
                            } else {
                                ColumnValue::from_variable(col.col_type, tc.data)
                            }
                        } else {
                            ColumnValue::from_variable(col.col_type, tc.data)
                        }
                    }
                    None => ColumnValue::Nil,
                }
            };
            result.push((col.name.clone(), value));
        }
        result
    }
}

// ─── OwnedColumnValue ────────────────────────────────────────────────────────

/// Owned variant of `ColumnValue`, suitable for use in long-lived structures
/// (e.g. `Row`) that outlive any individual page buffer.
#[derive(Debug, Clone)]
pub enum OwnedColumnValue {
    Nil,
    Bit(bool),
    UnsignedByte(u8),
    Short(i16),
    Long(i32),
    Currency(i64),
    IEEESingle(f32),
    IEEEDouble(f64),
    DateTime(ForensicTimestamp),
    Binary(Vec<u8>),
    /// Raw text bytes; use `Display` for a decoded string.
    Text(Vec<u8>),
    LongBinary(Vec<u8>),
    /// Raw long-text bytes; use `Display` for a decoded string.
    LongText(Vec<u8>),
    UnsignedLong(u32),
    LongLong(i64),
    GUID([u8; 16]),
    UnsignedShort(u16),
}

impl<'a> From<ColumnValue<'a>> for OwnedColumnValue {
    fn from(cv: ColumnValue<'a>) -> Self {
        match cv {
            ColumnValue::Nil              => OwnedColumnValue::Nil,
            ColumnValue::Bit(v)           => OwnedColumnValue::Bit(v),
            ColumnValue::UnsignedByte(v)  => OwnedColumnValue::UnsignedByte(v),
            ColumnValue::Short(v)         => OwnedColumnValue::Short(v),
            ColumnValue::Long(v)          => OwnedColumnValue::Long(v),
            ColumnValue::Currency(v)      => OwnedColumnValue::Currency(v),
            ColumnValue::IEEESingle(v)    => OwnedColumnValue::IEEESingle(v),
            ColumnValue::IEEEDouble(v)    => OwnedColumnValue::IEEEDouble(v),
            ColumnValue::DateTime(v)      => OwnedColumnValue::DateTime(v),
            ColumnValue::Binary(b)        => OwnedColumnValue::Binary(b.to_vec()),
            ColumnValue::Text(b)          => OwnedColumnValue::Text(b.to_vec()),
            ColumnValue::LongBinary(v)    => OwnedColumnValue::LongBinary(v),
            ColumnValue::LongText(v)      => OwnedColumnValue::LongText(v),
            ColumnValue::UnsignedLong(v)  => OwnedColumnValue::UnsignedLong(v),
            ColumnValue::LongLong(v)      => OwnedColumnValue::LongLong(v),
            ColumnValue::GUID(b)          => OwnedColumnValue::GUID(b),
            ColumnValue::UnsignedShort(v) => OwnedColumnValue::UnsignedShort(v),
        }
    }
}

impl OwnedColumnValue {
    /// Returns `true` if this value is `Nil`.
    pub fn is_null(&self) -> bool {
        matches!(self, OwnedColumnValue::Nil)
    }

    /// Decode and return text for `Text` or `LongText` variants.
    ///
    /// Returns `None` for all other types.
    pub fn as_string(&self) -> Option<String> {
        match self {
            OwnedColumnValue::Text(b) | OwnedColumnValue::LongText(b) => {
                Some(bytes_to_string(b))
            }
            _ => None,
        }
    }

    /// Coerce any integer variant to `i64`.
    ///
    /// Maps `UnsignedByte`, `Short`, `Long`, `Currency`, `LongLong`,
    /// `UnsignedLong`, `UnsignedShort`, and `Bit` (0/1). Returns `None` for
    /// non-integer types.
    pub fn as_i64(&self) -> Option<i64> {
        match self {
            OwnedColumnValue::Bit(v)          => Some(*v as i64),
            OwnedColumnValue::UnsignedByte(v) => Some(*v as i64),
            OwnedColumnValue::Short(v)        => Some(*v as i64),
            OwnedColumnValue::Long(v)         => Some(*v as i64),
            OwnedColumnValue::Currency(v)     => Some(*v),
            OwnedColumnValue::LongLong(v)     => Some(*v),
            OwnedColumnValue::UnsignedLong(v) => Some(*v as i64),
            OwnedColumnValue::UnsignedShort(v)=> Some(*v as i64),
            _ => None,
        }
    }

    /// Coerce a float variant to `f64`.
    ///
    /// Maps `IEEESingle` and `IEEEDouble`. Returns `None` for other types.
    pub fn as_f64(&self) -> Option<f64> {
        match self {
            OwnedColumnValue::IEEESingle(v) => Some(*v as f64),
            OwnedColumnValue::IEEEDouble(v) => Some(*v),
            _ => None,
        }
    }

    /// Return raw bytes for `Binary` or `LongBinary` variants.
    pub fn as_bytes(&self) -> Option<&[u8]> {
        match self {
            OwnedColumnValue::Binary(b) | OwnedColumnValue::LongBinary(b) => Some(b),
            _ => None,
        }
    }

    /// Return the boolean value of a `Bit` column.
    pub fn as_bool(&self) -> Option<bool> {
        match self {
            OwnedColumnValue::Bit(v) => Some(*v),
            _ => None,
        }
    }

    /// Return the `ForensicTimestamp` from a `DateTime` column.
    pub fn as_datetime(&self) -> Option<ForensicTimestamp> {
        match self {
            OwnedColumnValue::DateTime(v) => Some(*v),
            _ => None,
        }
    }

    /// Return the 16-byte GUID.
    pub fn as_guid(&self) -> Option<[u8; 16]> {
        match self {
            OwnedColumnValue::GUID(b) => Some(*b),
            _ => None,
        }
    }
}

impl fmt::Display for OwnedColumnValue {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            OwnedColumnValue::Nil              => write!(f, "<nil>"),
            OwnedColumnValue::Bit(v)           => write!(f, "{v}"),
            OwnedColumnValue::UnsignedByte(v)  => write!(f, "{v}"),
            OwnedColumnValue::Short(v)         => write!(f, "{v}"),
            OwnedColumnValue::Long(v)          => write!(f, "{v}"),
            OwnedColumnValue::Currency(v)      => write!(f, "{v}"),
            OwnedColumnValue::IEEESingle(v)    => write!(f, "{v}"),
            OwnedColumnValue::IEEEDouble(v)    => write!(f, "{v}"),
            OwnedColumnValue::DateTime(v)      => write!(f, "{v}"),
            OwnedColumnValue::UnsignedLong(v)  => write!(f, "{v}"),
            OwnedColumnValue::LongLong(v)      => write!(f, "{v}"),
            OwnedColumnValue::UnsignedShort(v) => write!(f, "{v}"),
            OwnedColumnValue::GUID(b)          => write!(f, "{}", format_guid(b)),
            OwnedColumnValue::Binary(b)        => write!(f, "{}", bytes_to_hex(b)),
            OwnedColumnValue::Text(b)          => write!(f, "{}", bytes_to_string(b)),
            OwnedColumnValue::LongBinary(b)    => write!(f, "{}", bytes_to_hex(b)),
            OwnedColumnValue::LongText(b)      => write!(f, "{}", bytes_to_string(b)),
        }
    }
}

// ─── Text / binary helpers ───────────────────────────────────────────────────

/// Decode a byte slice as text: UTF-16LE when the data looks like it
/// (>50 % of second bytes in consecutive u16 pairs are zero), otherwise
/// interprets as UTF-8 with lossy replacement.
pub fn bytes_to_string(bytes: &[u8]) -> String {
    if is_likely_utf16le(bytes) {
        let pairs: Vec<u16> = bytes
            .chunks_exact(2)
            .map(|c| u16::from_le_bytes([c[0], c[1]]))
            .collect();
        String::from_utf16_lossy(&pairs)
    } else {
        String::from_utf8_lossy(bytes).into_owned()
    }
}

fn is_likely_utf16le(bytes: &[u8]) -> bool {
    if bytes.len() < 4 || !bytes.len().is_multiple_of(2) {
        return false;
    }
    let zero_second = bytes.chunks_exact(2).filter(|c| c[1] == 0).count();
    zero_second * 2 > bytes.len() / 2 // >50 % of pairs have zero high byte
}

fn bytes_to_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect::<Vec<_>>().join("")
}

fn format_guid(b: &[u8; 16]) -> String {
    format!(
        "{:02x}{:02x}{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-\
         {:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
        b[3], b[2], b[1], b[0],
        b[5], b[4],
        b[7], b[6],
        b[8], b[9],
        b[10], b[11], b[12], b[13], b[14], b[15]
    )
}

/// Decode the `var_idx`-th variable column from the overflow region.
///
/// When variable-column data cannot fit in the inline `pre_tagged_data` region
/// (common in ESE revision 20 databases), each variable column is stored in
/// the overflow/tagged area as a length-prefixed blob: `[len: u16 LE][bytes]`,
/// in column-ID order starting at index 0.
fn overflow_var_col<'a>(overflow: &'a [u8], var_idx: usize, coltyp: ColumnType) -> ColumnValue<'a> {
    let mut pos = 0usize;
    for i in 0..=var_idx {
        if pos + 2 > overflow.len() {
            return ColumnValue::Nil;
        }
        let len = u16::from_le_bytes([overflow[pos], overflow[pos + 1]]) as usize;
        pos += 2;
        if pos + len > overflow.len() {
            return ColumnValue::Nil;
        }
        if i == var_idx {
            if len == 0 {
                return ColumnValue::Nil;
            }
            return ColumnValue::from_variable(coltyp, &overflow[pos..pos + len]);
        }
        pos += len;
    }
    ColumnValue::Nil
}

// ─── Tests ───────────────────────────────────────────────────────────────────
#[cfg(test)]
mod tst {
    use super::ColumnType;

    #[test]
    fn fixed_sizes_are_correct() {
        assert_eq!(Some(0),  ColumnType::Nil.fixed_size());
        assert_eq!(Some(1),  ColumnType::Bit.fixed_size());
        assert_eq!(Some(1),  ColumnType::UnsignedByte.fixed_size());
        assert_eq!(Some(2),  ColumnType::Short.fixed_size());
        assert_eq!(Some(4),  ColumnType::Long.fixed_size());
        assert_eq!(Some(8),  ColumnType::Currency.fixed_size());
        assert_eq!(Some(4),  ColumnType::IEEESingle.fixed_size());
        assert_eq!(Some(8),  ColumnType::IEEEDouble.fixed_size());
        assert_eq!(Some(8),  ColumnType::DateTime.fixed_size());
        assert_eq!(None,     ColumnType::Binary.fixed_size());
        assert_eq!(None,     ColumnType::Text.fixed_size());
        assert_eq!(None,     ColumnType::LongBinary.fixed_size());
        assert_eq!(None,     ColumnType::LongText.fixed_size());
        assert_eq!(Some(4),  ColumnType::UnsignedLong.fixed_size());
        assert_eq!(Some(8),  ColumnType::LongLong.fixed_size());
        assert_eq!(Some(16), ColumnType::GUID.fixed_size());
        assert_eq!(Some(2),  ColumnType::UnsignedShort.fixed_size());
    }

    #[test]
    fn from_u8_roundtrip() {
        for v in [0x00u8, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
                  0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0e, 0x0f, 0x10, 0x11] {
            assert!(ColumnType::from_u8(v).is_some(), "missing {v:#04x}");
        }
        assert!(ColumnType::from_u8(0x0d).is_none()); // SLV reserved
        assert!(ColumnType::from_u8(0xff).is_none());
    }

    #[test]
    fn datetime_column_decodes_as_ole_automation_date_not_filetime() {
        // Real bytes from `artifacts/sru/SRUDB.dat`'s AppResourceUsage
        // TimeStamp column (verified against the fixture directly): the
        // raw 8 bytes, read as an OLE Automation date (the JET/ESE
        // JET_coltypDateTime encoding), decode to 2020-10-13 — plausible
        // for this fixture's known era. Reading the same bytes as a raw
        // Win32 FILETIME integer (the pre-existing bug) produced year 16419.
        let raw: u64 = 4676296323666758133;
        let bytes = raw.to_le_bytes();
        let value = super::ColumnValue::from_fixed(ColumnType::DateTime, &bytes)
            .expect("DateTime column should decode");
        let super::ColumnValue::DateTime(ts) = value else {
            panic!("expected DateTime variant");
        };
        assert_eq!(2020, ts.year());
        assert_eq!(10, ts.month());
        assert_eq!(13, ts.day());
    }

    #[test]
    fn datetime_column_rejects_out_of_range_ole_date() {
        // A bit pattern whose f64 interpretation is out of Timestamp128's
        // representable range must degrade to `None`, not fabricate a
        // clamped/epoch timestamp.
        let bytes = f64::MAX.to_le_bytes();
        assert!(super::ColumnValue::from_fixed(ColumnType::DateTime, &bytes).is_none());
    }
}
