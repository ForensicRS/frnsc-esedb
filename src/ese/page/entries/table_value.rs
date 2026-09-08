use forensic_rs::err::{ForensicError, ForensicResult};

use crate::ese::{page::Page, tag::TagData};

/// Parsed data record from an ESE leaf page.
#[derive(Debug, Clone)]
pub struct TableValueEntry<'a> {
    pub header: RecordHeader,
    pub data: RecordData<'a>,
}

/// First four bytes of every ESE data record.
#[derive(Debug, Clone)]
pub struct RecordHeader {
    /// Highest fixed-column ID present in this record (0 = none).
    pub last_fixed_column_id: u8,
    /// Highest variable-column ID present (IDs start at 128; 127 means none).
    pub last_variable_column_id: u8,
    /// Byte offset from the record start to the START of tagged-column data.
    /// Equivalently, the end of all variable data (including the offset array).
    pub variable_data_offset: u16,
}

/// Raw byte regions of an ESE data record.
///
/// ESE record layout:
/// ```text
/// [0]      last_fixed_column_id
/// [1]      last_variable_column_id  (128 = first var col id; 127 = no var cols)
/// [2-3]    variable_data_offset     (LE u16; byte offset to start of tagged data)
/// [4 ..    variable_data_offset - num_var*2]  → pre_tagged_data
///          (contains fixed-size data then variable-size data; schema needed to split)
/// [variable_data_offset - num_var*2 ..
///          variable_data_offset]              → var_column_offsets
///          (num_var × u16 LE, cumulative byte offsets from start of variable data)
/// [variable_data_offset ..]                  → tagged data (and/or variable overflow)
/// ```
///
/// Use `TableSchema::decode_record` for schema-aware decoding.
#[derive(Debug, Clone)]
pub struct RecordData<'a> {
    /// Combined fixed + variable bytes (schema needed to split at `fixed_data_size`).
    pub pre_tagged_data: &'a [u8],
    /// Variable-column offset array (num_var × u16 LE, cumulative).
    pub var_column_offsets: &'a [u8],
    /// Tagged column entries (decoded descriptors; see `TaggedColumn`).
    pub tagged_columns: Vec<TaggedColumn<'a>>,
    /// Raw bytes at `variable_data_offset` through end of record.  Used to
    /// extract variable-column overflow data when the inline variable region
    /// is empty (some ESE writers store variable data here with a u16
    /// length-prefix per column rather than in the pre_tagged region).
    pub raw_overflow: &'a [u8],
}

/// One tagged column value decoded from the tagged descriptor array.
#[derive(Debug, Clone)]
pub struct TaggedColumn<'a> {
    /// Column identifier (≥ 256).
    pub id: u16,
    /// ESE tagged-column flags (bit 0 = multi-value, bit 1 = long-value).
    pub flags: u8,
    /// Raw column bytes.
    pub data: &'a [u8],
}

impl<'a> TableValueEntry<'a> {
    /// Parse a tagged-page data record.
    pub fn new(_page: &'a Page<'_>, tag: TagData<'a>) -> ForensicResult<TableValueEntry<'a>> {
        let data = tag.data;
        if data.len() < 4 {
            return Err(ForensicError::invalid_format("ESE", 
                "TableValueEntry must be at least 4 bytes",
            ));
        }

        let last_fixed_column_id = data[0];
        let last_variable_column_id = data[1];
        let variable_data_offset = u16::from_le_bytes([data[2], data[3]]) as usize;

        let header = RecordHeader {
            last_fixed_column_id,
            last_variable_column_id,
            variable_data_offset: variable_data_offset as u16,
        };

        // Number of variable-size columns present.
        let num_var: usize = if last_variable_column_id >= 128 {
            (last_variable_column_id - 127) as usize
        } else {
            0
        };

        // The variable offset array occupies the `num_var * 2` bytes immediately
        // before `variable_data_offset` in the record.
        let var_offsets_start = variable_data_offset.saturating_sub(num_var * 2);

        if variable_data_offset > data.len() {
            return Err(ForensicError::invalid_format("ESE", 
                "TableValueEntry: variable_data_offset exceeds record length",
            ));
        }

        // Everything from byte 4 up to (but not including) the offset array is
        // the combined fixed + variable data that only the schema can split.
        let pre_tagged_start = 4usize;
        let pre_tagged_end = var_offsets_start.max(pre_tagged_start).min(data.len());
        let pre_tagged_data = &data[pre_tagged_start..pre_tagged_end];

        let var_column_offsets = &data[var_offsets_start.min(data.len())..variable_data_offset.min(data.len())];

        let raw_overflow = if variable_data_offset < data.len() {
            &data[variable_data_offset..]
        } else {
            &data[..0]
        };

        let tagged_columns = if variable_data_offset < data.len() {
            Self::parse_tagged_columns(&data[variable_data_offset..])
        } else {
            Vec::new()
        };

        Ok(TableValueEntry {
            header,
            data: RecordData {
                pre_tagged_data,
                var_column_offsets,
                tagged_columns,
                raw_overflow,
            },
        })
    }

    /// Parse the tagged-column descriptor block.
    ///
    /// The first descriptor's data-offset field (bits 13:0) equals the total
    /// number of descriptors × 4, which is how we derive the count.
    fn parse_tagged_columns(block: &'a [u8]) -> Vec<TaggedColumn<'a>> {
        if block.len() < 4 {
            return Vec::new();
        }
        // Number of descriptors derived from the first descriptor's offset field.
        let first_offset_raw = u16::from_le_bytes([block[2], block[3]]);
        let num_tags = ((first_offset_raw & 0x3FFF) as usize) / 4;
        if num_tags == 0 || num_tags * 4 > block.len() {
            return Vec::new();
        }
        let mut cols = Vec::with_capacity(num_tags);
        for i in 0..num_tags {
            let base = i * 4;
            if base + 4 > block.len() {
                break;
            }
            let col_id = u16::from_le_bytes([block[base], block[base + 1]]);
            let off_raw = u16::from_le_bytes([block[base + 2], block[base + 3]]);
            // High 2 bits are flags; low 14 bits are the data offset within the block.
            let flags = (off_raw >> 14) as u8;
            let data_offset = (off_raw & 0x3FFF) as usize;

            let data_end = if i + 1 < num_tags {
                let next_off_raw = u16::from_le_bytes([block[(i + 1) * 4 + 2], block[(i + 1) * 4 + 3]]);
                (next_off_raw & 0x3FFF) as usize
            } else {
                block.len()
            };

            let col_data = if data_offset < data_end && data_end <= block.len() {
                &block[data_offset..data_end]
            } else {
                &block[..0]
            };

            cols.push(TaggedColumn {
                id: col_id,
                flags,
                data: col_data,
            });
        }
        cols
    }
}

#[cfg(test)]
mod tst {
    use super::*;
    use crate::ese::tag::TagData;

    fn make_tag(data: &[u8]) -> TagData<'_> {
        TagData { data, flags: 0x04 }
    }

    /// Minimal record: one fixed column (4 bytes), no variable, no tagged.
    /// last_fixed_column_id = 1, last_variable_column_id = 127 (none),
    /// variable_data_offset = 8, pre_tagged_data = [0xAB, 0xCD, 0xEF, 0x01]
    #[test]
    fn parse_minimal_record() {
        let data: &[u8] = &[0x01, 0x7F, 0x08, 0x00, 0xAB, 0xCD, 0xEF, 0x01];
        let tag = make_tag(data);
        let page = crate::ese::page::Page::dummy();
        let entry = TableValueEntry::new(&page, tag).unwrap();
        assert_eq!(1, entry.header.last_fixed_column_id);
        assert_eq!(127, entry.header.last_variable_column_id);
        assert_eq!(8, entry.header.variable_data_offset);
        assert_eq!(&[0xAB, 0xCD, 0xEF, 0x01], entry.data.pre_tagged_data);
        assert!(entry.data.var_column_offsets.is_empty());
        assert!(entry.data.tagged_columns.is_empty());
    }

    /// Record with one variable column (id 128) containing bytes [0x01, 0x02].
    /// Layout:
    ///   last_fixed = 0, last_var = 128 → num_var = 1
    ///   variable_data_offset = 8 (start of tagged / end of var region)
    ///   offset array at [6..8] = [0x02,0x00] → end_offset = 2 (relative to var data start)
    ///   pre_tagged_data = data[4..6] = [0x01, 0x02]  (no fixed; var data only)
    ///   var_data_start = 0 (within pre_tagged_data, since no fixed cols)
    ///   column 128 data = pre_tagged_data[0..2] = [0x01, 0x02]
    #[test]
    fn parse_variable_column() {
        let data: &[u8] = &[0x00, 0x80, 0x08, 0x00, 0x01, 0x02, 0x02, 0x00];
        let tag = make_tag(data);
        let page = crate::ese::page::Page::dummy();
        let entry = TableValueEntry::new(&page, tag).unwrap();
        // Offset array = [0x02, 0x00]
        assert_eq!(&[0x02, 0x00], entry.data.var_column_offsets);
        // pre_tagged_data = [0x01, 0x02]
        assert_eq!(&[0x01, 0x02], entry.data.pre_tagged_data);
        assert!(entry.data.tagged_columns.is_empty());
    }
}
