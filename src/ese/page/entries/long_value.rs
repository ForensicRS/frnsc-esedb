use forensic_rs::err::ForensicResult;

use crate::ese::tag::TagData;

/// One segment of a long-value record from an ESE long-value page.
///
/// In the long-value B-tree each leaf entry has:
///   - A key composed of a 4-byte long-value ID (LVID, big-endian) concatenated with an
///     optional 4-byte chunk offset (big-endian).  The key is stored in the `page_key`
///     field of the owning `LeafPageEntry`.
///   - The raw data bytes for this segment.
///
/// Callers that need to reassemble a multi-chunk long value must collect all
/// `LongValueEntry` items with the same LVID and concatenate their `data`
/// slices in ascending `segment_offset` order.
#[derive(Clone, Debug)]
pub struct LongValueEntry<'a> {
    /// Long-value identifier, derived from the first 4 bytes of the page key.
    pub lvid: u32,
    /// Raw segment data bytes.
    pub data: &'a [u8],
    /// Byte offset of this segment within the full long value.
    /// 0 for single-segment values or the first segment of multi-chunk values.
    pub segment_offset: u32,
}

impl<'a> LongValueEntry<'a> {
    /// Parse a long-value leaf tag, extracting LVID and segment offset from
    /// the entry's `page_key` (first 4 bytes = LVID, next 4 bytes = offset).
    pub fn new(tag: TagData<'a>, page_key: &[u8]) -> ForensicResult<Self> {
        let lvid = if page_key.len() >= 4 {
            u32::from_be_bytes([page_key[0], page_key[1], page_key[2], page_key[3]])
        } else {
            0
        };
        let segment_offset = if page_key.len() >= 8 {
            u32::from_be_bytes([page_key[4], page_key[5], page_key[6], page_key[7]])
        } else {
            0
        };
        Ok(Self {
            lvid,
            data: tag.data,
            segment_offset,
        })
    }
}

#[cfg(test)]
mod tst {
    use super::*;

    #[test]
    fn parse_lv_segment_single_chunk() {
        let payload = [0xDE, 0xAD, 0xBE, 0xEF];
        let tag = TagData { data: &payload, flags: 0 };
        let key = [0x00, 0x00, 0x00, 0x2A]; // LVID = 42
        let lv = LongValueEntry::new(tag, &key).unwrap();
        assert_eq!(42, lv.lvid);
        assert_eq!(0, lv.segment_offset);
        assert_eq!(&[0xDE, 0xAD, 0xBE, 0xEF], lv.data);
    }

    #[test]
    fn parse_lv_segment_multi_chunk() {
        let payload = [0x01, 0x02];
        let tag = TagData { data: &payload, flags: 0 };
        // LVID = 1, offset = 256
        let key = [0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x01, 0x00];
        let lv = LongValueEntry::new(tag, &key).unwrap();
        assert_eq!(1, lv.lvid);
        assert_eq!(256, lv.segment_offset);
        assert_eq!(&[0x01, 0x02], lv.data);
    }

    #[test]
    fn parse_empty_lv_segment() {
        let tag = TagData { data: &[], flags: 0 };
        let lv = LongValueEntry::new(tag, &[]).unwrap();
        assert!(lv.data.is_empty());
        assert_eq!(0, lv.lvid);
        assert_eq!(0, lv.segment_offset);
    }
}
