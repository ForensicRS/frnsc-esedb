//! Long-value reassembly for ESE databases.
//!
//! ESE stores large binary and text column values (LongBinary, LongText) in a
//! dedicated B-tree per table.  Each value is split into one or more segments,
//! keyed by a 4-byte long-value ID (LVID, big-endian) plus an optional 4-byte
//! chunk offset.  `LongValueStore` traverses that B-tree and reassembles each
//! LVID into a contiguous `Vec<u8>`.

use std::collections::HashMap;

use forensic_rs::err::ForensicResult;

use crate::ese::{header::Header, page::entries::PageEntry, reader::PageReader, tree};

/// Reassembled long values for one table, keyed by LVID.
pub struct LongValueStore {
    values: HashMap<u32, Vec<u8>>,
}

impl LongValueStore {
    /// Traverse the long-value B-tree rooted at `lv_page` and collect all
    /// long values, reassembling multi-chunk values in offset order.
    ///
    /// A gap or overlap between a value's segments (an offset that doesn't
    /// pick up exactly where the previous segment left off) stops
    /// reassembly at the discontinuity rather than silently concatenating
    /// across it — a silently-stitched value would misrepresent evidence
    /// that was actually incomplete or corrupted.
    pub fn from_db(reader: &dyn PageReader, header: &Header, lv_page: u32) -> ForensicResult<Self> {
        let mut segments: HashMap<u32, Vec<(u32, Vec<u8>)>> = HashMap::new();
        tree::visit_leaves(reader, header, lv_page, |entry| {
            if let PageEntry::LongValue(lv) = entry {
                if lv.lvid != 0 || !lv.data.is_empty() {
                    segments
                        .entry(lv.lvid)
                        .or_default()
                        .push((lv.segment_offset, lv.data.to_vec()));
                }
            }
        })?;

        // Sort each LVID's segments by offset and concatenate, stopping at
        // the first gap or overlap.
        let mut values = HashMap::with_capacity(segments.len());
        for (lvid, mut segs) in segments {
            segs.sort_by_key(|(off, _)| *off);
            let mut data = Vec::new();
            for (off, seg) in segs {
                if off as usize != data.len() {
                    forensic_rs::warn!(
                        "ESE: long value {lvid:#x} has a segment gap/overlap at offset {off} (expected {}); value truncated",
                        data.len()
                    );
                    break;
                }
                data.extend_from_slice(&seg);
            }
            values.insert(lvid, data);
        }

        Ok(Self { values })
    }

    /// Return the reassembled bytes for `lvid`, or `None` if not found.
    pub fn get(&self, lvid: u32) -> Option<&[u8]> {
        self.values.get(&lvid).map(Vec::as_slice)
    }
}
