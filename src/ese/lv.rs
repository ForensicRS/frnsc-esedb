//! Long-value reassembly for ESE databases.
//!
//! ESE stores large binary and text column values (LongBinary, LongText) in a
//! dedicated B-tree per table.  Each value is split into one or more segments,
//! keyed by a 4-byte long-value ID (LVID, big-endian) plus an optional 4-byte
//! chunk offset.  `LongValueStore` traverses that B-tree and reassembles each
//! LVID into a contiguous `Vec<u8>`.

use std::collections::HashMap;

use forensic_rs::err::{ForensicError, ForensicResult};

use crate::ese::{
    header::Header,
    page::{
        entries::PageEntry,
        root::RootEntry,
        Page, TreePage,
    },
    reader::PageReader,
};

/// Reassembled long values for one table, keyed by LVID.
pub struct LongValueStore {
    values: HashMap<u32, Vec<u8>>,
}

impl LongValueStore {
    /// Traverse the long-value B-tree rooted at `lv_page` and collect all
    /// long values, reassembling multi-chunk values in offset order.
    pub fn from_db(reader: &dyn PageReader, header: &Header, lv_page: u32) -> ForensicResult<Self> {
        let mut segments: HashMap<u32, Vec<(u32, Vec<u8>)>> = HashMap::new();
        collect_lv_segments(reader, header, lv_page, &mut segments, 0)?;

        // Sort each LVID's segments by offset and concatenate.
        let mut values = HashMap::with_capacity(segments.len());
        for (lvid, mut segs) in segments {
            segs.sort_by_key(|(off, _)| *off);
            let data: Vec<u8> = segs.into_iter().flat_map(|(_, d)| d).collect();
            values.insert(lvid, data);
        }

        Ok(Self { values })
    }

    /// Return the reassembled bytes for `lvid`, or `None` if not found.
    pub fn get(&self, lvid: u32) -> Option<&[u8]> {
        self.values.get(&lvid).map(Vec::as_slice)
    }
}

// ─── Internal: B-tree traversal ─────────────────────────────────────────────

fn collect_lv_segments(
    reader: &dyn PageReader,
    header: &Header,
    page_n: u32,
    out: &mut HashMap<u32, Vec<(u32, Vec<u8>)>>,
    depth: u32,
) -> ForensicResult<()> {
    if depth > 32 {
        return Err(ForensicError::bad_format_str(
            "LV B-tree depth exceeds 32 (cycle?)",
        ));
    }

    let page = load_lv_page(reader, header, page_n)?;

    if !page.valid_page() || page.empty_page() {
        return Ok(());
    }

    match page.process_page()? {
        TreePage::Leaf(leaf) => {
            for entry in &leaf.entries {
                if let PageEntry::LongValue(ref lv) = entry.data {
                    if lv.lvid != 0 || !lv.data.is_empty() {
                        out.entry(lv.lvid)
                            .or_default()
                            .push((lv.segment_offset, lv.data.to_vec()));
                    }
                }
            }
        }
        TreePage::Branch(branch) => {
            for entry in &branch.entries {
                collect_lv_segments(reader, header, entry.child_page_number, out, depth + 1)?;
            }
        }
        TreePage::Root(root) => {
            for entry in &root.entries {
                match entry {
                    RootEntry::Branch(b) => {
                        collect_lv_segments(reader, header, b.child_page_number, out, depth + 1)?
                    }
                    RootEntry::Leaf(leaf_entry) => {
                        if let PageEntry::LongValue(ref lv) = leaf_entry.data {
                            if lv.lvid != 0 || !lv.data.is_empty() {
                                out.entry(lv.lvid)
                                    .or_default()
                                    .push((lv.segment_offset, lv.data.to_vec()));
                            }
                        }
                    }
                }
            }
        }
    }

    Ok(())
}

fn load_lv_page<'r>(reader: &'r dyn PageReader, header: &Header, page_n: u32) -> ForensicResult<Page<'r>> {
    let offset = header.page_to_file_offset(page_n as u64) as usize;
    let size = header.page_size as usize;
    let data = reader.read_page(offset, size)?;
    Page::new(data, page_n, header)
}
