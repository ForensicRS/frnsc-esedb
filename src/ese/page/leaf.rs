//! B-tree leaf-page entries: table records, long-value segments, index and
//! space-tree entries.

use forensic_rs::err::{ForensicError, ForensicResult};

use crate::ese::{page::entries::table_value::TableValueEntry, tag::{TagData, TAG_COMMON_KEY}};

use super::{entries::{index::IndexEntry, long_value::LongValueEntry, space_tree::SpaceTreeEntry, PageEntry}, Page};

#[derive(Clone, Debug)]
pub struct LeafPage<'a> {
    pub header : LeafPageHeader<'a>,
    pub entries : Vec<LeafPageEntry<'a>>
}

#[derive(Clone, Debug)]
pub struct LeafPageHeader<'a> {
    pub common_page_key : &'a [u8]
}


#[derive(Clone, Debug)]
pub struct LeafPageEntry<'a> {
    pub common_key_size : u16,
    pub page_key : &'a [u8],
    pub child_page_number : u32,
    pub data : PageEntry<'a>,
}

impl<'a> LeafPageHeader<'a> {
    pub fn new(data: &'a [u8]) -> LeafPageHeader<'a> {
        LeafPageHeader {
            common_page_key: data,
        }
    }
}

impl<'a> LeafPageEntry<'a> {
    pub fn new(tag : usize, page : &'a Page<'_>) -> ForensicResult<LeafPageEntry<'a>> {
        let tag_i = page.get_tag(tag)?;
        let (tag_flags, data) = (tag_i.flags, tag_i.data);

        // Leaf entries have no child page number (unlike branch entries), so
        // the minimum size differs by whether the common-key flag is set:
        // with it, the entry starts with a 2-byte common-key size followed by
        // a 2-byte local-key size (4 bytes minimum); without it, just a
        // 2-byte common-key size (2 bytes minimum).
        let has_common_key = tag_flags & TAG_COMMON_KEY != 0;
        let min_len = if has_common_key { 4 } else { 2 };
        if data.len() < min_len {
            return Err(ForensicError::invalid_format("ESE", 
                "Leaf Entry must have at least 2 (or 4, with a common key) bytes",
            ));
        }

        let (common_key_size, local_key, entry_data) = if has_common_key {
            let common_key_size = u16::from_le_bytes([data[0], data[1]]);
            let local_key_size = u16::from_le_bytes([data[2], data[3]]);
            let local_key_end = (4usize)
                .checked_add(local_key_size as usize)
                .filter(|&end| end <= data.len())
                .ok_or_else(|| ForensicError::invalid_format("ESE", 
                    "Leaf Entry local key size exceeds entry bounds",
                ))?;
            let local_key = &data[4..local_key_end];
            (common_key_size, local_key, &data[local_key_end..])
        } else {
            let common_key_size = u16::from_le_bytes([data[0], data[1]]);
            let key_end = (2usize)
                .checked_add(common_key_size as usize)
                .filter(|&end| end <= data.len())
                .ok_or_else(|| ForensicError::invalid_format("ESE", 
                    "Leaf Entry common key size exceeds entry bounds",
                ))?;
            (0, &data[2..key_end], &data[key_end..])
        };
        let tag_i = TagData {
            data : entry_data,
            flags : tag_flags
        };

        let entry = if page.is_index() {
            LeafPageEntry::index_entry(page, entry_data)?
        } else if page.is_space_tree() {
            LeafPageEntry::space_tree_entry(tag_i)?
        } else if page.is_long_value() {
            LeafPageEntry::long_value_entry(page, tag_i, local_key)?
        } else {
            LeafPageEntry::table_value_entry(page, tag_i)?
        };
        Ok(LeafPageEntry {
            common_key_size,
            page_key : local_key,
            child_page_number : 0,
            data : entry
        })
    }

    pub fn index_entry(_page : &'a Page<'_>, data : &'a [u8]) -> ForensicResult<PageEntry<'a>> {
        Ok(PageEntry::Index(IndexEntry {
            record_page_key: data,
        }))
    }
    pub fn space_tree_entry(tag : TagData<'a>) -> ForensicResult<PageEntry<'a>> {
        Ok(PageEntry::SpaceTree(SpaceTreeEntry::new(tag)?))
    }
    pub fn table_value_entry(page : &'a Page<'_>, tag : TagData<'a>) -> ForensicResult<PageEntry<'a>> {
        Ok(PageEntry::TableValue(TableValueEntry::new(page, tag)?))
    }
    pub fn long_value_entry(_page : &'a Page<'_>, tag : TagData<'a>, page_key: &[u8]) -> ForensicResult<PageEntry<'a>> {
        Ok(PageEntry::LongValue(LongValueEntry::new(tag, page_key)?))
    }

    pub fn leaf_entries(page: &'a Page<'_>) -> ForensicResult<Vec<LeafPageEntry<'a>>> {
        Ok(if page.tags.len() > 1 {
            let mut entries = Vec::with_capacity(page.tags.len().saturating_sub(1));
            for i in 1..page.tags.len() {
                let entry = match LeafPageEntry::new(i, page) {
                    Ok(v) => v,
                    Err(e) => {
                        forensic_rs::debug!(
                            "ESE: cannot parse leaf entry {i} of page {}: {e}",
                            page.page_number
                        );
                        continue;
                    }
                };
                entries.push(entry);
            }
            entries
        } else {
            Vec::new()
        })
    }
}

impl<'a> LeafPage<'a> {
    pub fn new(page: &'a Page<'_>) -> ForensicResult<LeafPage<'a>> {
        let tag_0 = page.get_tag_data(0)?;
        Ok(Self {
            header: LeafPageHeader::new(tag_0),
            entries : LeafPageEntry::leaf_entries(page)?,
        })
    }
}

#[cfg(test)]
mod tst {
    use std::borrow::Cow;
    use crate::ese::tag::Tag;
    use super::*;

    /// Build a dummy page whose tag 1 carries `tag_data` with `tag_flags`.
    /// Tag 0 (the common page key) is present but empty.
    fn make_page(tag_data: &[u8], tag_flags: u8) -> Page<'static> {
        let mut page = Page::dummy();
        let header_size = page.header.header_size as usize;
        let mut buf = vec![0u8; header_size];
        buf.extend_from_slice(tag_data);
        page.data = Cow::Owned(buf);
        page.tags = vec![
            Tag { value_offset: 0, tag_flags: 0, value_size: 0 },
            Tag { value_offset: 0, tag_flags, value_size: tag_data.len() as u16 },
        ];
        page
    }

    #[test]
    fn rejects_short_entry() {
        // A single-byte tag data is too short even for the no-common-key case.
        let page = make_page(&[0x00], 0);
        assert!(LeafPageEntry::new(1, &page).is_err());
    }

    #[test]
    fn oversized_local_key_size_is_rejected_not_panicking() {
        // TAG_COMMON_KEY set (0x04): common_key_size=0, local_key_size=0xFFFF,
        // but the entry itself is only 4 bytes long.
        let data: [u8; 4] = [0x00, 0x00, 0xFF, 0xFF];
        let page = make_page(&data, 0x04);
        let result = LeafPageEntry::new(1, &page);
        assert!(result.is_err(), "oversized local_key_size must error, not panic or overflow");
    }

    #[test]
    fn oversized_common_key_size_no_flag_is_rejected() {
        // No TAG_COMMON_KEY flag: layout is [common_key_size: u16][rest].
        let data: [u8; 2] = [0xFF, 0xFF];
        let page = make_page(&data, 0);
        assert!(LeafPageEntry::new(1, &page).is_err());
    }

    #[test]
    fn exact_fit_entry_parses() {
        // TAG_COMMON_KEY set, local_key_size = 2, followed by exactly 2 bytes
        // of key and nothing else (falls through to table_value_entry, which
        // has its own validation — we only assert this doesn't panic and the
        // key bounds are honoured).
        let data: [u8; 6] = [0x00, 0x00, 0x02, 0x00, 0xAA, 0xBB];
        let page = make_page(&data, 0x04);
        // table_value_entry parsing may still fail on the empty remainder,
        // but it must not panic on the key slicing itself.
        let _ = LeafPageEntry::new(1, &page);
    }
}
