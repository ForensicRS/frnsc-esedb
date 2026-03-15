use forensic_rs::{err::{ForensicError, ForensicResult}, prelude::NotificationType};

use crate::ese::{page::entries::table_value::TableValueEntry, tag::TagData};

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
        if tag_i.data.len() < 6 {
            return Err(ForensicError::bad_format_str(
                "Branch Entry must have 6 or more bytes",
            ));
        }

        let common_key_size = u16::from_le_bytes([data[0], data[1]]);
        let (common_key_size, local_key, entry_data) = if tag_flags & 0x04 > 0 {
            let local_key_size = u16::from_le_bytes([data[2], data[3]]);
            let local_key = &data[4..4 + local_key_size as usize];
            (common_key_size, local_key, &data[4 + local_key_size as usize..])
        } else {
            (0, &data[2..2 + common_key_size as usize], &data[2 + common_key_size as usize..])
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
            let mut entries = Vec::with_capacity(page.tags.len().wrapping_rem(1));
            for i in 1..page.tags.len() {
                let entry = match LeafPageEntry::new(i, page) {
                    Ok(v) => v,
                    Err(e) => {
                        forensic_rs::notify_low!(
                            NotificationType::Informational,
                            "Cannot parse branch entry {i} of page {}: {e}",
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
