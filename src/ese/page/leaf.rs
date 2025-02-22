use forensic_rs::{err::{ForensicError, ForensicResult}, prelude::NotificationType};

use super::{branch::BranchPageEntry, entries::{index::IndexEntry, space_tree::SpaceTreeEntry, PageEntry}, Page};

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
    pub page_key_size : u16,
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
    pub fn new(tag : usize, page : &'a Page) -> ForensicResult<LeafPageEntry<'a>> {
        let (tag_i, data) = page.get_tag(tag)?;
        if data.len() < 6 {
            return Err(ForensicError::bad_format_str(
                "Branch Entry must have 6 or more bytes",
            ));
        }

        let page_key_size = u16::from_le_bytes([data[0], data[1]]) as usize;
        if data.len() < (6 + page_key_size){
            return Err(ForensicError::bad_format_str(
                "Branch Entry size does not correspond with expected",
            ));
        }
        let page_key = &data[2..2 + page_key_size];
        let child_page_number = u32::from_le_bytes(data[2 + page_key_size..6 + page_key_size].try_into().unwrap_or_default());
        let entry_data = &data[6 + page_key_size..];
        let entry = if page.is_index() {
            LeafPageEntry::index_entry(page, entry_data)?
        } else if page.is_space_tree() {
            LeafPageEntry::space_tree_entry(tag_i.tag_flags, entry_data)?
        } else {
            LeafPageEntry::table_value_entry(page, entry_data)?
        };
        Ok(LeafPageEntry {
            page_key_size : page_key_size as u16,
            page_key,
            child_page_number,
            data : entry
        })
    }

    pub fn index_entry(_page : &'a Page, data : &'a [u8]) -> ForensicResult<PageEntry<'a>> {
        Ok(PageEntry::Index(IndexEntry {
            record_page_key: data,
        }))
    }
    pub fn space_tree_entry(tag_flags : u8, data : &'a [u8]) -> ForensicResult<PageEntry<'a>> {
        Ok(PageEntry::SpaceTree(SpaceTreeEntry::new(tag_flags, data)?))
    }
    pub fn table_value_entry(page : &'a Page, data : &'a [u8]) -> ForensicResult<PageEntry<'a>> {
        Ok(PageEntry::TableValue)
    }

    pub fn leaf_entries(page: &'a Page) -> ForensicResult<Vec<LeafPageEntry<'a>>> {
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
    pub fn new(page: &'a Page) -> ForensicResult<LeafPage<'a>> {
        let tag_0 = page.get_tag_data(0)?;
        Ok(Self {
            header: LeafPageHeader::new(tag_0),
            entries : LeafPageEntry::leaf_entries(&page)?,
        })
    }
}
