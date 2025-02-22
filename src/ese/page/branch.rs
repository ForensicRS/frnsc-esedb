use forensic_rs::{
    err::{ForensicError, ForensicResult},
    prelude::NotificationType,
};

use super::Page;

#[derive(Clone, Debug)]
pub struct BranchPage<'a> {
    pub header: BranchPageHeader<'a>,
    pub entries: Vec<BranchPageEntry<'a>>,
}

#[derive(Clone, Debug)]
pub struct BranchPageHeader<'a> {
    pub common_page_key: &'a [u8],
}

#[derive(Clone, Debug)]
pub struct BranchPageEntry<'a> {
    pub page_key_size: u16,
    pub page_key: &'a [u8],
    pub child_page_number: u32,
}

impl<'a> BranchPageHeader<'a> {
    pub fn new(data: &'a [u8]) -> BranchPageHeader<'a> {
        BranchPageHeader {
            common_page_key: data,
        }
    }
}

impl<'a> BranchPageEntry<'a> {
    pub fn new(data: &'a [u8]) -> ForensicResult<BranchPageEntry<'a>> {
        if data.len() < 6 {
            return Err(ForensicError::bad_format_str(
                "Branch Entry must have 6 or more bytes",
            ));
        }

        let page_key_size = u16::from_le_bytes([data[0], data[1]]);
        if data.len() < (6 + page_key_size) as usize {
            return Err(ForensicError::bad_format_str(
                "Branch Entry size does not correspond with expected",
            ));
        }
        let page_key = &data[2..2 + page_key_size as usize];
        let child_page_number = u32::from_le_bytes(data[2 + page_key_size as usize..6 + page_key_size as usize].try_into().unwrap_or_default());
        Ok(BranchPageEntry {
            page_key_size,
            page_key,
            child_page_number,
        })
    }

    pub fn branch_entries(page: &'a Page) -> ForensicResult<Vec<BranchPageEntry<'a>>> {
        Ok(if page.tags.len() > 1 {
            let mut entries = Vec::with_capacity(page.tags.len().wrapping_rem(1));
            for i in 1..page.tags.len() {
                let tag = match page.get_tag_data(i) {
                    Ok(v) => v,
                    Err(e) => {
                        forensic_rs::notify_low!(
                            NotificationType::Informational,
                            "Cannot get tag {i} of page {}: {e}",
                            page.page_number
                        );
                        continue;
                    }
                };
                let entry = match BranchPageEntry::new(tag) {
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

impl<'a> BranchPage<'a> {
    pub fn new(page: &'a Page) -> ForensicResult<BranchPage<'a>> {
        let tag_0 = page.get_tag_data(0)?;
        Ok(Self {
            header: BranchPageHeader::new(tag_0),
            entries : BranchPageEntry::branch_entries(&page)?,
        })
    }
}
