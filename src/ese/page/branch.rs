//! B-tree branch (interior) page entries.

use forensic_rs::err::{ForensicError, ForensicResult};

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
            return Err(ForensicError::invalid_format("ESE", 
                "Branch Entry must have 6 or more bytes",
            ));
        }

        let page_key_size = u16::from_le_bytes([data[0], data[1]]);
        // Widen to `usize` *before* adding: `6 + page_key_size` as a `u16` sum
        // overflows for any `page_key_size >= 65530`, which would wrap the
        // bounds check instead of failing it and let the slices below panic.
        let required = 6usize.checked_add(page_key_size as usize).ok_or_else(|| {
            ForensicError::invalid_format("ESE", "Branch Entry size overflow")
        })?;
        if data.len() < required {
            return Err(ForensicError::invalid_format("ESE", 
                "Branch Entry size does not correspond with expected",
            ));
        }
        let page_key = &data[2..2 + page_key_size as usize];
        let child_page_number = u32::from_le_bytes(
            data[2 + page_key_size as usize..6 + page_key_size as usize]
                .try_into()
                .map_err(|_| ForensicError::invalid_format("ESE", "Branch Entry child page number out of bounds"))?,
        );
        Ok(BranchPageEntry {
            page_key_size,
            page_key,
            child_page_number,
        })
    }

    pub fn branch_entries(page: &'a Page<'_>) -> ForensicResult<Vec<BranchPageEntry<'a>>> {
        Ok(if page.tags.len() > 1 {
            let mut entries = Vec::with_capacity(page.tags.len().saturating_sub(1));
            for i in 1..page.tags.len() {
                let tag = match page.get_tag_data(i) {
                    Ok(v) => v,
                    Err(e) => {
                        forensic_rs::debug!(
                            "ESE: cannot get tag {i} of page {}: {e}",
                            page.page_number
                        );
                        continue;
                    }
                };
                let entry = match BranchPageEntry::new(tag) {
                    Ok(v) => v,
                    Err(e) => {
                        forensic_rs::debug!(
                            "ESE: cannot parse branch entry {i} of page {}: {e}",
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
    pub fn new(page: &'a Page<'_>) -> ForensicResult<BranchPage<'a>> {
        let tag_0 = page.get_tag_data(0)?;
        Ok(Self {
            header: BranchPageHeader::new(tag_0),
            entries: BranchPageEntry::branch_entries(page)?,
        })
    }
}

#[cfg(test)]
mod tst {
    use super::*;

    #[test]
    fn rejects_short_entry() {
        assert!(BranchPageEntry::new(&[0, 0, 0]).is_err());
    }

    #[test]
    fn key_size_65535_does_not_overflow_or_panic() {
        // page_key_size = 0xFFFF: `6 + 0xFFFF` overflows a u16 sum, which used
        // to wrap and defeat the bounds check. Must error cleanly instead.
        let data = [0xFFu8, 0xFF, 0, 0, 0, 0];
        let result = BranchPageEntry::new(&data);
        assert!(result.is_err());
    }

    #[test]
    fn exact_fit_entry_parses() {
        // page_key_size = 2, key = [0xAA, 0xBB], child_page_number = 7.
        let data = [2u8, 0, 0xAA, 0xBB, 7, 0, 0, 0];
        let entry = BranchPageEntry::new(&data).expect("exact-fit entry should parse");
        assert_eq!(2, entry.page_key_size);
        assert_eq!(&[0xAA, 0xBB], entry.page_key);
        assert_eq!(7, entry.child_page_number);
    }
}
