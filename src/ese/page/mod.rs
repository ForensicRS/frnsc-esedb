use std::borrow::Cow;

use branch::BranchPage;
use forensic_rs::err::{ForensicError, ForensicResult};
use leaf::LeafPage;
use root::RootPage;

use super::{header::Header, tag::{Tag, TagData, TagReader}};

pub mod root;
pub mod branch;
pub mod leaf;
pub mod entries;

pub const ROOT_PAGE_FLAG : u32 = 0x00000001;
pub const LEAF_PAGE_FLAG : u32 = 0x00000002;
pub const PARENT_PAGE_FLAG : u32 = 0x00000004;
pub const EMPTY_PAGE_FLAG : u32 = 0x00000008;
pub const SPACE_TREE_PAGE_FLAG : u32 = 0x00000020;
pub const INDEX_PAGE_FLAG : u32 = 0x00000040;
pub const LONG_VALUE_PAGE_FLAG : u32 = 0x00000080;
pub const PRIMARY_PAGE_FLAG : u32 = 0x000800;
pub const ERASED_PAGE_FLAG : u32 = 0x00004000;
pub const REPAIRED_PAGE_FLAG : u32 = 0x200000;


#[derive(Clone, Debug)]
pub enum TreePage<'a> {
    Root(RootPage<'a>),
    Branch(BranchPage<'a>),
    Leaf(LeafPage<'a>)
}

/// True for the two "large" ESE page sizes (16 KiB / 32 KiB) that carry the
/// Win7 extended page-header checksum. The page sizes here are the real ESE
/// values (16 384 / 32 768) — a prior version of this check compared against
/// 16 000 / 32 000, which made the extended-header branch permanently dead.
fn page_size_is_large(len: usize) -> bool {
    len == 16_384 || len == 32_768
}

#[derive(Clone, Debug)]
pub enum PageFlag {
    Root,
    Leaf,
    Parent,
    Empty,
    SpaceTree,
    Index,
    LongValue
}

#[repr(C, packed)]
pub struct PageHeaderExchange2003Repr {
    pub xor : u32,
    pub page_number : u32,
    pub last_modification_time : u64,
    pub previous_page_number : u32,
    pub next_page_number : u32,
    pub father_data_page_id : u32,
    pub available_data_size : u16,
    pub available_uncommited_data_size : u16,
    pub available_data_offset : u16,
    pub available_page_tag : u16,
    pub page_flags : u32
}
#[derive(Clone, Debug)]
pub struct PageChecksumExchange2003 {
    pub xor : u32,
    pub page_number : u32
}

#[repr(C, packed)]
pub struct PageHeaderWinVistaRepr {
    pub xor_checksum : u32,
    pub ecc_checksum : u32,
    pub last_modification_time : u64,
    pub previous_page_number : u32,
    pub next_page_number : u32,
    pub father_data_page_id : u32,
    pub available_data_size : u16,
    pub available_uncommited_data_size : u16,
    pub available_data_offset : u16,
    pub available_page_tag : u16,
    pub page_flags : u32
}
#[derive(Clone, Debug)]
pub struct PageChecksumWinVista {
    pub xor_checksum : u32,
    pub ecc_checksum : u32
}
#[repr(C, packed)]
pub struct PageHeaderWin7ExtRepr {
    pub checksum : u64,
    pub last_modification_time : u64,
    pub previous_page_number : u32,
    pub next_page_number : u32,
    pub father_data_page_id : u32,
    pub available_data_size : u16,
    pub available_uncommited_data_size : u16,
    pub available_data_offset : u16,
    pub available_page_tag : u16,
    pub page_flags : u32,
    pub ext_checksum1 : u64,
    pub ext_checksum2 : u64,
    pub ext_checksum3 : u64,
    pub page_number : u64,
    pub unknown : u64
}

#[derive(Clone, Debug)]
pub struct PageChecksumWin7 {
    pub checksum : u64
}

#[repr(C, packed)]
pub struct PageHeaderRepr {
    pub checksum : u64,
    pub last_modification_time : u64,
    pub previous_page_number : u32,
    pub next_page_number : u32,
    pub father_data_page_id : u32,
    pub available_data_size : u16,
    pub available_uncommited_data_size : u16,
    pub available_data_offset : u16,
    pub available_page_tag : u16,
    pub page_flags : u32
}
#[derive(Clone, Debug)]
pub enum PageChecksum {
    Exchange2003(PageChecksumExchange2003),
    WinVista(PageChecksumWinVista),
    Win7(PageChecksumWin7)
}

impl<'a> TryFrom<&'a PageChecksum> for &'a PageChecksumWin7 {
    type Error = ForensicError;

    fn try_from(value: &'a PageChecksum) -> Result<Self, Self::Error> {
        match value {
            PageChecksum::Win7(v) => Ok(v),
            _ => Err(ForensicError::invalid_format("ESE", "Not a Win7 checksum"))
        }
    }
}

impl<'a> TryFrom<&'a PageChecksum> for &'a PageChecksumExchange2003 {
    type Error = ForensicError;

    fn try_from(value: &'a PageChecksum) -> Result<Self, Self::Error> {
        match value {
            PageChecksum::Exchange2003(v) => Ok(v),
            _ => Err(ForensicError::invalid_format("ESE", "Not a Exchange2003 checksum"))
        }
    }
}
impl<'a> TryFrom<&'a PageChecksum> for &'a PageChecksumWinVista {
    type Error = ForensicError;

    fn try_from(value: &'a PageChecksum) -> Result<Self, Self::Error> {
        match value {
            PageChecksum::WinVista(v) => Ok(v),
            _ => Err(ForensicError::invalid_format("ESE", "Not a WinVista checksum"))
        }
    }
}
#[derive(Clone, Debug)]
pub enum PageExtension {
    Win7(PageExtensionWin7)
}
#[derive(Clone, Debug)]
pub struct PageExtensionWin7 {
    pub ext_checksum1 : u64,
    pub ext_checksum2 : u64,
    pub ext_checksum3 : u64,
    pub page_number : u64,
    pub unknown : u64
}

#[derive(Clone, Debug)]
pub struct PageHeader {
    pub checksum : PageChecksum,
    pub last_modification_time : u64,
    pub previous_page_number : u32,
    pub next_page_number : u32,
    pub father_data_page_id : u32,
    pub available_data_size : u16,
    pub available_uncommited_data_size : u16,
    pub available_data_offset : u16,
    pub available_page_tag : u16,
    pub page_flags : u32,
    pub extension : Option<PageExtension>,
    pub header_size : u32,
    version : u32,
    revision : u32
}

impl From<&PageHeaderRepr> for PageHeader {
    fn from(value: &PageHeaderRepr) -> Self {
        Self {
            checksum: PageChecksum::Win7(PageChecksumWin7 {
                checksum : value.checksum
            }),
            last_modification_time: value.last_modification_time,
            previous_page_number: value.previous_page_number,
            next_page_number: value.next_page_number,
            father_data_page_id: value.father_data_page_id,
            available_data_size: value.available_data_size,
            available_uncommited_data_size: value.available_uncommited_data_size,
            available_data_offset: value.available_data_offset,
            available_page_tag: value.available_page_tag,
            page_flags: value.page_flags,
            extension: None,
            header_size : 40,
            version : 0,
            revision : 0
        }
    }
}


impl PageHeader {
    pub fn from_buff(buffer : &[u8], version : u32, revision : u32) -> ForensicResult<PageHeader> {
        forensic_rs::ensure_min_length!(std::mem::size_of::<PageHeaderRepr>(), buffer.len(), "ESE page header");
        // SAFETY: `PageHeaderRepr` is `#[repr(C, packed)]` (alignment 1) and
        // every field is a plain integer — any bit pattern is valid, so
        // `align_to` cannot produce an invalid value. Alignment 1 also means
        // `head` is always empty; the length check above (not
        // `head.is_empty()`, which is always true) is what actually matters.
        let (head, data, _tail) = unsafe { buffer.align_to::<PageHeaderRepr>() };
        if !head.is_empty() || data.is_empty() {
            return Err(forensic_rs::err::ForensicError::invalid_format("ESE", "Invalid alignement"));
        }
        let mut page : PageHeader = (&data[0]).into();
        page.version = version;
        page.revision = revision;
        // 0x620, not 0x602 — verified against the real ESE version field
        // (`artifacts/sru/SRUDB.dat` bytes 8..12 = `20 06 00 00`). The typo
        // meant this entire checksum/extension-refinement block was dead for
        // every real database; every bug below was consequently unreachable
        // until this was corrected, so both must land together.
        if version == 0x620 {
            if revision < 0x0000000b {
                // Before Exchange 2003 SP1 and Windows Vista
                page.checksum = PageChecksum::Exchange2003(PageChecksumExchange2003 {
                    xor : u32::from_le_bytes(buffer[0..4].try_into().unwrap_or_default()),
                    page_number : u32::from_le_bytes(buffer[4..8].try_into().unwrap_or_default())
                });
            } else if revision < 0x00000011 {
                // Exchange 2003 SP1 and Windows Vista and later
                page.checksum = PageChecksum::WinVista(PageChecksumWinVista {
                    xor_checksum : u32::from_le_bytes(buffer[0..4].try_into().unwrap_or_default()),
                    ecc_checksum : u32::from_le_bytes(buffer[4..8].try_into().unwrap_or_default())
                });
            }else if revision >= 0x00000011 {
                // Exchange 2003 SP1 and Windows Vista and later
                page.checksum = PageChecksum::Win7(PageChecksumWin7 {
                    checksum : u64::from_le_bytes(buffer[0..8].try_into().unwrap_or_default())
                });
                // The Win7 extended header lives at bytes [40..80] of the
                // page itself, immediately after the 40-byte base header —
                // *not* in whatever bytes `align_to` leaves over as `tail`
                // (which is the very end of the whole page buffer and, for
                // the previous buggy size check, was usually empty). Gated
                // on page size and revision, matching libesedb's model,
                // rather than the page's exact byte length.
                if buffer.len() >= 80 && (page_size_is_large(buffer.len()) ) && revision >= 0x00000011 {
                    let ext = &buffer[40..80];
                    page.extension = Some(PageExtension::Win7(PageExtensionWin7 {
                        ext_checksum1 : u64::from_le_bytes(ext[0..8].try_into().unwrap_or_default()),
                        ext_checksum2 : u64::from_le_bytes(ext[8..16].try_into().unwrap_or_default()),
                        ext_checksum3 : u64::from_le_bytes(ext[16..24].try_into().unwrap_or_default()),
                        page_number : u64::from_le_bytes(ext[24..32].try_into().unwrap_or_default()),
                        unknown : u64::from_le_bytes(ext[32..40].try_into().unwrap_or_default()),
                    }));
                    page.header_size = 80;
                }
            }
        }
        Ok(page)
    }

    pub fn is_branch(&self) -> bool {
        self.page_flags & (ROOT_PAGE_FLAG | LEAF_PAGE_FLAG | INDEX_PAGE_FLAG | SPACE_TREE_PAGE_FLAG | LONG_VALUE_PAGE_FLAG) == 0
    }

    pub fn is_root(&self) -> bool {
        self.page_flags & ROOT_PAGE_FLAG > 0
    }

    pub fn is_leaf(&self) -> bool {
        self.page_flags & LEAF_PAGE_FLAG > 0
    }
    pub fn is_long_value(&self) -> bool {
        self.page_flags & LONG_VALUE_PAGE_FLAG > 0
    }
    pub fn is_empty_flag(&self) -> bool {
        self.page_flags & EMPTY_PAGE_FLAG > 0
    }
    pub fn is_index(&self) -> bool {
        self.page_flags & INDEX_PAGE_FLAG > 0
    }
    pub fn is_primary(&self) -> bool {
        self.page_flags & PRIMARY_PAGE_FLAG > 0
    }
    pub fn is_parent(&self) -> bool {
        self.page_flags & PARENT_PAGE_FLAG > 0
    }
    pub fn is_space_tree(&self) -> bool {
        self.page_flags & SPACE_TREE_PAGE_FLAG > 0
    }
    pub fn is_erased(&self) -> bool {
        self.page_flags & ERASED_PAGE_FLAG > 0
    }
    pub fn is_repaired(&self) -> bool {
        self.page_flags & REPAIRED_PAGE_FLAG > 0
    }

    pub fn flags(&self) -> Vec<PageFlag> {
        let mut flags = Vec::with_capacity(8);
        if self.is_root() {
            flags.push(PageFlag::Root);
        }
        if self.is_leaf() {
            flags.push(PageFlag::Leaf);
        }
        if self.is_long_value() {
            flags.push(PageFlag::LongValue);
        }
        if self.is_empty_flag() {
            flags.push(PageFlag::Empty);
        }
        if self.is_index() {
            flags.push(PageFlag::Index);
        }
        if self.is_parent() {
            flags.push(PageFlag::Parent);
        }
        if self.is_space_tree() {
            flags.push(PageFlag::SpaceTree);
        }
        flags
    }
}

#[derive(Clone, Debug)]
pub struct Page<'a> {
    pub page_number : u32,
    pub data : Cow<'a, [u8]>,
    pub header : PageHeader,
    pub tags : Vec<Tag>
}

impl<'p> Page<'p> {
    pub fn new(data : Cow<'p, [u8]>, page_number : u32, header : &Header) -> ForensicResult<Self> {
        let page_size = header.page_size as usize;
        if data.len() != page_size {
            return Err(ForensicError::invalid_format("ESE", "Page data size does not match Header page size"))
        }
        let page_header = PageHeader::from_buff(&data, header.version, header.file_format_revision)?;
        // The tag array occupies `available_page_tag * 4` bytes at the *end*
        // of the page; validate that it actually fits there before trusting
        // it enough to loop over it. (A prior version of this check compared
        // the page's total byte length against the tag *count* — a
        // byte-vs-count comparison that was true for almost any tag count
        // and caught nothing.)
        let tag_table_fits = (page_header.header_size as usize)
            .checked_add((page_header.available_page_tag as usize).saturating_mul(4))
            .is_some_and(|end| end <= page_size);
        let tags = if !page_header.is_empty_flag() && page_header.available_page_tag > 1 && tag_table_fits {
            let mut tags = Vec::with_capacity(page_header.available_page_tag as usize);
            let tag_reader = TagReader::new(header.page_size, header.file_format_revision);
            for tag_n in 0..page_header.available_page_tag {
                let tag_offset_rel = (tag_n as usize + 1) * 4;
                if tag_offset_rel > page_size {
                    break
                }
                let tag_offset = page_size - tag_offset_rel;
                if tag_offset + 4 > data.len() {
                    break
                }
                let tag_data = &data[tag_offset..tag_offset + 4];
                let tag = match tag_reader.from_buff(tag_data) {
                    Ok(v) => v,
                    Err(_) => {
                        break
                    }
                };
                if tag.value_offset as usize + tag.value_size as usize > data.len() {
                    break
                }
                tags.push(tag);
            }
            tags
        } else {
            Vec::new()
        };
        
        Ok(Self {
            header : page_header,
            tags,
            data,
            page_number
        })
    } 

    pub fn get_tag_data(&self, tag_n : usize) -> ForensicResult<&[u8]> {
        let tag = match self.tags.get(tag_n) {
            Some(v) => v,
            None => return Err(ForensicError::missing_data("ESE", "Cannot find tag".into()))
        };
        let tag_offset = self.header.header_size as usize + tag.value_offset as usize;
        let tag_end = tag_offset + tag.value_size as usize;
        if tag_end > self.data.len() {
            return Err(ForensicError::missing_data("ESE", "Tag size out of bounds".into()))
        }
        let data = &self.data[tag_offset..tag_end];
        Ok(data)
    }
    pub fn get_tag<'a>(&'a self, tag_n : usize) -> ForensicResult<TagData<'a>> {
        let tag = match self.tags.get(tag_n) {
            Some(v) => v,
            None => return Err(ForensicError::missing_data("ESE", "Cannot find tag".into()))
        };
        let tag_offset = self.header.header_size as usize + tag.value_offset as usize;
        let tag_end = tag_offset + tag.value_size as usize;
        if tag_end > self.data.len() {
            return Err(ForensicError::missing_data("ESE", "Tag size out of bounds".into()))
        }
        let data = &self.data[tag_offset..tag_end];
        Ok(TagData {
            data,
            flags : tag.tag_flags
        })
    }

    pub fn is_root(&self) -> bool {
        self.header.is_root()
    }
    pub fn is_branch(&self) -> bool {
        self.header.is_branch()
    }
    pub fn is_leaf(&self) -> bool {
        self.header.is_leaf()
    }
    pub fn is_index(&self) -> bool {
        self.header.is_index()
    }
    pub fn is_primary(&self) -> bool {
        self.header.is_primary()
    }
    pub fn is_space_tree(&self) -> bool {
        self.header.is_space_tree()
    }
    pub fn empty_page(&self) -> bool {
        self.header.is_empty_flag()
    }

    pub fn is_long_value(&self) -> bool {
        self.header.is_long_value()
    }

    pub fn process_page<'a>(&'a self) -> ForensicResult<TreePage<'a>> {
        if self.is_branch() {
            return Ok(TreePage::Branch(BranchPage::new(self)?))
        }else if self.is_leaf() {
            return Ok(TreePage::Leaf(LeafPage::new(self)?))
        }else if self.is_root() {
            return Ok(TreePage::Root(RootPage::new(self)?))
        }
        Err(ForensicError::invalid_format("ESE", "No external header"))
    }

    /// Creates a zero-filled dummy page for use in unit tests where the
    /// `Page` argument is not actually accessed (e.g. `TableValueEntry::new`).
    #[cfg(test)]
    pub fn dummy() -> Page<'static> {
        Page {
            page_number: 0,
            data: Cow::Owned(vec![0u8; 40]),
            header: PageHeader {
                checksum: PageChecksum::Win7(PageChecksumWin7 { checksum: 0 }),
                last_modification_time: 0,
                previous_page_number: 0,
                next_page_number: 0,
                father_data_page_id: 0,
                available_data_size: 0,
                available_uncommited_data_size: 0,
                available_data_offset: 0,
                available_page_tag: 0,
                page_flags: 0,
                extension: None,
                header_size: 40,
                version: 0,
                revision: 0,
            },
            tags: Vec::new(),
        }
    }

    pub fn valid_page(&self) -> bool {
        if self.header.page_flags >= 0x340032 {
            return false
        }
        if self.header.available_data_size as usize > self.data.len() {
            return false
        }
        if self.header.available_data_offset as usize > self.data.len() {
            return false
        }
        if self.header.available_page_tag as usize > self.data.len() {
            return false
        }
        if self.header.available_uncommited_data_size > self.header.available_data_size {
            return false
        }
        if self.header.is_erased() || self.header.is_repaired() {
            return false
        }
        true
    }
}

#[cfg(test)]
mod tst {

    use std::borrow::Cow;
    use crate::ese::{page::PageChecksumWin7, tst::{get_mdb_and_header, get_mdb_and_header_ual}};

    use super::{Page, PageHeader};

    /// Getting info from `esentutl.exe /ms .\artifacts\SystemIdentity.mdb /p1`
    #[test]
    fn should_load_mdb_header() {
        let Some((buffer, header)) = get_mdb_and_header() else { return };
        assert_eq!(8192, header.page_to_file_offset(1).unwrap());
        let page_header = PageHeader::from_buff(&buffer[header.page_to_file_offset(1).unwrap() as usize..], header.version, header.file_format_revision).unwrap();
        let checksum: &PageChecksumWin7 = (&page_header.checksum).try_into().unwrap();
        assert_eq!(0x7fdf7fdf0001a77c, checksum.checksum);
        assert_eq!(0,page_header.previous_page_number);
        assert_eq!(0,page_header.next_page_number);
        assert_eq!(1, page_header.father_data_page_id);
        assert_eq!(4036, page_header.available_data_size);
        assert_eq!(0, page_header.available_uncommited_data_size);
        assert_eq!(1, page_header.available_page_tag);
        assert_eq!(0xA803, page_header.page_flags);

        let page_header = PageHeader::from_buff(&buffer[header.page_to_file_offset(2).unwrap() as usize..], header.version, header.file_format_revision).unwrap();
        let checksum: &PageChecksumWin7 = (&page_header.checksum).try_into().unwrap();
        assert_eq!(0x0192019200ec59d4, checksum.checksum);
        assert_eq!(0,page_header.previous_page_number);
        assert_eq!(0,page_header.next_page_number);
        assert_eq!(1, page_header.father_data_page_id);
        assert_eq!(4022, page_header.available_data_size);
        assert_eq!(0, page_header.available_uncommited_data_size);
        assert_eq!(2, page_header.available_page_tag);
        assert_eq!(0xA823, page_header.page_flags);

    }

    #[test]
    fn should_load_full_page() {
        let Some((buffer, header)) = get_mdb_and_header_ual() else { return };
        let page_n = 4u32;
        let page_offset = header.page_to_file_offset(page_n as u64).unwrap() as usize;
        let _page = Page::new(Cow::Owned(buffer[page_offset..page_offset + header.page_size as usize].to_vec()), page_n, &header).unwrap();

        for page_n in 4u32..254 {
            let page_offset = header.page_to_file_offset(page_n as u64).unwrap() as usize;
            let page = Page::new(Cow::Owned(buffer[page_offset..page_offset + header.page_size as usize].to_vec()), page_n, &header).unwrap();
            if page.tags.is_empty() {
                continue;
            }
            if !page.valid_page() {
                continue
            }
            if page.empty_page() {
                continue
            }
            let _tree_page = page.process_page().unwrap();
        }
    }

    #[test]
    fn page_size_16000_no_longer_panics() {
        // Regression guard for the historical (16_000/32_000-vs-16_384/32_768)
        // typo: neither a bogus 16_000-byte page nor a real 16_384-byte one
        // should panic while building a `PageHeader`.
        let buffer = vec![0u8; 16_000];
        let _ = PageHeader::from_buff(&buffer, 0x620, 0x11);
        let buffer = vec![0u8; 16_384];
        let header = PageHeader::from_buff(&buffer, 0x620, 0x11).unwrap();
        assert_eq!(80, header.header_size, "16 KiB pages must read the Win7 extension and set header_size=80");
    }
}