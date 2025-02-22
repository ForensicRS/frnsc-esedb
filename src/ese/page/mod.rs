use branch::BranchPage;
use forensic_rs::err::{BadFormatError, ForensicError, ForensicResult};
use key::PageKeyRef;
use leaf::LeafPage;
use root::{RootHeader, RootPage};

use super::{header::Header, tag::{Tag, TagReader}};

pub mod root;
pub mod branch;
pub mod key;
pub mod leaf;
pub mod entries;

pub const ROOT_PAGE_FLAG : u32 = 0x00000001;
pub const LEAF_PAGE_FLAG : u32 = 0x00000002;
pub const PARENT_PAGE_FLAG : u32 = 0x00000004;
pub const EMPTY_PAGE_FLAG : u32 = 0x00000008;
pub const SPACE_TREE_PAGE_FLAG : u32 = 0x00000020;
pub const INDEX_PAGE_FLAG : u32 = 0x00000040;
pub const LONG_VALUE_PAGE_FLAG : u32 = 0x00000080;
pub const ERASED_PAGE_FLAG : u32 = 0x00004000;
pub const REPAIRED_PAGE_FLAG : u32 = 0x200000;

#[derive(Clone, Debug)]
pub enum TreePage<'a> {
    Root(RootPage<'a>),
    Branch(BranchPage<'a>),
    Leaf(LeafPage<'a>)
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

#[repr(packed)]
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

#[repr(packed)]
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
#[repr(packed)]
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

#[repr(packed)]
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
            _ => Err(ForensicError::bad_format_str("Not a Win7 checksum"))
        }
    }
}

impl<'a> TryFrom<&'a PageChecksum> for &'a PageChecksumExchange2003 {
    type Error = ForensicError;

    fn try_from(value: &'a PageChecksum) -> Result<Self, Self::Error> {
        match value {
            PageChecksum::Exchange2003(v) => Ok(v),
            _ => Err(ForensicError::bad_format_str("Not a Exchange2003 checksum"))
        }
    }
}
impl<'a> TryFrom<&'a PageChecksum> for &'a PageChecksumWinVista {
    type Error = ForensicError;

    fn try_from(value: &'a PageChecksum) -> Result<Self, Self::Error> {
        match value {
            PageChecksum::WinVista(v) => Ok(v),
            _ => Err(ForensicError::bad_format_str("Not a WinVista checksum"))
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
        let (head, data, tail) = unsafe {&buffer[..].align_to::<PageHeaderRepr>()};
        if head.len() > 0 || data.len() == 0 {
            return Err(forensic_rs::err::ForensicError::bad_format_str("Invalid alignement"));
        }
        let mut page : PageHeader = (&data[0]).into();
        page.version = version;
        page.revision = revision;
        if version == 0x602 {
            if revision < 0x0000000b {
                // Before Exchange 2003 SP1 and Windows Vista
                page.checksum = PageChecksum::Exchange2003(PageChecksumExchange2003 {
                    xor : u32::from_le_bytes(buffer[0..4].try_into().unwrap_or_default()),
                    page_number : u32::from_le_bytes(buffer[4..9].try_into().unwrap_or_default())
                });
            } else if revision < 0x00000011 {
                // Exchange 2003 SP1 and Windows Vista and later
                page.checksum = PageChecksum::WinVista(PageChecksumWinVista {
                    xor_checksum : u32::from_le_bytes(buffer[0..4].try_into().unwrap_or_default()),
                    ecc_checksum : u32::from_le_bytes(buffer[4..9].try_into().unwrap_or_default())
                });
            }else if revision >= 0x00000011 {
                // Exchange 2003 SP1 and Windows Vista and later
                page.checksum = PageChecksum::Win7(PageChecksumWin7 {
                    checksum : u64::from_le_bytes(buffer[0..8].try_into().unwrap_or_default())
                });
                if buffer.len() == 16_000 || buffer.len() == 32_000 {
                    // Extended format
                    page.extension = Some(PageExtension::Win7(PageExtensionWin7 {
                        ext_checksum1 : u64::from_le_bytes(tail[0..8].try_into().unwrap_or_default()),
                        ext_checksum2 : u64::from_le_bytes(tail[8..16].try_into().unwrap_or_default()),
                        ext_checksum3 : u64::from_le_bytes(tail[16..24].try_into().unwrap_or_default()),
                        page_number : u64::from_le_bytes(tail[24..32].try_into().unwrap_or_default()),
                        unknown : u64::from_le_bytes(tail[32..40].try_into().unwrap_or_default()),
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
pub struct Page {
    pub page_number : u32,
    pub data : Vec<u8>,
    pub header : PageHeader,
    pub tags : Vec<Tag>
}

impl Page {
    pub fn new(data : Vec<u8>, page_number : u32, header : &Header) -> ForensicResult<Self> {
        let page_size = header.page_size as usize;
        if data.len() != page_size as usize {
            return Err(ForensicError::bad_format_str("Page data size does not match Header page size"))
        }
        let page_header = PageHeader::from_buff(&data, header.version, header.file_format_revision)?;
        let tags = if !page_header.is_empty_flag() && (page_header.available_page_tag > 1 && data.len() > page_header.available_page_tag as usize) {
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
                let tag = match tag_reader.from_buff(&tag_data) {
                    Ok(v) => v,
                    Err(e) => {
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
            None => return Err(ForensicError::missing_str("Cannot find tag"))
        };
        let tag_offset = self.header.header_size as usize + tag.value_offset as usize;
        let tag_end = tag_offset + tag.value_size as usize;
        if tag_end > self.data.len() {
            println!("tag_end={:#0x}", tag_end);
            println!("tag_offset={:#0x}", tag_offset);
            return Err(ForensicError::missing_str("Tag size out of bounds"))
        }
        let data = &self.data[tag_offset..tag_end];
        Ok(data)
    }
    pub fn get_tag(&self, tag_n : usize) -> ForensicResult<(&Tag, &[u8])> {
        let tag = match self.tags.get(tag_n) {
            Some(v) => v,
            None => return Err(ForensicError::missing_str("Cannot find tag"))
        };
        let tag_offset = self.header.header_size as usize + tag.value_offset as usize;
        let tag_end = tag_offset + tag.value_size as usize;
        if tag_end > self.data.len() {
            println!("tag_end={:#0x}", tag_end);
            println!("tag_offset={:#0x}", tag_offset);
            return Err(ForensicError::missing_str("Tag size out of bounds"))
        }
        let data = &self.data[tag_offset..tag_end];
        Ok((tag, data))
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
    pub fn is_space_tree(&self) -> bool {
        self.header.is_space_tree()
    }
    pub fn empty_page(&self) -> bool {
        self.header.is_empty_flag()
    }

    pub fn process_page<'a>(&'a self) -> ForensicResult<TreePage<'a>> {
        if self.is_branch() {
            return Ok(TreePage::Branch(BranchPage::new(&self)?))
        }else if self.is_leaf() {
            return Ok(TreePage::Leaf(LeafPage::new(&self)?))
        }else if self.is_root() {
            return Ok(TreePage::Root(RootPage::new(&self)?))
        }
        Err(ForensicError::bad_format_str("No external header"))
    }

    pub fn get_page_keys_if_root<'a>(&'a self, key_n : usize) -> ForensicResult<PageKeyRef<'a>> {
        let tag_data: &[u8] = self.get_tag_data(key_n + 1)?;
        PageKeyRef::new(tag_data)
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

    use crate::ese::{header::{FileFormatFingerprint, Header, DATABASE_CLEAN_SHUTDOWN}, page::PageChecksumWin7, tag::Tag, tst::{get_mdb_and_header, get_mdb_and_header_ual, open_debug_file, to_debug_file}};

    use super::{Page, PageHeader};

    /// Getting info from `esentutl.exe /ms .\artifacts\SystemIdentity.mdb /p1`
    #[test]
    fn should_load_mdb_header() {
        let (buffer, header) = get_mdb_and_header();
        assert_eq!(8192, header.page_to_file_offset(1));
        let page_header = PageHeader::from_buff(&buffer[header.page_to_file_offset(1) as usize..], header.version, header.file_format_revision).unwrap();
        let checksum: &PageChecksumWin7 = (&page_header.checksum).try_into().unwrap();
        assert_eq!(0x7fdf7fdf0001a77c, checksum.checksum);
        assert_eq!(0,page_header.previous_page_number);
        assert_eq!(0,page_header.next_page_number);
        assert_eq!(1, page_header.father_data_page_id);
        assert_eq!(4036, page_header.available_data_size);
        assert_eq!(0, page_header.available_uncommited_data_size);
        assert_eq!(1, page_header.available_page_tag);
        assert_eq!(0xA803, page_header.page_flags);

        let page_header = PageHeader::from_buff(&buffer[header.page_to_file_offset(2) as usize..], header.version, header.file_format_revision).unwrap();
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
        let (buffer, header) = get_mdb_and_header_ual();
        let mut dbg = open_debug_file("ual-test");
        to_debug_file(&mut dbg, " HEADER ",format!("{:#?}", header));
        let page_n = 4u32;
        let page_offset = header.page_to_file_offset(page_n as u64) as usize;
        let page = Page::new(buffer[page_offset..page_offset + header.page_size as usize].to_vec(), page_n, &header).unwrap();
        assert_eq!(&[Tag { value_offset: 0, tag_flags: 0, value_size: 16 }, Tag { value_offset: 2775, tag_flags: 0, value_size: 19 }, Tag { value_size: 14, tag_flags: 0, value_offset: 2794 }, Tag { value_size: 6, tag_flags: 0, value_offset: 2769 }], &page.tags[..]);

        for page_n in 4u32..254 {
            let page_offset = header.page_to_file_offset(page_n as u64) as usize;
            let page = Page::new(buffer[page_offset..page_offset + header.page_size as usize].to_vec(), page_n, &header).unwrap();
            to_debug_file(&mut dbg, &format!("Page {page_n} Header"),format!("{:#?}", page));
            to_debug_file(&mut dbg, &format!("Page {page_n} Flags"),format!("{:#?}", page.header.flags()));
            if page.tags.is_empty() {
                continue;
            }
            if !page.valid_page() {
                println!("Invalid page {page_n}");
                continue
            }
            if page.empty_page() {
                continue
            }
            for i in 0..page.tags.len() {
                let data = match page.get_tag_data(i) {
                    Ok(v) => v,
                    Err(e) => panic!("{e}")
                };
                //to_debug_file(&mut dbg, &format!("Page {page_n} tag {i} Data"),format!("{:#?}", data));
                //to_debug_file(&mut dbg, &format!("Page {page_n}  tag {i} Data as STR"),format!("{}", String::from_utf8_lossy(data)));
                //println!("4 last bytes={}", u32::from_le_bytes(data[data.len() - 4..data.len()].try_into().unwrap_or_default()));
            }
            let ext_header = page.process_page().unwrap();
            println!("{:?}", ext_header);
        }
        
    }
}