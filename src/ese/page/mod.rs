use branch::BranchHeader;
use forensic_rs::err::{BadFormatError, ForensicError, ForensicResult};
use key::PageKeyRef;
use root::RootHeader;

use super::{header::Header, tag::Tag};

pub mod root;
pub mod branch;
pub mod key;

pub const ROOT_PAGE_FLAG : u32 = 0x00000001;
pub const LEAF_PAGE_FLAG : u32 = 0x00000002;
pub const PARENT_PAGE_FLAG : u32 = 0x00000004;
pub const EMPTY_PAGE_FLAG : u32 = 0x00000008;
pub const SPACE_TREE_PAGE_FLAG : u32 = 0x00000020;
pub const INDEX_PAGE_FLAG : u32 = 0x00000040;
pub const LONG_VALUE_PAGE_FLAG : u32 = 0x00000080;

#[derive(Clone, Debug)]
pub enum TreePageHeader {
    Root(RootHeader),
    Branch(BranchHeader)
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

pub enum PageExtension {
    Win7(PageExtensionWin7)
}

pub struct PageExtensionWin7 {
    pub ext_checksum1 : u64,
    pub ext_checksum2 : u64,
    pub ext_checksum3 : u64,
    pub page_number : u64,
    pub unknown : u64
}


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

    pub fn is_root(&self) -> bool {
        self.page_flags & ROOT_PAGE_FLAG > 0
    }
    pub fn is_branch(&self) -> bool {
        !self.is_root() && !self.is_leaf()
    }
    pub fn is_leaf(&self) -> bool {
        self.page_flags & LEAF_PAGE_FLAG > 0
    }

}

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
        let mut tags = if page_header.available_page_tag > 1 {
            Vec::with_capacity(page_header.available_page_tag as usize)
        }else {
            Vec::new()
        };
        for tag_n in 0..page_header.available_page_tag {
            let tag_offset = page_size - ((tag_n as usize + 1) * 4);
            let tag_data = &data[tag_offset..tag_offset + 4];
            let tag = match Tag::from_buff(&tag_data, header.file_format_revision) {
                Ok(v) => v,
                Err(e) => return Err(ForensicError::bad_format_string(format!("Cannot parse Tag {tag_n} for page {page_number}: {}", e)))
            };
            tags.push(tag);
        }
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
        println!("Offset: {:#0x} tag_offset={:#0x} header_size={:#0x}", tag_offset, tag.value_offset, self.header.header_size);
        let tag_end = tag_offset + tag.value_size as usize;
        if tag_end > self.data.len() {
            return Err(ForensicError::missing_str("Tag size out of bounds"))
        }
        let data = &self.data[tag_offset..tag_end];
        Ok(data)
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

    pub fn get_tree_header(&self) -> ForensicResult<TreePageHeader> {
        let tag_data = self.get_tag_data(0)?;
        if self.is_root() {
            let root_header = RootHeader::new(tag_data, self.header.revision)?;
            return Ok(TreePageHeader::Root(root_header));
        }else if self.is_branch() {
            let branch_header = BranchHeader::new(tag_data, self.header.revision)?;
            return Ok(TreePageHeader::Branch(branch_header))
        }
        Err(ForensicError::bad_format_str("No external header"))
    }

    pub fn get_page_keys_if_root<'a>(&'a self, key_n : usize) -> ForensicResult<PageKeyRef<'a>> {
        let tag_data = self.get_tag_data(key_n + 1)?;
        PageKeyRef::new(tag_data)
    }
}

#[cfg(test)]
mod tst {

    use crate::ese::{header::{FileFormatFingerprint, Header, DATABASE_CLEAN_SHUTDOWN}, page::PageChecksumWin7, tag::Tag, tst::get_mdb_and_header};

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
        let (buffer, header) = get_mdb_and_header();
        println!("{:?}", header);
        let page_n = 4u32;
        let page_offset = header.page_to_file_offset(page_n as u64) as usize;
        let page = Page::new(buffer[page_offset..page_offset + header.page_size as usize].to_vec(), page_n, &header).unwrap();
        assert_eq!(&[Tag { value_offset: 0, tag_flags: 0, value_size: 16 }, Tag { value_offset: 2775, tag_flags: 0, value_size: 19 }, Tag { value_size: 14, tag_flags: 0, value_offset: 2794 }, Tag { value_size: 6, tag_flags: 0, value_offset: 2769 }], &page.tags[..]);

        let page_n = 4u32;
        let page_offset = header.page_to_file_offset(page_n as u64) as usize;
        let page = Page::new(buffer[page_offset..page_offset + header.page_size as usize].to_vec(), page_n, &header).unwrap();
        println!("{:?}", page.tags);
        println!("Page_offse={}", page_offset);
        for i in 0..page.tags.len() {
            let data = page.get_tag_data(i).unwrap();
            println!("{:?}", data);
            println!("{}", String::from_utf8_lossy(data));
            println!("4 last bytes={}", u32::from_le_bytes(data[data.len() - 4..data.len()].try_into().unwrap_or_default()));
            if i > 0 {
                println!("{:?}", page.get_page_keys_if_root(i - 1).unwrap());
            }
        }
        let ext_header = page.get_tree_header().unwrap();
        println!("{:?}", ext_header);
    }
}