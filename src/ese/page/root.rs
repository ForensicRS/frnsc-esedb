use forensic_rs::err::{ForensicError, ForensicResult};

#[derive(Clone, Debug)]
pub struct RootHeader {
    pub header_size : u16,
    pub number_of_pages : u32,
    pub parent_father_data_page : u32,
    pub extent_space : u32,
    pub space_tree_page_number : u32
}

impl RootHeader {
    pub fn new(data : &[u8], revision : u32) -> ForensicResult<Self> {
        let (header_size, mut offset) = if revision >= 0x14 && data.len() == 25 {
            (25, 1)
        }else if data.len() == 16{
            (16, 0)
        } else {
            return Err(ForensicError::bad_format_string(format!("Invalid Root Header size: {}", data.len())))
        };
        if header_size > data.len() {
            return Err(ForensicError::bad_format_string(format!("Invalid Root Header size: {} vs expected={}", data.len(), header_size)))
        }
        let number_of_pages = u32::from_le_bytes(data[0..4].try_into().unwrap_or_default());
        offset += 4;
        let parent_father_data_page = u32::from_le_bytes(data[offset..offset + 4].try_into().unwrap_or_default());
        offset += 4;
        let extent_space = u32::from_le_bytes(data[offset..offset + 4].try_into().unwrap_or_default());
        offset += 4;
        let space_tree_page_number = u32::from_le_bytes(data[offset..offset + 4].try_into().unwrap_or_default());
        Ok(Self {
            header_size : header_size as u16,
            number_of_pages,
            parent_father_data_page,
            extent_space,
            space_tree_page_number
        })
    }
}