use forensic_rs::err::{ForensicError, ForensicResult};

#[derive(Clone, Debug)]
pub struct SpaceTreeEntry<'a> {
    pub common_page_key_size : u16,
    pub local_page_key_size : u16,
    pub page_key : &'a [u8],
    pub entry_data : &'a [u8],
    pub num_pages : u32
}

impl<'a> SpaceTreeEntry<'a> {
    pub fn new(tag_flag : u8, data : &'a [u8]) -> ForensicResult<SpaceTreeEntry<'a>> {
        if data.len() < 8 {
            return Err(ForensicError::bad_format_str("Space Tree size must be bigger than 8 bytes"))
        }
        let common_page_key_size = if tag_flag == 0x4 {
            u16::from_le_bytes([data[0], data[1]])
        }else {
            0
        };
        let local_page_key_size = u16::from_le_bytes([data[2], data[3]]);
        if data.len() < 8 + local_page_key_size as usize {
            return Err(ForensicError::bad_format_str("Space Tree size must be bigger than local_page_key_size + 8 bytes"))
        }
        let page_key = &data[4..4 + local_page_key_size as usize];
        let entry_data = &data[4 + local_page_key_size as usize..data.len() - 4];
        let num_pages = u32::from_le_bytes(data[data.len() - 4..].try_into().unwrap_or_default());
        Ok(SpaceTreeEntry {
            common_page_key_size,
            local_page_key_size,
            page_key,
            entry_data,
            num_pages,
        })
    }
}