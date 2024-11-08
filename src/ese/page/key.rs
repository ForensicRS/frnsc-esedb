use forensic_rs::err::ForensicResult;

pub struct PageKey {
    pub suffix : Vec<u8>,
    pub preffix : Vec<u8>,
    pub page_number : u32
}

#[derive(Default, Clone, Debug)]
pub struct PageKeyRef<'a> {
    pub suffix : &'a [u8],
    pub preffix : &'a [u8],
    pub page_number : u32
}

impl<'a> PageKeyRef<'a> {
    pub fn new(buff : &'a[u8]) -> ForensicResult<Self> {
        if buff.len() < 2 {
            return Err(forensic_rs::err::ForensicError::bad_format_str("PageKey size must be bigger than 2 bytes"))
        }
        let suffix_len = buff[0] as usize;
        let prefix_len = buff[1] as usize;
        if buff.len() < 2 + suffix_len + prefix_len {
            return Err(forensic_rs::err::ForensicError::bad_format_str("PageKey size is invalid: not enough space for key prefix and suffix"))
        }
        let suffix = if suffix_len > 0 {
            &buff[2..2 + suffix_len]
        }else {
            &[]
        };
        let preffix = if prefix_len > 0 {
            &buff[2 + suffix_len..2 + suffix_len + prefix_len]
        }else {
            &[]
        };
        let data = &buff[2 + suffix_len + prefix_len..];

        Ok(Self {
            preffix,
            suffix,
            page_number : u32::from_le_bytes(data.try_into().unwrap_or_default())
        })
    }
}