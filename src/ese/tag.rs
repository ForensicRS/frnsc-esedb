use forensic_rs::err::ForensicResult;

pub const TAG_VARIABLE_SIZE : u8 = 0x0001;
pub const TAG_DEFUNCT : u8 = 0x0002;
pub const TAG_COMMON_KEY : u8 = 0x0004;


#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Tag {
    /// Offset relative after the page header
    pub value_offset : u16,
    pub tag_flags : u8,
    pub value_size : u16
}

impl Tag {
    pub fn from_buff(buffer : &[u8], revision : u32) -> ForensicResult<Self> {
        if buffer.len() < 4 {
            return Err(forensic_rs::err::ForensicError::bad_format_str("Invalid buffer size. Must be at least 4 bytes"))
        }
        let size = u16::from_le_bytes(buffer[0..2].try_into().unwrap_or_default());
        let offset = u16::from_le_bytes(buffer[2..4].try_into().unwrap_or_default());
        let (value_offset, tag_flags, value_size) = if revision <= 12 {
            (offset & 0x1FFF, (offset >> 13) as u8, size & 0x1FFF)
        } else {
            (offset & 0x7FFF, (offset >> 15) as u8, size & 0x7FFF)
        };

        Ok(Self {
            value_offset,
            tag_flags,
            value_size
        })
    }
}