use forensic_rs::err::ForensicResult;

pub const TAG_VARIABLE_SIZE : u8 = 0x0001;
pub const TAG_DEFUNCT : u8 = 0x0002;
pub const TAG_COMMON_KEY : u8 = 0x0004;


pub struct TagReader {
    revision : u32, 
    page_size : u32
}

impl TagReader {
    pub fn new(page_size : u32, revision : u32) -> Self {
        Self { revision, page_size }
    }
    pub fn from_buff(&self, buffer : &[u8]) -> ForensicResult<Tag> {
        Tag::from_buff(buffer, self.revision, self.page_size)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Tag {
    /// Offset relative after the page header
    pub value_offset : u16,
    pub tag_flags : u8,
    pub value_size : u16
}

impl Tag {
    pub fn from_buff(buffer : &[u8], revision : u32, page_size : u32) -> ForensicResult<Self> {
        if buffer.len() < 4 {
            return Err(forensic_rs::err::ForensicError::bad_format_str("Invalid buffer size. Must be at least 4 bytes"))
        }
        let size = u16::from_le_bytes(buffer[0..2].try_into().unwrap_or_default());
        let offset = u16::from_le_bytes(buffer[2..4].try_into().unwrap_or_default());
        let (value_offset, tag_flags, value_size) = if revision >= 17 && (page_size == 16_384 || page_size == 32_768) {
            (offset & 0x7FFF, (offset >> 15) as u8, size & 0x7FFF)
        } else {
            (offset & 0x1FFF, (offset >> 13) as u8, size & 0x1FFF)
        };

        Ok(Self {
            value_offset,
            tag_flags,
            value_size
        })
    }
}


#[test]
fn should_deserialize_tags(){
    let reader = TagReader {
        revision : 20,
        page_size : 4096
    };

    let tag = reader.from_buff(&[36, 0, 175, 32]).unwrap();
    assert_eq!(0x00af, tag.value_offset);
    assert_eq!(36, tag.value_size);
    assert_eq!(0x01, tag.tag_flags);

    let tag = reader.from_buff(&[30, 0, 111, 32]).unwrap();
    assert_eq!(0x006f, tag.value_offset);
    assert_eq!(30, tag.value_size);
    assert_eq!(0x01, tag.tag_flags);

    let tag = reader.from_buff(&[30, 0, 16, 0]).unwrap();
    assert_eq!(0x0010, tag.value_offset);
    assert_eq!(30, tag.value_size);
    assert_eq!(0x0, tag.tag_flags);

    let tag = reader.from_buff(&[36, 0, 46, 32]).unwrap();
    assert_eq!(0x002e, tag.value_offset);
    assert_eq!(36, tag.value_size);
    assert_eq!(0x01, tag.tag_flags);
    let tag = reader.from_buff(&[29, 0, 82, 32]).unwrap();
    assert_eq!(0x0052, tag.value_offset);
    assert_eq!(29, tag.value_size);
    assert_eq!(0x01, tag.tag_flags);
    let tag = reader.from_buff(&[27, 0, 211, 32]).unwrap();
    assert_eq!(0x00d3, tag.value_offset);
    assert_eq!(27, tag.value_size);
    assert_eq!(0x01, tag.tag_flags);
    let tag = reader.from_buff(&[34, 0, 141, 32]).unwrap();
    assert_eq!(0x008d, tag.value_offset);
    assert_eq!(34, tag.value_size);
    assert_eq!(0x01, tag.tag_flags);

}