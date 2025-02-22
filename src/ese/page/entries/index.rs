use forensic_rs::err::{ForensicError, ForensicResult};

#[derive(Clone, Debug)]
pub struct IndexEntry<'a> {
    pub record_page_key : &'a [u8]
}

impl<'a> IndexEntry<'a> {
    pub fn new(data : &'a [u8]) -> ForensicResult<Self> {
        Ok(Self { record_page_key: data })
    }
}
