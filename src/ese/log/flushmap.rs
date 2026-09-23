//! ESE flush map (`.jfm`) -- header only.
//!
//! The flush map's page-flush-state bitmap layout is not determined, and its
//! only consumer would be deciding which database pages need log replay --
//! itself out of scope (see the crate documentation on deferred log
//! replay). This module exposes only what is independently verifiable: the
//! stored checksum (confirmed **not** a XOR-fold of the file), a couple of
//! header words, and any LOGTIMEs found by scanning and validating candidate
//! positions in the first page -- reported with their offsets rather than
//! claimed as named fields, since the field layout around them is not
//! pinned down.

use std::path::Path;

use forensic_rs::err::ForensicResult;

use crate::ese::checksum::{ChecksumVerdict, NotVerifiedReason};
use crate::ese::signature::LogTimestamp;

/// A parsed flush-map header. No bitmap, no `page_flush_state(n)` -- see the
/// module documentation.
#[derive(Debug, Clone)]
pub struct FlushMap {
    pub stored_checksum: u32,
    /// Word at offset 4. Observed as `3` in the SRUM fixture; meaning
    /// otherwise unconfirmed.
    pub version: u32,
    /// Word at offset 0x24. Observed as `1` in the SRUM fixture.
    pub field_24: u32,
    /// `(offset, timestamp)` pairs for every 8-byte window in the first page
    /// that decodes as a plausible (non-`Invalid`) `LOGTIME`. Found by
    /// scanning, not by asserting a fixed field layout.
    pub timestamps: Vec<(usize, LogTimestamp)>,
    /// The whole first page, verbatim.
    pub raw_header: Vec<u8>,
    pub size: usize,
}

impl FlushMap {
    pub fn from_buff(buffer: &[u8]) -> ForensicResult<Self> {
        forensic_rs::ensure_min_length!(0x28, buffer.len(), "ESE flush map");
        let stored_checksum = u32::from_le_bytes(buffer[0..4].try_into().unwrap_or_default());
        let version = u32::from_le_bytes(buffer[4..8].try_into().unwrap_or_default());
        let field_24 = if buffer.len() >= 0x28 {
            u32::from_le_bytes(buffer[0x24..0x28].try_into().unwrap_or_default())
        } else {
            0
        };

        let page = &buffer[..buffer.len().min(4096)];
        let mut timestamps = Vec::new();
        let mut offset = 0usize;
        while offset + 8 <= page.len() {
            let raw: [u8; 8] = page[offset..offset + 8].try_into().unwrap_or_default();
            let ts = LogTimestamp::from_raw(raw);
            if matches!(ts, LogTimestamp::Present { .. }) {
                timestamps.push((offset, ts));
            }
            offset += 1;
        }

        Ok(Self {
            stored_checksum,
            version,
            field_24,
            timestamps,
            raw_header: page.to_vec(),
            size: buffer.len(),
        })
    }

    pub fn open(path: impl AsRef<Path>) -> ForensicResult<Self> {
        let bytes = std::fs::read(path.as_ref())
            .map_err(|e| forensic_rs::err::ForensicError::io_error_with_source(e, "Cannot open ESE flush map"))?;
        Self::from_buff(&bytes)
    }

    /// Always `NotVerified` -- confirmed not a XOR-fold of the file (stored
    /// `0xdb083a2f` vs `xor32(4..end)=0x515cf43f`, `xor32(4..4096)=0x52a3f7c0`
    /// on the SRUM fixture). Never claim `Match`/`Mismatch` here.
    pub fn checksum_status(&self) -> ChecksumVerdict {
        ChecksumVerdict::NotVerified { reason: NotVerifiedReason::AlgorithmUnknown }
    }
}

#[cfg(test)]
mod tst {
    use super::*;

    #[test]
    fn rejects_buffer_shorter_than_minimum() {
        assert!(FlushMap::from_buff(&[0u8; 10]).is_err());
    }

    #[test]
    fn checksum_status_is_always_not_verified() {
        let map = FlushMap::from_buff(&[0u8; 4096]).unwrap();
        assert_eq!(
            map.checksum_status(),
            ChecksumVerdict::NotVerified { reason: NotVerifiedReason::AlgorithmUnknown }
        );
    }

    #[test]
    fn real_fixture_parses_with_expected_header_words() {
        let Ok(bytes) = std::fs::read("./artifacts/sru/SRUDB.jfm") else {
            eprintln!("SKIP: fixture unavailable");
            return;
        };
        let map = FlushMap::from_buff(&bytes).unwrap();
        assert_eq!(map.stored_checksum, 0xdb08_3a2f);
        assert_eq!(map.version, 3);
        assert_eq!(map.field_24, 1);
        assert!(!map.timestamps.is_empty(), "expected at least one plausible LOGTIME in the header");
    }
}
