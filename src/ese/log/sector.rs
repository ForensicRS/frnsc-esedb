//! Individual log data sectors. Every sector at index >= `csecHeader`
//! self-identifies its own position (an [`Lgpos`]) and a recorded time, which
//! is what makes it possible to tell a live sector from a torn-write shadow
//! copy from residual data left behind by a recycled generation -- **without**
//! trusting the file's name or its header's stated generation for anything
//! beyond a starting hypothesis.

use std::borrow::Cow;

use forensic_rs::err::ForensicResult;

use crate::ese::checksum::{ChecksumVerdict, NotVerifiedReason};
use crate::ese::lgpos::Lgpos;
use crate::ese::signature::LogTimestamp;

use super::header::LogFileHeader;

/// One log sector's classification relative to its containing file's header.
///
/// # Ordering rule -- read before touching this enum
///
/// [`LogSector::classify`] tests **generation before `isec`**. This is not
/// an arbitrary choice: `artifacts/sru/SRU000B8.log` sector 15 has
/// `self_position.sector == 14` (which looks exactly like the benign
/// torn-write shadow every other archived log's last sector shows) but
/// `self_position.generation == 174`, sixteen generations stale. Testing
/// `isec` first would classify verified residual evidence as a harmless
/// shadow and silently discard it. If you touch `classify`, re-verify this
/// exact fixture.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum SectorClass {
    /// `generation == header generation` and `sector == physical index`: an
    /// ordinary live sector of the current generation.
    Live,
    /// `generation == header generation` but `sector != physical index`:
    /// ESE's torn-write guard -- a duplicate of the frontier sector written
    /// one slot further along. Benign.
    Shadow { of: u16 },
    /// `generation != header generation`: residual data from a previous life
    /// of this recycled log file. Forensically significant -- this is
    /// recoverable log content the engine believes has been superseded.
    Stale { generation: u32 },
    /// Every byte zero: never written in this generation.
    Unwritten,
    /// Not zeroed, and no plausible self-reported `Lgpos`.
    Unrecognized,
}

/// One sector of a transaction log's data region.
pub struct LogSector<'a> {
    pub index: u16,
    /// The sector's own claimed position, decoded from `+0x08`. This is the
    /// self-identifying field that makes classification possible without
    /// trusting the file's name or the header's stated generation.
    pub self_position: Lgpos,
    /// The sector's recorded time, decoded from `+0x10`.
    pub timestamp: LogTimestamp,
    /// The stored checksum at `+0x00`. The algorithm that produces it is
    /// **not** known -- see [`LogSector::checksum_status`].
    pub stored_checksum: u32,
    pub unknown_04: u16,
    pub unknown_06: u16,
    pub data: Cow<'a, [u8]>,
}

impl<'a> LogSector<'a> {
    /// Size of the decoded sector header (checksum + unknowns + LGPOS +
    /// LOGTIME + 8 bytes of padding up to the documented `0x28` boundary).
    pub const HEADER_SIZE: usize = 0x28;

    pub fn new(index: u16, data: Cow<'a, [u8]>) -> ForensicResult<Self> {
        forensic_rs::ensure_min_length!(Self::HEADER_SIZE, data.len(), "ESE log sector");
        let stored_checksum = u32::from_le_bytes(data[0..4].try_into().unwrap_or_default());
        let unknown_04 = u16::from_le_bytes(data[4..6].try_into().unwrap_or_default());
        let unknown_06 = u16::from_le_bytes(data[6..8].try_into().unwrap_or_default());
        let self_position = Lgpos::from_buff(&data[8..16])?;
        let timestamp_raw: [u8; 8] = data[16..24].try_into().unwrap_or_default();
        Ok(Self {
            index,
            self_position,
            timestamp: LogTimestamp::from_raw(timestamp_raw),
            stored_checksum,
            unknown_04,
            unknown_06,
            data,
        })
    }

    /// `true` when every byte of the sector is zero.
    pub fn is_zeroed(&self) -> bool {
        self.data.iter().all(|&b| b == 0)
    }

    /// The sector's payload, from `+0x28` onward. Deliberately not decoded
    /// into individual log records -- see the crate documentation for why
    /// LR-type decoding is out of scope.
    pub fn payload(&self) -> &[u8] {
        if self.data.len() <= Self::HEADER_SIZE {
            &[]
        } else {
            &self.data[Self::HEADER_SIZE..]
        }
    }

    /// Always `NotVerified` -- no verified checksum algorithm exists for a
    /// log data sector (the stored `u32` at `+0x00` is confirmed not to be a
    /// XOR-fold of the sector). Never claim `Match`/`Mismatch` here.
    pub fn checksum_status(&self) -> ChecksumVerdict {
        ChecksumVerdict::NotVerified { reason: NotVerifiedReason::AlgorithmUnknown }
    }

    /// Classify this sector relative to its containing file's header.
    ///
    /// **Generation is tested before `isec`.** See the [`SectorClass`]
    /// documentation for the fixture that makes this order mandatory.
    pub fn classify(&self, header: &LogFileHeader) -> SectorClass {
        if self.is_zeroed() {
            return SectorClass::Unwritten;
        }
        if self.self_position.is_null() {
            return SectorClass::Unrecognized;
        }
        if self.self_position.generation != header.generation {
            return SectorClass::Stale { generation: self.self_position.generation };
        }
        if self.self_position.sector == self.index {
            SectorClass::Live
        } else {
            SectorClass::Shadow { of: self.self_position.sector }
        }
    }
}

/// A contiguous run of `Stale` sectors within one log file -- residual data
/// from a previous life of a recycled file.
#[derive(Clone, Debug)]
pub struct ResidualSpan {
    pub generation: u32,
    pub first_sector: u16,
    pub last_sector: u16,
    pub earliest: LogTimestamp,
    pub latest: LogTimestamp,
}

impl ResidualSpan {
    /// Total bytes covered by this span, given the file's sector size.
    pub fn byte_len(&self, cb_sec: u16) -> usize {
        let sectors = (self.last_sector - self.first_sector + 1) as usize;
        sectors.saturating_mul(cb_sec as usize)
    }
}

/// Lazily iterates every data sector of a log file, in physical order.
///
/// Bounded by `min(header.file_sectors, total_size / sector_size)` computed
/// up front, so it never issues an out-of-bounds read even when the file is
/// shorter than its header declares -- that discrepancy is reported as a
/// [`crate::ese::log::report::LogAnomaly::DeclaredSizeMismatch`] elsewhere,
/// not discovered here as a read failure.
pub struct LogSectorIter<'r> {
    reader: &'r dyn crate::ese::reader::PageReader,
    sector_size: u16,
    next_index: u16,
    last_index_exclusive: u16,
}

impl<'r> LogSectorIter<'r> {
    pub(crate) fn new(
        reader: &'r dyn crate::ese::reader::PageReader,
        header: &LogFileHeader,
    ) -> Self {
        let sector_size = header.sector_size;
        let by_size = if sector_size == 0 {
            0
        } else {
            (reader.total_size() / sector_size as usize) as u16
        };
        let last_index_exclusive = header.file_sectors.min(by_size);
        Self {
            reader,
            sector_size,
            next_index: header.header_sectors,
            last_index_exclusive,
        }
    }
}

impl<'r> Iterator for LogSectorIter<'r> {
    type Item = ForensicResult<LogSector<'r>>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.next_index >= self.last_index_exclusive {
            return None;
        }
        let index = self.next_index;
        self.next_index += 1;
        let offset = index as usize * self.sector_size as usize;
        let result = self
            .reader
            .read_page(offset, self.sector_size as usize)
            .and_then(|data| LogSector::new(index, data));
        Some(result)
    }
}

#[cfg(test)]
mod tst {
    use super::*;

    fn synthetic_header(generation: u32) -> LogFileHeader {
        use crate::ese::log::header::LogFileHeaderRpr;
        let mut buf = vec![0u8; std::mem::size_of::<LogFileHeaderRpr>()];
        buf[4..8].copy_from_slice(&generation.to_le_bytes());
        buf[8..10].copy_from_slice(&4096u16.to_le_bytes());
        buf[10..12].copy_from_slice(&1u16.to_le_bytes());
        buf[12..14].copy_from_slice(&16u16.to_le_bytes());
        buf[14..16].copy_from_slice(&4096u16.to_le_bytes());
        LogFileHeader::from_buff(&buf).unwrap()
    }

    fn sector_with_position(index: u16, generation: u32, sector: u16) -> LogSector<'static> {
        let mut data = vec![0u8; 4096];
        data[8..10].copy_from_slice(&0u16.to_le_bytes()); // ib
        data[10..12].copy_from_slice(&sector.to_le_bytes()); // isec
        data[12..16].copy_from_slice(&generation.to_le_bytes());
        // Mark at least one non-header byte nonzero so it isn't classified
        // Unwritten purely by accident of an all-zero payload.
        data[0x30] = 0x01;
        LogSector::new(index, Cow::Owned(data)).unwrap()
    }

    #[test]
    fn classify_live_when_generation_and_isec_both_match() {
        let header = synthetic_header(185);
        let sector = sector_with_position(5, 185, 5);
        assert_eq!(sector.classify(&header), SectorClass::Live);
    }

    #[test]
    fn classify_shadow_when_generation_matches_but_isec_does_not() {
        let header = synthetic_header(185);
        let sector = sector_with_position(6, 185, 5);
        assert_eq!(sector.classify(&header), SectorClass::Shadow { of: 5 });
    }

    #[test]
    fn classify_stale_when_generation_differs_even_if_isec_matches() {
        // The SRU000B8.log sector-15 fixture: isec looks like a shadow of
        // sector 14, but the generation (174) is stale relative to the
        // header's 184. Generation must be tested first.
        let header = synthetic_header(184);
        let sector = sector_with_position(15, 174, 14);
        assert_eq!(sector.classify(&header), SectorClass::Stale { generation: 174 });
    }

    #[test]
    fn classify_stale_when_both_generation_and_isec_differ() {
        let header = synthetic_header(185);
        let sector = sector_with_position(7, 180, 7);
        assert_eq!(sector.classify(&header), SectorClass::Stale { generation: 180 });
    }

    #[test]
    fn classify_unwritten_for_all_zero_sector() {
        let header = synthetic_header(185);
        let sector = LogSector::new(15, Cow::Owned(vec![0u8; 4096])).unwrap();
        assert_eq!(sector.classify(&header), SectorClass::Unwritten);
    }

    #[test]
    fn classify_unrecognized_for_nonzero_garbage_without_plausible_lgpos() {
        let header = synthetic_header(185);
        let data = vec![0xFFu8; 4096];
        let sector = LogSector::new(3, Cow::Owned(data)).unwrap();
        // generation decodes to 0xFFFFFFFF, which differs from the header's
        // generation, so this would actually classify as Stale under the
        // generation-first rule -- Unrecognized is reserved specifically for
        // a null self-position (all-zero LGPOS) on a non-zeroed sector.
        let mut data2 = vec![0xFFu8; 4096];
        data2[8..16].copy_from_slice(&[0u8; 8]); // null LGPOS
        let sector2 = LogSector::new(3, Cow::Owned(data2)).unwrap();
        assert_eq!(sector2.classify(&header), SectorClass::Unrecognized);
        // Sanity: the plain 0xFF-filled sector is Stale, not silently Live.
        assert_ne!(sector.classify(&header), SectorClass::Live);
    }

    #[test]
    fn new_rejects_sector_shorter_than_header_size() {
        assert!(LogSector::new(1, Cow::Owned(vec![0u8; 10])).is_err());
    }

    #[test]
    fn payload_starts_at_0x28() {
        let mut data = vec![0u8; 100];
        data[0x28] = 0xAB;
        let sector = LogSector::new(1, Cow::Owned(data)).unwrap();
        assert_eq!(sector.payload()[0], 0xAB);
    }

    #[test]
    fn checksum_status_is_always_not_verified() {
        let sector = sector_with_position(1, 185, 1);
        assert_eq!(
            sector.checksum_status(),
            ChecksumVerdict::NotVerified { reason: NotVerifiedReason::AlgorithmUnknown }
        );
    }

    #[test]
    fn real_fixture_sector_classification_matches_the_verified_walk() {
        // SRU.log: frontier at sector 5 (Live), shadow at 6, residual gen-180
        // at 7..=14, unwritten at 15.
        let Ok(bytes) = std::fs::read("./artifacts/sru/SRU.log") else {
            eprintln!("SKIP: fixture unavailable");
            return;
        };
        let header = LogFileHeader::from_buff(&bytes).unwrap();
        let read = |i: u16| -> LogSector<'_> {
            let off = i as usize * header.sector_size as usize;
            LogSector::new(i, Cow::Borrowed(&bytes[off..off + header.sector_size as usize])).unwrap()
        };
        for i in 1..=5u16 {
            assert_eq!(read(i).classify(&header), SectorClass::Live, "sector {i}");
        }
        assert_eq!(read(6).classify(&header), SectorClass::Shadow { of: 5 });
        for i in 7..=14u16 {
            assert_eq!(read(i).classify(&header), SectorClass::Stale { generation: 180 }, "sector {i}");
        }
        assert_eq!(read(15).classify(&header), SectorClass::Unwritten);
    }

    #[test]
    fn real_fixture_sru000b8_sector15_is_stale_not_shadow() {
        let Ok(bytes) = std::fs::read("./artifacts/sru/SRU000B8.log") else {
            eprintln!("SKIP: fixture unavailable");
            return;
        };
        let header = LogFileHeader::from_buff(&bytes).unwrap();
        let off = 15usize * header.sector_size as usize;
        let sector =
            LogSector::new(15, Cow::Borrowed(&bytes[off..off + header.sector_size as usize])).unwrap();
        assert_eq!(sector.self_position.sector, 14, "sanity: isec looks shadow-shaped");
        assert_eq!(
            sector.classify(&header),
            SectorClass::Stale { generation: 174 },
            "generation must be tested before isec"
        );
    }

    #[test]
    fn real_fixture_shadow_siblings_classify_as_shadow() {
        for (path, expected_gen) in
            [("./artifacts/sru/SRU000B6.log", 182u32), ("./artifacts/sru/SRU000B7.log", 183u32)]
        {
            let Ok(bytes) = std::fs::read(path) else {
                eprintln!("SKIP: fixture '{path}' unavailable");
                continue;
            };
            let header = LogFileHeader::from_buff(&bytes).unwrap();
            let off = 15usize * header.sector_size as usize;
            let sector = LogSector::new(
                15,
                Cow::Borrowed(&bytes[off..off + header.sector_size as usize]),
            )
            .unwrap();
            assert_eq!(header.generation, expected_gen, "{path}");
            assert_eq!(sector.classify(&header), SectorClass::Shadow { of: 14 }, "{path}");
        }
    }
}
