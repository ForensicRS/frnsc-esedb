//! `LOGFILEHDR`: the fixed-layout prefix of every ESE transaction log file
//! (`.log`/`.jrs`), occupying the first sector.
//!
//! Only the region `0x00..0x48` is decoded here -- the fully-known part of
//! the header. The `DBMS_PARAM`/`ATTACHINFO` region that follows (system
//! path, log path, attached-database records) lives at a *different* base
//! offset in `.log` (`0x48`) than in `.chk` (`0x30`), so it is decoded
//! separately by the shared scanner in [`super::params`].

use forensic_rs::err::ForensicResult;

use crate::ese::checksum::{self, ChecksumVerdict, NotVerifiedReason};
use crate::ese::signature::{LogTimestamp, Signature};

/// Valid ESE log sector sizes, mirroring the database's `VALID_PAGE_SIZES`
/// (`header.rs`) -- rejecting anything else here is what keeps every later
/// offset (`cb_sec * csec_lg_file`, a sector's byte offset, ...) from being
/// derived from an attacker-chosen, unbounded value.
const VALID_SECTOR_SIZES: [u16; 5] = [512, 1024, 2048, 4096, 8192];

/// On-disk overlay for the fixed `0x00..0x48` prefix of `LOGFILEHDR`.
#[repr(C, packed)]
pub struct LogFileHeaderRpr {
    pub checksum: u32,
    pub generation: u32,
    pub cb_sec: u16,
    pub csec_header: u16,
    pub csec_lg_file: u16,
    pub cb_page_size: u16,
    pub tm_create: u64,
    pub tm_prev_gen: u64,
    pub major: u32,
    pub minor: u32,
    pub update_major: u32,
    pub log_signature: [u8; 28],
}

/// Safe, owned view of a transaction log file's header.
#[derive(Debug)]
pub struct LogFileHeader {
    pub checksum: u32,
    pub generation: u32,
    /// Sector size in bytes (`cbSec`).
    pub sector_size: u16,
    /// Number of sectors occupied by the header (`csecHeader`).
    pub header_sectors: u16,
    /// Total sectors in the file (`csecLGFile`).
    pub file_sectors: u16,
    /// The *attached database's* page size (`cbPageSize`) -- not validated
    /// against the set of known-good ESE page sizes, because a mismatch
    /// here is evidence about the log/database pairing, not a parse error.
    pub database_page_size: u16,
    pub created: LogTimestamp,
    pub previous_generation_created: LogTimestamp,
    pub major: u32,
    pub minor: u32,
    pub update_major: u32,
    pub log_signature: Signature,
}

impl LogFileHeader {
    /// Parse the fixed `0x00..0x48` prefix. Only geometry whose corruption
    /// makes every later offset arbitrary is a hard error here; a bad
    /// checksum or an implausible `database_page_size` is reported as
    /// evidence elsewhere, not rejected at parse time.
    pub fn from_buff(buffer: &[u8]) -> ForensicResult<Self> {
        forensic_rs::ensure_min_length!(
            std::mem::size_of::<LogFileHeaderRpr>(),
            buffer.len(),
            "ESE log file header"
        );
        // SAFETY: `LogFileHeaderRpr` is `#[repr(C, packed)]` (alignment 1)
        // and every field is a plain integer or byte array -- any bit
        // pattern is a valid instance, so `align_to` cannot produce an
        // invalid value. Alignment 1 also means `head` is always empty; the
        // length check above (not `head.is_empty()`, which is always true)
        // is what actually matters.
        let (head, data, _tail) = unsafe { buffer.align_to::<LogFileHeaderRpr>() };
        if !head.is_empty() || data.is_empty() {
            return Err(forensic_rs::err::ForensicError::invalid_format(
                "ESE log",
                "Invalid alignement",
            ));
        }
        let repr = &data[0];
        let cb_sec = repr.cb_sec;
        forensic_rs::ensure_format!(
            VALID_SECTOR_SIZES.contains(&cb_sec),
            "ESE log",
            "invalid sector size"
        );
        let csec_header = repr.csec_header;
        let csec_lg_file = repr.csec_lg_file;
        forensic_rs::ensure_format!(csec_header > 0, "ESE log", "csecHeader must be nonzero");
        forensic_rs::ensure_format!(
            csec_lg_file > csec_header,
            "ESE log",
            "csecLGFile must exceed csecHeader"
        );
        // Defense in depth: `declared_file_size` below also checks this, but
        // failing here means a caller can never even construct a
        // `LogFileHeader` whose own geometry cannot address itself.
        (cb_sec as usize).checked_mul(csec_lg_file as usize).ok_or_else(|| {
            forensic_rs::invalid_offset!(
                "ESE log declared_file_size",
                csec_lg_file as i64,
                cb_sec as u64
            )
        })?;

        let mut log_signature_raw = [0u8; 28];
        log_signature_raw.copy_from_slice(&repr.log_signature);

        Ok(Self {
            checksum: repr.checksum,
            generation: repr.generation,
            sector_size: cb_sec,
            header_sectors: csec_header,
            file_sectors: csec_lg_file,
            database_page_size: repr.cb_page_size,
            created: LogTimestamp::from_raw(repr.tm_create.to_le_bytes()),
            previous_generation_created: LogTimestamp::from_raw(repr.tm_prev_gen.to_le_bytes()),
            major: repr.major,
            minor: repr.minor,
            update_major: repr.update_major,
            log_signature: Signature::from_buff(&log_signature_raw)?,
        })
    }

    /// `file_sectors * sector_size`, checked. Already validated not to
    /// overflow at parse time; this is the accessor callers should use
    /// rather than repeating the multiplication.
    pub fn declared_file_size(&self) -> ForensicResult<usize> {
        (self.sector_size as usize).checked_mul(self.file_sectors as usize).ok_or_else(|| {
            forensic_rs::invalid_offset!(
                "ESE log declared_file_size",
                self.file_sectors as i64,
                self.sector_size as u64
            )
        })
    }

    /// The sector-index range that holds log data (excludes the header
    /// sectors at the front).
    pub fn data_sector_range(&self) -> std::ops::Range<u16> {
        self.header_sectors..self.file_sectors
    }

    /// Verify the header checksum against `sector0` (the first `sector_size`
    /// bytes of the file). Returns `NotVerified` (never a fabricated
    /// `Mismatch`) when `sector0` is too short to cover the checksum region.
    pub fn verify_checksum(&self, sector0: &[u8]) -> ChecksumVerdict {
        match checksum::log_file_header_checksum(sector0, self.sector_size) {
            Ok(computed) if computed == self.checksum => ChecksumVerdict::Match,
            Ok(computed) => ChecksumVerdict::Mismatch { stored: self.checksum, computed },
            Err(_) => ChecksumVerdict::NotVerified { reason: NotVerifiedReason::RegionUnknown },
        }
    }
}

#[cfg(test)]
mod tst {
    use super::*;

    fn valid_header_bytes() -> Vec<u8> {
        let mut buf = vec![0u8; std::mem::size_of::<LogFileHeaderRpr>()];
        buf[8..10].copy_from_slice(&4096u16.to_le_bytes()); // cb_sec
        buf[10..12].copy_from_slice(&1u16.to_le_bytes()); // csec_header
        buf[12..14].copy_from_slice(&16u16.to_le_bytes()); // csec_lg_file
        buf[14..16].copy_from_slice(&4096u16.to_le_bytes()); // cb_page_size
        buf
    }

    #[test]
    fn accepts_a_synthetic_valid_header() {
        let header = LogFileHeader::from_buff(&valid_header_bytes()).unwrap();
        assert_eq!(header.sector_size, 4096);
        assert_eq!(header.header_sectors, 1);
        assert_eq!(header.file_sectors, 16);
        assert_eq!(header.declared_file_size().unwrap(), 65536);
        assert_eq!(header.data_sector_range(), 1..16);
    }

    #[test]
    fn rejects_zero_sector_size() {
        let mut buf = valid_header_bytes();
        buf[8..10].copy_from_slice(&0u16.to_le_bytes());
        assert!(LogFileHeader::from_buff(&buf).is_err());
    }

    #[test]
    fn rejects_sector_size_of_three() {
        let mut buf = valid_header_bytes();
        buf[8..10].copy_from_slice(&3u16.to_le_bytes());
        assert!(LogFileHeader::from_buff(&buf).is_err());
    }

    #[test]
    fn rejects_csec_lg_file_not_exceeding_csec_header() {
        let mut buf = valid_header_bytes();
        buf[10..12].copy_from_slice(&5u16.to_le_bytes());
        buf[12..14].copy_from_slice(&5u16.to_le_bytes());
        assert!(LogFileHeader::from_buff(&buf).is_err());

        let mut buf2 = valid_header_bytes();
        buf2[10..12].copy_from_slice(&5u16.to_le_bytes());
        buf2[12..14].copy_from_slice(&3u16.to_le_bytes());
        assert!(LogFileHeader::from_buff(&buf2).is_err());
    }

    #[test]
    fn declared_file_size_uses_checked_mul() {
        let mut buf = valid_header_bytes();
        buf[8..10].copy_from_slice(&8192u16.to_le_bytes());
        buf[12..14].copy_from_slice(&u16::MAX.to_le_bytes());
        // Must not panic; 8192 * 65535 fits in a 64-bit usize, so this
        // succeeds -- the guarantee under test is "no panic on the
        // multiplication", which unwrap() alone already proves.
        let header = LogFileHeader::from_buff(&buf).unwrap();
        let _ = header.declared_file_size().unwrap();
    }

    #[test]
    fn rejects_buffer_shorter_than_fixed_header() {
        assert!(LogFileHeader::from_buff(&[0u8; 10]).is_err());
    }

    #[test]
    fn accepts_implausible_database_page_size_as_evidence_not_error() {
        let mut buf = valid_header_bytes();
        buf[14..16].copy_from_slice(&7u16.to_le_bytes());
        let header = LogFileHeader::from_buff(&buf).unwrap();
        assert_eq!(header.database_page_size, 7);
    }

    #[test]
    fn verify_checksum_reports_not_verified_on_short_sector() {
        let header = LogFileHeader::from_buff(&valid_header_bytes()).unwrap();
        let short_sector = vec![0u8; 10];
        assert_eq!(
            header.verify_checksum(&short_sector),
            ChecksumVerdict::NotVerified { reason: NotVerifiedReason::RegionUnknown }
        );
    }

    #[test]
    fn parses_and_verifies_every_real_log_fixture() {
        let cases = [
            ("./artifacts/sru/SRU.log", 185u32),
            ("./artifacts/sru/SRU000B6.log", 182u32),
            ("./artifacts/sru/SRU000B7.log", 183u32),
            ("./artifacts/sru/SRU000B8.log", 184u32),
            ("./artifacts/sru/SRUtmp.log", 181u32),
        ];
        for (path, expected_gen) in cases {
            let Ok(bytes) = std::fs::read(path) else {
                eprintln!("SKIP: fixture '{path}' unavailable");
                continue;
            };
            let header = LogFileHeader::from_buff(&bytes).unwrap();
            assert_eq!(header.generation, expected_gen, "{path}");
            assert_eq!(header.sector_size, 4096, "{path}");
            assert_eq!(header.header_sectors, 1, "{path}");
            assert_eq!(header.file_sectors, 16, "{path}");
            assert_eq!(header.database_page_size, 4096, "{path}");
            assert_eq!(header.declared_file_size().unwrap(), bytes.len(), "{path}");
            assert_eq!(header.verify_checksum(&bytes), ChecksumVerdict::Match, "{path}");
            assert_eq!(header.major, 8, "{path}");
            assert_eq!(header.minor, 4000, "{path}");
            assert_eq!(header.update_major, 5, "{path}");
        }
    }

    #[test]
    fn tm_prev_gen_chain_is_byte_exact_across_all_generations() {
        let paths = [
            "./artifacts/sru/SRUtmp.log",
            "./artifacts/sru/SRU000B6.log",
            "./artifacts/sru/SRU000B7.log",
            "./artifacts/sru/SRU000B8.log",
            "./artifacts/sru/SRU.log",
        ];
        let mut headers = Vec::new();
        for path in paths {
            let Ok(bytes) = std::fs::read(path) else {
                eprintln!("SKIP: fixture '{path}' unavailable");
                return;
            };
            headers.push(LogFileHeader::from_buff(&bytes).unwrap());
        }
        for pair in headers.windows(2) {
            let (older, newer) = (&pair[0], &pair[1]);
            assert_eq!(
                newer.previous_generation_created.raw(),
                older.created.raw(),
                "chain break: gen {} -> gen {}",
                older.generation,
                newer.generation
            );
        }
    }

    #[test]
    fn all_five_logs_share_one_signature() {
        let paths = [
            "./artifacts/sru/SRU.log",
            "./artifacts/sru/SRU000B6.log",
            "./artifacts/sru/SRU000B7.log",
            "./artifacts/sru/SRU000B8.log",
            "./artifacts/sru/SRUtmp.log",
        ];
        let mut signatures = Vec::new();
        for path in paths {
            let Ok(bytes) = std::fs::read(path) else {
                eprintln!("SKIP: fixture '{path}' unavailable");
                return;
            };
            signatures.push(LogFileHeader::from_buff(&bytes).unwrap().log_signature);
        }
        for sig in &signatures[1..] {
            assert_eq!(sig, &signatures[0], "signLog mismatch across the fixture set");
        }
    }
}
