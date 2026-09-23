//! The ESE checkpoint file (`.chk`): a fixed-size file recording where log
//! replay should resume from. Unlike a transaction log, its checksum covers
//! the *entire* file, so [`CheckpointFile`] is fully eager and owned -- no
//! [`crate::ese::reader::PageReader`], no held file descriptor.
//!
//! **Verified structural note:** `artifacts/sru/SRU.chk` (8192 bytes) is two
//! byte-identical 4096-byte halves. This is the checkpoint file's own
//! torn-write guard -- the same idea as a transaction log's per-sector
//! shadow copy (see [`super::sector::SectorClass::Shadow`]), just applied at
//! whole-file granularity. Because of this, [`super::params::LogParams::scan`]
//! honestly finds every `ATTACHINFO` record twice when both halves are
//! present and identical -- this is not a bug in the scanner, and code
//! consuming [`CheckpointFile::params`] must not assume attachments are
//! deduplicated.

use std::path::Path;

use forensic_rs::err::ForensicResult;

use crate::ese::checksum::{self, ChecksumVerdict, NotVerifiedReason};
use crate::ese::lgpos::Lgpos;
use crate::ese::signature::Signature;

use super::params::LogParams;

/// Minimum length: `4` (checksum) + `8` (lgposLastFullBackupCheckpoint) +
/// `8` (lgposCheckpoint) + `28` (signLog) = `0x30`.
const MIN_CHECKPOINT_LEN: usize = 0x30;

/// The parsed, fixed-layout fields of a checkpoint file.
#[derive(Debug)]
pub struct Checkpoint {
    pub checksum: u32,
    pub last_full_backup_checkpoint: Lgpos,
    pub checkpoint: Lgpos,
    pub log_signature: Signature,
}

/// A fully-parsed checkpoint file, including its checksum verdict and any
/// `DBMS_PARAM`/`ATTACHINFO` records found past the fixed header.
#[derive(Debug)]
pub struct CheckpointFile {
    pub checkpoint: Checkpoint,
    pub checksum_status: ChecksumVerdict,
    /// Best-effort; `None` never fails the parse.
    pub params: Option<LogParams>,
    pub size: usize,
}

/// Base offset of the `DBMS_PARAM`/`ATTACHINFO` region within a checkpoint
/// file -- immediately after `signLog`. Verified at `0x30` in
/// `artifacts/sru/SRU.chk`; distinct from the `0x48` base used in a log file
/// header, which is exactly why the region is decoded by a shared,
/// base-parameterized scanner rather than a hardcoded offset.
const PARAMS_BASE: usize = 0x30;

impl CheckpointFile {
    /// Parse a whole checkpoint file from its bytes.
    pub fn from_buff(buffer: &[u8]) -> ForensicResult<Self> {
        forensic_rs::ensure_min_length!(MIN_CHECKPOINT_LEN, buffer.len(), "ESE checkpoint");

        let checksum = u32::from_le_bytes(buffer[0..4].try_into().unwrap_or_default());
        let last_full_backup_checkpoint = Lgpos::from_buff(&buffer[4..12])?;
        let checkpoint = Lgpos::from_buff(&buffer[12..20])?;
        let log_signature = Signature::from_buff(&buffer[0x14..0x14 + Signature::SIZE])?;

        let checksum_status = if !buffer.len().is_multiple_of(4) {
            // xor32_le silently ignores a trailing partial word; report that
            // honestly rather than computing over an incomplete picture.
            ChecksumVerdict::NotVerified { reason: NotVerifiedReason::RegionUnknown }
        } else {
            let computed = checksum::checkpoint_checksum(buffer);
            if computed == checksum {
                ChecksumVerdict::Match
            } else {
                ChecksumVerdict::Mismatch { stored: checksum, computed }
            }
        };

        let params = if buffer.len() > PARAMS_BASE {
            LogParams::scan(&buffer[PARAMS_BASE..], &super::params::AttachScanContext::unbounded())
                .ok()
        } else {
            None
        };

        Ok(Self {
            checkpoint: Checkpoint { checksum, last_full_backup_checkpoint, checkpoint, log_signature },
            checksum_status,
            params,
            size: buffer.len(),
        })
    }

    pub fn open(path: impl AsRef<Path>) -> ForensicResult<Self> {
        let bytes = std::fs::read(path.as_ref()).map_err(|e| {
            forensic_rs::err::ForensicError::io_error_with_source(e, "Cannot open ESE checkpoint file")
        })?;
        Self::from_buff(&bytes)
    }

    pub fn from_virtual_file(mut file: Box<dyn forensic_rs::traits::vfs::VirtualFile>) -> ForensicResult<Self> {
        use std::io::Read;
        let mut buf = Vec::new();
        file.read_to_end(&mut buf)
            .map_err(|e| forensic_rs::err::ForensicError::io_error_with_source(e, "ESE checkpoint read"))?;
        Self::from_buff(&buf)
    }

    /// Resolve the checkpoint position to `(generation, byte offset within
    /// that log file)`, given the log set's sector size.
    pub fn resolve(&self, cb_sec: u16) -> ForensicResult<(u32, usize)> {
        Ok((self.checkpoint.checkpoint.generation, self.checkpoint.checkpoint.byte_offset(cb_sec)?))
    }
}

#[cfg(test)]
mod tst {
    use super::*;

    fn synthetic_checkpoint(checksum_correct: bool) -> Vec<u8> {
        let mut buf = vec![0u8; 8192];
        buf[12..14].copy_from_slice(&0u16.to_le_bytes()); // checkpoint.ib
        buf[14..16].copy_from_slice(&5u16.to_le_bytes()); // checkpoint.isec
        buf[16..20].copy_from_slice(&185u32.to_le_bytes()); // checkpoint.generation
        let computed = checksum::checkpoint_checksum(&buf);
        if checksum_correct {
            buf[0..4].copy_from_slice(&computed.to_le_bytes());
        } else {
            buf[0..4].copy_from_slice(&(computed ^ 0xFFFF_FFFF).to_le_bytes());
        }
        buf
    }

    #[test]
    fn accepts_synthetic_checkpoint_with_correct_checksum() {
        let buf = synthetic_checkpoint(true);
        let file = CheckpointFile::from_buff(&buf).unwrap();
        assert_eq!(file.checksum_status, ChecksumVerdict::Match);
        assert_eq!(
            file.checkpoint.checkpoint,
            Lgpos { generation: 185, sector: 5, byte: 0 }
        );
    }

    #[test]
    fn detects_corrupted_checksum() {
        let buf = synthetic_checkpoint(false);
        let file = CheckpointFile::from_buff(&buf).unwrap();
        assert!(matches!(file.checksum_status, ChecksumVerdict::Mismatch { .. }));
    }

    #[test]
    fn reports_not_verified_when_length_not_a_multiple_of_four() {
        let mut buf = synthetic_checkpoint(true);
        buf.push(0xAB);
        let file = CheckpointFile::from_buff(&buf).unwrap();
        assert_eq!(
            file.checksum_status,
            ChecksumVerdict::NotVerified { reason: NotVerifiedReason::RegionUnknown }
        );
    }

    #[test]
    fn rejects_too_short_buffer() {
        assert!(CheckpointFile::from_buff(&[0u8; 0x2F]).is_err());
    }

    #[test]
    fn real_fixture_matches_verified_checkpoint_position() {
        let Ok(bytes) = std::fs::read("./artifacts/sru/SRU.chk") else {
            eprintln!("SKIP: fixture unavailable");
            return;
        };
        let file = CheckpointFile::from_buff(&bytes).unwrap();
        assert_eq!(file.checksum_status, ChecksumVerdict::Match);
        assert_eq!(
            file.checkpoint.checkpoint,
            Lgpos { generation: 185, sector: 5, byte: 0 }
        );
        assert!(file.checkpoint.last_full_backup_checkpoint.is_null());
        assert_eq!(file.resolve(4096).unwrap(), (185, 5 * 4096));
    }
}
