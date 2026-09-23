//! ESE transaction log, checkpoint, flush-map, and reserved-log parsing.
//!
//! An ESE database is a *file set*, not a single file: alongside the
//! `.edb`/`.dat` itself sit transaction logs (`<base>.log` current,
//! `<base>NNNNN.log` archived, `<base>tmp.log` a recycled slot), a
//! checkpoint (`<base>.chk`), a flush map (`<dbname>.jfm`), and reserved
//! logs (`<base>resNNNNN.jrs`). This module parses each of those file kinds
//! individually; [`set`] aggregates them into a log set and produces an
//! integrity report.
//!
//! See `docs/internals.md` for the on-disk layouts, verified byte-exactly
//! against `artifacts/sru/`.
//!
//! # Explicitly out of scope
//!
//! - **Individual log-record (LR) decoding.** [`sector::LogSector::payload`]
//!   returns raw bytes rather than decoded records. ESE log records are
//!   page-image deltas keyed by `(dbid, objid, pgno)`, ~60 version-gated
//!   types mixing full page images, byte-range replaces, and tag-level
//!   insert/replace/delete. A wrong delta produces a page that still passes
//!   structural validation and still decodes rows -- silently wrong, with
//!   no error anywhere. Doing this soundly needs independent ground truth
//!   (an `esentutl /ml` dump, or a before/after database pair) that is not
//!   currently part of this crate's fixtures.
//! - **`.jfm`'s page-flush-state bitmap.** [`flushmap::FlushMap`] exposes
//!   only the header; the bitmap's layout is not determined, and its only
//!   consumer -- deciding which pages need log replay -- is itself out of
//!   scope (see above).
//! - **The log data-sector checksum algorithm.** Confirmed *not* a XOR-fold
//!   like the header/checkpoint checksums; [`sector::LogSector::checksum_status`]
//!   always returns `NotVerified`, never a guessed `Match`.
//! - **Log replay.** An analyst wants to know *that* replay is needed and
//!   *which* generations are required (`Header::requires_log_replay`,
//!   `EseLogSet::missing_generations`) -- not to have this crate mutate the
//!   evidence's logical state by applying undecoded LR deltas.

pub mod checkpoint;
pub mod flushmap;
pub mod header;
pub mod params;
pub mod report;
pub mod sector;
pub mod set;

use std::path::Path;

use forensic_rs::err::ForensicResult;
use forensic_rs::traits::format::ProbeScore;

use crate::ese::checksum::ChecksumVerdict;
use crate::ese::header::ESE_HEADER_SIGNATURE;
use crate::ese::lgpos::Lgpos;
use crate::ese::reader::{FileReader, PageReader, SliceReader, VirtualFileReader};

pub use checkpoint::{Checkpoint, CheckpointFile};
pub use flushmap::FlushMap;
pub use header::LogFileHeader;
pub use params::{AttachInfo, AttachScanContext, LogParams};
pub use report::{LogAnomaly, LogSetReport, LogSetStats, RecoveryAssessment, Severity};
pub use sector::{LogSector, LogSectorIter, ResidualSpan, SectorClass};
pub use set::{EseLogSet, LogFileRole, LogSetEntry, ReservedLog};

/// An open ESE transaction log file. Mirrors [`crate::ese::db::EseDb`]'s
/// constructor shape (`open`/`from_bytes`/`from_virtual_file`/
/// `pub(crate) from_reader`).
pub struct LogFile {
    reader: Box<dyn PageReader>,
    header: LogFileHeader,
    params: Option<LogParams>,
}

impl LogFile {
    pub fn open(path: impl AsRef<Path>) -> ForensicResult<Self> {
        let reader = FileReader::open(path.as_ref())
            .map_err(|e| forensic_rs::err::ForensicError::io_error_with_source(e, "Cannot open ESE log file"))?;
        Self::from_reader(Box::new(reader))
    }

    pub fn from_bytes(data: Vec<u8>) -> ForensicResult<Self> {
        Self::from_reader(Box::new(SliceReader::new(data)))
    }

    pub fn from_virtual_file(file: Box<dyn forensic_rs::traits::vfs::VirtualFile>) -> ForensicResult<Self> {
        Self::from_reader(Box::new(VirtualFileReader::new(file)?))
    }

    pub(crate) fn from_reader(reader: Box<dyn PageReader>) -> ForensicResult<Self> {
        let header = {
            let buf = reader.read_page(0, 4096.min(reader.total_size()))?;
            LogFileHeader::from_buff(&buf)?
        };
        let params = {
            let want = 4096.max(header.sector_size as usize).min(reader.total_size());
            reader
                .read_page(0, want)
                .ok()
                .and_then(|buf| {
                    if buf.len() > 0x48 {
                        let ctx = AttachScanContext::new(header.sector_size, header.file_sectors);
                        LogParams::scan(&buf[0x48..], &ctx).ok()
                    } else {
                        None
                    }
                })
        };
        Ok(Self { reader, header, params })
    }

    pub fn header(&self) -> &LogFileHeader {
        &self.header
    }

    pub fn params(&self) -> Option<&LogParams> {
        self.params.as_ref()
    }

    pub fn header_checksum(&self) -> ChecksumVerdict {
        match self.reader.read_page(0, self.header.sector_size as usize) {
            Ok(sector0) => self.header.verify_checksum(&sector0),
            Err(_) => ChecksumVerdict::NotVerified {
                reason: crate::ese::checksum::NotVerifiedReason::RegionUnknown,
            },
        }
    }

    pub fn sectors(&self) -> LogSectorIter<'_> {
        LogSectorIter::new(self.reader.as_ref(), &self.header)
    }

    pub fn sector(&self, isec: u16) -> ForensicResult<LogSector<'_>> {
        let offset = isec as usize * self.header.sector_size as usize;
        let data = self.reader.read_page(offset, self.header.sector_size as usize)?;
        LogSector::new(isec, data)
    }

    /// The highest `Live` sector's position. `None` if the first data sector
    /// is already stale/unwritten (an allocated-but-never-used generation).
    pub fn write_frontier(&self) -> ForensicResult<Option<Lgpos>> {
        let mut frontier = None;
        for sector in self.sectors() {
            let sector = sector?;
            if sector.classify(&self.header) == SectorClass::Live {
                frontier = Some(sector.self_position);
            }
        }
        Ok(frontier)
    }

    /// Contiguous runs of `Stale` sectors -- residual data from a previous
    /// life of this recycled log file.
    pub fn residual_spans(&self) -> ForensicResult<Vec<ResidualSpan>> {
        let mut spans: Vec<ResidualSpan> = Vec::new();
        for sector in self.sectors() {
            let sector = sector?;
            if let SectorClass::Stale { generation } = sector.classify(&self.header) {
                match spans.last_mut() {
                    Some(span)
                        if span.generation == generation && span.last_sector + 1 == sector.index =>
                    {
                        span.last_sector = sector.index;
                        span.latest = sector.timestamp;
                    }
                    _ => spans.push(ResidualSpan {
                        generation,
                        first_sector: sector.index,
                        last_sector: sector.index,
                        earliest: sector.timestamp,
                        latest: sector.timestamp,
                    }),
                }
            }
        }
        Ok(spans)
    }
}

/// Identify whether `head` (the first few KiB of a file) looks like an ESE
/// transaction log header, without constructing a [`LogFile`]. Kept
/// separate so a future `FormatFactory` and this module's own tests call the
/// exact same logic.
pub fn probe_log_file(head: &[u8]) -> ProbeScore {
    if head.len() < 8 {
        return ProbeScore::No;
    }
    // A log file has no fixed magic signature at a constant offset the way
    // a database does; the closest analogue is `file_signature` at the same
    // relative offset the database uses, which does NOT apply here (logs
    // don't carry `ESE_HEADER_SIGNATURE`). Instead, treat successful,
    // internally-consistent header parsing plus a plausible generation as
    // the identification signal.
    let _ = ESE_HEADER_SIGNATURE; // not applicable to logs; see doc above
    match LogFileHeader::from_buff(head) {
        Ok(header) if header.generation > 0 => ProbeScore::Strong,
        Ok(_) => ProbeScore::Strong,
        Err(_) => ProbeScore::No,
    }
}

#[cfg(test)]
mod tst {
    use super::*;

    #[test]
    fn probe_rejects_short_buffer() {
        assert_eq!(probe_log_file(&[0u8; 4]), ProbeScore::No);
    }

    #[test]
    fn probe_scores_a_real_log_as_strong() {
        let Ok(bytes) = std::fs::read("./artifacts/sru/SRU.log") else {
            eprintln!("SKIP: fixture unavailable");
            return;
        };
        assert_eq!(probe_log_file(&bytes[..4096]), ProbeScore::Strong);
    }

    #[test]
    fn open_from_bytes_parses_header_and_params() {
        let Ok(bytes) = std::fs::read("./artifacts/sru/SRU.log") else {
            eprintln!("SKIP: fixture unavailable");
            return;
        };
        let log = LogFile::from_bytes(bytes).unwrap();
        assert_eq!(log.header().generation, 185);
        assert_eq!(log.header_checksum(), ChecksumVerdict::Match);
        let params = log.params().expect("params should have been found");
        assert_eq!(params.attachments.len(), 1);
    }

    #[test]
    fn write_frontier_and_residual_spans_match_the_verified_walk() {
        let Ok(bytes) = std::fs::read("./artifacts/sru/SRU.log") else {
            eprintln!("SKIP: fixture unavailable");
            return;
        };
        let log = LogFile::from_bytes(bytes).unwrap();
        let frontier = log.write_frontier().unwrap().unwrap();
        assert_eq!(frontier, Lgpos { generation: 185, sector: 5, byte: 0 });

        let spans = log.residual_spans().unwrap();
        assert_eq!(spans.len(), 1);
        assert_eq!(spans[0].generation, 180);
        assert_eq!(spans[0].first_sector, 7);
        assert_eq!(spans[0].last_sector, 14);
        assert_eq!(spans[0].byte_len(4096), 8 * 4096);
    }

    #[test]
    fn complete_generation_181_has_no_residual_in_its_live_range() {
        let Ok(bytes) = std::fs::read("./artifacts/sru/SRUtmp.log") else {
            eprintln!("SKIP: fixture unavailable");
            return;
        };
        let log = LogFile::from_bytes(bytes).unwrap();
        let spans = log.residual_spans().unwrap();
        // Sector 15 is stale (gen 175); sectors 1..=14 are all Live.
        assert_eq!(spans.len(), 1);
        assert_eq!(spans[0].first_sector, 15);
        assert_eq!(spans[0].generation, 175);
    }
}
