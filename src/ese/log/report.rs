//! The log-set integrity report: [`LogAnomaly`], [`LogSetReport`], and the
//! three-way split this crate uses everywhere else (`ForensicError` for
//! geometry so broken that every later offset is arbitrary; `warn!`/`debug!`
//! for tracing; everything else as structured data).
//!
//! Every [`LogAnomaly`] variant carries the observed and expected values
//! that produced it -- never prose -- and [`LogAnomaly::benign_explanation`]
//! states, in the type itself, the innocent explanation an examiner must
//! rule out before treating the anomaly as evidence of tampering. Losing
//! that guidance between analysis and report is exactly the failure mode
//! this module is built to prevent.

use crate::ese::header::{DatabaseState, Header};
use crate::ese::lgpos::Lgpos;

use super::set::{EseLogSet, LogFileRole};

/// Severity of a [`LogAnomaly`], loosely mirroring
/// `forensic_rs::pipeline::finding::FindingSeverity`.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Debug)]
pub enum Severity {
    Info,
    Low,
    Medium,
    High,
    Critical,
}

/// One integrity finding about a log set. `#[non_exhaustive]` so a
/// consumer's `match` cannot silently become non-exhaustive-but-compiling
/// when a new variant is added; use the accessor methods instead of
/// matching directly wherever possible.
#[non_exhaustive]
#[derive(Clone, Debug)]
pub enum LogAnomaly {
    /// Two files in the same set disagree on `signLog`. Benign explanation:
    /// two different log sets were collected into one directory.
    LogSignatureMismatch { file: String, observed: [u8; 28], expected: [u8; 28], expected_from: String },
    /// The database's `log_signature` does not match the log set's shared
    /// signature. Benign explanation: the logs belong to a different
    /// instance of the database (e.g. after a rebuild).
    DatabaseLogSignatureMismatch { db_observed: [u8; 28], log_expected: [u8; 28], log_file: String },
    /// No `ATTACHINFO` record in the log set names this database. Benign
    /// explanation: a log set attached to multiple databases, none matching
    /// this one exactly (only fires when *no* attachment matches).
    AttachedDbSignatureMismatch { log_file: String, db_observed: [u8; 28] },
    /// A generation between the lowest and highest present has no file.
    /// Benign explanation: ESE deletes logs below the checkpoint; a full
    /// backup truncates the set. Only reaches `Medium` when
    /// `inside_required_range` is true.
    GenerationGap { after: u32, before: u32, missing: Vec<u32>, inside_required_range: bool },
    /// `tmPrevGen(generation) != tmCreate(generation - 1)` as a raw 8-byte
    /// compare, with both generations present. Benign explanation: none,
    /// when both files and both timestamps are genuinely present -- a
    /// missing generation is `GenerationGap`, not this.
    PreviousGenerationTimeBreak {
        file: String,
        generation: u32,
        tm_prev_gen: [u8; 8],
        predecessor_tm_create: [u8; 8],
        predecessor_file: String,
    },
    /// The database states it needs generations in
    /// `min_required..=max_required` to become consistent, and at least one
    /// is absent from the collected set. No benign explanation -- this caps
    /// what can be concluded from the evidence as collected.
    RequiredGenerationsMissing { min_required: u32, max_required: u32, missing: Vec<u32> },
    /// The checkpoint names a generation higher than any log file present.
    /// Benign explanation: the current log was not collected.
    CheckpointAheadOfLogs { checkpoint: Lgpos, highest_generation_present: u32 },
    /// Two files in the set claim the same header generation with different
    /// content. Benign explanation: a temp/reserve file recycling an old
    /// generation is *not* this (see
    /// [`super::set::LogFileRole::Temp`]) -- only fires between two
    /// non-temp files.
    DuplicateGeneration { generation: u32, files: Vec<String> },
    /// A log file's header checksum does not match
    /// `checksum::log_file_header_checksum`. Benign explanation: a
    /// zero-filled reserve log has no valid checksum by construction and is
    /// classified before this rule ever runs.
    HeaderChecksumMismatch { file: String, stored: u32, computed: u32 },
    /// The checkpoint file's whole-file checksum does not match.
    CheckpointChecksumMismatch { stored: u32, computed: u32 },
    /// `csecLGFile * cbSec` does not equal the file's actual size. Benign
    /// explanation: the log was still being written, or was padded by the
    /// collection tool.
    DeclaredSizeMismatch { file: String, declared_bytes: u64, actual_bytes: u64 },
    /// A log's `cbPageSize` does not match the database's `page_size`.
    /// Benign explanation: usually none -- this log set most likely belongs
    /// to a different database.
    PageSizeMismatch { file: String, log_page_size: u16, db_page_size: u32 },
    /// A `.jrs` reserve log is not entirely zero-filled. Benign explanation:
    /// some ESE versions pre-stamp a header into the reserve file; treat as
    /// low-severity until corroborated by a second fixture.
    ReserveLogNotZeroFilled { file: String, first_nonzero_offset: usize },
    /// The database's `state` is not `CleanShutdown`. Benign explanation:
    /// entirely normal on a live-acquired or power-cut system; severity
    /// depends on whether the required generations are all present.
    DatabaseNotCleanlyShutDown { state: DatabaseState, min_required: u32, max_required: u32 },
}

impl LogAnomaly {
    pub fn severity(&self) -> Severity {
        use LogAnomaly::*;
        match self {
            LogSignatureMismatch { .. } => Severity::Critical,
            DatabaseLogSignatureMismatch { .. } => Severity::Critical,
            AttachedDbSignatureMismatch { .. } => Severity::High,
            GenerationGap { inside_required_range, .. } => {
                if *inside_required_range {
                    Severity::Medium
                } else {
                    Severity::Info
                }
            }
            PreviousGenerationTimeBreak { .. } => Severity::High,
            RequiredGenerationsMissing { .. } => Severity::Critical,
            CheckpointAheadOfLogs { .. } => Severity::High,
            DuplicateGeneration { .. } => Severity::Medium,
            HeaderChecksumMismatch { .. } => Severity::High,
            CheckpointChecksumMismatch { .. } => Severity::High,
            DeclaredSizeMismatch { .. } => Severity::Medium,
            PageSizeMismatch { .. } => Severity::High,
            ReserveLogNotZeroFilled { .. } => Severity::Info,
            DatabaseNotCleanlyShutDown { .. } => Severity::Medium,
        }
    }

    /// The benign explanation an examiner should rule out before treating
    /// this anomaly as tampering evidence. Kept in the type itself so it
    /// cannot be dropped between analysis and report.
    pub fn benign_explanation(&self) -> &'static str {
        use LogAnomaly::*;
        match self {
            LogSignatureMismatch { .. } => {
                "Two different log sets were collected into one directory (e.g. two copies, \
                 or a VSS-restored file mixed with live ones). Check containing paths and file \
                 times before calling it tampering."
            }
            DatabaseLogSignatureMismatch { .. } => {
                "The database was copied from a different machine/instance than the logs, or \
                 the logs are from a rebuilt database. Either way the log set cannot be \
                 replayed into this database, which is the reportable conclusion -- not \
                 necessarily malicious."
            }
            AttachedDbSignatureMismatch { .. } => {
                "A log set can legitimately be attached to multiple databases (normal for \
                 Exchange); this only fires when none of the attachments match this database."
            }
            GenerationGap { .. } => {
                "ESE deletes logs below the checkpoint; a full backup truncates the set; a \
                 collection script may have grabbed files mid-roll. Only reaches Medium \
                 severity when the gap falls inside the database's required-generation range."
            }
            PreviousGenerationTimeBreak { .. } => {
                "None, when both files and both timestamps are genuinely present -- a missing \
                 generation is reported separately as GenerationGap, not this."
            }
            RequiredGenerationsMissing { .. } => {
                "Usually an incomplete collection rather than tampering; either way it caps \
                 what can be concluded from the evidence as collected."
            }
            CheckpointAheadOfLogs { .. } => {
                "The current log was not collected -- extremely common when only archived logs \
                 were pulled and the live '.log' file was skipped."
            }
            DuplicateGeneration { .. } => {
                "A recycled temp/reserve file holding an old generation is normal ESE behavior \
                 and is excluded from this rule; this only fires between two non-temp files."
            }
            HeaderChecksumMismatch { .. } => {
                "A zero-filled reserve log has no valid checksum by construction and is never \
                 subject to this rule; a torn write during collection, or a truncated file, \
                 can also produce this."
            }
            CheckpointChecksumMismatch { .. } => {
                "A checkpoint file staler than the logs is written lazily by the engine and can \
                 legitimately fail to match if collected mid-write."
            }
            DeclaredSizeMismatch { .. } => {
                "The log may have still been open/being written at collection time (short), or \
                 padded by the collection tool (long)."
            }
            PageSizeMismatch { .. } => {
                "Usually none -- this most often means the log set belongs to a different \
                 database than the one being examined; see also DatabaseLogSignatureMismatch."
            }
            ReserveLogNotZeroFilled { .. } => {
                "Some ESE versions/instances pre-stamp a header into the reserve file; this has \
                 only been confirmed absent (all fixtures observed are zero-filled), not \
                 confirmed impossible -- treat at Info severity until corroborated."
            }
            DatabaseNotCleanlyShutDown { .. } => {
                "Entirely normal on a live-acquired or power-cut system. Severity depends on \
                 whether every required generation was collected -- see \
                 RequiredGenerationsMissing."
            }
        }
    }
}

/// What the database's own header says about whether it needs log replay,
/// and whether the collected log set can satisfy that.
#[derive(Clone, Debug)]
pub enum RecoveryAssessment {
    /// `state == CleanShutdown` and `min_required == max_required == 0`.
    NoRecoveryRequired { min_required: u32, max_required: u32 },
    /// The database needs replay; `present`/`missing` describe what of the
    /// required range was actually collected.
    Required { min_required: u32, max_required: u32, present: Vec<u32>, missing: Vec<u32>, satisfiable: bool },
    /// No database header was supplied to [`EseLogSet::report`]. This is
    /// **not** a synonym for "clean" -- callers must not treat it as such.
    Undetermined,
}

/// Diagnostic counters for a log-set report, mirroring
/// [`crate::ese::tree::TreeStats`]'s "here is what was degraded" shape.
#[derive(Clone, Copy, Debug, Default)]
pub struct LogSetStats {
    pub files_seen: usize,
    pub files_parsed: usize,
    pub files_zero_filled: usize,
    pub files_unreadable: usize,
    pub checksums_verified: usize,
    pub checksums_failed: usize,
    pub checksums_not_verified: usize,
}

/// The full report produced by [`EseLogSet::report`].
#[derive(Clone, Debug)]
pub struct LogSetReport {
    pub base_name: String,
    pub generations_present: Vec<u32>,
    pub missing_generations: Vec<u32>,
    pub checkpoint: Option<Lgpos>,
    pub recovery: RecoveryAssessment,
    /// Sectors classified `Stale` across every file in the set -- a normal,
    /// expected, and evidentially valuable observation, kept separate from
    /// `anomalies` deliberately: it is not a defect.
    pub residual_sector_count: usize,
    pub anomalies: Vec<LogAnomaly>,
    pub stats: LogSetStats,
}

impl EseLogSet {
    /// Produce the full integrity report. `db` is optional -- when absent,
    /// `recovery` is `Undetermined` and any anomaly that requires the
    /// database header (signature/page-size cross-checks) is skipped rather
    /// than fabricated.
    pub fn report(&self, db: Option<&Header>) -> LogSetReport {
        let mut anomalies = Vec::new();
        let mut stats = LogSetStats::default();
        let mut residual_sector_count = 0usize;

        stats.files_seen = self.entries.len() + self.reserves.len();

        // ── signLog agreement across the set ──────────────────────────
        let mut reference: Option<(&str, [u8; 28])> = None;
        for entry in &self.entries {
            let observed = entry.header.log_signature.raw;
            match reference {
                None => reference = Some((entry.name.as_str(), observed)),
                Some((ref_name, expected)) if expected != observed => {
                    anomalies.push(LogAnomaly::LogSignatureMismatch {
                        file: entry.name.clone(),
                        observed,
                        expected,
                        expected_from: ref_name.to_string(),
                    });
                }
                _ => {}
            }
        }

        // ── per-file checksum + geometry checks ───────────────────────
        for entry in &self.entries {
            stats.files_parsed += 1;
            match &entry.header_checksum {
                crate::ese::checksum::ChecksumVerdict::Match => stats.checksums_verified += 1,
                crate::ese::checksum::ChecksumVerdict::Mismatch { stored, computed } => {
                    stats.checksums_failed += 1;
                    anomalies.push(LogAnomaly::HeaderChecksumMismatch {
                        file: entry.name.clone(),
                        stored: *stored,
                        computed: *computed,
                    });
                }
                crate::ese::checksum::ChecksumVerdict::NotVerified { .. } => {
                    stats.checksums_not_verified += 1;
                }
            }

            if let Ok(declared) = entry.header.declared_file_size() {
                if declared as u64 != entry.size {
                    anomalies.push(LogAnomaly::DeclaredSizeMismatch {
                        file: entry.name.clone(),
                        declared_bytes: declared as u64,
                        actual_bytes: entry.size,
                    });
                }
            }

            if let Some(db) = db {
                if entry.header.database_page_size != db.page_size as u16 {
                    anomalies.push(LogAnomaly::PageSizeMismatch {
                        file: entry.name.clone(),
                        log_page_size: entry.header.database_page_size,
                        db_page_size: db.page_size,
                    });
                }
            }
        }

        // ── reserve logs: classified before any checksum rule ever
        // applies to them (a zero-filled `.jrs` has no valid checksum by
        // construction, so it is never routed through the log-header
        // checksum logic above at all -- it isn't even parsed as one) ──
        for reserve in &self.reserves {
            if reserve.is_zero_filled {
                stats.files_zero_filled += 1;
            } else {
                anomalies.push(LogAnomaly::ReserveLogNotZeroFilled {
                    file: reserve.name.clone(),
                    first_nonzero_offset: reserve.first_nonzero.unwrap_or(0),
                });
            }
        }

        // ── prev-gen chain, across every generation actually present ──
        // Deliberately includes `Temp`: a recycled temp slot can be the
        // *only* surviving record of a generation (verified:
        // `SRUtmp.log` holds a complete generation 181, with no separate
        // archived file for it), and that generation still participates in
        // the byte-exact `tmCreate`/`tmPrevGen` chain like any other.
        let mut sequence: Vec<_> = self.entries.iter().collect();
        sequence.sort_by_key(|e| e.header.generation);
        for pair in sequence.windows(2) {
            let (older, newer) = (pair[0], pair[1]);
            if newer.header.generation == older.header.generation + 1 {
                let expected = older.header.created.raw();
                let found = newer.header.previous_generation_created.raw();
                if expected != [0u8; 8] && found != [0u8; 8] && expected != found {
                    anomalies.push(LogAnomaly::PreviousGenerationTimeBreak {
                        file: newer.name.clone(),
                        generation: newer.header.generation,
                        tm_prev_gen: found,
                        predecessor_tm_create: expected,
                        predecessor_file: older.name.clone(),
                    });
                }
            }
        }

        // ── generation sequence gaps ───────────────────────────────────
        let mut generations_present: Vec<u32> =
            sequence.iter().map(|e| e.header.generation).collect();
        generations_present.sort_unstable();
        generations_present.dedup();

        let mut missing_generations = Vec::new();
        if let (Some(&lo), Some(&hi)) = (generations_present.first(), generations_present.last()) {
            let (required_lo, required_hi) = db
                .map(|h| (h.min_required_generation, h.max_required_generation))
                .filter(|(lo, hi)| *lo != 0 || *hi != 0)
                .unwrap_or((0, 0));
            let mut run_start: Option<u32> = None;
            for generation in lo..=hi {
                if generations_present.binary_search(&generation).is_err() {
                    missing_generations.push(generation);
                    if run_start.is_none() {
                        run_start = Some(generation);
                    }
                } else if let Some(start) = run_start.take() {
                    let inside_required =
                        required_hi > 0 && start >= required_lo && (generation - 1) <= required_hi;
                    anomalies.push(LogAnomaly::GenerationGap {
                        after: start.saturating_sub(1),
                        before: generation,
                        missing: (start..generation).collect(),
                        inside_required_range: inside_required,
                    });
                }
            }
            if let Some(start) = run_start {
                let inside_required = required_hi > 0 && start >= required_lo && start <= required_hi;
                anomalies.push(LogAnomaly::GenerationGap {
                    after: start.saturating_sub(1),
                    before: hi + 1,
                    missing: (start..=hi).collect(),
                    inside_required_range: inside_required,
                });
            }
        }

        // ── duplicate generations among non-temp files ─────────────────
        // A temp slot recycling an old generation is normal ESE behavior,
        // not a duplicate -- excluded here explicitly (see
        // `LogAnomaly::DuplicateGeneration`'s documentation).
        let mut by_gen: std::collections::BTreeMap<u32, Vec<String>> = Default::default();
        for e in sequence.iter().filter(|e| matches!(e.role, LogFileRole::Current | LogFileRole::Archived)) {
            by_gen.entry(e.header.generation).or_default().push(e.name.clone());
        }
        for (generation, files) in by_gen {
            if files.len() > 1 {
                anomalies.push(LogAnomaly::DuplicateGeneration { generation, files });
            }
        }

        // ── checkpoint cross-checks ────────────────────────────────────
        let checkpoint = self.checkpoint.as_ref().map(|c| c.checkpoint.checkpoint);
        if let Some(cp) = checkpoint {
            if let Some(&highest) = generations_present.last() {
                if cp.generation > highest {
                    anomalies.push(LogAnomaly::CheckpointAheadOfLogs {
                        checkpoint: cp,
                        highest_generation_present: highest,
                    });
                }
            }
            if let Some(chk) = &self.checkpoint {
                if let crate::ese::checksum::ChecksumVerdict::Mismatch { stored, computed } =
                    chk.checksum_status
                {
                    anomalies.push(LogAnomaly::CheckpointChecksumMismatch { stored, computed });
                }
            }
        }

        // ── database-header cross-checks ───────────────────────────────
        let recovery = match db {
            None => RecoveryAssessment::Undetermined,
            Some(header) => {
                if let Some((_, set_signature)) = reference {
                    if header.log_signature.raw != set_signature {
                        anomalies.push(LogAnomaly::DatabaseLogSignatureMismatch {
                            db_observed: header.log_signature.raw,
                            log_expected: set_signature,
                            log_file: self
                                .entries
                                .first()
                                .map(|e| e.name.clone())
                                .unwrap_or_default(),
                        });
                    } else {
                        // Signature agreement established: also check that at
                        // least one ATTACHINFO record names this database.
                        let mut attached = false;
                        for entry in &self.entries {
                            if let Some(params) = &entry.params {
                                if params
                                    .attachments
                                    .iter()
                                    .any(|a| a.database_signature.raw == header.database_signature.raw)
                                {
                                    attached = true;
                                    break;
                                }
                            }
                        }
                        if !attached {
                            if let Some(first) = self.entries.first() {
                                anomalies.push(LogAnomaly::AttachedDbSignatureMismatch {
                                    log_file: first.name.clone(),
                                    db_observed: header.database_signature.raw,
                                });
                            }
                        }
                    }
                }

                if header.state() != DatabaseState::CleanShutdown
                    || header.min_required_generation != 0
                    || header.max_required_generation != 0
                {
                    anomalies.push(LogAnomaly::DatabaseNotCleanlyShutDown {
                        state: header.state(),
                        min_required: header.min_required_generation,
                        max_required: header.max_required_generation,
                    });
                }

                let min_required = header.min_required_generation;
                let max_required = header.max_required_generation;
                if min_required == 0 && max_required == 0 && header.state() == DatabaseState::CleanShutdown {
                    RecoveryAssessment::NoRecoveryRequired { min_required, max_required }
                } else {
                    let required_range: Vec<u32> = if max_required >= min_required && max_required > 0 {
                        (min_required..=max_required).collect()
                    } else {
                        Vec::new()
                    };
                    let present: Vec<u32> = required_range
                        .iter()
                        .copied()
                        .filter(|g| generations_present.binary_search(g).is_ok())
                        .collect();
                    let missing: Vec<u32> = required_range
                        .iter()
                        .copied()
                        .filter(|g| generations_present.binary_search(g).is_err())
                        .collect();
                    let satisfiable = missing.is_empty();
                    if !satisfiable {
                        anomalies.push(LogAnomaly::RequiredGenerationsMissing {
                            min_required,
                            max_required,
                            missing: missing.clone(),
                        });
                    }
                    RecoveryAssessment::Required { min_required, max_required, present, missing, satisfiable }
                }
            }
        };

        for entry in &self.entries {
            residual_sector_count += entry.residual_sector_count;
        }

        LogSetReport {
            base_name: self.base_name.clone(),
            generations_present,
            missing_generations,
            checkpoint,
            recovery,
            residual_sector_count,
            anomalies,
            stats,
        }
    }
}
