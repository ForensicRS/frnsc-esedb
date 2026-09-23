//! Discovery and aggregation of an ESE log set: the transaction logs,
//! checkpoint, flush map, and reserved logs that sit beside one database.
//!
//! The database's own filename gives no clue to its log set's base name --
//! `SRUDB.dat`'s logs are named `SRU*.log`, not `SRUDB*.log` -- so discovery
//! is a directory scan grouped by the shared 28-byte `signLog`, which is
//! authoritative and filename-independent; the base name is only a
//! convenience label recovered from whichever files happen to share it.
//!
//! The directory scan itself is [`forensic_rs::traits::format::MountContext`]'s
//! job, not this module's: [`MountContext::parent_dir`]/[`MountContext::siblings`]
//! already decline correctly for a target with no directory to scan (an
//! archive entry, stream, or carved offset), which is exactly the case a
//! hand-rolled walk would otherwise have to special-case. What stays here is
//! purely ESE-specific: the `signLog`-grouping rule and the `.log`/`.chk`/
//! `.jfm`/`.jrs` filename shapes.

use std::path::Path;
use std::sync::Arc;

use forensic_rs::core::fs::StdVirtualFS;
use forensic_rs::core::path::{FPath, FPathBuf};
use forensic_rs::err::{ForensicError, ForensicResult};
use forensic_rs::traits::format::MountContext;
use forensic_rs::traits::vfs::{FileSystem, VFileType};

use crate::ese::checksum::ChecksumVerdict;
use crate::ese::db::EseDb;
use crate::ese::lgpos::Lgpos;
use crate::ese::reader::{PageReader, VirtualFileReader};

use super::checkpoint::CheckpointFile;
use super::flushmap::FlushMap;
use super::header::LogFileHeader;
use super::params::{AttachScanContext, LogParams};
use super::LogFile;

/// A log file's role within its set, derived from its filename shape (not
/// trusted for anything beyond a starting classification -- every value
/// used in the integrity report comes from the file's own header).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum LogFileRole {
    /// `<base>.log` -- the currently-open generation.
    Current,
    /// `<base>NNNNN.log` (5-hex) or `<base>NNNNNNNN.log` (8-hex) -- an
    /// archived generation.
    Archived,
    /// `<base>tmp.log` -- a recycled slot, commonly holding a stale
    /// generation. Normal ESE behavior, not evidence of tampering on its
    /// own.
    Temp,
}

/// One parsed, header-known member of a log set (a current, archived, or
/// temp `.log` file -- never a reserve, which carries no header).
pub struct LogSetEntry {
    pub name: String,
    pub role: LogFileRole,
    pub header: LogFileHeader,
    pub header_checksum: ChecksumVerdict,
    pub size: u64,
    /// Best-effort; `None` never fails discovery.
    pub params: Option<LogParams>,
    /// Number of sectors classified `Stale` in this file (residual data
    /// from a previous life of a recycled log). Computed eagerly at
    /// discovery time so the report doesn't need to re-open every file.
    pub residual_sector_count: usize,
}

/// A `.jrs` reserved log: preallocated space with no header of its own.
pub struct ReservedLog {
    pub name: String,
    pub size: u64,
    pub is_zero_filled: bool,
    pub first_nonzero: Option<usize>,
}

/// One discovered ESE log set.
pub struct EseLogSet {
    pub base_name: String,
    /// The signature shared by every member of this set -- the
    /// authoritative join key.
    pub log_signature: [u8; 28],
    pub entries: Vec<LogSetEntry>,
    pub checkpoint: Option<CheckpointFile>,
    pub checkpoint_name: Option<String>,
    pub flush_maps: Vec<(String, FlushMap)>,
    pub reserves: Vec<ReservedLog>,
    /// Where to re-open a member's full body from -- see [`Self::open_log`].
    /// Bodies are not held by the set itself (eager headers, lazy bodies).
    fs: Arc<dyn FileSystem>,
    dir: FPathBuf,
}

/// Classification of one candidate `.log` filename, independent of its
/// content. `strip_log_role` never trusts this beyond a starting
/// hypothesis -- an empty resulting base name is rejected outright (this is
/// what correctly rejects a file literally named `000B6.log` or `tmp.log`).
struct NameShape {
    base: String,
    role: LogFileRole,
    #[allow(dead_code)]
    generation_from_name: Option<u32>,
}

fn strip_log_role(stem: &str) -> Option<NameShape> {
    // `stem` has already had the `.log` extension removed.
    if stem.len() >= 3 && stem[stem.len() - 3..].eq_ignore_ascii_case("tmp") {
        let base = stem[..stem.len() - 3].to_string();
        if base.is_empty() {
            return None;
        }
        return Some(NameShape { base, role: LogFileRole::Temp, generation_from_name: None });
    }
    for hex_len in [8usize, 5usize] {
        if stem.len() >= hex_len {
            let (base_part, gen_part) = stem.split_at(stem.len() - hex_len);
            if gen_part.chars().all(|c| c.is_ascii_hexdigit()) {
                if let Ok(generation) = u32::from_str_radix(gen_part, 16) {
                    if base_part.is_empty() {
                        // A bare hex-shaped stem (e.g. "AAAAA.log") is
                        // ambiguous between "archived generation with an
                        // empty base" and "a current log literally named
                        // after hex digits" -- reject rather than silently
                        // picking one interpretation, instead of falling
                        // through to the `Current` catch-all below.
                        return None;
                    }
                    return Some(NameShape {
                        base: base_part.to_string(),
                        role: LogFileRole::Archived,
                        generation_from_name: Some(generation),
                    });
                }
            }
        }
    }
    if stem.is_empty() {
        return None;
    }
    Some(NameShape { base: stem.to_string(), role: LogFileRole::Current, generation_from_name: None })
}

fn strip_extension<'a>(name: &'a str, ext: &str) -> Option<&'a str> {
    if name.len() > ext.len() && name[name.len() - ext.len()..].eq_ignore_ascii_case(ext) {
        Some(&name[..name.len() - ext.len()])
    } else {
        None
    }
}

/// Names of every file directly within `dir` on `fs` (non-recursive).
/// Directories, symlinks, etc. are excluded; order is not significant.
fn list_dir_file_names(fs: &dyn FileSystem, dir: &FPath) -> ForensicResult<Vec<String>> {
    let mut names = Vec::new();
    for entry in fs.read_dir(dir)? {
        let entry = entry?;
        if entry.file_type == VFileType::File {
            if let Some(name) = entry.file_name() {
                names.push(name.to_string());
            }
        }
    }
    Ok(names)
}

/// Open `name` (a direct child of `dir`, as returned by
/// [`list_dir_file_names`] or [`MountContext::siblings`]) for
/// page/sector-at-a-time reads.
fn open_member(fs: &dyn FileSystem, dir: &FPath, name: &str) -> ForensicResult<Box<dyn PageReader>> {
    let file = fs.open(&dir.join(name))?;
    Ok(Box::new(VirtualFileReader::new(file)?))
}

impl EseLogSet {
    /// Discover every log set in the real filesystem directory `dir`.
    pub fn discover(dir: impl AsRef<Path>) -> ForensicResult<Vec<Self>> {
        let fs: Arc<dyn FileSystem> = Arc::new(StdVirtualFS::new());
        let dir = FPathBuf::from(dir.as_ref().to_string_lossy().into_owned());
        Self::discover_in(&fs, dir)
    }

    /// Discover every log set reachable through `fs` at `dir` -- e.g. inside
    /// a mounted disk image.
    pub fn discover_in(fs: &Arc<dyn FileSystem>, dir: FPathBuf) -> ForensicResult<Vec<Self>> {
        let names = list_dir_file_names(fs.as_ref(), dir.as_path())?;
        Self::from_names(fs.clone(), dir, names)
    }

    /// Discover every log set beside the file `ctx` is mounting, using the
    /// framework's own sibling-discovery mechanics
    /// ([`MountContext::parent_dir`]/[`MountContext::siblings`]) instead of a
    /// hand-rolled directory walk. Returns an empty `Vec` (not an error) for
    /// a target with no directory to scan -- an archive entry, stream, or
    /// carved offset.
    pub fn discover_via_mount_context(ctx: &MountContext<'_>) -> ForensicResult<Vec<Self>> {
        let Some(dir) = ctx.parent_dir() else { return Ok(Vec::new()) };
        let names: Vec<String> = ctx
            .siblings()?
            .into_iter()
            .filter(|e| e.file_type == VFileType::File)
            .filter_map(|e| e.file_name().map(str::to_string))
            .collect();
        Self::from_names(ctx.fs().clone(), dir, names)
    }

    /// The discovery engine shared by every entry point above: group `names`
    /// (already known to be files in `dir`, on `fs`) into log sets. The only
    /// ESE-specific knowledge here is the `signLog`-grouping rule and the
    /// `.log`/`.chk`/`.jfm`/`.jrs` filename shapes -- everything about
    /// finding and opening the files themselves is `fs`'s job.
    fn from_names(fs: Arc<dyn FileSystem>, dir: FPathBuf, names: Vec<String>) -> ForensicResult<Vec<Self>> {
        struct Candidate {
            name: String,
            role: LogFileRole,
            base: String,
            header: LogFileHeader,
            header_checksum: ChecksumVerdict,
            size: u64,
            params: Option<LogParams>,
            residual_sector_count: usize,
        }

        let mut candidates = Vec::new();
        let mut chk_candidates: Vec<(String, CheckpointFile)> = Vec::new();
        let mut flush_maps = Vec::new();
        let mut reserves = Vec::new();

        for name in &names {
            if let Some(stem) = strip_extension(name, ".log") {
                let Some(shape) = strip_log_role(stem) else { continue };
                let reader = match open_member(fs.as_ref(), dir.as_path(), name) {
                    Ok(r) => r,
                    Err(_) => continue,
                };
                let size = reader.total_size() as u64;
                let head = match reader.read_page(0, 4096.min(reader.total_size())) {
                    Ok(h) => h,
                    Err(_) => continue,
                };
                let header = match LogFileHeader::from_buff(&head) {
                    Ok(h) => h,
                    // A structurally-broken header is skipped (not kept) --
                    // every offset past it would be arbitrary. A bad
                    // checksum on an otherwise-valid header IS kept; that
                    // distinction is handled by `verify_checksum` below,
                    // not here.
                    Err(_) => continue,
                };
                let header_checksum = header.verify_checksum(&head);
                let ctx = AttachScanContext::new(header.sector_size, header.file_sectors);
                let params = if head.len() > 0x48 {
                    LogParams::scan(&head[0x48..], &ctx).ok()
                } else {
                    None
                };
                let residual_sector_count = LogFile::from_reader(reader)
                    .ok()
                    .and_then(|log| log.residual_spans().ok())
                    .map(|spans| {
                        spans
                            .iter()
                            .map(|s| (s.last_sector - s.first_sector + 1) as usize)
                            .sum()
                    })
                    .unwrap_or(0);

                candidates.push(Candidate {
                    name: name.clone(),
                    role: shape.role,
                    base: shape.base,
                    header,
                    header_checksum,
                    size,
                    params,
                    residual_sector_count,
                });
            } else if let Some(_stem) = strip_extension(name, ".chk") {
                if let Ok(reader) = open_member(fs.as_ref(), dir.as_path(), name) {
                    if let Ok(bytes) = reader.read_page(0, reader.total_size()) {
                        if let Ok(chk) = CheckpointFile::from_buff(&bytes) {
                            chk_candidates.push((name.clone(), chk));
                        }
                    }
                }
            } else if let Some(_stem) = strip_extension(name, ".jfm") {
                if let Ok(reader) = open_member(fs.as_ref(), dir.as_path(), name) {
                    if let Ok(bytes) = reader.read_page(0, reader.total_size()) {
                        if let Ok(map) = FlushMap::from_buff(&bytes) {
                            flush_maps.push((name.clone(), map));
                        }
                    }
                }
            } else if strip_extension(name, ".jrs").is_some() {
                if let Ok(reader) = open_member(fs.as_ref(), dir.as_path(), name) {
                    let size = reader.total_size() as u64;
                    let (is_zero_filled, first_nonzero) = match reader.read_page(0, reader.total_size()) {
                        Ok(bytes) => match bytes.iter().position(|&b| b != 0) {
                            Some(pos) => (false, Some(pos)),
                            None => (true, None),
                        },
                        Err(_) => (true, None),
                    };
                    reserves.push(ReservedLog { name: name.clone(), size, is_zero_filled, first_nonzero });
                }
            }
        }

        if candidates.is_empty() {
            return Ok(Vec::new());
        }

        // Group by signLog first (authoritative), base name second (a label
        // recovered from whichever files happen to share it).
        let mut buckets: Vec<(Vec<u8>, Vec<Candidate>)> = Vec::new();
        'outer: for candidate in candidates {
            let sig = candidate.header.log_signature.raw.to_vec();
            for (bucket_sig, members) in buckets.iter_mut() {
                if *bucket_sig == sig {
                    members.push(candidate);
                    continue 'outer;
                }
            }
            buckets.push((sig, vec![candidate]));
        }

        // A `.jfm`/`.jrs` file carries no `signLog` of its own (see
        // `flushmap.rs`'s module documentation and `ReservedLog`'s "no
        // header of its own"), so there is no honest way to attribute one to
        // a specific signature bucket when more than one is discovered in
        // the same directory. Rather than guess by duplicating every one
        // into every bucket -- which silently claims a flush map belongs to
        // a set it might not -- attach them only in the unambiguous case: a
        // single log set in this directory. This is the overwhelmingly
        // common real-world layout (one database, one log set per
        // directory); a directory holding more than one deliberately leaves
        // every set's `flush_maps`/`reserves` empty rather than fabricate an
        // assignment.
        let unambiguous = buckets.len() == 1;

        let mut sets = Vec::new();
        for (sig, members) in buckets {
            let mut sig_arr = [0u8; 28];
            sig_arr.copy_from_slice(&sig);

            // Base name: the most common base string among this bucket's
            // members (ties broken by first-seen).
            let mut base_counts: Vec<(String, usize)> = Vec::new();
            for m in &members {
                match base_counts.iter_mut().find(|(b, _)| b == &m.base) {
                    Some((_, count)) => *count += 1,
                    None => base_counts.push((m.base.clone(), 1)),
                }
            }
            let base_name = base_counts
                .into_iter()
                .max_by_key(|(_, count)| *count)
                .map(|(b, _)| b)
                .unwrap_or_default();

            let entries = members
                .into_iter()
                .map(|c| LogSetEntry {
                    name: c.name,
                    role: c.role,
                    header: c.header,
                    header_checksum: c.header_checksum,
                    size: c.size,
                    params: c.params,
                    residual_sector_count: c.residual_sector_count,
                })
                .collect::<Vec<_>>();

            // Signature match wins over name match for the checkpoint.
            let (checkpoint_name, checkpoint) = chk_candidates
                .iter()
                .find(|(_, chk)| chk.checkpoint.log_signature.raw == sig_arr)
                .map(|(name, chk)| (Some(name.clone()), Some(clone_checkpoint(chk))))
                .unwrap_or((None, None));

            sets.push(EseLogSet {
                base_name,
                log_signature: sig_arr,
                entries,
                checkpoint,
                checkpoint_name,
                flush_maps: if unambiguous { flush_maps.clone() } else { Vec::new() },
                reserves: if unambiguous { clone_reserves(&reserves) } else { Vec::new() },
                fs: fs.clone(),
                dir: dir.clone(),
            });
        }

        Ok(sets)
    }

    /// Discover the log set belonging to `db` in `dir` (matched purely by
    /// `log_signature`, never by filename).
    pub fn for_database(db: &EseDb, dir: impl AsRef<Path>) -> ForensicResult<Option<Self>> {
        let sets = Self::discover(dir)?;
        Ok(sets
            .into_iter()
            .find(|s| s.log_signature == db.header().log_signature.raw))
    }

    /// Re-open the named generation's log file for full sector access.
    /// Bodies are not held by the set itself (see the module documentation
    /// on eager headers / lazy bodies), so this re-reads through the
    /// source each time.
    pub fn open_log(&self, generation: u32) -> ForensicResult<LogFile> {
        let entry = self
            .entries
            .iter()
            .find(|e| e.header.generation == generation)
            .ok_or_else(|| ForensicError::missing_data("ESE log generation", generation.to_string().into()))?;
        LogFile::from_reader(open_member(self.fs.as_ref(), self.dir.as_path(), &entry.name)?)
    }

    /// Every generation actually present in the set. Deliberately includes
    /// generations held only by a `Temp` slot: `SRUtmp.log` can be the sole
    /// surviving record of a generation, and excluding it here would
    /// misreport a fully-present generation as missing.
    pub fn generations(&self) -> Vec<u32> {
        let mut gens: Vec<u32> = self.entries.iter().map(|e| e.header.generation).collect();
        gens.sort_unstable();
        gens.dedup();
        gens
    }

    pub fn missing_generations(&self) -> Vec<u32> {
        let gens = self.generations();
        let (Some(&lo), Some(&hi)) = (gens.first(), gens.last()) else {
            return Vec::new();
        };
        (lo..=hi).filter(|g| gens.binary_search(g).is_err()).collect()
    }

    pub fn checkpoint_position(&self) -> Option<Lgpos> {
        self.checkpoint.as_ref().map(|c| c.checkpoint.checkpoint)
    }
}

fn clone_checkpoint(chk: &CheckpointFile) -> CheckpointFile {
    CheckpointFile {
        checkpoint: crate::ese::log::checkpoint::Checkpoint {
            checksum: chk.checkpoint.checksum,
            last_full_backup_checkpoint: chk.checkpoint.last_full_backup_checkpoint,
            checkpoint: chk.checkpoint.checkpoint,
            log_signature: chk.checkpoint.log_signature.clone(),
        },
        checksum_status: chk.checksum_status,
        params: None, // params are best-effort diagnostics; not needed per-set-clone
        size: chk.size,
    }
}

fn clone_reserves(reserves: &[ReservedLog]) -> Vec<ReservedLog> {
    reserves
        .iter()
        .map(|r| ReservedLog {
            name: r.name.clone(),
            size: r.size,
            is_zero_filled: r.is_zero_filled,
            first_nonzero: r.first_nonzero,
        })
        .collect()
}

#[cfg(test)]
mod tst {
    use super::*;
    use forensic_rs::prelude::testing::InMemoryVirtualFileSystem;

    /// Build an in-memory directory `"/evidence"` holding `files`, ready for
    /// [`EseLogSet::discover_in`]. This is what replaces the old
    /// `InMemoryLogSetSource` seam -- discovery drives the same
    /// `forensic_rs::traits::vfs::FileSystem` a mounted disk image would.
    fn discover_synthetic(files: Vec<(&str, Vec<u8>)>) -> ForensicResult<Vec<EseLogSet>> {
        let mut vfs = InMemoryVirtualFileSystem::new();
        for (name, bytes) in files {
            vfs.add_file(format!("evidence/{name}"), bytes);
        }
        let fs: Arc<dyn FileSystem> = Arc::new(vfs);
        EseLogSet::discover_in(&fs, FPathBuf::from("/evidence"))
    }

    fn synthetic_log_bytes(generation: u32, signature_seed: u8) -> Vec<u8> {
        use crate::ese::log::header::LogFileHeaderRpr;
        let mut buf = vec![0u8; std::mem::size_of::<LogFileHeaderRpr>().max(4096)];
        buf[4..8].copy_from_slice(&generation.to_le_bytes());
        buf[8..10].copy_from_slice(&4096u16.to_le_bytes());
        buf[10..12].copy_from_slice(&1u16.to_le_bytes());
        buf[12..14].copy_from_slice(&16u16.to_le_bytes());
        buf[14..16].copy_from_slice(&4096u16.to_le_bytes());
        // signLog at 0x2c..0x48; make it distinct per signature_seed.
        for b in &mut buf[0x2c..0x2c + 28] {
            *b = signature_seed;
        }
        // valid embedded LOGTIME so Signature::from_buff succeeds cleanly.
        buf[0x2c + 4..0x2c + 12].copy_from_slice(&[0x01, 0x08, 0x14, 0x0d, 0x0a, 0x78, 0x21, 0x00]);
        let cksum = crate::ese::checksum::log_file_header_checksum(&buf, 4096).unwrap();
        buf[0..4].copy_from_slice(&cksum.to_le_bytes());
        buf.resize(65536, 0);
        buf
    }

    #[test]
    fn strip_log_role_classifies_every_documented_pattern() {
        assert!(matches!(
            strip_log_role("SRU").unwrap(),
            NameShape { role: LogFileRole::Current, .. }
        ));
        let archived = strip_log_role("SRU000B6").unwrap();
        assert!(matches!(archived.role, LogFileRole::Archived));
        assert_eq!(archived.base, "SRU");
        assert_eq!(archived.generation_from_name, Some(0x000B6));

        let temp = strip_log_role("SRUtmp").unwrap();
        assert!(matches!(temp.role, LogFileRole::Temp));
        assert_eq!(temp.base, "SRU");

        assert!(strip_log_role("AAAAA").is_none()); // bare 5-hex, empty base
        assert!(strip_log_role("").is_none());

        let exchange = strip_log_role("E0100000001").unwrap();
        assert!(matches!(exchange.role, LogFileRole::Archived));
        assert_eq!(exchange.base, "E01");
        assert_eq!(exchange.generation_from_name, Some(1));

        let max_gen = strip_log_role("SRUFFFFF").unwrap();
        assert_eq!(max_gen.generation_from_name, Some(0xFFFFF));
    }

    #[test]
    fn discover_finds_one_set_from_synthetic_source() {
        let sets = discover_synthetic(vec![
            ("SRU.log", synthetic_log_bytes(185, 0xAA)),
            ("SRU000B6.log", synthetic_log_bytes(182, 0xAA)),
        ])
        .unwrap();
        assert_eq!(sets.len(), 1);
        assert_eq!(sets[0].base_name, "SRU");
        assert_eq!(sets[0].generations(), vec![182, 185]);
        assert_eq!(sets[0].missing_generations(), vec![183, 184]);
    }

    #[test]
    fn discover_splits_by_signature_even_with_shared_base_name() {
        let sets = discover_synthetic(vec![
            ("SRU.log", synthetic_log_bytes(1, 0xAA)),
            ("SRU000B6.log", synthetic_log_bytes(2, 0xBB)),
        ])
        .unwrap();
        assert_eq!(sets.len(), 2, "two distinct signatures must yield two sets");
    }

    #[test]
    fn a_multi_set_directory_leaves_flush_maps_and_reserves_unattributed() {
        // Two distinct signatures share one directory, plus a flush map and
        // a reserved log that carry no signature of their own -- there is no
        // honest way to say which set either belongs to, so both sets must
        // come back empty on these fields rather than have the ambiguous
        // members duplicated into both.
        let sets = discover_synthetic(vec![
            ("SRU.log", synthetic_log_bytes(1, 0xAA)),
            ("SRU000B6.log", synthetic_log_bytes(2, 0xBB)),
            ("SRUDB.jfm", vec![0u8; 0x28]),
        ])
        .unwrap();
        assert_eq!(sets.len(), 2);
        for set in &sets {
            assert!(set.flush_maps.is_empty(), "ambiguous attribution must not be guessed");
        }
    }

    #[test]
    fn real_fixture_discovers_exactly_one_complete_set() {
        let dir = std::path::Path::new("./artifacts/sru");
        if !dir.exists() {
            eprintln!("SKIP: fixture directory unavailable");
            return;
        }
        let sets = EseLogSet::discover(dir).unwrap();
        assert_eq!(sets.len(), 1);
        let set = &sets[0];
        assert_eq!(set.base_name, "SRU");
        assert_eq!(set.generations(), vec![181, 182, 183, 184, 185]);
        assert!(set.missing_generations().is_empty());
        assert!(set.checkpoint.is_some());
        assert_eq!(set.reserves.len(), 2);
        assert!(set.reserves.iter().all(|r| r.is_zero_filled));
        assert_eq!(set.flush_maps.len(), 1);
        assert_eq!(set.checkpoint_position().unwrap(), Lgpos { generation: 185, sector: 5, byte: 0 });
    }
}
