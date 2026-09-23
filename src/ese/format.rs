//! `forensic_rs::traits::format::FormatFactory` for ESE databases.
//!
//! Lets a triage pipeline discover and mount `.mdb`/`.edb`/`.dat` files as a
//! [`forensic_rs::traits::db::ForensicDb`] without the caller needing to
//! know in advance that a given file is an ESE database — the replacement for
//! the pre-0.14 `SqlDb::from_file` construction path, which had no equivalent
//! left after `traits::sql` was removed.
//!
//! `.jfm` is **not** handled by this factory — it is a flush map, not a
//! database, and `probe_inner` correctly scores it `ProbeScore::No` (its
//! magic word at offset 4 is `3`, not [`ESE_HEADER_SIGNATURE`]). Parse a
//! `.jfm` directly via [`crate::ese::log::flushmap::FlushMap`].
//!
//! [`EseLogSetFactory`] is a second, independent factory over the *same*
//! candidate file: a FileSet factory is not a Database factory (they yield
//! different [`MountKind`]s), so both are registered and the resolver is
//! asked twice -- `Some(MountKind::Database)` for the parsed database,
//! `Some(MountKind::FileSet)` for the sibling group. It reports only
//! filename-shape membership (no header parsing, no `signLog` matching) --
//! addresses, not open handles, per [`forensic_rs::traits::format::FileSet`]'s
//! contract that a FileSet mount is terminal. A caller wanting the
//! signature-verified grouping and integrity report should use
//! [`crate::ese::log::set::EseLogSet::discover_via_mount_context`] directly.

use std::io::{Seek, SeekFrom};
use std::sync::Arc;

use forensic_rs::err::ForensicResult;
use forensic_rs::traits::format::{FileSet, FileSetRole, FormatFactory, MountContext, MountKind, Mounted, ProbeScore};
use forensic_rs::traits::vfs::VirtualFile;

use crate::ese::db::EseDb;
use crate::ese::header::ESE_HEADER_SIGNATURE;
use crate::ese::reader::VirtualFileReader;

/// Mounts ESE (JET Blue) databases as a `ForensicDb`.
pub struct EseFormatFactory;

impl FormatFactory for EseFormatFactory {
    fn name(&self) -> &'static str {
        "ese"
    }

    fn yields(&self) -> MountKind {
        MountKind::Database
    }

    fn probe(&self, file: &mut dyn VirtualFile, _ctx: &MountContext<'_>) -> ForensicResult<ProbeScore> {
        // Must restore the stream position on every path, including errors.
        let start = file.stream_position()?;
        let result = probe_inner(file);
        file.seek(SeekFrom::Start(start))?;
        result
    }

    fn mount(&self, file: Box<dyn VirtualFile>, ctx: &MountContext<'_>) -> ForensicResult<Mounted> {
        let size = file.metadata()?.size as usize;
        let limit = ctx.limits().materialize_in_memory_limit;
        let db = if size <= limit {
            // Small enough to slurp: regains zero-copy page reads via
            // `SliceReader`, which a `VirtualFileReader` cannot offer (it
            // always returns `Cow::Owned`).
            let mut file = file;
            let mut buf = Vec::with_capacity(size);
            file.seek(SeekFrom::Start(0))?;
            std::io::Read::read_to_end(&mut file, &mut buf)
                .map_err(|e| forensic_rs::err::ForensicError::io_error_with_source(e, "ESE mount: read_to_end"))?;
            EseDb::from_bytes(buf)
        } else {
            // Large file (e.g. a multi-GiB Exchange .edb): stream pages on
            // demand instead, respecting the resolver's in-memory budget.
            EseDb::from_reader(Box::new(VirtualFileReader::new(file)?))
        };
        let db = db.map_err(|e| e.with_path(ctx.locator().to_string()))?;
        Ok(Mounted::Database(Arc::new(db)))
    }
}

fn probe_inner(file: &mut dyn VirtualFile) -> ForensicResult<ProbeScore> {
    file.seek(SeekFrom::Start(0))?;
    let mut head = [0u8; 12];
    if file.read_exact(&mut head).is_err() {
        return Ok(ProbeScore::No);
    }
    let signature = u32::from_le_bytes([head[4], head[5], head[6], head[7]]);
    if signature != ESE_HEADER_SIGNATURE {
        return Ok(ProbeScore::No);
    }
    // Signature matches; also sanity-check the page size to distinguish a
    // genuinely well-formed header from a coincidental 4-byte match. Get the
    // length *before* seeking back to the start to read it — `Seek::End`
    // leaves the cursor at EOF, so reading it in the other order would read
    // zero bytes.
    let total_len = file.seek(SeekFrom::End(0))? as usize;
    file.seek(SeekFrom::Start(0))?;
    let mut header_region = vec![0u8; 4096.min(total_len)];
    if file.read_exact(&mut header_region).is_ok()
        && crate::ese::header::Header::from_buff(&header_region).is_ok()
    {
        return Ok(ProbeScore::Exact);
    }
    // Signature matched but the rest didn't fully validate — still very
    // likely ESE (a truncated or partially-overwritten database should still
    // be offered for mounting rather than rejected outright).
    Ok(ProbeScore::Strong)
}

/// Groups an ESE database with the transaction logs, checkpoint, flush map,
/// and reserved logs beside it, purely by filename shape -- see the module
/// documentation for why this is deliberately lighter than
/// [`crate::ese::log::set::EseLogSet`]'s signature-verified discovery.
pub struct EseLogSetFactory;

impl FormatFactory for EseLogSetFactory {
    fn name(&self) -> &'static str {
        "ese_log_set"
    }

    fn yields(&self) -> MountKind {
        MountKind::FileSet
    }

    fn probe(&self, file: &mut dyn VirtualFile, _ctx: &MountContext<'_>) -> ForensicResult<ProbeScore> {
        // The candidate for grouping is the database itself -- same sniff as
        // `EseFormatFactory`, so a directory is only ever offered as a
        // FileSet when it actually contains an ESE database to group around.
        let start = file.stream_position()?;
        let result = probe_inner(file);
        file.seek(SeekFrom::Start(start))?;
        result
    }

    fn mount(&self, _file: Box<dyn VirtualFile>, ctx: &MountContext<'_>) -> ForensicResult<Mounted> {
        let mut set = FileSet::new(ctx.locator().clone());
        // Determinism is the caller's job, not the filesystem's.
        let mut names: Vec<String> =
            ctx.siblings()?.into_iter().filter_map(|e| e.file_name().map(str::to_string)).collect();
        names.sort();
        for name in names {
            let role = if name.ends_with(".log") {
                FileSetRole::Log
            } else if name.ends_with(".chk") {
                FileSetRole::Checkpoint
            } else if name.ends_with(".jfm") {
                FileSetRole::Other("flush_map".into())
            } else if name.ends_with(".jrs") {
                FileSetRole::Other("reserved_log".into())
            } else {
                continue;
            };
            if let Some(locator) = ctx.sibling_locator(&name) {
                set.push_mut(role, locator);
            }
        }
        Ok(Mounted::FileSet(set))
    }
}

#[cfg(test)]
mod tst {
    use super::*;
    use std::io::Cursor;

    /// Minimal in-memory `VirtualFile`, mirroring forensic-rs's own
    /// conformance-test pattern (`tests/format_conformance.rs`).
    struct BytesFile(Cursor<Vec<u8>>);
    impl std::io::Read for BytesFile {
        fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
            self.0.read(buf)
        }
    }
    impl Seek for BytesFile {
        fn seek(&mut self, pos: SeekFrom) -> std::io::Result<u64> {
            self.0.seek(pos)
        }
    }
    impl VirtualFile for BytesFile {
        fn metadata(&self) -> ForensicResult<forensic_rs::traits::vfs::VMetadata> {
            Ok(forensic_rs::traits::vfs::VMetadata {
                file_type: forensic_rs::traits::vfs::VFileType::File,
                size: self.0.get_ref().len() as u64,
                allocated_size: None,
                times: forensic_rs::traits::vfs::MacbTimes::default(),
                id: None,
                attributes: forensic_rs::traits::vfs::FileAttributes::empty(),
            })
        }
    }

    #[test]
    fn probe_rejects_non_ese_bytes() {
        let mut file = BytesFile(Cursor::new(vec![0u8; 64]));
        let score = probe_inner(&mut file).unwrap();
        assert_eq!(ProbeScore::No, score);
    }

    #[test]
    fn probe_scores_exact_on_a_real_database() {
        // Regression guard: an earlier version of `head_region_len` seeked
        // to EOF to measure the file, then never seeked back before
        // reading — the read always failed, and every real database
        // scored `Strong` instead of `Exact`.
        let Ok(bytes) = std::fs::read("./artifacts/sru/SRUDB.dat") else {
            eprintln!("SKIP: fixture unavailable");
            return;
        };
        let mut file = BytesFile(Cursor::new(bytes));
        let start = file.stream_position().unwrap();
        let score = probe_inner(&mut file).unwrap();
        assert_eq!(ProbeScore::Exact, score);
        // `probe_inner` itself doesn't restore position (its caller,
        // `EseFormatFactory::probe`, does) — assert the position moved,
        // confirming this test would have caught a "never reads anything"
        // regression too.
        assert_ne!(start, file.stream_position().unwrap());
    }

    #[test]
    fn log_set_factory_groups_siblings_by_role_and_excludes_unrelated_files() {
        let Ok(bytes) = std::fs::read("./artifacts/sru/SRUDB.dat") else {
            eprintln!("SKIP: fixture unavailable");
            return;
        };

        let mut vfs = forensic_rs::prelude::testing::InMemoryVirtualFileSystem::new();
        vfs.add_file("evidence/SRUDB.dat", bytes.clone());
        vfs.add_file("evidence/SRU.log", vec![0u8; 4]);
        vfs.add_file("evidence/SRU000B6.log", vec![0u8; 4]);
        vfs.add_file("evidence/SRU.chk", vec![0u8; 4]);
        vfs.add_file("evidence/SRUDB.jfm", vec![0u8; 4]);
        vfs.add_file("evidence/SRUres00001.jrs", vec![0u8; 4]);
        vfs.add_file("evidence/unrelated.txt", vec![0u8; 4]);
        let fs: Arc<dyn forensic_rs::traits::vfs::FileSystem> = Arc::new(vfs);

        let locator = forensic_rs::prelude::EvidenceLocator::root()
            .push(forensic_rs::prelude::LocatorSegment::Path("/evidence/SRUDB.dat".into()));
        let limits = forensic_rs::prelude::Limits::default();
        let spill = forensic_rs::prelude::MemorySpillStore::default();
        let cancellation = forensic_rs::prelude::CancellationToken::new();
        let ctx = MountContext::new(&fs, &locator, &limits, 0, &spill, None, &cancellation);

        let factory = EseLogSetFactory;
        assert_eq!(factory.yields(), MountKind::FileSet);

        let mut file: Box<dyn VirtualFile> = Box::new(BytesFile(Cursor::new(bytes.clone())));
        let score = factory.probe(file.as_mut(), &ctx).unwrap();
        assert_eq!(ProbeScore::Exact, score);

        let mounted = factory.mount(file, &ctx).unwrap();
        let Mounted::FileSet(set) = mounted else {
            panic!("expected Mounted::FileSet");
        };
        assert_eq!(set.primary(), &locator);
        assert_eq!(set.by_role(&FileSetRole::Log).count(), 2);
        assert_eq!(set.by_role(&FileSetRole::Checkpoint).count(), 1);
        assert_eq!(set.by_role(&FileSetRole::Other("flush_map".into())).count(), 1);
        assert_eq!(set.by_role(&FileSetRole::Other("reserved_log".into())).count(), 1);
        // Primary + 5 recognized siblings; `unrelated.txt` must not appear.
        assert_eq!(set.len(), 6);
    }

    #[test]
    fn probe_then_mount_round_trip_lists_tables() {
        let Ok(bytes) = std::fs::read("./artifacts/sru/SRUDB.dat") else {
            eprintln!("SKIP: fixture unavailable");
            return;
        };
        let factory = EseFormatFactory;
        let fs: Arc<dyn forensic_rs::traits::vfs::FileSystem> =
            Arc::new(forensic_rs::prelude::testing::InMemoryVirtualFileSystem::new());
        let locator = forensic_rs::prelude::EvidenceLocator::root();
        let limits = forensic_rs::prelude::Limits::default();
        let spill = forensic_rs::prelude::MemorySpillStore::default();
        let cancellation = forensic_rs::prelude::CancellationToken::new();
        let ctx = MountContext::new(&fs, &locator, &limits, 0, &spill, None, &cancellation);

        let mut file: Box<dyn VirtualFile> = Box::new(BytesFile(Cursor::new(bytes)));
        let score = factory.probe(file.as_mut(), &ctx).unwrap();
        assert_eq!(ProbeScore::Exact, score);

        let mounted = factory.mount(file, &ctx).unwrap();
        let Mounted::Database(db) = mounted else {
            panic!("expected Mounted::Database");
        };
        assert!(!db.list_tables().unwrap().is_empty());
    }
}
