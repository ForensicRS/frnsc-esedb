//! Probe and mount an ESE database through `forensic_rs`'s `FormatFactory`
//! contract, rather than opening it directly via `EseDb::open`/`from_bytes`.
//!
//! This is what a triage pipeline does: it doesn't know in advance that a
//! given file is an ESE database, so it hands each candidate `VirtualFile`
//! to every registered `FormatFactory` and asks `probe()` to guess.
//!
//! Also demonstrates the companion `EseLogSetFactory`: a *second*,
//! independent factory over the same file that yields `MountKind::FileSet`
//! instead of `MountKind::Database` -- the sibling transaction logs,
//! checkpoint, flush map, and reserved logs grouped by filename shape,
//! reported as addresses (not open handles) via `Mounted::FileSet`.
//!
//! Usage: `cargo run --example mount_ese -- <path.mdb>`

use std::io::{Cursor, Read, Seek, SeekFrom};
use std::sync::Arc;

use forensic_rs::prelude::*;

/// A minimal in-memory `VirtualFile` — just enough to drive `probe`/`mount`
/// without pulling in a real filesystem backend.
struct BytesFile(Cursor<Vec<u8>>);

impl Read for BytesFile {
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

fn main() -> ForensicResult<()> {
    let path = std::env::args().nth(1).unwrap_or_else(|| {
        eprintln!("Usage: mount_ese <path.mdb>");
        std::process::exit(1);
    });
    let bytes = std::fs::read(&path).unwrap_or_else(|e| {
        eprintln!("Failed to read '{path}': {e}");
        std::process::exit(1);
    });

    let factory = frnsc_esedb::EseFormatFactory;

    // The MountContext plumbing a real resolver would already have on hand.
    // Backed by the real filesystem (not an empty in-memory one) so the
    // FileSet demo below can actually list `path`'s sibling files.
    let fs: Arc<dyn FileSystem> = Arc::new(forensic_rs::core::fs::StdVirtualFS::new());
    let locator = EvidenceLocator::root().push(LocatorSegment::Path(FPathBuf::from(path.clone())));
    let limits = Limits::default();
    let spill = MemorySpillStore::default();
    let cancellation = CancellationToken::new();
    let ctx = MountContext::new(&fs, &locator, &limits, 0, &spill, None, &cancellation);

    // ── probe ──────────────────────────────────────────────────────────────
    let mut file: Box<dyn VirtualFile> = Box::new(BytesFile(Cursor::new(bytes)));
    let score = factory.probe(file.as_mut(), &ctx)?;
    println!("probe() -> {score:?}");
    if matches!(score, ProbeScore::No) {
        eprintln!("'{path}' does not look like an ESE database");
        std::process::exit(1);
    }

    // ── mount ──────────────────────────────────────────────────────────────
    let mounted = factory.mount(file, &ctx)?;
    let Mounted::Database(db) = mounted else {
        unreachable!("EseFormatFactory::yields() is MountKind::Database");
    };

    // From here on, everything goes through the generic ForensicDb trait —
    // no `frnsc_esedb`-specific API needed.
    println!("Tables ({}):", db.list_tables()?.len());
    for name in db.list_tables()? {
        let table = db.table(&name)?;
        println!("  {name} — {} columns", table.columns().len());
    }

    // ── the companion FileSet factory ─────────────────────────────────────
    // A different `MountKind`, so a real resolver would register both
    // factories and call `resolve` twice -- a FileSet factory is not a
    // Database factory.
    let log_set_factory = frnsc_esedb::EseLogSetFactory;
    let mut file: Box<dyn VirtualFile> = Box::new(BytesFile(Cursor::new(std::fs::read(&path)?)));
    let score = log_set_factory.probe(file.as_mut(), &ctx)?;
    println!("\nEseLogSetFactory::probe() -> {score:?}");
    if !matches!(score, ProbeScore::No) {
        let Mounted::FileSet(set) = log_set_factory.mount(file, &ctx)? else {
            unreachable!("EseLogSetFactory::yields() is MountKind::FileSet");
        };
        println!("FileSet members ({}):", set.len());
        for member in set.members() {
            println!("  [{:?}] {}", member.role, member.locator);
        }
    }

    Ok(())
}
