//! Abstract over how raw page bytes are read from an ESE database source.
//!
//! Three implementations are provided:
//! * [`SliceReader`] — wraps an in-memory `Vec<u8>`; pages are returned as
//!   borrowed slices (zero copy per page).
//! * [`FileReader`] — wraps an open file; each `read_page` call performs a
//!   positioned read of exactly `page_size` bytes on demand — the full file
//!   is never buffered into memory.
//! * [`VirtualFileReader`] — wraps a `forensic_rs::traits::vfs::VirtualFile`
//!   (used by [`crate::ese::format::EseFormatFactory`]).
//!
//! All implementations are `Send + Sync`: `forensic_rs::traits::db::ForensicDb`
//! requires it, since a mounted database is cached and shared across parallel
//! pipeline workers.

use std::borrow::Cow;
use std::fs::File;
use std::sync::Mutex;

use forensic_rs::err::ForensicResult;
use forensic_rs::ensure_buffer_size;

// ─── Trait ────────────────────────────────────────────────────────────────────

/// Provides on-demand access to raw page bytes from an ESE database source.
///
/// `Send + Sync` because `EseDb` implements `forensic_rs::traits::db::ForensicDb`,
/// which the framework caches and shares across parallel pipeline workers
/// (`forensic_rs::traits::format::Mounted::Database`).
pub trait PageReader: Send + Sync {
    /// Return `size` bytes starting at byte `offset`.
    ///
    /// Implementations may return borrowed bytes (`Cow::Borrowed`) for
    /// zero-copy in-memory access, or owned bytes (`Cow::Owned`) for
    /// file-backed sources.
    fn read_page<'a>(&'a self, offset: usize, size: usize) -> ForensicResult<Cow<'a, [u8]>>;

    /// Total byte length of the database source.
    fn total_size(&self) -> usize;
}

// ─── SliceReader ─────────────────────────────────────────────────────────────

/// In-memory reader backed by an owned `Vec<u8>`.
///
/// `read_page` returns `Cow::Borrowed` — no allocation per page.
pub struct SliceReader(pub(crate) Vec<u8>);

impl SliceReader {
    /// Wrap an in-memory buffer for page-at-a-time access.
    pub fn new(data: Vec<u8>) -> Self {
        Self(data)
    }
}

impl PageReader for SliceReader {
    fn read_page<'a>(&'a self, offset: usize, size: usize) -> ForensicResult<Cow<'a, [u8]>> {
        ensure_buffer_size!(self.0, offset, size, "ESE page");
        Ok(Cow::Borrowed(&self.0[offset..offset + size]))
    }

    fn total_size(&self) -> usize {
        self.0.len()
    }
}

// ─── FileReader ───────────────────────────────────────────────────────────────

/// Seek-free reader backed by an open file, using positioned reads.
///
/// Only the requested page is loaded per call — the full file is never
/// buffered. Uses OS positioned-read primitives (`pread`/`ReadFile` with an
/// offset) that take `&self`, so no interior mutability (`Mutex`/`RefCell`)
/// is needed — unlike a seek-then-read approach, this is naturally
/// thread-safe and avoids the seek/read race a shared cursor would have.
pub struct FileReader {
    file: File,
    size: usize,
}

impl FileReader {
    /// Open the file at `path` for page-at-a-time reading.
    pub fn open(path: impl AsRef<std::path::Path>) -> std::io::Result<Self> {
        let file = File::open(path.as_ref())?;
        let size = file.metadata()?.len() as usize;
        Ok(Self { file, size })
    }
}

impl PageReader for FileReader {
    fn read_page<'a>(&'a self, offset: usize, size: usize) -> ForensicResult<Cow<'a, [u8]>> {
        check_range(offset, size, self.size)?;
        let mut buf = vec![0u8; size];
        read_exact_at(&self.file, offset as u64, &mut buf)
            .map_err(|e| forensic_rs::err::ForensicError::io_error_with_source(e, "ESE page read"))?;
        Ok(Cow::Owned(buf))
    }

    fn total_size(&self) -> usize {
        self.size
    }
}

/// Shared bounds check for the two owned-size readers (`FileReader`,
/// `VirtualFileReader`), which cannot cheaply satisfy `ensure_buffer_size!`'s
/// `$buffer.len()` requirement without borrowing a live buffer.
fn check_range(offset: usize, size: usize, total: usize) -> ForensicResult<()> {
    let required = offset.saturating_add(size);
    if required > total {
        return Err(forensic_rs::err::ForensicError::buffer_too_small(
            required, total, "ESE page",
        ));
    }
    Ok(())
}

#[cfg(unix)]
fn read_exact_at(file: &File, mut offset: u64, mut buf: &mut [u8]) -> std::io::Result<()> {
    use std::os::unix::fs::FileExt;
    while !buf.is_empty() {
        let n = file.read_at(buf, offset)?;
        if n == 0 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::UnexpectedEof,
                "unexpected EOF while reading ESE page",
            ));
        }
        buf = &mut buf[n..];
        offset += n as u64;
    }
    Ok(())
}

#[cfg(windows)]
fn read_exact_at(file: &File, mut offset: u64, mut buf: &mut [u8]) -> std::io::Result<()> {
    use std::os::windows::fs::FileExt;
    while !buf.is_empty() {
        let n = file.seek_read(buf, offset)?;
        if n == 0 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::UnexpectedEof,
                "unexpected EOF while reading ESE page",
            ));
        }
        buf = &mut buf[n..];
        offset += n as u64;
    }
    Ok(())
}

#[cfg(not(any(unix, windows)))]
fn read_exact_at(file: &File, offset: u64, buf: &mut [u8]) -> std::io::Result<()> {
    // Fallback for platforms without a positioned-read primitive in std:
    // fall back to a mutex-guarded seek + read.
    use std::io::{Read, Seek, SeekFrom};
    static FALLBACK_LOCK: Mutex<()> = Mutex::new(());
    let _guard = FALLBACK_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let mut f = file.try_clone()?;
    f.seek(SeekFrom::Start(offset))?;
    f.read_exact(buf)
}

// ─── VirtualFileReader ───────────────────────────────────────────────────────

/// Page reader over a `forensic_rs::traits::vfs::VirtualFile`.
///
/// `VirtualFile` is `Send` but not `Sync`, and its `Read`/`Seek` methods need
/// `&mut self`, so a `Mutex` is unavoidable here (unlike [`FileReader`], which
/// has a real positioned-read primitive available). `Mutex<T>: Sync` holds
/// because `Box<dyn VirtualFile>: Send`.
pub struct VirtualFileReader {
    inner: Mutex<Box<dyn forensic_rs::traits::vfs::VirtualFile>>,
    size: usize,
}

impl VirtualFileReader {
    /// Wrap an already-open `VirtualFile` for page-at-a-time access.
    pub fn new(file: Box<dyn forensic_rs::traits::vfs::VirtualFile>) -> ForensicResult<Self> {
        let size = file.metadata()?.size as usize;
        Ok(Self { inner: Mutex::new(file), size })
    }
}

impl PageReader for VirtualFileReader {
    fn read_page<'a>(&'a self, offset: usize, size: usize) -> ForensicResult<Cow<'a, [u8]>> {
        check_range(offset, size, self.size)?;
        use std::io::{Read, Seek, SeekFrom};
        let mut guard = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        let mut buf = vec![0u8; size];
        guard
            .seek(SeekFrom::Start(offset as u64))
            .map_err(|e| forensic_rs::err::ForensicError::io_error_with_source(e, "ESE VFS seek"))?;
        guard
            .read_exact(&mut buf)
            .map_err(|e| forensic_rs::err::ForensicError::io_error_with_source(e, "ESE VFS read"))?;
        Ok(Cow::Owned(buf))
    }

    fn total_size(&self) -> usize {
        self.size
    }
}

#[cfg(test)]
mod tst {
    use super::*;

    fn assert_send_sync<T: Send + Sync>() {}

    #[test]
    fn readers_are_send_sync() {
        assert_send_sync::<SliceReader>();
        assert_send_sync::<FileReader>();
        assert_send_sync::<VirtualFileReader>();
    }

    #[test]
    fn slice_reader_rejects_overflowing_range() {
        let r = SliceReader::new(vec![1, 2, 3, 4]);
        assert!(r.read_page(usize::MAX - 1, 4).is_err());
        assert!(r.read_page(2, 4).is_err());
        assert_eq!(&*r.read_page(1, 2).unwrap(), &[2, 3]);
    }
}
