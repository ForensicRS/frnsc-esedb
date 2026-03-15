//! Abstract over how raw page bytes are read from an ESE database source.
//!
//! Two implementations are provided:
//! * [`SliceReader`] — wraps an in-memory `Vec<u8>`; pages are returned as
//!   borrowed slices (zero copy per page).
//! * [`FileReader`] — wraps an open file; each `read_page` call seeks and
//!   reads exactly `page_size` bytes on demand — the full file is never
//!   buffered into memory.

use std::borrow::Cow;
use std::cell::RefCell;
use std::fs::File;
use std::io::{BufReader, Read, Seek, SeekFrom};

use forensic_rs::err::{ForensicError, ForensicResult};

// ─── Trait ────────────────────────────────────────────────────────────────────

/// Provides on-demand access to raw page bytes from an ESE database source.
pub trait PageReader {
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
pub struct SliceReader(pub Vec<u8>);

impl PageReader for SliceReader {
    fn read_page<'a>(&'a self, offset: usize, size: usize) -> ForensicResult<Cow<'a, [u8]>> {
        if offset + size > self.0.len() {
            return Err(ForensicError::missing_str("Page out of bounds"));
        }
        Ok(Cow::Borrowed(&self.0[offset..offset + size]))
    }

    fn total_size(&self) -> usize {
        self.0.len()
    }
}

// ─── FileReader ───────────────────────────────────────────────────────────────

/// Seek-based reader backed by an open file.
///
/// Only the requested page is loaded per call — the full file is never
/// buffered.  Uses `RefCell<BufReader<File>>` for interior mutability;
/// this type is intentionally single-threaded.
pub struct FileReader {
    inner: RefCell<BufReader<File>>,
    size: usize,
}

impl FileReader {
    /// Open the file at `path` for page-at-a-time reading.
    pub fn open(path: impl AsRef<std::path::Path>) -> std::io::Result<Self> {
        let file = File::open(path.as_ref())?;
        let size = file.metadata()?.len() as usize;
        Ok(Self {
            inner: RefCell::new(BufReader::new(file)),
            size,
        })
    }
}

impl PageReader for FileReader {
    fn read_page<'a>(&'a self, offset: usize, size: usize) -> ForensicResult<Cow<'a, [u8]>> {
        if offset + size > self.size {
            return Err(ForensicError::missing_str("Page out of bounds"));
        }
        let mut buf = vec![0u8; size];
        let mut inner = self.inner.borrow_mut();
        inner
            .seek(SeekFrom::Start(offset as u64))
            .map_err(|e| ForensicError::bad_format_string(format!("ESE seek error: {e}")))?;
        inner
            .read_exact(&mut buf)
            .map_err(|e| ForensicError::bad_format_string(format!("ESE read error: {e}")))?;
        Ok(Cow::Owned(buf))
    }

    fn total_size(&self) -> usize {
        self.size
    }
}
