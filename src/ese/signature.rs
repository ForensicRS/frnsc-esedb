//! `LOGTIME` (three-state timestamp) and `SIGNATURE` (the 28-byte instance
//! identity), shared by the database header, every transaction log header,
//! the checkpoint file, and `ATTACHINFO` records.
//!
//! `Signature` equality is the cross-file join key for the whole log-set
//! feature: a database's `log_signature`, every `.log` file's `signLog`, the
//! `.chk`'s `signLog`, and the `signDb` embedded in `ATTACHINFO` are all
//! compared byte-for-byte to establish that a set of files belongs together.
//! Getting that comparison wrong (e.g. by degrading an unparseable embedded
//! `LOGTIME` to a default instant before comparing) would let a mismatched
//! set silently pass as matching, so `Signature`'s `PartialEq` is derived
//! directly on `raw`, and its embedded timestamp is never defaulted away.

use forensic_rs::{err::ForensicResult, utils::time::ForensicTimestamp};

use super::time::LogTime;

/// An ESE `LOGTIME`, decoded to one of three states.
///
/// Unlike `Header::log_time_or_epoch` (which degrades an unparseable header
/// timestamp to the Unix epoch so a handful of legitimately-unset diagnostic
/// fields don't abort the whole header parse), this type is used in
/// case-facing summaries -- a log-set report, a sector's recorded time, a
/// signature's creation instant. Silently rendering "1601-01-01" for a value
/// that was never actually present would be a fabricated instant in exactly
/// the place an examiner is most likely to read it at face value. Every
/// consumer of `LogTimestamp` must handle `Unset`/`Invalid` explicitly
/// (`instant()` returns `None` for both) rather than receiving a defaulted
/// `ForensicTimestamp`.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum LogTimestamp {
    /// All eight bytes zero -- the field was never written. Not a time.
    Unset,
    /// Decoded to one-second resolution. `raw` retains the original eight
    /// bytes verbatim (including bytes 6/7, whose bit layout is not
    /// verified -- see `docs/internals.md` -- so no sub-second value and no
    /// timezone is asserted from them) -- stored directly rather than
    /// re-derived from `time`, so the byte-exact `tmPrevGen(N) ==
    /// tmCreate(N-1)` chain check this type exists to support can never be
    /// defeated by a lossy round-trip through the decoded calendar fields.
    Present { time: ForensicTimestamp, raw: [u8; 8] },
    /// Bytes present but not a valid date/time (out-of-range seconds,
    /// month, etc). All eight bytes preserved for inspection.
    Invalid { raw: [u8; 8] },
}

impl LogTimestamp {
    /// Decode the raw 8-byte packed `LOGTIME`.
    pub fn from_raw(raw: [u8; 8]) -> Self {
        if raw == [0u8; 8] {
            return LogTimestamp::Unset;
        }
        let value = u64::from_le_bytes(raw);
        match ForensicTimestamp::try_from(LogTime(value)) {
            Ok(time) => LogTimestamp::Present { time, raw },
            Err(_) => LogTimestamp::Invalid { raw },
        }
    }

    /// The original eight bytes, byte-exact. Used for the
    /// `tmPrevGen(N) == tmCreate(N-1)` chain check, which must compare raw
    /// bytes (including the undecoded sub-second bytes) rather than
    /// second-resolution instants, since the latter would accept a chain
    /// break that differs only in sub-second bytes.
    pub fn raw(&self) -> [u8; 8] {
        match self {
            LogTimestamp::Unset => [0u8; 8],
            LogTimestamp::Present { raw, .. } => *raw,
            LogTimestamp::Invalid { raw } => *raw,
        }
    }

    /// Bytes 6 and 7 of the raw form, verbatim and uninterpreted.
    pub fn sub_second_raw(&self) -> [u8; 2] {
        let raw = self.raw();
        [raw[6], raw[7]]
    }

    /// The decoded instant, or `None` for both `Unset` and `Invalid` -- no
    /// caller can ever obtain a fabricated instant from this type.
    pub fn instant(&self) -> Option<ForensicTimestamp> {
        match self {
            LogTimestamp::Present { time, .. } => Some(*time),
            _ => None,
        }
    }
}

/// The 16-byte computer-name field embedded in a `SIGNATURE`.
#[derive(Clone, PartialEq, Eq, Hash, Debug)]
pub enum ComputerName {
    /// All 16 bytes zero. Distinct from `Present(String::new())` -- a blank
    /// name is not evidence of divergence from another blank name, while an
    /// empty *decoded* string from non-zero bytes would be.
    Blank,
    Present(String),
    /// Not decodable as printable ASCII up to the terminator. Bytes
    /// preserved rather than a lossy string, since a garbled computer name
    /// is itself potentially significant.
    Undecodable { raw: [u8; 16] },
}

/// The 28-byte ESE `SIGNATURE`: `{ u32 random; LOGTIME created; u8
/// computer_name[16] }`. Verified byte-identical across
/// `SRUDB.dat`'s `log_signature` (@108), every log file's `signLog` (@0x2c),
/// and `SRU.chk`'s `signLog` (@0x14).
#[derive(Clone, PartialEq, Eq, Hash)]
pub struct Signature {
    /// The original 28 bytes. Equality and the cross-file join comparison
    /// are performed on this field.
    pub raw: [u8; 28],
    pub random: u32,
    pub computer_name: ComputerName,
}

impl std::fmt::Debug for Signature {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Signature {{ raw: ")?;
        for b in &self.raw {
            write!(f, "{b:02x}")?;
        }
        write!(f, ", random: 0x{:08x}, computer_name: {:?} }}", self.random, self.computer_name)
    }
}

impl Signature {
    pub const SIZE: usize = 28;

    pub fn from_buff(b: &[u8]) -> ForensicResult<Self> {
        forensic_rs::ensure_min_length!(Self::SIZE, b.len(), "ESE SIGNATURE");
        let mut raw = [0u8; 28];
        raw.copy_from_slice(&b[..28]);
        let random = u32::from_le_bytes([raw[0], raw[1], raw[2], raw[3]]);
        let name_bytes: [u8; 16] = raw[12..28].try_into().unwrap_or_default();
        let computer_name = decode_computer_name(name_bytes);
        Ok(Self { raw, random, computer_name })
    }

    /// The `LOGTIME` embedded at bytes 4..12.
    pub fn created(&self) -> LogTimestamp {
        let raw: [u8; 8] = self.raw[4..12].try_into().unwrap_or_default();
        LogTimestamp::from_raw(raw)
    }

    /// `true` when every byte is zero -- a signature that was never written
    /// (as opposed to one that was written but happens to compare unequal to
    /// another).
    pub fn is_null(&self) -> bool {
        self.raw == [0u8; 28]
    }
}

fn decode_computer_name(raw: [u8; 16]) -> ComputerName {
    if raw == [0u8; 16] {
        return ComputerName::Blank;
    }
    // ASCII up to the first NUL (or the full 16 bytes if unterminated).
    let end = raw.iter().position(|&b| b == 0).unwrap_or(16);
    let candidate = &raw[..end];
    if candidate.iter().all(|&b| b.is_ascii_graphic() || b == b' ') {
        ComputerName::Present(String::from_utf8_lossy(candidate).into_owned())
    } else {
        ComputerName::Undecodable { raw }
    }
}

#[cfg(test)]
mod tst {
    use super::*;

    fn valid_signature_bytes() -> [u8; 28] {
        // The verified SRU signature: random + a valid LOGTIME + blank name.
        let mut b = [0u8; 28];
        b[0..4].copy_from_slice(&0x52dd1ea0u32.to_le_bytes());
        // LOGTIME: sec=0x01 min=0x08 hour=0x14 day=0x0d month=0x0a year=0x78(120->2020) b6=0x21 b7=0x00
        b[4..12].copy_from_slice(&[0x01, 0x08, 0x14, 0x0d, 0x0a, 0x78, 0x21, 0x00]);
        // computer_name stays all-zero (blank), matching the fixture.
        b
    }

    #[test]
    fn round_trips_the_verified_fixture_signature() {
        let raw = valid_signature_bytes();
        let sig = Signature::from_buff(&raw).unwrap();
        assert_eq!(sig.raw, raw);
        assert_eq!(sig.random, 0x52dd1ea0);
        assert_eq!(sig.computer_name, ComputerName::Blank);
        assert!(!sig.is_null());
        let sig_time = sig.created();
        let LogTimestamp::Present { time, .. } = sig_time else {
            panic!("expected a valid embedded LOGTIME");
        };
        assert_eq!(time.year(), 2020);
        assert_eq!(time.month(), 10);
        assert_eq!(time.day(), 13);
        assert_eq!(sig_time.sub_second_raw(), [0x21, 0x00]);
    }

    #[test]
    fn from_buff_rejects_short_buffer() {
        assert!(Signature::from_buff(&[0u8; 27]).is_err());
    }

    #[test]
    fn all_zero_signature_is_null_with_unset_time_and_blank_name() {
        let sig = Signature::from_buff(&[0u8; 28]).unwrap();
        assert!(sig.is_null());
        assert_eq!(sig.created(), LogTimestamp::Unset);
        assert_eq!(sig.computer_name, ComputerName::Blank);
    }

    #[test]
    fn field_equality_matches_byte_equality() {
        let a = Signature::from_buff(&valid_signature_bytes()).unwrap();
        let b = Signature::from_buff(&valid_signature_bytes()).unwrap();
        assert_eq!(a, b);

        let mut tampered = valid_signature_bytes();
        tampered[0] ^= 0x01;
        let c = Signature::from_buff(&tampered).unwrap();
        assert_ne!(a, c);
    }

    #[test]
    fn invalid_embedded_logtime_never_produces_a_fabricated_instant() {
        let mut raw = valid_signature_bytes();
        // month = 13 is out of range (1..=12).
        raw[8] = 13;
        let sig = Signature::from_buff(&raw).unwrap();
        let LogTimestamp::Invalid { raw: preserved } = sig.created() else {
            panic!("expected Invalid, not a fabricated instant");
        };
        assert_eq!(preserved, [raw[4], raw[5], raw[6], raw[7], raw[8], raw[9], raw[10], raw[11]]);
        assert_eq!(sig.created().instant(), None);
    }

    #[test]
    fn non_ascii_computer_name_is_undecodable_not_lossy() {
        let mut raw = valid_signature_bytes();
        raw[12..28].copy_from_slice(&[0xff; 16]);
        let sig = Signature::from_buff(&raw).unwrap();
        match sig.computer_name {
            ComputerName::Undecodable { raw: name_raw } => assert_eq!(name_raw, [0xffu8; 16]),
            other => panic!("expected Undecodable, got {other:?}"),
        }
    }

    #[test]
    fn printable_ascii_computer_name_decodes() {
        let mut raw = valid_signature_bytes();
        let mut name = [0u8; 16];
        name[..7].copy_from_slice(b"HOST-01");
        raw[12..28].copy_from_slice(&name);
        let sig = Signature::from_buff(&raw).unwrap();
        assert_eq!(sig.computer_name, ComputerName::Present("HOST-01".to_string()));
    }
}
