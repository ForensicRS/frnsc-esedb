//! `DBMS_PARAM`/`ATTACHINFO`: the region following a log file's or a
//! checkpoint's fixed header, carrying the recorded system/log paths and one
//! record per attached database.
//!
//! This region sits at a **different base offset** in a `.log` header
//! (`0x48`, immediately after `signLog`) than in a `.chk` file (`0x30`,
//! same relative position after its own `signLog`) -- verified against
//! `artifacts/sru/SRU.log` and `SRU.chk`. Worse, the offset from that base to
//! the first `ATTACHINFO` record is **568** in the log and **600** in the
//! checkpoint -- an extra ~32 bytes of fields in the checkpoint's params
//! block that are not otherwise decoded. Hardcoding either delta would work
//! for exactly one of the two file kinds, so `ATTACHINFO` records are found
//! by a bounded structural scan instead, validated against the log
//! signature's own embedded structure rather than trusted at a fixed offset.

use forensic_rs::err::{ForensicError, ForensicResult};

use crate::ese::lgpos::Lgpos;
use crate::ese::signature::Signature;

/// Byte length of each of the two ANSI path fields following the params
/// base. Verified: `system_path` at `base+0`, `log_file_path` at `base+261`.
const PATH_FIELD_LEN: usize = 261;
/// Offset from the params base to the start of the (undecoded) params block
/// that precedes the `ATTACHINFO` array. Verified at `base+522` in both a
/// log header and a checkpoint file.
const PARAMS_BLOCK_OFFSET: usize = 2 * PATH_FIELD_LEN;
/// Offset, relative to the start of one `ATTACHINFO` record, of the embedded
/// database `SIGNATURE`.
const ATTACH_SIGNATURE_OFFSET: usize = 0x43;
/// Offset, relative to the start of one `ATTACHINFO` record, of the
/// NUL-terminated UTF-16LE database path.
const ATTACH_PATH_OFFSET: usize = 0x5F;

/// Bounds used to sanity-check a candidate `ATTACHINFO`'s embedded `Lgpos`
/// during the scan. Pass generous/maximal values (see
/// [`AttachScanContext::unbounded`]) when the caller does not know its own
/// file's sector geometry (e.g. scanning a checkpoint file's params region
/// stand-alone).
#[derive(Clone, Copy, Debug)]
pub struct AttachScanContext {
    pub cb_sec: u16,
    pub csec_lg_file: u16,
}

impl AttachScanContext {
    pub fn new(cb_sec: u16, csec_lg_file: u16) -> Self {
        Self { cb_sec, csec_lg_file }
    }

    /// No sector-geometry bound available; accepts any `Lgpos` that is
    /// non-null. Used when scanning a checkpoint's params region, which
    /// carries no `cbSec`/`csecLGFile` of its own.
    pub fn unbounded() -> Self {
        Self { cb_sec: u16::MAX, csec_lg_file: u16::MAX }
    }
}

/// One attached-database record found in the `ATTACHINFO` array.
#[derive(Debug)]
pub struct AttachInfo {
    /// The LGPOS recorded at the point this database was attached.
    pub lgpos_attach: Lgpos,
    /// Verified byte-identical to the attached database's own header
    /// `database_signature` field.
    pub database_signature: Signature,
    /// The attached database's recorded path, decoded from UTF-16LE.
    pub database_path: String,
    /// The 59 undecoded bytes between the LGPOS and the signature. Two
    /// plausible-looking `Lgpos` values were observed within this region at
    /// offsets `+0x33`/`+0x3B` during investigation, but neither is
    /// corroborated by an independent cross-check, so neither is named as a
    /// field -- only the raw bytes are exposed.
    pub raw: [u8; 0x3B],
    /// Offset of this record within the region that was scanned, for
    /// provenance (so two records found in the same scan can be told apart
    /// and located again).
    pub region_offset: usize,
}

/// The decoded `DBMS_PARAM`/`ATTACHINFO` region.
#[derive(Debug)]
pub struct LogParams {
    pub system_path: String,
    pub log_file_path: String,
    /// Bytes from `base+522` to the end of the scanned region. Not decoded
    /// -- exposed raw because this sub-region's field layout is not pinned
    /// down.
    pub raw_params: Vec<u8>,
    pub attachments: Vec<AttachInfo>,
}

impl LogParams {
    /// Scan `region` (the bytes starting at a structure's params base, to
    /// the end of the sector/file) for the two path fields and any
    /// `ATTACHINFO` records.
    pub fn scan(region: &[u8], ctx: &AttachScanContext) -> ForensicResult<Self> {
        if region.len() < 2 * PATH_FIELD_LEN {
            return Err(ForensicError::invalid_format("ESE log params", "region too short for path fields"));
        }
        let system_path = decode_ansi_field(&region[0..PATH_FIELD_LEN]);
        let log_file_path = decode_ansi_field(&region[PATH_FIELD_LEN..2 * PATH_FIELD_LEN]);

        let params_start = PARAMS_BLOCK_OFFSET.min(region.len());
        let raw_params = region[params_start..].to_vec();

        let attachments = scan_attachments(&region[params_start..], params_start, ctx);

        Ok(Self { system_path, log_file_path, raw_params, attachments })
    }
}

fn decode_ansi_field(field: &[u8]) -> String {
    let end = field.iter().position(|&b| b == 0).unwrap_or(field.len());
    String::from_utf8_lossy(&field[..end]).into_owned()
}

/// Bounded structural scan for `ATTACHINFO` records within `block`. Never
/// panics on adversarial input: every index used to slice `block` is
/// checked, and a candidate is accepted only when it satisfies every gate in
/// the module documentation's admission list. `block_region_offset` is added
/// to record offsets purely for provenance in the returned
/// [`AttachInfo::region_offset`].
fn scan_attachments(block: &[u8], block_region_offset: usize, ctx: &AttachScanContext) -> Vec<AttachInfo> {
    let mut results = Vec::new();
    let mut i = 0usize;
    // Minimum bytes needed to test a candidate: LGPOS(8) + 59 raw + a
    // 28-byte signature = 0x5F, plus at least 4 bytes for a plausible
    // UTF-16LE path start (2 chars) + terminator.
    let min_candidate_len = ATTACH_PATH_OFFSET + 4;
    while i + min_candidate_len <= block.len() {
        match try_attach_at(block, i, ctx) {
            Some((attach, consumed)) => {
                results.push(AttachInfo { region_offset: block_region_offset + i, ..attach });
                i += consumed;
            }
            None => {
                i += 1;
            }
        }
    }
    results
}

fn try_attach_at(block: &[u8], i: usize, ctx: &AttachScanContext) -> Option<(AttachInfo, usize)> {
    // Gate 1: a plausible, non-null Lgpos at +0x00.
    let lgpos_bytes = block.get(i..i + 8)?;
    let lgpos_attach = Lgpos::from_buff(lgpos_bytes).ok()?;
    if lgpos_attach.is_null() {
        return None;
    }
    if lgpos_attach.generation == 0 {
        return None;
    }
    if lgpos_attach.sector >= ctx.csec_lg_file {
        return None;
    }
    if lgpos_attach.byte >= ctx.cb_sec {
        return None;
    }

    // Gate 2: room for the signature (ATTACH_SIGNATURE_OFFSET + SIZE ==
    // ATTACH_PATH_OFFSET by construction, so this also bounds the path start).
    let sig_start = i + ATTACH_SIGNATURE_OFFSET;
    let sig_end = sig_start + Signature::SIZE;
    if sig_end > block.len() {
        return None;
    }

    // Gate 3: a plausible signature (non-null, embedded LOGTIME decodes to
    // an actual instant, computer name decodes cleanly --
    // `Signature::from_buff` already enforces the ASCII-or-undecodable
    // split). Note this requires `Present` specifically, not merely
    // "not `Invalid`": an all-zero embedded LOGTIME (`Unset`) is exactly
    // the kind of coincidental match ordinary padding bytes produce, and
    // accepting it here was verified to manufacture a second, spurious
    // attachment out of `artifacts/sru/SRU.chk`'s zero-padding -- a real
    // `ATTACHINFO` record always carries an actual creation time.
    let sig_bytes = &block[sig_start..sig_end];
    let signature = Signature::from_buff(sig_bytes).ok()?;
    if signature.is_null() {
        return None;
    }
    if !matches!(signature.created(), crate::ese::signature::LogTimestamp::Present { .. }) {
        return None;
    }

    // Gate 4: a UTF-16LE path starting with a drive letter or a UNC
    // backslash, NUL-terminated (or bounded at the region end).
    let path_start = i + ATTACH_PATH_OFFSET;
    let (path, path_len) = decode_utf16_path(&block[path_start..])?;

    let raw: [u8; 0x3B] = block.get(i + 8..i + 8 + 0x3B)?.try_into().ok()?;

    let consumed = ATTACH_PATH_OFFSET + path_len;
    Some((
        AttachInfo {
            lgpos_attach,
            database_signature: signature,
            database_path: path,
            raw,
            region_offset: 0, // filled in by the caller
        },
        consumed.max(1),
    ))
}

/// Decode a NUL-terminated (or region-bounded) UTF-16LE string starting with
/// a drive letter (`X:\`) or a UNC backslash (`\`). Returns the decoded
/// string (lossy on unpaired surrogates) and the number of bytes consumed
/// (including the terminator, when one was found within the region).
fn decode_utf16_path(bytes: &[u8]) -> Option<(String, usize)> {
    if bytes.len() < 6 {
        return None;
    }
    // First char check: 'A'..'Z' or 'a'..'z' followed by ':' for a drive
    // letter, or '\\' for a UNC path. Both are ASCII-range UTF-16 code
    // units, so the low byte carries the character and the high byte is 0.
    let first = u16::from_le_bytes([bytes[0], bytes[1]]);
    let looks_like_drive = first < 128
        && (first as u8).is_ascii_alphabetic()
        && bytes.len() >= 4
        && u16::from_le_bytes([bytes[2], bytes[3]]) == u16::from(b':');
    let looks_like_unc = first == u16::from(b'\\');
    if !looks_like_drive && !looks_like_unc {
        return None;
    }

    let mut units = Vec::new();
    let mut consumed = 0usize;
    let mut idx = 0usize;
    while idx + 2 <= bytes.len() {
        let unit = u16::from_le_bytes([bytes[idx], bytes[idx + 1]]);
        idx += 2;
        if unit == 0 {
            consumed = idx;
            break;
        }
        units.push(unit);
        consumed = idx;
        // Bound the scan: a plausible Windows path is well under 260 UTF-16
        // units; refuse to run away across an unterminated region.
        if units.len() > 512 {
            return None;
        }
    }
    if units.len() < 3 {
        return None;
    }
    Some((String::from_utf16_lossy(&units), consumed))
}

#[cfg(test)]
mod tst {
    use super::*;

    fn utf16le(s: &str) -> Vec<u8> {
        let mut out = Vec::new();
        for u in s.encode_utf16() {
            out.extend_from_slice(&u.to_le_bytes());
        }
        out.extend_from_slice(&[0, 0]); // NUL terminator
        out
    }

    fn build_attach_record(lgpos: Lgpos, sig_raw: [u8; 28], path: &str) -> Vec<u8> {
        let mut rec = vec![0u8; ATTACH_PATH_OFFSET];
        rec[0..2].copy_from_slice(&lgpos.byte.to_le_bytes());
        rec[2..4].copy_from_slice(&lgpos.sector.to_le_bytes());
        rec[4..8].copy_from_slice(&lgpos.generation.to_le_bytes());
        rec[ATTACH_SIGNATURE_OFFSET..ATTACH_SIGNATURE_OFFSET + 28].copy_from_slice(&sig_raw);
        rec.extend_from_slice(&utf16le(path));
        rec
    }

    fn valid_sig_raw() -> [u8; 28] {
        let mut raw = [0u8; 28];
        raw[0..4].copy_from_slice(&0x1234_5678u32.to_le_bytes());
        raw[4..12].copy_from_slice(&[0x01, 0x08, 0x14, 0x0d, 0x0a, 0x78, 0x21, 0x00]);
        raw
    }

    fn full_region_with(record: &[u8]) -> Vec<u8> {
        let mut region = vec![0u8; 2 * PATH_FIELD_LEN];
        region[0..24].copy_from_slice(b"C:\\Windows\\system32\\SRU\\");
        region[PATH_FIELD_LEN..PATH_FIELD_LEN + 24].copy_from_slice(b"C:\\Windows\\system32\\SRU\\");
        region.resize(PARAMS_BLOCK_OFFSET, 0);
        region.extend_from_slice(record);
        region
    }

    #[test]
    fn scans_one_well_formed_attachment() {
        let lgpos = Lgpos { generation: 182, sector: 6, byte: 616 };
        let record = build_attach_record(lgpos, valid_sig_raw(), "C:\\Windows\\system32\\SRU\\SRUDB.dat");
        let region = full_region_with(&record);
        let ctx = AttachScanContext::new(4096, 16);
        let params = LogParams::scan(&region, &ctx).unwrap();
        assert_eq!(params.system_path, "C:\\Windows\\system32\\SRU\\");
        assert_eq!(params.log_file_path, "C:\\Windows\\system32\\SRU\\");
        assert_eq!(params.attachments.len(), 1);
        let a = &params.attachments[0];
        assert_eq!(a.lgpos_attach, lgpos);
        assert_eq!(a.database_path, "C:\\Windows\\system32\\SRU\\SRUDB.dat");
    }

    #[test]
    fn candidate_at_the_very_end_is_skipped_not_panicked() {
        let region = vec![0u8; 2 * PATH_FIELD_LEN + 4];
        // Not enough room for even the minimum candidate length -- must not
        // panic, must yield zero attachments.
        let ctx = AttachScanContext::unbounded();
        let params = LogParams::scan(&region, &ctx).unwrap();
        assert!(params.attachments.is_empty());
    }

    #[test]
    fn all_0xff_region_yields_zero_attachments_and_terminates() {
        let mut region = vec![0xFFu8; 2 * PATH_FIELD_LEN + 4096];
        region.truncate(2 * PATH_FIELD_LEN + 4096);
        let ctx = AttachScanContext::new(4096, 16);
        let params = LogParams::scan(&region, &ctx).unwrap();
        assert!(params.attachments.is_empty());
    }

    #[test]
    fn all_zero_region_yields_zero_attachments() {
        let region = vec![0u8; 2 * PATH_FIELD_LEN + 4096];
        let ctx = AttachScanContext::new(4096, 16);
        let params = LogParams::scan(&region, &ctx).unwrap();
        assert!(params.attachments.is_empty());
    }

    #[test]
    fn two_adjacent_records_are_both_found() {
        let lgpos1 = Lgpos { generation: 182, sector: 6, byte: 616 };
        let lgpos2 = Lgpos { generation: 183, sector: 2, byte: 100 };
        let rec1 = build_attach_record(lgpos1, valid_sig_raw(), "C:\\A.dat");
        let rec2 = build_attach_record(lgpos2, valid_sig_raw(), "C:\\B.dat");
        let mut combined = rec1.clone();
        combined.extend_from_slice(&rec2);
        let region = full_region_with(&combined);
        let ctx = AttachScanContext::new(4096, 16);
        let params = LogParams::scan(&region, &ctx).unwrap();
        assert_eq!(params.attachments.len(), 2);
        assert_eq!(params.attachments[0].database_path, "C:\\A.dat");
        assert_eq!(params.attachments[1].database_path, "C:\\B.dat");
    }

    #[test]
    fn scan_rejects_when_region_too_short_for_paths() {
        let ctx = AttachScanContext::unbounded();
        assert!(LogParams::scan(&[0u8; 10], &ctx).is_err());
    }

    #[test]
    fn real_fixture_log_and_checkpoint_agree_on_attachment() {
        let Ok(log_bytes) = std::fs::read("./artifacts/sru/SRU.log") else {
            eprintln!("SKIP: fixture unavailable");
            return;
        };
        let Ok(chk_bytes) = std::fs::read("./artifacts/sru/SRU.chk") else {
            eprintln!("SKIP: fixture unavailable");
            return;
        };
        let ctx = AttachScanContext::new(4096, 16);
        let log_params = LogParams::scan(&log_bytes[0x48..], &ctx).unwrap();
        let chk_params = LogParams::scan(&chk_bytes[0x30..], &ctx).unwrap();

        assert_eq!(log_params.system_path, "C:\\Windows\\system32\\SRU\\");
        assert_eq!(log_params.log_file_path, "C:\\Windows\\system32\\SRU\\");
        assert_eq!(chk_params.system_path, log_params.system_path);
        assert_eq!(chk_params.log_file_path, log_params.log_file_path);

        assert_eq!(log_params.attachments.len(), 1, "log attachments");
        // `SRU.chk` is 8192 bytes: two byte-identical 4096-byte halves (the
        // checkpoint file's own torn-write guard, the same idea as a log
        // sector's shadow copy, just at whole-file granularity -- verified
        // directly: `chk_bytes[0..4096] == chk_bytes[4096..8192]`). The
        // structural scan honestly finds the same ATTACHINFO record twice,
        // once in each half; both must be identical.
        assert_eq!(chk_params.attachments.len(), 2, "chk attachments (one per duplicated half)");
        assert_eq!(&chk_bytes[0..4096], &chk_bytes[4096..8192], "checkpoint halves must be identical");
        assert_eq!(
            chk_params.attachments[0].database_signature.raw,
            chk_params.attachments[1].database_signature.raw,
            "both copies of the duplicated checkpoint must agree"
        );
        assert_eq!(
            log_params.attachments[0].database_path,
            "C:\\Windows\\system32\\SRU\\SRUDB.dat"
        );
        assert_eq!(chk_params.attachments[0].database_path, log_params.attachments[0].database_path);
        assert_eq!(
            chk_params.attachments[0].database_signature.raw,
            log_params.attachments[0].database_signature.raw
        );

        // Cross-check against the database header's own signature.
        let db_bytes = std::fs::read("./artifacts/sru/SRUDB.dat").unwrap();
        assert_eq!(&log_params.attachments[0].database_signature.raw[..], &db_bytes[24..52]);
    }
}

