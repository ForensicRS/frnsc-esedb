//! Checksum algorithms verified against real transaction-log and checkpoint
//! files, plus [`ChecksumVerdict`], which is careful to distinguish "the
//! stored checksum matched" from "no verified algorithm exists for this
//! structure" -- the two must never be conflated. Reporting a checksum as
//! valid for an algorithm/region that was never actually verified would be
//! worse than reporting nothing: it would tell an examiner a structure is
//! intact when the tool simply never checked.

/// XOR-fold a byte range as little-endian `u32` words.
///
/// A trailing partial word (when `buffer.len()` is not a multiple of 4) is
/// silently ignored -- this matters for the checkpoint checksum, whose
/// region can be any file length. Implemented with `chunks_exact` rather
/// than an `unsafe` `align_to::<u32>()` cast: the input slice is not
/// guaranteed to be 4-byte aligned (it is frequently a sub-slice starting at
/// byte offset 4), and `align_to` would silently treat a misaligned prefix
/// as an empty `head`/`tail` split that skips real data rather than
/// failing loudly. `chunks_exact` is both safe and autovectorizes.
pub fn xor32_le(buffer: &[u8]) -> u32 {
    let mut acc = 0u32;
    for chunk in buffer.chunks_exact(4) {
        acc ^= u32::from_le_bytes(chunk.try_into().unwrap_or_default());
    }
    acc
}

/// Seed for the `LOGFILEHDR` checksum. Numerically equal to
/// `header::ESE_HEADER_SIGNATURE`, but semantically a different thing --
/// kept as a separate constant so the two are never accidentally coupled.
pub const LOG_HEADER_CHECKSUM_SEED: u32 = 0x89ab_cdef;

/// `LOGFILEHDR` checksum: `LOG_HEADER_CHECKSUM_SEED ^ xor32_le(sector0[4..cb_sec])`.
///
/// Verified byte-exactly against all five log files in
/// `artifacts/sru/`. The range is `[4..cb_sec]` -- exactly one sector,
/// **not** `[4..sector0.len()]` -- so a caller who passes more than one
/// sector still gets the right answer.
pub fn log_file_header_checksum(sector0: &[u8], cb_sec: u16) -> forensic_rs::err::ForensicResult<u32> {
    let cb_sec = cb_sec as usize;
    forensic_rs::ensure_min_length!(cb_sec, sector0.len(), "ESE log header checksum region");
    Ok(LOG_HEADER_CHECKSUM_SEED ^ xor32_le(&sector0[4..cb_sec]))
}

/// `CHECKPOINT` checksum: `xor32_le(file[4..])`, seed 0.
///
/// Verified byte-exactly against `artifacts/sru/SRU.chk`
/// (`0xff61c355`). Unlike the log header checksum, this covers the *entire*
/// file from byte 4 onward, not one sector.
pub fn checkpoint_checksum(file: &[u8]) -> u32 {
    if file.len() <= 4 {
        return xor32_le(&[]);
    }
    xor32_le(&file[4..])
}

/// Why a [`ChecksumVerdict`] could not be a `Match`/`Mismatch` verdict.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum NotVerifiedReason {
    /// No known algorithm exists for this structure (e.g. the `.jfm` header,
    /// or a log data sector's per-sector checksum).
    AlgorithmUnknown,
    /// The algorithm is known, but the region it covers for this particular
    /// input is not well-defined (e.g. a `.chk` file whose length is not a
    /// multiple of 4, or shorter than the minimum header).
    RegionUnknown,
    /// The structure is a reserved/preallocated file with no meaningful
    /// content to checksum (e.g. an all-zero `.jrs` reserve log).
    ZeroFilled,
}

/// The outcome of comparing a stored checksum against a computed one -- or
/// the explicit acknowledgement that no such comparison could be made.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum ChecksumVerdict {
    Match,
    Mismatch { stored: u32, computed: u32 },
    /// No verified algorithm/region for this structure. Never elided into
    /// `Match` -- see the module documentation.
    NotVerified { reason: NotVerifiedReason },
}

#[cfg(test)]
mod tst {
    use super::*;

    #[test]
    fn xor32_le_ignores_a_trailing_partial_word() {
        assert_eq!(xor32_le(&[]), 0);
        assert_eq!(xor32_le(&[0xff]), 0);
        assert_eq!(xor32_le(&[0xff, 0xff, 0xff]), 0);
        assert_eq!(xor32_le(&[0x01, 0x00, 0x00, 0x00]), 1);
        // 7 bytes: one full word XORed, the trailing 3 bytes ignored.
        assert_eq!(xor32_le(&[0x01, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff]), 1);
        assert_eq!(
            xor32_le(&[0x01, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00]),
            1 ^ 2
        );
    }

    #[test]
    fn log_file_header_checksum_uses_cb_sec_not_buffer_len() {
        // Build two sectors; the checksum must depend only on the first.
        let mut sector0 = vec![0u8; 4096];
        sector0[4..8].copy_from_slice(&1u32.to_le_bytes());
        sector0[8..12].copy_from_slice(&2u32.to_le_bytes());
        let expected = LOG_HEADER_CHECKSUM_SEED ^ (1 ^ 2);
        assert_eq!(log_file_header_checksum(&sector0, 4096).unwrap(), expected);

        // Append a second sector full of nonzero noise; passing the whole
        // two-sector buffer with cb_sec=4096 must ignore it entirely.
        let mut two_sectors = sector0.clone();
        two_sectors.extend(vec![0xAAu8; 4096]);
        assert_eq!(log_file_header_checksum(&two_sectors, 4096).unwrap(), expected);
    }

    #[test]
    fn log_file_header_checksum_rejects_short_buffer() {
        assert!(log_file_header_checksum(&[0u8; 100], 4096).is_err());
    }

    #[test]
    fn checkpoint_checksum_matches_the_verified_fixture_value() {
        let Ok(bytes) = std::fs::read("./artifacts/sru/SRU.chk") else {
            eprintln!("SKIP: fixture 'artifacts/sru/SRU.chk' unavailable");
            return;
        };
        assert_eq!(checkpoint_checksum(&bytes), 0xff61c355);
    }

    #[test]
    fn log_file_header_checksum_matches_every_verified_fixture() {
        let cases = [
            ("./artifacts/sru/SRU.log", 185u32),
            ("./artifacts/sru/SRU000B6.log", 182u32),
            ("./artifacts/sru/SRU000B7.log", 183u32),
            ("./artifacts/sru/SRU000B8.log", 184u32),
            ("./artifacts/sru/SRUtmp.log", 181u32),
        ];
        for (path, expected_gen) in cases {
            let Ok(bytes) = std::fs::read(path) else {
                eprintln!("SKIP: fixture '{path}' unavailable");
                continue;
            };
            let stored = u32::from_le_bytes(bytes[0..4].try_into().unwrap());
            let generation = u32::from_le_bytes(bytes[4..8].try_into().unwrap());
            assert_eq!(generation, expected_gen, "{path}: unexpected generation");
            let cb_sec = u16::from_le_bytes(bytes[8..10].try_into().unwrap());
            let computed = log_file_header_checksum(&bytes, cb_sec).unwrap();
            assert_eq!(stored, computed, "{path}: checksum mismatch");
        }
    }
}
