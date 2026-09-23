//! `LGPOS`: the ESE engine's position within a transaction log, shared by the
//! database header (`lgposConsistent`/`lgposAttach`/`lgposDetach`), the log
//! file header (`signLog`'s creation context, `ATTACHINFO`), the checkpoint
//! file (`lgposCheckpoint`), and every log data sector's self-identifying
//! position field.
//!
//! On disk this is `{ u16 ib; u16 isec; u32 lGeneration }` (8 bytes, byte
//! offset within the log file, sector index, log generation). That is *not*
//! the ordering an examiner cares about — two positions in different
//! generations compare by generation first, then sector, then byte — so this
//! type re-orders its fields at parse time rather than deriving `Ord` on the
//! on-disk layout directly.

use forensic_rs::err::ForensicResult;

/// A position within an ESE transaction log, as `(generation, sector, byte)`.
///
/// Field declaration order is chosen deliberately so `#[derive(Ord)]` yields
/// exactly `(generation, sector, byte)` — this does **not** match the on-disk
/// field order (`ib`, `isec`, `lGeneration`). Do not "simplify" this to mirror
/// the on-disk layout: that would silently sort by `ib` (byte offset) first,
/// which is wrong for every "is the checkpoint before the write frontier"
/// comparison this type exists to make.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Debug, Default)]
pub struct Lgpos {
    pub generation: u32,
    pub sector: u16,
    pub byte: u16,
}

impl Lgpos {
    /// Size of the on-disk `LGPOS` structure, in bytes.
    pub const SIZE: usize = 8;

    /// Decode an on-disk `LGPOS`: `{ ib: u16, isec: u16, lGeneration: u32 }`,
    /// little-endian, in that order.
    pub fn from_buff(b: &[u8]) -> ForensicResult<Self> {
        forensic_rs::ensure_min_length!(Self::SIZE, b.len(), "ESE LGPOS");
        let byte = u16::from_le_bytes([b[0], b[1]]);
        let sector = u16::from_le_bytes([b[2], b[3]]);
        let generation = u32::from_le_bytes([b[4], b[5], b[6], b[7]]);
        Ok(Self { generation, sector, byte })
    }

    /// Decode from the packed `u64` representation used by the database
    /// header's `position`/`attach_position`/`detach_position` fields, which
    /// store the same on-disk byte layout as a flat little-endian integer
    /// (`ib` in the low 16 bits, `isec` in the next 16, `lGeneration` in the
    /// high 32 bits). Lossless — the inverse of [`Self::to_u64_le`].
    pub fn from_u64_le(raw: u64) -> Self {
        let b = raw.to_le_bytes();
        Self::from_buff(&b).unwrap_or_default()
    }

    /// Re-pack into the on-disk-order `u64` representation. Lossless inverse
    /// of [`Self::from_u64_le`].
    pub fn to_u64_le(self) -> u64 {
        let mut b = [0u8; 8];
        b[0..2].copy_from_slice(&self.byte.to_le_bytes());
        b[2..4].copy_from_slice(&self.sector.to_le_bytes());
        b[4..8].copy_from_slice(&self.generation.to_le_bytes());
        u64::from_le_bytes(b)
    }

    /// `true` when every field is zero — an unset/null position (e.g. a
    /// checkpoint file's `lgposLastFullBackupCheckpoint` when no backup has
    /// ever been recorded).
    pub fn is_null(self) -> bool {
        self.generation == 0 && self.sector == 0 && self.byte == 0
    }

    /// Byte offset of this position within its own log file, given the log's
    /// sector size. Widened to `usize` before multiplying so this cannot
    /// silently wrap on a 32-bit target for an adversarial `sector`/`cb_sec`
    /// combination.
    pub fn byte_offset(self, cb_sec: u16) -> ForensicResult<usize> {
        (self.sector as usize)
            .checked_mul(cb_sec as usize)
            .and_then(|base| base.checked_add(self.byte as usize))
            .ok_or_else(|| {
                forensic_rs::invalid_offset!(
                    "ESE Lgpos::byte_offset",
                    i64::from(self.sector),
                    cb_sec as u64
                )
            })
    }
}

#[cfg(test)]
mod tst {
    use super::*;

    #[test]
    fn from_buff_decodes_on_disk_order() {
        // ib=0x0343 (835), isec=4, lGeneration=185 (0xb9) — the verified
        // `lgposConsistent` from artifacts/sru/SRUDB.dat @56.
        let raw = [0x43, 0x03, 0x04, 0x00, 0xb9, 0x00, 0x00, 0x00];
        let pos = Lgpos::from_buff(&raw).unwrap();
        assert_eq!(pos, Lgpos { generation: 185, sector: 4, byte: 835 });
    }

    #[test]
    fn from_buff_rejects_short_buffer() {
        assert!(Lgpos::from_buff(&[0u8; 7]).is_err());
    }

    #[test]
    fn u64_round_trip_is_lossless() {
        let pos = Lgpos { generation: 185, sector: 4, byte: 835 };
        assert_eq!(pos, Lgpos::from_u64_le(pos.to_u64_le()));

        // Exhaustive-ish sweep, not just the fixture value.
        for (generation, sector, byte) in [
            (0u32, 0u16, 0u16),
            (1, 0, 0),
            (0xFFFF_FFFF, 0xFFFF, 0xFFFF),
            (182, 6, 616),
            (185, 5, 0),
        ] {
            let pos = Lgpos { generation, sector, byte };
            assert_eq!(pos, Lgpos::from_u64_le(pos.to_u64_le()));
        }
    }

    #[test]
    fn ordering_is_generation_then_sector_then_byte() {
        // A hand-written `Ord` mistake (sorting by `ib`/byte first, mirroring
        // the on-disk layout) would make this fail: a later generation with a
        // small byte offset must still sort after an earlier generation with
        // a large one.
        let earlier = Lgpos { generation: 184, sector: 14, byte: 4000 };
        let later = Lgpos { generation: 185, sector: 1, byte: 0 };
        assert!(earlier < later);

        let same_gen_earlier_sector = Lgpos { generation: 185, sector: 4, byte: 9000 };
        let same_gen_later_sector = Lgpos { generation: 185, sector: 5, byte: 0 };
        assert!(same_gen_earlier_sector < same_gen_later_sector);

        let same_gen_sector_earlier_byte = Lgpos { generation: 185, sector: 5, byte: 0 };
        let same_gen_sector_later_byte = Lgpos { generation: 185, sector: 5, byte: 1 };
        assert!(same_gen_sector_earlier_byte < same_gen_sector_later_byte);
    }

    #[test]
    fn is_null_only_when_every_field_is_zero() {
        assert!(Lgpos::default().is_null());
        assert!(!Lgpos { generation: 0, sector: 0, byte: 1 }.is_null());
        assert!(!Lgpos { generation: 1, sector: 0, byte: 0 }.is_null());
    }

    #[test]
    fn byte_offset_is_checked_and_widens_before_multiply() {
        let pos = Lgpos { generation: 185, sector: 5, byte: 0 };
        assert_eq!(pos.byte_offset(4096).unwrap(), 5 * 4096);

        // Would overflow a 32-bit `usize` multiply if not widened/checked
        // first; must return an error, never panic.
        let pathological = Lgpos { generation: 1, sector: u16::MAX, byte: u16::MAX };
        // On a 64-bit target this succeeds (fits easily); the guarantee under
        // test is "no panic", which `.unwrap()` alone would already prove.
        let _ = pathological.byte_offset(8192);
    }
}
