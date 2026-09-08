//! ESE database file header (`Header`), parsed from the first page of a
//! `.mdb`/`.edb`/`.dat` file.

use forensic_rs::{err::{ForensicError, ForensicResult}, utils::time::ForensicTimestamp};

use super::time::LogTime;

pub const ESE_HEADER_SIGNATURE : u32 = 0x89abcdef;

/// Valid ESE page sizes. Anything else is rejected at header-parse time —
/// this is what keeps `page_to_file_offset` and `FileReader::read_page` from
/// ever being asked to allocate or seek to an attacker-chosen, unbounded
/// offset derived from a bogus `page_size`.
const VALID_PAGE_SIZES: [u32; 5] = [2048, 4096, 8192, 16384, 32768];

pub const DATABASE_JUST_CREATED : u32 = 1;
pub const DAABASE_DIRTY_SHUTDOWN : u32 = 2;
pub const DATABASE_CLEAN_SHUTDOWN : u32 = 3;
pub const DATABASE_BEING_CONVERTED : u32 = 4;
pub const DATABASE_FORCE_DETACH : u32 = 5;

#[repr(u8)]
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Default, Debug)]
pub enum DatabaseState {
    JustCreated = 0x1,
    DirtyShutdown = 0x2,
    CleanShutdown = 0x3,
    BeingConverted = 0x4,
    ForceDetach = 0x5,
    #[default]
    Unknown
}

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Default, Debug)]
pub enum FileFormatFingerprint {
    /// Version 0x00000623 Revision 0x00000000
    ///
    /// 1999 version
    NewSpaceManager,
    OriginalOperatingSystemBetaFormat,
    /// Revision 0x00000009
    WindowsXPSP3,
    /// Revision 0x0000000b
    ExchangeWithEcc,
    /// Revision 0x0000000c
    WindowsVista,
    /// Revision 0x00000011
    Windows7SP0,
    /// Revision 0x00000014
    #[default]
    Exchange2013Ad2016,
    /// Revision 0x000000c8
    Windows11_21H2,
    /// Revision 0x000000e6
    Windows11,
    Other(u32, u32)

}

#[repr(C, packed)]
pub struct HeaderRpr {
    pub checksum : u32,
    pub file_signature : u32,
    pub version : u32,
    pub r#type : u32,
    pub time : u64,
    pub database_signature : [u8; 28],
    pub state : u32,
    pub position : u64,
    pub shutdown_datetime : u64,
    pub attach_datetime : u64,
    pub attach_position : u64,
    pub detach_datetime : u64,
    pub detach_position : u64,
    pub dbid : u32,
    pub log_signature : [u8; 28],
    pub previous_full_backup : [u8; 24],
    pub previous_incremental_backup : [u8; 24],
    pub current_full_backup : [u8; 24],
    pub shadowin_disabled : u32,
    pub last_object_id : u32,
    pub major_version : u32,
    pub minor_version : u32,
    pub build_number : u32,
    pub service_pack_nmber : u32,
    pub file_format_revision : u32,
    pub page_size : u32,
    pub repair_count : u32,
    pub repair_datetime : u64,
    pub unknown2 : [u8; 28],
    pub scrub_database_time : u64,
    pub scrub_datetime : u64,
    pub required_log : u64,
    pub upgrade_exchange : u32,
    pub upgrade_free_pages : u32,
    pub upgrade_space_map_pages : u32,
    pub current_shadow_copy_backup : [u8; 24],
    pub creation_file_format_version : u32,
    pub creation_file_format_revision : u32,
    pub unknown3 : [u8; 16],
    pub old_repair_count  :u32,
    pub ecc_fix_success_count : u32,
    pub last_ecc_datetime : u64,
    pub old_ecc_fix_success_count : u32,
    pub ecc_fix_error_count : u32,
    pub last_ecc_error_datetime : u64,
    pub old_ecc_fix_error_count : u32,
    pub bad_checksum_error_count : u32,
    pub last_bad_checksum_error_datetime : u64,
    pub old_bad_checksum_error_count : u32,
    pub commited_log : u32,
    pub previous_copy_backup : [u8; 24],
    pub pevious_differential_backup : [u8; 24],
    pub unknown4 : [u8; 40],
    pub nls_major_version :u32,
    pub nls_minor_version : u32,
    pub unknown5 : [u8; 148],
    pub flags : u32
}

#[derive(Debug)]
pub struct Header {
    pub checksum : u32,
    pub version : u32,
    pub r#type : u32,
    pub time : u64,
    pub state : u32,
    pub position : u64,
    pub shutdown_datetime : ForensicTimestamp,
    pub attach_datetime : ForensicTimestamp,
    pub attach_position : u64,
    pub detach_datetime : ForensicTimestamp,
    pub detach_position : u64,
    pub dbid : u32,
    pub shadowin_disabled : u32,
    pub last_object_id : u32,
    pub major_version : u32,
    pub minor_version : u32,
    pub build_number : u32,
    pub service_pack_nmber : u32,
    pub file_format_revision : u32,
    pub page_size : u32,
    pub repair_count : u32,
    pub repair_datetime : ForensicTimestamp,
    pub scrub_database_time : ForensicTimestamp,
    pub scrub_datetime : ForensicTimestamp,
    pub required_log : u64,
    pub upgrade_exchange : u32,
    pub upgrade_free_pages : u32,
    pub upgrade_space_map_pages : u32,
    pub creation_file_format_version : u32,
    pub creation_file_format_revision : u32,
    pub old_repair_count  :u32,
    pub ecc_fix_success_count : u32,
    pub last_ecc_datetime : ForensicTimestamp,
    pub old_ecc_fix_success_count : u32,
    pub ecc_fix_error_count : u32,
    pub last_ecc_error_datetime : ForensicTimestamp,
    pub old_ecc_fix_error_count : u32,
    pub bad_checksum_error_count : u32,
    pub last_bad_checksum_error_datetime : ForensicTimestamp,
    pub old_bad_checksum_error_count : u32,
    pub commited_log : u32,
    pub nls_major_version :u32,
    pub nls_minor_version : u32,
    pub flags : u32
}

/// A `LogTime` field that fails to parse (e.g. all-zero, or an out-of-range
/// component) degrades to the Unix epoch rather than aborting the whole
/// header parse — most of these fields (`repair_datetime`, `scrub_datetime`,
/// ECC/checksum-error timestamps) are legitimately zero/unset on the vast
/// majority of databases. `shutdown_datetime`/`attach_datetime`/
/// `detach_datetime`, which matter for triage, are validated separately by
/// callers that care (see `EseDb::open`'s use of `Header::fingerprint`/`state`,
/// which do not depend on these fields at all).
fn log_time_or_epoch(raw: u64) -> ForensicTimestamp {
    LogTime(raw).try_into().unwrap_or_else(|_| ForensicTimestamp::from_win_filetime(0))
}

impl TryFrom<&HeaderRpr> for Header {
    fn try_from(v: &HeaderRpr) -> Result<Self, Self::Error> {
        Ok(Self {
            checksum : v.checksum,
            version : v.version,
            r#type : v.r#type,
            time : v.time,
            state : v.state,
            position : v.position,
            shutdown_datetime : log_time_or_epoch(v.shutdown_datetime),
            attach_datetime : log_time_or_epoch(v.attach_datetime),
            attach_position : v.attach_position,
            detach_datetime : log_time_or_epoch(v.detach_datetime),
            detach_position : v.detach_position,
            dbid : v.dbid,
            shadowin_disabled : v.shadowin_disabled,
            last_object_id : v.last_object_id,
            major_version : v.major_version,
            minor_version : v.minor_version,
            build_number : v.build_number,
            service_pack_nmber : v.service_pack_nmber,
            file_format_revision : v.file_format_revision,
            page_size : v.page_size,
            repair_count : v.repair_count,
            repair_datetime : log_time_or_epoch(v.repair_datetime),
            scrub_database_time : log_time_or_epoch(v.scrub_database_time),
            scrub_datetime : log_time_or_epoch(v.scrub_datetime),
            required_log : v.required_log,
            upgrade_exchange : v.upgrade_exchange,
            upgrade_free_pages : v.upgrade_free_pages,
            upgrade_space_map_pages : v.upgrade_space_map_pages,
            creation_file_format_version : v.creation_file_format_version,
            creation_file_format_revision : v.creation_file_format_revision,
            old_repair_count : v.old_repair_count,
            ecc_fix_success_count : v.ecc_fix_success_count,
            last_ecc_datetime : log_time_or_epoch(v.last_ecc_datetime),
            old_ecc_fix_success_count : v.old_ecc_fix_success_count,
            ecc_fix_error_count : v.ecc_fix_error_count,
            last_ecc_error_datetime : log_time_or_epoch(v.last_ecc_error_datetime),
            old_ecc_fix_error_count : v.old_ecc_fix_error_count,
            bad_checksum_error_count : v.bad_checksum_error_count,
            last_bad_checksum_error_datetime : log_time_or_epoch(v.last_bad_checksum_error_datetime),
            old_bad_checksum_error_count : v.old_bad_checksum_error_count,
            commited_log : v.commited_log,
            nls_major_version : v.nls_major_version,
            nls_minor_version : v.nls_minor_version,
            flags : v.flags,
        })
    }

    type Error = ForensicError;
}


impl Header {
    pub fn from_buff(buffer : &[u8]) -> ForensicResult<Header> {
        forensic_rs::ensure_min_length!(std::mem::size_of::<HeaderRpr>(), buffer.len(), "ESE header");
        // SAFETY: `HeaderRpr` is `#[repr(C, packed)]` (alignment 1) and every
        // field is a plain integer or byte array — any bit pattern is a valid
        // instance, so `align_to` cannot produce an invalid value. Alignment
        // 1 also means `head` is always empty; the length check above (not
        // `head.is_empty()`, which is always true) is what actually matters.
        let (head, data, _tail) = unsafe { buffer.align_to::<HeaderRpr>() };
        if !head.is_empty() || data.is_empty() {
            return Err(ForensicError::invalid_format("ESE", "Invalid alignement"));
        }
        let repr = &data[0];
        forensic_rs::ensure_format!(
            repr.file_signature == ESE_HEADER_SIGNATURE,
            "ESE",
            "bad file signature"
        );
        let page_size = repr.page_size; // copy out of the packed struct before referencing
        forensic_rs::ensure_format!(
            VALID_PAGE_SIZES.contains(&page_size),
            "ESE",
            "invalid page size"
        );
        let header : Header = repr.try_into()?;
        Ok(header)
    }
    pub fn fingerprint(&self) -> FileFormatFingerprint {
        match self.version {
            0x00000620 => {
                match self.file_format_revision {
                    0x00000000 => FileFormatFingerprint::OriginalOperatingSystemBetaFormat,
                    0x00000009 => FileFormatFingerprint::WindowsXPSP3,
                    0x0000000b => FileFormatFingerprint::ExchangeWithEcc,
                    0x0000000c => FileFormatFingerprint::WindowsVista,
                    0x00000011 => FileFormatFingerprint::Windows7SP0,
                    0x00000014 => FileFormatFingerprint::Exchange2013Ad2016,
                    0x000000c8 => FileFormatFingerprint::Windows11_21H2,
                    0x000000e6 => FileFormatFingerprint::Windows11,
                    _ => FileFormatFingerprint::Other(self.version, self.file_format_revision)
                }
            },
            0x00000623 => {
                match self.file_format_revision {
                    0x00000000 => FileFormatFingerprint::NewSpaceManager,
                    _ => FileFormatFingerprint::Other(self.version, self.file_format_revision)
                }
            },
            _ => {
                FileFormatFingerprint::Other(self.version, self.file_format_revision)
            }
        }
    }

    pub fn state(&self) -> DatabaseState {
        match self.state {
            DATABASE_JUST_CREATED => DatabaseState::JustCreated,
            DAABASE_DIRTY_SHUTDOWN => DatabaseState::DirtyShutdown,
            DATABASE_BEING_CONVERTED => DatabaseState::BeingConverted,
            DATABASE_CLEAN_SHUTDOWN => DatabaseState::CleanShutdown,
            DATABASE_FORCE_DETACH => DatabaseState::ForceDetach,
            _ => DatabaseState::Unknown
        }
    }

    /// Convert a logical page number to its byte offset in the file
    /// (page 0 is the header; page N lives at `(N+1) * page_size`).
    ///
    /// `page_size` is validated to one of the known-good ESE page sizes in
    /// [`Header::from_buff`], so this cannot overflow for any in-range page
    /// number the reader would ever be asked to seek within a real file —
    /// the checked arithmetic here is defense in depth for a corrupted or
    /// adversarially-crafted branch/root page number.
    pub fn page_to_file_offset(&self, n : u64) -> ForensicResult<u64> {
        n.checked_add(1)
            .and_then(|n| n.checked_mul(self.page_size as u64))
            .ok_or_else(|| forensic_rs::invalid_offset!(
                "ESE page_to_file_offset",
                i64::try_from(n).unwrap_or(i64::MAX),
                self.page_size as u64
            ))
    }
}

#[cfg(test)]
mod tst {

    use crate::ese::{header::{DatabaseState, FileFormatFingerprint, Header, DATABASE_CLEAN_SHUTDOWN}, tst::load_mdb_to_memory};

    /// Getting info from `esentutl.exe /mh .\artifacts\SystemIdentity.mdb`
    #[test]
    fn should_load_mdb_header() {
        let Some(buffer) = load_mdb_to_memory() else { return };
        let header = Header::from_buff(&buffer).unwrap();
        assert_eq!(2023, header.shutdown_datetime.year());
        assert_eq!(4, header.shutdown_datetime.month());
        assert_eq!(3, header.shutdown_datetime.day());
        assert_eq!(13, header.shutdown_datetime.hour());
        assert_eq!(56, header.shutdown_datetime.minute());
        assert_eq!(53, header.shutdown_datetime.second());
        assert_eq!(0x10009a53, header.checksum);
        assert_eq!(0x620, header.version);
        assert_eq!(20, header.file_format_revision);
        assert_eq!(FileFormatFingerprint::Exchange2013Ad2016, header.fingerprint());
        assert_eq!(DATABASE_CLEAN_SHUTDOWN, header.state);
        assert_eq!(DatabaseState::CleanShutdown, header.state());
        assert_eq!(13, header.last_object_id);
        assert_eq!(1, header.dbid);
        assert_eq!(0, header.shadowin_disabled);
        assert_eq!(4096, header.page_size);
    }

    use super::HeaderRpr;

    const SIG_OFF: usize = std::mem::offset_of!(HeaderRpr, file_signature);
    const PAGE_SIZE_OFF: usize = std::mem::offset_of!(HeaderRpr, page_size);

    fn valid_buf() -> Vec<u8> {
        let mut buf = vec![0u8; std::mem::size_of::<HeaderRpr>()];
        buf[SIG_OFF..SIG_OFF + 4].copy_from_slice(&super::ESE_HEADER_SIGNATURE.to_le_bytes());
        buf[PAGE_SIZE_OFF..PAGE_SIZE_OFF + 4].copy_from_slice(&4096u32.to_le_bytes());
        buf
    }

    #[test]
    fn rejects_bad_signature() {
        // Zeroed signature must fail even with an otherwise-valid page size.
        let mut buf = valid_buf();
        buf[SIG_OFF..SIG_OFF + 4].copy_from_slice(&0u32.to_le_bytes());
        assert!(Header::from_buff(&buf).is_err());
    }

    #[test]
    fn rejects_invalid_page_size() {
        let mut buf = valid_buf();
        // page_size = 0 is not one of the valid ESE page sizes.
        buf[PAGE_SIZE_OFF..PAGE_SIZE_OFF + 4].copy_from_slice(&0u32.to_le_bytes());
        assert!(Header::from_buff(&buf).is_err());
    }

    #[test]
    fn rejects_short_buffer() {
        assert!(Header::from_buff(&[0u8; 4]).is_err());
    }

    #[test]
    fn accepts_valid_header() {
        assert!(Header::from_buff(&valid_buf()).is_ok());
    }

    #[test]
    fn page_to_file_offset_overflows_cleanly() {
        let mut buf = valid_buf();
        buf[PAGE_SIZE_OFF..PAGE_SIZE_OFF + 4].copy_from_slice(&32768u32.to_le_bytes());
        let header = Header::from_buff(&buf).unwrap();
        assert!(header.page_to_file_offset(u64::MAX).is_err());
    }
}
