use forensic_rs::{err::{ForensicError, ForensicResult}, utils::time::{Filetime, WinFiletime}};

use super::time::LogTime;

pub const ESE_HEADER_SIGNATURE : u32 = 0x89abcdef;

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

#[repr(packed)]
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
    pub shutdown_datetime : Filetime,
    pub attach_datetime : Filetime,
    pub attach_position : u64,
    pub detach_datetime : Filetime,
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
    pub repair_datetime : Filetime,
    pub scrub_database_time : Filetime,
    pub scrub_datetime : Filetime,
    pub required_log : u64,
    pub upgrade_exchange : u32,
    pub upgrade_free_pages : u32,
    pub upgrade_space_map_pages : u32,
    pub creation_file_format_version : u32,
    pub creation_file_format_revision : u32,
    pub old_repair_count  :u32,
    pub ecc_fix_success_count : u32,
    pub last_ecc_datetime : Filetime,
    pub old_ecc_fix_success_count : u32,
    pub ecc_fix_error_count : u32,
    pub last_ecc_error_datetime : Filetime,
    pub old_ecc_fix_error_count : u32,
    pub bad_checksum_error_count : u32,
    pub last_bad_checksum_error_datetime : Filetime,
    pub old_bad_checksum_error_count : u32,
    pub commited_log : u32,
    pub nls_major_version :u32,
    pub nls_minor_version : u32,
    pub flags : u32
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
            shutdown_datetime : LogTime(v.shutdown_datetime).try_into()?,
            attach_datetime : LogTime(v.attach_datetime).try_into()?,
            attach_position : v.attach_position,
            detach_datetime : LogTime(v.detach_datetime).try_into()?,
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
            repair_datetime : LogTime(v.repair_datetime).try_into()?,
            scrub_database_time : LogTime(v.scrub_database_time).try_into()?,
            scrub_datetime : LogTime(v.scrub_datetime).try_into()?,
            required_log : v.required_log,
            upgrade_exchange : v.upgrade_exchange,
            upgrade_free_pages : v.upgrade_free_pages,
            upgrade_space_map_pages : v.upgrade_space_map_pages,
            creation_file_format_version : v.creation_file_format_version,
            creation_file_format_revision : v.creation_file_format_revision,
            old_repair_count : v.old_repair_count,
            ecc_fix_success_count : v.ecc_fix_success_count,
            last_ecc_datetime : LogTime(v.last_ecc_datetime).try_into()?,
            old_ecc_fix_success_count : v.old_ecc_fix_success_count,
            ecc_fix_error_count : v.ecc_fix_error_count,
            last_ecc_error_datetime : LogTime(v.last_ecc_error_datetime).try_into()?,
            old_ecc_fix_error_count : v.old_ecc_fix_error_count,
            bad_checksum_error_count : v.bad_checksum_error_count,
            last_bad_checksum_error_datetime : LogTime(v.last_bad_checksum_error_datetime).try_into()?,
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
        let (head, data, _tail) = unsafe {&buffer[..].align_to::<HeaderRpr>()};
        if head.len() > 0 || data.len() == 0 {
            return Err(forensic_rs::err::ForensicError::bad_format_str("Invalid alignement"));
        }
        let header : Header = (&data[0]).try_into()?;
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

    pub fn page_to_file_offset(&self, n : u64) -> u64 {
        (n + 1) * (self.page_size as u64)
    }
}

#[cfg(test)]
mod tst {

    use crate::ese::{header::{DatabaseState, FileFormatFingerprint, Header, DATABASE_CLEAN_SHUTDOWN}, tst::load_mdb_to_memory};

    use super::HeaderRpr;

    /// Getting info from `esentutl.exe /mh .\artifacts\SystemIdentity.mdb`
    #[test]
    fn should_load_mdb_header() {
        let buffer = load_mdb_to_memory();
        let (head, data, _tail) = unsafe {&buffer[..].align_to::<HeaderRpr>()};
        assert!(head.is_empty());
        let header = &data[0];
        let header : Header = header.try_into().unwrap();
        assert_eq!("03-04-2023 13:56:53", format!("{}", header.shutdown_datetime));
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
}