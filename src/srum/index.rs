use std::collections::HashMap;
use crate::RowIter;

// ---------------------------------------------------------------------------
// AppEntry — what an app ID resolves to
// ---------------------------------------------------------------------------

/// A resolved app identity from SruDbIdMapTable.
#[derive(Debug, Clone)]
pub enum AppEntry {
    /// Full kernel device path, e.g. `\Device\HarddiskVolume2\Windows\System32\foo.exe`.
    /// Use [`crate::srum::volume::VolumeMap`] to convert to a drive-letter path.
    Path(String),
    /// Short-lived packaged/temporal app, e.g. `!!msedge.exe!2024/05/01:22:21:50!3f2312!`.
    Temporal {
        name: String,
        /// Raw string from the blob, format `YYYY/MM/DD:HH:MM:SS`.
        timestamp: String,
        /// Random instance ID parsed from hex.
        id: u64,
    },
    /// Windows Store / UWP package identity string,
    /// e.g. `Microsoft.WindowsStore_22403.1401.5.0_x64__8wekyb3d8bbwe`.
    StoreApp(String),
}

impl AppEntry {
    pub(crate) fn parse(s: String) -> Self {
        if s.starts_with("!!") {
            let parts: Vec<&str> = s.split('!').collect();
            // "!!msedge.exe!2024/05/01:22:21:50!3f2312!" →
            // ["", "", "msedge.exe", "2024/05/01:22:21:50", "3f2312", ""]
            if parts.len() >= 5 {
                let id =
                    u64::from_str_radix(parts[4].trim_end_matches('\0'), 16).unwrap_or(0);
                return AppEntry::Temporal {
                    name: parts[2].to_owned(),
                    timestamp: parts[3].to_owned(),
                    id,
                };
            }
        }
        if s.starts_with('\\') || s.starts_with('/') {
            return AppEntry::Path(s);
        }
        AppEntry::StoreApp(s)
    }

    /// Returns the executable name regardless of variant.
    pub fn name(&self) -> &str {
        match self {
            AppEntry::Path(p) => p
                .rsplit('\\')
                .next()
                .unwrap_or(p.as_str()),
            AppEntry::Temporal { name, .. } => name.as_str(),
            AppEntry::StoreApp(s) => s.as_str(),
        }
    }
}

impl std::fmt::Display for AppEntry {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AppEntry::Path(p) => write!(f, "{p}"),
            AppEntry::Temporal { name, timestamp, id } => {
                write!(f, "{name} [{timestamp}] ({id:#x})")
            }
            AppEntry::StoreApp(s) => write!(f, "{s}"),
        }
    }
}

// ---------------------------------------------------------------------------
// IdType — internal classification of IdType column values
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum IdType {
    App,         // 0-2: Win32 path, temporal, store variant
    User,        // 3: binary Windows SID
    Unknown(i64),
}

impl IdType {
    fn from_i64(v: i64) -> Self {
        match v {
            0..=2 => IdType::App,
            3 => IdType::User,
            other => IdType::Unknown(other),
        }
    }
}

// ---------------------------------------------------------------------------
// SrumIdIndex — the only thing we keep in memory
// ---------------------------------------------------------------------------

/// In-memory index of all app and user IDs from `SruDbIdMapTable`.
///
/// Only this mapping is held in RAM; all other SRUM data is streamed on demand
/// via iterators returned by [`crate::srum::SrumDatabase`].
#[derive(Default, Clone, Debug)]
pub struct SrumIdIndex {
    pub app: HashMap<i64, AppEntry>,
    /// Canonical Windows SID string, e.g. `"S-1-5-5-0-174464526"`.
    pub user: HashMap<i64, String>,
}

impl SrumIdIndex {
    /// Load the index from the `SruDbIdMapTable` ESE table.
    pub fn load(rows: RowIter<'_>) -> Self {
        let mut index = SrumIdIndex::default();
        for row in rows {
            let typ = match row.get_i64("IdType") {
                Some(v) => v,
                None => continue,
            };
            let id = match row.get_i64("IdIndex") {
                Some(v) => v,
                None => continue,
            };
            let blob = match row.get_bytes("IdBlob") {
                Some(v) => v,
                None => continue,
            };
            let (kind, data) = match blob.split_first() {
                Some(v) => v,
                None => continue,
            };
            if *kind != 1 {
                continue; // unknown blob format — skip silently
            }

            match IdType::from_i64(typ) {
                IdType::App => {
                    let s = decode_utf16_blob(data);
                    index.app.insert(id, AppEntry::parse(s));
                }
                IdType::User => {
                    let sid = parse_sid(data)
                        .unwrap_or_else(|| format!("<invalid SID: {data:?}>"));
                    index.user.insert(id, sid);
                }
                IdType::Unknown(_) => {} // forward-compat: ignore gracefully
            }
        }
        index
    }

    /// Resolve an `AppId` foreign key to its [`AppEntry`].
    #[inline]
    pub fn resolve_app(&self, id: i64) -> Option<&AppEntry> {
        self.app.get(&id)
    }

    /// Resolve a `UserId` foreign key to its SID string.
    #[inline]
    pub fn resolve_user(&self, id: i64) -> Option<&str> {
        self.user.get(&id).map(String::as_str)
    }

    /// Last sub-authority of a logon-session SID `S-1-5-5-X-Y` is the
    /// `TargetLogonId` from Event 4624 (in decimal). Returns it when the
    /// SID matches a logon session pattern.
    pub fn logon_id_for_user(&self, id: i64) -> Option<u64> {
        let sid = self.user.get(&id)?;
        // Must match S-1-5-5-*
        let after = sid.strip_prefix("S-1-5-5-")?;
        // after = "X-Y" — we want Y
        let last = after.rsplit('-').next()?;
        last.parse().ok()
    }
}

// ---------------------------------------------------------------------------
// Private helpers
// ---------------------------------------------------------------------------

/// Decode a raw byte slice as a UTF-16LE string, stripping a trailing NUL.
pub(crate) fn decode_utf16_blob(data: &[u8]) -> String {
    let wide: Vec<u16> = data
        .chunks(2)
        .map(|c| u16::from_le_bytes([c[0], c.get(1).copied().unwrap_or(0)]))
        .collect();
    let wide = wide.strip_suffix(&[0u16]).unwrap_or(&wide);
    String::from_utf16_lossy(wide).to_owned()
}

/// Parse a binary Windows SID → `"S-revision-authority[-sub...]"`.
///
/// Layout: `[revision u8, sub_count u8, authority[6] BE, sub_auth[] LE u32]`
pub(crate) fn parse_sid(data: &[u8]) -> Option<String> {
    if data.len() < 8 {
        return None;
    }
    let revision = data[0];
    let sub_count = data[1] as usize;
    if data.len() < 8 + sub_count * 4 {
        return None;
    }
    let authority = data[2..8]
        .iter()
        .fold(0u64, |acc, &b| (acc << 8) | b as u64);
    let mut sid = format!("S-{revision}-{authority}");
    for i in 0..sub_count {
        let off = 8 + i * 4;
        let sub =
            u32::from_le_bytes([data[off], data[off + 1], data[off + 2], data[off + 3]]);
        sid.push('-');
        sid.push_str(&sub.to_string());
    }
    Some(sid)
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── AppEntry::parse ──────────────────────────────────────────────────

    #[test]
    fn parse_temporal_entry() {
        let s = "!!msedge.exe!2024/05/01:22:21:50!3f2312!".to_owned();
        match AppEntry::parse(s) {
            AppEntry::Temporal { name, timestamp, id } => {
                assert_eq!(name, "msedge.exe");
                assert_eq!(timestamp, "2024/05/01:22:21:50");
                assert_eq!(id, 0x3f2312);
            }
            other => panic!("expected Temporal, got {other:?}"),
        }
    }

    #[test]
    fn parse_path_entry_backslash() {
        let s = r"\Device\HarddiskVolume2\Windows\System32\svchost.exe".to_owned();
        match AppEntry::parse(s) {
            AppEntry::Path(p) => assert!(p.contains("svchost.exe")),
            other => panic!("expected Path, got {other:?}"),
        }
    }

    #[test]
    fn parse_path_entry_forward_slash() {
        let s = "/Device/HarddiskVolume2/foo.exe".to_owned();
        match AppEntry::parse(s) {
            AppEntry::Path(p) => assert_eq!(p, "/Device/HarddiskVolume2/foo.exe"),
            other => panic!("expected Path, got {other:?}"),
        }
    }

    #[test]
    fn parse_store_app() {
        let s = "Microsoft.WindowsStore_22403.1401.5.0_x64__8wekyb3d8bbwe".to_owned();
        match AppEntry::parse(s) {
            AppEntry::StoreApp(v) => assert!(v.contains("WindowsStore")),
            other => panic!("expected StoreApp, got {other:?}"),
        }
    }

    #[test]
    fn parse_malformed_temporal_falls_back_to_store_app() {
        // Fewer than 5 !-delimited parts → not recognized as Temporal
        let s = "!!only_two_parts!".to_owned();
        assert!(matches!(AppEntry::parse(s), AppEntry::StoreApp(_)));
    }

    #[test]
    fn parse_empty_string_is_store_app() {
        assert!(matches!(AppEntry::parse(String::new()), AppEntry::StoreApp(_)));
    }

    // ── AppEntry::name ───────────────────────────────────────────────────

    #[test]
    fn name_from_path() {
        let e = AppEntry::Path(r"\Device\HarddiskVolume2\Windows\System32\foo.exe".to_owned());
        assert_eq!(e.name(), "foo.exe");
    }

    #[test]
    fn name_from_temporal() {
        let e = AppEntry::Temporal {
            name: "msedge.exe".to_owned(),
            timestamp: "2024/05/01:22:21:50".to_owned(),
            id: 0,
        };
        assert_eq!(e.name(), "msedge.exe");
    }

    #[test]
    fn name_from_store_app() {
        let e = AppEntry::StoreApp("Microsoft.WindowsStore_1.0_x64__abc".to_owned());
        assert_eq!(e.name(), "Microsoft.WindowsStore_1.0_x64__abc");
    }

    // ── AppEntry::Display ────────────────────────────────────────────────

    #[test]
    fn display_path() {
        let e = AppEntry::Path(r"\Device\foo.exe".to_owned());
        assert_eq!(format!("{e}"), r"\Device\foo.exe");
    }

    #[test]
    fn display_temporal() {
        let e = AppEntry::Temporal {
            name: "edge.exe".to_owned(),
            timestamp: "2024/01/01:00:00:00".to_owned(),
            id: 0xff,
        };
        let s = format!("{e}");
        assert!(s.contains("edge.exe"));
        assert!(s.contains("2024/01/01:00:00:00"));
        assert!(s.contains("0xff"));
    }

    #[test]
    fn display_store_app() {
        let e = AppEntry::StoreApp("pkg_1.0".to_owned());
        assert_eq!(format!("{e}"), "pkg_1.0");
    }

    // ── decode_utf16_blob ────────────────────────────────────────────────

    #[test]
    fn decode_utf16_ascii_with_nul() {
        // "ABC" as UTF-16LE + NUL terminator
        let data: Vec<u8> = vec![0x41, 0x00, 0x42, 0x00, 0x43, 0x00, 0x00, 0x00];
        assert_eq!(decode_utf16_blob(&data), "ABC");
    }

    #[test]
    fn decode_utf16_odd_length() {
        // Odd byte count: last code-unit gets zero-padded high byte
        let data: Vec<u8> = vec![0x41, 0x00, 0x42];
        assert_eq!(decode_utf16_blob(&data), "AB");
    }

    #[test]
    fn decode_utf16_empty() {
        assert_eq!(decode_utf16_blob(&[]), "");
    }

    // ── parse_sid ────────────────────────────────────────────────────────

    #[test]
    fn parse_known_sid() {
        // S-1-5-21-100-200-300-1001
        // revision=1, sub_count=5, authority=5 (big-endian 6 bytes)
        let mut data = vec![
            0x01, // revision
            0x05, // sub_count = 5
            0x00, 0x00, 0x00, 0x00, 0x00, 0x05, // authority = 5
        ];
        for sub in &[21u32, 100, 200, 300, 1001] {
            data.extend_from_slice(&sub.to_le_bytes());
        }
        assert_eq!(parse_sid(&data), Some("S-1-5-21-100-200-300-1001".to_owned()));
    }

    #[test]
    fn parse_sid_too_short() {
        assert_eq!(parse_sid(&[0x01, 0x01, 0x00]), None);
    }

    #[test]
    fn parse_sid_zero_sub_authorities() {
        let data = vec![
            0x01, // revision
            0x00, // sub_count = 0
            0x00, 0x00, 0x00, 0x00, 0x00, 0x05, // authority = 5
        ];
        assert_eq!(parse_sid(&data), Some("S-1-5".to_owned()));
    }

    #[test]
    fn parse_sid_truncated_sub_authorities() {
        // Claims 2 sub-authorities but only has bytes for 1
        let mut data = vec![
            0x01, 0x02,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x05,
        ];
        data.extend_from_slice(&21u32.to_le_bytes());
        // Missing second sub-authority bytes → None
        assert_eq!(parse_sid(&data), None);
    }

    // ── SrumIdIndex::logon_id_for_user ───────────────────────────────────

    #[test]
    fn logon_id_from_logon_session_sid() {
        let mut idx = SrumIdIndex::default();
        idx.user.insert(42, "S-1-5-5-0-174464526".to_owned());
        assert_eq!(idx.logon_id_for_user(42), Some(174464526));
    }

    #[test]
    fn logon_id_returns_none_for_non_logon_sid() {
        let mut idx = SrumIdIndex::default();
        idx.user.insert(7, "S-1-5-21-3623811015-3361044348-30300820-1013".to_owned());
        assert_eq!(idx.logon_id_for_user(7), None);
    }

    #[test]
    fn logon_id_returns_none_for_missing_user() {
        let idx = SrumIdIndex::default();
        assert_eq!(idx.logon_id_for_user(999), None);
    }

    // ── IdType ───────────────────────────────────────────────────────────

    #[test]
    fn id_type_classification() {
        assert_eq!(IdType::from_i64(0), IdType::App);
        assert_eq!(IdType::from_i64(1), IdType::App);
        assert_eq!(IdType::from_i64(2), IdType::App);
        assert_eq!(IdType::from_i64(3), IdType::User);
        assert_eq!(IdType::from_i64(99), IdType::Unknown(99));
    }
}
