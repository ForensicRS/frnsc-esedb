use std::collections::HashMap;

use crate::srum::index::{AppEntry, SrumIdIndex};

// ---------------------------------------------------------------------------
// VolumeMap — \Device\HarddiskVolumeN → drive letter
// ---------------------------------------------------------------------------

/// Maps NT kernel device paths (`\Device\HarddiskVolumeN`) to drive letters
/// (`C:`, `D:`, …), enabling human-readable paths in forensic output.
///
/// # Usage
/// ```rust,ignore
/// // From external evidence (registry, WMI dump, …):
/// let mut vm = VolumeMap::new();
/// vm.add(r"\Device\HarddiskVolume2", "C:");
/// vm.add(r"\Device\HarddiskVolume4", "D:");
///
/// // Or let it autodetect from the app paths already in the index:
/// let vm = VolumeMap::autodetect(&index);
///
/// // Normalise all paths stored in the index in-place:
/// index.normalize_paths(&vm);
///
/// // Or normalise a single path on the fly:
/// let human = vm.normalize(r"\Device\HarddiskVolume2\Windows\System32\foo.exe");
/// assert_eq!(human, r"C:\Windows\System32\foo.exe");
/// ```
#[derive(Default, Clone, Debug)]
pub struct VolumeMap {
    /// `\Device\HarddiskVolumeN` → `"C:"` (no trailing backslash)
    map: HashMap<String, String>,
}

impl VolumeMap {
    pub fn new() -> Self {
        Self::default()
    }

    /// Register an explicit device→letter mapping.
    pub fn add(&mut self, device: impl Into<String>, letter: impl Into<String>) {
        self.map.insert(device.into(), letter.into());
    }

    /// Heuristic autodetection: scan all `AppEntry::Path` values in `index`
    /// and assign drive letters based on well-known Windows directory names.
    ///
    /// Heuristic rules (applied in order, first match wins per volume):
    /// - Contains `\Windows\` or `\Program Files` → `C:` (system volume)
    /// - Contains `\Users\` → `C:` (on most single-disk systems)
    ///
    /// When multiple volumes could match the same letter this returns the
    /// best-effort guess; callers with definitive evidence should use
    /// [`add`](Self::add) instead.
    pub fn autodetect(index: &SrumIdIndex) -> Self {
        let mut vm = VolumeMap::new();

        // Heuristic patterns → likely drive letter
        let system_hints: &[(&str, &str)] = &[
            (r"\Windows\",        "C:"),
            (r"\Program Files",   "C:"),
            (r"\Program Files (x86)", "C:"),
            (r"\ProgramData\",    "C:"),
            (r"\Users\",          "C:"),
        ];

        for entry in index.app.values() {
            if let AppEntry::Path(path) = entry {
                // Extract the device prefix: everything up to the 3rd backslash
                // e.g. r"\Device\HarddiskVolume2\Windows\…" → r"\Device\HarddiskVolume2"
                let device = nth_component(path, 2);
                if device.is_empty() || vm.map.contains_key(device) {
                    continue;
                }
                let rest = &path[device.len()..];
                for (hint, letter) in system_hints {
                    // case-insensitive search
                    if rest.to_ascii_lowercase().contains(&hint.to_ascii_lowercase()) {
                        vm.map.insert(device.to_owned(), letter.to_string());
                        break;
                    }
                }
            }
        }
        vm
    }

    /// Translate a single NT kernel path to a drive-letter path.
    /// Returns the original string unchanged if no mapping matches.
    pub fn normalize(&self, path: &str) -> String {
        let device = nth_component(path, 2);
        if device.is_empty() {
            return path.to_owned();
        }
        match self.map.get(device) {
            Some(letter) => format!("{}{}", letter, &path[device.len()..]),
            None => path.to_owned(),
        }
    }
}

impl SrumIdIndex {
    /// Rewrite all `AppEntry::Path` values in-place using `volumes`.
    ///
    /// Call this once after [`SrumIdIndex::load`] and optional
    /// [`SrumEnrichment`](crate::srum::enrichment::SrumEnrichment) if you
    /// want human-readable paths throughout the rest of the analysis.
    pub fn normalize_paths(&mut self, volumes: &VolumeMap) {
        for entry in self.app.values_mut() {
            if let AppEntry::Path(p) = entry {
                *p = volumes.normalize(p);
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Private helpers
// ---------------------------------------------------------------------------

/// Return the slice of `path` that covers the first `n` backslash-delimited
/// components (including leading backslash).
/// n=2: `"\Device\HarddiskVolume2\..."` → `"\Device\HarddiskVolume2"`
fn nth_component(path: &str, n: usize) -> &str {
    let mut found = 0usize;
    for (i, ch) in path.char_indices() {
        if ch == '\\' || ch == '/' {
            if i == 0 {
                continue; // skip leading separator
            }
            found += 1;
            if found == n {
                return &path[..i];
            }
        }
    }
    // Path had fewer components than n; return whole thing only if we found
    // at least n-1 separators (i.e. the path IS the device prefix).
    if found >= n - 1 {
        path
    } else {
        ""
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_nth_component() {
        let p = r"\Device\HarddiskVolume2\Windows\System32\foo.exe";
        assert_eq!(nth_component(p, 2), r"\Device\HarddiskVolume2");
    }

    #[test]
    fn test_normalize() {
        let mut vm = VolumeMap::new();
        vm.add(r"\Device\HarddiskVolume2", "C:");
        assert_eq!(
            vm.normalize(r"\Device\HarddiskVolume2\Windows\System32\foo.exe"),
            r"C:\Windows\System32\foo.exe"
        );
    }

    #[test]
    fn test_autodetect_windows_dir() {
        let mut index = SrumIdIndex::default();
        index.app.insert(
            1,
            AppEntry::Path(r"\Device\HarddiskVolume2\Windows\System32\foo.exe".to_owned()),
        );
        let vm = VolumeMap::autodetect(&index);
        assert_eq!(vm.map.get(r"\Device\HarddiskVolume2").map(String::as_str), Some("C:"));
    }

    #[test]
    fn nth_component_fewer_components() {
        // Only one component after the leading separator — fewer than n=2
        assert_eq!(nth_component(r"\Device", 2), "");
    }

    #[test]
    fn nth_component_no_separators() {
        assert_eq!(nth_component("plain_string", 2), "");
    }

    #[test]
    fn nth_component_forward_slashes() {
        let p = "/Device/HarddiskVolume2/Windows/foo.exe";
        assert_eq!(nth_component(p, 2), "/Device/HarddiskVolume2");
    }

    #[test]
    fn nth_component_trailing_separator() {
        let p = r"\Device\HarddiskVolume2\";
        assert_eq!(nth_component(p, 2), r"\Device\HarddiskVolume2");
    }

    #[test]
    fn normalize_no_op_for_unmatched_prefix() {
        let vm = VolumeMap::new();
        let path = r"\Device\HarddiskVolume99\foo.exe";
        assert_eq!(vm.normalize(path), path);
    }

    #[test]
    fn normalize_no_op_for_non_device_path() {
        let vm = VolumeMap::new();
        assert_eq!(vm.normalize("C:\\Windows\\foo.exe"), "C:\\Windows\\foo.exe");
    }
}
