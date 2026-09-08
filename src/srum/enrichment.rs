//! Extension points for enriching SRUM data with external sources.
//!
//! These traits define seams for future integrations (registry reader, win
//! event reader) without coupling the core parser to any specific source.

// ---------------------------------------------------------------------------
// SrumEnrichment — registry-based enrichment
// ---------------------------------------------------------------------------

/// Provides registry-sourced metadata to enrich a [`crate::srum::SrumIdIndex`].
///
/// Implement this trait on top of a forensic-rs registry reader to resolve:
/// - SRUM extension GUIDs → human-readable table names
///   (`HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SRUM\Extensions\{GUID}`)
/// - SID strings → real account (username, domain)
pub trait SrumEnrichment {
    /// Resolve a SRUM extension GUID to its human-readable display name.
    ///
    /// # Example
    /// `"{D10CA2FE-…-FA89}"` → `Some("Application Resource Usage")`
    fn resolve_extension_name(&self, guid: &str) -> Option<String>;

    /// Resolve a canonical SID string to `(username, domain)`.
    ///
    /// # Example
    /// `"S-1-5-21-3623811015-3361044348-30300820-1013"` → `Some(("jdoe", "CORP"))`
    fn resolve_user_sid(&self, sid: &str) -> Option<(String, String)>;
}

// ---------------------------------------------------------------------------
// WinEventEnrichment — Security event log / 4624 enrichment
// ---------------------------------------------------------------------------

/// Provides Windows Security Event Log data to resolve logon-session SIDs.
///
/// Implement this on top of a forensic-rs win event reader. The SRUM user
/// table stores logon-session SIDs (`S-1-5-5-X-Y`). The last sub-authority
/// Y equals the `TargetLogonId` field in Event 4624 (in decimal), which in
/// turn maps to a real `TargetUserName` / `TargetDomainName`.
pub trait WinEventEnrichment {
    /// Given the decimal value of the last SID sub-authority of a logon-session
    /// SID, return the real `(username, domain)` from Event 4624.
    ///
    /// # Example
    /// logon_id = `174464526` (= `0xa63720e`) → `Some(("jdoe", "CORP"))`
    fn resolve_logon_session(&self, logon_id: u64) -> Option<(String, String)>;
}
