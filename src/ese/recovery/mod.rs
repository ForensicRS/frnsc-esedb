//! Value recovery: rows that are absent from the database's ordinary
//! iteration but still recoverable from bytes the engine has not yet
//! overwritten.
//!
//! This is deliberately narrower than log replay (see the crate
//! documentation on why replay is not attempted): every source here is
//! read-only inspection of bytes that already exist on disk, validated
//! through the *same* decoder the live read path uses
//! ([`crate::ese::column::TableSchema::decode_record`]), never a
//! speculative reconstruction. A candidate that does not decode cleanly is
//! dropped, not reported with lower confidence -- see
//! [`defunct::recover_defunct_rows`]'s module documentation for the
//! rationale, copied from this crate's closest precedent
//! (`frnsc-hive`'s deleted-cell carving).
//!
//! # Scope of this pass
//!
//! Two sources are implemented: [`defunct::recover_defunct_rows`] (rows
//! whose page tag is still marked with [`crate::ese::tag::TAG_DEFUNCT`] but
//! whose bytes have not yet been reclaimed) and [`slack::recover_slack_rows`]
//! (candidate records found in the unallocated region between a live page's
//! data and its tag array). Log-borne row recovery is follow-up work -- see
//! the crate's implementation plan.
//!
//! Both sources share the same admission gate ([`validate::decode_and_admit`])
//! but differ in risk: a defunct tag is reliable evidence the engine itself
//! produced (it explicitly marks deletion), while a slack candidate is
//! located purely by structural plausibility with no such marker -- see
//! [`slack`]'s module documentation for the additional constraints that
//! difference demands.
//!
//! # A note on the existing row iterator
//!
//! [`crate::ese::db::RowIter`] (via [`crate::ese::page::leaf::LeafPageEntry::leaf_entries`])
//! does **not** filter on `TAG_DEFUNCT` today: it decodes every tag on a
//! leaf page, live or defunct, into the same undifferentiated row stream.
//! That means a table's ordinary iteration can already silently include
//! logically-deleted rows with no way to tell them apart from live ones --
//! discovered while building this module, and out of scope to change here
//! (it is a behavior change to a heavily-used, already-tested code path,
//! not a new capability), but worth flagging: an examiner relying on
//! `Table::iter_rows()` row counts alone should be aware of it.

pub mod defunct;
pub mod history;
pub mod sidecar;
pub mod slack;
pub mod validate;

use forensic_rs::provenance::Locus;

use crate::ese::db::Row;

/// One row recovered from a source other than ordinary, live iteration.
///
/// [`forensic_rs::recovery::Recovered`] carries the two things a recovered
/// value must never travel without: *how* it was located
/// ([`forensic_rs::provenance::Recovery`]) and *exactly which bytes* it came
/// from ([`Locus`]). It deliberately has no `Deref` -- reach the row through
/// `value()`/`into_value()`, so dropping the recovery mode is visible in
/// review rather than implicit.
///
/// The owning table is not a field here: every cursor and every recovery
/// function is already scoped to one table, so carrying the name per row
/// would just duplicate it.
pub type RecoveredRow = forensic_rs::recovery::Recovered<Row>;

/// The `Locus` for a defunct-tagged row: a genuine `(page, tag)` home the
/// engine itself wrote.
pub(crate) fn tagged_locus(page: u32, tag: u16) -> Locus {
    Locus::Record { page: page as u64, slot: tag as u32 }
}

/// The `Locus` for a slack candidate: the page it was found on, plus a byte
/// offset within that page.
///
/// Deliberately **not** `Locus::Record`: a slack candidate has no tag, and
/// putting a byte offset in `slot` would make a reader seek to the wrong
/// place. `Locus::PageOffset` is the shape core added for exactly this —
/// a paged container's unallocated space, addressed by offset rather than
/// slot — and it is strictly more useful than flattening to an absolute
/// file offset (`Locus::RawOffset`) would be: the page number is a real
/// fact a second examiner wants (which page's slack this was, not just
/// where in the file), and keeping it means never needing `Header` (or its
/// fallible `page_to_file_offset`) just to report an address.
pub(crate) fn slack_locus(page: u32, offset_in_page: u32) -> Locus {
    Locus::PageOffset { page: page as u64, offset: offset_in_page }
}

/// Diagnostic counters for one recovery pass, mirroring
/// [`crate::ese::tree::TreeStats`]'s "here is what was degraded" shape.
///
/// Kept as its own type (not just built directly as a
/// `forensic_rs::recovery::RecoveryReport`) because ESE's own recovery
/// functions are also called directly by [`history::row_history`], which has
/// no `ForensicRows` cursor to hang a `scan_report()` off of -- see
/// [`RecoveryStats::to_report`] for the seam where the two meet.
#[derive(Clone, Copy, Debug, Default)]
pub struct RecoveryStats {
    pub pages_scanned: usize,
    pub candidate_tags_found: usize,
    pub rows_recovered: usize,
    /// A candidate that failed the admission gate (see
    /// [`defunct::recover_defunct_rows`]) -- silently dropped, not reported
    /// with lower confidence.
    pub rows_rejected: usize,
    pub pages_unparsable: usize,
}

impl RecoveryStats {
    /// Convert to the framework's scan-level diagnostics shape, for
    /// `ForensicRows::scan_report()`. Field-for-field: `pages_scanned` is
    /// "units walked" (ESE's unit is a page), `candidate_tags_found` is
    /// candidates, `rows_recovered`/`rows_rejected` are admitted/rejected,
    /// and `pages_unparsable` is unreadable.
    pub(crate) fn to_report(self) -> forensic_rs::recovery::RecoveryReport {
        forensic_rs::recovery::RecoveryReport {
            units_scanned: self.pages_scanned as u64,
            candidates_found: self.candidate_tags_found as u64,
            admitted: self.rows_recovered as u64,
            rejected: self.rows_rejected as u64,
            unreadable: self.pages_unparsable as u64,
        }
    }
}
