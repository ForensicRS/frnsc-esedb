//! Group a table's live and recovered rows by key, so an examiner can see
//! every version of "the same" logical row an artifact retains -- current,
//! deleted-but-still-tagged, and slack-carved -- without any of them being
//! silently picked as "the" answer.
//!
//! # Why the key is caller-supplied, not auto-detected
//!
//! The natural design would group by the table's primary index. This crate
//! does not yet decode index key specifications -- [`crate::ese::catalog::TableDef::indexes`]
//! is names only, with no column list -- so there is no honest way to
//! derive a grouping key from the catalog today. Rather than guess (e.g.
//! "the first few fixed columns are probably the key"), the caller names
//! the columns explicitly. For SRUM tables this is normally
//! `["AppId", "UserId", "TimeStamp"]` or similar; consult the artifact's
//! own documentation for the table in question.
//!
//! # Never picking a side
//!
//! [`RowHistory::is_disputed`] reports whether any two versions disagree on
//! a non-key column, mirroring the framework's own `FactStore::observe`
//! contract (`ObservationOutcome::Diverged`) -- retained disagreement is
//! surfaced as a fact, never collapsed to one "winning" value.

use std::collections::HashMap;

use forensic_rs::err::ForensicResult;
use forensic_rs::provenance::Recovery;

use crate::ese::column::OwnedColumnValue;
use crate::ese::db::{EseDb, Row};

use super::{defunct, slack, tagged_locus, RecoveredRow, RecoveryStats};

/// One row's value as seen from one source (live iteration, or one of the
/// recovery sources).
///
/// A [`forensic_rs::recovery::Recovered<Row>`]: the row plus how it was
/// located and the exact bytes it came from. Live rows are included with
/// [`Recovery::Allocated`] and their real `(page, tag)` locus -- they are not
/// a recovery source, but placing a recovered version *relative to the
/// table's current content* is the whole point of a history.
pub type RowVersion = RecoveredRow;

/// Every version found for one key across live iteration and every
/// implemented recovery source, in the order they were found (live rows
/// first, then defunct-tagged, then slack-carved -- not a claim about
/// chronological order, since only some versions carry a usable timestamp).
#[derive(Clone, Debug)]
pub struct RowHistory {
    /// The key column values, rendered via `Display` -- see the module
    /// documentation for why this is a caller-supplied key rather than a
    /// decoded primary index.
    pub key: Vec<String>,
    pub versions: Vec<RowVersion>,
}

impl RowHistory {
    /// `true` when at least two versions disagree on some non-key column
    /// that both have a non-null value for. Never resolved to a single
    /// answer here -- see the module documentation.
    pub fn is_disputed(&self) -> bool {
        let Some((first, rest)) = self.versions.split_first() else { return false };
        rest.iter().any(|v| rows_disagree(first.value(), v.value()))
    }
}

fn rows_disagree(a: &Row, b: &Row) -> bool {
    for (name, a_val) in a.iter() {
        if matches!(a_val, OwnedColumnValue::Nil) {
            continue;
        }
        let Some(b_val) = b.get(name) else { continue };
        if matches!(b_val, OwnedColumnValue::Nil) {
            continue;
        }
        // Compared via `Display` rather than a derived `PartialEq` on
        // `OwnedColumnValue`: two independently-decoded values that render
        // identically are close enough for "do these two sources agree",
        // and this avoids requiring float/byte-exact equality semantics
        // this module has no need to define.
        if a_val.to_string() != b_val.to_string() {
            return true;
        }
    }
    false
}

/// How many versions -- by source -- could not be placed into any history
/// because they were missing a value for one of the caller's key columns.
///
/// Reported per source, not as one total: "5 live rows had no key" and "5
/// slack candidates had no key" mean very different things to an examiner --
/// the first suggests the chosen key columns are a poor fit for this table,
/// the second is closer to routine (a slack candidate's admitted columns are
/// whatever survived the admission gate, not a guaranteed full row).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct SkippedWithoutKey {
    pub live: usize,
    pub defunct: usize,
    pub slack: usize,
}

impl SkippedWithoutKey {
    pub fn total(&self) -> usize {
        self.live + self.defunct + self.slack
    }
}

/// The result of one [`row_history`] call: the groupings themselves, plus
/// the diagnostics that used to be dropped at this exact boundary
/// (`let (rows, _) = recover_defunct_rows(..)`, mirroring the bug
/// `ForensicRows::scan_report()` was added to close on the trait-cursor
/// path -- see [`super::RecoveryStats`]'s own documentation on why it exists
/// as a type separate from that cursor). "How hard did this look, and what
/// did it reject" is case-relevant here, not debug noise.
#[derive(Clone, Debug, Default)]
pub struct RowHistoryReport {
    pub histories: Vec<RowHistory>,
    /// Scan diagnostics from the defunct-tag pass. Reported separately from
    /// `slack`, not summed -- collapsing them would hide which source
    /// actually did the work.
    pub defunct: RecoveryStats,
    pub slack: RecoveryStats,
    pub skipped_without_key: SkippedWithoutKey,
}

/// Build every row's history for `table`, keyed by `key_columns` (see the
/// module documentation for why this is caller-supplied). A row missing a
/// value for any key column cannot be placed in a history without inventing
/// a key for it -- it is still counted, in the returned report's
/// `skipped_without_key`, rather than silently vanishing.
pub fn row_history(db: &EseDb, table: &str, key_columns: &[&str]) -> ForensicResult<RowHistoryReport> {
    let mut order: Vec<RowHistory> = Vec::new();
    let mut index: HashMap<Vec<String>, usize> = HashMap::new();
    let mut skipped = SkippedWithoutKey::default();

    {
        let handle = db.table(table)?;
        let mut rows = handle.iter_rows();
        while let Some(row) = rows.next() {
            // `current_locus()` is set by the `next()` that just produced
            // this row. A live row always has a genuine `(page, tag)` home,
            // so `Locus::Api` here would be a fabrication, not a fallback --
            // skip rather than invent one.
            let Some((page, tag)) = rows.current_locus() else { continue };
            let placed = add_version(
                &mut order,
                &mut index,
                key_columns,
                RowVersion::new(row, Recovery::Allocated, tagged_locus(page, tag)),
            );
            if !placed {
                skipped.live += 1;
            }
        }
    }

    let (defunct_rows, defunct_stats) = defunct::recover_defunct_rows(db, table)?;
    for r in defunct_rows {
        if !add_version(&mut order, &mut index, key_columns, r) {
            skipped.defunct += 1;
        }
    }

    let (slack_rows, slack_stats) = slack::recover_slack_rows(db, table)?;
    for r in slack_rows {
        if !add_version(&mut order, &mut index, key_columns, r) {
            skipped.slack += 1;
        }
    }

    Ok(RowHistoryReport { histories: order, defunct: defunct_stats, slack: slack_stats, skipped_without_key: skipped })
}

/// Place `version` into `order`/`index` under its key. Returns `false`
/// (without touching `order`/`index`) when `version` has no value for at
/// least one key column -- the caller counts this, it does not just drop it.
fn add_version(
    order: &mut Vec<RowHistory>,
    index: &mut HashMap<Vec<String>, usize>,
    key_columns: &[&str],
    version: RowVersion,
) -> bool {
    let Some(key): Option<Vec<String>> =
        key_columns.iter().map(|c| version.value().get(c).map(|v| v.to_string())).collect()
    else {
        return false;
    };
    match index.get(&key) {
        Some(&i) => order[i].versions.push(version),
        None => {
            index.insert(key.clone(), order.len());
            order.push(RowHistory { key, versions: vec![version] });
        }
    }
    true
}

#[cfg(test)]
mod tst {
    use super::*;
    use super::super::slack_locus;

    #[test]
    fn real_srum_fixture_history_groups_by_declared_key_without_panicking() {
        let Ok(bytes) = std::fs::read("./artifacts/sru/SRUDB.dat") else {
            eprintln!("SKIP: fixture unavailable");
            return;
        };
        let db = EseDb::from_bytes(bytes).unwrap();
        for name in db.table_names() {
            let table = db.table(name).unwrap();
            let columns = table.columns();
            if columns.is_empty() {
                continue;
            }
            // Use the first column as a (probably degenerate but always
            // present) key just to exercise the grouping/dispute logic
            // without panicking across every real table shape.
            let key_col = columns[0].name.clone();
            let report = row_history(&db, name, &[key_col.as_str()]).unwrap();
            for h in &report.histories {
                assert_eq!(h.key.len(), 1);
                assert!(!h.versions.is_empty());
                let _ = h.is_disputed();
            }
        }
    }

    /// The whole point of this fix: a caller can see how much ground each
    /// scan actually covered, instead of the stats disappearing at this
    /// boundary the way `let (rows, _) = ...` used to drop them.
    #[test]
    fn scan_stats_from_both_sources_are_reported_not_dropped() {
        let Ok(bytes) = std::fs::read("./artifacts/sru/SRUDB.dat") else {
            eprintln!("SKIP: fixture unavailable");
            return;
        };
        let db = EseDb::from_bytes(bytes).unwrap();
        let Some(name) = db.table_names().into_iter().find(|n| !db.table(n).unwrap().columns().is_empty()) else {
            eprintln!("SKIP: fixture has no non-empty tables");
            return;
        };
        let key_col = db.table(name).unwrap().columns()[0].name.clone();
        let report = row_history(&db, name, &[key_col.as_str()]).unwrap();
        // Both scans walked this table's own data tree -- the page count is
        // exactly what the old `let (rows, _) = ...` used to make
        // unobservable, regardless of this fixture's separately-verified
        // honest-zero admission result (see `recovery::defunct`/
        // `recovery::slack`'s own `real_srum_fixture_*` tests).
        assert!(report.defunct.pages_scanned > 0, "defunct scan must report pages walked");
        assert!(report.slack.pages_scanned > 0, "slack scan must report pages walked");
        // Each scan's own bookkeeping stays internally consistent.
        assert_eq!(
            report.defunct.rows_recovered + report.defunct.rows_rejected,
            report.defunct.candidate_tags_found
        );
    }

    #[test]
    fn missing_table_returns_an_error_not_a_panic() {
        let Ok(bytes) = std::fs::read("./artifacts/sru/SRUDB.dat") else {
            eprintln!("SKIP: fixture unavailable");
            return;
        };
        let db = EseDb::from_bytes(bytes).unwrap();
        assert!(row_history(&db, "does-not-exist-anywhere", &["Col"]).is_err());
    }

    #[test]
    fn rows_missing_a_key_column_value_are_skipped_but_counted_not_fabricated() {
        let Ok(bytes) = std::fs::read("./artifacts/sru/SRUDB.dat") else {
            eprintln!("SKIP: fixture unavailable");
            return;
        };
        let db = EseDb::from_bytes(bytes).unwrap();
        let Some(name) = db.table_names().into_iter().next() else { return };
        let live_row_count = db.table(name).unwrap().iter_rows().count();

        // A key column name that certainly does not exist on any row.
        let report = row_history(&db, name, &["___definitely_not_a_real_column___"]).unwrap();
        assert!(report.histories.is_empty(), "no key value can ever match, so no history can form");
        // Not fabricated into a history, but not silently dropped either --
        // every live row in the table was individually counted as skipped.
        assert_eq!(report.skipped_without_key.live, live_row_count);
    }

    #[test]
    fn is_disputed_is_false_for_a_single_version() {
        let history = RowHistory {
            key: vec!["k".to_string()],
            versions: vec![RowVersion::new(
                Row::from_pairs(vec![("Col".to_string(), OwnedColumnValue::Long(1))]),
                Recovery::Allocated,
                tagged_locus(1, 1),
            )],
        };
        assert!(!history.is_disputed());
    }

    #[test]
    fn is_disputed_detects_a_disagreeing_non_key_column() {
        let make = |v: i32| Row::from_pairs(vec![("Val".to_string(), OwnedColumnValue::Long(v))]);
        let history = RowHistory {
            key: vec!["k".to_string()],
            versions: vec![
                RowVersion::new(make(1), Recovery::Allocated, tagged_locus(1, 1)),
                RowVersion::new(make(2), Recovery::DeletedMetadata, tagged_locus(1, 2)),
            ],
        };
        assert!(history.is_disputed());
    }

    #[test]
    fn is_disputed_is_false_when_only_nulls_differ() {
        let a = Row::from_pairs(vec![
            ("Val".to_string(), OwnedColumnValue::Long(1)),
            ("Extra".to_string(), OwnedColumnValue::Nil),
        ]);
        let b = Row::from_pairs(vec![
            ("Val".to_string(), OwnedColumnValue::Long(1)),
            ("Extra".to_string(), OwnedColumnValue::Text(vec![1, 2, 3])),
        ]);
        let history = RowHistory {
            key: vec!["k".to_string()],
            versions: vec![
                RowVersion::new(a, Recovery::Allocated, tagged_locus(1, 1)),
                RowVersion::new(b, Recovery::Slack, slack_locus(1, 0x1000)),
            ],
        };
        // One side is Nil for `Extra`, so the two are not comparable there --
        // must not count as a disagreement.
        assert!(!history.is_disputed());
    }
}
