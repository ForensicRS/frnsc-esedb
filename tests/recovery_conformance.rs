//! Conformance-style checks that `EseDb`'s recovery capability is reachable
//! *generically*, through `&dyn ForensicDb`/`&dyn ForensicRows`, the way
//! `forensic-rs`'s own `tests/db_conformance.rs` exercises the trait family
//! against `InMemoryForensicDb`. Public API only, from outside the crate.
//!
//! This crate's own SRUM fixture is verified to hold zero recoverable rows
//! (see `AGENTS.md` and each recovery module's `real_srum_fixture_*` tests)
//! -- an honest result, not a gap in these tests -- so what is checked here
//! is the *plumbing*: that recovery is discoverable through the base trait,
//! that an ordinary scan stays allocated-only, and that the defaults the
//! trait promises hold. Synthetic byte-level tests proving the recovery
//! sources themselves find and admit the right candidates live alongside
//! `src/ese/recovery/{defunct,slack}.rs`.

use forensic_rs::prelude::*;
use frnsc_esedb::EseDb;

fn open_fixture() -> Option<EseDb> {
    let bytes = std::fs::read("./artifacts/sru/SRUDB.dat").ok()?;
    Some(EseDb::from_bytes(bytes).expect("fixture must parse"))
}

/// `EseDb` always advertises recovery -- unlike a backend that only
/// sometimes has anything to recover, every ESE table can be asked for its
/// defunct/slack rows, even when the honest answer is "none". Reporting
/// `None` here would hide that capability from a generic caller.
#[test]
fn ese_db_always_advertises_recovery_through_the_trait_object() {
    let Some(db) = open_fixture() else {
        eprintln!("SKIP: fixture unavailable");
        return;
    };
    let db: &dyn ForensicDb = &db;
    assert!(db.as_recovery().is_some());
}

/// Recovery must be reachable without knowing `EseDb`'s concrete type, and
/// the cursor it returns must expose the table's real column set even when
/// it has zero rows to yield -- an empty cursor is not a "no such table"
/// error, and the caller must be able to tell them apart.
#[test]
fn recovered_rows_are_reachable_through_a_trait_object_with_correct_columns() {
    let Some(db) = open_fixture() else {
        eprintln!("SKIP: fixture unavailable");
        return;
    };
    let Some(table_name) = db.table_names().into_iter().next() else {
        eprintln!("SKIP: fixture has no tables");
        return;
    };
    let expected_columns = db.table(table_name).unwrap().columns().len();

    let dyn_db: &dyn ForensicDb = &db;
    let recovery = dyn_db.as_recovery().expect("EseDb must advertise recovery");

    let mut defunct = recovery.recovered_rows(table_name).unwrap();
    assert_eq!(defunct.column_count(), expected_columns);
    assert!(!defunct.next().unwrap(), "verified honest zero on this fixture");

    let mut slack = recovery.slack_rows(table_name).unwrap();
    assert_eq!(slack.column_count(), expected_columns);
    assert!(!slack.next().unwrap(), "verified honest zero on this fixture");
}

/// `row_history` is documented as log-replay-derived prior versions, which
/// this crate deliberately does not implement -- it must report the trait's
/// own "unsupported" answer (an empty cursor), never an error, so a generic
/// caller can ask every backend uniformly.
#[test]
fn row_history_reports_the_unsupported_default() {
    let Some(db) = open_fixture() else {
        eprintln!("SKIP: fixture unavailable");
        return;
    };
    let Some(table_name) = db.table_names().into_iter().next() else {
        eprintln!("SKIP: fixture has no tables");
        return;
    };
    let recovery = (&db as &dyn ForensicDb).as_recovery().unwrap();
    let mut history = recovery.row_history(table_name).unwrap();
    assert_eq!(history.column_count(), 0);
    assert!(!history.next().unwrap());
}

/// An ordinary table scan is the allocated-only view: every row it yields
/// must report itself as a live, addressable read, not the trait's
/// unaddressed default.
#[test]
fn an_ordinary_scan_reports_allocated_rows_with_a_real_locus() {
    let Some(db) = open_fixture() else {
        eprintln!("SKIP: fixture unavailable");
        return;
    };
    let Some(table_name) = db.table_names().into_iter().find(|name| {
        db.table(name).map(|t| !t.columns().is_empty()).unwrap_or(false)
    }) else {
        eprintln!("SKIP: fixture has no non-empty tables");
        return;
    };

    let table = (&db as &dyn ForensicDb).table(table_name).unwrap();
    let mut rows = table.iter_rows().unwrap();
    let Some(true) = rows.next().ok() else {
        eprintln!("SKIP: table '{table_name}' has no live rows in this fixture");
        return;
    };

    assert!(rows.allocated());
    assert_eq!(rows.recovery(), Recovery::Allocated);
    let Some(Locus::Record { page, .. }) = rows.locus() else {
        panic!("a live row must report a real Locus::Record, got {:?}", rows.locus());
    };
    assert_ne!(page, 0, "page 0 is the database header, never a table's data page");
}

/// A recovery cursor's scan diagnostics are reachable the same generic way
/// as everything else in this suite -- through `&dyn ForensicRows` -- and an
/// ordinary allocated cursor must not fabricate a scan that never happened.
#[test]
fn scan_report_distinguishes_a_recovery_scan_from_an_ordinary_read() {
    let Some(db) = open_fixture() else {
        eprintln!("SKIP: fixture unavailable");
        return;
    };
    let Some(table_name) = db.table_names().into_iter().next() else {
        eprintln!("SKIP: fixture has no tables");
        return;
    };

    // An ordinary scan reports no diagnostics: it never ran a recovery pass.
    let table = (&db as &dyn ForensicDb).table(table_name).unwrap();
    let rows = table.iter_rows().unwrap();
    assert_eq!(rows.scan_report(), None);

    // Both recovery cursors report real ground covered, even though this
    // fixture's honest result is zero admitted/rejected candidates -- the
    // table's data pages were still walked, and that count is exactly what
    // the old inherent API (`let (rows, _stats) = ...`) used to drop.
    let recovery = (&db as &dyn ForensicDb).as_recovery().unwrap();
    for cursor in [recovery.recovered_rows(table_name).unwrap(), recovery.slack_rows(table_name).unwrap()] {
        let report = cursor.scan_report().expect("a recovery cursor must report its scan");
        assert!(report.units_scanned > 0, "the table's own pages must have been walked");
        assert_eq!(report.admitted + report.rejected, report.candidates_found);
    }
}
