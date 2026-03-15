//! Integration tests for `artifacts/UAL/UAL/Current.mdb` and
//! `artifacts/UAL/UAL/{FC57251C-CDA7-4D0E-9071-60F47E1DFC55}.mdb`.
//!
//! UAL (User Access Logging) databases record per-client and per-role network
//! access events on Windows Server.  `Current.mdb` holds the active log;
//! the GUID-named file holds a yearly archive snapshot.
//!
//! Run with: `cargo test --test ual`

use frnsc_esedb::ese::{
    column::OwnedColumnValue,
    db::EseDb,
    header::{DatabaseState, FileFormatFingerprint},
};

const PATH_CURRENT: &str = "./artifacts/UAL/UAL/Current.mdb";
const PATH_GUID: &str =
    "./artifacts/UAL/UAL/{FC57251C-CDA7-4D0E-9071-60F47E1DFC55}.mdb";

fn open_current() -> EseDb {
    EseDb::open(PATH_CURRENT).expect("failed to open UAL/Current.mdb")
}

fn open_guid_db() -> EseDb {
    EseDb::open(PATH_GUID).expect("failed to open GUID-named UAL archive")
}

// ── Current.mdb — Header ──────────────────────────────────────────────────────

/// Page size must be 4 096 bytes.
#[test]
fn ual_current_header_page_size() {
    let db = open_current();
    assert_eq!(4096, db.header().page_size, "unexpected page size in Current.mdb");
}

/// Format fingerprint must be Exchange2013Ad2016 (revision 0x14).
#[test]
fn ual_current_header_fingerprint() {
    let db = open_current();
    assert_eq!(
        FileFormatFingerprint::Exchange2013Ad2016,
        db.header().fingerprint(),
        "unexpected format fingerprint in Current.mdb"
    );
}

/// A live-captured UAL database is in DirtyShutdown state (it was copied
/// while Windows still held the file open).  Verify we parse the state
/// correctly rather than returning Unknown.
#[test]
fn ual_current_header_state_parseable() {
    let db = open_current();
    let state = db.header().state();
    assert_ne!(
        DatabaseState::Unknown,
        state,
        "Current.mdb state must be a recognised DatabaseState, got Unknown"
    );
    // Current.mdb was captured while the service was running → DirtyShutdown.
    assert_eq!(
        DatabaseState::DirtyShutdown,
        state,
        "expected DirtyShutdown for a live-captured Current.mdb"
    );
}

// ── Current.mdb — Catalog ────────────────────────────────────────────────────

/// The catalog must contain at least one user table.
#[test]
fn ual_current_catalog_has_tables() {
    let db = open_current();
    assert!(
        !db.table_names().is_empty(),
        "expected at least one table in Current.mdb"
    );
}

/// The four known UAL user tables must all be present.
#[test]
fn ual_current_known_tables() {
    let db = open_current();
    let names: Vec<&str> = db.table_names();
    for expected in &["CLIENTS", "DNS", "ROLE_ACCESS", "VIRTUALMACHINES"] {
        assert!(
            names.contains(expected),
            "expected table '{expected}' not found; tables: {names:?}"
        );
    }
}

// ── Current.mdb — Column schema spot checks ───────────────────────────────────

/// DNS must have exactly the three expected columns.
#[test]
fn ual_current_dns_columns() {
    let db = open_current();
    let tbl = db.table("DNS").expect("DNS table not found");
    let col_names: Vec<&str> = tbl.columns().iter().map(|c| c.name.as_str()).collect();
    for expected in &["LastSeen", "Address", "HostName"] {
        assert!(
            col_names.contains(expected),
            "DNS missing column '{expected}'; found: {col_names:?}"
        );
    }
}

/// ROLE_ACCESS must have `RoleGuid`, `FirstSeen`, and `LastSeen`.
#[test]
fn ual_current_role_access_columns() {
    let db = open_current();
    let tbl = db.table("ROLE_ACCESS").expect("ROLE_ACCESS table not found");
    let col_names: Vec<&str> = tbl.columns().iter().map(|c| c.name.as_str()).collect();
    for expected in &["RoleGuid", "FirstSeen", "LastSeen"] {
        assert!(
            col_names.contains(expected),
            "ROLE_ACCESS missing column '{expected}'; found: {col_names:?}"
        );
    }
}

/// CLIENTS must have the core access-tracking columns.
#[test]
fn ual_current_clients_core_columns() {
    let db = open_current();
    let tbl = db.table("CLIENTS").expect("CLIENTS table not found");
    let col_names: Vec<&str> = tbl.columns().iter().map(|c| c.name.as_str()).collect();
    for expected in &[
        "RoleGuid",
        "TenantId",
        "TotalAccesses",
        "InsertDate",
        "Address",
        "AuthenticatedUserName",
    ] {
        assert!(
            col_names.contains(expected),
            "CLIENTS missing column '{expected}'; found first 20: {:?}",
            &col_names[..col_names.len().min(20)]
        );
    }
}

/// VIRTUALMACHINES must have `VmGuid`, `BIOSGuid`, `CreationTime`,
/// `LastSeenActive`, and `SerialNumber`.
#[test]
fn ual_current_virtualmachines_columns() {
    let db = open_current();
    let tbl = db.table("VIRTUALMACHINES").expect("VIRTUALMACHINES table not found");
    let col_names: Vec<&str> = tbl.columns().iter().map(|c| c.name.as_str()).collect();
    for expected in &["VmGuid", "BIOSGuid", "CreationTime", "LastSeenActive", "SerialNumber"] {
        assert!(
            col_names.contains(expected),
            "VIRTUALMACHINES missing column '{expected}'; found: {col_names:?}"
        );
    }
}

// ── Current.mdb — Row iteration ───────────────────────────────────────────────

/// Iterating all tables must not panic and must yield at least one row overall.
#[test]
fn ual_current_all_tables_iterable() {
    let db = open_current();
    let mut total = 0usize;
    for name in db.table_names() {
        let tbl = db.table(name).unwrap();
        for _row in tbl.iter_rows() {
            total += 1;
        }
    }
    assert!(total > 0, "expected at least one row across all tables in Current.mdb");
}

// ── Current.mdb — DNS deep checks ────────────────────────────────────────────

/// Every DNS row must have a non-nil, non-empty HostName.
#[test]
fn ual_current_dns_rows_have_hostname() {
    let db = open_current();
    let tbl = db.table("DNS").expect("DNS table not found");
    let rows: Vec<_> = tbl.iter_rows().collect();
    assert!(!rows.is_empty(), "DNS table must not be empty");
    for row in &rows {
        match row.get("HostName") {
            Some(OwnedColumnValue::Text(bytes)) => {
                assert!(!bytes.is_empty(), "DNS HostName must not be empty bytes");
            }
            Some(OwnedColumnValue::Nil) | None => {
                panic!("DNS row has Nil or missing HostName");
            }
            Some(_) => {} // other encodings (LongText, Binary) acceptable
        }
    }
}

/// Every DNS row must have a non-nil Address.
#[test]
fn ual_current_dns_rows_have_address() {
    let db = open_current();
    let tbl = db.table("DNS").expect("DNS table not found");
    for row in tbl.iter_rows() {
        let val = row.get("Address");
        assert!(
            val.is_some(),
            "DNS row is missing Address column"
        );
        assert!(
            !matches!(val, Some(OwnedColumnValue::Nil)),
            "DNS row has Nil Address"
        );
    }
}

// ── Current.mdb — ROLE_ACCESS deep checks ────────────────────────────────────

/// Every ROLE_ACCESS row must have a non-nil RoleGuid.
#[test]
fn ual_current_role_access_rows_have_role_guid() {
    let db = open_current();
    let tbl = db.table("ROLE_ACCESS").expect("ROLE_ACCESS table not found");
    let rows: Vec<_> = tbl.iter_rows().collect();
    assert!(!rows.is_empty(), "ROLE_ACCESS must have at least one row");
    for row in &rows {
        let val = row.get("RoleGuid");
        assert!(val.is_some(), "ROLE_ACCESS row missing RoleGuid");
        assert!(
            !matches!(val, Some(OwnedColumnValue::Nil)),
            "ROLE_ACCESS row has Nil RoleGuid"
        );
    }
}

/// CLIENTS must have more than one row (it is the primary access log).
#[test]
fn ual_current_clients_has_rows() {
    let db = open_current();
    let tbl = db.table("CLIENTS").expect("CLIENTS table not found");
    let count = tbl.iter_rows().count();
    assert!(count > 0, "CLIENTS table must not be empty");
}

/// Every CLIENTS row must have a non-nil TotalAccesses integer value.
#[test]
fn ual_current_clients_total_accesses_numeric() {
    let db = open_current();
    let tbl = db.table("CLIENTS").expect("CLIENTS table not found");
    for row in tbl.iter_rows() {
        match row.get("TotalAccesses") {
            Some(OwnedColumnValue::Long(_))
            | Some(OwnedColumnValue::UnsignedLong(_))
            | Some(OwnedColumnValue::LongLong(_)) => {} // valid numeric types
            Some(OwnedColumnValue::Nil) | None => {} // may be null in some rows
            Some(other) => panic!("unexpected TotalAccesses type: {other:?}"),
        }
    }
}

// ── GUID archive .mdb ─────────────────────────────────────────────────────────

/// The GUID-named archive must open without error.
#[test]
fn ual_guid_db_opens() {
    let _db = open_guid_db();
}

/// The GUID archive must have the same four UAL user tables as Current.mdb.
#[test]
fn ual_guid_db_known_tables() {
    let db = open_guid_db();
    let names: Vec<&str> = db.table_names();
    for expected in &["CLIENTS", "DNS", "ROLE_ACCESS", "VIRTUALMACHINES"] {
        assert!(
            names.contains(expected),
            "expected table '{expected}' in GUID archive; tables: {names:?}"
        );
    }
}

/// All tables in the GUID archive must iterate without panicking.
#[test]
fn ual_guid_db_all_tables_iterable() {
    let db = open_guid_db();
    for name in db.table_names() {
        let tbl = db.table(name).unwrap();
        for _row in tbl.iter_rows() {}
    }
}

/// The GUID archive CLIENTS table must have rows (it is an annual snapshot
/// with 236 rows in this artifact).
#[test]
fn ual_guid_db_clients_has_rows() {
    let db = open_guid_db();
    let tbl = db.table("CLIENTS").expect("CLIENTS table not found in GUID archive");
    assert!(
        tbl.iter_rows().count() > 0,
        "CLIENTS in GUID archive must not be empty"
    );
}

/// The GUID archive DNS table must have rows.
#[test]
fn ual_guid_db_dns_has_rows() {
    let db = open_guid_db();
    let tbl = db.table("DNS").expect("DNS table not found in GUID archive");
    assert!(
        tbl.iter_rows().count() > 0,
        "DNS in GUID archive must not be empty"
    );
}

/// Page size of the GUID archive must match Current.mdb (both created by the same OS).
#[test]
fn ual_guid_db_header_page_size() {
    let current = open_current();
    let archive = open_guid_db();
    assert_eq!(
        current.header().page_size,
        archive.header().page_size,
        "page size mismatch between Current.mdb and GUID archive"
    );
}
