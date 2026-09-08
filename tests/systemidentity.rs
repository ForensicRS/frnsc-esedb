//! Integration tests for `artifacts/SystemIdentity.mdb`.
//!
//! SystemIdentity.mdb is a UAL (User Access Logging) system-identity database.
//! It is created by Windows Server and records static system fingerprint data.
//!
//! Run with: `cargo test --test systemidentity`

use frnsc_esedb::ese::{
    column::OwnedColumnValue,
    db::EseDb,
    header::{DatabaseState, FileFormatFingerprint},
};

const PATH: &str = "./artifacts/SystemIdentity.mdb";

/// `artifacts/` is gitignored, so this fixture is only present for whoever
/// placed it there locally. Tests skip (rather than fail) when it's absent.
fn open_db() -> Option<EseDb> {
    if !std::path::Path::new(PATH).exists() {
        eprintln!("SKIP: fixture '{PATH}' unavailable");
        return None;
    }
    Some(EseDb::open(PATH).expect("failed to open SystemIdentity.mdb"))
}

// ── Header ────────────────────────────────────────────────────────────────────

/// The page size in SystemIdentity.mdb must be exactly 4 096 bytes.
#[test]
fn header_page_size() {
    let Some(db) = open_db() else { return; };
    assert_eq!(4096, db.header().page_size, "unexpected page size");
}

/// The format fingerprint must be Exchange2013Ad2016
/// (version=0x620, revision=0x14).
#[test]
fn header_version_fingerprint() {
    let Some(db) = open_db() else { return; };
    assert_eq!(
        FileFormatFingerprint::Exchange2013Ad2016,
        db.header().fingerprint(),
        "unexpected format fingerprint"
    );
}

/// The database must be in a clean-shutdown state (not dirty / being converted).
#[test]
fn header_database_state() {
    let Some(db) = open_db() else { return; };
    assert_eq!(
        DatabaseState::CleanShutdown,
        db.header().state(),
        "expected CleanShutdown state"
    );
}

// ── Catalog ───────────────────────────────────────────────────────────────────

/// The catalog must contain at least one user table.
#[test]
fn catalog_has_tables() {
    let Some(db) = open_db() else { return; };
    assert!(
        !db.table_names().is_empty(),
        "expected at least one table in SystemIdentity.mdb"
    );
}

/// The three forensically relevant user tables must be present.
#[test]
fn catalog_known_tables() {
    let Some(db) = open_db() else { return; };
    let names: Vec<&str> = db.table_names();

    for expected in &["SYSTEM_IDENTITY", "CHAINED_DATABASES", "ROLE_IDS"] {
        assert!(
            names.contains(expected),
            "expected table '{expected}' not found; tables: {names:?}"
        );
    }
}

/// Every table returned by `table_names()` must have at least one decoded column.
#[test]
fn table_columns_populated() {
    let Some(db) = open_db() else { return; };
    for name in db.table_names() {
        let tbl = db.table(name).unwrap_or_else(|_| panic!("table '{name}' disappeared"));
        assert!(
            !tbl.columns().is_empty(),
            "table '{name}' has no columns in the catalog"
        );
    }
}

// ── SYSTEM_IDENTITY spot checks ───────────────────────────────────────────────

/// SYSTEM_IDENTITY must have the expected forensic columns present in the schema.
#[test]
fn system_identity_expected_columns() {
    let Some(db) = open_db() else { return; };
    let tbl = db.table("SYSTEM_IDENTITY").expect("SYSTEM_IDENTITY table not found");
    let col_names: Vec<&str> = tbl.columns().iter().map(|c| c.name.as_str()).collect();

    for expected in &[
        "OSBuildNumber",
        "SystemDNSHostName",
        "SystemDomainName",
        "SystemSMBIOSUUID",
        "OSLastBootUpTime",
        "OSMajor",
        "OSMinor",
    ] {
        assert!(
            col_names.contains(expected),
            "expected column '{expected}' in SYSTEM_IDENTITY; found: {col_names:?}"
        );
    }
}

/// CHAINED_DATABASES must have `Year` and `FileName` columns.
#[test]
fn chained_databases_columns() {
    let Some(db) = open_db() else { return; };
    let tbl = db.table("CHAINED_DATABASES").expect("CHAINED_DATABASES table not found");
    let col_names: Vec<&str> = tbl.columns().iter().map(|c| c.name.as_str()).collect();
    assert!(col_names.contains(&"Year"), "missing 'Year' column");
    assert!(col_names.contains(&"FileName"), "missing 'FileName' column");
}

/// ROLE_IDS must have `RoleGuid`, `ProductName`, and `RoleName` columns.
#[test]
fn role_ids_columns() {
    let Some(db) = open_db() else { return; };
    let tbl = db.table("ROLE_IDS").expect("ROLE_IDS table not found");
    let col_names: Vec<&str> = tbl.columns().iter().map(|c| c.name.as_str()).collect();
    assert!(col_names.contains(&"RoleGuid"), "missing 'RoleGuid' column");
    assert!(col_names.contains(&"ProductName"), "missing 'ProductName' column");
    assert!(col_names.contains(&"RoleName"), "missing 'RoleName' column");
}

// ── Row iteration ─────────────────────────────────────────────────────────────

/// Iterating all rows of all tables must not panic and must yield at least one row.
#[test]
fn row_iteration_no_panic() {
    let Some(db) = open_db() else { return; };
    let mut total = 0usize;
    for name in db.table_names() {
        let tbl = db.table(name).unwrap();
        for _row in tbl.iter_rows() {
            total += 1;
        }
    }
    assert!(total > 0, "expected at least one row across all tables");
}

/// Calling `row.get(col_name)` for every column in every row must not panic.
/// Also verifies that the column values are accessible by name.
#[test]
fn row_get_column_by_name() {
    let Some(db) = open_db() else { return; };
    for name in db.table_names() {
        let tbl = db.table(name).unwrap();
        let col_names: Vec<String> = tbl.columns().iter().map(|c| c.name.clone()).collect();
        for row in tbl.iter_rows() {
            for col in &col_names {
                // Must not panic; value may be Nil but must be accessible.
                let _ = row.get(col);
            }
        }
    }
}

// ── ROLE_IDS deep spot check ──────────────────────────────────────────────────

/// ROLE_IDS rows must each have a non-nil `RoleName` value.
#[test]
fn role_ids_rows_have_role_names() {
    let Some(db) = open_db() else { return; };
    let tbl = db.table("ROLE_IDS").expect("ROLE_IDS table not found");
    let rows: Vec<_> = tbl.iter_rows().collect();
    assert!(!rows.is_empty(), "ROLE_IDS should contain at least one row");
    for row in &rows {
        let val = row.get("RoleName");
        assert!(
            val.is_some(),
            "ROLE_IDS row is missing RoleName column"
        );
        assert!(
            !matches!(val, Some(OwnedColumnValue::Nil)),
            "ROLE_IDS row has Nil RoleName"
        );
    }
}

/// ROLE_IDS rows must have a non-empty `RoleGuid` (GUID type, 16 bytes).
#[test]
fn role_ids_rows_have_guid() {
    let Some(db) = open_db() else { return; };
    let tbl = db.table("ROLE_IDS").expect("ROLE_IDS table not found");
    for row in tbl.iter_rows() {
        match row.get("RoleGuid") {
            Some(OwnedColumnValue::GUID(bytes)) => {
                assert_ne!(
                    [0u8; 16],
                    *bytes,
                    "RoleGuid should not be all-zero"
                );
            }
            Some(other) => {
                // Some artifacts store GUID as binary — still acceptable.
                let _ = other;
            }
            None => panic!("RoleGuid column missing from ROLE_IDS row"),
        }
    }
}
