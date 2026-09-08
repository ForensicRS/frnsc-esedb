//! Test fixture helpers.
//!
//! `artifacts/` is gitignored, so only whoever placed fixture files there
//! locally can run the tests that depend on them. Every helper here returns
//! `Option` rather than panicking/unwrapping so a test can skip gracefully
//! (`let Some(x) = helper() else { return };`) instead of failing the whole
//! suite on a fresh checkout.

use super::header::Header;

fn read_fixture(path: &str) -> Option<Vec<u8>> {
    match std::fs::read(path) {
        Ok(data) => Some(data),
        Err(e) => {
            eprintln!("SKIP: fixture '{path}' unavailable ({e}); run with fixtures present to exercise this test");
            None
        }
    }
}

pub fn load_mdb_to_memory() -> Option<Vec<u8>> {
    read_fixture("./artifacts/SystemIdentity.mdb")
}

pub fn get_mdb_and_header() -> Option<(Vec<u8>, Header)> {
    let db = read_fixture("./artifacts/SystemIdentity.mdb")?;
    let header = Header::from_buff(&db).ok()?;
    Some((db, header))
}

pub fn get_mdb_and_header_ual() -> Option<(Vec<u8>, Header)> {
    let db = read_fixture("./artifacts/UAL/UAL/Current.mdb")?;
    let header = Header::from_buff(&db).ok()?;
    Some((db, header))
}

pub fn get_srum_bytes() -> Option<Vec<u8>> {
    read_fixture("./artifacts/sru/SRUDB.dat")
}
