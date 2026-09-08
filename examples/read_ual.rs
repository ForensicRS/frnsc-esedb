//! Read and display rows from the CLIENTS table in a UAL database.
//!
//! Usage: `cargo run --example read_ual -- <path.mdb>`

use frnsc_esedb::EseDb;

fn main() {
    let path = std::env::args().nth(1).unwrap_or_else(|| {
        eprintln!("Usage: read_ual <path.mdb>");
        std::process::exit(1);
    });

    let db = EseDb::open(&path).expect("failed to open UAL database");

    let table = db.table("CLIENTS").expect("CLIENTS table not found — is this a UAL database?");
    println!(
        "CLIENTS table: {} columns",
        table.columns().len()
    );

    for (i, row) in table.iter_rows().enumerate() {
        let user = row.get_str("AuthenticatedUserName").unwrap_or_default();
        let addr = row.get_str("Address").unwrap_or_default();
        let accesses = row.get_i64("TotalAccesses").unwrap_or(0);
        let insert = row
            .get_datetime("InsertDate")
            .map(|ts| format!("{:04}-{:02}-{:02}T{:02}:{:02}:{:02}Z", ts.year(), ts.month(), ts.day(), ts.hour(), ts.minute(), ts.second()))
            .unwrap_or_else(|| "-".into());

        println!(
            "[{i:>4}] user={user:40} addr={addr:20} accesses={accesses:>6}  inserted={insert}",
        );
    }
}
