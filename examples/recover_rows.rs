//! Recover rows absent from a table's ordinary iteration but still
//! addressable on disk: rows whose page tag is marked defunct (deleted) but
//! whose bytes have not yet been reclaimed, and candidate rows found in a
//! live page's unallocated slack.
//!
//! Driven entirely through `forensic_rs::traits::db::{ForensicDb, RecoverRows}`
//! -- the same seam a generic triage tool would use, not an ESE-specific API
//! -- to demonstrate that recovery is now discoverable without knowing the
//! concrete backend type. Every recovered row prints the exact address
//! (`recovery()`/`locus()`) it came from, so a second examiner can
//! independently re-locate and re-verify it.
//!
//! Usage: `cargo run --example recover_rows -- <path/to/db.dat>`

use forensic_rs::traits::db::{ForensicDb, ForensicRows};
use frnsc_esedb::EseDb;

fn print_recovered(name: &str, mut rows: Box<dyn ForensicRows + '_>, label: &str) -> usize {
    let mut count = 0;
    while rows.next().unwrap_or(false) {
        if count == 0 {
            println!("{name}: {label} row(s):");
        }
        count += 1;
        println!("  [{:?} @ {:?}]", rows.recovery(), rows.locus());
        for i in 0..rows.column_count() {
            if let Some(col) = rows.column_name(i) {
                if let Ok(value) = rows.read(i) {
                    if !matches!(value, forensic_rs::traits::db::ForensicValue::Null) {
                        println!("    {col} = {value:?}");
                    }
                }
            }
        }
    }
    count
}

fn main() {
    let path = std::env::args().nth(1).unwrap_or_else(|| {
        eprintln!("Usage: recover_rows <path/to/db.dat>");
        std::process::exit(1);
    });

    let db = EseDb::open(&path).expect("failed to open ESE database");
    let db: &dyn ForensicDb = &db;
    let recovery = db.as_recovery().expect("EseDb always advertises recovery");

    let mut total = 0usize;
    for name in db.list_tables().expect("list_tables failed") {
        let defunct = recovery.recovered_rows(&name).expect("defunct-row scan failed");
        total += print_recovered(&name, defunct, "defunct-tagged");

        let slack = recovery.slack_rows(&name).expect("slack scan failed");
        total += print_recovered(&name, slack, "slack-carved");
    }

    if total == 0 {
        println!("No recoverable rows found (a healthy, honest result on many databases --");
        println!("see AGENTS.md for why this crate's own SRUM fixture reports zero defunct rows today).");
    }
}
