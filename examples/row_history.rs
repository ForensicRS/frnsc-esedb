//! Group a table's live and recovered rows by a caller-chosen key, print
//! any disagreement found, and optionally export every recovered row to a
//! provenance-bearing JSONL sidecar.
//!
//! Usage: `cargo run --example row_history -- <path/to/db.dat> <table> <key column> [<key column> ...]`
//!
//! The key columns are caller-supplied because this crate does not yet
//! decode index key specifications from the catalog -- see
//! `frnsc_esedb::ese::recovery::history` for why.

use forensic_rs::provenance::{Acquisition, Recovery, SourceKey};
use frnsc_esedb::EseDb;

fn main() {
    let mut args = std::env::args().skip(1);
    let (Some(path), Some(table)) = (args.next(), args.next()) else {
        eprintln!("Usage: row_history <path/to/db.dat> <table> <key column> [<key column> ...]");
        std::process::exit(1);
    };
    let key_columns: Vec<String> = args.collect();
    if key_columns.is_empty() {
        eprintln!("At least one key column is required.");
        std::process::exit(1);
    }
    let key_refs: Vec<&str> = key_columns.iter().map(|s| s.as_str()).collect();

    let db = EseDb::open(&path).expect("failed to open ESE database");
    let report = db.row_history(&table, &key_refs).expect("row_history failed");
    let histories = report.histories;

    let disputed = histories.iter().filter(|h| h.is_disputed()).count();
    println!(
        "{table}: {} distinct key(s), {} version(s) total, {disputed} disputed",
        histories.len(),
        histories.iter().map(|h| h.versions.len()).sum::<usize>()
    );
    println!(
        "  defunct scan: {} page(s) walked, {} candidate(s), {} admitted, {} rejected, {} unreadable",
        report.defunct.pages_scanned,
        report.defunct.candidate_tags_found,
        report.defunct.rows_recovered,
        report.defunct.rows_rejected,
        report.defunct.pages_unparsable,
    );
    println!(
        "  slack scan:   {} page(s) walked, {} candidate(s), {} admitted, {} rejected, {} unreadable",
        report.slack.pages_scanned,
        report.slack.candidate_tags_found,
        report.slack.rows_recovered,
        report.slack.rows_rejected,
        report.slack.pages_unparsable,
    );
    if report.skipped_without_key.total() > 0 {
        println!(
            "  skipped for lacking a key value: {} live, {} defunct, {} slack",
            report.skipped_without_key.live, report.skipped_without_key.defunct, report.skipped_without_key.slack,
        );
    }

    for h in histories.iter().filter(|h| h.versions.len() > 1 || h.is_disputed()) {
        println!("\nkey {:?}{}", h.key, if h.is_disputed() { " (DISPUTED)" } else { "" });
        for v in &h.versions {
            println!("  [{:?} @ {:?}]", v.recovery(), v.locus());
        }
    }

    // Optional sidecar export: recovered (non-live) rows from every version
    // found above, written only if an output path was requested via the
    // FRNSC_ESEDB_SIDECAR environment variable -- never on by default.
    // Both `<path>.jsonl` and `<path>.sidecar.json` are produced.
    if let Ok(out_path) = std::env::var("FRNSC_ESEDB_SIDECAR") {
        let recovered: Vec<_> = histories
            .into_iter()
            .flat_map(|h| h.versions)
            .filter(|v| v.recovery() != Recovery::Allocated)
            .collect();
        let sidecar_path = format!("{out_path}.sidecar.json");
        let summary = frnsc_esedb::ese::recovery::sidecar::export_recovered_to_files(
            &out_path,
            &sidecar_path,
            "row_history example",
            SourceKey::Path(path.clone()),
            Acquisition::ImageRead,
            &table,
            &recovered,
        )
        .expect("sidecar export failed");
        println!(
            "\nWrote {} recovered row(s) to {out_path} (+ {sidecar_path}, {} dropped)",
            summary.written, summary.dropped
        );
    }
}
