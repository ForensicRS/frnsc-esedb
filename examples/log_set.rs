//! Discover an ESE database's transaction-log set and print an integrity
//! report: which generations are present, what's missing, whether the
//! database needs log replay, and any anomalies found -- each with the
//! benign explanation an examiner should rule out before treating it as
//! evidence of tampering.
//!
//! Usage: `cargo run --example log_set -- <path/to/db.dat>`
//!
//! Discovery scans the database's own directory. On the crate's SRUM
//! fixture (`artifacts/sru/SRUDB.dat`), a healthy set:
//!
//! ```text
//! cargo run --example log_set -- artifacts/sru/SRUDB.dat
//! ```

use frnsc_esedb::ese::log::EseLogSet;
use frnsc_esedb::EseDb;

fn main() {
    let path = std::env::args().nth(1).unwrap_or_else(|| {
        eprintln!("Usage: log_set <path/to/db.dat>");
        std::process::exit(1);
    });

    let db = EseDb::open(&path).expect("failed to open ESE database");
    let dir = std::path::Path::new(&path).parent().unwrap_or_else(|| std::path::Path::new("."));

    let Some(set) = EseLogSet::for_database(&db, dir).expect("log-set discovery failed") else {
        println!("No log set found for this database's signature in {}.", dir.display());
        println!("(Recovery status without logs is always Undetermined, not a synonym for clean.)");
        return;
    };

    let report = set.report(Some(db.header()));

    println!("ESE TRANSACTION LOG SET -- base name {:?}", report.base_name);
    println!(
        "Generations present : {:?}{}",
        report.generations_present,
        if report.missing_generations.is_empty() {
            " (complete)".to_string()
        } else {
            format!("  MISSING: {:?}", report.missing_generations)
        }
    );
    if let Some(cp) = report.checkpoint {
        println!("Checkpoint          : generation {}, sector {}, byte {}", cp.generation, cp.sector, cp.byte);
    } else {
        println!("Checkpoint          : none found");
    }
    println!(
        "Residual sectors    : {} (data from a generation the file's own header no longer claims)",
        report.residual_sector_count
    );
    println!("Recovery assessment : {:?}", report.recovery);
    println!();
    println!(
        "Stats: {} files seen, {} parsed, {} zero-filled, {} checksums verified, {} failed, {} not verified",
        report.stats.files_seen,
        report.stats.files_parsed,
        report.stats.files_zero_filled,
        report.stats.checksums_verified,
        report.stats.checksums_failed,
        report.stats.checksums_not_verified,
    );
    println!();

    if report.anomalies.is_empty() {
        println!("No anomalies found.");
    } else {
        println!("ANOMALIES ({}):", report.anomalies.len());
        for anomaly in &report.anomalies {
            println!("  [{:?}] {:?}", anomaly.severity(), anomaly);
            println!("    Rule out first: {}", anomaly.benign_explanation());
        }
    }

    println!();
    println!("(This report covers file-set completeness/integrity only.");
    println!(" For deleted/recovered row values, see `examples/recover_rows.rs`.)");
}
