//! List all tables and their columns in an ESE database.
//!
//! Usage: `cargo run --example list_tables -- <path.mdb>`

use frnsc_esedb::EseDb;

fn main() {
    let path = std::env::args().nth(1).unwrap_or_else(|| {
        eprintln!("Usage: list_tables <path.mdb>");
        std::process::exit(1);
    });

    let db = EseDb::open(&path).expect("failed to open ESE database");

    println!("Format : {:?}", db.header().fingerprint());
    println!("State  : {:?}", db.header().state());
    println!("Pages  : {} bytes", db.header().page_size);
    println!();

    for name in db.table_names() {
        let table = db.table(name).unwrap();
        println!("── {} ({} columns) ──", name, table.columns().len());
        for col in table.columns() {
            println!("  {:>4}  {:20} {:?}", col.id, col.name, col.col_type);
        }
        println!();
    }
}
