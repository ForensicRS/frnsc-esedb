//! Dump SRUM (System Resource Usage Monitor) data from a SRUDB.dat file.
//!
//! Usage:
//!   cargo run --example read_srum -- <path/to/SRUDB.dat>
//!
//! Example (fixture):
//!   cargo run --example read_srum -- ./artifacts/sru/SRUDB.dat
//!
//! Example (live Windows copy — requires admin or offline copy):
//!   cargo run --example read_srum -- "C:\Windows\System32\sru\SRUDB.dat"

use frnsc_esedb::srum::{AppEntry, SrumDatabase, VolumeMap};

fn main() {
    let path = std::env::args().nth(1).unwrap_or_else(|| {
        eprintln!("Usage: read_srum <path/to/SRUDB.dat>");
        std::process::exit(1);
    });

    let mut db = SrumDatabase::open(&path).unwrap_or_else(|e| {
        eprintln!("Failed to open '{path}': {e}");
        std::process::exit(1);
    });

    // ── Volume map ────────────────────────────────────────────────────────

    // Autodetect \Device\HarddiskVolumeN -> drive-letter mappings from the
    // app paths already in the index, then rewrite all paths in-place.
    let vm = VolumeMap::autodetect(&db.index);
    db.index.normalize_paths(&vm);

    // ── ID index summary ──────────────────────────────────────────────────

    println!("=== SRUM ID Index ===");
    println!("  App entries  : {}", db.index.app.len());
    println!("  User entries : {}", db.index.user.len());
    println!();

    println!("--- Known apps (first 20) ---");
    let mut apps: Vec<_> = db.index.app.iter().collect();
    apps.sort_by_key(|&(id, _)| id);
    for (id, entry) in apps.iter().take(20) {
        let variant = match entry {
            AppEntry::Path(_) => "path",
            AppEntry::Temporal { .. } => "temporal",
            AppEntry::StoreApp(_) => "store",
        };
        println!("  [{id:>6}] ({variant:8}) {}", entry.name());
    }
    if apps.len() > 20 {
        println!("  ... and {} more", apps.len() - 20);
    }
    println!();

    println!("--- Known users ---");
    let mut users: Vec<_> = db.index.user.iter().collect();
    users.sort_by_key(|&(id, _)| id);
    for (id, sid) in &users {
        let logon = db.index.logon_id_for_user(**id)
            .map(|l| format!(" (logon id: {l})"))
            .unwrap_or_default();
        println!("  [{id:>6}] {sid}{logon}");
    }
    println!();

    // ── App Resource Usage ────────────────────────────────────────────────

    println!("=== App Resource Usage (first 10) ===");
    if let Ok(iter) = db.app_resource_usage() {
        let records: Vec<_> = iter.take(10).collect();
        if records.is_empty() {
            println!("  (no records)");
        }
        for r in &records {
            let app = db.index.resolve_app(r.app_id)
                .map(|e| e.name().to_owned())
                .unwrap_or_else(|| format!("<id:{}>", r.app_id));
            println!(
                "  [{:>4}] {app:50} fg_cpu={:>14}  bg_cpu={:>14}  disk_r={:>12}  disk_w={:>12}",
                r.auto_inc_id,
                r.foreground_cycle_time.unwrap_or(0),
                r.background_cycle_time.unwrap_or(0),
                r.foreground_bytes_read.unwrap_or(0) + r.background_bytes_read.unwrap_or(0),
                r.foreground_bytes_written.unwrap_or(0) + r.background_bytes_written.unwrap_or(0),
            );
        }
    } else {
        println!("  (table not present)");
    }
    println!();

    // ── Network Usage ─────────────────────────────────────────────────────

    println!("=== Network Usage (first 10) ===");
    if let Ok(iter) = db.network_usage() {
        let records: Vec<_> = iter.take(10).collect();
        if records.is_empty() {
            println!("  (no records)");
        }
        for r in &records {
            let app = db.index.resolve_app(r.app_id)
                .map(|e| e.name().to_owned())
                .unwrap_or_else(|| format!("<id:{}>", r.app_id));
            println!(
                "  [{:>4}] {app:50}  sent={:>12}  recv={:>12}",
                r.auto_inc_id,
                r.bytes_sent.unwrap_or(0),
                r.bytes_received.unwrap_or(0),
            );
        }
    } else {
        println!("  (table not present)");
    }
    println!();

    // ── Network Connectivity ──────────────────────────────────────────────

    println!("=== Network Connectivity (first 10) ===");
    if let Ok(iter) = db.network_connectivity() {
        let records: Vec<_> = iter.take(10).collect();
        if records.is_empty() {
            println!("  (no records)");
        }
        for r in &records {
            let app = db.index.resolve_app(r.app_id)
                .map(|e| e.name().to_owned())
                .unwrap_or_else(|| format!("<id:{}>", r.app_id));
            println!(
                "  [{:>4}] {app:50}  connected_s={:>8}",
                r.auto_inc_id,
                r.connected_time.unwrap_or(0),
            );
        }
    } else {
        println!("  (table not present)");
    }
    println!();

    // ── App Timeline ──────────────────────────────────────────────────────

    println!("=== App Timeline (first 10) ===");
    if let Ok(iter) = db.app_timeline() {
        let records: Vec<_> = iter.take(10).collect();
        if records.is_empty() {
            println!("  (no records)");
        }
        for r in &records {
            let app = db.index.resolve_app(r.app_id)
                .map(|e| e.name().to_owned())
                .unwrap_or_else(|| format!("<id:{}>", r.app_id));
            println!(
                "  [{:>4}] {app:50}  focus_s={:>8}  input_s={:>8}  cycles={:>14}",
                r.auto_inc_id,
                r.in_focus_s.unwrap_or(0),
                r.user_input_s.unwrap_or(0),
                r.cycles.unwrap_or(0),
            );
        }
    } else {
        println!("  (table not present)");
    }
    println!();

    // ── Energy Usage ──────────────────────────────────────────────────────

    println!("=== Energy Usage (first 10) ===");
    if let Ok(iter) = db.energy_usage() {
        let records: Vec<_> = iter.take(10).collect();
        if records.is_empty() {
            println!("  (no records)");
        }
        for r in &records {
            println!(
                "  [{:>4}]  charge={:>6} mWh  full={:>6} mWh  designed={:>6} mWh  cycles={:?}",
                r.auto_inc_id,
                r.charge_level.unwrap_or(0),
                r.full_charged_capacity.unwrap_or(0),
                r.designed_capacity.unwrap_or(0),
                r.cycle_count,
            );
        }
    } else {
        println!("  (table not present)");
    }
    println!();

    // ── Energy Usage LT ───────────────────────────────────────────────────

    println!("=== Energy Usage LT (first 10) ===");
    if let Ok(iter) = db.energy_usage_lt() {
        let records: Vec<_> = iter.take(10).collect();
        if records.is_empty() {
            println!("  (no records)");
        }
        for r in &records {
            println!(
                "  [{:>4}]  ac_active_s={:>8}  dc_active_s={:>8}  active_mWh={:>6}  cs_mWh={:>6}",
                r.auto_inc_id,
                r.active_ac_time.unwrap_or(0),
                r.active_dc_time.unwrap_or(0),
                r.active_energy.unwrap_or(0),
                r.cs_energy.unwrap_or(0),
            );
        }
    } else {
        println!("  (table not present)");
    }
    println!();

    // ── Energy Estimator ──────────────────────────────────────────────────

    println!("=== Energy Estimator (first 10) ===");
    if let Ok(iter) = db.energy_estimator() {
        let records: Vec<_> = iter.take(10).collect();
        if records.is_empty() {
            println!("  (no records)");
        }
        for r in &records {
            let app = db.index.resolve_app(r.app_id)
                .map(|e| e.name().to_owned())
                .unwrap_or_else(|| format!("<id:{}>", r.app_id));
            println!(
                "  [{:>4}] {app:50}  usage_uWh={:?}",
                r.auto_inc_id,
                r.usage,
            );
        }
    } else {
        println!("  (table not present)");
    }
    println!();

    // ── Push Notifications ────────────────────────────────────────────────

    println!("=== Push Notifications (first 10) ===");
    if let Ok(iter) = db.push_notifications() {
        let records: Vec<_> = iter.take(10).collect();
        if records.is_empty() {
            println!("  (no records)");
        }
        for r in &records {
            let app = db.index.resolve_app(r.app_id)
                .map(|e| e.name().to_owned())
                .unwrap_or_else(|| format!("<id:{}>", r.app_id));
            println!(
                "  [{:>4}] {app:50}  type={:?}  payload={:?} bytes",
                r.auto_inc_id,
                r.notification_type,
                r.payload_size,
            );
        }
    } else {
        println!("  (table not present)");
    }
    println!();

    // ── Cross-table timeline summary ──────────────────────────────────────

    println!("=== Timeline (all tables, first 15 events sorted by timestamp) ===");
    let events = db.timeline().with_all().sorted().expect("timeline build should succeed");
    println!("  Total events: {}", events.len());
    for event in events.iter().take(15) {
        let t = event.timestamp();
        let ts = format!("{:04}-{:02}-{:02}T{:02}:{:02}:{:02}Z", t.year(), t.month(), t.day(), t.hour(), t.minute(), t.second());
        let app = event.app_id()
            .and_then(|id| db.index.resolve_app(id))
            .map(|e| e.name().to_owned())
            .unwrap_or_else(|| "-".to_owned());
        let kind = match event {
            frnsc_esedb::srum::TimelineEvent::AppResource(_)        => "AppResource",
            frnsc_esedb::srum::TimelineEvent::AppTimeline(_)        => "AppTimeline",
            frnsc_esedb::srum::TimelineEvent::NetworkUsage(_)       => "NetworkUsage",
            frnsc_esedb::srum::TimelineEvent::NetworkConnectivity(_) => "NetConnect",
            frnsc_esedb::srum::TimelineEvent::EnergyUsage(_)        => "EnergyUsage",
            frnsc_esedb::srum::TimelineEvent::EnergyUsageLt(_)      => "EnergyLt",
            frnsc_esedb::srum::TimelineEvent::EnergyEstimator(_)    => "EnergyEst",
            frnsc_esedb::srum::TimelineEvent::PushNotification(_)   => "PushNotif",
        };
        println!("  ts={ts:>20}  {kind:14}  {app}");
    }
}
