//! Integration tests for `artifacts/sru/SRUDB.dat`.
//!
//! SRUDB.dat is a SRUM (System Resource Usage Monitor) ESE database shipped
//! with Windows 8+.  It records per-app CPU, disk, network, energy, and
//! push-notification metrics.
//!
//! Run with: `cargo test --test srum`

use frnsc_esedb::srum::{SrumDatabase, TimelineEvent, VolumeMap};

const PATH: &str = "./artifacts/sru/SRUDB.dat";

/// `artifacts/` is gitignored, so this fixture is only present for whoever
/// placed it there locally. Tests skip (rather than fail) when it's absent.
fn open_db() -> Option<SrumDatabase> {
    if !std::path::Path::new(PATH).exists() {
        eprintln!("SKIP: fixture '{PATH}' unavailable");
        return None;
    }
    Some(SrumDatabase::open(PATH).expect("failed to open SRUDB.dat"))
}

// ── Open & Index ──────────────────────────────────────────────────────────────

/// Opening the SRUDB.dat fixture must succeed.
#[test]
fn open_srudb() {
    if !std::path::Path::new(PATH).exists() {
        return;
    }
    assert!(SrumDatabase::open(PATH).is_ok());
}

/// After opening, both the app and user maps in the ID index must be populated.
#[test]
fn index_populated() {
    let Some(db) = open_db() else { return };
    assert!(
        !db.index.app.is_empty(),
        "expected at least one app entry in SruDbIdMapTable"
    );
    assert!(
        !db.index.user.is_empty(),
        "expected at least one user entry in SruDbIdMapTable"
    );
}

/// Every resolved app entry must have a non-empty name.
#[test]
fn app_entries_have_names() {
    let Some(db) = open_db() else { return };
    for (id, entry) in &db.index.app {
        assert!(
            !entry.name().is_empty(),
            "app entry {id} has an empty name: {entry:?}"
        );
    }
}

/// Every user entry must be a valid-looking SID string.
#[test]
fn user_entries_are_valid_sids() {
    let Some(db) = open_db() else { return };
    for (id, sid) in &db.index.user {
        assert!(
            sid.starts_with("S-"),
            "user entry {id} has invalid SID: {sid}"
        );
    }
}

/// resolve_app / resolve_user round-trip: every key in the maps must resolve.
#[test]
fn index_resolve_round_trip() {
    let Some(db) = open_db() else { return };
    for &id in db.index.app.keys() {
        assert!(db.index.resolve_app(id).is_some());
    }
    for &id in db.index.user.keys() {
        assert!(db.index.resolve_user(id).is_some());
    }
}

// ── App Resource Usage ────────────────────────────────────────────────────────

#[test]
fn app_resource_usage_iterates() {
    let Some(db) = open_db() else { return };
    let iter = db.app_resource_usage().expect("table not found");
    let records: Vec<_> = iter.collect();
    assert!(!records.is_empty(), "expected at least one AppResourceUsage record");
    let first = &records[0];
    assert!(first.auto_inc_id > 0);
    assert!(first.timestamp.to_win_filetime().unwrap() > 0);
    // IDs should be in the index
    assert!(
        db.index.resolve_app(first.app_id).is_some(),
        "app_id {} not in index",
        first.app_id
    );
}

// ── App Timeline ──────────────────────────────────────────────────────────────

#[test]
fn app_timeline_iterates() {
    let Some(db) = open_db() else { return };
    let iter = db.app_timeline().expect("table not found");
    let records: Vec<_> = iter.collect();
    assert!(!records.is_empty(), "expected at least one AppTimeline record");
    for r in &records {
        assert!(r.auto_inc_id > 0);
        // Bitmap fields, when present, must be non-empty
        if let Some(ref bm) = r.in_focus_timeline {
            assert!(!bm.is_empty(), "in_focus_timeline bitmap is empty");
        }
    }
}

// ── Network Usage ─────────────────────────────────────────────────────────────

#[test]
fn network_usage_iterates() {
    let Some(db) = open_db() else { return };
    let iter = db.network_usage().expect("table not found");
    let records: Vec<_> = iter.collect();
    assert!(!records.is_empty(), "expected at least one NetworkUsage record");
    let first = &records[0];
    assert!(first.auto_inc_id > 0);
    // At least one record should have non-None bytes_sent or bytes_received
    let has_traffic = records.iter().any(|r| {
        r.bytes_sent.is_some() || r.bytes_received.is_some()
    });
    assert!(has_traffic, "expected at least one record with traffic data");
}

// ── Network Connectivity ──────────────────────────────────────────────────────

#[test]
fn network_connectivity_iterates() {
    let Some(db) = open_db() else { return };
    let iter = db.network_connectivity().expect("table not found");
    let records: Vec<_> = iter.collect();
    assert!(!records.is_empty(), "expected at least one NetworkConnectivity record");
    let has_connected_time = records.iter().any(|r| r.connected_time.is_some());
    assert!(has_connected_time, "expected at least one record with connected_time");
}

// ── Energy Usage ──────────────────────────────────────────────────────────────

#[test]
fn energy_usage_does_not_panic() {
    let Some(db) = open_db() else { return };
    // Table may be present but empty (no battery state transitions in fixture).
    if let Ok(iter) = db.energy_usage() {
        for r in iter {
            assert!(r.auto_inc_id > 0);
        }
    }
}

// ── Energy Usage LT ───────────────────────────────────────────────────────────

#[test]
fn energy_usage_lt_iterates() {
    let Some(db) = open_db() else { return };
    let iter = db.energy_usage_lt().expect("table not found");
    let records: Vec<_> = iter.collect();
    assert!(!records.is_empty(), "expected at least one EnergyUsageLt record");
    for r in &records {
        assert!(r.auto_inc_id > 0);
    }
}

// ── Energy Estimator (may be absent) ──────────────────────────────────────────

#[test]
fn energy_estimator_does_not_panic() {
    let Some(db) = open_db() else { return };
    // Table may or may not be present depending on the SRUDB version / device.
    if let Ok(iter) = db.energy_estimator() {
        for r in iter {
            assert!(r.auto_inc_id > 0);
        }
    }
}

// ── Push Notifications (may be absent) ────────────────────────────────────────

#[test]
fn push_notifications_does_not_panic() {
    let Some(db) = open_db() else { return };
    if let Ok(iter) = db.push_notifications() {
        for r in iter {
            assert!(r.auto_inc_id > 0);
        }
    }
}

// ── Timeline ──────────────────────────────────────────────────────────────────

/// A timeline built from all tables must yield at least one event and be sorted
/// by ascending timestamp.
#[test]
fn timeline_with_all_sorted() {
    let Some(db) = open_db() else { return };
    let events = db.timeline().with_all().sorted().expect("timeline build should succeed");
    assert!(!events.is_empty(), "expected at least one timeline event");
    // Verify ascending order
    for window in events.windows(2) {
        assert!(
            window[0].timestamp() <= window[1].timestamp(),
            "timeline is not sorted"
        );
    }
}

/// Selecting only two tables must produce only the corresponding event variants.
#[test]
fn timeline_selective_flags() {
    let Some(db) = open_db() else { return };
    let events = db
        .timeline()
        .with_app_resource()
        .with_network_usage()
        .sorted()
        .expect("timeline build should succeed");
    for event in &events {
        match event {
            TimelineEvent::AppResource(_) | TimelineEvent::NetworkUsage(_) => {}
            other => panic!(
                "unexpected event variant in selective timeline: {other:?}"
            ),
        }
    }
    // Should still have events (both tables are known to be populated)
    assert!(!events.is_empty(), "selective timeline yielded zero events");
}

/// The lazy `.iter()` path must work too (unsorted).
#[test]
fn timeline_lazy_iter() {
    let Some(db) = open_db() else { return };
    let count = db.timeline().with_all().iter().expect("timeline iter should succeed").count();
    assert!(count > 0, "lazy timeline iterator yielded zero events");
}

/// Most timeline events should reference a resolvable app_id.
/// Some IDs may be missing from the index (blob format != 1 are skipped).
#[test]
fn timeline_events_mostly_resolvable() {
    let Some(db) = open_db() else { return };
    let events = db.timeline().with_all().sorted().expect("timeline build should succeed");
    let total = events.len();
    let resolved = events
        .iter()
        .filter(|e| e.app_id().and_then(|id| db.index.resolve_app(id)).is_some())
        .count();
    // At least half of events should resolve (generous threshold).
    assert!(
        resolved > total / 2,
        "too few resolvable app_ids: {resolved}/{total}"
    );
}

// ── Volume Map ────────────────────────────────────────────────────────────────

/// If the index contains any device-path based app entries, autodetect should
/// find at least one volume mapping.
#[test]
fn volume_autodetect_from_fixture() {
    let Some(db) = open_db() else { return };
    use frnsc_esedb::srum::AppEntry;
    let has_paths = db.index.app.values().any(|e| matches!(e, AppEntry::Path(_)));
    if has_paths {
        let vm = VolumeMap::autodetect(&db.index);
        // autodetect should find at least one \Device\HarddiskVolume → "C:" mapping
        // based on the Windows / Program Files heuristic.
        let s = format!("{vm:?}");
        assert!(
            s.contains("C:"),
            "expected autodetect to find a C: mapping; got: {s}"
        );
    }
}
