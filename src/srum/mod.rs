//! SRUM (System Resource Usage Monitor) parser.
//!
//! # Quick start
//! ```rust,ignore
//! let db = SrumDatabase::open(r"C:\Windows\System32\sru\SRUDB.dat")
//!     .expect("failed to open SRUDB.dat");
//!
//! // Iterate CPU/disk usage records lazily:
//! if let Ok(iter) = db.app_resource_usage() {
//!     for record in iter {
//!         if let Some(app) = db.index.resolve_app(record.app_id) {
//!             println!("{}: cpu_fg={:?}", app.name(), record.foreground_cycle_time);
//!         }
//!     }
//! }
//!
//! // Cross-table timeline sorted by timestamp:
//! let events = db.timeline().with_all().sorted()?;
//! ```

pub mod enrichment;
pub mod index;
pub mod tables;
pub mod timeline;
pub mod volume;

pub use enrichment::{SrumEnrichment, WinEventEnrichment};
pub use index::{AppEntry, SrumIdIndex};
pub use timeline::{TableFlags, TimelineBuilder, TimelineEvent};
pub use volume::VolumeMap;

use forensic_rs::err::ForensicResult;

use tables::{
    app_resource::{AppResourceUsageIter, TABLE_GUID as APP_RESOURCE_GUID},
    app_timeline::{AppTimelineIter, TABLE_GUID as APP_TIMELINE_GUID},
    energy_estimator::{EnergyEstimatorIter, TABLE_GUID as ENERGY_ESTIMATOR_GUID},
    energy_lt::{EnergyUsageLtIter, TABLE_GUID as ENERGY_LT_GUID},
    energy_usage::{EnergyUsageIter, TABLE_GUID as ENERGY_USAGE_GUID},
    network_connectivity::{NetworkConnectivityIter, TABLE_GUID as NET_CONNECTIVITY_GUID},
    network_usage::{NetworkUsageIter, TABLE_GUID as NET_USAGE_GUID},
    push_notification::{PushNotificationIter, TABLE_GUID as PUSH_NOTIFICATION_GUID},
};

use crate::EseDb;

/// Name of the ID-map table inside SRUDB.dat.
const ID_MAP_TABLE: &str = "SruDbIdMapTable";

// ---------------------------------------------------------------------------
// SrumDatabase — main entry point
// ---------------------------------------------------------------------------

/// An open SRUM database.
///
/// Owning type that holds both the raw [`crate::EseDb`] handle and the
/// in-memory [`SrumIdIndex`].  All data tables are streamed lazily on demand
/// via the per-table accessors below — only the ID map is loaded into RAM
/// during [`open`](Self::open).
pub struct SrumDatabase {
    db: EseDb,
    /// In-memory index mapping 8-byte integer IDs to app identities and user
    /// SIDs.  Built from `SruDbIdMapTable` during [`open`](Self::open).
    pub index: SrumIdIndex,
}

impl SrumDatabase {
    /// Open a SRUDB.dat file, parse the header, and load the ID-map index.
    ///
    /// Returns an error if the file cannot be opened/parsed, or if
    /// `SruDbIdMapTable` (which every real SRUM database has) is missing —
    /// both indicate this isn't actually a SRUM database, and the caller
    /// gets the real reason instead of a bare `None`.
    pub fn open(path: &str) -> ForensicResult<Self> {
        let db = EseDb::open(path)?;
        Self::from_db(db)
    }

    /// Build a `SrumDatabase` from an already-open [`EseDb`] (e.g. one
    /// mounted through [`crate::ese::format::EseFormatFactory`]).
    pub fn from_db(db: EseDb) -> ForensicResult<Self> {
        let index = SrumIdIndex::load(db.rows(ID_MAP_TABLE)?);
        Ok(Self { db, index })
    }

    // -----------------------------------------------------------------------
    // Per-table accessors
    // -----------------------------------------------------------------------

    /// CPU + disk I/O usage per app — table `{D10CA2FE-…FA89}`.
    pub fn app_resource_usage(&self) -> ForensicResult<AppResourceUsageIter<'_>> {
        Ok(AppResourceUsageIter::new(self.db.rows(APP_RESOURCE_GUID)?))
    }

    /// Per-second activity bitmaps per app — table `{5C8CF1C7-…}`.
    pub fn app_timeline(&self) -> ForensicResult<AppTimelineIter<'_>> {
        Ok(AppTimelineIter::new(self.db.rows(APP_TIMELINE_GUID)?))
    }

    /// Network bytes sent/received per app — table `{973F5D5C-…}`.
    pub fn network_usage(&self) -> ForensicResult<NetworkUsageIter<'_>> {
        Ok(NetworkUsageIter::new(self.db.rows(NET_USAGE_GUID)?))
    }

    /// Network session durations per app — table `{DD6636C4-…}`.
    pub fn network_connectivity(&self) -> ForensicResult<NetworkConnectivityIter<'_>> {
        Ok(NetworkConnectivityIter::new(self.db.rows(NET_CONNECTIVITY_GUID)?))
    }

    /// Battery state transitions — table `{FEE4E14F-…E37}`.
    pub fn energy_usage(&self) -> ForensicResult<EnergyUsageIter<'_>> {
        Ok(EnergyUsageIter::new(self.db.rows(ENERGY_USAGE_GUID)?))
    }

    /// Long-term AC/DC energy stats — table `{FEE4E14F-…E37}LT`.
    pub fn energy_usage_lt(&self) -> ForensicResult<EnergyUsageLtIter<'_>> {
        Ok(EnergyUsageLtIter::new(self.db.rows(ENERGY_LT_GUID)?))
    }

    /// Per-app energy estimates in µWh — table `{7ACBBAA3-…}`.
    pub fn energy_estimator(&self) -> ForensicResult<EnergyEstimatorIter<'_>> {
        Ok(EnergyEstimatorIter::new(self.db.rows(ENERGY_ESTIMATOR_GUID)?))
    }

    /// Push notification events — table `{D10CA2FE-…FA86}`.
    pub fn push_notifications(&self) -> ForensicResult<PushNotificationIter<'_>> {
        Ok(PushNotificationIter::new(self.db.rows(PUSH_NOTIFICATION_GUID)?))
    }

    // -----------------------------------------------------------------------
    // Cross-table timeline
    // -----------------------------------------------------------------------

    /// Create a [`TimelineBuilder`] for constructing a unified cross-table view.
    ///
    /// Chain `.with_*()` calls to select tables, then call `.iter()` (lazy) or
    /// `.sorted()` (collected and sorted by timestamp).
    pub fn timeline(&self) -> TimelineBuilder<'_> {
        TimelineBuilder::new(self)
    }
}
