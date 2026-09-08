use forensic_rs::err::{DataAccessError, ForensicError, ForensicResult};
use forensic_rs::utils::time::ForensicTimestamp;

use crate::srum::tables::{
    AppResourceUsage, AppTimelineRecord, EnergyEstimator, EnergyUsage, EnergyUsageLt,
    NetworkConnectivity, NetworkUsage, PushNotification,
};
use crate::srum::SrumDatabase;

// ---------------------------------------------------------------------------
// TimelineEvent — one entry across all SRUM tables
// ---------------------------------------------------------------------------

/// A single event sampled from any SRUM table, used when building a unified
/// cross-table timeline.
#[derive(Debug, Clone)]
pub enum TimelineEvent {
    AppResource(Box<AppResourceUsage>),
    AppTimeline(Box<AppTimelineRecord>),
    NetworkUsage(NetworkUsage),
    NetworkConnectivity(NetworkConnectivity),
    EnergyUsage(EnergyUsage),
    EnergyUsageLt(EnergyUsageLt),
    EnergyEstimator(EnergyEstimator),
    PushNotification(PushNotification),
}

impl TimelineEvent {
    /// The ESE `TimeStamp` column for this event.
    pub fn timestamp(&self) -> ForensicTimestamp {
        match self {
            TimelineEvent::AppResource(r) => r.timestamp,
            TimelineEvent::AppTimeline(r) => r.timestamp,
            TimelineEvent::NetworkUsage(r) => r.timestamp,
            TimelineEvent::NetworkConnectivity(r) => r.timestamp,
            TimelineEvent::EnergyUsage(r) => r.timestamp,
            TimelineEvent::EnergyUsageLt(r) => r.timestamp,
            TimelineEvent::EnergyEstimator(r) => r.timestamp,
            TimelineEvent::PushNotification(r) => r.timestamp,
        }
    }

    /// The `AppId` foreign key (resolvable via [`crate::srum::SrumIdIndex`]).
    pub fn app_id(&self) -> Option<i64> {
        Some(match self {
            TimelineEvent::AppResource(r) => r.app_id,
            TimelineEvent::AppTimeline(r) => r.app_id,
            TimelineEvent::NetworkUsage(r) => r.app_id,
            TimelineEvent::NetworkConnectivity(r) => r.app_id,
            TimelineEvent::EnergyUsage(r) => r.app_id,
            TimelineEvent::EnergyUsageLt(r) => r.app_id,
            TimelineEvent::EnergyEstimator(r) => r.app_id,
            TimelineEvent::PushNotification(r) => r.app_id,
        })
    }

    /// The `UserId` foreign key (resolvable via [`crate::srum::SrumIdIndex`]).
    pub fn user_id(&self) -> Option<i64> {
        Some(match self {
            TimelineEvent::AppResource(r) => r.user_id,
            TimelineEvent::AppTimeline(r) => r.user_id,
            TimelineEvent::NetworkUsage(r) => r.user_id,
            TimelineEvent::NetworkConnectivity(r) => r.user_id,
            TimelineEvent::EnergyUsage(r) => r.user_id,
            TimelineEvent::EnergyUsageLt(r) => r.user_id,
            TimelineEvent::EnergyEstimator(r) => r.user_id,
            TimelineEvent::PushNotification(r) => r.user_id,
        })
    }
}

// ---------------------------------------------------------------------------
// Table flags — which tables to include in the timeline
// ---------------------------------------------------------------------------

/// Bitflags controlling which SRUM tables the [`TimelineBuilder`] reads.
#[derive(Clone, Copy)]
pub struct TableFlags(u8);

impl TableFlags {
    pub const APP_RESOURCE: u8      = 1 << 0;
    pub const APP_TIMELINE: u8      = 1 << 1;
    pub const NETWORK_USAGE: u8     = 1 << 2;
    pub const NET_CONNECTIVITY: u8  = 1 << 3;
    pub const ENERGY_USAGE: u8      = 1 << 4;
    pub const ENERGY_LT: u8         = 1 << 5;
    pub const ENERGY_ESTIMATOR: u8  = 1 << 6;
    pub const PUSH_NOTIFICATION: u8 = 1 << 7;
    pub const ALL: u8               = 0xFF;

    fn has(self, flag: u8) -> bool {
        self.0 & flag != 0
    }
}

/// Resolve one table accessor's result into an optional iterator: a missing
/// table (common — SRUM's table set varies across Windows builds) becomes an
/// empty stream, but every other error propagates. This is the explicit
/// version of what `.into_iter().flatten()` over a `Result` would otherwise
/// do implicitly and silently for *every* kind of error, not just "missing".
fn tolerate_missing<T>(result: ForensicResult<T>) -> ForensicResult<Option<T>> {
    match result {
        Ok(v) => Ok(Some(v)),
        Err(ForensicError::DataAccess(DataAccessError::Missing { .. })) => Ok(None),
        Err(e) => Err(e),
    }
}

// ---------------------------------------------------------------------------
// TimelineBuilder
// ---------------------------------------------------------------------------

/// Fluent builder for a cross-table SRUM timeline.
///
/// # Examples
/// ```rust,ignore
/// // Lazy, unsorted (zero extra memory):
/// for event in db.timeline().with_all().iter()? {
///     println!("{} {:?}", event.timestamp(), event.app_id());
/// }
///
/// // Sorted by timestamp (collects all events into memory first):
/// let events = db.timeline().with_network_usage().with_app_resource().sorted()?;
/// ```
pub struct TimelineBuilder<'a> {
    db: &'a SrumDatabase,
    flags: TableFlags,
}

impl<'a> TimelineBuilder<'a> {
    pub(crate) fn new(db: &'a SrumDatabase) -> Self {
        Self { db, flags: TableFlags(0) }
    }

    pub fn with_app_resource(mut self) -> Self {
        self.flags.0 |= TableFlags::APP_RESOURCE;
        self
    }
    pub fn with_app_timeline(mut self) -> Self {
        self.flags.0 |= TableFlags::APP_TIMELINE;
        self
    }
    pub fn with_network_usage(mut self) -> Self {
        self.flags.0 |= TableFlags::NETWORK_USAGE;
        self
    }
    pub fn with_network_connectivity(mut self) -> Self {
        self.flags.0 |= TableFlags::NET_CONNECTIVITY;
        self
    }
    pub fn with_energy_usage(mut self) -> Self {
        self.flags.0 |= TableFlags::ENERGY_USAGE;
        self
    }
    pub fn with_energy_usage_lt(mut self) -> Self {
        self.flags.0 |= TableFlags::ENERGY_LT;
        self
    }
    pub fn with_energy_estimator(mut self) -> Self {
        self.flags.0 |= TableFlags::ENERGY_ESTIMATOR;
        self
    }
    pub fn with_push_notifications(mut self) -> Self {
        self.flags.0 |= TableFlags::PUSH_NOTIFICATION;
        self
    }
    /// Include all available tables.
    pub fn with_all(mut self) -> Self {
        self.flags.0 = TableFlags::ALL;
        self
    }

    /// Lazy iterator — chains all selected tables sequentially.
    /// Events are **not** guaranteed to be in timestamp order; use
    /// [`sorted`](Self::sorted) if ordering matters.
    ///
    /// A table that doesn't exist in this database (SRUM's table set varies
    /// across Windows builds) is treated as empty; any other error (a
    /// corrupt B-tree, an unreadable page) propagates instead of being
    /// silently dropped.
    pub fn iter(self) -> ForensicResult<impl Iterator<Item = TimelineEvent> + 'a> {
        let db = self.db;
        let flags = self.flags;

        let app_res = if flags.has(TableFlags::APP_RESOURCE) {
            tolerate_missing(db.app_resource_usage())?
        } else {
            None
        };
        let app_tl = if flags.has(TableFlags::APP_TIMELINE) {
            tolerate_missing(db.app_timeline())?
        } else {
            None
        };
        let net_use = if flags.has(TableFlags::NETWORK_USAGE) {
            tolerate_missing(db.network_usage())?
        } else {
            None
        };
        let net_con = if flags.has(TableFlags::NET_CONNECTIVITY) {
            tolerate_missing(db.network_connectivity())?
        } else {
            None
        };
        let en_use = if flags.has(TableFlags::ENERGY_USAGE) {
            tolerate_missing(db.energy_usage())?
        } else {
            None
        };
        let en_lt = if flags.has(TableFlags::ENERGY_LT) {
            tolerate_missing(db.energy_usage_lt())?
        } else {
            None
        };
        let en_est = if flags.has(TableFlags::ENERGY_ESTIMATOR) {
            tolerate_missing(db.energy_estimator())?
        } else {
            None
        };
        let push = if flags.has(TableFlags::PUSH_NOTIFICATION) {
            tolerate_missing(db.push_notifications())?
        } else {
            None
        };

        Ok(std::iter::empty::<TimelineEvent>()
            .chain(app_res.into_iter().flatten().map(|r| TimelineEvent::AppResource(Box::new(r))))
            .chain(app_tl.into_iter().flatten().map(|r| TimelineEvent::AppTimeline(Box::new(r))))
            .chain(net_use.into_iter().flatten().map(TimelineEvent::NetworkUsage))
            .chain(net_con.into_iter().flatten().map(TimelineEvent::NetworkConnectivity))
            .chain(en_use.into_iter().flatten().map(TimelineEvent::EnergyUsage))
            .chain(en_lt.into_iter().flatten().map(TimelineEvent::EnergyUsageLt))
            .chain(en_est.into_iter().flatten().map(TimelineEvent::EnergyEstimator))
            .chain(push.into_iter().flatten().map(TimelineEvent::PushNotification)))
    }

    /// Collect all events from the selected tables and sort by timestamp
    /// (ascending). This holds everything in memory.
    pub fn sorted(self) -> ForensicResult<Vec<TimelineEvent>> {
        let mut events: Vec<TimelineEvent> = self.iter()?.collect();
        events.sort_by_key(|e| e.timestamp());
        Ok(events)
    }
}
