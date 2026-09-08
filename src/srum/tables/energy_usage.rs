//! `{FEE4E14F-02A9-4550-B5CE-5FA2DA202E37}` — Energy Usage Provider.
//!
//! Battery state transitions: charge level, capacity, and cycle count at each event.
use forensic_rs::utils::time::ForensicTimestamp;

use crate::RowIter;

pub const TABLE_GUID: &str = "{FEE4E14F-02A9-4550-B5CE-5FA2DA202E37}";

#[derive(Debug, Clone)]
pub struct EnergyUsage {
    pub auto_inc_id: i64,
    pub timestamp: ForensicTimestamp,
    pub app_id: i64,
    pub user_id: i64,
    pub event_timestamp: Option<ForensicTimestamp>,
    pub state_transition: Option<i64>,
    /// Designed capacity in mWh.
    pub designed_capacity: Option<i64>,
    /// Full charge capacity in mWh.
    pub full_charged_capacity: Option<i64>,
    /// Current charge level in mWh.
    pub charge_level: Option<i64>,
    pub cycle_count: Option<i64>,
    pub configuration_hash: Option<i64>,
}

pub struct EnergyUsageIter<'a> {
    rows: RowIter<'a>,
}

impl<'a> EnergyUsageIter<'a> {
    pub(crate) fn new(rows: RowIter<'a>) -> Self {
        Self { rows }
    }
}

impl<'a> Iterator for EnergyUsageIter<'a> {
    type Item = EnergyUsage;

    fn next(&mut self) -> Option<Self::Item> {
        loop {
        let row = self.rows.next()?;
        let Some(auto_inc_id) = row.get_i64("AutoIncId") else { continue };
        let Some(timestamp) = row.get_datetime("TimeStamp") else { continue };
        let Some(app_id) = row.get_i64("AppId") else { continue };
        let Some(user_id) = row.get_i64("UserId") else { continue };
        return Some(EnergyUsage {
            auto_inc_id,
            timestamp,
            app_id,
            user_id,
            event_timestamp: row.get_datetime("EventTimestamp"),
            state_transition: row.get_i64("StateTransition"),
            designed_capacity: row.get_i64("DesignedCapacity"),
            full_charged_capacity: row.get_i64("FullChargedCapacity"),
            charge_level: row.get_i64("ChargeLevel"),
            cycle_count: row.get_i64("CycleCount"),
            configuration_hash: row.get_i64("ConfigurationHash"),
        });
        } // loop
    }
}
