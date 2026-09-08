//! `{FEE4E14F-02A9-4550-B5CE-5FA2DA202E37}LT` — Energy Usage Provider (Long Term).
//!
//! Long-term aggregated energy statistics: active/CS time on AC and DC,
//! energy consumed, and battery health.
use forensic_rs::utils::time::ForensicTimestamp;

use crate::RowIter;

pub const TABLE_GUID: &str = "{FEE4E14F-02A9-4550-B5CE-5FA2DA202E37}LT";

#[derive(Debug, Clone)]
pub struct EnergyUsageLt {
    pub auto_inc_id: i64,
    pub timestamp: ForensicTimestamp,
    pub app_id: i64,
    pub user_id: i64,
    /// Seconds of active time on AC power.
    pub active_ac_time: Option<i64>,
    /// Seconds in connected standby on AC power.
    pub cs_ac_time: Option<i64>,
    /// Seconds of active time on DC (battery).
    pub active_dc_time: Option<i64>,
    /// Seconds in connected standby on DC.
    pub cs_dc_time: Option<i64>,
    pub active_discharge_time: Option<i64>,
    pub cs_discharge_time: Option<i64>,
    /// Energy consumed while active (mWh).
    pub active_energy: Option<i64>,
    /// Energy consumed in connected standby (mWh).
    pub cs_energy: Option<i64>,
    pub designed_capacity: Option<i64>,
    pub full_charged_capacity: Option<i64>,
    pub cycle_count: Option<i64>,
    pub configuration_hash: Option<i64>,
}

pub struct EnergyUsageLtIter<'a> {
    rows: RowIter<'a>,
}

impl<'a> EnergyUsageLtIter<'a> {
    pub(crate) fn new(rows: RowIter<'a>) -> Self {
        Self { rows }
    }
}

impl<'a> Iterator for EnergyUsageLtIter<'a> {
    type Item = EnergyUsageLt;

    fn next(&mut self) -> Option<Self::Item> {
        loop {
        let row = self.rows.next()?;
        let Some(auto_inc_id) = row.get_i64("AutoIncId") else { continue };
        let Some(timestamp) = row.get_datetime("TimeStamp") else { continue };
        let Some(app_id) = row.get_i64("AppId") else { continue };
        let Some(user_id) = row.get_i64("UserId") else { continue };
        return Some(EnergyUsageLt {
            auto_inc_id,
            timestamp,
            app_id,
            user_id,
            active_ac_time: row.get_i64("ActiveAcTime"),
            cs_ac_time: row.get_i64("CsAcTime"),
            active_dc_time: row.get_i64("ActiveDcTime"),
            cs_dc_time: row.get_i64("CsDcTime"),
            active_discharge_time: row.get_i64("ActiveDischargeTime"),
            cs_discharge_time: row.get_i64("CsDischargeTime"),
            active_energy: row.get_i64("ActiveEnergy"),
            cs_energy: row.get_i64("CsEnergy"),
            designed_capacity: row.get_i64("DesignedCapacity"),
            full_charged_capacity: row.get_i64("FullChargedCapacity"),
            cycle_count: row.get_i64("CycleCount"),
            configuration_hash: row.get_i64("ConfigurationHash"),
        });
        } // loop
    }
}
