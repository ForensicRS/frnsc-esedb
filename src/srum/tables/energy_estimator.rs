//! `{7ACBBAA3-D029-4BE4-9A7A-0885927F1D8F}` — Energy Estimator.
//!
//! Estimated energy usage per app per interval (in µWh).
use forensic_rs::utils::time::ForensicTimestamp;

use crate::RowIter;

pub const TABLE_GUID: &str = "{7ACBBAA3-D029-4BE4-9A7A-0885927F1D8F}";

#[derive(Debug, Clone)]
pub struct EnergyEstimator {
    pub auto_inc_id: i64,
    pub timestamp: ForensicTimestamp,
    pub app_id: i64,
    pub user_id: i64,
    pub flags: Option<i64>,
    pub start_time: Option<ForensicTimestamp>,
    pub end_time: Option<ForensicTimestamp>,
    /// Estimated usage in µWh.
    pub usage: Option<i64>,
}

pub struct EnergyEstimatorIter<'a> {
    rows: RowIter<'a>,
}

impl<'a> EnergyEstimatorIter<'a> {
    pub(crate) fn new(rows: RowIter<'a>) -> Self {
        Self { rows }
    }
}

impl<'a> Iterator for EnergyEstimatorIter<'a> {
    type Item = EnergyEstimator;

    fn next(&mut self) -> Option<Self::Item> {
        loop {
        let row = self.rows.next()?;
        let Some(auto_inc_id) = row.get_i64("AutoIncId") else { continue };
        let Some(timestamp) = row.get_datetime("TimeStamp") else { continue };
        let Some(app_id) = row.get_i64("AppId") else { continue };
        let Some(user_id) = row.get_i64("UserId") else { continue };
        return Some(EnergyEstimator {
            auto_inc_id,
            timestamp,
            app_id,
            user_id,
            flags: row.get_i64("Flags"),
            start_time: row.get_datetime("StartTime"),
            end_time: row.get_datetime("EndTime"),
            usage: row.get_i64("Usage"),
        });
        } // loop
    }
}
