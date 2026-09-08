//! `{DD6636C4-8929-4683-974E-22C046A43763}` — Network Connectivity Usage Monitor.
//!
//! Tracks how long each app was connected per network interface (session duration).
use forensic_rs::utils::time::ForensicTimestamp;

use crate::RowIter;

pub const TABLE_GUID: &str = "{DD6636C4-8929-4683-974E-22C046A43763}";

#[derive(Debug, Clone)]
pub struct NetworkConnectivity {
    pub auto_inc_id: i64,
    pub timestamp: ForensicTimestamp,
    pub app_id: i64,
    pub user_id: i64,
    pub interface_luid: Option<i64>,
    pub l2_profile_id: Option<i64>,
    /// Total connected time in seconds.
    pub connected_time: Option<i64>,
    /// When the connection started.
    pub connect_start_time: Option<ForensicTimestamp>,
    pub l2_profile_flags: Option<i64>,
}

pub struct NetworkConnectivityIter<'a> {
    rows: RowIter<'a>,
}

impl<'a> NetworkConnectivityIter<'a> {
    pub(crate) fn new(rows: RowIter<'a>) -> Self {
        Self { rows }
    }
}

impl<'a> Iterator for NetworkConnectivityIter<'a> {
    type Item = NetworkConnectivity;

    fn next(&mut self) -> Option<Self::Item> {
        loop {
        let row = self.rows.next()?;
        let Some(auto_inc_id) = row.get_i64("AutoIncId") else { continue };
        let Some(timestamp) = row.get_datetime("TimeStamp") else { continue };
        let Some(app_id) = row.get_i64("AppId") else { continue };
        let Some(user_id) = row.get_i64("UserId") else { continue };
        return Some(NetworkConnectivity {
            auto_inc_id,
            timestamp,
            app_id,
            user_id,
            interface_luid: row.get_i64("InterfaceLuid"),
            l2_profile_id: row.get_i64("L2ProfileId"),
            connected_time: row.get_i64("ConnectedTime"),
            connect_start_time: row.get_datetime("ConnectStartTime"),
            l2_profile_flags: row.get_i64("L2ProfileFlags"),
        });
        } // loop
    }
}
