//! `{973F5D5C-1D90-4944-BE8E-24B94231A174}` — Network Data Usage Monitor.
//!
//! Bytes sent and received per app per network interface per interval.
use forensic_rs::utils::time::ForensicTimestamp;

use crate::RowIter;

pub const TABLE_GUID: &str = "{973F5D5C-1D90-4944-BE8E-24B94231A174}";

#[derive(Debug, Clone)]
pub struct NetworkUsage {
    pub auto_inc_id: i64,
    pub timestamp: ForensicTimestamp,
    pub app_id: i64,
    pub user_id: i64,
    /// LUID of the network interface (opaque u64; correlate with adapter list).
    pub interface_luid: Option<i64>,
    pub l2_profile_id: Option<i64>,
    pub l2_profile_flags: Option<i64>,
    pub bytes_sent: Option<i64>,
    pub bytes_received: Option<i64>,
}

pub struct NetworkUsageIter<'a> {
    rows: RowIter<'a>,
}

impl<'a> NetworkUsageIter<'a> {
    pub(crate) fn new(rows: RowIter<'a>) -> Self {
        Self { rows }
    }
}

impl<'a> Iterator for NetworkUsageIter<'a> {
    type Item = NetworkUsage;

    fn next(&mut self) -> Option<Self::Item> {
        loop {
        let row = self.rows.next()?;
        let Some(auto_inc_id) = row.get_i64("AutoIncId") else { continue };
        let Some(timestamp) = row.get_datetime("TimeStamp") else { continue };
        let Some(app_id) = row.get_i64("AppId") else { continue };
        let Some(user_id) = row.get_i64("UserId") else { continue };
        return Some(NetworkUsage {
            auto_inc_id,
            timestamp,
            app_id,
            user_id,
            interface_luid: row.get_i64("InterfaceLuid"),
            l2_profile_id: row.get_i64("L2ProfileId"),
            l2_profile_flags: row.get_i64("L2ProfileFlags"),
            bytes_sent: row.get_i64("BytesSent"),
            bytes_received: row.get_i64("BytesRecvd"),
        });
        } // loop
    }
}
