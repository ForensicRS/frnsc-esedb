//! `{D10CA2FE-6FCF-4F6D-848E-B2E99266FA86}` — Windows Push Notification Data.
//!
//! Push notification events: type, payload size, and network type per app.
use forensic_rs::utils::time::ForensicTimestamp;

use crate::RowIter;

pub const TABLE_GUID: &str = "{D10CA2FE-6FCF-4F6D-848E-B2E99266FA86}";

#[derive(Debug, Clone)]
pub struct PushNotification {
    pub auto_inc_id: i64,
    pub timestamp: ForensicTimestamp,
    pub app_id: i64,
    pub user_id: i64,
    pub notification_type: Option<i64>,
    pub payload_size: Option<i64>,
    pub network_type: Option<i64>,
}

pub struct PushNotificationIter<'a> {
    rows: RowIter<'a>,
}

impl<'a> PushNotificationIter<'a> {
    pub(crate) fn new(rows: RowIter<'a>) -> Self {
        Self { rows }
    }
}

impl<'a> Iterator for PushNotificationIter<'a> {
    type Item = PushNotification;

    fn next(&mut self) -> Option<Self::Item> {
        loop {
        let row = self.rows.next()?;
        let Some(auto_inc_id) = row.get_i64("AutoIncId") else { continue };
        let Some(timestamp) = row.get_datetime("TimeStamp") else { continue };
        let Some(app_id) = row.get_i64("AppId") else { continue };
        let Some(user_id) = row.get_i64("UserId") else { continue };
        return Some(PushNotification {
            auto_inc_id,
            timestamp,
            app_id,
            user_id,
            notification_type: row.get_i64("NotificationType"),
            payload_size: row.get_i64("PayloadSize"),
            network_type: row.get_i64("NetworkType"),
        });
        } // loop
    }
}
