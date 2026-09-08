//! `{D10CA2FE-6FCF-4F6D-848E-B2E99266FA89}` — Application Resource Usage.
//!
//! Tracks CPU cycles, disk I/O, and context switches per app per interval.
use forensic_rs::utils::time::ForensicTimestamp;

use crate::RowIter;
pub const TABLE_GUID: &str = "{D10CA2FE-6FCF-4F6D-848E-B2E99266FA89}";

#[derive(Debug, Clone)]
pub struct AppResourceUsage {
    pub auto_inc_id: i64,
    pub timestamp: ForensicTimestamp,
    pub app_id: i64,
    pub user_id: i64,
    pub flags: Option<i64>,
    pub foreground_cycle_time: Option<i64>,
    pub background_cycle_time: Option<i64>,
    /// Foreground time in 100-ns ticks (same unit as ForensicTimestamp).
    pub face_time: Option<i64>,
    pub foreground_context_switches: Option<i64>,
    pub background_context_switches: Option<i64>,
    pub foreground_bytes_read: Option<i64>,
    pub foreground_bytes_written: Option<i64>,
    pub foreground_num_read_ops: Option<i64>,
    pub foreground_num_write_ops: Option<i64>,
    pub foreground_num_flushes: Option<i64>,
    pub background_bytes_read: Option<i64>,
    pub background_bytes_written: Option<i64>,
    pub background_num_read_ops: Option<i64>,
    pub background_num_write_ops: Option<i64>,
    pub background_num_flushes: Option<i64>,
}

pub struct AppResourceUsageIter<'a> {
    rows: RowIter<'a>,
}

impl<'a> AppResourceUsageIter<'a> {
    pub(crate) fn new(rows: RowIter<'a>) -> Self {
        Self { rows }
    }
}

impl<'a> Iterator for AppResourceUsageIter<'a> {
    type Item = AppResourceUsage;

    fn next(&mut self) -> Option<Self::Item> {
        loop {
            let row = self.rows.next()?;
            let Some(auto_inc_id) = row.get_i64("AutoIncId") else { continue };
            let Some(timestamp) = row.get_datetime("TimeStamp") else { continue };
            let Some(app_id) = row.get_i64("AppId") else { continue };
            let Some(user_id) = row.get_i64("UserId") else { continue };
            return Some(AppResourceUsage {
                auto_inc_id,
                timestamp,
                app_id,
                user_id,
                flags: row.get_i64("Flags"),
                foreground_cycle_time: row.get_i64("ForegroundCycleTime"),
                background_cycle_time: row.get_i64("BackgroundCycleTime"),
                face_time: row.get_i64("FaceTime"),
                foreground_context_switches: row.get_i64("ForegroundContextSwitches"),
                background_context_switches: row.get_i64("BackgroundContextSwitches"),
                foreground_bytes_read: row.get_i64("ForegroundBytesRead"),
                foreground_bytes_written: row.get_i64("ForegroundBytesWritten"),
                foreground_num_read_ops: row.get_i64("ForegroundNumReadOperations"),
                foreground_num_write_ops: row.get_i64("ForegroundNumWriteOperations"),
                foreground_num_flushes: row.get_i64("ForegroundNumberOfFlushes"),
                background_bytes_read: row.get_i64("BackgroundBytesRead"),
                background_bytes_written: row.get_i64("BackgroundBytesWritten"),
                background_num_read_ops: row.get_i64("BackgroundNumReadOperations"),
                background_num_write_ops: row.get_i64("BackgroundNumWriteOperations"),
                background_num_flushes: row.get_i64("BackgroundNumberOfFlushes"),
            });
        }
    }
}
