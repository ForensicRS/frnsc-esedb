//! `{5C8CF1C7-7257-4F13-B223-970EF5939312}` — Application Timeline.
//!
//! Detailed per-second timeline bitmaps for focus, input, CPU, disk, network,
//! audio, and display activity.
use forensic_rs::utils::time::ForensicTimestamp;

use crate::RowIter;

pub const TABLE_GUID: &str = "{5C8CF1C7-7257-4F13-B223-970EF5939312}";

/// A raw blob timeline is a packed bit array (1 bit per second). We expose it
/// as raw bytes; callers can decode individual seconds as needed.
pub type TimelineBitmap = Vec<u8>;

#[derive(Debug, Clone)]
pub struct AppTimelineRecord {
    pub auto_inc_id: i64,
    pub timestamp: ForensicTimestamp,
    pub app_id: i64,
    pub user_id: i64,
    pub flags: Option<i64>,
    pub end_time: Option<ForensicTimestamp>,
    // Aggregate seconds counters
    pub in_focus_s: Option<i64>,
    pub psm_foreground_s: Option<i64>,
    pub user_input_s: Option<i64>,
    pub comp_rendered_s: Option<i64>,
    pub comp_dirtied_s: Option<i64>,
    pub comp_propagated_s: Option<i64>,
    pub audio_in_s: Option<i64>,
    pub audio_out_s: Option<i64>,
    pub cycles: Option<i64>,
    pub cycles_wob: Option<i64>,
    pub disk_raw: Option<i64>,
    pub network_tail_raw: Option<i64>,
    pub network_bytes_raw: Option<i64>,
    pub mbb_tail_raw: Option<i64>,
    pub mbb_bytes_raw: Option<i64>,
    pub display_required_s: Option<i64>,
    pub keyboard_input_s: Option<i64>,
    pub mouse_input_s: Option<i64>,
    // Raw timeline bitmaps (1 bit per second of activity)
    pub in_focus_timeline: Option<TimelineBitmap>,
    pub user_input_timeline: Option<TimelineBitmap>,
    pub comp_rendered_timeline: Option<TimelineBitmap>,
    pub comp_dirtied_timeline: Option<TimelineBitmap>,
    pub comp_propagated_timeline: Option<TimelineBitmap>,
    pub audio_in_timeline: Option<TimelineBitmap>,
    pub audio_out_timeline: Option<TimelineBitmap>,
    pub cpu_timeline: Option<TimelineBitmap>,
    pub disk_timeline: Option<TimelineBitmap>,
    pub network_timeline: Option<TimelineBitmap>,
    pub mbb_timeline: Option<TimelineBitmap>,
    pub display_required_timeline: Option<TimelineBitmap>,
    pub keyboard_input_timeline: Option<TimelineBitmap>,
}

pub struct AppTimelineIter<'a> {
    rows: RowIter<'a>,
}

impl<'a> AppTimelineIter<'a> {
    pub(crate) fn new(rows: RowIter<'a>) -> Self {
        Self { rows }
    }
}

impl<'a> Iterator for AppTimelineIter<'a> {
    type Item = AppTimelineRecord;

    fn next(&mut self) -> Option<Self::Item> {
        loop {
        let row = self.rows.next()?;
        let Some(auto_inc_id) = row.get_i64("AutoIncId") else { continue };
        let Some(timestamp) = row.get_datetime("TimeStamp") else { continue };
        let Some(app_id) = row.get_i64("AppId") else { continue };
        let Some(user_id) = row.get_i64("UserId") else { continue };
        return Some(AppTimelineRecord {
            auto_inc_id,
            timestamp,
            app_id,
            user_id,
            flags: row.get_i64("Flags"),
            end_time: row.get_datetime("EndTime"),
            in_focus_s: row.get_i64("InFocusS"),
            psm_foreground_s: row.get_i64("PSMForegroundS"),
            user_input_s: row.get_i64("UserInputS"),
            comp_rendered_s: row.get_i64("CompRenderedS"),
            comp_dirtied_s: row.get_i64("CompDirtiedS"),
            comp_propagated_s: row.get_i64("CompPropagatedS"),
            audio_in_s: row.get_i64("AudioInS"),
            audio_out_s: row.get_i64("AudioOutS"),
            cycles: row.get_i64("Cycles"),
            cycles_wob: row.get_i64("CyclesWOB"),
            disk_raw: row.get_i64("DiskRaw"),
            network_tail_raw: row.get_i64("NetworkTailRaw"),
            network_bytes_raw: row.get_i64("NetworkBytesRaw"),
            mbb_tail_raw: row.get_i64("MBBTailRaw"),
            mbb_bytes_raw: row.get_i64("MBBBytesRaw"),
            display_required_s: row.get_i64("DisplayRequiredS"),
            keyboard_input_s: row.get_i64("KeyboardInputS"),
            mouse_input_s: row.get_i64("MouseInputS"),
            in_focus_timeline: row.get_bytes("InFocusTimeline").map(<[u8]>::to_vec),
            user_input_timeline: row.get_bytes("UserInputTimeline").map(<[u8]>::to_vec),
            comp_rendered_timeline: row.get_bytes("CompRenderedTimeline").map(<[u8]>::to_vec),
            comp_dirtied_timeline: row.get_bytes("CompDirtiedTimeline").map(<[u8]>::to_vec),
            comp_propagated_timeline: row.get_bytes("CompPropagatedTimeline").map(<[u8]>::to_vec),
            audio_in_timeline: row.get_bytes("AudioInTimeline").map(<[u8]>::to_vec),
            audio_out_timeline: row.get_bytes("AudioOutTimeline").map(<[u8]>::to_vec),
            cpu_timeline: row.get_bytes("CpuTimeline").map(<[u8]>::to_vec),
            disk_timeline: row.get_bytes("DiskTimeline").map(<[u8]>::to_vec),
            network_timeline: row.get_bytes("NetworkTimeline").map(<[u8]>::to_vec),
            mbb_timeline: row.get_bytes("MBBTimeline").map(<[u8]>::to_vec),
            display_required_timeline: row.get_bytes("DisplayRequiredTimeline").map(<[u8]>::to_vec),
            keyboard_input_timeline: row.get_bytes("KeyboardInputTimeline").map(<[u8]>::to_vec),
        });
        } // loop
    }
}
