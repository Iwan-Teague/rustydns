//! Per-client scheduled block windows (TODO 8.5).
//!
//! A `[[policy]]` may carry `[[policy.block_windows]]` entries — time windows
//! during which **all** of that client's queries are refused ("kids' devices
//! off after 22:00", "guest network blocked overnight"). The matching is a
//! pure function of a Unix timestamp so it is fully deterministic and
//! unit-testable; the daemon feeds it `SystemTime::now()` per query.
//!
//! # Time model — dependency-free, fixed offset
//!
//! We deliberately avoid pulling in a timezone database. Each window carries an
//! explicit `utc_offset_minutes`; the local wall-clock day-of-week and
//! time-of-day are computed from the Unix timestamp plus that offset. **DST is
//! not handled** — an operator in a DST zone should set the offset for the
//! period that matters, or split the window. This is documented and is the
//! intended trade-off (keeping the schema timezone-*explicit* without a tz
//! crate).

use crate::config::BlockWindow;

/// Bit `i` (Mon=0 … Sun=6) set means that weekday is included. `0x7f` = all.
const ALL_DAYS: u8 = 0b0111_1111;

/// A single compiled window.
#[derive(Debug, Clone, Copy)]
struct CompiledWindow {
    /// Weekday bitmask (Mon=0 … Sun=6).
    days_mask: u8,
    /// `Some((start_min, end_min))` for a timed window, or `None` for all-day.
    /// `end <= start` means the window wraps past midnight.
    span: Option<(u16, u16)>,
    /// Fixed UTC offset in minutes used to interpret the window locally.
    offset_min: i32,
}

/// A compiled set of block windows for one client. Empty when none configured.
#[derive(Debug, Clone, Default)]
pub struct BlockSchedule {
    windows: Vec<CompiledWindow>,
}

impl BlockSchedule {
    /// Compile and validate `windows`. Returns a human-readable error (naming
    /// the bad field) so `validate_config` can reject a bad config at startup.
    pub fn compile(windows: &[BlockWindow]) -> Result<Self, String> {
        let mut compiled = Vec::with_capacity(windows.len());
        for (i, w) in windows.iter().enumerate() {
            let days_mask = parse_days(&w.days).map_err(|e| format!("block_windows[{i}]: {e}"))?;

            let span = match (&w.start, &w.end) {
                (None, None) => None, // all-day
                (Some(s), Some(e)) => {
                    let start = parse_hhmm(s)
                        .map_err(|err| format!("block_windows[{i}].start `{s}`: {err}"))?;
                    let end = parse_hhmm(e)
                        .map_err(|err| format!("block_windows[{i}].end `{e}`: {err}"))?;
                    if start == end {
                        return Err(format!(
                            "block_windows[{i}]: start and end are equal (`{s}`); use \
                             both-omitted for an all-day window, or pick distinct times"
                        ));
                    }
                    Some((start, end))
                }
                _ => {
                    return Err(format!(
                        "block_windows[{i}]: set both `start` and `end` (a timed window) or \
                         neither (an all-day window)"
                    ));
                }
            };

            if w.utc_offset_minutes < -1440 || w.utc_offset_minutes > 1440 {
                return Err(format!(
                    "block_windows[{i}].utc_offset_minutes = {} is out of range (-1440..=1440)",
                    w.utc_offset_minutes
                ));
            }

            compiled.push(CompiledWindow {
                days_mask,
                span,
                offset_min: w.utc_offset_minutes,
            });
        }
        Ok(Self { windows: compiled })
    }

    /// Returns `true` if `unix_secs` falls inside any block window.
    pub fn is_blocked_at(&self, unix_secs: u64) -> bool {
        self.windows.iter().any(|w| window_matches(w, unix_secs))
    }

    /// Returns `true` if no windows are configured.
    pub fn is_empty(&self) -> bool {
        self.windows.is_empty()
    }
}

fn window_matches(w: &CompiledWindow, unix_secs: u64) -> bool {
    // Local wall-clock = UTC + offset. Use i64 + euclidean math so a negative
    // offset near the epoch (or any offset) yields a correct day/time.
    let local = unix_secs as i64 + (w.offset_min as i64) * 60;
    let days = local.div_euclid(86_400);
    // Epoch day 0 (1970-01-01) was a Thursday = weekday 3 with Mon=0.
    let weekday = (days + 3).rem_euclid(7) as u8;
    if w.days_mask & (1 << weekday) == 0 {
        return false;
    }
    match w.span {
        None => true, // all-day
        Some((start, end)) => {
            let tod_min = (local.rem_euclid(86_400) / 60) as u16;
            if start < end {
                tod_min >= start && tod_min < end
            } else {
                // Wraps past midnight: [start, 24:00) ∪ [00:00, end).
                tod_min >= start || tod_min < end
            }
        }
    }
}

/// Parse a `["mon","sat",…]` list into a weekday bitmask. Empty list = all days.
fn parse_days(days: &[String]) -> Result<u8, String> {
    if days.is_empty() {
        return Ok(ALL_DAYS);
    }
    let mut mask = 0u8;
    for d in days {
        let bit = match d.trim().to_ascii_lowercase().as_str() {
            "mon" | "monday" => 0,
            "tue" | "tuesday" => 1,
            "wed" | "wednesday" => 2,
            "thu" | "thursday" => 3,
            "fri" | "friday" => 4,
            "sat" | "saturday" => 5,
            "sun" | "sunday" => 6,
            other => {
                return Err(format!(
                    "`{other}` is not a weekday (use mon/tue/wed/thu/fri/sat/sun)"
                ));
            }
        };
        mask |= 1 << bit;
    }
    Ok(mask)
}

/// Parse `"HH:MM"` (24-hour) into minutes since midnight (0..=1439).
fn parse_hhmm(s: &str) -> Result<u16, String> {
    let (h, m) = s
        .trim()
        .split_once(':')
        .ok_or_else(|| "expected HH:MM".to_string())?;
    let h: u16 = h.parse().map_err(|_| "hour is not a number".to_string())?;
    let m: u16 = m
        .parse()
        .map_err(|_| "minute is not a number".to_string())?;
    if h > 23 {
        return Err("hour must be 0..=23".to_string());
    }
    if m > 59 {
        return Err("minute must be 0..=59".to_string());
    }
    Ok(h * 60 + m)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn win(days: &[&str], start: Option<&str>, end: Option<&str>, off: i32) -> BlockWindow {
        BlockWindow {
            days: days.iter().map(|s| s.to_string()).collect(),
            start: start.map(str::to_string),
            end: end.map(str::to_string),
            utc_offset_minutes: off,
        }
    }

    // 2021-06-14 12:00:00 UTC was a Monday. Epoch = 1623672000.
    const MON_NOON_UTC: u64 = 1_623_672_000;

    fn at(base: u64, add_min: i64) -> u64 {
        (base as i64 + add_min * 60) as u64
    }

    #[test]
    fn empty_schedule_blocks_nothing() {
        let s = BlockSchedule::compile(&[]).unwrap();
        assert!(s.is_empty());
        assert!(!s.is_blocked_at(MON_NOON_UTC));
    }

    #[test]
    fn timed_window_same_day_utc() {
        // Block 09:00–17:00 UTC, all days. Monday noon is inside.
        let s = BlockSchedule::compile(&[win(&[], Some("09:00"), Some("17:00"), 0)]).unwrap();
        assert!(s.is_blocked_at(MON_NOON_UTC));
        // 08:59 just before → not blocked; 17:00 exclusive → not blocked.
        assert!(!s.is_blocked_at(at(MON_NOON_UTC, -181))); // 08:59
        assert!(!s.is_blocked_at(at(MON_NOON_UTC, 300))); // 17:00 exactly
        assert!(s.is_blocked_at(at(MON_NOON_UTC, 299))); // 16:59
    }

    #[test]
    fn wrapping_window_past_midnight() {
        // 22:00–07:00 (overnight). At Monday 23:00 → blocked; 12:00 → not.
        let s = BlockSchedule::compile(&[win(&[], Some("22:00"), Some("07:00"), 0)]).unwrap();
        assert!(s.is_blocked_at(at(MON_NOON_UTC, 11 * 60))); // 23:00 Mon
        assert!(s.is_blocked_at(at(MON_NOON_UTC, -6 * 60))); // 06:00 Mon
        assert!(!s.is_blocked_at(MON_NOON_UTC)); // 12:00 Mon
        assert!(!s.is_blocked_at(at(MON_NOON_UTC, -5 * 60))); // 07:00 exactly
    }

    #[test]
    fn day_filter_respected() {
        // Weekends only, all-day. Monday noon → not blocked.
        let s = BlockSchedule::compile(&[win(&["sat", "sun"], None, None, 0)]).unwrap();
        assert!(!s.is_blocked_at(MON_NOON_UTC));
        // +5 days = Saturday noon → blocked.
        assert!(s.is_blocked_at(at(MON_NOON_UTC, 5 * 24 * 60)));
        // +6 days = Sunday → blocked.
        assert!(s.is_blocked_at(at(MON_NOON_UTC, 6 * 24 * 60)));
        // +1 day = Tuesday → not.
        assert!(!s.is_blocked_at(at(MON_NOON_UTC, 24 * 60)));
    }

    #[test]
    fn utc_offset_shifts_local_time() {
        // 09:00–17:00 in UTC-5. Monday noon UTC = 07:00 local → NOT blocked.
        let s = BlockSchedule::compile(&[win(&[], Some("09:00"), Some("17:00"), -300)]).unwrap();
        assert!(!s.is_blocked_at(MON_NOON_UTC)); // 07:00 local
        // 14:00 UTC = 09:00 local → blocked.
        assert!(s.is_blocked_at(at(MON_NOON_UTC, 120)));
    }

    #[test]
    fn offset_can_change_the_weekday() {
        // Monday 00:30 UTC with offset -60 is Sunday 23:30 local. A
        // Sunday-only all-day window must catch it.
        let s = BlockSchedule::compile(&[win(&["sun"], None, None, -60)]).unwrap();
        let mon_0030 = at(MON_NOON_UTC, -(11 * 60 + 30)); // back to 00:30 Mon UTC
        assert!(s.is_blocked_at(mon_0030));
    }

    #[test]
    fn all_day_window_blocks_whole_day() {
        let s = BlockSchedule::compile(&[win(&["mon"], None, None, 0)]).unwrap();
        assert!(s.is_blocked_at(MON_NOON_UTC));
        assert!(s.is_blocked_at(at(MON_NOON_UTC, -11 * 60))); // 01:00 Mon
        assert!(s.is_blocked_at(at(MON_NOON_UTC, 11 * 60))); // 23:00 Mon
    }

    #[test]
    fn invalid_day_rejected() {
        let err = BlockSchedule::compile(&[win(&["funday"], None, None, 0)]).unwrap_err();
        assert!(err.contains("not a weekday"), "{err}");
    }

    #[test]
    fn invalid_time_rejected() {
        assert!(
            BlockSchedule::compile(&[win(&[], Some("25:00"), Some("26:00"), 0)])
                .unwrap_err()
                .contains("hour must be")
        );
        assert!(
            BlockSchedule::compile(&[win(&[], Some("9"), Some("17:00"), 0)])
                .unwrap_err()
                .contains("expected HH:MM")
        );
    }

    #[test]
    fn half_open_window_rejected() {
        let err = BlockSchedule::compile(&[win(&[], Some("09:00"), None, 0)]).unwrap_err();
        assert!(err.contains("both `start` and `end`"), "{err}");
    }

    #[test]
    fn equal_start_end_rejected() {
        let err = BlockSchedule::compile(&[win(&[], Some("09:00"), Some("09:00"), 0)]).unwrap_err();
        assert!(err.contains("equal"), "{err}");
    }

    #[test]
    fn out_of_range_offset_rejected() {
        let err = BlockSchedule::compile(&[win(&[], None, None, 2000)]).unwrap_err();
        assert!(err.contains("out of range"), "{err}");
    }
}
