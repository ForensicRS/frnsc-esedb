use forensic_rs::{err::ForensicError, utils::time::Filetime};

pub struct LogTime(pub u64);

impl TryFrom<LogTime> for Filetime {
    fn try_from(value: LogTime) -> Result<Self, Self::Error> {
        let bf = value.0.to_le_bytes();
        let seconds = bf[0];
        if seconds >= 60 {
            return Err(ForensicError::bad_format_str("Seconds must be between 0 and 60"));
        }
        let minutes = bf[1];
        if minutes >= 60 {
            return Err(ForensicError::bad_format_str("Minutes must be between 0 and 60"));
        }
        let hours = bf[2];
        if hours >= 24 {
            return Err(ForensicError::bad_format_str("Hours must be between 0 and 24"));
        }
        let days = bf[3] as u64;
        if days >= 31 {
            return Err(ForensicError::bad_format_str("Hours must be between 0 and 32"));
        }
        let month = bf[4];
        if month >= 12 {
            return Err(ForensicError::bad_format_str("Month must be between 0 and 12"));
        }
        let year = bf[5] as u64 + 1900;

        let acumulated_day_month = if is_leap_year(year) {
            [0, 31, 60, 91, 121, 152, 182, 213, 244, 274, 305, 335][month as usize]
        } else {
            [0, 31, 59, 90, 120, 151, 181, 212, 243, 273, 304, 334][month as usize]
        };
        let days_years = to_days_since_begining(year);
        let total = (((days_years + acumulated_day_month + days as u64) * 24 + hours as u64) * 3600 + minutes as u64 * 60 + seconds as u64) * 1000 * 1000 * 10;
        Ok(Self::new(total))
    }
    
    type Error = ForensicError;
}

fn is_leap_year(year: u64) -> bool {
    (year % 4 == 0 && year % 100 != 0) || (year % 100 == 0 && year % 400 == 0)
}

fn to_days_since_begining(year : u64) -> u64 {
    let mut total = 0;
    for y in 1601..year {
        total += if is_leap_year(y) { 366 } else { 365 };
    }
    total
}

#[test]
fn should_convert_to_filetime() {
    let time = LogTime(u64::from_le_bytes([0u8,0,0,0,0,0,0,0]));
    let filetime : Filetime = time.try_into().unwrap();
    assert_eq!(Filetime::new(94354848000000000).filetime(), filetime.filetime());
}