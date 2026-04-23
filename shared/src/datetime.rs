use chrono::{DateTime, NaiveDateTime, Utc};

const SQLITE_DATETIME_FMT: &str = "%Y-%m-%d %H:%M:%S";

pub trait SqliteDateTimeExt {
    fn to_sqlite(&self) -> String;
}

impl SqliteDateTimeExt for DateTime<Utc> {
    fn to_sqlite(&self) -> String {
        self.format(SQLITE_DATETIME_FMT).to_string()
    }
}

pub fn parse_sqlite(s: &str) -> Option<NaiveDateTime> {
    NaiveDateTime::parse_from_str(s, SQLITE_DATETIME_FMT).ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn format_matches_sqlite() {
        let dt = chrono::TimeZone::with_ymd_and_hms(&Utc, 2025, 1, 15, 9, 30, 0).unwrap();
        assert_eq!(dt.to_sqlite(), "2025-01-15 09:30:00");
    }

    #[test]
    fn parse_roundtrip() {
        let dt = chrono::TimeZone::with_ymd_and_hms(&Utc, 2025, 1, 15, 9, 30, 0).unwrap();
        let s = dt.to_sqlite();
        let parsed = parse_sqlite(&s).unwrap();
        assert_eq!(parsed, dt.naive_utc());
    }

    #[test]
    fn parse_invalid_returns_none() {
        assert!(parse_sqlite("not-a-date").is_none());
    }
}
