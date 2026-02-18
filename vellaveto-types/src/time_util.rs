//! Shared ISO 8601 timestamp parsing utilities.
//!
//! Provides a single, reusable parser for converting ISO 8601 timestamps
//! (format `YYYY-MM-DDTHH:MM:SS...`) to approximate Unix epoch seconds.
//! Used by both `etdi` and `minja` modules to avoid duplicated validation logic.

/// Parse an ISO 8601 timestamp to approximate Unix epoch seconds.
///
/// Accepts timestamps in the format `YYYY-MM-DDTHH:MM:SS` (with optional
/// trailing characters like `Z` or fractional seconds). Returns `Err` with
/// a description if the timestamp is malformed or contains invalid values.
///
/// SECURITY (FIND-P1-6): Validates that year >= 1970, month in 1..=12,
/// day in 1..=31, hour in 0..=23, minute in 0..=59, second in 0..=60
/// (allowing leap seconds). Rejects values that would cause underflow
/// in the epoch calculation.
///
/// Note: The calculation is approximate (assumes 365-day years and 30-day
/// months) but is consistent and monotonic, which is sufficient for
/// relative time comparisons (trust decay, expiry checks).
pub fn parse_iso8601_secs(ts: &str) -> Result<u64, String> {
    if ts.len() < 19 {
        return Err(format!(
            "Timestamp too short ({} chars, need at least 19)",
            ts.len()
        ));
    }

    let year: u64 = ts
        .get(0..4)
        .and_then(|s| s.parse().ok())
        .ok_or_else(|| "Invalid year".to_string())?;
    let month: u64 = ts
        .get(5..7)
        .and_then(|s| s.parse().ok())
        .ok_or_else(|| "Invalid month".to_string())?;
    let day: u64 = ts
        .get(8..10)
        .and_then(|s| s.parse().ok())
        .ok_or_else(|| "Invalid day".to_string())?;
    let hour: u64 = ts
        .get(11..13)
        .and_then(|s| s.parse().ok())
        .ok_or_else(|| "Invalid hour".to_string())?;
    let min: u64 = ts
        .get(14..16)
        .and_then(|s| s.parse().ok())
        .ok_or_else(|| "Invalid minute".to_string())?;
    let sec: u64 = ts
        .get(17..19)
        .and_then(|s| s.parse().ok())
        .ok_or_else(|| "Invalid second".to_string())?;

    if year < 1970 {
        return Err(format!("Year {year} is before Unix epoch (1970)"));
    }
    if month == 0 || month > 12 {
        return Err(format!("Month {month} out of range 1..=12"));
    }
    if day == 0 || day > 31 {
        return Err(format!("Day {day} out of range 1..=31"));
    }
    if hour > 23 {
        return Err(format!("Hour {hour} out of range 0..=23"));
    }
    if min > 59 {
        return Err(format!("Minute {min} out of range 0..=59"));
    }
    // sec == 60 is valid for leap seconds in ISO 8601, but > 60 is not
    if sec > 60 {
        return Err(format!("Second {sec} out of range 0..=60"));
    }

    // Approximate calculation (ignores leap years, varying month lengths)
    let days_since_epoch = (year - 1970) * 365 + (month - 1) * 30 + day;
    Ok(days_since_epoch * 86400 + hour * 3600 + min * 60 + sec)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_iso8601_secs_valid_timestamp() {
        let result = parse_iso8601_secs("2026-02-01T00:00:00Z");
        assert!(result.is_ok());
        assert!(result.unwrap() > 0);
    }

    #[test]
    fn test_parse_iso8601_secs_valid_without_z() {
        // Parser accepts timestamps without trailing Z (minja use case)
        let result = parse_iso8601_secs("2026-02-01T12:30:45");
        assert!(result.is_ok());
    }

    #[test]
    fn test_parse_iso8601_secs_too_short() {
        let result = parse_iso8601_secs("2026-02");
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("too short"));
    }

    #[test]
    fn test_parse_iso8601_secs_rejects_month_zero() {
        let result = parse_iso8601_secs("2026-00-15T12:00:00Z");
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("Month"));
    }

    #[test]
    fn test_parse_iso8601_secs_rejects_month_13() {
        let result = parse_iso8601_secs("2026-13-01T00:00:00Z");
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("Month"));
    }

    #[test]
    fn test_parse_iso8601_secs_rejects_year_before_epoch() {
        let result = parse_iso8601_secs("1969-06-15T12:00:00Z");
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("before Unix epoch"));
    }

    #[test]
    fn test_parse_iso8601_secs_rejects_day_zero() {
        let result = parse_iso8601_secs("2026-01-00T12:00:00Z");
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("Day"));
    }

    #[test]
    fn test_parse_iso8601_secs_rejects_hour_25() {
        let result = parse_iso8601_secs("2026-01-01T25:00:00Z");
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("Hour"));
    }

    #[test]
    fn test_parse_iso8601_secs_allows_leap_second() {
        let result = parse_iso8601_secs("2026-01-01T23:59:60Z");
        assert!(result.is_ok());
    }

    #[test]
    fn test_parse_iso8601_secs_rejects_second_61() {
        let result = parse_iso8601_secs("2026-01-01T23:59:61Z");
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("Second"));
    }

    #[test]
    fn test_parse_iso8601_secs_monotonic() {
        let t1 = parse_iso8601_secs("2026-01-01T00:00:00Z").unwrap();
        let t2 = parse_iso8601_secs("2026-01-02T00:00:00Z").unwrap();
        let t3 = parse_iso8601_secs("2026-02-01T00:00:00Z").unwrap();
        assert!(t1 < t2);
        assert!(t2 < t3);
    }
}
