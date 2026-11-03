//! RFC 3339 `date-time` strings in UTC for API timestamps (`specs/api.md`, Conventions).

use crate::error::AppError;

/// Formats Unix seconds as `YYYY-MM-DDThh:mm:ssZ`. Uses the proleptic Gregorian
/// calendar (Howard Hinnant's `civil_from_days`). Returns an error for times
/// outside years 0 to 9999.
pub fn rfc3339(unix_secs: i64) -> Result<String, AppError> {
    let days = unix_secs.div_euclid(86_400);
    let secs_of_day = unix_secs.rem_euclid(86_400);
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = if m <= 2 { y + 1 } else { y };
    if !(0..=9999).contains(&year) {
        return Err(AppError::InternalError);
    }
    Ok(format!(
        "{year:04}-{m:02}-{d:02}T{:02}:{:02}:{:02}Z",
        secs_of_day / 3600,
        (secs_of_day % 3600) / 60,
        secs_of_day % 60
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn formats_known_instants() {
        assert_eq!(rfc3339(0).unwrap(), "1970-01-01T00:00:00Z");
        assert_eq!(rfc3339(1_000_000_000).unwrap(), "2001-09-09T01:46:40Z");
        assert_eq!(rfc3339(951_782_400).unwrap(), "2000-02-29T00:00:00Z");
    }
}
