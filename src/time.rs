//! Platform-independent clock and RFC 3339 helpers.

/// Milliseconds since the Unix epoch.
pub(crate) fn now_millis() -> i64 {
    #[cfg(target_arch = "wasm32")]
    {
        js_sys::Date::now() as i64
    }
    #[cfg(not(target_arch = "wasm32"))]
    {
        use std::time::{SystemTime, UNIX_EPOCH};
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_millis() as i64)
            .unwrap_or(0)
    }
}

/// Format Unix seconds + nanos as RFC 3339 UTC (`2024-01-02T03:04:05.123456789Z`).
pub(crate) fn format_rfc3339(secs: i64, nanos: u32) -> String {
    let days = secs.div_euclid(86_400);
    let sod = secs.rem_euclid(86_400);
    let (y, m, d) = civil_from_days(days);
    let (hh, mm, ss) = (sod / 3600, (sod % 3600) / 60, sod % 60);
    if nanos == 0 {
        format!("{y:04}-{m:02}-{d:02}T{hh:02}:{mm:02}:{ss:02}Z")
    } else {
        format!("{y:04}-{m:02}-{d:02}T{hh:02}:{mm:02}:{ss:02}.{nanos:09}Z")
    }
}

/// Parse an RFC 3339 timestamp into (Unix seconds, nanos).
pub(crate) fn parse_rfc3339(s: &str) -> Option<(i64, u32)> {
    let b = s.as_bytes();
    if b.len() < 20 || b[4] != b'-' || b[7] != b'-' || !(b[10] == b'T' || b[10] == b't') {
        return None;
    }
    let num = |r: std::ops::Range<usize>| s.get(r)?.parse::<i64>().ok();
    let (y, mo, d) = (num(0..4)?, num(5..7)?, num(8..10)?);
    let (hh, mi, ss) = (num(11..13)?, num(14..16)?, num(17..19)?);
    let mut idx = 19;
    let mut nanos: u32 = 0;
    if b.get(idx) == Some(&b'.') {
        idx += 1;
        let start = idx;
        while idx < b.len() && b[idx].is_ascii_digit() {
            idx += 1;
        }
        let frac = &s[start..idx];
        if frac.is_empty() {
            return None;
        }
        let mut digits = frac.chars().take(9).collect::<String>();
        while digits.len() < 9 {
            digits.push('0');
        }
        nanos = digits.parse().ok()?;
    }
    let offset_secs = match s.get(idx..)? {
        "Z" | "z" => 0,
        rest if rest.len() == 6 && (rest.starts_with('+') || rest.starts_with('-')) => {
            let h: i64 = rest[1..3].parse().ok()?;
            let m: i64 = rest[4..6].parse().ok()?;
            let v = h * 3600 + m * 60;
            if rest.starts_with('-') {
                -v
            } else {
                v
            }
        }
        _ => return None,
    };
    if !(1..=12).contains(&mo) || !(1..=31).contains(&d) || hh > 23 || mi > 59 || ss > 60 {
        return None;
    }
    let days = days_from_civil(y, mo as u32, d as u32);
    Some((
        days * 86_400 + hh * 3600 + mi * 60 + ss - offset_secs,
        nanos,
    ))
}

// Howard Hinnant's civil date algorithms.
fn civil_from_days(z: i64) -> (i64, u32, u32) {
    let z = z + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    (if m <= 2 { y + 1 } else { y }, m, d)
}

fn days_from_civil(y: i64, m: u32, d: u32) -> i64 {
    let y = if m <= 2 { y - 1 } else { y };
    let era = y.div_euclid(400);
    let yoe = y.rem_euclid(400);
    let mp = (m as i64 + 9) % 12;
    let doy = (153 * mp + 2) / 5 + d as i64 - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146_097 + doe - 719_468
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip() {
        assert_eq!(format_rfc3339(0, 0), "1970-01-01T00:00:00Z");
        assert_eq!(
            format_rfc3339(1_700_000_000, 5),
            "2023-11-14T22:13:20.000000005Z"
        );
        assert_eq!(
            parse_rfc3339("2023-11-14T22:13:20.000000005Z"),
            Some((1_700_000_000, 5))
        );
        assert_eq!(
            parse_rfc3339("2023-11-15T07:13:20.5+09:00"),
            Some((1_700_000_000, 500_000_000))
        );
        assert_eq!(parse_rfc3339("1969-12-31T23:59:59Z"), Some((-1, 0)));
        assert_eq!(parse_rfc3339("garbage"), None);
        for s in [-86_400 * 800_000, -1, 0, 951_782_400, 4_102_444_800] {
            let f = format_rfc3339(s, 0);
            assert_eq!(parse_rfc3339(&f), Some((s, 0)), "{f}");
        }
    }
}
