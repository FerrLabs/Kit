//! The contract version itself: a date, totally ordered, parsed strictly.

use std::fmt;
use std::str::FromStr;

use serde::{Deserialize, Deserializer, Serialize, Serializer};

/// A point in time of the API contract.
///
/// Not a release of software. The `api` binary ships many times without the
/// contract moving, and conflating the two is the failure this type exists to
/// prevent — see the crate docs for why a date rather than a number.
///
/// Ordering is chronological, which is the only property the transform chain
/// depends on.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ApiVersion {
    // Field order *is* the comparison order: `derive(Ord)` compares
    // lexicographically by declaration. Reordering these silently breaks
    // every version comparison in the crate.
    year: u16,
    month: u8,
    day: u8,
}

impl ApiVersion {
    /// A version from its parts, or `None` if that date does not exist.
    ///
    /// `const` so a product can name its current contract as a constant:
    ///
    /// ```
    /// # use ferrlabs_api_version::ApiVersion;
    /// const CURRENT: ApiVersion = match ApiVersion::from_ymd(2026, 8, 3) {
    ///     Some(v) => v,
    ///     None => panic!("invalid contract version"),
    /// };
    /// ```
    #[must_use]
    pub const fn from_ymd(year: u16, month: u8, day: u8) -> Option<Self> {
        if month == 0 || month > 12 || day == 0 {
            return None;
        }
        if day > days_in_month(year, month) {
            return None;
        }
        Some(Self { year, month, day })
    }

    #[must_use]
    pub const fn year(self) -> u16 {
        self.year
    }

    #[must_use]
    pub const fn month(self) -> u8 {
        self.month
    }

    #[must_use]
    pub const fn day(self) -> u8 {
        self.day
    }
}

const fn days_in_month(year: u16, month: u8) -> u8 {
    match month {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        2 if is_leap(year) => 29,
        2 => 28,
        _ => 0,
    }
}

const fn is_leap(year: u16) -> bool {
    year % 4 == 0 && (year % 100 != 0 || year % 400 == 0)
}

/// Why a version string was rejected.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ParseApiVersionError {
    /// Not exactly `YYYY-MM-DD`.
    Malformed,
    /// Well-formed but not a real date — `2026-02-30`, say.
    NotACalendarDate,
}

impl fmt::Display for ParseApiVersionError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Malformed => f.write_str("expected a version of the form YYYY-MM-DD"),
            Self::NotACalendarDate => f.write_str("not a real calendar date"),
        }
    }
}

impl std::error::Error for ParseApiVersionError {}

impl FromStr for ApiVersion {
    type Err = ParseApiVersionError;

    /// Strict: exactly ten characters, zero-padded, dashes in place.
    ///
    /// A lenient parser would accept `2026-8-3` and hand back a version whose
    /// `Display` does not round-trip, so the same contract would reach logs and
    /// audit rows under two spellings.
    fn from_str(raw: &str) -> Result<Self, Self::Err> {
        let bytes = raw.as_bytes();
        if bytes.len() != 10 || bytes[4] != b'-' || bytes[7] != b'-' {
            return Err(ParseApiVersionError::Malformed);
        }
        let year = parse_digits(&bytes[0..4]).ok_or(ParseApiVersionError::Malformed)?;
        let month = parse_digits(&bytes[5..7]).ok_or(ParseApiVersionError::Malformed)?;
        let day = parse_digits(&bytes[8..10]).ok_or(ParseApiVersionError::Malformed)?;

        let month = u8::try_from(month).map_err(|_| ParseApiVersionError::NotACalendarDate)?;
        let day = u8::try_from(day).map_err(|_| ParseApiVersionError::NotACalendarDate)?;

        Self::from_ymd(year, month, day).ok_or(ParseApiVersionError::NotACalendarDate)
    }
}

fn parse_digits(bytes: &[u8]) -> Option<u16> {
    let mut value: u16 = 0;
    for &byte in bytes {
        if !byte.is_ascii_digit() {
            return None;
        }
        value = value.checked_mul(10)?.checked_add(u16::from(byte - b'0'))?;
    }
    Some(value)
}

impl fmt::Display for ApiVersion {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:04}-{:02}-{:02}", self.year, self.month, self.day)
    }
}

impl Serialize for ApiVersion {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.collect_str(self)
    }
}

impl<'de> Deserialize<'de> for ApiVersion {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let raw = String::deserialize(deserializer)?;
        raw.parse().map_err(serde::de::Error::custom)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_and_round_trips() {
        let version: ApiVersion = "2026-08-03".parse().unwrap();
        assert_eq!(version.year(), 2026);
        assert_eq!(version.month(), 8);
        assert_eq!(version.day(), 3);
        assert_eq!(version.to_string(), "2026-08-03");
    }

    /// Chronological order is the one property the transform chain relies on:
    /// "every transform newer than what the client pinned" is a comparison.
    #[test]
    fn orders_chronologically() {
        let older: ApiVersion = "2026-08-03".parse().unwrap();
        let newer: ApiVersion = "2026-09-01".parse().unwrap();
        let next_year: ApiVersion = "2027-01-01".parse().unwrap();
        assert!(older < newer);
        assert!(newer < next_year);
        assert!(older < next_year);
    }

    #[test]
    fn rejects_shapes_that_are_not_yyyy_mm_dd() {
        for raw in [
            "2026-8-3",
            "2026-08-3",
            "26-08-03",
            "2026/08/03",
            "2026-08-03T00:00:00Z",
            "2026-08-0",
            "",
            "abcd-ef-gh",
            "3.36.0",
        ] {
            assert_eq!(
                raw.parse::<ApiVersion>(),
                Err(ParseApiVersionError::Malformed),
                "accepted {raw}"
            );
        }
    }

    /// A package version is the shape most likely to be sent by mistake, and
    /// it must not parse into something plausible.
    #[test]
    fn rejects_dates_that_do_not_exist() {
        for raw in ["2026-02-30", "2026-13-01", "2026-00-01", "2026-01-00"] {
            assert_eq!(
                raw.parse::<ApiVersion>(),
                Err(ParseApiVersionError::NotACalendarDate),
                "accepted {raw}"
            );
        }
    }

    #[test]
    fn knows_about_leap_years() {
        assert!("2028-02-29".parse::<ApiVersion>().is_ok());
        assert!("2026-02-29".parse::<ApiVersion>().is_err());
        assert!("2000-02-29".parse::<ApiVersion>().is_ok());
        assert!("1900-02-29".parse::<ApiVersion>().is_err());
    }

    #[test]
    fn serde_uses_the_wire_spelling() {
        let version: ApiVersion = "2026-08-03".parse().unwrap();
        let json = serde_json::to_string(&version).unwrap();
        assert_eq!(json, "\"2026-08-03\"");
        assert_eq!(serde_json::from_str::<ApiVersion>(&json).unwrap(), version);
    }
}
