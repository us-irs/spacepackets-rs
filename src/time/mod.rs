//! CCSDS Time Code Formats according to [CCSDS 301.0-B-4](https://public.ccsds.org/Pubs/301x0b4e1.pdf)
use crate::ByteConversionError;
#[cfg(feature = "chrono")]
use chrono::{TimeZone, Utc};
use core::cmp::Ordering;
use core::fmt::{Display, Formatter};
use core::ops::{Add, AddAssign, Sub};
use core::time::Duration;

#[allow(unused_imports)]
#[cfg(not(feature = "std"))]
use num_traits::float::FloatCore;

#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

#[cfg(feature = "std")]
use std::error::Error;
#[cfg(feature = "std")]
use std::time::{SystemTime, SystemTimeError};
#[cfg(feature = "std")]
pub use std_mod::*;

pub mod ascii;
pub mod cds;
pub mod cuc;

pub const DAYS_CCSDS_TO_UNIX: i32 = -4383;
pub const SECONDS_PER_DAY: u32 = 86400;
pub const MS_PER_DAY: u32 = SECONDS_PER_DAY * 1000;
pub const NANOS_PER_SECOND: u32 = 1_000_000_000;

#[derive(Debug, PartialEq, Eq, Copy, Clone)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum CcsdsTimeCode {
    CucCcsdsEpoch = 0b001,
    CucAgencyEpoch = 0b010,
    Cds = 0b100,
    Ccs = 0b101,
    AgencyDefined = 0b110,
}

impl TryFrom<u8> for CcsdsTimeCode {
    type Error = ();

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            x if x == CcsdsTimeCode::CucCcsdsEpoch as u8 => Ok(CcsdsTimeCode::CucCcsdsEpoch),
            x if x == CcsdsTimeCode::CucAgencyEpoch as u8 => Ok(CcsdsTimeCode::CucAgencyEpoch),
            x if x == CcsdsTimeCode::Cds as u8 => Ok(CcsdsTimeCode::Cds),
            x if x == CcsdsTimeCode::Ccs as u8 => Ok(CcsdsTimeCode::Ccs),
            x if x == CcsdsTimeCode::AgencyDefined as u8 => Ok(CcsdsTimeCode::AgencyDefined),
            _ => Err(()),
        }
    }
}

/// Retrieve the CCSDS time code from the p-field. If no valid time code identifier is found, the
/// value of the raw time code identification field is returned.
pub fn ccsds_time_code_from_p_field(pfield: u8) -> Result<CcsdsTimeCode, u8> {
    let raw_bits = (pfield >> 4) & 0b111;
    CcsdsTimeCode::try_from(raw_bits).map_err(|_| raw_bits)
}

#[derive(Debug, PartialEq, Eq, Copy, Clone)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct DateBeforeCcsdsEpochError(UnixTime);

impl Display for DateBeforeCcsdsEpochError {
    fn fmt(&self, f: &mut Formatter<'_>) -> core::fmt::Result {
        write!(f, "date before ccsds epoch: {:?}", self.0)
    }
}

#[cfg(feature = "std")]
impl Error for DateBeforeCcsdsEpochError {}

#[derive(Debug, PartialEq, Eq, Copy, Clone)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
#[non_exhaustive]
pub enum TimestampError {
    InvalidTimeCode { expected: CcsdsTimeCode, found: u8 },
    ByteConversion(ByteConversionError),
    Cds(cds::CdsError),
    Cuc(cuc::CucError),
    CustomEpochNotSupported,
}

impl Display for TimestampError {
    fn fmt(&self, f: &mut Formatter<'_>) -> core::fmt::Result {
        match self {
            TimestampError::InvalidTimeCode { expected, found } => {
                write!(
                    f,
                    "invalid raw time code value {found} for time code {expected:?}"
                )
            }
            TimestampError::Cds(e) => {
                write!(f, "cds error: {e}")
            }
            TimestampError::Cuc(e) => {
                write!(f, "cuc error: {e}")
            }
            TimestampError::ByteConversion(e) => {
                write!(f, "time stamp: {e}")
            }
            TimestampError::CustomEpochNotSupported => {
                write!(f, "custom epochs are not supported")
            }
        }
    }
}

#[cfg(feature = "std")]
impl Error for TimestampError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            TimestampError::ByteConversion(e) => Some(e),
            TimestampError::Cds(e) => Some(e),
            TimestampError::Cuc(e) => Some(e),
            _ => None,
        }
    }
}

impl From<cds::CdsError> for TimestampError {
    fn from(e: cds::CdsError) -> Self {
        TimestampError::Cds(e)
    }
}

impl From<cuc::CucError> for TimestampError {
    fn from(e: cuc::CucError) -> Self {
        TimestampError::Cuc(e)
    }
}

#[cfg(feature = "std")]
pub mod std_mod {
    use crate::time::TimestampError;
    use std::time::SystemTimeError;
    use thiserror::Error;

    #[derive(Debug, Clone, Error)]
    pub enum StdTimestampError {
        #[error("system time error: {0:?}")]
        SystemTime(#[from] SystemTimeError),
        #[error("timestamp error: {0}")]
        Timestamp(#[from] TimestampError),
    }
}

#[cfg(feature = "std")]
pub fn seconds_since_epoch() -> f64 {
    SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .expect("System time generation failed")
        .as_secs_f64()
}

/// Convert UNIX days to CCSDS days
///
///  - CCSDS epoch: 1958-01-01T00:00:00+00:00
///  - UNIX Epoch: 1970-01-01T00:00:00+00:00
#[inline]
pub const fn unix_to_ccsds_days(unix_days: i64) -> i64 {
    unix_days - DAYS_CCSDS_TO_UNIX as i64
}

/// Convert CCSDS days to UNIX days
///
///  - CCSDS epoch: 1958-01-01T00:00:00+00:00
///  - UNIX Epoch: 1970-01-01T00:00:00+00:00
#[inline]
pub const fn ccsds_to_unix_days(ccsds_days: i64) -> i64 {
    ccsds_days + DAYS_CCSDS_TO_UNIX as i64
}

/// Similar to [unix_to_ccsds_days] but converts the epoch instead, which is the number of elpased
/// seconds since the CCSDS and UNIX epoch times.
#[inline]
pub const fn unix_epoch_to_ccsds_epoch(unix_epoch: i64) -> i64 {
    unix_epoch - (DAYS_CCSDS_TO_UNIX as i64 * SECONDS_PER_DAY as i64)
}

#[inline]
pub const fn ccsds_epoch_to_unix_epoch(ccsds_epoch: i64) -> i64 {
    ccsds_epoch + (DAYS_CCSDS_TO_UNIX as i64 * SECONDS_PER_DAY as i64)
}

#[cfg(feature = "std")]
pub fn ms_of_day_using_sysclock() -> u32 {
    ms_of_day(seconds_since_epoch())
}

pub fn ms_of_day(seconds_since_epoch: f64) -> u32 {
    let fraction_ms = seconds_since_epoch - seconds_since_epoch.floor();
    let ms_of_day: u32 = (((seconds_since_epoch.floor() as u32 % SECONDS_PER_DAY) * 1000) as f64
        + fraction_ms)
        .floor() as u32;
    ms_of_day
}

pub trait TimeWriter {
    fn len_written(&self) -> usize;

    /// Generic function to convert write a timestamp into a raw buffer.
    /// Returns the number of written bytes on success.
    fn write_to_bytes(&self, bytes: &mut [u8]) -> Result<usize, TimestampError>;

    #[cfg(feature = "alloc")]
    fn to_vec(&self) -> Result<alloc::vec::Vec<u8>, TimestampError> {
        let mut vec = alloc::vec![0; self.len_written()];
        self.write_to_bytes(&mut vec)?;
        Ok(vec)
    }
}

pub trait TimeReader: Sized {
    fn from_bytes(buf: &[u8]) -> Result<Self, TimestampError>;
}

/// Trait for generic CCSDS time providers.
///
/// The UNIX helper methods and the helper method are not strictly necessary but extremely
/// practical because they are a very common and simple exchange format for time information.
/// Therefore, it was decided to keep them in this trait as well.
pub trait CcsdsTimeProvider {
    fn len_as_bytes(&self) -> usize;

    /// Returns the pfield of the time provider. The pfield can have one or two bytes depending
    /// on the extension bit (first bit). The time provider should returns a tuple where the first
    /// entry denotes the length of the pfield and the second entry is the value of the pfield
    /// in big endian format.
    fn p_field(&self) -> (usize, [u8; 2]);
    fn ccdsd_time_code(&self) -> CcsdsTimeCode;

    fn unix_secs(&self) -> i64;
    fn subsec_nanos(&self) -> u32;

    fn subsec_millis(&self) -> u16 {
        (self.subsec_nanos() / 1_000_000) as u16
    }

    fn unix_time(&self) -> UnixTime {
        UnixTime::new(self.unix_secs(), self.subsec_nanos())
    }

    #[cfg(feature = "chrono")]
    fn chrono_date_time(&self) -> chrono::LocalResult<chrono::DateTime<chrono::Utc>> {
        chrono::Utc.timestamp_opt(self.unix_secs(), self.subsec_nanos())
    }

    #[cfg(feature = "timelib")]
    fn timelib_date_time(&self) -> Result<time::OffsetDateTime, time::error::ComponentRange> {
        Ok(time::OffsetDateTime::from_unix_timestamp(self.unix_secs())?
            + time::Duration::nanoseconds(self.subsec_nanos().into()))
    }
}

/// UNIX time: Elapsed non-leap seconds since 1970-01-01T00:00:00+00:00 UTC.
///
/// This is a commonly used time format and can therefore also be used as a generic format to
/// convert other CCSDS time formats to and from. The subsecond precision is in nanoseconds
/// similarly to other common time formats and libraries.
#[derive(Default, Debug, Copy, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct UnixTime {
    secs: i64,
    subsec_nanos: u32,
}

impl UnixTime {
    /// The UNIX epoch time: 1970-01-01T00:00:00+00:00 UTC.
    pub const EPOCH: Self = Self {
        secs: 0,
        subsec_nanos: 0,
    };

    /// The minimum possible `UnixTime`.
    pub const MIN: Self = Self {
        secs: i64::MIN,
        subsec_nanos: 0,
    };

    /// The maximum possible `UnixTime`.
    pub const MAX: Self = Self {
        secs: i64::MAX,
        subsec_nanos: NANOS_PER_SECOND - 1,
    };

    /// Returns [None] if the subsecond nanosecond value is invalid (larger than fraction of a
    /// second)
    pub fn new_checked(unix_seconds: i64, subsec_nanos: u32) -> Option<Self> {
        if subsec_nanos >= NANOS_PER_SECOND {
            return None;
        }
        Some(Self::new(unix_seconds, subsec_nanos))
    }

    /// Returns [None] if the subsecond millisecond value is invalid (larger than fraction of a
    /// second)
    pub fn new_subsec_millis_checked(unix_seconds: i64, subsec_millis: u16) -> Option<Self> {
        if subsec_millis >= 1000 {
            return None;
        }
        Self::new_checked(unix_seconds, subsec_millis as u32 * 1_000_000)
    }

    /// This function will panic if the subsecond value is larger than the fraction of a second.
    /// Use [Self::new_checked] if you want to handle this case without a panic.
    pub const fn new(unix_seconds: i64, subsecond_nanos: u32) -> Self {
        if subsecond_nanos >= NANOS_PER_SECOND {
            panic!("invalid subsecond nanos value");
        }
        Self {
            secs: unix_seconds,
            subsec_nanos: subsecond_nanos,
        }
    }

    /// This function will panic if the subsecond value is larger than the fraction of a second.
    /// Use [Self::new_subsec_millis_checked] if you want to handle this case without a panic.
    pub const fn new_subsec_millis(unix_seconds: i64, subsecond_millis: u16) -> Self {
        if subsecond_millis >= 1000 {
            panic!("invalid subsecond millisecond value");
        }
        Self {
            secs: unix_seconds,
            subsec_nanos: subsecond_millis as u32 * 1_000_000,
        }
    }

    pub fn new_only_secs(unix_seconds: i64) -> Self {
        Self {
            secs: unix_seconds,
            subsec_nanos: 0,
        }
    }

    #[inline]
    pub fn subsec_millis(&self) -> u16 {
        (self.subsec_nanos / 1_000_000) as u16
    }

    pub fn subsec_nanos(&self) -> u32 {
        self.subsec_nanos
    }

    #[cfg(feature = "std")]
    pub fn now() -> Result<Self, SystemTimeError> {
        let now = SystemTime::now().duration_since(SystemTime::UNIX_EPOCH)?;
        let epoch = now.as_secs();
        Ok(Self::new(epoch as i64, now.subsec_nanos()))
    }

    #[inline]
    pub fn unix_secs_f64(&self) -> f64 {
        self.secs as f64 + (self.subsec_nanos as f64 / 1_000_000_000.0)
    }

    pub fn as_secs(&self) -> i64 {
        self.secs
    }

    #[cfg(feature = "chrono")]
    pub fn chrono_date_time(&self) -> chrono::LocalResult<chrono::DateTime<chrono::Utc>> {
        Utc.timestamp_opt(self.secs, self.subsec_nanos)
    }

    #[cfg(feature = "timelib")]
    pub fn timelib_date_time(&self) -> Result<time::OffsetDateTime, time::error::ComponentRange> {
        Ok(time::OffsetDateTime::from_unix_timestamp(self.as_secs())?
            + time::Duration::nanoseconds(self.subsec_nanos().into()))
    }

    // Calculate the difference in milliseconds between two UnixTimestamps
    pub fn diff_in_millis(&self, other: &UnixTime) -> Option<i64> {
        let seconds_difference = self.secs.checked_sub(other.secs)?;
        // Convert seconds difference to milliseconds
        let milliseconds_difference = seconds_difference.checked_mul(1000)?;

        // Calculate the difference in subsecond milliseconds directly
        let subsecond_difference_nanos = self.subsec_nanos as i64 - other.subsec_nanos as i64;

        // Combine the differences
        Some(milliseconds_difference + (subsecond_difference_nanos / 1_000_000))
    }
}

#[cfg(feature = "chrono")]
impl From<chrono::DateTime<chrono::Utc>> for UnixTime {
    fn from(value: chrono::DateTime<chrono::Utc>) -> Self {
        Self::new(value.timestamp(), value.timestamp_subsec_nanos())
    }
}

#[cfg(feature = "timelib")]
impl From<time::OffsetDateTime> for UnixTime {
    fn from(value: time::OffsetDateTime) -> Self {
        Self::new(value.unix_timestamp(), value.nanosecond())
    }
}

impl PartialOrd for UnixTime {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for UnixTime {
    fn cmp(&self, other: &Self) -> Ordering {
        if self == other {
            return Ordering::Equal;
        }
        match self.secs.cmp(&other.secs) {
            Ordering::Less => return Ordering::Less,
            Ordering::Greater => return Ordering::Greater,
            _ => (),
        }

        match self.subsec_millis().cmp(&other.subsec_millis()) {
            Ordering::Less => {
                return if self.secs < 0 {
                    Ordering::Greater
                } else {
                    Ordering::Less
                }
            }
            Ordering::Greater => {
                return if self.secs < 0 {
                    Ordering::Less
                } else {
                    Ordering::Greater
                }
            }
            Ordering::Equal => (),
        }
        Ordering::Equal
    }
}

/// Difference between two UNIX timestamps. The [Duration] type can not contain negative durations,
/// so the sign information is supplied separately.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct StampDiff {
    pub positive_duration: bool,
    pub duration_absolute: Duration,
}

impl Sub for UnixTime {
    type Output = Option<StampDiff>;

    fn sub(self, rhs: Self) -> Self::Output {
        let difference = self.diff_in_millis(&rhs)?;
        Some(if difference < 0 {
            StampDiff {
                positive_duration: false,
                duration_absolute: Duration::from_millis(-difference as u64),
            }
        } else {
            StampDiff {
                positive_duration: true,
                duration_absolute: Duration::from_millis(difference as u64),
            }
        })
    }
}

fn get_new_stamp_after_addition(current_stamp: &UnixTime, duration: Duration) -> UnixTime {
    let mut new_subsec_nanos = current_stamp.subsec_nanos() + duration.subsec_nanos();
    let mut new_unix_seconds = current_stamp.secs;
    let mut increment_seconds = |value: u32| {
        if new_unix_seconds < 0 {
            new_unix_seconds = new_unix_seconds
                .checked_sub(value.into())
                .expect("new unix seconds would exceed i64::MIN");
        } else {
            new_unix_seconds = new_unix_seconds
                .checked_add(value.into())
                .expect("new unix seconds would exceed i64::MAX");
        }
    };
    if new_subsec_nanos >= 1_000_000_000 {
        new_subsec_nanos -= 1_000_000_000;
        increment_seconds(1);
    }
    increment_seconds(
        duration
            .as_secs()
            .try_into()
            .expect("duration seconds exceeds u32::MAX"),
    );
    UnixTime::new(new_unix_seconds, new_subsec_nanos)
}

/// Please note that this operation will panic on the following conditions:
///
/// - Unix seconds after subtraction for stamps before the unix epoch exceeds [i64::MIN].
/// - Unix seconds after addition  exceeds [i64::MAX].
/// - Seconds from duration to add exceeds [u32::MAX].
impl AddAssign<Duration> for UnixTime {
    fn add_assign(&mut self, duration: Duration) {
        *self = get_new_stamp_after_addition(self, duration);
    }
}

/// Please note that this operation will panic for the following conditions:
///
/// - Unix seconds after subtraction for stamps before the unix epoch exceeds [i64::MIN].
/// - Unix seconds after addition  exceeds [i64::MAX].
/// - Unix seconds exceeds [u32::MAX].
impl Add<Duration> for UnixTime {
    type Output = Self;

    fn add(self, duration: Duration) -> Self::Output {
        get_new_stamp_after_addition(&self, duration)
    }
}

impl Add<Duration> for &UnixTime {
    type Output = UnixTime;

    fn add(self, duration: Duration) -> Self::Output {
        get_new_stamp_after_addition(self, duration)
    }
}

#[cfg(all(test, feature = "std"))]
mod tests {
    use alloc::string::ToString;
    use chrono::{Datelike, Timelike};
    use std::{format, println};

    use super::{cuc::CucError, *};

    #[allow(dead_code)]
    const UNIX_STAMP_CONST: UnixTime = UnixTime::new(5, 999_999_999);
    #[allow(dead_code)]
    const UNIX_STAMP_CONST_2: UnixTime = UnixTime::new_subsec_millis(5, 999);

    #[test]
    fn test_days_conversion() {
        assert_eq!(unix_to_ccsds_days(DAYS_CCSDS_TO_UNIX.into()), 0);
        assert_eq!(ccsds_to_unix_days(0), DAYS_CCSDS_TO_UNIX.into());
    }

    #[test]
    #[cfg_attr(miri, ignore)]
    fn test_get_current_time() {
        let sec_floats = seconds_since_epoch();
        assert!(sec_floats > 0.0);
    }

    #[test]
    fn test_ms_of_day() {
        let ms = ms_of_day(0.0);
        assert_eq!(ms, 0);
        let ms = ms_of_day(5.0);
        assert_eq!(ms, 5000);
    }

    #[test]
    #[cfg_attr(miri, ignore)]
    fn test_ccsds_epoch() {
        let now = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap();
        let unix_epoch = now.as_secs();
        let ccsds_epoch = unix_epoch_to_ccsds_epoch(now.as_secs() as i64) as u64;
        assert!(ccsds_epoch > unix_epoch);
        assert_eq!((ccsds_epoch - unix_epoch) % SECONDS_PER_DAY as u64, 0);
        let days_diff = (ccsds_epoch - unix_epoch) / SECONDS_PER_DAY as u64;
        assert_eq!(days_diff, -DAYS_CCSDS_TO_UNIX as u64);
    }

    #[test]
    fn basic_unix_stamp_test() {
        let stamp = UnixTime::new_only_secs(-200);
        assert_eq!(stamp.secs, -200);
        assert_eq!(stamp.subsec_millis(), 0);
        let stamp = UnixTime::new_only_secs(250);
        assert_eq!(stamp.secs, 250);
        assert_eq!(stamp.subsec_millis(), 0);
    }

    #[test]
    fn basic_float_unix_stamp_test() {
        let stamp = UnixTime::new_subsec_millis_checked(500, 600).unwrap();
        assert_eq!(stamp.secs, 500);
        let subsec_millis = stamp.subsec_millis();
        assert_eq!(subsec_millis, 600);
        println!("{:?}", (500.6 - stamp.unix_secs_f64()).to_string());
        assert!((500.6 - stamp.unix_secs_f64()).abs() < 0.0001);
    }

    #[test]
    fn test_ord_larger() {
        let stamp0 = UnixTime::new_only_secs(5);
        let stamp1 = UnixTime::new_subsec_millis_checked(5, 500).unwrap();
        let stamp2 = UnixTime::new_only_secs(6);
        assert!(stamp1 > stamp0);
        assert!(stamp2 > stamp0);
        assert!(stamp2 > stamp1);
    }

    #[test]
    fn test_ord_smaller() {
        let stamp0 = UnixTime::new_only_secs(5);
        let stamp1 = UnixTime::new_subsec_millis_checked(5, 500).unwrap();
        let stamp2 = UnixTime::new_only_secs(6);
        assert!(stamp0 < stamp1);
        assert!(stamp0 < stamp2);
        assert!(stamp1 < stamp2);
    }

    #[test]
    fn test_ord_larger_neg_numbers() {
        let stamp0 = UnixTime::new_only_secs(-5);
        let stamp1 = UnixTime::new_subsec_millis_checked(-5, 500).unwrap();
        let stamp2 = UnixTime::new_only_secs(-6);
        assert!(stamp0 > stamp1);
        assert!(stamp0 > stamp2);
        assert!(stamp1 > stamp2);
        assert!(stamp1 >= stamp2);
        assert!(stamp0 >= stamp1);
    }

    #[test]
    fn test_ord_smaller_neg_numbers() {
        let stamp0 = UnixTime::new_only_secs(-5);
        let stamp1 = UnixTime::new_subsec_millis_checked(-5, 500).unwrap();
        let stamp2 = UnixTime::new_only_secs(-6);
        assert!(stamp2 < stamp1);
        assert!(stamp2 < stamp0);
        assert!(stamp1 < stamp0);
        assert!(stamp1 <= stamp0);
        assert!(stamp2 <= stamp1);
    }

    #[allow(clippy::nonminimal_bool)]
    #[test]
    fn test_eq() {
        let stamp0 = UnixTime::new(5, 0);
        let stamp1 = UnixTime::new_only_secs(5);
        assert_eq!(stamp0, stamp1);
        assert!(stamp0 <= stamp1);
        assert!(stamp0 >= stamp1);
        assert!(!(stamp0 < stamp1));
        assert!(!(stamp0 > stamp1));
    }

    #[test]
    fn test_addition() {
        let mut stamp0 = UnixTime::new_only_secs(1);
        stamp0 += Duration::from_secs(5);
        assert_eq!(stamp0.as_secs(), 6);
        assert_eq!(stamp0.subsec_millis(), 0);
        let stamp1 = stamp0 + Duration::from_millis(500);
        assert_eq!(stamp1.secs, 6);
        assert_eq!(stamp1.subsec_millis(), 500);
    }

    #[test]
    fn test_addition_on_ref() {
        let stamp0 = &UnixTime::new_subsec_millis_checked(20, 500).unwrap();
        let stamp1 = stamp0 + Duration::from_millis(2500);
        assert_eq!(stamp1.secs, 23);
        assert_eq!(stamp1.subsec_millis(), 0);
    }

    #[test]
    fn test_as_dt() {
        let stamp = UnixTime::new_only_secs(0);
        let dt = stamp.chrono_date_time().unwrap();
        assert_eq!(dt.year(), 1970);
        assert_eq!(dt.month(), 1);
        assert_eq!(dt.day(), 1);
        assert_eq!(dt.hour(), 0);
        assert_eq!(dt.minute(), 0);
        assert_eq!(dt.second(), 0);
    }

    #[test]
    #[cfg_attr(miri, ignore)]
    fn test_from_now() {
        let stamp_now = UnixTime::now().unwrap();
        let dt_now = stamp_now.chrono_date_time().unwrap();
        assert!(dt_now.year() >= 2020);
    }

    #[test]
    fn test_stamp_diff_positive_0() {
        let stamp_later = UnixTime::new(2, 0);
        let StampDiff {
            positive_duration,
            duration_absolute,
        } = (stamp_later - UnixTime::new(1, 0)).expect("stamp diff error");
        assert!(positive_duration);
        assert_eq!(duration_absolute, Duration::from_secs(1));
    }

    #[test]
    fn test_stamp_diff_positive_1() {
        let stamp_later = UnixTime::new(3, 800 * 1_000_000);
        let stamp_earlier = UnixTime::new_subsec_millis_checked(1, 900).unwrap();
        let StampDiff {
            positive_duration,
            duration_absolute,
        } = (stamp_later - stamp_earlier).expect("stamp diff error");
        assert!(positive_duration);
        assert_eq!(duration_absolute, Duration::from_millis(1900));
    }

    #[test]
    fn test_stamp_diff_negative() {
        let stamp_later = UnixTime::new_subsec_millis_checked(3, 800).unwrap();
        let stamp_earlier = UnixTime::new_subsec_millis_checked(1, 900).unwrap();
        let StampDiff {
            positive_duration,
            duration_absolute,
        } = (stamp_earlier - stamp_later).expect("stamp diff error");
        assert!(!positive_duration);
        assert_eq!(duration_absolute, Duration::from_millis(1900));
    }

    #[test]
    fn test_addition_spillover() {
        let mut stamp0 = UnixTime::new_subsec_millis_checked(1, 900).unwrap();
        stamp0 += Duration::from_millis(100);
        assert_eq!(stamp0.secs, 2);
        assert_eq!(stamp0.subsec_millis(), 0);
        stamp0 += Duration::from_millis(1100);
        assert_eq!(stamp0.secs, 3);
        assert_eq!(stamp0.subsec_millis(), 100);
    }

    #[test]
    fn test_cuc_error_printout() {
        let cuc_error = CucError::InvalidCounterWidth(12);
        let stamp_error = TimestampError::from(cuc_error);
        assert_eq!(stamp_error.to_string(), format!("cuc error: {cuc_error}"));
    }

    #[test]
    #[cfg(feature = "timelib")]
    fn test_unix_stamp_as_timelib_datetime() {
        let stamp_epoch = UnixTime::EPOCH;
        let timelib_dt = stamp_epoch.timelib_date_time().unwrap();
        assert_eq!(timelib_dt.year(), 1970);
        assert_eq!(timelib_dt.month(), time::Month::January);
        assert_eq!(timelib_dt.day(), 1);
        assert_eq!(timelib_dt.hour(), 0);
        assert_eq!(timelib_dt.minute(), 0);
        assert_eq!(timelib_dt.second(), 0);
    }

    #[test]
    #[cfg(feature = "timelib")]
    fn test_unix_stamp_from_timelib_datetime() {
        let timelib_dt = time::OffsetDateTime::UNIX_EPOCH;
        let unix_time = UnixTime::from(timelib_dt);
        let timelib_converted_back = unix_time.timelib_date_time().unwrap();
        assert_eq!(timelib_dt, timelib_converted_back);
    }
}
