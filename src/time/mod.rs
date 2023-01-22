//! CCSDS Time Code Formats according to [CCSDS 301.0-B-4](https://public.ccsds.org/Pubs/301x0b4e1.pdf)
use crate::{ByteConversionError, SizeMissmatch};
use chrono::{DateTime, LocalResult, TimeZone, Utc};
use core::cmp::Ordering;
use core::fmt::{Display, Formatter};
use core::ops::{Add, AddAssign};
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

pub mod ascii;
pub mod cds;
pub mod cuc;

pub const DAYS_CCSDS_TO_UNIX: i32 = -4383;
pub const SECONDS_PER_DAY: u32 = 86400;
pub const MS_PER_DAY: u32 = SECONDS_PER_DAY * 1000;

#[derive(Debug, PartialEq, Eq, Copy, Clone)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub enum CcsdsTimeCodes {
    CucCcsdsEpoch = 0b001,
    CucAgencyEpoch = 0b010,
    Cds = 0b100,
    Ccs = 0b101,
    AgencyDefined = 0b110,
}

impl TryFrom<u8> for CcsdsTimeCodes {
    type Error = ();

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            x if x == CcsdsTimeCodes::CucCcsdsEpoch as u8 => Ok(CcsdsTimeCodes::CucCcsdsEpoch),
            x if x == CcsdsTimeCodes::CucAgencyEpoch as u8 => Ok(CcsdsTimeCodes::CucAgencyEpoch),
            x if x == CcsdsTimeCodes::Cds as u8 => Ok(CcsdsTimeCodes::Cds),
            x if x == CcsdsTimeCodes::Ccs as u8 => Ok(CcsdsTimeCodes::Ccs),
            x if x == CcsdsTimeCodes::AgencyDefined as u8 => Ok(CcsdsTimeCodes::AgencyDefined),
            _ => Err(()),
        }
    }
}

/// Retrieve the CCSDS time code from the p-field. If no valid time code identifier is found, the
/// value of the raw time code identification field is returned.
pub fn ccsds_time_code_from_p_field(pfield: u8) -> Result<CcsdsTimeCodes, u8> {
    let raw_bits = (pfield >> 4) & 0b111;
    CcsdsTimeCodes::try_from(raw_bits).map_err(|_| raw_bits)
}

#[derive(Debug, PartialEq, Eq, Copy, Clone)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[non_exhaustive]
pub enum TimestampError {
    /// Contains tuple where first value is the expected time code and the second
    /// value is the found raw value
    InvalidTimeCode(CcsdsTimeCodes, u8),
    ByteConversionError(ByteConversionError),
    CdsError(cds::CdsError),
    CucError(cuc::CucError),
    DateBeforeCcsdsEpoch(DateTime<Utc>),
    CustomEpochNotSupported,
}

impl From<cds::CdsError> for TimestampError {
    fn from(e: cds::CdsError) -> Self {
        TimestampError::CdsError(e)
    }
}

impl From<cuc::CucError> for TimestampError {
    fn from(e: cuc::CucError) -> Self {
        TimestampError::CucError(e)
    }
}

#[cfg(feature = "std")]
#[cfg_attr(doc_cfg, doc(cfg(feature = "std")))]
#[derive(Debug, Clone)]
pub enum StdTimestampError {
    SystemTimeError(SystemTimeError),
    TimestampError(TimestampError),
}

#[cfg(feature = "std")]
impl From<TimestampError> for StdTimestampError {
    fn from(v: TimestampError) -> Self {
        Self::TimestampError(v)
    }
}

#[cfg(feature = "std")]
impl From<SystemTimeError> for StdTimestampError {
    fn from(v: SystemTimeError) -> Self {
        Self::SystemTimeError(v)
    }
}

impl Display for TimestampError {
    fn fmt(&self, f: &mut Formatter<'_>) -> core::fmt::Result {
        match self {
            TimestampError::InvalidTimeCode(time_code, raw_val) => {
                write!(
                    f,
                    "invalid raw time code value {} for time code {:?}",
                    raw_val, time_code
                )
            }
            TimestampError::CdsError(e) => {
                write!(f, "cds error {}", e)
            }
            TimestampError::CucError(e) => {
                write!(f, "cuc error {}", e)
            }
            TimestampError::ByteConversionError(e) => {
                write!(f, "byte conversion error {}", e)
            }
            TimestampError::DateBeforeCcsdsEpoch(e) => {
                write!(f, "datetime with date before ccsds epoch: {}", e)
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
            TimestampError::ByteConversionError(e) => Some(e),
            TimestampError::CdsError(e) => Some(e),
            TimestampError::CucError(e) => Some(e),
            _ => None,
        }
    }
}

#[cfg(feature = "std")]
#[cfg_attr(doc_cfg, doc(cfg(feature = "std")))]
pub fn seconds_since_epoch() -> f64 {
    SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .expect("System time generation failed")
        .as_secs_f64()
}

/// Convert UNIX days to CCSDS days
///
///  - CCSDS epoch: 1958 January 1
///  - UNIX Epoch: 1970 January 1
pub const fn unix_to_ccsds_days(unix_days: i64) -> i64 {
    unix_days - DAYS_CCSDS_TO_UNIX as i64
}

/// Convert CCSDS days to UNIX days
///
///  - CCSDS epoch: 1958 January 1
///  - UNIX Epoch: 1970 January 1
pub const fn ccsds_to_unix_days(ccsds_days: i64) -> i64 {
    ccsds_days + DAYS_CCSDS_TO_UNIX as i64
}

/// Similar to [unix_to_ccsds_days] but converts the epoch instead, which is the number of elpased
/// seconds since the CCSDS and UNIX epoch times.
pub const fn unix_epoch_to_ccsds_epoch(unix_epoch: i64) -> i64 {
    unix_epoch - (DAYS_CCSDS_TO_UNIX as i64 * SECONDS_PER_DAY as i64)
}

pub const fn ccsds_epoch_to_unix_epoch(ccsds_epoch: i64) -> i64 {
    ccsds_epoch + (DAYS_CCSDS_TO_UNIX as i64 * SECONDS_PER_DAY as i64)
}

#[cfg(feature = "std")]
#[cfg_attr(doc_cfg, doc(cfg(feature = "std")))]
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
    /// Generic function to convert write a timestamp into a raw buffer.
    /// Returns the number of written bytes on success.
    fn write_to_bytes(&self, bytes: &mut [u8]) -> Result<usize, TimestampError>;
}

pub trait TimeReader {
    fn from_bytes(buf: &[u8]) -> Result<Self, TimestampError>
    where
        Self: Sized;
}

/// Trait for generic CCSDS time providers.
///
/// The UNIX helper methods and the [Self::date_time] method are not strictly necessary but extremely
/// practical because they are a very common and simple exchange format for time information.
pub trait CcsdsTimeProvider {
    fn len_as_bytes(&self) -> usize;

    /// Returns the pfield of the time provider. The pfield can have one or two bytes depending
    /// on the extension bit (first bit). The time provider should returns a tuple where the first
    /// entry denotes the length of the pfield and the second entry is the value of the pfield
    /// in big endian format.
    fn p_field(&self) -> (usize, [u8; 2]);
    fn ccdsd_time_code(&self) -> CcsdsTimeCodes;

    fn unix_seconds(&self) -> i64;
    fn subsecond_millis(&self) -> Option<u16>;
    fn unix_stamp(&self) -> UnixTimestamp {
        UnixTimestamp {
            unix_seconds: self.unix_seconds(),
            subsecond_millis: self.subsecond_millis(),
        }
    }

    fn date_time(&self) -> Option<DateTime<Utc>>;
}

/// UNIX timestamp: Elapsed seconds since 01-01-1970 00:00:00.
///
/// Also can optionally include subsecond millisecond for greater accuracy. Please note that a
/// subsecond millisecond value of 0 gets converted to [None].
#[derive(Default, Debug, Copy, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct UnixTimestamp {
    pub unix_seconds: i64,
    subsecond_millis: Option<u16>,
}

impl UnixTimestamp {
    /// Returns none if the subsecond millisecond value is larger than 999. 0 is converted to
    /// a [None] value.
    pub fn new(unix_seconds: i64, subsec_millis: u16) -> Option<Self> {
        if subsec_millis > 999 {
            return None;
        }
        Some(Self::const_new(unix_seconds, subsec_millis))
    }

    /// Like [Self::new] but const. Panics if the subsecond value is larger than 999.
    pub const fn const_new(unix_seconds: i64, subsec_millis: u16) -> Self {
        if subsec_millis > 999 {
            panic!("subsec milliseconds exceeds 999");
        }
        let subsecond_millis = if subsec_millis == 0 {
            None
        } else {
            Some(subsec_millis)
        };
        Self {
            unix_seconds,
            subsecond_millis,
        }
    }

    pub fn new_only_seconds(unix_seconds: i64) -> Self {
        Self {
            unix_seconds,
            subsecond_millis: None,
        }
    }

    pub fn subsecond_millis(&self) -> Option<u16> {
        self.subsecond_millis
    }

    #[cfg(feature = "std")]
    #[cfg_attr(doc_cfg, doc(cfg(feature = "std")))]
    pub fn from_now() -> Result<Self, SystemTimeError> {
        let now = SystemTime::now().duration_since(SystemTime::UNIX_EPOCH)?;
        let epoch = now.as_secs();
        Ok(UnixTimestamp {
            unix_seconds: epoch as i64,
            subsecond_millis: Some(now.subsec_millis() as u16),
        })
    }

    #[inline]
    pub fn unix_seconds_f64(&self) -> f64 {
        let mut secs = self.unix_seconds as f64;
        if let Some(subsec_millis) = self.subsecond_millis {
            secs += subsec_millis as f64 / 1000.0;
        }
        secs
    }

    pub fn as_date_time(&self) -> LocalResult<DateTime<Utc>> {
        Utc.timestamp_opt(
            self.unix_seconds,
            self.subsecond_millis.unwrap_or(0) as u32 * 10_u32.pow(6),
        )
    }
}

impl From<DateTime<Utc>> for UnixTimestamp {
    fn from(value: DateTime<Utc>) -> Self {
        Self {
            unix_seconds: value.timestamp(),
            subsecond_millis: Some(value.timestamp_subsec_millis() as u16),
        }
    }
}

impl PartialOrd for UnixTimestamp {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        if self == other {
            return Some(Ordering::Equal);
        }
        match self.unix_seconds.cmp(&other.unix_seconds) {
            Ordering::Less => return Some(Ordering::Less),
            Ordering::Greater => return Some(Ordering::Greater),
            _ => (),
        }

        match self
            .subsecond_millis()
            .unwrap_or(0)
            .cmp(&other.subsecond_millis().unwrap_or(0))
        {
            Ordering::Less => {
                return if self.unix_seconds < 0 {
                    Some(Ordering::Greater)
                } else {
                    Some(Ordering::Less)
                }
            }
            Ordering::Greater => {
                return if self.unix_seconds < 0 {
                    Some(Ordering::Less)
                } else {
                    Some(Ordering::Greater)
                }
            }
            Ordering::Equal => (),
        }
        Some(Ordering::Equal)
    }
}

impl Ord for UnixTimestamp {
    fn cmp(&self, other: &Self) -> Ordering {
        PartialOrd::partial_cmp(self, other).unwrap()
    }
}

fn get_new_stamp_after_addition(
    current_stamp: &UnixTimestamp,
    duration: Duration,
) -> UnixTimestamp {
    let mut new_subsec_millis =
        current_stamp.subsecond_millis().unwrap_or(0) + duration.subsec_millis() as u16;
    let mut new_unix_seconds = current_stamp.unix_seconds;
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
    if new_subsec_millis >= 1000 {
        new_subsec_millis -= 1000;
        increment_seconds(1);
    }
    increment_seconds(duration.as_secs().try_into().expect("duration seconds exceeds u32::MAX"));
    UnixTimestamp::const_new(new_unix_seconds, new_subsec_millis)
}

/// Please note that this operation will panic on the following conditions:
///
/// - Unix seconds after subtraction for stamps before the unix epoch exceeds [i64::MIN].
/// - Unix seconds after addition  exceeds [i64::MAX].
/// - Seconds from duration to add exceeds [u32::MAX].
impl AddAssign<Duration> for UnixTimestamp {
    fn add_assign(&mut self, duration: Duration) {
        *self = get_new_stamp_after_addition(self, duration);
    }
}

/// Please note that this operation will panic for the following conditions:
///
/// - Unix seconds after subtraction for stamps before the unix epoch exceeds [i64::MIN].
/// - Unix seconds after addition  exceeds [i64::MAX].
/// - Unix seconds exceeds [u32::MAX].
impl Add<Duration> for UnixTimestamp {
    type Output = Self;

    fn add(self, duration: Duration) -> Self::Output {
        get_new_stamp_after_addition(&self, duration)
    }
}

impl Add<Duration> for &UnixTimestamp {
    type Output = UnixTimestamp;

    fn add(self, duration: Duration) -> Self::Output {
        get_new_stamp_after_addition(self, duration)
    }
}

#[cfg(all(test, feature = "std"))]
mod tests {
    use super::*;

    #[test]
    fn test_days_conversion() {
        assert_eq!(unix_to_ccsds_days(DAYS_CCSDS_TO_UNIX.into()), 0);
        assert_eq!(ccsds_to_unix_days(0), DAYS_CCSDS_TO_UNIX.into());
    }

    #[test]
    fn test_get_current_time() {
        let sec_floats = seconds_since_epoch();
        assert!(sec_floats > 0.0);
    }

    #[test]
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
        let stamp = UnixTimestamp::new_only_seconds(-200);
        assert_eq!(stamp.unix_seconds, -200);
        assert!(stamp.subsecond_millis().is_none());
        let stamp = UnixTimestamp::new_only_seconds(250);
        assert_eq!(stamp.unix_seconds, 250);
        assert!(stamp.subsecond_millis().is_none());
    }

    #[test]
    fn basic_float_unix_stamp_test() {
        let stamp = UnixTimestamp::new(500, 600).unwrap();
        assert!(stamp.subsecond_millis.is_some());
        assert_eq!(stamp.unix_seconds, 500);
        let subsec_millis = stamp.subsecond_millis().unwrap();
        assert_eq!(subsec_millis, 600);
        assert!((500.6 - stamp.unix_seconds_f64()).abs() < 0.0001);
    }

    #[test]
    fn test_ord_larger() {
        let stamp0 = UnixTimestamp::new_only_seconds(5);
        let stamp1 = UnixTimestamp::new(5, 500).unwrap();
        let stamp2 = UnixTimestamp::new_only_seconds(6);
        assert!(stamp1 > stamp0);
        assert!(stamp2 > stamp0);
        assert!(stamp2 > stamp1);
    }

    #[test]
    fn test_ord_smaller() {
        let stamp0 = UnixTimestamp::new_only_seconds(5);
        let stamp1 = UnixTimestamp::new(5, 500).unwrap();
        let stamp2 = UnixTimestamp::new_only_seconds(6);
        assert!(stamp0 < stamp1);
        assert!(stamp0 < stamp2);
        assert!(stamp1 < stamp2);
    }

    #[test]
    fn test_ord_larger_neg_numbers() {
        let stamp0 = UnixTimestamp::new_only_seconds(-5);
        let stamp1 = UnixTimestamp::new(-5, 500).unwrap();
        let stamp2 = UnixTimestamp::new_only_seconds(-6);
        assert!(stamp0 > stamp1);
        assert!(stamp0 > stamp2);
        assert!(stamp1 > stamp2);
        assert!(stamp1 >= stamp2);
        assert!(stamp0 >= stamp1);
    }

    #[test]
    fn test_ord_smaller_neg_numbers() {
        let stamp0 = UnixTimestamp::new_only_seconds(-5);
        let stamp1 = UnixTimestamp::new(-5, 500).unwrap();
        let stamp2 = UnixTimestamp::new_only_seconds(-6);
        assert!(stamp2 < stamp1);
        assert!(stamp2 < stamp0);
        assert!(stamp1 < stamp0);
        assert!(stamp1 <= stamp0);
        assert!(stamp2 <= stamp1);
    }

    #[test]
    fn test_eq() {
        let stamp0 = UnixTimestamp::new(5, 0).unwrap();
        let stamp1 = UnixTimestamp::new_only_seconds(5);
        assert_eq!(stamp0, stamp1);
        assert!(stamp0 <= stamp1);
        assert!(stamp0 >= stamp1);
        assert!(!(stamp0 < stamp1));
        assert!(!(stamp0 > stamp1));
    }

    #[test]
    fn test_addition() {
        let mut stamp0 = UnixTimestamp::new_only_seconds(1);
        stamp0 += Duration::from_secs(5);
        assert_eq!(stamp0.unix_seconds, 6);
        assert!(stamp0.subsecond_millis().is_none());
        let stamp1 = stamp0 + Duration::from_millis(500);
        assert_eq!(stamp1.unix_seconds, 6);
        assert!(stamp1.subsecond_millis().is_some());
        assert_eq!(stamp1.subsecond_millis().unwrap(), 500);
    }

    #[test]
    fn test_addition_spillover() {
        let mut stamp0 = UnixTimestamp::new(1, 900).unwrap();
        stamp0 += Duration::from_millis(100);
        assert_eq!(stamp0.unix_seconds, 2);
        assert!(stamp0.subsecond_millis().is_none());
        stamp0 += Duration::from_millis(1100);
        assert_eq!(stamp0.unix_seconds, 3);
        assert_eq!(stamp0.subsecond_millis().unwrap(), 100);
    }
}
