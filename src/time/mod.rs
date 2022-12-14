//! CCSDS Time Code Formats according to [CCSDS 301.0-B-4](https://public.ccsds.org/Pubs/301x0b4e1.pdf)
use crate::{ByteConversionError, SizeMissmatch};
use chrono::{DateTime, LocalResult, TimeZone, Utc};
use core::fmt::{Display, Formatter};

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
pub enum TimestampError {
    /// Contains tuple where first value is the expected time code and the second
    /// value is the found raw value
    InvalidTimeCode(CcsdsTimeCodes, u8),
    ByteConversionError(ByteConversionError),
    CdsError(cds::CdsError),
    CucError(cuc::CucError),
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
pub const fn unix_epoch_to_ccsds_epoch(unix_epoch: u64) -> u64 {
    (unix_epoch as i64 - (DAYS_CCSDS_TO_UNIX as i64 * SECONDS_PER_DAY as i64)) as u64
}

pub const fn ccsds_epoch_to_unix_epoch(ccsds_epoch: u64) -> u64 {
    (ccsds_epoch as i64 + (DAYS_CCSDS_TO_UNIX as i64 * SECONDS_PER_DAY as i64)) as u64
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
pub trait CcsdsTimeProvider {
    fn len_as_bytes(&self) -> usize;

    /// Returns the pfield of the time provider. The pfield can have one or two bytes depending
    /// on the extension bit (first bit). The time provider should returns a tuple where the first
    /// entry denotes the length of the pfield and the second entry is the value of the pfield
    /// in big endian format.
    fn p_field(&self) -> (usize, [u8; 2]);
    fn ccdsd_time_code(&self) -> CcsdsTimeCodes;
    fn unix_seconds(&self) -> i64;
    fn date_time(&self) -> Option<DateTime<Utc>>;
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
        let ccsds_epoch = unix_epoch_to_ccsds_epoch(now.as_secs());
        assert!(ccsds_epoch > unix_epoch);
        assert_eq!((ccsds_epoch - unix_epoch) % SECONDS_PER_DAY as u64, 0);
        let days_diff = (ccsds_epoch - unix_epoch) / SECONDS_PER_DAY as u64;
        assert_eq!(days_diff, -DAYS_CCSDS_TO_UNIX as u64);
    }
}
