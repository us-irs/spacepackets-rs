//! CCSDS Time Code Formats according to [CCSDS 301.0-B-4](https://public.ccsds.org/Pubs/301x0b4e1.pdf)
use crate::{ByteConversionError, SizeMissmatch};
use chrono::{DateTime, LocalResult, TimeZone, Utc};

#[allow(unused_imports)]
#[cfg(not(feature = "std"))]
use num_traits::float::FloatCore;

use crate::time::CcsdsTimeCodes::Cds;
#[cfg(feature = "std")]
use std::time::{SystemTime, SystemTimeError};

pub const CDS_SHORT_LEN: usize = 7;
pub const DAYS_CCSDS_TO_UNIX: i32 = -4383;
pub const SECONDS_PER_DAY: u32 = 86400;

#[derive(Debug, PartialEq, Eq, Copy, Clone)]
pub enum CcsdsTimeCodes {
    None = 0,
    CucCcsdsEpoch = 0b001,
    CucAgencyEpoch = 0b010,
    Cds = 0b100,
    Ccs = 0b101,
}

const CDS_SHORT_P_FIELD: u8 = (CcsdsTimeCodes::Cds as u8) << 4;

impl TryFrom<u8> for CcsdsTimeCodes {
    type Error = ();

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            x if x == CcsdsTimeCodes::None as u8 => Ok(CcsdsTimeCodes::None),
            x if x == CcsdsTimeCodes::CucCcsdsEpoch as u8 => Ok(CcsdsTimeCodes::CucCcsdsEpoch),
            x if x == CcsdsTimeCodes::CucAgencyEpoch as u8 => Ok(CcsdsTimeCodes::CucAgencyEpoch),
            x if x == CcsdsTimeCodes::Cds as u8 => Ok(CcsdsTimeCodes::Cds),
            x if x == CcsdsTimeCodes::Ccs as u8 => Ok(CcsdsTimeCodes::Ccs),
            _ => Err(()),
        }
    }
}

#[derive(Debug, PartialEq, Eq, Copy, Clone)]
pub enum TimestampError {
    /// Contains tuple where first value is the expected time code and the second
    /// value is the found raw value
    InvalidTimeCode(CcsdsTimeCodes, u8),
    OtherPacketError(ByteConversionError),
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
pub const fn unix_to_ccsds_days(unix_days: i32) -> i32 {
    unix_days - DAYS_CCSDS_TO_UNIX
}

/// Convert CCSDS days to UNIX days
///
///  - CCSDS epoch: 1958 January 1
///  - UNIX Epoch: 1970 January 1
pub const fn ccsds_to_unix_days(ccsds_days: i32) -> i32 {
    ccsds_days + DAYS_CCSDS_TO_UNIX
}

pub trait TimeWriter {
    fn write_to_bytes(&self, bytes: &mut [u8]) -> Result<(), TimestampError>;
}

pub trait TimeReader {
    fn from_bytes(buf: &[u8]) -> Result<Self, TimestampError>
    where
        Self: Sized;
}

/// Trait for generic CCSDS time providers
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

/// This object is the abstraction for the CCSDS Day Segmented Time Code (CDS).
///
/// It has the capability to generate and read timestamps as specified in the CCSDS 301.0-B-4
/// section 3.3
///
/// # Example
///
/// ```
/// use spacepackets::time::{CdsShortTimeProvider, TimeWriter};
/// use spacepackets::time::CcsdsTimeCodes::Cds;
/// let timestamp_now = CdsShortTimeProvider::from_now().unwrap();
/// let mut raw_stamp = [0; 7];
/// timestamp_now.write_to_bytes(&mut raw_stamp).unwrap();
/// assert_eq!((raw_stamp[0] >> 4) & 0b111, Cds as u8);
/// ```
#[derive(Debug, Copy, Clone, Default)]
pub struct CdsShortTimeProvider {
    ccsds_days: u16,
    ms_of_day: u32,
    unix_seconds: i64,
    date_time: Option<DateTime<Utc>>,
}

impl CdsShortTimeProvider {
    pub fn new(ccsds_days: u16, ms_of_day: u32) -> Self {
        let provider = Self {
            ccsds_days,
            ms_of_day,
            unix_seconds: 0,
            date_time: None,
        };
        let unix_days_seconds =
            ccsds_to_unix_days(ccsds_days as i32) as i64 * SECONDS_PER_DAY as i64;
        provider.setup(unix_days_seconds as i64, ms_of_day.into())
    }

    #[cfg(feature = "std")]
    #[cfg_attr(doc_cfg, doc(cfg(feature = "std")))]
    pub fn from_now() -> Result<Self, SystemTimeError> {
        let now = SystemTime::now().duration_since(SystemTime::UNIX_EPOCH)?;
        let epoch = now.as_secs();
        let secs_of_day = epoch % SECONDS_PER_DAY as u64;
        let unix_days_seconds = epoch - secs_of_day;
        let ms_of_day = secs_of_day * 1000 + now.subsec_millis() as u64;
        let provider = Self {
            ccsds_days: unix_to_ccsds_days((unix_days_seconds / SECONDS_PER_DAY as u64) as i32)
                as u16,
            ms_of_day: ms_of_day as u32,
            unix_seconds: 0,
            date_time: None,
        };
        Ok(provider.setup(unix_days_seconds as i64, ms_of_day))
    }

    #[cfg(feature = "std")]
    #[cfg_attr(doc_cfg, doc(cfg(feature = "std")))]
    pub fn update_from_now(&mut self) -> Result<(), SystemTimeError> {
        let now = SystemTime::now().duration_since(SystemTime::UNIX_EPOCH)?;
        let epoch = now.as_secs();
        let secs_of_day = epoch % SECONDS_PER_DAY as u64;
        let unix_days_seconds = epoch - secs_of_day;
        let ms_of_day = secs_of_day * 1000 + now.subsec_millis() as u64;
        self.setup(unix_days_seconds as i64, ms_of_day);
        Ok(())
    }

    fn setup(mut self, unix_days_seconds: i64, ms_of_day: u64) -> Self {
        self.calc_unix_seconds(unix_days_seconds, ms_of_day);
        self.calc_date_time((ms_of_day % 1000) as u32);
        self
    }

    #[cfg(feature = "std")]
    #[cfg_attr(doc_cfg, doc(cfg(feature = "std")))]
    pub fn ms_of_day_using_sysclock() -> u32 {
        Self::ms_of_day(seconds_since_epoch())
    }

    pub fn ms_of_day(seconds_since_epoch: f64) -> u32 {
        let fraction_ms = seconds_since_epoch - seconds_since_epoch.floor();
        let ms_of_day: u32 =
            (((seconds_since_epoch.floor() as u32 % SECONDS_PER_DAY) * 1000) as f64 + fraction_ms)
                .floor() as u32;
        ms_of_day
    }

    fn calc_unix_seconds(&mut self, unix_days_seconds: i64, ms_of_day: u64) {
        self.unix_seconds = unix_days_seconds;
        let seconds_of_day = (ms_of_day / 1000) as i64;
        if self.unix_seconds < 0 {
            self.unix_seconds -= seconds_of_day;
        } else {
            self.unix_seconds += seconds_of_day;
        }
    }

    fn calc_date_time(&mut self, ms_since_last_second: u32) {
        assert!(ms_since_last_second < 1000, "Invalid MS since last second");
        let ns_since_last_sec = ms_since_last_second * 1e6 as u32;
        if let LocalResult::Single(val) = Utc.timestamp_opt(self.unix_seconds, ns_since_last_sec) {
            self.date_time = Some(val);
        } else {
            self.date_time = None;
        }
    }
}

impl CcsdsTimeProvider for CdsShortTimeProvider {
    fn len_as_bytes(&self) -> usize {
        CDS_SHORT_LEN
    }

    fn p_field(&self) -> (usize, [u8; 2]) {
        (1, [CDS_SHORT_P_FIELD, 0])
    }

    fn ccdsd_time_code(&self) -> CcsdsTimeCodes {
        Cds
    }

    fn unix_seconds(&self) -> i64 {
        self.unix_seconds
    }

    fn date_time(&self) -> Option<DateTime<Utc>> {
        self.date_time
    }
}

impl TimeWriter for CdsShortTimeProvider {
    fn write_to_bytes(&self, buf: &mut [u8]) -> Result<(), TimestampError> {
        if buf.len() < self.len_as_bytes() {
            return Err(TimestampError::OtherPacketError(
                ByteConversionError::ToSliceTooSmall(SizeMissmatch {
                    expected: self.len_as_bytes(),
                    found: buf.len(),
                }),
            ));
        }
        buf[0] = CDS_SHORT_P_FIELD;
        buf[1..3].copy_from_slice(self.ccsds_days.to_be_bytes().as_slice());
        buf[3..7].copy_from_slice(self.ms_of_day.to_be_bytes().as_slice());
        Ok(())
    }
}

impl TimeReader for CdsShortTimeProvider {
    fn from_bytes(buf: &[u8]) -> Result<Self, TimestampError> {
        if buf.len() < CDS_SHORT_LEN {
            return Err(TimestampError::OtherPacketError(
                ByteConversionError::FromSliceTooSmall(SizeMissmatch {
                    expected: CDS_SHORT_LEN,
                    found: buf.len(),
                }),
            ));
        }
        let pfield = buf[0];
        match CcsdsTimeCodes::try_from(pfield >> 4 & 0b111) {
            Ok(cds_type) => match cds_type {
                Cds => (),
                _ => return Err(TimestampError::InvalidTimeCode(Cds, cds_type as u8)),
            },
            _ => return Err(TimestampError::InvalidTimeCode(Cds, pfield >> 4 & 0b111)),
        };
        let ccsds_days: u16 = u16::from_be_bytes(buf[1..3].try_into().unwrap());
        let ms_of_day: u32 = u32::from_be_bytes(buf[3..7].try_into().unwrap());
        Ok(Self::new(ccsds_days, ms_of_day))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::time::TimestampError::{InvalidTimeCode, OtherPacketError};
    use crate::ByteConversionError::{FromSliceTooSmall, ToSliceTooSmall};
    use alloc::format;
    use chrono::{Datelike, Timelike};

    #[test]
    fn test_creation() {
        assert_eq!(unix_to_ccsds_days(DAYS_CCSDS_TO_UNIX), 0);
        assert_eq!(ccsds_to_unix_days(0), DAYS_CCSDS_TO_UNIX);
    }

    #[cfg(feature = "std")]
    #[test]
    fn test_get_current_time() {
        let sec_floats = seconds_since_epoch();
        assert!(sec_floats > 0.0);
    }

    #[test]
    fn test_time_stamp_zero_args() {
        let time_stamper = CdsShortTimeProvider::new(0, 0);
        assert_eq!(
            time_stamper.unix_seconds(),
            (DAYS_CCSDS_TO_UNIX * SECONDS_PER_DAY as i32) as i64
        );
        assert_eq!(time_stamper.ccdsd_time_code(), Cds);
        assert_eq!(time_stamper.p_field(), (1, [(Cds as u8) << 4, 0]));
        let date_time = time_stamper.date_time().unwrap();
        assert_eq!(date_time.year(), 1958);
        assert_eq!(date_time.month(), 1);
        assert_eq!(date_time.day(), 1);
        assert_eq!(date_time.hour(), 0);
        assert_eq!(date_time.minute(), 0);
        assert_eq!(date_time.second(), 0);
    }

    #[test]
    fn test_time_stamp_unix_epoch() {
        let time_stamper = CdsShortTimeProvider::new((-DAYS_CCSDS_TO_UNIX) as u16, 0);
        assert_eq!(time_stamper.unix_seconds(), 0);
        let date_time = time_stamper.date_time().unwrap();
        assert_eq!(date_time.year(), 1970);
        assert_eq!(date_time.month(), 1);
        assert_eq!(date_time.day(), 1);
        assert_eq!(date_time.hour(), 0);
        assert_eq!(date_time.minute(), 0);
        assert_eq!(date_time.second(), 0);
    }

    #[test]
    fn test_write() {
        let mut buf = [0; 16];
        let time_stamper_0 = CdsShortTimeProvider::new(0, 0);
        let mut res = time_stamper_0.write_to_bytes(&mut buf);
        assert!(res.is_ok());
        assert_eq!(buf[0], (CcsdsTimeCodes::Cds as u8) << 4);
        assert_eq!(
            u16::from_be_bytes(buf[1..3].try_into().expect("Byte conversion failed")),
            0
        );
        assert_eq!(
            u32::from_be_bytes(buf[3..7].try_into().expect("Byte conversion failed")),
            0
        );
        let time_stamper_1 = CdsShortTimeProvider::new(u16::MAX - 1, u32::MAX - 1);
        res = time_stamper_1.write_to_bytes(&mut buf);
        assert!(res.is_ok());
        assert_eq!(buf[0], (CcsdsTimeCodes::Cds as u8) << 4);
        assert_eq!(
            u16::from_be_bytes(buf[1..3].try_into().expect("Byte conversion failed")),
            u16::MAX - 1
        );
        assert_eq!(
            u32::from_be_bytes(buf[3..7].try_into().expect("Byte conversion failed")),
            u32::MAX - 1
        );
    }

    #[test]
    fn test_faulty_write_buf_too_small() {
        let mut buf = [0; 7];
        let time_stamper = CdsShortTimeProvider::new(u16::MAX - 1, u32::MAX - 1);
        for i in 0..6 {
            let res = time_stamper.write_to_bytes(&mut buf[0..i]);
            assert!(res.is_err());
            match res.unwrap_err() {
                OtherPacketError(ToSliceTooSmall(missmatch)) => {
                    assert_eq!(missmatch.found, i);
                    assert_eq!(missmatch.expected, 7);
                }
                _ => panic!(
                    "{}",
                    format!("Invalid error {:?} detected", res.unwrap_err())
                ),
            }
        }
    }

    #[test]
    fn test_faulty_read_buf_too_small() {
        let buf = [0; 7];
        for i in 0..6 {
            let res = CdsShortTimeProvider::from_bytes(&buf[0..i]);
            assert!(res.is_err());
            match res.unwrap_err() {
                InvalidTimeCode(_, _) => {
                    panic!("Unexpected error");
                }
                OtherPacketError(e) => match e {
                    FromSliceTooSmall(missmatch) => {
                        assert_eq!(missmatch.found, i);
                        assert_eq!(missmatch.expected, 7);
                    }
                    _ => panic!("{}", format!("Invalid error {:?} detected", e)),
                },
            }
        }
    }

    #[test]
    fn test_faulty_invalid_pfield() {
        let mut buf = [0; 16];
        let time_stamper_0 = CdsShortTimeProvider::new(0, 0);
        let res = time_stamper_0.write_to_bytes(&mut buf);
        assert!(res.is_ok());
        buf[0] = 0;
        let res = CdsShortTimeProvider::from_bytes(&buf);
        assert!(res.is_err());
        let err = res.unwrap_err();
        match err {
            InvalidTimeCode(code, raw) => {
                assert_eq!(code, Cds);
                assert_eq!(raw, 0);
            }
            OtherPacketError(_) => {}
        }
    }

    #[test]
    fn test_reading() {
        let mut buf = [0; 16];
        let time_stamper = CdsShortTimeProvider::new(u16::MAX - 1, u32::MAX - 1);
        let res = time_stamper.write_to_bytes(&mut buf);
        assert!(res.is_ok());
        assert_eq!(buf[0], (CcsdsTimeCodes::Cds as u8) << 4);
        assert_eq!(
            u16::from_be_bytes(buf[1..3].try_into().expect("Byte conversion failed")),
            u16::MAX - 1
        );
        assert_eq!(
            u32::from_be_bytes(buf[3..7].try_into().expect("Byte conversion failed")),
            u32::MAX - 1
        );

        let read_stamp = CdsShortTimeProvider::from_bytes(&buf).expect("Reading timestamp failed");
        assert_eq!(read_stamp.ccsds_days, u16::MAX - 1);
        assert_eq!(read_stamp.ms_of_day, u32::MAX - 1);
    }

    #[cfg(feature = "std")]
    #[test]
    fn test_time_now() {
        let timestamp_now = CdsShortTimeProvider::from_now().unwrap();
        let compare_stamp = Utc::now();
        let dt = timestamp_now.date_time().unwrap();
        if compare_stamp.year() > dt.year() {
            assert_eq!(compare_stamp.year() - dt.year(), 1);
        } else {
            assert_eq!(dt.year(), compare_stamp.year());
        }
        generic_dt_property_equality_check(dt.month(), compare_stamp.month(), 1, 12);

        assert_eq!(dt.day(), compare_stamp.day());
        if compare_stamp.day() < dt.day() {
            assert!(dt.day() >= 28);
            assert_eq!(compare_stamp.day(), 1);
        } else if compare_stamp.day() > dt.day() {
            assert_eq!(compare_stamp.day() - dt.day(), 1);
        } else {
            assert_eq!(compare_stamp.day(), dt.day());
        }
        generic_dt_property_equality_check(dt.hour(), compare_stamp.hour(), 0, 23);
        generic_dt_property_equality_check(dt.minute(), compare_stamp.minute(), 0, 59);
    }

    #[cfg(feature = "std")]
    fn generic_dt_property_equality_check(first: u32, second: u32, start: u32, end: u32) {
        if second < first {
            assert_eq!(second, start);
            assert_eq!(first, end);
        } else if second > first {
            assert_eq!(second - first, 1);
        } else {
            assert_eq!(first, second);
        }
    }
}
