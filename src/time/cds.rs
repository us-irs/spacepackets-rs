//! Module to generate or read CCSDS Day Segmented (CDS) timestamps as specified in
//! [CCSDS 301.0-B-4](https://public.ccsds.org/Pubs/301x0b4e1.pdf) section 3.3 .
//!
//! The core data structure to do this is the [cds::TimeProvider] struct.
use super::*;
use crate::private::Sealed;
use core::fmt::Debug;

/// Base value for the preamble field for a time field parser to determine the time field type.
pub const P_FIELD_BASE: u8 = (CcsdsTimeCodes::Cds as u8) << 4;
pub const MIN_CDS_FIELD_LEN: usize = 7;

/// Generic trait implemented by token structs to specify the length of day field at type
/// level. This trait is only meant to be implemented in this crate and therefore sealed.
pub trait ProvidesDaysLength: Sealed {
    type FieldType: Copy + Clone + TryFrom<i32>;
}

/// Type level token to be used as a generic parameter to [TimeProvider].
#[derive(Debug, PartialEq, Eq, Default)]
pub struct DaysLen16Bits {}

impl Sealed for DaysLen16Bits {}
impl ProvidesDaysLength for DaysLen16Bits {
    type FieldType = u16;
}

/// Type level token to be used as a generic parameter to [TimeProvider].
#[derive(Debug, PartialEq, Eq, Default)]
pub struct DaysLen24Bits {}
impl Sealed for DaysLen24Bits {}
impl ProvidesDaysLength for DaysLen24Bits {
    type FieldType = u32;
}

#[derive(Debug, PartialEq, Eq, Copy, Clone)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub enum LengthOfDaySegment {
    Short16Bits = 0,
    Long24Bits = 1,
}

#[derive(Debug, Copy, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub enum SubmillisPrecision {
    Absent,
    Microseconds(u16),
    Picoseconds(u32),
    Reserved,
}

#[derive(Debug, PartialEq, Eq, Copy, Clone)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub enum CdsError {
    /// CCSDS days value exceeds maximum allowed size or is negative
    InvalidCcsdsDays(i64),
    /// There are distinct constructors depending on the days field width detected in the preamble
    /// field. This error will be returned if there is a missmatch.
    InvalidCtorForDaysOfLenInPreamble(LengthOfDaySegment),
}

impl Display for CdsError {
    fn fmt(&self, f: &mut Formatter<'_>) -> core::fmt::Result {
        match self {
            CdsError::InvalidCcsdsDays(days) => {
                write!(f, "invalid ccsds days {}", days)
            }
            CdsError::InvalidCtorForDaysOfLenInPreamble(length_of_day) => {
                write!(
                    f,
                    "wrong constructor for length of day {:?} detected in preamble",
                    length_of_day
                )
            }
        }
    }
}

#[cfg(feature = "std")]
impl Error for CdsError {}
pub fn length_of_day_segment_from_pfield(pfield: u8) -> LengthOfDaySegment {
    if (pfield >> 2) & 0b1 == 1 {
        return LengthOfDaySegment::Long24Bits;
    }
    LengthOfDaySegment::Short16Bits
}
pub fn precision_from_pfield(pfield: u8) -> SubmillisPrecision {
    match pfield & 0b11 {
        0b01 => SubmillisPrecision::Microseconds(0),
        0b10 => SubmillisPrecision::Picoseconds(0),
        0b00 => SubmillisPrecision::Absent,
        0b11 => SubmillisPrecision::Reserved,
        _ => panic!("pfield to SubmillisPrecision failed"),
    }
}

/// This object is the abstraction for the CCSDS Day Segmented Time Code (CDS).
///
/// It has the capability to generate and read timestamps as specified in the CCSDS 301.0-B-4
/// section 3.3 . The width of the days field is configured at compile time via the generic
/// [ProvidesDaysLength] trait which is implemented by [DaysLen16Bits] and [DaysLen24Bits].
///
/// Custom epochs are not supported yet.
/// Furthermore, the preamble field (p-field) is explicitly conveyed.
/// That means it will always be present when writing the time stamp to a raw buffer, and it
/// must be present when reading a CDS timestamp from a raw buffer.
///
/// # Example
///
/// ```
/// use spacepackets::time::cds::{TimeProvider, DaysLen16Bits};
/// use spacepackets::time::{TimeWriter, CcsdsTimeCodes, TimeReader, CcsdsTimeProvider};
///
/// let timestamp_now = TimeProvider::from_now_with_u16_days().unwrap();
/// let mut raw_stamp = [0; 7];
/// {
///     let written = timestamp_now.write_to_bytes(&mut raw_stamp).unwrap();
///     assert_eq!((raw_stamp[0] >> 4) & 0b111, CcsdsTimeCodes::Cds as u8);
///     assert_eq!(written, 7);
/// }
/// {
///     let read_result = TimeProvider::<DaysLen16Bits>::from_bytes(&raw_stamp);
///     assert!(read_result.is_ok());
///     let stamp_deserialized = read_result.unwrap();
///     assert_eq!(stamp_deserialized.len_as_bytes(), 7);
/// }
/// ```
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct TimeProvider<DaysLen: ProvidesDaysLength = DaysLen16Bits> {
    pfield: u8,
    ccsds_days: DaysLen::FieldType,
    ms_of_day: u32,
    submillis_precision: Option<SubmillisPrecision>,
    unix_seconds: i64,
}

#[cfg(feature = "std")]
struct ConversionFromNow {
    ccsds_days: i32,
    ms_of_day: u64,
    unix_days_seconds: u64,
    submillis_prec: Option<SubmillisPrecision>,
}

#[cfg(feature = "std")]
impl ConversionFromNow {
    fn new() -> Result<Self, SystemTimeError> {
        Self::new_generic(None)
    }

    fn new_with_submillis_us_prec() -> Result<Self, SystemTimeError> {
        Self::new_generic(Some(SubmillisPrecision::Microseconds(0)))
    }

    fn new_with_submillis_ps_prec() -> Result<Self, SystemTimeError> {
        Self::new_generic(Some(SubmillisPrecision::Picoseconds(0)))
    }

    fn new_generic(mut prec: Option<SubmillisPrecision>) -> Result<Self, SystemTimeError> {
        let now = SystemTime::now().duration_since(SystemTime::UNIX_EPOCH)?;
        let epoch = now.as_secs();
        let secs_of_day = epoch % SECONDS_PER_DAY as u64;
        let unix_days_seconds = epoch - secs_of_day;
        if let Some(submilli_prec) = prec {
            match submilli_prec {
                SubmillisPrecision::Microseconds(_) => {
                    prec = Some(SubmillisPrecision::Microseconds(
                        (now.subsec_micros() % 1000) as u16,
                    ));
                }
                SubmillisPrecision::Picoseconds(_) => {
                    prec = Some(SubmillisPrecision::Picoseconds(now.subsec_nanos() * 1000));
                }
                _ => (),
            }
        }
        Ok(Self {
            ms_of_day: secs_of_day * 1000 + now.subsec_millis() as u64,
            ccsds_days: unix_to_ccsds_days((unix_days_seconds / SECONDS_PER_DAY as u64) as i64)
                as i32,
            unix_days_seconds,
            submillis_prec: prec,
        })
    }
}

impl<ProvidesDaysLen: ProvidesDaysLength> TimeProvider<ProvidesDaysLen> {
    pub fn set_submillis_precision(&mut self, prec: SubmillisPrecision) {
        self.pfield &= !(0b11);
        if let SubmillisPrecision::Absent = prec {
            self.submillis_precision = None;
            return;
        }
        self.submillis_precision = Some(prec);
        match prec {
            SubmillisPrecision::Microseconds(_) => {
                self.pfield |= 0b01;
            }
            SubmillisPrecision::Picoseconds(_) => {
                self.pfield |= 0b10;
            }
            _ => (),
        }
    }

    pub fn clear_submillis_precision(&mut self) {
        self.pfield &= !(0b11);
        self.submillis_precision = None;
    }

    pub fn ccsds_days(&self) -> ProvidesDaysLen::FieldType {
        self.ccsds_days
    }

    pub fn submillis_precision(&self) -> Option<SubmillisPrecision> {
        self.submillis_precision
    }

    pub fn ms_of_day(&self) -> u32 {
        self.ms_of_day
    }

    fn generic_raw_read_checks(
        buf: &[u8],
        days_len: LengthOfDaySegment,
    ) -> Result<SubmillisPrecision, TimestampError> {
        if buf.len() < MIN_CDS_FIELD_LEN {
            return Err(TimestampError::ByteConversionError(
                ByteConversionError::FromSliceTooSmall(SizeMissmatch {
                    expected: MIN_CDS_FIELD_LEN,
                    found: buf.len(),
                }),
            ));
        }
        let pfield = buf[0];
        match CcsdsTimeCodes::try_from(pfield >> 4 & 0b111) {
            Ok(cds_type) => match cds_type {
                CcsdsTimeCodes::Cds => (),
                _ => {
                    return Err(TimestampError::InvalidTimeCode(
                        CcsdsTimeCodes::Cds,
                        cds_type as u8,
                    ))
                }
            },
            _ => {
                return Err(TimestampError::InvalidTimeCode(
                    CcsdsTimeCodes::Cds,
                    pfield >> 4 & 0b111,
                ))
            }
        };
        if ((pfield >> 3) & 0b1) == 1 {
            return Err(TimestampError::CustomEpochNotSupported);
        }
        let days_len_from_pfield = length_of_day_segment_from_pfield(pfield);
        if days_len_from_pfield != days_len {
            return Err(CdsError::InvalidCtorForDaysOfLenInPreamble(days_len_from_pfield).into());
        }
        let stamp_len = Self::calc_stamp_len(pfield);
        if buf.len() < stamp_len {
            return Err(TimestampError::ByteConversionError(
                ByteConversionError::FromSliceTooSmall(SizeMissmatch {
                    expected: stamp_len,
                    found: buf.len(),
                }),
            ));
        }
        Ok(precision_from_pfield(pfield))
    }

    fn calc_stamp_len(pfield: u8) -> usize {
        let mut init_len = 7;
        if length_of_day_segment_from_pfield(pfield) == LengthOfDaySegment::Long24Bits {
            init_len += 1
        }
        match pfield & 0b11 {
            0b01 => {
                init_len += 2;
            }
            0b10 => {
                init_len += 4;
            }
            _ => (),
        }
        init_len
    }

    fn setup(&mut self, unix_days_seconds: i64, ms_of_day: u64) {
        self.calc_unix_seconds(unix_days_seconds, ms_of_day);
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

    fn calc_date_time(&self, ms_since_last_second: u32) -> Option<DateTime<Utc>> {
        assert!(ms_since_last_second < 1000, "Invalid MS since last second");
        let ns_since_last_sec = ms_since_last_second * 1e6 as u32;
        if let LocalResult::Single(val) = Utc.timestamp_opt(self.unix_seconds, ns_since_last_sec) {
            return Some(val);
        }
        None
    }

    fn length_check(&self, buf: &[u8], len_as_bytes: usize) -> Result<(), TimestampError> {
        if buf.len() < len_as_bytes {
            return Err(TimestampError::ByteConversionError(
                ByteConversionError::ToSliceTooSmall(SizeMissmatch {
                    expected: len_as_bytes,
                    found: buf.len(),
                }),
            ));
        }
        Ok(())
    }

    fn generic_new(
        days_len: LengthOfDaySegment,
        ccsds_days: ProvidesDaysLen::FieldType,
        ms_of_day: u32,
    ) -> Result<Self, CdsError>
    where
        i64: From<ProvidesDaysLen::FieldType>,
    {
        let mut provider = Self {
            pfield: Self::generate_p_field(days_len, None),
            ccsds_days,
            ms_of_day,
            unix_seconds: 0,
            submillis_precision: None,
        };
        let unix_days_seconds = ccsds_to_unix_days(ccsds_days.into()) * SECONDS_PER_DAY as i64;
        provider.setup(unix_days_seconds, ms_of_day.into());
        Ok(provider)
    }

    #[cfg(feature = "std")]
    fn generic_from_now(
        days_len: LengthOfDaySegment,
        conversion_from_now: ConversionFromNow,
    ) -> Result<Self, StdTimestampError>
    where
        <ProvidesDaysLen::FieldType as TryFrom<i32>>::Error: Debug,
    {
        let ccsds_days: ProvidesDaysLen::FieldType =
            conversion_from_now.ccsds_days.try_into().map_err(|_| {
                StdTimestampError::TimestampError(
                    CdsError::InvalidCcsdsDays(conversion_from_now.ccsds_days.into()).into(),
                )
            })?;
        let mut provider = Self {
            pfield: Self::generate_p_field(days_len, conversion_from_now.submillis_prec),
            ccsds_days,
            ms_of_day: conversion_from_now.ms_of_day as u32,
            unix_seconds: 0,
            submillis_precision: conversion_from_now.submillis_prec,
        };
        provider.setup(
            conversion_from_now.unix_days_seconds as i64,
            conversion_from_now.ms_of_day,
        );
        Ok(provider)
    }

    #[cfg(feature = "std")]
    fn generic_conversion_from_now(&self) -> Result<ConversionFromNow, SystemTimeError> {
        Ok(match self.submillis_precision {
            None => ConversionFromNow::new()?,
            Some(prec) => match prec {
                SubmillisPrecision::Microseconds(_) => {
                    ConversionFromNow::new_with_submillis_us_prec()?
                }
                SubmillisPrecision::Picoseconds(_) => {
                    ConversionFromNow::new_with_submillis_ps_prec()?
                }
                _ => ConversionFromNow::new()?,
            },
        })
    }

    fn generate_p_field(
        day_seg_len: LengthOfDaySegment,
        submillis_prec: Option<SubmillisPrecision>,
    ) -> u8 {
        let mut pfield = P_FIELD_BASE | ((day_seg_len as u8) << 2);
        if let Some(submillis_prec) = submillis_prec {
            match submillis_prec {
                SubmillisPrecision::Microseconds(_) => pfield |= 0b01,
                SubmillisPrecision::Picoseconds(_) => pfield |= 0b10,
                SubmillisPrecision::Reserved => pfield |= 0b11,
                _ => (),
            }
        }
        pfield
    }

    #[cfg(feature = "std")]
    #[cfg_attr(doc_cfg, doc(cfg(feature = "std")))]
    pub fn update_from_now(&mut self) -> Result<(), StdTimestampError>
    where
        <ProvidesDaysLen::FieldType as TryFrom<i32>>::Error: Debug,
    {
        let conversion_from_now = self.generic_conversion_from_now()?;
        let ccsds_days: ProvidesDaysLen::FieldType =
            conversion_from_now.ccsds_days.try_into().map_err(|_| {
                StdTimestampError::TimestampError(
                    CdsError::InvalidCcsdsDays(conversion_from_now.ccsds_days as i64).into(),
                )
            })?;
        self.ccsds_days = ccsds_days;
        self.ms_of_day = conversion_from_now.ms_of_day as u32;
        self.setup(
            conversion_from_now.unix_days_seconds as i64,
            conversion_from_now.ms_of_day,
        );
        Ok(())
    }
}

impl TimeProvider<DaysLen24Bits> {
    /// Generate a new timestamp provider with the days field width set to 24 bits
    pub fn new_with_u24_days(ccsds_days: u32, ms_of_day: u32) -> Result<Self, CdsError> {
        if ccsds_days > 2_u32.pow(24) {
            return Err(CdsError::InvalidCcsdsDays(ccsds_days.into()));
        }
        Self::generic_new(LengthOfDaySegment::Long24Bits, ccsds_days, ms_of_day)
    }

    /// Generate a time stamp from the current time using the system clock.
    #[cfg(feature = "std")]
    #[cfg_attr(doc_cfg, doc(cfg(feature = "std")))]
    pub fn from_now_with_u24_days() -> Result<Self, StdTimestampError> {
        let conversion_from_now = ConversionFromNow::new()?;
        Self::generic_from_now(LengthOfDaySegment::Long24Bits, conversion_from_now)
    }

    /// Like [Self::from_now_with_u24_days] but with microsecond sub-millisecond precision.
    #[cfg(feature = "std")]
    #[cfg_attr(doc_cfg, doc(cfg(feature = "std")))]
    pub fn from_now_with_u24_days_and_us_prec() -> Result<Self, StdTimestampError> {
        let conversion_from_now = ConversionFromNow::new_with_submillis_us_prec()?;
        Self::generic_from_now(LengthOfDaySegment::Long24Bits, conversion_from_now)
    }

    /// Like [Self::from_now_with_u24_days] but with picoseconds sub-millisecond precision.
    #[cfg(feature = "std")]
    #[cfg_attr(doc_cfg, doc(cfg(feature = "std")))]
    pub fn from_now_with_u24_days_ps_submillis_prec() -> Result<Self, StdTimestampError> {
        let conversion_from_now = ConversionFromNow::new_with_submillis_ps_prec()?;
        Self::generic_from_now(LengthOfDaySegment::Long24Bits, conversion_from_now)
    }

    fn from_bytes_24_bit_days(buf: &[u8]) -> Result<Self, TimestampError> {
        let submillis_precision =
            Self::generic_raw_read_checks(buf, LengthOfDaySegment::Long24Bits)?;
        let mut temp_buf: [u8; 4] = [0; 4];
        temp_buf[1..4].copy_from_slice(&buf[1..4]);
        let cccsds_days: u32 = u32::from_be_bytes(temp_buf);
        let ms_of_day: u32 = u32::from_be_bytes(buf[4..8].try_into().unwrap());
        let mut provider = Self::new_with_u24_days(cccsds_days, ms_of_day)?;
        match submillis_precision {
            SubmillisPrecision::Microseconds(_) => {
                provider.set_submillis_precision(SubmillisPrecision::Microseconds(
                    u16::from_be_bytes(buf[8..10].try_into().unwrap()),
                ))
            }
            SubmillisPrecision::Picoseconds(_) => provider.set_submillis_precision(
                SubmillisPrecision::Picoseconds(u32::from_be_bytes(buf[8..12].try_into().unwrap())),
            ),
            _ => (),
        }
        Ok(provider)
    }
}

impl TimeProvider<DaysLen16Bits> {
    /// Generate a new timestamp provider with the days field width set to 16 bits
    pub fn new_with_u16_days(ccsds_days: u16, ms_of_day: u32) -> Self {
        // This should never fail, type system ensures CCSDS can not be negative or too large
        Self::generic_new(LengthOfDaySegment::Short16Bits, ccsds_days, ms_of_day).unwrap()
    }

    /// Generate a time stamp from the current time using the system clock.
    #[cfg(feature = "std")]
    #[cfg_attr(doc_cfg, doc(cfg(feature = "std")))]
    pub fn from_now_with_u16_days() -> Result<Self, StdTimestampError> {
        let conversion_from_now = ConversionFromNow::new()?;
        Self::generic_from_now(LengthOfDaySegment::Short16Bits, conversion_from_now)
    }

    /// Like [Self::from_now_with_u16_days] but with microsecond sub-millisecond precision.
    #[cfg(feature = "std")]
    #[cfg_attr(doc_cfg, doc(cfg(feature = "std")))]
    pub fn from_now_with_u16_days_and_us_prec() -> Result<Self, StdTimestampError> {
        let conversion_from_now = ConversionFromNow::new_with_submillis_us_prec()?;
        Self::generic_from_now(LengthOfDaySegment::Short16Bits, conversion_from_now)
    }

    /// Like [Self::from_now_with_u16_days] but with picosecond sub-millisecond precision.
    #[cfg(feature = "std")]
    #[cfg_attr(doc_cfg, doc(cfg(feature = "std")))]
    pub fn from_now_with_u16_days_and_ps_prec() -> Result<Self, StdTimestampError> {
        let conversion_from_now = ConversionFromNow::new_with_submillis_ps_prec()?;
        Self::generic_from_now(LengthOfDaySegment::Short16Bits, conversion_from_now)
    }

    fn from_bytes_16_bit_days(buf: &[u8]) -> Result<Self, TimestampError> {
        let submillis_precision =
            Self::generic_raw_read_checks(buf, LengthOfDaySegment::Short16Bits)?;
        let ccsds_days: u16 = u16::from_be_bytes(buf[1..3].try_into().unwrap());
        let ms_of_day: u32 = u32::from_be_bytes(buf[3..7].try_into().unwrap());
        let mut provider = Self::new_with_u16_days(ccsds_days, ms_of_day);
        provider.pfield = buf[0];
        match submillis_precision {
            SubmillisPrecision::Microseconds(_) => provider.set_submillis_precision(
                SubmillisPrecision::Microseconds(u16::from_be_bytes(buf[7..9].try_into().unwrap())),
            ),
            SubmillisPrecision::Picoseconds(_) => provider.set_submillis_precision(
                SubmillisPrecision::Picoseconds(u32::from_be_bytes(buf[7..11].try_into().unwrap())),
            ),
            _ => (),
        }
        Ok(provider)
    }
}

impl<ProvidesDaysLen: ProvidesDaysLength> CcsdsTimeProvider for TimeProvider<ProvidesDaysLen> {
    fn len_as_bytes(&self) -> usize {
        Self::calc_stamp_len(self.pfield)
    }

    fn p_field(&self) -> (usize, [u8; 2]) {
        (1, [self.pfield, 0])
    }

    fn ccdsd_time_code(&self) -> CcsdsTimeCodes {
        CcsdsTimeCodes::Cds
    }

    fn unix_seconds(&self) -> i64 {
        self.unix_seconds
    }

    fn date_time(&self) -> Option<DateTime<Utc>> {
        self.calc_date_time(self.ms_of_day % 1000)
    }
}

impl TimeReader for TimeProvider<DaysLen16Bits> {
    fn from_bytes(buf: &[u8]) -> Result<Self, TimestampError> {
        Self::from_bytes_16_bit_days(buf)
    }
}

impl TimeReader for TimeProvider<DaysLen24Bits> {
    fn from_bytes(buf: &[u8]) -> Result<Self, TimestampError> {
        Self::from_bytes_24_bit_days(buf)
    }
}

impl TimeWriter for TimeProvider<DaysLen16Bits> {
    fn write_to_bytes(&self, buf: &mut [u8]) -> Result<usize, TimestampError> {
        self.length_check(buf, self.len_as_bytes())?;
        buf[0] = self.pfield;
        buf[1..3].copy_from_slice(self.ccsds_days.to_be_bytes().as_slice());
        buf[3..7].copy_from_slice(self.ms_of_day.to_be_bytes().as_slice());
        if let Some(submillis_prec) = self.submillis_precision {
            match submillis_prec {
                SubmillisPrecision::Microseconds(ms) => {
                    buf[7..9].copy_from_slice(ms.to_be_bytes().as_slice());
                }
                SubmillisPrecision::Picoseconds(ps) => {
                    buf[7..11].copy_from_slice(ps.to_be_bytes().as_slice());
                }
                _ => (),
            }
        }
        Ok(self.len_as_bytes())
    }
}

impl TimeWriter for TimeProvider<DaysLen24Bits> {
    fn write_to_bytes(&self, buf: &mut [u8]) -> Result<usize, TimestampError> {
        self.length_check(buf, self.len_as_bytes())?;
        buf[0] = self.pfield;
        let be_days = self.ccsds_days.to_be_bytes();
        buf[1..4].copy_from_slice(&be_days[1..4]);
        buf[4..8].copy_from_slice(self.ms_of_day.to_be_bytes().as_slice());
        if let Some(submillis_prec) = self.submillis_precision {
            match submillis_prec {
                SubmillisPrecision::Microseconds(ms) => {
                    buf[8..10].copy_from_slice(ms.to_be_bytes().as_slice());
                }
                SubmillisPrecision::Picoseconds(ps) => {
                    buf[8..12].copy_from_slice(ps.to_be_bytes().as_slice());
                }
                _ => (),
            }
        }
        Ok(self.len_as_bytes())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::time::TimestampError::{ByteConversionError, InvalidTimeCode};
    use crate::ByteConversionError::{FromSliceTooSmall, ToSliceTooSmall};
    use chrono::{Datelike, Timelike};
    #[cfg(feature = "serde")]
    use postcard::{from_bytes, to_allocvec};
    use std::format;

    #[test]
    fn test_time_stamp_zero_args() {
        let time_stamper = TimeProvider::new_with_u16_days(0, 0);
        assert_eq!(
            time_stamper.unix_seconds(),
            (DAYS_CCSDS_TO_UNIX * SECONDS_PER_DAY as i32) as i64
        );
        assert_eq!(time_stamper.submillis_precision(), None);
        assert_eq!(time_stamper.ccdsd_time_code(), CcsdsTimeCodes::Cds);
        assert_eq!(
            time_stamper.p_field(),
            (1, [(CcsdsTimeCodes::Cds as u8) << 4, 0])
        );
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
        let time_stamper = TimeProvider::new_with_u16_days((-DAYS_CCSDS_TO_UNIX) as u16, 0);
        assert_eq!(time_stamper.unix_seconds(), 0);
        assert_eq!(time_stamper.submillis_precision(), None);
        let date_time = time_stamper.date_time().unwrap();
        assert_eq!(date_time.year(), 1970);
        assert_eq!(date_time.month(), 1);
        assert_eq!(date_time.day(), 1);
        assert_eq!(date_time.hour(), 0);
        assert_eq!(date_time.minute(), 0);
        assert_eq!(date_time.second(), 0);
    }

    #[test]
    fn test_large_days_field_write() {
        let time_stamper = TimeProvider::new_with_u24_days(0x108020, 0);
        assert!(time_stamper.is_ok());
        let time_stamper = time_stamper.unwrap();
        assert_eq!(time_stamper.len_as_bytes(), 8);
        let mut buf = [0; 16];
        let written = time_stamper.write_to_bytes(&mut buf);
        assert!(written.is_ok());
        let written = written.unwrap();
        assert_eq!(written, 8);
        assert_eq!(buf[1], 0x10);
        assert_eq!(buf[2], 0x80);
        assert_eq!(buf[3], 0x20);
        let ms = u32::from_be_bytes(buf[4..8].try_into().unwrap());
        assert_eq!(ms, 0);
        assert_eq!((buf[0] >> 2) & 0b1, 1);
    }

    #[test]
    fn test_large_days_field_read() {
        let time_stamper = TimeProvider::new_with_u24_days(0x108020, 0);
        assert!(time_stamper.is_ok());
        let time_stamper = time_stamper.unwrap();
        let mut buf = [0; 16];
        let written = time_stamper.write_to_bytes(&mut buf);
        assert!(written.is_ok());
        let provider = TimeProvider::<DaysLen24Bits>::from_bytes(&buf);
        assert!(provider.is_ok());
        let provider = provider.unwrap();
        assert_eq!(provider.ccsds_days(), 0x108020);
        assert_eq!(provider.ms_of_day(), 0);
    }

    #[test]
    fn test_large_days_field_read_invalid_ctor() {
        let time_stamper = TimeProvider::new_with_u24_days(0x108020, 0);
        assert!(time_stamper.is_ok());
        let time_stamper = time_stamper.unwrap();
        let mut buf = [0; 16];
        let written = time_stamper.write_to_bytes(&mut buf);
        assert!(written.is_ok());
        let faulty_ctor = TimeProvider::<DaysLen16Bits>::from_bytes(&buf);
        assert!(faulty_ctor.is_err());
        let error = faulty_ctor.unwrap_err();
        if let TimestampError::CdsError(cds::CdsError::InvalidCtorForDaysOfLenInPreamble(
            len_of_day,
        )) = error
        {
            assert_eq!(len_of_day, LengthOfDaySegment::Long24Bits);
        } else {
            panic!("Wrong error type");
        }
    }

    #[test]
    fn test_write() {
        let mut buf = [0; 16];
        let time_stamper_0 = TimeProvider::new_with_u16_days(0, 0);
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
        let time_stamper_1 = TimeProvider::new_with_u16_days(u16::MAX - 1, u32::MAX - 1);
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
        let time_stamper = TimeProvider::new_with_u16_days(u16::MAX - 1, u32::MAX - 1);
        for i in 0..6 {
            let res = time_stamper.write_to_bytes(&mut buf[0..i]);
            assert!(res.is_err());
            match res.unwrap_err() {
                ByteConversionError(ToSliceTooSmall(missmatch)) => {
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
            let res = TimeProvider::<DaysLen16Bits>::from_bytes(&buf[0..i]);
            assert!(res.is_err());
            let err = res.unwrap_err();
            match err {
                ByteConversionError(e) => match e {
                    FromSliceTooSmall(missmatch) => {
                        assert_eq!(missmatch.found, i);
                        assert_eq!(missmatch.expected, 7);
                    }
                    _ => panic!("{}", format!("Invalid error {:?} detected", e)),
                },
                _ => {
                    panic!("Unexpected error {:?}", err);
                }
            }
        }
    }

    #[test]
    fn test_faulty_invalid_pfield() {
        let mut buf = [0; 16];
        let time_stamper_0 = TimeProvider::new_with_u16_days(0, 0);
        let res = time_stamper_0.write_to_bytes(&mut buf);
        assert!(res.is_ok());
        buf[0] = 0;
        let res = TimeProvider::<DaysLen16Bits>::from_bytes(&buf);
        assert!(res.is_err());
        let err = res.unwrap_err();
        match err {
            InvalidTimeCode(code, raw) => {
                assert_eq!(code, CcsdsTimeCodes::Cds);
                assert_eq!(raw, 0);
            }
            _ => {}
        }
    }

    #[test]
    fn test_reading() {
        let mut buf = [0; 16];
        let time_stamper = TimeProvider::new_with_u16_days(u16::MAX - 1, u32::MAX - 1);
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

        let read_stamp: TimeProvider<DaysLen16Bits> =
            TimeProvider::from_bytes(&buf).expect("Reading timestamp failed");
        assert_eq!(read_stamp.ccsds_days(), u16::MAX - 1);
        assert_eq!(read_stamp.ms_of_day(), u32::MAX - 1);
    }

    #[test]
    fn test_time_now() {
        let timestamp_now = TimeProvider::from_now_with_u16_days().unwrap();
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

    #[test]
    fn test_submillis_precision_micros() {
        let mut time_stamper = TimeProvider::new_with_u16_days(0, 0);
        time_stamper.set_submillis_precision(SubmillisPrecision::Microseconds(500));
        assert!(time_stamper.submillis_precision().is_some());
        if let SubmillisPrecision::Microseconds(micros) =
            time_stamper.submillis_precision().unwrap()
        {
            assert_eq!(micros, 500);
        } else {
            panic!("Submillis precision was not set properly");
        }
        let mut write_buf: [u8; 16] = [0; 16];
        let written = time_stamper
            .write_to_bytes(&mut write_buf)
            .expect("Writing timestamp failed");
        assert_eq!(written, 9);
        let cross_check: u16 = 500;
        assert_eq!(write_buf[7..9], cross_check.to_be_bytes());
    }

    #[test]
    fn test_submillis_precision_picos() {
        let mut time_stamper = TimeProvider::new_with_u16_days(0, 0);
        time_stamper.set_submillis_precision(SubmillisPrecision::Picoseconds(5e8 as u32));
        assert!(time_stamper.submillis_precision().is_some());
        if let SubmillisPrecision::Picoseconds(ps) = time_stamper.submillis_precision().unwrap() {
            assert_eq!(ps, 5e8 as u32);
        } else {
            panic!("Submillis precision was not set properly");
        }
        let mut write_buf: [u8; 16] = [0; 16];
        let written = time_stamper
            .write_to_bytes(&mut write_buf)
            .expect("Writing timestamp failed");
        assert_eq!(written, 11);
        let cross_check: u32 = 5e8 as u32;
        assert_eq!(write_buf[7..11], cross_check.to_be_bytes());
    }

    #[test]
    fn read_stamp_with_ps_submillis_precision() {
        let mut time_stamper = TimeProvider::new_with_u16_days(0, 0);
        time_stamper.set_submillis_precision(SubmillisPrecision::Picoseconds(5e8 as u32));
        let mut write_buf: [u8; 16] = [0; 16];
        let written = time_stamper
            .write_to_bytes(&mut write_buf)
            .expect("Writing timestamp failed");
        assert_eq!(written, 11);
        let stamp_deserialized = TimeProvider::<DaysLen16Bits>::from_bytes(&write_buf);
        assert!(stamp_deserialized.is_ok());
        let stamp_deserialized = stamp_deserialized.unwrap();
        assert_eq!(stamp_deserialized.len_as_bytes(), 11);
        assert!(stamp_deserialized.submillis_precision().is_some());
        let submillis_rec = stamp_deserialized.submillis_precision().unwrap();
        if let SubmillisPrecision::Picoseconds(ps) = submillis_rec {
            assert_eq!(ps, 5e8 as u32);
        } else {
            panic!("Wrong precision field detected");
        }
    }

    #[test]
    fn read_stamp_with_us_submillis_precision() {
        let mut time_stamper = TimeProvider::new_with_u16_days(0, 0);
        time_stamper.set_submillis_precision(SubmillisPrecision::Microseconds(500));
        let mut write_buf: [u8; 16] = [0; 16];
        let written = time_stamper
            .write_to_bytes(&mut write_buf)
            .expect("Writing timestamp failed");
        assert_eq!(written, 9);
        let stamp_deserialized = TimeProvider::<DaysLen16Bits>::from_bytes(&write_buf);
        assert!(stamp_deserialized.is_ok());
        let stamp_deserialized = stamp_deserialized.unwrap();
        assert_eq!(stamp_deserialized.len_as_bytes(), 9);
        assert!(stamp_deserialized.submillis_precision().is_some());
        let submillis_rec = stamp_deserialized.submillis_precision().unwrap();
        if let SubmillisPrecision::Microseconds(us) = submillis_rec {
            assert_eq!(us, 500);
        } else {
            panic!("Wrong precision field detected");
        }
    }

    #[test]
    #[cfg(feature = "serde")]
    fn test_serialization() {
        let stamp_now = TimeProvider::from_now_with_u16_days().expect("Error retrieving time");
        let val = to_allocvec(&stamp_now).expect("Serializing timestamp failed");
        assert!(val.len() > 0);
        let stamp_deser: TimeProvider = from_bytes(&val).expect("Stamp deserialization failed");
        assert_eq!(stamp_deser, stamp_now);
    }

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
