//! Module to generate or read CCSDS Day Segmented (CDS) timestamps as specified in
//! [CCSDS 301.0-B-4](https://public.ccsds.org/Pubs/301x0b4e1.pdf) section 3.3 .
//!
//! The core data structure to do this is the [TimeProvider] struct and the
//! [get_dyn_time_provider_from_bytes] function to retrieve correct instances of the
//! struct from a bytestream.
use super::*;
use crate::private::Sealed;
#[cfg(feature = "alloc")]
use alloc::boxed::Box;
use chrono::Datelike;
#[cfg(feature = "alloc")]
use core::any::Any;
use core::cmp::Ordering;
use core::fmt::Debug;
use core::ops::{Add, AddAssign};
use core::time::Duration;
use delegate::delegate;

/// Base value for the preamble field for a time field parser to determine the time field type.
pub const P_FIELD_BASE: u8 = (CcsdsTimeCodes::Cds as u8) << 4;
pub const MIN_CDS_FIELD_LEN: usize = 7;
pub const MAX_DAYS_24_BITS: u32 = 2_u32.pow(24) - 1;

/// Generic trait implemented by token structs to specify the length of day field at type
/// level. This trait is only meant to be implemented in this crate and therefore sealed.
pub trait ProvidesDaysLength: Sealed + Clone {
    type FieldType: Debug
        + Copy
        + Clone
        + PartialEq
        + Eq
        + TryFrom<i32>
        + TryFrom<u32>
        + From<u16>
        + Into<u32>
        + Into<i64>;
}

/// Type level token to be used as a generic parameter to [TimeProvider].
#[derive(Debug, Copy, Clone, PartialEq, Eq, Default)]
pub struct DaysLen16Bits {}

impl Sealed for DaysLen16Bits {}
impl ProvidesDaysLength for DaysLen16Bits {
    type FieldType = u16;
}

/// Type level token to be used as a generic parameter to [TimeProvider].
#[derive(Debug, Copy, Clone, PartialEq, Eq, Default)]
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
                write!(f, "invalid ccsds days {days}")
            }
            CdsError::InvalidCtorForDaysOfLenInPreamble(length_of_day) => {
                write!(
                    f,
                    "wrong constructor for length of day {length_of_day:?} detected in preamble",
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
/// If you do not want to perform a forward check of the days length field with
/// [length_of_day_segment_from_pfield] and you have [alloc] support, you can also
/// use [get_dyn_time_provider_from_bytes] to retrieve the correct instance as a [DynCdsTimeProvider]
/// trait object.
///
/// Custom epochs are not supported yet.
/// Furthermore, the preamble field (p-field) is explicitly conveyed.
/// That means it will always be present when writing the time stamp to a raw buffer, and it
/// must be present when reading a CDS timestamp from a raw buffer.
///
/// # Example
///
/// ```
/// use core::time::Duration;
/// use spacepackets::time::cds::{TimeProvider, length_of_day_segment_from_pfield, LengthOfDaySegment};
/// use spacepackets::time::{TimeWriter, CcsdsTimeCodes, CcsdsTimeProvider};
///
/// let timestamp_now = TimeProvider::from_now_with_u16_days().unwrap();
/// let mut raw_stamp = [0; 7];
/// {
///     let written = timestamp_now.write_to_bytes(&mut raw_stamp).unwrap();
///     assert_eq!((raw_stamp[0] >> 4) & 0b111, CcsdsTimeCodes::Cds as u8);
///     assert_eq!(written, 7);
/// }
/// {
///     assert_eq!(length_of_day_segment_from_pfield(raw_stamp[0]), LengthOfDaySegment::Short16Bits);
///     let read_result = TimeProvider::from_bytes_with_u16_days(&raw_stamp);
///     assert!(read_result.is_ok());
///     let stamp_deserialized = read_result.unwrap();
///     assert_eq!(stamp_deserialized.len_as_bytes(), 7);
/// }
/// // It is possible to add a  Duration offset to a timestamp provider. Add 5 minutes offset here
/// let offset = Duration::from_secs(60 * 5);
/// let former_unix_seconds = timestamp_now.unix_seconds();
/// let timestamp_in_5_minutes = timestamp_now + offset;
/// assert_eq!(timestamp_in_5_minutes.unix_seconds(), former_unix_seconds + 5 * 60);
/// ```
#[derive(Debug, Copy, Clone, Eq)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct TimeProvider<DaysLen: ProvidesDaysLength = DaysLen16Bits> {
    pfield: u8,
    ccsds_days: DaysLen::FieldType,
    ms_of_day: u32,
    submillis_precision: Option<SubmillisPrecision>,
    /// This is not strictly necessary but still cached because it significantly simplifies the
    /// calculation of [`DateTime<Utc>`].
    unix_stamp: UnixTimestamp,
}

/// Common properties for all CDS time providers.
///
/// Also exists to encapsulate properties used by private converters.
pub trait CdsCommon {
    fn submillis_precision(&self) -> Option<SubmillisPrecision>;
    fn ms_of_day(&self) -> u32;
    fn ccsds_days_as_u32(&self) -> u32;
}

/// Generic properties for all CDS time providers.
pub trait CdsTimestamp: CdsCommon {
    fn len_of_day_seg(&self) -> LengthOfDaySegment;
}

/// Private trait which serves as an abstraction for different converters.
trait CdsConverter: CdsCommon {
    fn unix_days_seconds(&self) -> i64;
}

struct ConversionFromUnix {
    ccsds_days: u32,
    ms_of_day: u32,
    /// This is a side-product of the calculation of the CCSDS days. It is useful for
    /// re-calculating the datetime at a later point and therefore supplied as well.
    unix_days_seconds: i64,
}

impl ConversionFromUnix {
    fn new(unix_seconds: i64, subsec_millis: u32) -> Result<Self, TimestampError> {
        let (unix_days, secs_of_day) = calc_unix_days_and_secs_of_day(unix_seconds);
        let ccsds_days = unix_to_ccsds_days(unix_days);
        if ccsds_days == 0 && (secs_of_day > 0 || subsec_millis > 0) || ccsds_days < 0 {
            let millis = if unix_seconds < 0 {
                unix_seconds * 1000 - subsec_millis as i64
            } else {
                unix_seconds * 1000 + subsec_millis as i64
            };
            return Err(TimestampError::DateBeforeCcsdsEpoch(
                Utc.timestamp_millis_opt(millis).unwrap(),
            ));
        }
        Ok(Self {
            ccsds_days: unix_to_ccsds_days(unix_days) as u32,
            ms_of_day: secs_of_day * 1000 + subsec_millis,
            unix_days_seconds: unix_days * SECONDS_PER_DAY as i64,
        })
    }
}

impl CdsCommon for ConversionFromUnix {
    fn submillis_precision(&self) -> Option<SubmillisPrecision> {
        None
    }

    fn ms_of_day(&self) -> u32 {
        self.ms_of_day
    }

    fn ccsds_days_as_u32(&self) -> u32 {
        self.ccsds_days
    }
}

impl CdsConverter for ConversionFromUnix {
    fn unix_days_seconds(&self) -> i64 {
        self.unix_days_seconds
    }
}
/// Helper struct which generates fields for the CDS time provider from a datetime.
struct ConversionFromDatetime {
    unix_conversion: ConversionFromUnix,
    submillis_prec: Option<SubmillisPrecision>,
}

impl CdsCommon for ConversionFromDatetime {
    fn submillis_precision(&self) -> Option<SubmillisPrecision> {
        self.submillis_prec
    }

    delegate! {
        to self.unix_conversion {
            fn ms_of_day(&self) -> u32;
            fn ccsds_days_as_u32(&self) -> u32;
        }
    }
}

impl CdsConverter for ConversionFromDatetime {
    delegate! {to self.unix_conversion { fn unix_days_seconds(&self) -> i64; }}
}

#[inline]
fn calc_unix_days_and_secs_of_day(unix_seconds: i64) -> (i64, u32) {
    let mut secs_of_day = unix_seconds % SECONDS_PER_DAY as i64;
    let mut unix_days = (unix_seconds - secs_of_day) / SECONDS_PER_DAY as i64;
    // Imagine the CCSDS epoch time minus 5 seconds: We now have the last day in the year
    // 1969 (-1 unix days) shortly before midnight (SECONDS_PER_DAY - 5).
    if secs_of_day < 0 {
        unix_days -= 1;
        secs_of_day += SECONDS_PER_DAY as i64
    }
    (unix_days, secs_of_day as u32)
}

impl ConversionFromDatetime {
    fn new(dt: &DateTime<Utc>) -> Result<Self, TimestampError> {
        Self::new_generic(dt, None)
    }

    fn new_with_submillis_us_prec(dt: &DateTime<Utc>) -> Result<Self, TimestampError> {
        Self::new_generic(dt, Some(SubmillisPrecision::Microseconds(0)))
    }

    fn new_with_submillis_ps_prec(dt: &DateTime<Utc>) -> Result<Self, TimestampError> {
        Self::new_generic(dt, Some(SubmillisPrecision::Picoseconds(0)))
    }

    fn new_generic(
        dt: &DateTime<Utc>,
        mut prec: Option<SubmillisPrecision>,
    ) -> Result<Self, TimestampError> {
        // The CDS timestamp does not support timestamps before the CCSDS epoch.
        if dt.year() < 1958 {
            return Err(TimestampError::DateBeforeCcsdsEpoch(*dt));
        }
        // The contained values in the conversion should be all positive now
        let unix_conversion =
            ConversionFromUnix::new(dt.timestamp(), dt.timestamp_subsec_millis())?;
        if let Some(submilli_prec) = prec {
            match submilli_prec {
                SubmillisPrecision::Microseconds(_) => {
                    prec = Some(SubmillisPrecision::Microseconds(
                        (dt.timestamp_subsec_micros() % 1000) as u16,
                    ));
                }
                SubmillisPrecision::Picoseconds(_) => {
                    prec = Some(SubmillisPrecision::Picoseconds(
                        (dt.timestamp_subsec_nanos() % 10_u32.pow(6)) * 1000,
                    ));
                }
                _ => (),
            }
        }
        Ok(Self {
            unix_conversion,
            submillis_prec: prec,
        })
    }
}

#[cfg(feature = "std")]
struct ConversionFromNow {
    unix_conversion: ConversionFromUnix,
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
        // This should always return a value with valid (non-negative) CCSDS days,
        // so it is okay to unwrap
        let unix_conversion = ConversionFromUnix::new(epoch as i64, now.subsec_millis()).unwrap();
        // Both values should now be positive
        if let Some(submilli_prec) = prec {
            match submilli_prec {
                SubmillisPrecision::Microseconds(_) => {
                    prec = Some(SubmillisPrecision::Microseconds(
                        (now.subsec_micros() % 1000) as u16,
                    ));
                }
                SubmillisPrecision::Picoseconds(_) => {
                    prec = Some(SubmillisPrecision::Picoseconds(
                        (now.subsec_nanos() % 10_u32.pow(6)) * 1000,
                    ));
                }
                _ => (),
            }
        }
        Ok(Self {
            unix_conversion,
            submillis_prec: prec,
        })
    }
}

#[cfg(feature = "std")]
impl CdsCommon for ConversionFromNow {
    fn submillis_precision(&self) -> Option<SubmillisPrecision> {
        self.submillis_prec
    }
    delegate! {
        to self.unix_conversion {
            fn ms_of_day(&self) -> u32;
            fn ccsds_days_as_u32(&self) -> u32;
        }
    }
}

#[cfg(feature = "std")]
impl CdsConverter for ConversionFromNow {
    delegate! {to self.unix_conversion { fn unix_days_seconds(&self) -> i64; }}
}

#[cfg(feature = "alloc")]
#[cfg_attr(doc_cfg, doc(cfg(feature = "alloc")))]
pub trait DynCdsTimeProvider: CcsdsTimeProvider + CdsTimestamp + TimeWriter + Any {}
#[cfg(feature = "alloc")]
#[cfg_attr(doc_cfg, doc(cfg(feature = "alloc")))]
impl DynCdsTimeProvider for TimeProvider<DaysLen16Bits> {}
#[cfg(feature = "alloc")]
#[cfg_attr(doc_cfg, doc(cfg(feature = "alloc")))]
impl DynCdsTimeProvider for TimeProvider<DaysLen24Bits> {}

/// This function returns the correct [TimeProvider] instance from a raw byte array
/// by checking the length of days field. It also checks the CCSDS time code for correctness.
///
/// # Example
///
/// ```
/// use spacepackets::time::cds::{TimeProvider, LengthOfDaySegment, get_dyn_time_provider_from_bytes};
/// use spacepackets::time::{TimeWriter, CcsdsTimeCodes, CcsdsTimeProvider};
///
/// let timestamp_now = TimeProvider::new_with_u16_days(24, 24);
/// let mut raw_stamp = [0; 7];
/// {
///     let written = timestamp_now.write_to_bytes(&mut raw_stamp).unwrap();
///     assert_eq!((raw_stamp[0] >> 4) & 0b111, CcsdsTimeCodes::Cds as u8);
///     assert_eq!(written, 7);
/// }
/// {
///     let dyn_provider = get_dyn_time_provider_from_bytes(&raw_stamp).unwrap();
///     assert_eq!(dyn_provider.len_of_day_seg(), LengthOfDaySegment::Short16Bits);
///     assert_eq!(dyn_provider.ccsds_days_as_u32(), 24);
///     assert_eq!(dyn_provider.ms_of_day(), 24);
///     assert_eq!(dyn_provider.submillis_precision(), None);
/// }
/// ```
#[cfg(feature = "alloc")]
#[cfg_attr(doc_cfg, doc(cfg(feature = "alloc")))]
pub fn get_dyn_time_provider_from_bytes(
    buf: &[u8],
) -> Result<Box<dyn DynCdsTimeProvider>, TimestampError> {
    let time_code = ccsds_time_code_from_p_field(buf[0]);
    if let Err(e) = time_code {
        return Err(TimestampError::InvalidTimeCode {
            expected: CcsdsTimeCodes::Cds,
            found: e,
        });
    }
    let time_code = time_code.unwrap();
    if time_code != CcsdsTimeCodes::Cds {
        return Err(TimestampError::InvalidTimeCode {
            expected: CcsdsTimeCodes::Cds,
            found: time_code as u8,
        });
    }
    if length_of_day_segment_from_pfield(buf[0]) == LengthOfDaySegment::Short16Bits {
        Ok(Box::new(TimeProvider::from_bytes_with_u16_days(buf)?))
    } else {
        Ok(Box::new(TimeProvider::from_bytes_with_u24_days(buf)?))
    }
}

impl<ProvidesDaysLen: ProvidesDaysLength> CdsCommon for TimeProvider<ProvidesDaysLen> {
    fn submillis_precision(&self) -> Option<SubmillisPrecision> {
        self.submillis_precision
    }

    fn ms_of_day(&self) -> u32 {
        self.ms_of_day
    }

    fn ccsds_days_as_u32(&self) -> u32 {
        self.ccsds_days.into()
    }
}

impl<ProvidesDaysLen: ProvidesDaysLength> TimeProvider<ProvidesDaysLen> {
    /// Please note that a precision value of 0 will be converted to [None] (no precision).
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

    /// Maps the submillisecond precision to a nanosecond value. This will reduce precision when
    /// using picosecond resolution, but significantly simplifies comparison of timestamps.
    pub fn precision_as_ns(&self) -> Option<u32> {
        if let Some(prec) = self.submillis_precision {
            match prec {
                SubmillisPrecision::Microseconds(us) => {
                    return Some(us as u32 * 1000);
                }
                SubmillisPrecision::Picoseconds(ps) => {
                    return Some(ps / 1000);
                }
                _ => {
                    return None;
                }
            }
        }
        None
    }

    fn generic_raw_read_checks(
        buf: &[u8],
        days_len: LengthOfDaySegment,
    ) -> Result<SubmillisPrecision, TimestampError> {
        if buf.len() < MIN_CDS_FIELD_LEN {
            return Err(TimestampError::ByteConversion(
                ByteConversionError::FromSliceTooSmall {
                    expected: MIN_CDS_FIELD_LEN,
                    found: buf.len(),
                },
            ));
        }
        let pfield = buf[0];
        match CcsdsTimeCodes::try_from(pfield >> 4 & 0b111) {
            Ok(cds_type) => match cds_type {
                CcsdsTimeCodes::Cds => (),
                _ => {
                    return Err(TimestampError::InvalidTimeCode {
                        expected: CcsdsTimeCodes::Cds,
                        found: cds_type as u8,
                    })
                }
            },
            _ => {
                return Err(TimestampError::InvalidTimeCode {
                    expected: CcsdsTimeCodes::Cds,
                    found: pfield >> 4 & 0b111,
                });
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
            return Err(TimestampError::ByteConversion(
                ByteConversionError::FromSliceTooSmall {
                    expected: stamp_len,
                    found: buf.len(),
                },
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

    fn setup(&mut self, unix_days_seconds: i64, ms_of_day: u32) {
        self.calc_unix_seconds(unix_days_seconds, ms_of_day);
    }

    #[inline]
    fn calc_unix_seconds(&mut self, mut unix_days_seconds: i64, ms_of_day: u32) {
        let seconds_of_day = (ms_of_day / 1000) as i64;
        if unix_days_seconds < 0 {
            unix_days_seconds -= seconds_of_day;
        } else {
            unix_days_seconds += seconds_of_day;
        }
        self.unix_stamp = UnixTimestamp::const_new(unix_days_seconds, (ms_of_day % 1000) as u16);
    }

    fn calc_date_time(&self, ns_since_last_second: u32) -> Option<DateTime<Utc>> {
        assert!(
            ns_since_last_second < 10_u32.pow(9),
            "Invalid MS since last second"
        );
        if let LocalResult::Single(val) =
            Utc.timestamp_opt(self.unix_stamp.unix_seconds, ns_since_last_second)
        {
            return Some(val);
        }
        None
    }

    fn length_check(&self, buf: &[u8], len_as_bytes: usize) -> Result<(), TimestampError> {
        if buf.len() < len_as_bytes {
            return Err(TimestampError::ByteConversion(
                ByteConversionError::ToSliceTooSmall {
                    expected: len_as_bytes,
                    found: buf.len(),
                },
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
            unix_stamp: Default::default(),
            submillis_precision: None,
        };
        let unix_days_seconds = ccsds_to_unix_days(i64::from(ccsds_days)) * SECONDS_PER_DAY as i64;
        provider.setup(unix_days_seconds, ms_of_day);
        Ok(provider)
    }

    fn from_dt_generic(
        dt: &DateTime<Utc>,
        days_len: LengthOfDaySegment,
    ) -> Result<Self, TimestampError> {
        let conv_from_dt = ConversionFromDatetime::new(dt)?;
        Self::generic_from_conversion(days_len, conv_from_dt)
    }

    fn from_dt_generic_us_prec(
        dt: &DateTime<Utc>,
        days_len: LengthOfDaySegment,
    ) -> Result<Self, TimestampError> {
        let conv_from_dt = ConversionFromDatetime::new_with_submillis_us_prec(dt)?;
        Self::generic_from_conversion(days_len, conv_from_dt)
    }

    fn from_dt_generic_ps_prec(
        dt: &DateTime<Utc>,
        days_len: LengthOfDaySegment,
    ) -> Result<Self, TimestampError> {
        let conv_from_dt = ConversionFromDatetime::new_with_submillis_ps_prec(dt)?;
        Self::generic_from_conversion(days_len, conv_from_dt)
    }

    fn from_unix_generic(
        unix_stamp: &UnixTimestamp,
        days_len: LengthOfDaySegment,
    ) -> Result<Self, TimestampError> {
        let conv_from_dt = ConversionFromUnix::new(
            unix_stamp.unix_seconds,
            unix_stamp.subsecond_millis.unwrap_or(0) as u32,
        )?;
        Self::generic_from_conversion(days_len, conv_from_dt)
    }

    #[cfg(feature = "std")]
    fn from_now_generic(days_len: LengthOfDaySegment) -> Result<Self, StdTimestampError> {
        let conversion_from_now = ConversionFromNow::new()?;
        Self::generic_from_conversion(days_len, conversion_from_now)
            .map_err(StdTimestampError::Timestamp)
    }

    #[cfg(feature = "std")]
    fn from_now_generic_us_prec(days_len: LengthOfDaySegment) -> Result<Self, StdTimestampError> {
        let conversion_from_now = ConversionFromNow::new_with_submillis_us_prec()?;
        Self::generic_from_conversion(days_len, conversion_from_now)
            .map_err(StdTimestampError::Timestamp)
    }

    #[cfg(feature = "std")]
    fn from_now_generic_ps_prec(days_len: LengthOfDaySegment) -> Result<Self, StdTimestampError> {
        let conversion_from_now = ConversionFromNow::new_with_submillis_ps_prec()?;
        Self::generic_from_conversion(days_len, conversion_from_now)
            .map_err(StdTimestampError::Timestamp)
    }

    fn generic_from_conversion<C: CdsConverter>(
        days_len: LengthOfDaySegment,
        converter: C,
    ) -> Result<Self, TimestampError> {
        let ccsds_days: ProvidesDaysLen::FieldType =
            converter.ccsds_days_as_u32().try_into().map_err(|_| {
                TimestampError::Cds(CdsError::InvalidCcsdsDays(
                    converter.ccsds_days_as_u32().into(),
                ))
            })?;
        let mut provider = Self {
            pfield: Self::generate_p_field(days_len, converter.submillis_precision()),
            ccsds_days,
            ms_of_day: converter.ms_of_day(),
            unix_stamp: Default::default(),
            submillis_precision: converter.submillis_precision(),
        };
        provider.setup(converter.unix_days_seconds(), converter.ms_of_day());
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
    pub fn update_from_now(&mut self) -> Result<(), StdTimestampError> {
        let conversion_from_now = self.generic_conversion_from_now()?;
        let ccsds_days: ProvidesDaysLen::FieldType = conversion_from_now
            .unix_conversion
            .ccsds_days
            .try_into()
            .map_err(|_| {
                StdTimestampError::Timestamp(
                    CdsError::InvalidCcsdsDays(
                        conversion_from_now.unix_conversion.ccsds_days as i64,
                    )
                    .into(),
                )
            })?;
        self.ccsds_days = ccsds_days;
        self.ms_of_day = conversion_from_now.unix_conversion.ms_of_day;
        self.setup(
            conversion_from_now.unix_conversion.unix_days_seconds,
            conversion_from_now.unix_conversion.ms_of_day,
        );
        Ok(())
    }
}

impl TimeProvider<DaysLen24Bits> {
    /// Generate a new timestamp provider with the days field width set to 24 bits
    pub fn new_with_u24_days(ccsds_days: u32, ms_of_day: u32) -> Result<Self, CdsError> {
        if ccsds_days > MAX_DAYS_24_BITS {
            return Err(CdsError::InvalidCcsdsDays(ccsds_days.into()));
        }
        Self::generic_new(LengthOfDaySegment::Long24Bits, ccsds_days, ms_of_day)
    }

    /// Generate a time stamp from the current time using the system clock.
    #[cfg(feature = "std")]
    #[cfg_attr(doc_cfg, doc(cfg(feature = "std")))]
    pub fn from_now_with_u24_days() -> Result<Self, StdTimestampError> {
        Self::from_now_generic(LengthOfDaySegment::Long24Bits)
    }

    /// Create a provider from a [`DateTime<Utc>`] struct.
    ///
    /// ## Errors
    ///
    /// This function will return [TimestampError::DateBeforeCcsdsEpoch] or
    /// [TimestampError::Cds] if the time is before the CCSDS epoch (1958-01-01T00:00:00+00:00)
    /// or the CCSDS days value exceeds the allowed bit width (24 bits).
    pub fn from_dt_with_u24_days(dt: &DateTime<Utc>) -> Result<Self, TimestampError> {
        Self::from_dt_generic(dt, LengthOfDaySegment::Long24Bits)
    }

    /// Create a provider from a generic UNIX timestamp (seconds since 1970-01-01T00:00:00+00:00).
    ///
    /// ## Errors
    ///
    /// This function will return [TimestampError::DateBeforeCcsdsEpoch] or
    /// [TimestampError::Cds] if the time is before the CCSDS epoch (1958-01-01T00:00:00+00:00)
    /// or the CCSDS days value exceeds the allowed bit width (24 bits).
    pub fn from_unix_secs_with_u24_days(
        unix_stamp: &UnixTimestamp,
    ) -> Result<Self, TimestampError> {
        Self::from_unix_generic(unix_stamp, LengthOfDaySegment::Long24Bits)
    }

    /// Like [Self::from_dt_with_u24_days] but with microsecond sub-millisecond precision.
    pub fn from_dt_with_u24_days_us_precision(dt: &DateTime<Utc>) -> Result<Self, TimestampError> {
        Self::from_dt_generic_us_prec(dt, LengthOfDaySegment::Long24Bits)
    }

    /// Like [Self::from_dt_with_u24_days] but with picoseconds sub-millisecond precision.
    pub fn from_dt_with_u24_days_ps_precision(dt: &DateTime<Utc>) -> Result<Self, TimestampError> {
        Self::from_dt_generic_ps_prec(dt, LengthOfDaySegment::Long24Bits)
    }

    /// Like [Self::from_now_with_u24_days] but with microsecond sub-millisecond precision.
    #[cfg(feature = "std")]
    #[cfg_attr(doc_cfg, doc(cfg(feature = "std")))]
    pub fn from_now_with_u24_days_us_precision() -> Result<Self, StdTimestampError> {
        Self::from_now_generic_us_prec(LengthOfDaySegment::Long24Bits)
    }

    /// Like [Self::from_now_with_u24_days] but with picoseconds sub-millisecond precision.
    #[cfg(feature = "std")]
    #[cfg_attr(doc_cfg, doc(cfg(feature = "std")))]
    pub fn from_now_with_u24_days_ps_precision() -> Result<Self, StdTimestampError> {
        Self::from_now_generic_us_prec(LengthOfDaySegment::Long24Bits)
    }

    pub fn from_bytes_with_u24_days(buf: &[u8]) -> Result<Self, TimestampError> {
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

    /// Create a provider from a [`DateTime<Utc>`] struct.
    ///
    /// This function will return a [TimestampError::DateBeforeCcsdsEpoch] or a
    /// [TimestampError::Cds] if the time is before the CCSDS epoch (01-01-1958 00:00:00) or
    /// the CCSDS days value exceeds the allowed bit width (16 bits).
    pub fn from_dt_with_u16_days(dt: &DateTime<Utc>) -> Result<Self, TimestampError> {
        Self::from_dt_generic(dt, LengthOfDaySegment::Short16Bits)
    }

    /// Generate a time stamp from the current time using the system clock.
    #[cfg(feature = "std")]
    #[cfg_attr(doc_cfg, doc(cfg(feature = "std")))]
    pub fn from_now_with_u16_days() -> Result<Self, StdTimestampError> {
        Self::from_now_generic(LengthOfDaySegment::Short16Bits)
    }

    /// Create a provider from a generic UNIX timestamp (seconds since 1970-01-01T00:00:00+00:00).
    ///
    /// ## Errors
    ///
    /// This function will return [TimestampError::DateBeforeCcsdsEpoch] or
    /// [TimestampError::Cds] if the time is before the CCSDS epoch (1958-01-01T00:00:00+00:00)
    /// or the CCSDS days value exceeds the allowed bit width (24 bits).
    pub fn from_unix_secs_with_u16_days(
        unix_stamp: &UnixTimestamp,
    ) -> Result<Self, TimestampError> {
        Self::from_unix_generic(unix_stamp, LengthOfDaySegment::Short16Bits)
    }

    /// Like [Self::from_dt_with_u16_days] but with microsecond sub-millisecond precision.
    pub fn from_dt_with_u16_days_us_precision(dt: &DateTime<Utc>) -> Result<Self, TimestampError> {
        Self::from_dt_generic_us_prec(dt, LengthOfDaySegment::Short16Bits)
    }

    /// Like [Self::from_dt_with_u16_days] but with picoseconds sub-millisecond precision.
    pub fn from_dt_with_u16_days_ps_precision(dt: &DateTime<Utc>) -> Result<Self, TimestampError> {
        Self::from_dt_generic_ps_prec(dt, LengthOfDaySegment::Short16Bits)
    }

    /// Like [Self::from_now_with_u16_days] but with microsecond sub-millisecond precision.
    #[cfg(feature = "std")]
    #[cfg_attr(doc_cfg, doc(cfg(feature = "std")))]
    pub fn from_now_with_u16_days_us_precision() -> Result<Self, StdTimestampError> {
        Self::from_now_generic_us_prec(LengthOfDaySegment::Short16Bits)
    }

    /// Like [Self::from_now_with_u16_days] but with picosecond sub-millisecond precision.
    #[cfg(feature = "std")]
    #[cfg_attr(doc_cfg, doc(cfg(feature = "std")))]
    pub fn from_now_with_u16_days_ps_precision() -> Result<Self, StdTimestampError> {
        Self::from_now_generic_ps_prec(LengthOfDaySegment::Short16Bits)
    }

    pub fn from_bytes_with_u16_days(buf: &[u8]) -> Result<Self, TimestampError> {
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

fn add_for_max_ccsds_days_val<T: ProvidesDaysLength>(
    time_provider: &TimeProvider<T>,
    max_days_val: u32,
    duration: Duration,
) -> (u32, u32, Option<SubmillisPrecision>) {
    let mut next_ccsds_days = time_provider.ccsds_days_as_u32();
    let mut next_ms_of_day = time_provider.ms_of_day;
    // Increment CCSDS days by a certain amount while also accounting for overflow.
    let increment_days = |ccsds_days: &mut u32, days_inc: u32| {
        let days_addition: u64 = *ccsds_days as u64 + days_inc as u64;
        if days_addition > max_days_val as u64 {
            *ccsds_days = (days_addition - max_days_val as u64) as u32;
        } else {
            *ccsds_days += days_inc;
        }
    };
    // Increment MS of day by a certain amount while also accounting for overflow, where
    // the new value exceeds the MS of a day.
    let increment_ms_of_day = |ms_of_day: &mut u32, ms_inc: u32, ccsds_days: &mut u32| {
        *ms_of_day += ms_inc;
        if *ms_of_day >= MS_PER_DAY {
            *ms_of_day -= MS_PER_DAY;
            // Re-use existing closure to always amount for overflow.
            increment_days(ccsds_days, 1);
        }
    };
    let precision = if let Some(submillis_prec) = time_provider.submillis_precision {
        match submillis_prec {
            SubmillisPrecision::Microseconds(mut us) => {
                let subsec_micros = duration.subsec_micros();
                let subsec_millis = subsec_micros / 1000;
                let submilli_micros = (subsec_micros % 1000) as u16;
                us += submilli_micros;
                if us >= 1000 {
                    let carryover_us = us - 1000;
                    increment_ms_of_day(&mut next_ms_of_day, 1, &mut next_ccsds_days);
                    us = carryover_us;
                }
                increment_ms_of_day(&mut next_ms_of_day, subsec_millis, &mut next_ccsds_days);
                Some(SubmillisPrecision::Microseconds(us))
            }
            SubmillisPrecision::Picoseconds(mut ps) => {
                let subsec_nanos = duration.subsec_nanos();
                let subsec_millis = subsec_nanos / 10_u32.pow(6);
                // 1 ms as ns is 1e6.
                let submilli_nanos = subsec_nanos % 10_u32.pow(6);
                // No overflow risk: The maximum value of an u32 is ~4.294e9, and one ms as ps
                // is 1e9. The amount ps can now have is always less than 2e9.
                ps += submilli_nanos * 1000;
                if ps >= 10_u32.pow(9) {
                    let carry_over_ps = ps - 10_u32.pow(9);
                    increment_ms_of_day(&mut next_ms_of_day, 1, &mut next_ccsds_days);
                    ps = carry_over_ps;
                }
                increment_ms_of_day(&mut next_ms_of_day, subsec_millis, &mut next_ccsds_days);
                Some(SubmillisPrecision::Picoseconds(ps))
            }
            _ => None,
        }
    } else {
        increment_ms_of_day(
            &mut next_ms_of_day,
            duration.subsec_millis(),
            &mut next_ccsds_days,
        );
        None
    };
    // The subsecond millisecond were already handled.
    let full_seconds = duration.as_secs();
    let secs_of_day = (full_seconds % SECONDS_PER_DAY as u64) as u32;
    let ms_of_day = secs_of_day * 1000;
    increment_ms_of_day(&mut next_ms_of_day, ms_of_day, &mut next_ccsds_days);
    increment_days(
        &mut next_ccsds_days,
        (full_seconds as u32 - secs_of_day) / SECONDS_PER_DAY,
    );
    (next_ccsds_days, next_ms_of_day, precision)
}

impl CdsTimestamp for TimeProvider<DaysLen16Bits> {
    fn len_of_day_seg(&self) -> LengthOfDaySegment {
        LengthOfDaySegment::Short16Bits
    }
}

impl CdsTimestamp for TimeProvider<DaysLen24Bits> {
    fn len_of_day_seg(&self) -> LengthOfDaySegment {
        LengthOfDaySegment::Long24Bits
    }
}

/// Allows adding an duration in form of an offset. Please note that the CCSDS days will rollover
/// when they overflow, because addition needs to be infallible. The user needs to check for a
/// days overflow when this is a possibility and might be a problem.
impl Add<Duration> for TimeProvider<DaysLen16Bits> {
    type Output = Self;

    fn add(self, duration: Duration) -> Self::Output {
        let (next_ccsds_days, next_ms_of_day, precision) =
            add_for_max_ccsds_days_val(&self, u16::MAX as u32, duration);
        let mut provider = Self::new_with_u16_days(next_ccsds_days as u16, next_ms_of_day);
        if let Some(prec) = precision {
            provider.set_submillis_precision(prec);
        }
        provider
    }
}

impl Add<Duration> for &TimeProvider<DaysLen16Bits> {
    type Output = TimeProvider<DaysLen16Bits>;

    fn add(self, duration: Duration) -> Self::Output {
        let (next_ccsds_days, next_ms_of_day, precision) =
            add_for_max_ccsds_days_val(self, u16::MAX as u32, duration);
        let mut provider = Self::Output::new_with_u16_days(next_ccsds_days as u16, next_ms_of_day);
        if let Some(prec) = precision {
            provider.set_submillis_precision(prec);
        }
        provider
    }
}

/// Allows adding an duration in form of an offset. Please note that the CCSDS days will rollover
/// when they overflow, because addition needs to be infallible. The user needs to check for a
/// days overflow when this is a possibility and might be a problem.
impl Add<Duration> for TimeProvider<DaysLen24Bits> {
    type Output = Self;

    fn add(self, duration: Duration) -> Self::Output {
        let (next_ccsds_days, next_ms_of_day, precision) =
            add_for_max_ccsds_days_val(&self, MAX_DAYS_24_BITS, duration);
        let mut provider = Self::new_with_u24_days(next_ccsds_days, next_ms_of_day).unwrap();
        if let Some(prec) = precision {
            provider.set_submillis_precision(prec);
        }
        provider
    }
}

impl Add<Duration> for &TimeProvider<DaysLen24Bits> {
    type Output = TimeProvider<DaysLen24Bits>;
    fn add(self, duration: Duration) -> Self::Output {
        let (next_ccsds_days, next_ms_of_day, precision) =
            add_for_max_ccsds_days_val(self, MAX_DAYS_24_BITS, duration);
        let mut provider =
            Self::Output::new_with_u24_days(next_ccsds_days, next_ms_of_day).unwrap();
        if let Some(prec) = precision {
            provider.set_submillis_precision(prec);
        }
        provider
    }
}

/// Allows adding an duration in form of an offset. Please note that the CCSDS days will rollover
/// when they overflow, because addition needs to be infallible. The user needs to check for a
/// days overflow when this is a possibility and might be a problem.
impl AddAssign<Duration> for TimeProvider<DaysLen16Bits> {
    fn add_assign(&mut self, duration: Duration) {
        let (next_ccsds_days, next_ms_of_day, precision) =
            add_for_max_ccsds_days_val(self, u16::MAX as u32, duration);
        self.ccsds_days = next_ccsds_days as u16;
        self.ms_of_day = next_ms_of_day;
        self.submillis_precision = precision;
    }
}

/// Allows adding an duration in form of an offset. Please note that the CCSDS days will rollover
/// when they overflow, because addition needs to be infallible. The user needs to check for a
/// days overflow when this is a possibility and might be a problem.
impl AddAssign<Duration> for TimeProvider<DaysLen24Bits> {
    fn add_assign(&mut self, duration: Duration) {
        let (next_ccsds_days, next_ms_of_day, precision) =
            add_for_max_ccsds_days_val(self, MAX_DAYS_24_BITS, duration);
        self.ccsds_days = next_ccsds_days;
        self.ms_of_day = next_ms_of_day;
        self.submillis_precision = precision;
    }
}

impl TryFrom<DateTime<Utc>> for TimeProvider<DaysLen16Bits> {
    type Error = TimestampError;

    fn try_from(dt: DateTime<Utc>) -> Result<Self, Self::Error> {
        let conversion = ConversionFromDatetime::new(&dt)?;
        Self::generic_from_conversion(LengthOfDaySegment::Short16Bits, conversion)
    }
}

impl TryFrom<DateTime<Utc>> for TimeProvider<DaysLen24Bits> {
    type Error = TimestampError;

    fn try_from(dt: DateTime<Utc>) -> Result<Self, Self::Error> {
        let conversion = ConversionFromDatetime::new(&dt)?;
        Self::generic_from_conversion(LengthOfDaySegment::Long24Bits, conversion)
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

    #[inline]
    fn unix_seconds(&self) -> i64 {
        self.unix_stamp.unix_seconds
    }
    #[inline]
    fn subsecond_millis(&self) -> Option<u16> {
        self.unix_stamp.subsecond_millis
    }

    #[inline]
    fn unix_stamp(&self) -> UnixTimestamp {
        self.unix_stamp
    }

    fn date_time(&self) -> Option<DateTime<Utc>> {
        let mut ns_since_last_sec = (self.ms_of_day % 1000) * 10_u32.pow(6);
        if let Some(precision) = self.submillis_precision {
            match precision {
                SubmillisPrecision::Microseconds(us) => {
                    ns_since_last_sec += us as u32 * 1000;
                }
                SubmillisPrecision::Picoseconds(ps) => {
                    ns_since_last_sec += ps / 1000;
                }
                _ => (),
            }
        }
        self.calc_date_time(ns_since_last_sec)
    }
}

impl TimeReader for TimeProvider<DaysLen16Bits> {
    fn from_bytes(buf: &[u8]) -> Result<Self, TimestampError> {
        Self::from_bytes_with_u16_days(buf)
    }
}

impl TimeReader for TimeProvider<DaysLen24Bits> {
    fn from_bytes(buf: &[u8]) -> Result<Self, TimestampError> {
        Self::from_bytes_with_u24_days(buf)
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

impl<DaysLenProvider: ProvidesDaysLength> PartialEq for TimeProvider<DaysLenProvider> {
    fn eq(&self, other: &Self) -> bool {
        if self.ccsds_days == other.ccsds_days
            && self.ms_of_day == other.ms_of_day
            && self.precision_as_ns().unwrap_or(0) == other.precision_as_ns().unwrap_or(0)
        {
            return true;
        }
        false
    }
}

impl<DaysLenProvider: ProvidesDaysLength> PartialOrd for TimeProvider<DaysLenProvider> {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        if self == other {
            return Some(Ordering::Equal);
        }
        match self.ccsds_days_as_u32().cmp(&other.ccsds_days_as_u32()) {
            Ordering::Less => return Some(Ordering::Less),
            Ordering::Greater => return Some(Ordering::Greater),
            _ => (),
        }
        match self.ms_of_day().cmp(&other.ms_of_day()) {
            Ordering::Less => return Some(Ordering::Less),
            Ordering::Greater => return Some(Ordering::Greater),
            _ => (),
        }
        match self
            .precision_as_ns()
            .unwrap_or(0)
            .cmp(&other.precision_as_ns().unwrap_or(0))
        {
            Ordering::Less => return Some(Ordering::Less),
            Ordering::Greater => return Some(Ordering::Greater),
            _ => (),
        }
        Some(Ordering::Equal)
    }
}

impl<DaysLenProvider: ProvidesDaysLength + Eq> Ord for TimeProvider<DaysLenProvider> {
    fn cmp(&self, other: &Self) -> Ordering {
        PartialOrd::partial_cmp(self, other).unwrap()
    }
}

impl From<TimeProvider<DaysLen16Bits>> for TimeProvider<DaysLen24Bits> {
    fn from(value: TimeProvider<DaysLen16Bits>) -> Self {
        // This function only fails if the days value exceeds 24 bits, which is not possible here,
        // so it is okay to unwrap.
        Self::new_with_u24_days(value.ccsds_days_as_u32(), value.ms_of_day()).unwrap()
    }
}

/// This conversion can fail if the days value exceeds 16 bits.
impl TryFrom<TimeProvider<DaysLen24Bits>> for TimeProvider<DaysLen16Bits> {
    type Error = CdsError;
    fn try_from(value: TimeProvider<DaysLen24Bits>) -> Result<Self, CdsError> {
        let ccsds_days = value.ccsds_days_as_u32();
        if ccsds_days > u16::MAX as u32 {
            return Err(CdsError::InvalidCcsdsDays(ccsds_days as i64));
        }
        Ok(Self::new_with_u16_days(
            ccsds_days as u16,
            value.ms_of_day(),
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::time::TimestampError::{ByteConversion, InvalidTimeCode};
    use crate::ByteConversionError::{FromSliceTooSmall, ToSliceTooSmall};
    use alloc::string::ToString;
    use chrono::{Datelike, NaiveDate, Timelike};
    #[cfg(feature = "serde")]
    use postcard::{from_bytes, to_allocvec};
    use std::format;

    #[test]
    fn test_time_stamp_zero_args() {
        let time_stamper = TimeProvider::new_with_u16_days(0, 0);
        let unix_stamp = time_stamper.unix_stamp();
        assert_eq!(
            unix_stamp.unix_seconds,
            (DAYS_CCSDS_TO_UNIX * SECONDS_PER_DAY as i32) as i64
        );
        let subsecond_millis = unix_stamp.subsecond_millis;
        assert!(subsecond_millis.is_none());
        assert_eq!(time_stamper.submillis_precision(), None);
        assert!(time_stamper.subsecond_millis().is_none());
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
        assert_eq!(time_stamper.unix_stamp().unix_seconds, 0);
        assert_eq!(time_stamper.submillis_precision(), None);
        let date_time = time_stamper.date_time().unwrap();
        assert_eq!(date_time.year(), 1970);
        assert_eq!(date_time.month(), 1);
        assert_eq!(date_time.day(), 1);
        assert_eq!(date_time.hour(), 0);
        assert_eq!(date_time.minute(), 0);
        assert_eq!(date_time.second(), 0);
        let time_stamper = TimeProvider::new_with_u16_days((-DAYS_CCSDS_TO_UNIX) as u16, 40);
        assert!(time_stamper.subsecond_millis().is_some());
        assert_eq!(time_stamper.subsecond_millis().unwrap(), 40);
        let time_stamper = TimeProvider::new_with_u16_days((-DAYS_CCSDS_TO_UNIX) as u16, 1040);
        assert!(time_stamper.subsecond_millis().is_some());
        assert_eq!(time_stamper.subsecond_millis().unwrap(), 40);
    }

    #[test]
    fn test_large_days_field_write() {
        let time_stamper = TimeProvider::new_with_u24_days(0x108020_u32, 0x10203040);
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
        assert_eq!(ms, 0x10203040);
        assert_eq!((buf[0] >> 2) & 0b1, 1);
    }

    #[test]
    fn test_large_days_field_read() {
        let time_stamper = TimeProvider::new_with_u24_days(0x108020_u32, 0);
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
        if let TimestampError::Cds(CdsError::InvalidCtorForDaysOfLenInPreamble(len_of_day)) = error
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
        let unix_stamp = time_stamper_0.unix_stamp();
        assert_eq!(
            unix_stamp.unix_seconds,
            (DAYS_CCSDS_TO_UNIX * SECONDS_PER_DAY as i32).into()
        );
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
            let error = res.unwrap_err();
            match error {
                ByteConversion(ToSliceTooSmall { found, expected }) => {
                    assert_eq!(found, i);
                    assert_eq!(expected, 7);
                    assert_eq!(
                        error.to_string(),
                        format!("time stamp: target slice with size {i} is too small, expected size of at least 7")
                    );
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
                ByteConversion(e) => match e {
                    FromSliceTooSmall { found, expected } => {
                        assert_eq!(found, i);
                        assert_eq!(expected, 7);
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
        if let InvalidTimeCode { expected, found } = err {
            assert_eq!(expected, CcsdsTimeCodes::Cds);
            assert_eq!(found, 0);
            assert_eq!(
                err.to_string(),
                "invalid raw time code value 0 for time code Cds"
            );
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

    fn generic_now_test<T: ProvidesDaysLength>(
        timestamp_now: TimeProvider<T>,
        compare_stamp: DateTime<Utc>,
    ) {
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
    fn test_time_now() {
        let timestamp_now = TimeProvider::from_now_with_u16_days().unwrap();
        let compare_stamp = Utc::now();
        generic_now_test(timestamp_now, compare_stamp);
    }

    #[test]
    fn test_time_now_us_prec() {
        let timestamp_now = TimeProvider::from_now_with_u16_days_us_precision().unwrap();
        let compare_stamp = Utc::now();
        generic_now_test(timestamp_now, compare_stamp);
    }

    #[test]
    fn test_time_now_ps_prec() {
        let timestamp_now = TimeProvider::from_now_with_u16_days_ps_precision().unwrap();
        let compare_stamp = Utc::now();
        generic_now_test(timestamp_now, compare_stamp);
    }

    #[test]
    fn test_time_now_ps_prec_u16_days() {
        let timestamp_now = TimeProvider::from_now_with_u16_days_ps_precision().unwrap();
        let compare_stamp = Utc::now();
        generic_now_test(timestamp_now, compare_stamp);
    }

    #[test]
    fn test_time_now_ps_prec_u24_days() {
        let timestamp_now = TimeProvider::from_now_with_u24_days_ps_precision().unwrap();
        let compare_stamp = Utc::now();
        generic_now_test(timestamp_now, compare_stamp);
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
    fn read_u24_stamp_with_us_submillis_precision() {
        let mut time_stamper = TimeProvider::new_with_u24_days(u16::MAX as u32 + 1, 0).unwrap();
        time_stamper.set_submillis_precision(SubmillisPrecision::Microseconds(500));
        let mut write_buf: [u8; 16] = [0; 16];
        let written = time_stamper
            .write_to_bytes(&mut write_buf)
            .expect("Writing timestamp failed");
        // 1 byte pfield + 3 bytes days + 4 bytes ms of day + 2 bytes us precision
        assert_eq!(written, 10);
        let stamp_deserialized = TimeProvider::from_bytes_with_u24_days(&write_buf);
        assert!(stamp_deserialized.is_ok());
        let stamp_deserialized = stamp_deserialized.unwrap();
        assert_eq!(stamp_deserialized.len_as_bytes(), 10);
        assert_eq!(stamp_deserialized.ccsds_days(), u16::MAX as u32 + 1);
        assert!(stamp_deserialized.submillis_precision().is_some());
        let submillis_rec = stamp_deserialized.submillis_precision().unwrap();
        if let SubmillisPrecision::Microseconds(us) = submillis_rec {
            assert_eq!(us, 500);
        } else {
            panic!("Wrong precision field detected");
        }
    }

    #[test]
    fn read_u24_stamp_with_ps_submillis_precision() {
        let mut time_stamper = TimeProvider::new_with_u24_days(u16::MAX as u32 + 1, 0).unwrap();
        time_stamper.set_submillis_precision(SubmillisPrecision::Picoseconds(5e8 as u32));
        let mut write_buf: [u8; 16] = [0; 16];
        let written = time_stamper
            .write_to_bytes(&mut write_buf)
            .expect("Writing timestamp failed");
        // 1 byte pfield + 3 bytes days + 4 bytes ms of day + 4 bytes us precision
        assert_eq!(written, 12);
        let stamp_deserialized = TimeProvider::from_bytes_with_u24_days(&write_buf);
        assert!(stamp_deserialized.is_ok());
        let stamp_deserialized = stamp_deserialized.unwrap();
        assert_eq!(stamp_deserialized.len_as_bytes(), 12);
        assert_eq!(stamp_deserialized.ccsds_days(), u16::MAX as u32 + 1);
        assert!(stamp_deserialized.submillis_precision().is_some());
        let submillis_rec = stamp_deserialized.submillis_precision().unwrap();
        if let SubmillisPrecision::Picoseconds(ps) = submillis_rec {
            assert_eq!(ps, 5e8 as u32);
        } else {
            panic!("Wrong precision field detected");
        }
    }

    fn generic_dt_case_0_no_prec(subsec_millis: u32) -> DateTime<Utc> {
        NaiveDate::from_ymd_opt(2023, 1, 14)
            .unwrap()
            .and_hms_milli_opt(16, 49, 30, subsec_millis)
            .unwrap()
            .and_local_timezone(Utc)
            .unwrap()
    }

    fn generic_check_dt_case_0<DaysLen: ProvidesDaysLength>(
        time_provider: &TimeProvider<DaysLen>,
        subsec_millis: u32,
        datetime_utc: DateTime<Utc>,
    ) {
        // https://www.timeanddate.com/date/durationresult.html?d1=01&m1=01&y1=1958&d2=14&m2=01&y2=2023
        // Leap years need to be accounted for as well.
        assert_eq!(time_provider.ccsds_days, 23754.into());
        assert_eq!(
            time_provider.ms_of_day,
            30 * 1000 + 49 * 60 * 1000 + 16 * 60 * 60 * 1000 + subsec_millis
        );
        assert_eq!(time_provider.date_time().unwrap(), datetime_utc);
    }

    #[test]
    fn test_creation_from_dt_u16_days() {
        let subsec_millis = 250;
        let datetime_utc = generic_dt_case_0_no_prec(subsec_millis);
        let time_provider = TimeProvider::from_dt_with_u16_days(&datetime_utc).unwrap();
        generic_check_dt_case_0(&time_provider, subsec_millis, datetime_utc);
        let time_provider_2: TimeProvider<DaysLen16Bits> =
            datetime_utc.try_into().expect("conversion failed");
        // Test the TryInto trait impl
        assert_eq!(time_provider, time_provider_2);
    }
    #[test]
    fn test_creation_from_dt_u24_days() {
        let subsec_millis = 250;
        let datetime_utc = generic_dt_case_0_no_prec(subsec_millis);
        let time_provider = TimeProvider::from_dt_with_u24_days(&datetime_utc).unwrap();
        generic_check_dt_case_0(&time_provider, subsec_millis, datetime_utc);
        let time_provider_2: TimeProvider<DaysLen24Bits> =
            datetime_utc.try_into().expect("conversion failed");
        // Test the TryInto trait impl
        assert_eq!(time_provider, time_provider_2);
    }

    fn generic_dt_case_1_us_prec(subsec_millis: u32) -> DateTime<Utc> {
        // 250 ms + 500 us
        let subsec_micros = subsec_millis * 1000 + 500;
        NaiveDate::from_ymd_opt(2023, 1, 14)
            .unwrap()
            .and_hms_micro_opt(16, 49, 30, subsec_micros)
            .unwrap()
            .and_local_timezone(Utc)
            .unwrap()
    }

    fn generic_check_dt_case_1_us_prec<DaysLen: ProvidesDaysLength>(
        time_provider: &TimeProvider<DaysLen>,
        subsec_millis: u32,
        datetime_utc: DateTime<Utc>,
    ) {
        // https://www.timeanddate.com/date/durationresult.html?d1=01&m1=01&y1=1958&d2=14&m2=01&y2=2023
        // Leap years need to be accounted for as well.
        assert_eq!(time_provider.ccsds_days, 23754.into());
        assert_eq!(
            time_provider.ms_of_day,
            30 * 1000 + 49 * 60 * 1000 + 16 * 60 * 60 * 1000 + subsec_millis
        );
        assert!(time_provider.submillis_precision.is_some());
        match time_provider.submillis_precision.unwrap() {
            SubmillisPrecision::Microseconds(us) => {
                assert_eq!(us, 500);
            }
            _ => panic!("unexpected precision field"),
        }
        assert_eq!(time_provider.date_time().unwrap(), datetime_utc);
    }

    #[test]
    fn test_creation_from_dt_u16_days_us_prec() {
        let subsec_millis = 250;
        let datetime_utc = generic_dt_case_1_us_prec(subsec_millis);
        let time_provider =
            TimeProvider::from_dt_with_u16_days_us_precision(&datetime_utc).unwrap();
        generic_check_dt_case_1_us_prec(&time_provider, subsec_millis, datetime_utc);
    }

    #[test]
    fn test_creation_from_dt_u24_days_us_prec() {
        let subsec_millis = 250;
        let datetime_utc = generic_dt_case_1_us_prec(subsec_millis);
        let time_provider =
            TimeProvider::from_dt_with_u24_days_us_precision(&datetime_utc).unwrap();
        generic_check_dt_case_1_us_prec(&time_provider, subsec_millis, datetime_utc);
    }

    fn generic_dt_case_2_ps_prec(subsec_millis: u32) -> (DateTime<Utc>, u32) {
        // 250 ms + 500 us
        let subsec_nanos = subsec_millis * 1000 * 1000 + 500 * 1000;
        let submilli_nanos = subsec_nanos % 10_u32.pow(6);
        (
            NaiveDate::from_ymd_opt(2023, 1, 14)
                .unwrap()
                .and_hms_nano_opt(16, 49, 30, subsec_nanos)
                .unwrap()
                .and_local_timezone(Utc)
                .unwrap(),
            submilli_nanos,
        )
    }

    fn generic_check_dt_case_2_ps_prec<DaysLen: ProvidesDaysLength>(
        time_provider: &TimeProvider<DaysLen>,
        subsec_millis: u32,
        submilli_nanos: u32,
        datetime_utc: DateTime<Utc>,
    ) {
        // https://www.timeanddate.com/date/durationresult.html?d1=01&m1=01&y1=1958&d2=14&m2=01&y2=2023
        // Leap years need to be accounted for as well.
        assert_eq!(time_provider.ccsds_days, 23754.into());
        assert_eq!(
            time_provider.ms_of_day,
            30 * 1000 + 49 * 60 * 1000 + 16 * 60 * 60 * 1000 + subsec_millis
        );
        assert!(time_provider.submillis_precision.is_some());
        match time_provider.submillis_precision.unwrap() {
            SubmillisPrecision::Picoseconds(ps) => {
                assert_eq!(ps, submilli_nanos * 1000);
            }
            _ => panic!("unexpected precision field"),
        }
        assert_eq!(time_provider.date_time().unwrap(), datetime_utc);
    }

    #[test]
    fn test_creation_from_dt_u16_days_ps_prec() {
        let subsec_millis = 250;
        let (datetime_utc, submilli_nanos) = generic_dt_case_2_ps_prec(subsec_millis);
        let time_provider =
            TimeProvider::from_dt_with_u16_days_ps_precision(&datetime_utc).unwrap();
        generic_check_dt_case_2_ps_prec(
            &time_provider,
            subsec_millis,
            submilli_nanos,
            datetime_utc,
        );
    }

    #[test]
    fn test_creation_from_dt_u24_days_ps_prec() {
        let subsec_millis = 250;
        let (datetime_utc, submilli_nanos) = generic_dt_case_2_ps_prec(subsec_millis);
        let time_provider =
            TimeProvider::from_dt_with_u24_days_ps_precision(&datetime_utc).unwrap();
        generic_check_dt_case_2_ps_prec(
            &time_provider,
            subsec_millis,
            submilli_nanos,
            datetime_utc,
        );
    }

    #[test]
    fn test_creation_from_unix_stamp_0_u16_days() {
        let unix_secs = 0;
        let subsec_millis = 0;
        let time_provider = TimeProvider::from_unix_secs_with_u16_days(&UnixTimestamp::const_new(
            unix_secs,
            subsec_millis,
        ))
        .expect("creating provider from unix stamp failed");
        assert_eq!(time_provider.ccsds_days, -DAYS_CCSDS_TO_UNIX as u16)
    }

    #[test]
    fn test_creation_from_unix_stamp_0_u24_days() {
        let unix_secs = 0;
        let subsec_millis = 0;
        let time_provider = TimeProvider::from_unix_secs_with_u24_days(&UnixTimestamp::const_new(
            unix_secs,
            subsec_millis,
        ))
        .expect("creating provider from unix stamp failed");
        assert_eq!(time_provider.ccsds_days, (-DAYS_CCSDS_TO_UNIX) as u32)
    }

    #[test]
    fn test_creation_from_unix_stamp_1() {
        let subsec_millis = 250;
        let datetime_utc = NaiveDate::from_ymd_opt(2023, 1, 14)
            .unwrap()
            .and_hms_milli_opt(16, 49, 30, subsec_millis)
            .unwrap()
            .and_local_timezone(Utc)
            .unwrap();
        let time_provider = TimeProvider::from_unix_secs_with_u16_days(&datetime_utc.into())
            .expect("creating provider from unix stamp failed");
        // https://www.timeanddate.com/date/durationresult.html?d1=01&m1=01&y1=1958&d2=14&m2=01&y2=2023
        // Leap years need to be accounted for as well.
        assert_eq!(time_provider.ccsds_days, 23754);
        assert_eq!(
            time_provider.ms_of_day,
            30 * 1000 + 49 * 60 * 1000 + 16 * 60 * 60 * 1000 + subsec_millis
        );
        let dt_back = time_provider.date_time().unwrap();
        assert_eq!(datetime_utc, dt_back);
    }

    #[test]
    fn test_creation_0_ccsds_days() {
        let unix_secs = DAYS_CCSDS_TO_UNIX as i64 * SECONDS_PER_DAY as i64;
        let subsec_millis = 0;
        let time_provider = TimeProvider::from_unix_secs_with_u16_days(&UnixTimestamp::const_new(
            unix_secs,
            subsec_millis,
        ))
        .expect("creating provider from unix stamp failed");
        assert_eq!(time_provider.ccsds_days, 0)
    }

    #[test]
    fn test_invalid_creation_from_unix_stamp_days_too_large() {
        let invalid_unix_secs: i64 = (u16::MAX as i64 + 1) * SECONDS_PER_DAY as i64;
        let subsec_millis = 0;
        match TimeProvider::from_unix_secs_with_u16_days(&UnixTimestamp::const_new(
            invalid_unix_secs,
            subsec_millis,
        )) {
            Ok(_) => {
                panic!("creation should not succeed")
            }
            Err(e) => {
                if let TimestampError::Cds(CdsError::InvalidCcsdsDays(days)) = e {
                    assert_eq!(
                        days,
                        unix_to_ccsds_days(invalid_unix_secs / SECONDS_PER_DAY as i64)
                    );
                    assert_eq!(e.to_string(), "cds error: invalid ccsds days 69919");
                } else {
                    panic!("unexpected error {}", e)
                }
            }
        }
    }

    #[test]
    fn test_invalid_creation_from_unix_stamp_before_ccsds_epoch() {
        // This is a unix stamp before the CCSDS epoch (01-01-1958 00:00:00), this should be
        // precisely 31-12-1957 23:59:55
        let unix_secs = DAYS_CCSDS_TO_UNIX * SECONDS_PER_DAY as i32 - 5;
        let subsec_millis = 0;
        match TimeProvider::from_unix_secs_with_u16_days(&UnixTimestamp::const_new(
            unix_secs as i64,
            subsec_millis,
        )) {
            Ok(_) => {
                panic!("creation should not succeed")
            }
            Err(e) => {
                if let TimestampError::DateBeforeCcsdsEpoch(dt) = e {
                    assert_eq!(dt.year(), 1957);
                    assert_eq!(dt.month(), 12);
                    assert_eq!(dt.day(), 31);
                    assert_eq!(dt.hour(), 23);
                    assert_eq!(dt.minute(), 59);
                    assert_eq!(dt.second(), 55);
                } else {
                    panic!("unexpected error {}", e)
                }
            }
        }
    }

    #[test]
    fn test_addition_u16_days_day_increment() {
        let mut provider = TimeProvider::new_with_u16_days(0, MS_PER_DAY - 5 * 1000);
        let seconds_offset = Duration::from_secs(10);
        assert_eq!(provider.ccsds_days, 0);
        assert_eq!(provider.ms_of_day, MS_PER_DAY - 5 * 1000);
        provider += seconds_offset;
        assert_eq!(provider.ccsds_days, 1);
        assert_eq!(provider.ms_of_day, 5000);
    }

    #[test]
    fn test_addition_u16_days() {
        let mut provider = TimeProvider::new_with_u16_days(0, 0);
        let seconds_offset = Duration::from_secs(5);
        assert_eq!(provider.ccsds_days, 0);
        assert_eq!(provider.ms_of_day, 0);
        provider += seconds_offset;
        assert_eq!(provider.ms_of_day, 5000);
        // Add one day and test Add operator
        let provider2 = provider + Duration::from_secs(60 * 60 * 24);
        assert_eq!(provider2.ccsds_days, 1);
        assert_eq!(provider2.ms_of_day, 5000);
    }

    #[test]
    fn test_addition_u24_days() {
        let mut provider = TimeProvider::new_with_u24_days(u16::MAX as u32, 0).unwrap();
        let seconds_offset = Duration::from_secs(5);
        assert_eq!(provider.ccsds_days, u16::MAX as u32);
        assert_eq!(provider.ms_of_day, 0);
        provider += seconds_offset;
        assert_eq!(provider.ms_of_day, 5000);
        // Add one day and test Add operator
        let provider2 = provider + Duration::from_secs(60 * 60 * 24);
        assert_eq!(provider2.ccsds_days, u16::MAX as u32 + 1);
        assert_eq!(provider2.ms_of_day, 5000);
    }

    #[test]
    fn test_dyn_creation_u24_days() {
        let stamp = TimeProvider::new_with_u24_days(u16::MAX as u32 + 1, 24).unwrap();
        let mut buf: [u8; 32] = [0; 32];
        stamp.write_to_bytes(&mut buf).unwrap();
        let dyn_provider = get_dyn_time_provider_from_bytes(&buf);
        assert!(dyn_provider.is_ok());
        let dyn_provider = dyn_provider.unwrap();
        assert_eq!(dyn_provider.ccdsd_time_code(), CcsdsTimeCodes::Cds);
        assert_eq!(dyn_provider.ccsds_days_as_u32(), u16::MAX as u32 + 1);
        assert_eq!(dyn_provider.ms_of_day(), 24);
        assert_eq!(dyn_provider.submillis_precision(), None);
        assert_eq!(
            dyn_provider.len_of_day_seg(),
            LengthOfDaySegment::Long24Bits
        );
    }

    #[test]
    fn test_addition_with_us_precision_u16_days() {
        let mut provider = TimeProvider::new_with_u16_days(0, 0);
        provider.set_submillis_precision(SubmillisPrecision::Microseconds(0));
        let duration = Duration::from_micros(500);
        provider += duration;
        assert!(provider.submillis_precision().is_some());
        let prec = provider.submillis_precision().unwrap();
        if let SubmillisPrecision::Microseconds(us) = prec {
            assert_eq!(us, 500);
        } else {
            panic!("invalid precision {:?}", prec)
        }
    }

    #[test]
    fn test_addition_with_us_precision_u16_days_with_subsec_millis() {
        let mut provider = TimeProvider::new_with_u16_days(0, 0);
        provider.set_submillis_precision(SubmillisPrecision::Microseconds(0));
        let duration = Duration::from_micros(1200);
        provider += duration;
        assert!(provider.submillis_precision().is_some());
        let prec = provider.submillis_precision().unwrap();
        if let SubmillisPrecision::Microseconds(us) = prec {
            assert_eq!(us, 200);
            assert_eq!(provider.ms_of_day, 1);
        } else {
            panic!("invalid precision {:?}", prec)
        }
    }

    #[test]
    fn test_addition_with_us_precision_u16_days_carry_over() {
        let mut provider = TimeProvider::new_with_u16_days(0, 0);
        provider.set_submillis_precision(SubmillisPrecision::Microseconds(800));
        let duration = Duration::from_micros(400);
        provider += duration;
        assert!(provider.submillis_precision().is_some());
        let prec = provider.submillis_precision().unwrap();
        if let SubmillisPrecision::Microseconds(us) = prec {
            assert_eq!(us, 200);
            assert_eq!(provider.ms_of_day, 1);
        } else {
            panic!("invalid precision {:?}", prec)
        }
    }

    #[test]
    fn test_addition_with_ps_precision_u16_days() {
        let mut provider = TimeProvider::new_with_u16_days(0, 0);
        provider.set_submillis_precision(SubmillisPrecision::Picoseconds(0));
        // 500 us as ns
        let duration = Duration::from_nanos(500 * 10u32.pow(3) as u64);
        provider += duration;
        assert!(provider.submillis_precision().is_some());
        let prec = provider.submillis_precision().unwrap();
        if let SubmillisPrecision::Picoseconds(ps) = prec {
            assert_eq!(ps, 500 * 10_u32.pow(6));
        } else {
            panic!("invalid precision {:?}", prec)
        }
    }

    #[test]
    fn test_addition_on_ref() {
        // This test case also tests the case where there is no submillis precision but subsecond
        // milliseconds.
        let provider_ref = &TimeProvider::new_with_u16_days(2, 500);
        let new_stamp = provider_ref + Duration::from_millis(2 * 24 * 60 * 60 * 1000 + 500);
        assert_eq!(new_stamp.ccsds_days_as_u32(), 4);
        assert_eq!(new_stamp.ms_of_day, 1000);
    }

    fn check_ps_and_carryover(prec: SubmillisPrecision, ms_of_day: u32, val: u32) {
        if let SubmillisPrecision::Picoseconds(ps) = prec {
            assert_eq!(ps, val);
            assert_eq!(ms_of_day, 1);
        } else {
            panic!("invalid precision {:?}", prec)
        }
    }
    #[test]
    fn test_addition_with_ps_precision_u16_days_with_subsec_millis() {
        let mut provider = TimeProvider::new_with_u16_days(0, 0);
        provider.set_submillis_precision(SubmillisPrecision::Picoseconds(0));
        // 1200 us as ns
        let duration = Duration::from_nanos(1200 * 10u32.pow(3) as u64);
        provider += duration;
        assert!(provider.submillis_precision().is_some());
        let prec = provider.submillis_precision().unwrap();
        check_ps_and_carryover(prec, provider.ms_of_day, 200 * 10_u32.pow(6));
    }

    #[test]
    fn test_addition_with_ps_precision_u16_days_carryover() {
        let mut provider = TimeProvider::new_with_u16_days(0, 0);
        // 800 us as ps
        provider.set_submillis_precision(SubmillisPrecision::Picoseconds(800 * 10_u32.pow(6)));
        // 400 us as ns
        let duration = Duration::from_nanos(400 * 10u32.pow(3) as u64);
        provider += duration;
        assert!(provider.submillis_precision().is_some());
        let prec = provider.submillis_precision().unwrap();
        check_ps_and_carryover(prec, provider.ms_of_day, 200 * 10_u32.pow(6));
    }

    #[test]
    fn test_dyn_creation_u16_days_with_precision() {
        let mut stamp = TimeProvider::new_with_u16_days(24, 24);
        stamp.set_submillis_precision(SubmillisPrecision::Microseconds(666));
        let mut buf: [u8; 32] = [0; 32];
        stamp.write_to_bytes(&mut buf).unwrap();
        let dyn_provider = get_dyn_time_provider_from_bytes(&buf);
        assert!(dyn_provider.is_ok());
        let dyn_provider = dyn_provider.unwrap();
        assert_eq!(dyn_provider.ccdsd_time_code(), CcsdsTimeCodes::Cds);
        assert_eq!(dyn_provider.ccsds_days_as_u32(), 24);
        assert_eq!(dyn_provider.ms_of_day(), 24);
        assert_eq!(
            dyn_provider.len_of_day_seg(),
            LengthOfDaySegment::Short16Bits
        );
        assert!(dyn_provider.submillis_precision().is_some());
        if let SubmillisPrecision::Microseconds(us) = dyn_provider.submillis_precision().unwrap() {
            assert_eq!(us, 666);
        }
    }

    #[test]
    fn test_new_u24_days_too_large() {
        let time_provider = TimeProvider::new_with_u24_days(2_u32.pow(24), 0);
        assert!(time_provider.is_err());
        let e = time_provider.unwrap_err();
        if let CdsError::InvalidCcsdsDays(days) = e {
            assert_eq!(days, 2_u32.pow(24) as i64);
        } else {
            panic!("unexpected error {}", e)
        }
    }

    #[test]
    fn test_from_dt_invalid_time() {
        // Date before CCSDS epoch
        let datetime_utc = NaiveDate::from_ymd_opt(1957, 12, 31)
            .unwrap()
            .and_hms_milli_opt(23, 59, 59, 999)
            .unwrap()
            .and_local_timezone(Utc)
            .unwrap();
        let time_provider = TimeProvider::from_dt_with_u24_days(&datetime_utc);
        assert!(time_provider.is_err());
        if let TimestampError::DateBeforeCcsdsEpoch(dt) = time_provider.unwrap_err() {
            assert_eq!(dt, datetime_utc);
        }
    }

    #[test]
    fn test_eq() {
        let stamp0 = TimeProvider::new_with_u16_days(0, 0);
        let mut buf: [u8; 7] = [0; 7];
        stamp0.write_to_bytes(&mut buf).unwrap();
        let stamp1 = TimeProvider::from_bytes_with_u16_days(&buf).unwrap();
        assert_eq!(stamp0, stamp1);
        assert!(stamp0 >= stamp1);
        assert!(stamp1 <= stamp0);
    }

    #[test]
    fn test_ord() {
        let stamp0 = TimeProvider::new_with_u24_days(0, 0).unwrap();
        let stamp1 = TimeProvider::new_with_u24_days(0, 50000).unwrap();
        let mut stamp2 = TimeProvider::new_with_u24_days(0, 50000).unwrap();
        stamp2.set_submillis_precision(SubmillisPrecision::Microseconds(500));
        let stamp3 = TimeProvider::new_with_u24_days(1, 0).unwrap();
        assert!(stamp1 > stamp0);
        assert!(stamp2 > stamp0);
        assert!(stamp2 > stamp1);
        assert!(stamp3 > stamp0);
        assert!(stamp3 > stamp1);
        assert!(stamp3 > stamp2);
    }

    #[test]
    fn test_conversion() {
        let mut stamp_small = TimeProvider::new_with_u16_days(u16::MAX, 500);
        let stamp_larger: TimeProvider<DaysLen24Bits> = stamp_small.into();
        assert_eq!(stamp_larger.ccsds_days_as_u32(), u16::MAX as u32);
        assert_eq!(stamp_larger.ms_of_day(), 500);
        stamp_small = stamp_larger.try_into().unwrap();
        assert_eq!(stamp_small.ccsds_days_as_u32(), u16::MAX as u32);
        assert_eq!(stamp_small.ms_of_day(), 500);
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
