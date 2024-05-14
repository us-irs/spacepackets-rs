//! Module to generate or read CCSDS Unsegmented (CUC) timestamps as specified in
//! [CCSDS 301.0-B-4](https://public.ccsds.org/Pubs/301x0b4e1.pdf) section 3.2 .
//!
//! The core data structure to do this is the [CucTime] struct which provides a CUC time object
//! using the CCSDS Epoch.
#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

use core::fmt::{Debug, Display, Formatter};
use core::ops::{Add, AddAssign};
use core::time::Duration;
use core::u64;

use crate::ByteConversionError;

#[cfg(feature = "std")]
use super::StdTimestampError;
use super::{
    ccsds_epoch_to_unix_epoch, ccsds_time_code_from_p_field, unix_epoch_to_ccsds_epoch,
    CcsdsTimeCode, CcsdsTimeProvider, DateBeforeCcsdsEpochError, TimeReader, TimeWriter,
    TimestampError, UnixTime,
};
#[cfg(feature = "std")]
use std::error::Error;
#[cfg(feature = "std")]
use std::time::SystemTime;

#[cfg(feature = "chrono")]
use chrono::Datelike;

const MIN_CUC_LEN: usize = 2;

/// Base value for the preamble field for a time field parser to determine the time field type.
pub const P_FIELD_BASE: u8 = (CcsdsTimeCode::CucCcsdsEpoch as u8) << 4;
/// Maximum length if the preamble field is not extended.
pub const MAX_CUC_LEN_SMALL_PREAMBLE: usize = 8;

#[derive(Copy, Clone, PartialEq, Eq, Debug)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum FractionalResolution {
    /// No fractional part, only second resolution
    Seconds = 0,
    /// 255 fractional parts, resulting in 1/255 ~= 4 ms fractional resolution
    FourMs = 1,
    /// 65535 fractional parts, resulting in 1/65535 ~= 15 us fractional resolution
    FifteenUs = 2,
    /// 16777215 fractional parts, resulting in 1/16777215 ~= 60 ns fractional resolution
    SixtyNs = 3,
}

impl TryFrom<u8> for FractionalResolution {
    type Error = ();

    fn try_from(v: u8) -> Result<Self, Self::Error> {
        match v {
            0 => Ok(FractionalResolution::Seconds),
            1 => Ok(FractionalResolution::FourMs),
            2 => Ok(FractionalResolution::FifteenUs),
            3 => Ok(FractionalResolution::SixtyNs),
            _ => Err(()),
        }
    }
}

/// Please note that this function will panic if the fractional counter is not smaller than
/// the maximum number of fractions allowed for the particular resolution.
/// (e.g. passing 270 when the resolution only allows 255 values).
#[inline]
pub fn convert_fractional_part_to_ns(fractional_part: FractionalPart) -> u64 {
    let div = fractional_res_to_div(fractional_part.resolution);
    assert!(fractional_part.counter <= div);
    10_u64.pow(9) * fractional_part.counter as u64 / div as u64
}

#[inline(always)]
pub const fn fractional_res_to_div(res: FractionalResolution) -> u32 {
    // We do not use the full possible range for a given resolution. This is because if we did
    // that, the largest value would be equal to the counter being incremented by one. Thus, the
    // smallest allowed fractions value is 0 while the largest allowed fractions value is the
    // closest fractions value to the next counter increment.
    2_u32.pow(8 * res as u32) - 1
}

/// Calculate the fractional part for a given resolution and subsecond nanoseconds.
/// Please note that this function will panic if the passed nanoseconds exceeds 1 second
/// as a nanosecond (10 to the power of 9). Furthermore, it will return [None] if the
/// given resolution is [FractionalResolution::Seconds].
pub fn fractional_part_from_subsec_ns(res: FractionalResolution, ns: u64) -> FractionalPart {
    if res == FractionalResolution::Seconds {
        return FractionalPart::new_with_seconds_resolution();
    }
    let sec_as_ns = 10_u64.pow(9);
    if ns > sec_as_ns {
        panic!("passed nanosecond value larger than 1 second");
    }
    let resolution_divisor = fractional_res_to_div(res) as u64;
    // This is probably the cheapest way to calculate the fractional part without using expensive
    // floating point division.
    let fractional_counter = ns * (resolution_divisor + 1) / sec_as_ns;
    FractionalPart {
        resolution: res,
        counter: fractional_counter as u32,
    }
}

#[derive(Copy, Clone, PartialEq, Eq, Debug)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum CucError {
    InvalidCounterWidth(u8),
    /// Invalid counter supplied.
    InvalidCounter {
        width: u8,
        counter: u64,
    },
    InvalidFractions {
        resolution: FractionalResolution,
        value: u64,
    },
    LeapSecondCorrectionError,
    DateBeforeCcsdsEpoch(DateBeforeCcsdsEpochError),
}

impl Display for CucError {
    fn fmt(&self, f: &mut Formatter<'_>) -> core::fmt::Result {
        match self {
            CucError::InvalidCounterWidth(w) => {
                write!(f, "invalid cuc counter byte width {w}")
            }
            CucError::InvalidCounter { width, counter } => {
                write!(f, "invalid cuc counter {counter} for width {width}")
            }
            CucError::InvalidFractions { resolution, value } => {
                write!(
                    f,
                    "invalid cuc fractional part {value} for resolution {resolution:?}"
                )
            }
            CucError::LeapSecondCorrectionError => {
                write!(f, "error while correcting for leap seconds")
            }
            CucError::DateBeforeCcsdsEpoch(e) => {
                write!(f, "date before ccsds epoch: {e}")
            }
        }
    }
}

#[cfg(feature = "std")]
impl Error for CucError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            CucError::DateBeforeCcsdsEpoch(e) => Some(e),
            _ => None,
        }
    }
}

impl From<DateBeforeCcsdsEpochError> for CucError {
    fn from(e: DateBeforeCcsdsEpochError) -> Self {
        Self::DateBeforeCcsdsEpoch(e)
    }
}

/// Tuple object where the first value is the width of the counter and the second value
/// is the counter value.
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct WidthCounterPair(pub u8, pub u32);

#[derive(Copy, Clone, PartialEq, Eq, Debug)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct FractionalPart {
    pub resolution: FractionalResolution,
    pub counter: u32,
}

impl FractionalPart {
    #[inline]
    pub const fn new(resolution: FractionalResolution, counter: u32) -> Self {
        let div = fractional_res_to_div(resolution);
        assert!(counter <= div, "invalid counter for resolution");
        Self {
            resolution,
            counter,
        }
    }

    /// An empty fractional part for second resolution only.
    #[inline]
    pub const fn new_with_seconds_resolution() -> Self {
        Self::new(FractionalResolution::Seconds, 0)
    }

    /// Helper method which simply calls [Self::new_with_seconds_resolution].
    #[inline]
    pub const fn new_empty() -> Self {
        Self::new_with_seconds_resolution()
    }

    #[inline]
    pub fn new_checked(resolution: FractionalResolution, counter: u32) -> Option<Self> {
        let div = fractional_res_to_div(resolution);
        if counter > div {
            return None;
        }
        Some(Self {
            resolution,
            counter,
        })
    }

    #[inline]
    pub fn resolution(&self) -> FractionalResolution {
        self.resolution
    }

    #[inline]
    pub fn counter(&self) -> u32 {
        self.counter
    }

    #[inline]
    pub fn no_fractional_part(&self) -> bool {
        self.resolution == FractionalResolution::Seconds
    }
}

/// This object is the abstraction for the CCSDS Unsegmented Time Code (CUC) using the CCSDS epoch
/// and a small preamble field.
///
/// It has the capability to generate and read timestamps as specified in the CCSDS 301.0-B-4
/// section 3.2 . The preamble field only has one byte, which allows a time code representation
/// through the year 2094. The time is represented as a simple binary counter starting from the
/// fixed CCSDS epoch 1958-01-01T00:00:00+00:00 using the TAI reference time scale. This time
/// code provides the advantage of being truly monotonic.
/// It is possible to provide subsecond accuracy using the fractional field with various available
/// [resolutions][FractionalResolution].
///
/// Having a preamble field of one byte limits the width of the counter
/// type (generally seconds) to 4 bytes and the width of the fractions type to 3 bytes. This limits
/// the maximum time stamp size to [MAX_CUC_LEN_SMALL_PREAMBLE] (8 bytes).
///
/// Please note that this object does not implement the [CcsdsTimeProvider] trait by itself because
/// leap seconds corrections need to be applied to support the trait methods. Instead, it needs
/// to be converted to a [CucTimeWithLeapSecs] object using the [Self::to_leap_sec_helper] method.
///
/// This time code is not UTC based. Conversion to UTC based times, for example a UNIX timestamp,
/// can be performed by subtracting the current number of leap seconds.
///
/// # Example
///
/// ```
/// use spacepackets::time::cuc::{FractionalResolution, CucTime};
/// use spacepackets::time::{TimeWriter, CcsdsTimeCode, TimeReader, CcsdsTimeProvider};
///
/// const LEAP_SECONDS: u32 = 37;
///
/// // Highest fractional resolution
/// let timestamp_now = CucTime::now(FractionalResolution::SixtyNs, LEAP_SECONDS)
///     .expect("creating cuc stamp failed");
/// let mut raw_stamp = [0; 16];
/// {
///     let written = timestamp_now.write_to_bytes(&mut raw_stamp).expect("writing timestamp failed");
///     assert_eq!((raw_stamp[0] >> 4) & 0b111, CcsdsTimeCode::CucCcsdsEpoch as u8);
///     // 1 byte preamble + 4 byte counter + 3 byte fractional part
///     assert_eq!(written, 8);
/// }
/// {
///     let read_result = CucTime::from_bytes(&raw_stamp);
///     assert!(read_result.is_ok());
///     let stamp_deserialized = read_result.unwrap();
///     assert_eq!(stamp_deserialized, timestamp_now);
/// }
/// ```
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct CucTime {
    pfield: u8,
    counter: WidthCounterPair,
    fractions: FractionalPart,
}

/// This object is a wrapper object around the [CucTime] object which also tracks
/// the leap seconds. This is necessary to implement the [CcsdsTimeProvider] trait.
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct CucTimeWithLeapSecs {
    pub time: CucTime,
    pub leap_seconds: u32,
}

impl CucTimeWithLeapSecs {
    #[inline]
    pub fn new(time: CucTime, leap_seconds: u32) -> Self {
        Self { time, leap_seconds }
    }
}

#[inline]
pub fn pfield_len(pfield: u8) -> usize {
    if ((pfield >> 7) & 0b1) == 1 {
        return 2;
    }
    1
}

impl CucTime {
    /// Create a time provider with a four byte counter and no fractional part.
    #[inline]
    pub fn new(counter: u32) -> Self {
        // These values are definitely valid, so it is okay to unwrap here.
        Self::new_generic(
            WidthCounterPair(4, counter),
            FractionalPart::new_with_seconds_resolution(),
        )
        .unwrap()
    }

    /// Like [CucTime::new] but allow to supply a fractional part as well.
    #[inline]
    pub fn new_with_fractions(counter: u32, fractions: FractionalPart) -> Result<Self, CucError> {
        Self::new_generic(WidthCounterPair(4, counter), fractions)
    }

    /// Fractions with a resolution of ~ 4 ms
    #[inline]
    pub fn new_with_coarse_fractions(counter: u32, subsec_fractions: u8) -> Self {
        // These values are definitely valid, so it is okay to unwrap here.
        Self::new_generic(
            WidthCounterPair(4, counter),
            FractionalPart {
                resolution: FractionalResolution::FourMs,
                counter: subsec_fractions as u32,
            },
        )
        .unwrap()
    }

    /// Fractions with a resolution of ~ 16 us
    #[inline]
    pub fn new_with_medium_fractions(counter: u32, subsec_fractions: u16) -> Self {
        // These values are definitely valid, so it is okay to unwrap here.
        Self::new_generic(
            WidthCounterPair(4, counter),
            FractionalPart {
                resolution: FractionalResolution::FifteenUs,
                counter: subsec_fractions as u32,
            },
        )
        .unwrap()
    }

    /// Fractions with a resolution of ~ 60 ns. The fractional part value is limited by the
    /// 24 bits of the fractional field, so this function will fail with
    /// [CucError::InvalidFractions] if the fractional value exceeds the value.
    #[inline]
    pub fn new_with_fine_fractions(counter: u32, subsec_fractions: u32) -> Result<Self, CucError> {
        Self::new_generic(
            WidthCounterPair(4, counter),
            FractionalPart {
                resolution: FractionalResolution::SixtyNs,
                counter: subsec_fractions,
            },
        )
    }

    /// This function will return the current time as a CUC timestamp.
    /// The counter width will always be set to 4 bytes because the normal CCSDS epoch will overflow
    /// when using less than that.
    ///
    /// The CUC timestamp uses TAI as the reference time system. Therefore, leap second corrections
    /// must be applied on top of the UTC based time retrieved from the system in addition to the
    /// conversion to the CCSDS epoch.
    #[cfg(feature = "std")]
    pub fn now(
        fraction_resolution: FractionalResolution,
        leap_seconds: u32,
    ) -> Result<Self, StdTimestampError> {
        let now = SystemTime::now().duration_since(SystemTime::UNIX_EPOCH)?;
        let mut counter =
            u32::try_from(unix_epoch_to_ccsds_epoch(now.as_secs() as i64)).map_err(|_| {
                TimestampError::Cuc(CucError::InvalidCounter {
                    width: 4,
                    counter: now.as_secs(),
                })
            })?;
        counter = counter
            .checked_add(leap_seconds)
            .ok_or(TimestampError::Cuc(CucError::LeapSecondCorrectionError))?;
        if fraction_resolution == FractionalResolution::Seconds {
            return Ok(Self::new(counter));
        }
        let fractions =
            fractional_part_from_subsec_ns(fraction_resolution, now.subsec_nanos() as u64);
        Self::new_with_fractions(counter, fractions)
            .map_err(|e| StdTimestampError::Timestamp(e.into()))
    }

    /// Updates the current time stamp from the current time. The fractional field width remains
    /// the same and will be updated accordingly.
    ///
    /// The CUC timestamp uses TAI as the reference time system. Therefore, leap second corrections
    /// must be applied on top of the UTC based time retrieved from the system in addition to the
    /// conversion to the CCSDS epoch.
    #[cfg(feature = "std")]
    pub fn update_from_now(&mut self, leap_seconds: u32) -> Result<(), StdTimestampError> {
        let now = SystemTime::now().duration_since(SystemTime::UNIX_EPOCH)?;
        self.counter.1 = unix_epoch_to_ccsds_epoch(now.as_secs() as i64) as u32;
        self.counter.1 = self
            .counter
            .1
            .checked_add(leap_seconds)
            .ok_or(TimestampError::Cuc(CucError::LeapSecondCorrectionError))?;
        if let FractionalResolution::Seconds = self.fractions.resolution {
            self.fractions = fractional_part_from_subsec_ns(
                self.fractions.resolution,
                now.subsec_nanos() as u64,
            );
            return Ok(());
        }
        Ok(())
    }

    #[cfg(feature = "chrono")]
    pub fn from_chrono_date_time(
        dt: &chrono::DateTime<chrono::Utc>,
        res: FractionalResolution,
        leap_seconds: u32,
    ) -> Result<Self, CucError> {
        // Year before CCSDS epoch is invalid.
        if dt.year() < 1958 {
            return Err(DateBeforeCcsdsEpochError(UnixTime::from(*dt)).into());
        }
        let counter = dt
            .timestamp()
            .checked_add(i64::from(leap_seconds))
            .ok_or(CucError::LeapSecondCorrectionError)?;
        Self::new_generic(
            WidthCounterPair(4, counter as u32),
            fractional_part_from_subsec_ns(res, dt.timestamp_subsec_nanos() as u64),
        )
    }

    /// Generates a CUC timestamp from a UNIX timestamp with a width of 4. This width is able
    /// to accomodate all possible UNIX timestamp values.
    pub fn from_unix_time(
        unix_time: &UnixTime,
        res: FractionalResolution,
        leap_seconds: u32,
    ) -> Result<Self, CucError> {
        let counter = unix_epoch_to_ccsds_epoch(unix_time.secs);
        // Negative CCSDS epoch is invalid.
        if counter < 0 {
            return Err(DateBeforeCcsdsEpochError(*unix_time).into());
        }
        // We already excluded negative values, so the conversion to u64 should always work.
        let mut counter = u32::try_from(counter).map_err(|_| CucError::InvalidCounter {
            width: 4,
            counter: counter as u64,
        })?;
        counter = counter
            .checked_add(leap_seconds)
            .ok_or(CucError::LeapSecondCorrectionError)?;
        let fractions =
            fractional_part_from_subsec_ns(res, unix_time.subsec_millis() as u64 * 10_u64.pow(6));
        Self::new_generic(WidthCounterPair(4, counter as u32), fractions)
    }

    /// Most generic constructor which allows full configurability for the counter and for the
    /// fractions.
    #[inline]
    pub fn new_generic(
        width_and_counter: WidthCounterPair,
        fractions: FractionalPart,
    ) -> Result<Self, CucError> {
        Self::verify_counter_width(width_and_counter.0)?;
        if width_and_counter.1 > (2u64.pow(width_and_counter.0 as u32 * 8) - 1) as u32 {
            return Err(CucError::InvalidCounter {
                width: width_and_counter.0,
                counter: width_and_counter.1.into(),
            });
        }
        Self::verify_fractions_value(fractions)?;
        Ok(Self {
            pfield: Self::build_p_field(width_and_counter.0, fractions.resolution),
            counter: width_and_counter,
            fractions,
        })
    }

    #[inline]
    pub fn ccsds_time_code(&self) -> CcsdsTimeCode {
        CcsdsTimeCode::CucCcsdsEpoch
    }

    #[inline]
    pub fn width_counter_pair(&self) -> WidthCounterPair {
        self.counter
    }

    #[inline]
    pub fn counter_width(&self) -> u8 {
        self.counter.0
    }

    #[inline]
    pub fn counter(&self) -> u32 {
        self.counter.1
    }

    /// Subsecond fractional part of the CUC time.
    #[inline]
    pub fn fractions(&self) -> FractionalPart {
        self.fractions
    }

    #[inline]
    pub fn to_leap_sec_helper(&self, leap_seconds: u32) -> CucTimeWithLeapSecs {
        CucTimeWithLeapSecs::new(*self, leap_seconds)
    }

    #[inline]
    pub fn set_fractions(&mut self, fractions: FractionalPart) -> Result<(), CucError> {
        Self::verify_fractions_value(fractions)?;
        self.fractions = fractions;
        self.update_p_field_fractions();
        Ok(())
    }

    /// Set a fractional resolution. Please note that this function will reset the fractional value
    /// to 0 if the resolution changes.
    #[inline]
    pub fn set_fractional_resolution(&mut self, res: FractionalResolution) {
        if res == FractionalResolution::Seconds {
            self.fractions = FractionalPart::new_with_seconds_resolution();
        }
        if res != self.fractions().resolution() {
            self.fractions = FractionalPart::new(res, 0);
        }
    }

    #[inline]
    fn build_p_field(counter_width: u8, resolution: FractionalResolution) -> u8 {
        let mut pfield = P_FIELD_BASE;
        if !(1..=4).contains(&counter_width) {
            // Okay to panic here, this function is private and all input values should
            // have been sanitized
            panic!("invalid counter width {} for cuc timestamp", counter_width);
        }
        pfield |= (counter_width - 1) << 2;
        if resolution != FractionalResolution::Seconds {
            if !(1..=3).contains(&(resolution as u8)) {
                // Okay to panic here, this function is private and all input values should
                // have been sanitized
                panic!("invalid fractions width {:?} for cuc timestamp", resolution);
            }
            pfield |= resolution as u8;
        }
        pfield
    }

    #[inline]
    fn update_p_field_fractions(&mut self) {
        self.pfield &= !(0b11);
        self.pfield |= self.fractions.resolution() as u8;
    }

    #[inline]
    pub fn len_cntr_from_pfield(pfield: u8) -> u8 {
        ((pfield >> 2) & 0b11) + 1
    }

    #[inline]
    pub fn len_fractions_from_pfield(pfield: u8) -> u8 {
        pfield & 0b11
    }

    #[inline]
    pub fn unix_secs(&self, leap_seconds: u32) -> i64 {
        ccsds_epoch_to_unix_epoch(self.counter.1 as i64)
            .checked_sub(leap_seconds as i64)
            .unwrap()
    }

    #[inline]
    pub fn subsec_millis(&self) -> u16 {
        (self.subsec_nanos() / 1_000_000) as u16
    }

    /// This returns the length of the individual components of the CUC timestamp in addition
    /// to the total size.
    ///
    /// This function will return a tuple where the first value is the byte width of the
    /// counter, the second value is the byte width of the fractional part, and the third
    /// components is the total size.
    pub fn len_components_and_total_from_pfield(pfield: u8) -> (u8, u8, usize) {
        let base_len: usize = 1;
        let cntr_len = Self::len_cntr_from_pfield(pfield);
        let fractions_len = Self::len_fractions_from_pfield(pfield);
        (
            cntr_len,
            fractions_len,
            base_len + cntr_len as usize + fractions_len as usize,
        )
    }

    #[inline]
    pub fn len_packed_from_pfield(pfield: u8) -> usize {
        let mut base_len: usize = 1;
        base_len += Self::len_cntr_from_pfield(pfield) as usize;
        base_len += Self::len_fractions_from_pfield(pfield) as usize;
        base_len
    }

    /// Verifies the raw width parameter.
    #[inline]
    fn verify_counter_width(width: u8) -> Result<(), CucError> {
        if width == 0 || width > 4 {
            return Err(CucError::InvalidCounterWidth(width));
        }
        Ok(())
    }

    #[inline]
    fn verify_fractions_value(val: FractionalPart) -> Result<(), CucError> {
        if val.counter > 2u32.pow((val.resolution as u32) * 8) - 1 {
            return Err(CucError::InvalidFractions {
                resolution: val.resolution,
                value: val.counter as u64,
            });
        }
        Ok(())
    }

    #[inline]
    fn len_as_bytes(&self) -> usize {
        Self::len_packed_from_pfield(self.pfield)
    }

    #[inline]
    fn subsec_nanos(&self) -> u32 {
        if self.fractions.resolution() == FractionalResolution::Seconds {
            return 0;
        }
        // Rounding down here is the correct approach.
        convert_fractional_part_to_ns(self.fractions) as u32
    }
}

impl TimeReader for CucTime {
    fn from_bytes(buf: &[u8]) -> Result<Self, TimestampError> {
        if buf.len() < MIN_CUC_LEN {
            return Err(TimestampError::ByteConversion(
                ByteConversionError::FromSliceTooSmall {
                    expected: MIN_CUC_LEN,
                    found: buf.len(),
                },
            ));
        }
        match ccsds_time_code_from_p_field(buf[0]) {
            Ok(code) => {
                if code != CcsdsTimeCode::CucCcsdsEpoch {
                    return Err(TimestampError::InvalidTimeCode {
                        expected: CcsdsTimeCode::CucCcsdsEpoch,
                        found: code as u8,
                    });
                }
            }
            Err(raw) => {
                return Err(TimestampError::InvalidTimeCode {
                    expected: CcsdsTimeCode::CucCcsdsEpoch,
                    found: raw,
                });
            }
        }
        let (cntr_len, fractions_len, total_len) =
            Self::len_components_and_total_from_pfield(buf[0]);
        if buf.len() < total_len {
            return Err(TimestampError::ByteConversion(
                ByteConversionError::FromSliceTooSmall {
                    expected: total_len,
                    found: buf.len(),
                },
            ));
        }
        let mut current_idx = 1;
        let counter = match cntr_len {
            1 => buf[current_idx] as u32,
            2 => u16::from_be_bytes(buf[current_idx..current_idx + 2].try_into().unwrap()) as u32,
            3 => {
                let mut tmp_buf: [u8; 4] = [0; 4];
                tmp_buf[1..4].copy_from_slice(&buf[current_idx..current_idx + 3]);
                u32::from_be_bytes(tmp_buf)
            }
            4 => u32::from_be_bytes(buf[current_idx..current_idx + 4].try_into().unwrap()),
            _ => panic!("unreachable match arm"),
        };
        current_idx += cntr_len as usize;
        let mut fractions = FractionalPart::new_with_seconds_resolution();
        if fractions_len > 0 {
            match fractions_len {
                1 => {
                    fractions = FractionalPart::new(
                        fractions_len.try_into().unwrap(),
                        buf[current_idx] as u32,
                    )
                }
                2 => {
                    fractions = FractionalPart::new(
                        fractions_len.try_into().unwrap(),
                        u16::from_be_bytes(buf[current_idx..current_idx + 2].try_into().unwrap())
                            as u32,
                    )
                }
                3 => {
                    let mut tmp_buf: [u8; 4] = [0; 4];
                    tmp_buf[1..4].copy_from_slice(&buf[current_idx..current_idx + 3]);
                    fractions = FractionalPart::new(
                        fractions_len.try_into().unwrap(),
                        u32::from_be_bytes(tmp_buf),
                    )
                }
                _ => panic!("unreachable match arm"),
            }
        }
        let provider = Self::new_generic(WidthCounterPair(cntr_len, counter), fractions)?;
        Ok(provider)
    }
}

impl TimeWriter for CucTime {
    fn write_to_bytes(&self, bytes: &mut [u8]) -> Result<usize, TimestampError> {
        // Cross check the sizes of the counters against byte widths in the ctor
        if bytes.len() < self.len_as_bytes() {
            return Err(TimestampError::ByteConversion(
                ByteConversionError::ToSliceTooSmall {
                    found: bytes.len(),
                    expected: self.len_as_bytes(),
                },
            ));
        }
        bytes[0] = self.pfield;
        let mut current_idx: usize = 1;
        match self.counter.0 {
            1 => {
                bytes[current_idx] = self.counter.1 as u8;
            }
            2 => {
                bytes[current_idx..current_idx + 2]
                    .copy_from_slice(&(self.counter.1 as u16).to_be_bytes());
            }
            3 => {
                bytes[current_idx..current_idx + 3]
                    .copy_from_slice(&self.counter.1.to_be_bytes()[1..4]);
            }
            4 => {
                bytes[current_idx..current_idx + 4].copy_from_slice(&self.counter.1.to_be_bytes());
            }
            // Should never happen
            _ => panic!("invalid counter width value"),
        }
        current_idx += self.counter.0 as usize;
        match self.fractions.resolution() {
            FractionalResolution::FourMs => bytes[current_idx] = self.fractions.counter as u8,
            FractionalResolution::FifteenUs => bytes[current_idx..current_idx + 2]
                .copy_from_slice(&(self.fractions.counter as u16).to_be_bytes()),
            FractionalResolution::SixtyNs => bytes[current_idx..current_idx + 3]
                .copy_from_slice(&self.fractions.counter.to_be_bytes()[1..4]),
            _ => (),
        }
        current_idx += self.fractions.resolution as usize;
        Ok(current_idx)
    }

    fn len_written(&self) -> usize {
        self.len_as_bytes()
    }
}

impl CcsdsTimeProvider for CucTimeWithLeapSecs {
    #[inline]
    fn len_as_bytes(&self) -> usize {
        self.time.len_as_bytes()
    }

    #[inline]
    fn p_field(&self) -> (usize, [u8; 2]) {
        (1, [self.time.pfield, 0])
    }

    #[inline]
    fn ccdsd_time_code(&self) -> CcsdsTimeCode {
        self.time.ccsds_time_code()
    }

    #[inline]
    fn unix_secs(&self) -> i64 {
        self.time.unix_secs(self.leap_seconds)
    }

    #[inline]
    fn subsec_nanos(&self) -> u32 {
        self.time.subsec_nanos()
    }
}

// TODO: Introduce more overflow checks here.
fn get_time_values_after_duration_addition(
    time: &CucTime,
    duration: Duration,
) -> (u32, FractionalPart) {
    let mut new_counter = time.counter.1;
    let subsec_nanos = duration.subsec_nanos();
    let mut increment_counter = |amount: u32| {
        let mut sum: u64 = 0;
        let mut counter_inc_handler = |max_val: u64| {
            sum = new_counter as u64 + amount as u64;
            if sum >= max_val {
                new_counter = (sum % max_val) as u32;
                return;
            }
            new_counter = sum as u32;
        };
        match time.counter.0 {
            1 => counter_inc_handler(u8::MAX as u64),
            2 => counter_inc_handler(u16::MAX as u64),
            3 => counter_inc_handler((2_u32.pow(24) - 1) as u64),
            4 => counter_inc_handler(u32::MAX as u64),
            _ => {
                // Should never happen
                panic!("invalid counter width")
            }
        }
    };
    let resolution = time.fractions().resolution();
    let fractional_increment = fractional_part_from_subsec_ns(resolution, subsec_nanos as u64);
    let mut fractional_part = FractionalPart::new_with_seconds_resolution();
    if resolution != FractionalResolution::Seconds {
        let mut new_fractions = time.fractions().counter() + fractional_increment.counter;
        let max_fractions = fractional_res_to_div(resolution);
        if new_fractions > max_fractions {
            increment_counter(1);
            new_fractions -= max_fractions;
        }
        fractional_part = FractionalPart {
            resolution,
            counter: new_fractions,
        }
    }
    increment_counter(duration.as_secs() as u32);
    (new_counter, fractional_part)
}

impl AddAssign<Duration> for CucTime {
    fn add_assign(&mut self, duration: Duration) {
        let (new_counter, new_fractional_part) =
            get_time_values_after_duration_addition(self, duration);
        self.counter.1 = new_counter;
        self.fractions = new_fractional_part;
    }
}

impl Add<Duration> for CucTime {
    type Output = Self;

    fn add(self, duration: Duration) -> Self::Output {
        let (new_counter, new_fractional_part) =
            get_time_values_after_duration_addition(&self, duration);
        // The generated fractional part should always be valid, so its okay to unwrap here.
        Self::new_with_fractions(new_counter, new_fractional_part).unwrap()
    }
}

impl Add<Duration> for &CucTime {
    type Output = CucTime;

    fn add(self, duration: Duration) -> Self::Output {
        let (new_counter, new_fractional_part) =
            get_time_values_after_duration_addition(self, duration);
        // The generated fractional part should always be valid, so its okay to unwrap here.
        Self::Output::new_with_fractions(new_counter, new_fractional_part).unwrap()
    }
}

#[cfg(test)]
mod tests {
    use crate::time::{UnixTime, DAYS_CCSDS_TO_UNIX, SECONDS_PER_DAY};

    use super::*;
    use alloc::string::ToString;
    use chrono::{Datelike, TimeZone, Timelike};
    #[allow(unused_imports)]
    use std::println;

    const LEAP_SECONDS: u32 = 37;

    #[test]
    fn test_basic_zero_epoch() {
        // Do not include leap second corrections, which do not apply to dates before 1972.
        let zero_cuc = CucTime::new(0);
        assert_eq!(zero_cuc.len_as_bytes(), 5);
        assert_eq!(zero_cuc.counter_width(), zero_cuc.width_counter_pair().0);
        assert_eq!(zero_cuc.counter(), zero_cuc.width_counter_pair().1);
        let ccsds_cuc = zero_cuc.to_leap_sec_helper(0);
        assert_eq!(ccsds_cuc.ccdsd_time_code(), CcsdsTimeCode::CucCcsdsEpoch);
        let counter = zero_cuc.width_counter_pair();
        assert_eq!(counter.0, 4);
        assert_eq!(counter.1, 0);
        let fractions = zero_cuc.fractions();
        assert_eq!(fractions, FractionalPart::new_with_seconds_resolution());
        let dt = ccsds_cuc.chrono_date_time();
        if let chrono::LocalResult::Single(dt) = dt {
            assert_eq!(dt.year(), 1958);
            assert_eq!(dt.month(), 1);
            assert_eq!(dt.day(), 1);
            assert_eq!(dt.hour(), 0);
            assert_eq!(dt.minute(), 0);
            assert_eq!(dt.second(), 0);
        }
    }

    #[test]
    fn test_write_no_fractions() {
        let mut buf: [u8; 16] = [0; 16];
        let zero_cuc =
            CucTime::new_generic(WidthCounterPair(4, 0x20102030), FractionalPart::new_empty());
        assert!(zero_cuc.is_ok());
        let zero_cuc = zero_cuc.unwrap();
        let res = zero_cuc.write_to_bytes(&mut buf);
        assert!(res.is_ok());
        assert_eq!(zero_cuc.subsec_nanos(), 0);
        assert_eq!(zero_cuc.len_as_bytes(), 5);
        assert_eq!(pfield_len(buf[0]), 1);
        let written = res.unwrap();
        assert_eq!(written, 5);
        assert_eq!((buf[0] >> 7) & 0b1, 0);
        let time_code = ccsds_time_code_from_p_field(buf[0]);
        assert!(time_code.is_ok());
        assert_eq!(time_code.unwrap(), CcsdsTimeCode::CucCcsdsEpoch);
        assert_eq!((buf[0] >> 2) & 0b11, 0b11);
        assert_eq!(buf[0] & 0b11, 0);
        let raw_counter = u32::from_be_bytes(buf[1..5].try_into().unwrap());
        assert_eq!(raw_counter, 0x20102030);
        assert_eq!(buf[5], 0);
    }

    #[test]
    #[cfg_attr(miri, ignore)]
    fn test_datetime_now() {
        let now = chrono::Utc::now();
        let cuc_now = CucTime::now(FractionalResolution::SixtyNs, LEAP_SECONDS);
        assert!(cuc_now.is_ok());
        let cuc_now = cuc_now.unwrap();
        let ccsds_cuc = cuc_now.to_leap_sec_helper(LEAP_SECONDS);
        let dt_opt = ccsds_cuc.chrono_date_time();
        if let chrono::LocalResult::Single(dt) = dt_opt {
            let diff = dt - now;
            assert!(diff.num_milliseconds() < 1000);
            println!("datetime from cuc: {}", dt);
            println!("datetime now: {}", now);
        } else {
            panic!("date time creation from now failed")
        }
    }

    #[test]
    fn test_read_no_fractions() {
        let mut buf: [u8; 16] = [0; 16];
        let zero_cuc = CucTime::new_generic(
            WidthCounterPair(4, 0x20102030),
            FractionalPart::new_with_seconds_resolution(),
        )
        .unwrap();
        zero_cuc.write_to_bytes(&mut buf).unwrap();
        let cuc_read_back = CucTime::from_bytes(&buf).expect("reading cuc timestamp failed");
        assert_eq!(cuc_read_back, zero_cuc);
        assert_eq!(cuc_read_back.width_counter_pair().1, 0x20102030);
        assert_eq!(cuc_read_back.fractions(), FractionalPart::new_empty());
    }

    #[test]
    fn invalid_read_len() {
        let mut buf: [u8; 16] = [0; 16];
        for i in 0..2 {
            let res = CucTime::from_bytes(&buf[0..i]);
            assert!(res.is_err());
            let err = res.unwrap_err();
            if let TimestampError::ByteConversion(ByteConversionError::FromSliceTooSmall {
                found,
                expected,
            }) = err
            {
                assert_eq!(found, i);
                assert_eq!(expected, 2);
            }
        }
        let large_stamp = CucTime::new_with_fine_fractions(22, 300).unwrap();
        large_stamp.write_to_bytes(&mut buf).unwrap();
        for i in 2..large_stamp.len_as_bytes() - 1 {
            let res = CucTime::from_bytes(&buf[0..i]);
            assert!(res.is_err());
            let err = res.unwrap_err();
            if let TimestampError::ByteConversion(ByteConversionError::FromSliceTooSmall {
                found,
                expected,
            }) = err
            {
                assert_eq!(found, i);
                assert_eq!(expected, large_stamp.len_as_bytes());
            }
        }
    }

    #[test]
    fn write_and_read_tiny_stamp() {
        let mut buf = [0; 2];
        let cuc = CucTime::new_generic(WidthCounterPair(1, 200), FractionalPart::new_empty());
        assert!(cuc.is_ok());
        let cuc = cuc.unwrap();
        assert_eq!(cuc.len_as_bytes(), 2);
        let res = cuc.write_to_bytes(&mut buf);
        assert!(res.is_ok());
        let written = res.unwrap();
        assert_eq!(written, 2);
        assert_eq!(buf[1], 200);
        let cuc_read_back = CucTime::from_bytes(&buf);
        assert!(cuc_read_back.is_ok());
        let cuc_read_back = cuc_read_back.unwrap();
        assert_eq!(cuc_read_back, cuc);
    }

    #[test]
    fn write_slightly_larger_stamp() {
        let mut buf = [0; 4];
        let cuc = CucTime::new_generic(WidthCounterPair(2, 40000), FractionalPart::new_empty());
        assert!(cuc.is_ok());
        let cuc = cuc.unwrap();
        assert_eq!(cuc.len_as_bytes(), 3);
        let res = cuc.write_to_bytes(&mut buf);
        assert!(res.is_ok());
        let written = res.unwrap();
        assert_eq!(written, 3);
        assert_eq!(u16::from_be_bytes(buf[1..3].try_into().unwrap()), 40000);
        let cuc_read_back = CucTime::from_bytes(&buf);
        assert!(cuc_read_back.is_ok());
        let cuc_read_back = cuc_read_back.unwrap();
        assert_eq!(cuc_read_back, cuc);
    }

    #[test]
    fn invalid_buf_len_for_read() {}

    #[test]
    fn write_read_three_byte_cntr_stamp() {
        let mut buf = [0; 4];
        let cuc = CucTime::new_generic(
            WidthCounterPair(3, 2_u32.pow(24) - 2),
            FractionalPart::new_empty(),
        );
        assert!(cuc.is_ok());
        let cuc = cuc.unwrap();
        assert_eq!(cuc.len_as_bytes(), 4);
        let res = cuc.write_to_bytes(&mut buf);
        assert!(res.is_ok());
        let written = res.unwrap();
        assert_eq!(written, 4);
        let mut temp_buf = [0; 4];
        temp_buf[1..4].copy_from_slice(&buf[1..4]);
        assert_eq!(u32::from_be_bytes(temp_buf), 2_u32.pow(24) - 2);
        let cuc_read_back = CucTime::from_bytes(&buf);
        assert!(cuc_read_back.is_ok());
        let cuc_read_back = cuc_read_back.unwrap();
        assert_eq!(cuc_read_back, cuc);
    }

    #[test]
    fn test_write_invalid_buf() {
        let mut buf: [u8; 16] = [0; 16];
        let res = CucTime::new_with_fine_fractions(0, 0);
        let cuc = res.unwrap();
        for i in 0..cuc.len_as_bytes() - 1 {
            let err = cuc.write_to_bytes(&mut buf[0..i]);
            assert!(err.is_err());
            let err = err.unwrap_err();
            if let TimestampError::ByteConversion(ByteConversionError::ToSliceTooSmall {
                found,
                expected,
            }) = err
            {
                assert_eq!(expected, cuc.len_as_bytes());
                assert_eq!(found, i);
            } else {
                panic!("unexpected error: {}", err);
            }
        }
    }
    #[test]
    fn invalid_ccsds_stamp_type() {
        let mut buf: [u8; 16] = [0; 16];
        buf[0] |= (CcsdsTimeCode::CucAgencyEpoch as u8) << 4;
        let res = CucTime::from_bytes(&buf);
        assert!(res.is_err());
        let err = res.unwrap_err();
        if let TimestampError::InvalidTimeCode { expected, found } = err {
            assert_eq!(expected, CcsdsTimeCode::CucCcsdsEpoch);
            assert_eq!(found, CcsdsTimeCode::CucAgencyEpoch as u8);
        } else {
            panic!("unexpected error: {}", err);
        }
    }

    #[test]
    fn test_write_with_coarse_fractions() {
        let mut buf: [u8; 16] = [0; 16];
        let cuc = CucTime::new_with_coarse_fractions(0x30201060, 120);
        assert_eq!(cuc.fractions().counter(), 120);
        assert_eq!(cuc.fractions().resolution(), FractionalResolution::FourMs);
        let res = cuc.write_to_bytes(&mut buf);
        assert!(res.is_ok());
        let written = res.unwrap();
        assert_eq!(written, 6);
        assert_eq!(buf[5], 120);
        assert_eq!(buf[6], 0);
        assert_eq!(
            u32::from_be_bytes(buf[1..5].try_into().unwrap()),
            0x30201060
        );
    }

    #[test]
    fn test_read_with_coarse_fractions() {
        let mut buf: [u8; 16] = [0; 16];
        let cuc = CucTime::new_with_coarse_fractions(0x30201060, 120);
        let res = cuc.write_to_bytes(&mut buf);
        assert!(res.is_ok());
        let res = CucTime::from_bytes(&buf);
        assert!(res.is_ok());
        let read_back = res.unwrap();
        assert_eq!(read_back, cuc);
    }

    #[test]
    fn test_write_with_medium_fractions() {
        let mut buf: [u8; 16] = [0; 16];
        let cuc = CucTime::new_with_medium_fractions(0x30303030, 30000);
        let res = cuc.write_to_bytes(&mut buf);
        assert!(res.is_ok());
        let written = res.unwrap();
        assert_eq!(written, 7);
        assert_eq!(u16::from_be_bytes(buf[5..7].try_into().unwrap()), 30000);
        assert_eq!(buf[7], 0);
    }

    #[test]
    fn test_read_with_medium_fractions() {
        let mut buf: [u8; 16] = [0; 16];
        let cuc = CucTime::new_with_medium_fractions(0x30303030, 30000);
        let res = cuc.write_to_bytes(&mut buf);
        assert!(res.is_ok());
        let res = CucTime::from_bytes(&buf);
        assert!(res.is_ok());
        let cuc_read_back = res.unwrap();
        assert_eq!(cuc_read_back, cuc);
    }

    #[test]
    fn test_write_with_fine_fractions() {
        let mut buf: [u8; 16] = [0; 16];
        let cuc = CucTime::new_with_fine_fractions(0x30303030, u16::MAX as u32 + 60000);
        assert!(cuc.is_ok());
        let cuc = cuc.unwrap();
        let res = cuc.write_to_bytes(&mut buf);
        let written = res.unwrap();
        assert_eq!(written, 8);
        let mut dummy_buf: [u8; 4] = [0; 4];
        dummy_buf[1..4].copy_from_slice(&buf[5..8]);
        assert_eq!(u32::from_be_bytes(dummy_buf), u16::MAX as u32 + 60000);
        assert_eq!(buf[8], 0);
    }

    #[test]
    fn test_read_with_fine_fractions() {
        let mut buf: [u8; 16] = [0; 16];
        let cuc = CucTime::new_with_fine_fractions(0x30303030, u16::MAX as u32 + 60000);
        assert!(cuc.is_ok());
        let cuc = cuc.unwrap();
        let res = cuc.write_to_bytes(&mut buf);
        assert!(res.is_ok());
        let res = CucTime::from_bytes(&buf);
        assert!(res.is_ok());
        let cuc_read_back = res.unwrap();
        assert_eq!(cuc_read_back, cuc);
    }

    #[test]
    fn test_fractional_converter() {
        let ns = convert_fractional_part_to_ns(FractionalPart {
            resolution: FractionalResolution::FourMs,
            counter: 2,
        });
        // The formula for this is 2/255 * 10e9 = 7.843.137.
        assert_eq!(ns, 7843137);
        // This is the largest value we should be able to pass without this function panicking.
        let ns = convert_fractional_part_to_ns(FractionalPart {
            resolution: FractionalResolution::SixtyNs,
            counter: 2_u32.pow(24) - 2,
        });
        assert_eq!(ns, 999999940);
    }

    #[test]
    #[should_panic]
    fn test_fractional_converter_invalid_input() {
        convert_fractional_part_to_ns(FractionalPart {
            resolution: FractionalResolution::FourMs,
            counter: 256,
        });
    }

    #[test]
    #[should_panic]
    fn test_fractional_converter_invalid_input_2() {
        convert_fractional_part_to_ns(FractionalPart {
            resolution: FractionalResolution::SixtyNs,
            counter: 2_u32.pow(32) - 1,
        });
    }

    #[test]
    fn fractional_part_formula() {
        let fractional_part = fractional_part_from_subsec_ns(FractionalResolution::FourMs, 7843138);
        assert_eq!(fractional_part.counter, 2);
    }

    #[test]
    fn fractional_part_formula_2() {
        let fractional_part =
            fractional_part_from_subsec_ns(FractionalResolution::FourMs, 12000000);
        assert_eq!(fractional_part.counter, 3);
    }

    #[test]
    fn fractional_part_formula_3() {
        let one_fraction_with_width_two_in_ns =
            10_u64.pow(9) as f64 / (2_u32.pow(8 * 2) - 1) as f64;
        assert_eq!(one_fraction_with_width_two_in_ns.ceil(), 15260.0);
        let hundred_fractions_and_some =
            (100.0 * one_fraction_with_width_two_in_ns).floor() as u64 + 7000;
        let fractional_part = fractional_part_from_subsec_ns(
            FractionalResolution::FifteenUs,
            hundred_fractions_and_some,
        );
        assert_eq!(fractional_part.counter, 100);
        // Using exactly 101.0 can yield values which will later be rounded down to 100
        let hundred_and_one_fractions =
            (101.001 * one_fraction_with_width_two_in_ns).floor() as u64;
        let fractional_part = fractional_part_from_subsec_ns(
            FractionalResolution::FifteenUs,
            hundred_and_one_fractions,
        );
        assert_eq!(fractional_part.counter, 101);
    }

    #[test]
    fn update_fractions() {
        let mut stamp = CucTime::new(2000);
        let res = stamp.set_fractions(FractionalPart {
            resolution: FractionalResolution::SixtyNs,
            counter: 5000,
        });
        assert!(res.is_ok());
        assert_eq!(
            stamp.fractions().resolution(),
            FractionalResolution::SixtyNs
        );
        assert_eq!(stamp.fractions().counter(), 5000);
    }

    #[test]
    #[cfg_attr(miri, ignore)]
    fn set_fract_resolution() {
        let mut stamp = CucTime::new(2000);
        stamp.set_fractional_resolution(FractionalResolution::SixtyNs);
        assert_eq!(
            stamp.fractions().resolution(),
            FractionalResolution::SixtyNs
        );
        assert_eq!(stamp.fractions().counter(), 0);
        let res = stamp.update_from_now(LEAP_SECONDS);

        assert!(res.is_ok());
    }

    #[test]
    fn test_small_fraction_floored_to_zero() {
        let fractions = fractional_part_from_subsec_ns(FractionalResolution::SixtyNs, 59);
        assert_eq!(fractions.counter, 0);
    }

    #[test]
    fn test_small_fraction_becomes_fractional_part() {
        let fractions = fractional_part_from_subsec_ns(FractionalResolution::SixtyNs, 61);
        assert_eq!(fractions.counter, 1);
    }

    #[test]
    fn test_smallest_resolution_small_nanoseconds_floored_to_zero() {
        let fractions =
            fractional_part_from_subsec_ns(FractionalResolution::FourMs, 3800 * 1e3 as u64);
        assert_eq!(fractions.counter, 0);
    }

    #[test]
    fn test_smallest_resolution_small_nanoseconds_becomes_one_fraction() {
        let fractions =
            fractional_part_from_subsec_ns(FractionalResolution::FourMs, 4000 * 1e3 as u64);
        assert_eq!(fractions.counter, 1);
    }

    #[test]
    fn test_smallest_resolution_large_nanoseconds_becomes_largest_fraction() {
        let fractions =
            fractional_part_from_subsec_ns(FractionalResolution::FourMs, 10u64.pow(9) - 1);
        assert_eq!(fractions.counter, 2_u32.pow(8) - 1);
    }

    #[test]
    fn test_largest_fractions_with_largest_resolution() {
        let fractions =
            fractional_part_from_subsec_ns(FractionalResolution::SixtyNs, 10u64.pow(9) - 1);
        // The value can not be larger than representable by 3 bytes
        // Assert that the maximum resolution can be reached
        assert_eq!(fractions.counter, 2_u32.pow(3 * 8) - 1);
    }

    fn check_stamp_after_addition(cuc_stamp: &CucTime) {
        let cuc_with_leaps = cuc_stamp.to_leap_sec_helper(LEAP_SECONDS);
        assert_eq!(
            cuc_with_leaps.ccdsd_time_code(),
            CcsdsTimeCode::CucCcsdsEpoch
        );
        assert_eq!(cuc_stamp.width_counter_pair().1, 202);
        let fractions = cuc_stamp.fractions().counter();
        let expected_val =
            (0.5 * fractional_res_to_div(FractionalResolution::FifteenUs) as f64).ceil() as u32;
        assert_eq!(fractions, expected_val);
        let cuc_stamp2 = cuc_stamp + Duration::from_millis(501);
        // What I would roughly expect
        assert_eq!(cuc_stamp2.counter.1, 203);
        assert!(cuc_stamp2.fractions().counter() < 100);
        assert!(cuc_stamp2.subsec_millis() <= 1);
    }

    #[test]
    fn add_duration_basic() {
        let mut cuc_stamp = CucTime::new(200);
        cuc_stamp.set_fractional_resolution(FractionalResolution::FifteenUs);
        let duration = Duration::from_millis(2500);
        cuc_stamp += duration;
        check_stamp_after_addition(&cuc_stamp);
    }

    #[test]
    fn add_duration_basic_on_ref() {
        let mut cuc_stamp = CucTime::new(200);
        cuc_stamp.set_fractional_resolution(FractionalResolution::FifteenUs);
        let duration = Duration::from_millis(2500);
        let new_stamp = cuc_stamp + duration;
        check_stamp_after_addition(&new_stamp);
    }

    #[test]
    fn add_duration_basic_no_fractions() {
        let mut cuc_stamp = CucTime::new(200);
        let duration = Duration::from_millis(2000);
        cuc_stamp += duration;
        assert_eq!(cuc_stamp.counter(), 202);
        assert_eq!(cuc_stamp.fractions(), FractionalPart::new_empty());
    }

    #[test]
    fn add_duration_basic_on_ref_no_fractions() {
        let cuc_stamp = CucTime::new(200);
        let duration = Duration::from_millis(2000);
        let new_stamp = cuc_stamp + duration;
        assert_eq!(new_stamp.counter(), 202);
        assert_eq!(new_stamp.fractions(), FractionalPart::new_empty());
    }
    #[test]
    fn add_duration_overflow() {
        let mut cuc_stamp =
            CucTime::new_generic(WidthCounterPair(1, 255), FractionalPart::new_empty()).unwrap();
        let duration = Duration::from_secs(10);
        cuc_stamp += duration;
        assert_eq!(cuc_stamp.counter.1, 10);
    }

    #[test]
    fn test_invalid_width_param() {
        let error = CucTime::new_generic(WidthCounterPair(8, 0), FractionalPart::new_empty());
        assert!(error.is_err());
        let error = error.unwrap_err();
        if let CucError::InvalidCounterWidth(width) = error {
            assert_eq!(width, 8);
            assert_eq!(error.to_string(), "invalid cuc counter byte width 8");
        } else {
            panic!("unexpected error: {}", error);
        }
    }

    #[test]
    fn test_from_dt() {
        let dt = chrono::Utc.with_ymd_and_hms(2021, 1, 1, 0, 0, 0).unwrap();
        let cuc = CucTime::from_chrono_date_time(&dt, FractionalResolution::Seconds, LEAP_SECONDS)
            .unwrap();
        assert_eq!(cuc.counter(), dt.timestamp() as u32 + LEAP_SECONDS);
    }

    #[test]
    fn from_unix_stamp() {
        let unix_stamp = UnixTime::new(0, 0);
        let cuc = CucTime::from_unix_time(&unix_stamp, FractionalResolution::Seconds, LEAP_SECONDS)
            .expect("failed to create cuc from unix stamp");
        assert_eq!(
            cuc.counter(),
            (-DAYS_CCSDS_TO_UNIX * SECONDS_PER_DAY as i32) as u32 + LEAP_SECONDS
        );
    }

    #[test]
    fn test_invalid_counter() {
        let cuc_error = CucTime::new_generic(WidthCounterPair(1, 256), FractionalPart::new_empty());
        assert!(cuc_error.is_err());
        let cuc_error = cuc_error.unwrap_err();
        if let CucError::InvalidCounter { width, counter } = cuc_error {
            assert_eq!(width, 1);
            assert_eq!(counter, 256);
            assert_eq!(cuc_error.to_string(), "invalid cuc counter 256 for width 1");
        } else {
            panic!("unexpected error: {}", cuc_error);
        }
    }

    #[test]
    fn test_stamp_to_vec() {
        let stamp = CucTime::new(100);
        let stamp_vec = stamp.to_vec().unwrap();
        let mut buf: [u8; 16] = [0; 16];
        stamp.write_to_bytes(&mut buf).unwrap();
        assert_eq!(stamp_vec, buf[..stamp.len_written()]);
    }
}
