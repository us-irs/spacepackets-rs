//! Module to generate or read CCSDS Unsegmented (CUC) timestamps as specified in
//! [CCSDS 301.0-B-4](https://public.ccsds.org/Pubs/301x0b4e1.pdf) section 3.2 .
//!
//! The core data structure to do this is the [TimeProviderCcsdsEpoch] struct.
use super::*;
use chrono::Datelike;
use core::fmt::Debug;
use core::ops::{Add, AddAssign};
use core::time::Duration;

const MIN_CUC_LEN: usize = 2;

/// Base value for the preamble field for a time field parser to determine the time field type.
pub const P_FIELD_BASE: u8 = (CcsdsTimeCodes::CucCcsdsEpoch as u8) << 4;
/// Maximum length if the preamble field is not extended.
pub const MAX_CUC_LEN_SMALL_PREAMBLE: usize = 8;

#[derive(Copy, Clone, PartialEq, Eq, Debug)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub enum FractionalResolution {
    /// No fractional part, only second resolution
    Seconds = 0,
    /// 256 fractional parts, resulting in 1/255 ~= 4 ms fractional resolution
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

/// Please note that this function will panic if the fractional value is not smaller than
/// the maximum number of fractions allowed for the particular resolution.
/// (e.g. passing 270 when the resolution only allows 255 values).
#[inline]
pub fn convert_fractional_part_to_ns(fractional_part: FractionalPart) -> u64 {
    let div = fractional_res_to_div(fractional_part.0);
    assert!(fractional_part.1 < div);
    10_u64.pow(9) * fractional_part.1 as u64 / div as u64
}

#[inline(always)]
pub const fn fractional_res_to_div(res: FractionalResolution) -> u32 {
    2_u32.pow(8 * res as u32) - 1
}

/// Calculate the fractional part for a given resolution and subsecond nanoseconds.
/// Please note that this function will panic if the passed nanoseconds exceeds 1 second
/// as a nanosecond (10 to the power of 9). Furthermore, it will return [None] if the
/// given resolution is [FractionalResolution::Seconds].
pub fn fractional_part_from_subsec_ns(
    res: FractionalResolution,
    ns: u64,
) -> Option<FractionalPart> {
    if res == FractionalResolution::Seconds {
        return None;
    }
    let sec_as_ns = 10_u64.pow(9);
    if ns > sec_as_ns {
        panic!("passed nanosecond value larger than 1 second");
    }
    let resolution = fractional_res_to_div(res) as u64;
    // Use integer division because this can reduce code size of really small systems.
    // First determine the nanoseconds for the smallest segment given the resolution.
    // Then divide by that to find out the fractional part. For the calculation of the smallest
    // fraction, we perform a ceiling division. This is because if we would use the default
    // flooring division, we would divide by a smaller value, thereby allowing the calculation to
    // invalid fractional parts which are too large. For the division of the nanoseconds by the
    // smallest fraction, a flooring division is correct.
    // The multiplication with 100000 is necessary to avoid precision loss during integer division.
    // TODO: Floating point division might actually be faster option, but requires additional
    //       code on small embedded systems..
    let fractional_part = ns * 100000 / ((sec_as_ns * 100000 + resolution) / resolution);
    // Floating point division.
    //let fractional_part = (ns as f64 / ((sec_as_ns as f64) / resolution as f64)).floor() as u32;
    Some(FractionalPart(res, fractional_part as u32))
}

#[derive(Copy, Clone, PartialEq, Eq, Debug)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub enum CucError {
    InvalidCounterWidth(u8),
    InvalidFractionResolution(FractionalResolution),
    /// Invalid counter supplied.
    InvalidCounter(u8, u64),
    InvalidFractions(FractionalResolution, u64),
}

impl Display for CucError {
    fn fmt(&self, f: &mut Formatter<'_>) -> core::fmt::Result {
        match self {
            CucError::InvalidCounterWidth(w) => {
                write!(f, "invalid cuc counter byte width {}", w)
            }
            CucError::InvalidFractionResolution(w) => {
                write!(f, "invalid cuc fractional part byte width {:?}", w)
            }
            CucError::InvalidCounter(w, c) => {
                write!(f, "invalid cuc counter {} for width {}", c, w)
            }
            CucError::InvalidFractions(w, c) => {
                write!(f, "invalid cuc fractional part {} for width {:?}", c, w)
            }
        }
    }
}

#[cfg(feature = "std")]
impl Error for CucError {}

#[derive(Copy, Clone, PartialEq, Eq, Debug)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct WidthCounterPair(u8, u32);
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct FractionalPart(FractionalResolution, u32);

/// This object is the abstraction for the CCSDS Unsegmented Time Code (CUC) using the CCSDS epoch
/// and a small preamble field.
///
/// It has the capability to generate and read timestamps as specified in the CCSDS 301.0-B-4
/// section 3.2 . The preamble field only has one byte, which allows a time code representation
/// through the year 2094. The time is represented as a simple binary counter starting from the
/// fixed CCSDS epoch (1958-01-01 00:00:00). It is possible to provide subsecond accuracy using the
/// fractional field with various available [resolutions][FractionalResolution].
///
/// Having a preamble field of one byte limits the width of the counter
/// type (generally seconds) to 4 bytes and the width of the fractions type to 3 bytes. This limits
/// the maximum time stamp size to [MAX_CUC_LEN_SMALL_PREAMBLE] (8 bytes).
///
/// # Example
///
/// ```
/// use spacepackets::time::cuc::{FractionalResolution, TimeProviderCcsdsEpoch};
/// use spacepackets::time::{TimeWriter, CcsdsTimeCodes, TimeReader, CcsdsTimeProvider};
///
/// // Highest fractional resolution
/// let timestamp_now = TimeProviderCcsdsEpoch::from_now(FractionalResolution::SixtyNs).expect("creating cuc stamp failed");
/// let mut raw_stamp = [0; 16];
/// {
///     let written = timestamp_now.write_to_bytes(&mut raw_stamp).expect("writing timestamp failed");
///     assert_eq!((raw_stamp[0] >> 4) & 0b111, CcsdsTimeCodes::CucCcsdsEpoch as u8);
///     // 1 byte preamble + 4 byte counter + 3 byte fractional part
///     assert_eq!(written, 8);
/// }
/// {
///     let read_result = TimeProviderCcsdsEpoch::from_bytes(&raw_stamp);
///     assert!(read_result.is_ok());
///     let stamp_deserialized = read_result.unwrap();
///     assert_eq!(stamp_deserialized, timestamp_now);
/// }
/// ```
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct TimeProviderCcsdsEpoch {
    pfield: u8,
    counter: WidthCounterPair,
    fractions: Option<FractionalPart>,
}

#[inline]
pub fn pfield_len(pfield: u8) -> usize {
    if ((pfield >> 7) & 0b1) == 1 {
        return 2;
    }
    1
}

impl TimeProviderCcsdsEpoch {
    /// Create a time provider with a four byte counter and no fractional part.
    pub fn new(counter: u32) -> Self {
        // These values are definitely valid, so it is okay to unwrap here.
        Self::new_generic(WidthCounterPair(4, counter), None).unwrap()
    }

    /// Like [TimeProviderCcsdsEpoch::new] but allow to supply a fractional part as well.
    pub fn new_with_fractions(counter: u32, fractions: FractionalPart) -> Result<Self, CucError> {
        Self::new_generic(WidthCounterPair(4, counter), Some(fractions))
    }

    /// Fractions with a resolution of ~ 4 ms
    pub fn new_with_coarse_fractions(counter: u32, subsec_fractions: u8) -> Self {
        // These values are definitely valid, so it is okay to unwrap here.
        Self::new_generic(
            WidthCounterPair(4, counter),
            Some(FractionalPart(
                FractionalResolution::FourMs,
                subsec_fractions as u32,
            )),
        )
        .unwrap()
    }

    /// Fractions with a resolution of ~ 16 us
    pub fn new_with_medium_fractions(counter: u32, subsec_fractions: u16) -> Self {
        // These values are definitely valid, so it is okay to unwrap here.
        Self::new_generic(
            WidthCounterPair(4, counter),
            Some(FractionalPart(
                FractionalResolution::FifteenUs,
                subsec_fractions as u32,
            )),
        )
        .unwrap()
    }

    /// Fractions with a resolution of ~ 60 ns. The fractional part value is limited by the
    /// 24 bits of the fractional field, so this function will fail with
    /// [CucError::InvalidFractions] if the fractional value exceeds the value.
    pub fn new_with_fine_fractions(counter: u32, subsec_fractions: u32) -> Result<Self, CucError> {
        Self::new_generic(
            WidthCounterPair(4, counter),
            Some(FractionalPart(
                FractionalResolution::SixtyNs,
                subsec_fractions,
            )),
        )
    }

    /// This function will return the current time as a CUC timestamp.
    /// The counter width will always be set to 4 bytes because the normal CCSDS epoch will overflow
    /// when using less than that.
    #[cfg(feature = "std")]
    #[cfg_attr(doc_cfg, doc(cfg(feature = "std")))]
    pub fn from_now(fraction_resolution: FractionalResolution) -> Result<Self, StdTimestampError> {
        let now = SystemTime::now().duration_since(SystemTime::UNIX_EPOCH)?;
        let ccsds_epoch = unix_epoch_to_ccsds_epoch(now.as_secs() as i64);
        if fraction_resolution == FractionalResolution::Seconds {
            return Ok(Self::new(ccsds_epoch as u32));
        }
        let fractions =
            fractional_part_from_subsec_ns(fraction_resolution, now.subsec_nanos() as u64);
        Self::new_with_fractions(ccsds_epoch as u32, fractions.unwrap())
            .map_err(|e| StdTimestampError::TimestampError(e.into()))
    }

    /// Updates the current time stamp from the current time. The fractional field width remains
    /// the same and will be updated accordingly.
    #[cfg(feature = "std")]
    #[cfg_attr(doc_cfg, doc(cfg(feature = "std")))]
    pub fn update_from_now(&mut self) -> Result<(), StdTimestampError> {
        let now = SystemTime::now().duration_since(SystemTime::UNIX_EPOCH)?;
        self.counter.1 = unix_epoch_to_ccsds_epoch(now.as_secs() as i64) as u32;
        if self.fractions.is_some() {
            self.fractions = fractional_part_from_subsec_ns(
                self.fractions.unwrap().0,
                now.subsec_nanos() as u64,
            );
        }
        Ok(())
    }

    pub fn from_date_time(
        dt: &DateTime<Utc>,
        res: FractionalResolution,
    ) -> Result<Self, TimestampError> {
        // Year before CCSDS epoch is invalid.
        if dt.year() < 1958 {
            return Err(TimestampError::DateBeforeCcsdsEpoch(*dt));
        }
        Self::new_generic(
            WidthCounterPair(4, dt.timestamp() as u32),
            fractional_part_from_subsec_ns(res, dt.timestamp_subsec_nanos() as u64),
        )
        .map_err(|e| e.into())
    }

    pub fn from_unix_stamp(
        unix_stamp: &UnixTimestamp,
        res: FractionalResolution,
    ) -> Result<Self, TimestampError> {
        let ccsds_epoch = unix_epoch_to_ccsds_epoch(unix_stamp.unix_seconds);
        // Negative CCSDS epoch is invalid.
        if ccsds_epoch < 0 {
            return Err(TimestampError::DateBeforeCcsdsEpoch(
                unix_stamp.as_date_time().unwrap(),
            ));
        }
        if ccsds_epoch > u32::MAX as i64 {
            return Err(CucError::InvalidCounter(4, ccsds_epoch as u64).into());
        }
        let mut fractions = None;
        if let Some(subsec_millis) = unix_stamp.subsecond_millis {
            fractions = fractional_part_from_subsec_ns(res, subsec_millis as u64 * 10_u64.pow(6));
        }
        Self::new_generic(WidthCounterPair(4, ccsds_epoch as u32), fractions).map_err(|e| e.into())
    }

    pub fn new_u16_counter(counter: u16) -> Self {
        // These values are definitely valid, so it is okay to unwrap here.
        Self::new_generic(WidthCounterPair(2, counter as u32), None).unwrap()
    }

    pub fn width_counter_pair(&self) -> WidthCounterPair {
        self.counter
    }

    pub fn width_fractions_pair(&self) -> Option<FractionalPart> {
        self.fractions
    }

    pub fn set_fractions(&mut self, fractions: FractionalPart) -> Result<(), CucError> {
        Self::verify_fractions_width(fractions.0)?;
        Self::verify_fractions_value(fractions)?;
        self.fractions = Some(fractions);
        self.update_p_field_fractions();
        Ok(())
    }

    /// Set a fractional resolution. Please note that this function will reset the fractional value
    /// to 0 if the resolution changes.
    pub fn set_fractional_resolution(&mut self, res: FractionalResolution) {
        if res == FractionalResolution::Seconds {
            self.fractions = None;
        }
        let mut update_fractions = true;
        if let Some(existing_fractions) = self.fractions {
            if existing_fractions.0 == res {
                update_fractions = false;
            }
        };
        if update_fractions {
            self.fractions = Some(FractionalPart(res, 0));
        }
    }

    pub fn new_generic(
        counter: WidthCounterPair,
        fractions: Option<FractionalPart>,
    ) -> Result<Self, CucError> {
        Self::verify_counter_width(counter.0)?;
        if counter.1 > (2u64.pow(counter.0 as u32 * 8) - 1) as u32 {
            return Err(CucError::InvalidCounter(counter.0, counter.1 as u64));
        }
        if let Some(fractions) = fractions {
            Self::verify_fractions_width(fractions.0)?;
            Self::verify_fractions_value(fractions)?;
        }
        Ok(Self {
            pfield: Self::build_p_field(counter.0, fractions.map(|v| v.0)),
            counter,
            fractions,
        })
    }

    fn build_p_field(counter_width: u8, fractions_width: Option<FractionalResolution>) -> u8 {
        let mut pfield = P_FIELD_BASE;
        if !(1..=4).contains(&counter_width) {
            // Okay to panic here, this function is private and all input values should
            // have been sanitized
            panic!("invalid counter width {} for cuc timestamp", counter_width);
        }
        pfield |= (counter_width - 1) << 2;
        if let Some(fractions_width) = fractions_width {
            if !(1..=3).contains(&(fractions_width as u8)) {
                // Okay to panic here, this function is private and all input values should
                // have been sanitized
                panic!(
                    "invalid fractions width {:?} for cuc timestamp",
                    fractions_width
                );
            }
            pfield |= fractions_width as u8;
        }
        pfield
    }

    fn update_p_field_fractions(&mut self) {
        self.pfield &= !(0b11);
        if let Some(fractions) = self.fractions {
            self.pfield |= fractions.0 as u8;
        }
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
    fn unix_seconds(&self) -> i64 {
        ccsds_epoch_to_unix_epoch(self.counter.1 as i64)
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

    pub fn len_packed_from_pfield(pfield: u8) -> usize {
        let mut base_len: usize = 1;
        base_len += Self::len_cntr_from_pfield(pfield) as usize;
        base_len += Self::len_fractions_from_pfield(pfield) as usize;
        base_len
    }

    /// Verifies the raw width parameter.
    fn verify_counter_width(width: u8) -> Result<(), CucError> {
        if width == 0 || width > 4 {
            return Err(CucError::InvalidCounterWidth(width));
        }
        Ok(())
    }

    fn verify_fractions_width(width: FractionalResolution) -> Result<(), CucError> {
        if width as u8 > 3 {
            return Err(CucError::InvalidFractionResolution(width));
        }
        Ok(())
    }

    fn verify_fractions_value(val: FractionalPart) -> Result<(), CucError> {
        if val.1 > 2u32.pow((val.0 as u32) * 8) - 1 {
            return Err(CucError::InvalidFractions(val.0, val.1 as u64));
        }
        Ok(())
    }
}

impl TimeReader for TimeProviderCcsdsEpoch {
    fn from_bytes(buf: &[u8]) -> Result<Self, TimestampError>
    where
        Self: Sized,
    {
        if buf.len() < MIN_CUC_LEN {
            return Err(TimestampError::ByteConversionError(
                ByteConversionError::FromSliceTooSmall(SizeMissmatch {
                    expected: MIN_CUC_LEN,
                    found: buf.len(),
                }),
            ));
        }
        match ccsds_time_code_from_p_field(buf[0]) {
            Ok(code) => {
                if code != CcsdsTimeCodes::CucCcsdsEpoch {
                    return Err(TimestampError::InvalidTimeCode(
                        CcsdsTimeCodes::CucCcsdsEpoch,
                        code as u8,
                    ));
                }
            }
            Err(raw) => {
                return Err(TimestampError::InvalidTimeCode(
                    CcsdsTimeCodes::CucCcsdsEpoch,
                    raw,
                ))
            }
        }
        let (cntr_len, fractions_len, total_len) =
            Self::len_components_and_total_from_pfield(buf[0]);
        if buf.len() < total_len {
            return Err(TimestampError::ByteConversionError(
                ByteConversionError::FromSliceTooSmall(SizeMissmatch {
                    expected: total_len,
                    found: buf.len(),
                }),
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
        let mut fractions = None;
        if fractions_len > 0 {
            match fractions_len {
                1 => {
                    fractions = Some(FractionalPart(
                        fractions_len.try_into().unwrap(),
                        buf[current_idx] as u32,
                    ))
                }
                2 => {
                    fractions = Some(FractionalPart(
                        fractions_len.try_into().unwrap(),
                        u16::from_be_bytes(buf[current_idx..current_idx + 2].try_into().unwrap())
                            as u32,
                    ))
                }
                3 => {
                    let mut tmp_buf: [u8; 4] = [0; 4];
                    tmp_buf[1..4].copy_from_slice(&buf[current_idx..current_idx + 3]);
                    fractions = Some(FractionalPart(
                        fractions_len.try_into().unwrap(),
                        u32::from_be_bytes(tmp_buf),
                    ))
                }
                _ => panic!("unreachable match arm"),
            }
        }
        let provider = Self::new_generic(WidthCounterPair(cntr_len, counter), fractions)?;
        Ok(provider)
    }
}

impl TimeWriter for TimeProviderCcsdsEpoch {
    fn write_to_bytes(&self, bytes: &mut [u8]) -> Result<usize, TimestampError> {
        // Cross check the sizes of the counters against byte widths in the ctor
        if bytes.len() < self.len_as_bytes() {
            return Err(TimestampError::ByteConversionError(
                ByteConversionError::ToSliceTooSmall(SizeMissmatch {
                    found: bytes.len(),
                    expected: self.len_as_bytes(),
                }),
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
        if let Some(fractions) = self.fractions {
            match fractions.0 {
                FractionalResolution::FourMs => bytes[current_idx] = fractions.1 as u8,
                FractionalResolution::FifteenUs => bytes[current_idx..current_idx + 2]
                    .copy_from_slice(&(fractions.1 as u16).to_be_bytes()),
                FractionalResolution::SixtyNs => bytes[current_idx..current_idx + 3]
                    .copy_from_slice(&fractions.1.to_be_bytes()[1..4]),
                // Should also never happen
                _ => panic!("invalid fractions value"),
            }
            current_idx += fractions.0 as usize;
        }
        Ok(current_idx)
    }
}

impl CcsdsTimeProvider for TimeProviderCcsdsEpoch {
    fn len_as_bytes(&self) -> usize {
        Self::len_packed_from_pfield(self.pfield)
    }

    fn p_field(&self) -> (usize, [u8; 2]) {
        (1, [self.pfield, 0])
    }

    fn ccdsd_time_code(&self) -> CcsdsTimeCodes {
        CcsdsTimeCodes::CucCcsdsEpoch
    }

    fn unix_seconds(&self) -> i64 {
        self.unix_seconds()
    }

    fn subsecond_millis(&self) -> Option<u16> {
        if let Some(fractions) = self.fractions {
            if fractions.0 == FractionalResolution::Seconds {
                return None;
            }
            // Rounding down here is the correct approach.
            return Some((convert_fractional_part_to_ns(fractions) / 10_u32.pow(6) as u64) as u16);
        }
        None
    }

    fn date_time(&self) -> Option<DateTime<Utc>> {
        let unix_seconds = self.unix_seconds();
        let ns = if let Some(fractional_part) = self.fractions {
            convert_fractional_part_to_ns(fractional_part)
        } else {
            0
        };
        if let LocalResult::Single(res) = Utc.timestamp_opt(unix_seconds, ns as u32) {
            return Some(res);
        }
        None
    }
}

fn get_provider_values_after_duration_addition(
    provider: &TimeProviderCcsdsEpoch,
    duration: Duration,
) -> (u32, Option<FractionalPart>) {
    let mut new_counter = provider.counter.1;
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
        match provider.counter.0 {
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
    let fractional_part = if let Some(fractional_part) = &provider.fractions {
        let fractional_increment =
            fractional_part_from_subsec_ns(fractional_part.0, subsec_nanos as u64).unwrap();
        let mut increment_fractions = |resolution| {
            let mut new_fractions = fractional_part.1 + fractional_increment.1;
            let max_fractions = fractional_res_to_div(resolution);
            if new_fractions > max_fractions {
                increment_counter(1);
                new_fractions -= max_fractions;
            }
            Some(FractionalPart(resolution, new_fractions))
        };
        match fractional_increment.0 {
            FractionalResolution::Seconds => None,
            _ => increment_fractions(fractional_increment.0),
        }
    } else {
        None
    };
    increment_counter(duration.as_secs() as u32);
    (new_counter, fractional_part)
}

impl AddAssign<Duration> for TimeProviderCcsdsEpoch {
    fn add_assign(&mut self, duration: Duration) {
        let (new_counter, new_fractional_part) =
            get_provider_values_after_duration_addition(self, duration);
        self.counter.1 = new_counter;
        if self.fractions.is_some() {
            self.fractions = new_fractional_part;
        }
    }
}

impl Add<Duration> for TimeProviderCcsdsEpoch {
    type Output = Self;

    fn add(self, duration: Duration) -> Self::Output {
        let (new_counter, new_fractional_part) =
            get_provider_values_after_duration_addition(&self, duration);
        if let Some(fractional_part) = new_fractional_part {
            // The generated fractional part should always be valid, so its okay to unwrap here.
            return Self::new_with_fractions(new_counter, fractional_part).unwrap();
        }
        Self::new(new_counter)
    }
}

impl Add<Duration> for &TimeProviderCcsdsEpoch {
    type Output = TimeProviderCcsdsEpoch;

    fn add(self, duration: Duration) -> Self::Output {
        let (new_counter, new_fractional_part) =
            get_provider_values_after_duration_addition(self, duration);
        if let Some(fractional_part) = new_fractional_part {
            // The generated fractional part should always be valid, so its okay to unwrap here.
            return Self::Output::new_with_fractions(new_counter, fractional_part).unwrap();
        }
        Self::Output::new(new_counter)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::{Datelike, Timelike};
    #[allow(unused_imports)]
    use std::println;

    #[test]
    fn test_basic_zero_epoch() {
        let zero_cuc = TimeProviderCcsdsEpoch::new(0);
        assert_eq!(zero_cuc.len_as_bytes(), 5);
        assert_eq!(zero_cuc.ccdsd_time_code(), CcsdsTimeCodes::CucCcsdsEpoch);
        let counter = zero_cuc.width_counter_pair();
        assert_eq!(counter.0, 4);
        assert_eq!(counter.1, 0);
        let fractions = zero_cuc.width_fractions_pair();
        assert!(fractions.is_none());
        let dt = zero_cuc.date_time();
        assert!(dt.is_some());
        let dt = dt.unwrap();
        assert_eq!(dt.year(), 1958);
        assert_eq!(dt.month(), 1);
        assert_eq!(dt.day(), 1);
        assert_eq!(dt.hour(), 0);
        assert_eq!(dt.minute(), 0);
        assert_eq!(dt.second(), 0);
    }

    #[test]
    fn test_write_no_fractions() {
        let mut buf: [u8; 16] = [0; 16];
        let zero_cuc = TimeProviderCcsdsEpoch::new_generic(WidthCounterPair(4, 0x20102030), None);
        assert!(zero_cuc.is_ok());
        let zero_cuc = zero_cuc.unwrap();
        let res = zero_cuc.write_to_bytes(&mut buf);
        assert!(res.is_ok());
        assert!(zero_cuc.subsecond_millis().is_none());
        assert_eq!(zero_cuc.len_as_bytes(), 5);
        assert_eq!(pfield_len(buf[0]), 1);
        let written = res.unwrap();
        assert_eq!(written, 5);
        assert_eq!((buf[0] >> 7) & 0b1, 0);
        let time_code = ccsds_time_code_from_p_field(buf[0]);
        assert!(time_code.is_ok());
        assert_eq!(time_code.unwrap(), CcsdsTimeCodes::CucCcsdsEpoch);
        assert_eq!((buf[0] >> 2) & 0b11, 0b11);
        assert_eq!(buf[0] & 0b11, 0);
        let raw_counter = u32::from_be_bytes(buf[1..5].try_into().unwrap());
        assert_eq!(raw_counter, 0x20102030);
        assert_eq!(buf[5], 0);
    }

    #[test]
    fn test_datetime_now() {
        let now = Utc::now();
        let cuc_now = TimeProviderCcsdsEpoch::from_now(FractionalResolution::SixtyNs);
        assert!(cuc_now.is_ok());
        let cuc_now = cuc_now.unwrap();
        let dt_opt = cuc_now.date_time();
        assert!(dt_opt.is_some());
        let dt = dt_opt.unwrap();
        let diff = dt - now;
        assert!(diff.num_milliseconds() < 1000);
        println!("datetime from cuc: {}", dt);
        println!("datetime now: {}", now);
    }

    #[test]
    fn test_read_no_fractions() {
        let mut buf: [u8; 16] = [0; 16];
        let zero_cuc =
            TimeProviderCcsdsEpoch::new_generic(WidthCounterPair(4, 0x20102030), None).unwrap();
        zero_cuc.write_to_bytes(&mut buf).unwrap();
        let cuc_read_back =
            TimeProviderCcsdsEpoch::from_bytes(&buf).expect("reading cuc timestamp failed");
        assert_eq!(cuc_read_back, zero_cuc);
        assert_eq!(cuc_read_back.width_counter_pair().1, 0x20102030);
        assert_eq!(cuc_read_back.width_fractions_pair(), None);
    }

    #[test]
    fn invalid_read_len() {
        let mut buf: [u8; 16] = [0; 16];
        for i in 0..2 {
            let res = TimeProviderCcsdsEpoch::from_bytes(&buf[0..i]);
            assert!(res.is_err());
            let err = res.unwrap_err();
            if let TimestampError::ByteConversionError(ByteConversionError::FromSliceTooSmall(e)) =
                err
            {
                assert_eq!(e.found, i);
                assert_eq!(e.expected, 2);
            }
        }
        let large_stamp = TimeProviderCcsdsEpoch::new_with_fine_fractions(22, 300).unwrap();
        large_stamp.write_to_bytes(&mut buf).unwrap();
        for i in 2..large_stamp.len_as_bytes() - 1 {
            let res = TimeProviderCcsdsEpoch::from_bytes(&buf[0..i]);
            assert!(res.is_err());
            let err = res.unwrap_err();
            if let TimestampError::ByteConversionError(ByteConversionError::FromSliceTooSmall(e)) =
                err
            {
                assert_eq!(e.found, i);
                assert_eq!(e.expected, large_stamp.len_as_bytes());
            }
        }
    }

    #[test]
    fn write_and_read_tiny_stamp() {
        let mut buf = [0; 2];
        let cuc = TimeProviderCcsdsEpoch::new_generic(WidthCounterPair(1, 200), None);
        assert!(cuc.is_ok());
        let cuc = cuc.unwrap();
        assert_eq!(cuc.len_as_bytes(), 2);
        let res = cuc.write_to_bytes(&mut buf);
        assert!(res.is_ok());
        let written = res.unwrap();
        assert_eq!(written, 2);
        assert_eq!(buf[1], 200);
        let cuc_read_back = TimeProviderCcsdsEpoch::from_bytes(&buf);
        assert!(cuc_read_back.is_ok());
        let cuc_read_back = cuc_read_back.unwrap();
        assert_eq!(cuc_read_back, cuc);
    }

    #[test]
    fn write_slightly_larger_stamp() {
        let mut buf = [0; 4];
        let cuc = TimeProviderCcsdsEpoch::new_generic(WidthCounterPair(2, 40000), None);
        assert!(cuc.is_ok());
        let cuc = cuc.unwrap();
        assert_eq!(cuc.len_as_bytes(), 3);
        let res = cuc.write_to_bytes(&mut buf);
        assert!(res.is_ok());
        let written = res.unwrap();
        assert_eq!(written, 3);
        assert_eq!(u16::from_be_bytes(buf[1..3].try_into().unwrap()), 40000);
        let cuc_read_back = TimeProviderCcsdsEpoch::from_bytes(&buf);
        assert!(cuc_read_back.is_ok());
        let cuc_read_back = cuc_read_back.unwrap();
        assert_eq!(cuc_read_back, cuc);
    }

    #[test]
    fn invalid_buf_len_for_read() {}
    #[test]
    fn write_read_three_byte_cntr_stamp() {
        let mut buf = [0; 4];
        let cuc = TimeProviderCcsdsEpoch::new_generic(WidthCounterPair(3, 2_u32.pow(24) - 2), None);
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
        let cuc_read_back = TimeProviderCcsdsEpoch::from_bytes(&buf);
        assert!(cuc_read_back.is_ok());
        let cuc_read_back = cuc_read_back.unwrap();
        assert_eq!(cuc_read_back, cuc);
    }

    #[test]
    fn test_write_invalid_buf() {
        let mut buf: [u8; 16] = [0; 16];
        let res = TimeProviderCcsdsEpoch::new_with_fine_fractions(0, 0);
        let cuc = res.unwrap();
        for i in 0..cuc.len_as_bytes() - 1 {
            let err = cuc.write_to_bytes(&mut buf[0..i]);
            assert!(err.is_err());
            let err = err.unwrap_err();
            if let TimestampError::ByteConversionError(ByteConversionError::ToSliceTooSmall(e)) =
                err
            {
                assert_eq!(e.expected, cuc.len_as_bytes());
                assert_eq!(e.found, i);
            } else {
                panic!("unexpected error: {}", err);
            }
        }
    }
    #[test]
    fn invalid_ccsds_stamp_type() {
        let mut buf: [u8; 16] = [0; 16];
        buf[0] |= (CcsdsTimeCodes::CucAgencyEpoch as u8) << 4;
        let res = TimeProviderCcsdsEpoch::from_bytes(&buf);
        assert!(res.is_err());
        let err = res.unwrap_err();
        if let TimestampError::InvalidTimeCode(code, raw) = err {
            assert_eq!(code, CcsdsTimeCodes::CucCcsdsEpoch);
            assert_eq!(raw, CcsdsTimeCodes::CucAgencyEpoch as u8);
        } else {
            panic!("unexpected error: {}", err);
        }
    }

    #[test]
    fn test_write_with_coarse_fractions() {
        let mut buf: [u8; 16] = [0; 16];
        let cuc = TimeProviderCcsdsEpoch::new_with_coarse_fractions(0x30201060, 120);
        assert!(cuc.fractions.is_some());
        assert_eq!(cuc.fractions.unwrap().1, 120);
        assert_eq!(cuc.fractions.unwrap().0, FractionalResolution::FourMs);
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
        let cuc = TimeProviderCcsdsEpoch::new_with_coarse_fractions(0x30201060, 120);
        let res = cuc.write_to_bytes(&mut buf);
        assert!(res.is_ok());
        let res = TimeProviderCcsdsEpoch::from_bytes(&buf);
        assert!(res.is_ok());
        let read_back = res.unwrap();
        assert_eq!(read_back, cuc);
    }

    #[test]
    fn test_write_with_medium_fractions() {
        let mut buf: [u8; 16] = [0; 16];
        let cuc = TimeProviderCcsdsEpoch::new_with_medium_fractions(0x30303030, 30000);
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
        let cuc = TimeProviderCcsdsEpoch::new_with_medium_fractions(0x30303030, 30000);
        let res = cuc.write_to_bytes(&mut buf);
        assert!(res.is_ok());
        let res = TimeProviderCcsdsEpoch::from_bytes(&buf);
        assert!(res.is_ok());
        let cuc_read_back = res.unwrap();
        assert_eq!(cuc_read_back, cuc);
    }

    #[test]
    fn test_write_with_fine_fractions() {
        let mut buf: [u8; 16] = [0; 16];
        let cuc =
            TimeProviderCcsdsEpoch::new_with_fine_fractions(0x30303030, u16::MAX as u32 + 60000);
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
        let cuc =
            TimeProviderCcsdsEpoch::new_with_fine_fractions(0x30303030, u16::MAX as u32 + 60000);
        assert!(cuc.is_ok());
        let cuc = cuc.unwrap();
        let res = cuc.write_to_bytes(&mut buf);
        assert!(res.is_ok());
        let res = TimeProviderCcsdsEpoch::from_bytes(&buf);
        assert!(res.is_ok());
        let cuc_read_back = res.unwrap();
        assert_eq!(cuc_read_back, cuc);
    }

    #[test]
    fn test_fractional_converter() {
        let ns = convert_fractional_part_to_ns(FractionalPart(FractionalResolution::FourMs, 2));
        // The formula for this is 2/255 * 10e9 = 7.843.137.
        assert_eq!(ns, 7843137);
        // This is the largest value we should be able to pass without this function panicking.
        let ns = convert_fractional_part_to_ns(FractionalPart(
            FractionalResolution::SixtyNs,
            2_u32.pow(24) - 2,
        ));
        assert_eq!(ns, 999999940);
    }

    #[test]
    #[should_panic]
    fn test_fractional_converter_invalid_input() {
        convert_fractional_part_to_ns(FractionalPart(FractionalResolution::FourMs, 256));
    }

    #[test]
    #[should_panic]
    fn test_fractional_converter_invalid_input_2() {
        convert_fractional_part_to_ns(FractionalPart(
            FractionalResolution::SixtyNs,
            2_u32.pow(32) - 1,
        ));
    }

    #[test]
    fn fractional_part_formula() {
        let fractional_part =
            fractional_part_from_subsec_ns(FractionalResolution::FourMs, 7843138).unwrap();
        assert_eq!(fractional_part.1, 2);
    }

    #[test]
    fn fractional_part_formula_2() {
        let fractional_part =
            fractional_part_from_subsec_ns(FractionalResolution::FourMs, 12000000).unwrap();
        assert_eq!(fractional_part.1, 3);
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
        )
        .unwrap();
        assert_eq!(fractional_part.1, 100);
        // Using exactly 101.0 can yield values which will later be rounded down to 100
        let hundred_and_one_fractions =
            (101.001 * one_fraction_with_width_two_in_ns).floor() as u64;
        let fractional_part = fractional_part_from_subsec_ns(
            FractionalResolution::FifteenUs,
            hundred_and_one_fractions,
        )
        .unwrap();
        assert_eq!(fractional_part.1, 101);
    }

    #[test]
    fn update_fractions() {
        let mut stamp = TimeProviderCcsdsEpoch::new(2000);
        let res = stamp.set_fractions(FractionalPart(FractionalResolution::SixtyNs, 5000));
        assert!(res.is_ok());
        assert!(stamp.fractions.is_some());
        let fractions = stamp.fractions.unwrap();
        assert_eq!(fractions.0, FractionalResolution::SixtyNs);
        assert_eq!(fractions.1, 5000);
    }

    #[test]
    fn set_fract_resolution() {
        let mut stamp = TimeProviderCcsdsEpoch::new(2000);
        stamp.set_fractional_resolution(FractionalResolution::SixtyNs);
        assert!(stamp.fractions.is_some());
        let fractions = stamp.fractions.unwrap();
        assert_eq!(fractions.0, FractionalResolution::SixtyNs);
        assert_eq!(fractions.1, 0);
        let res = stamp.update_from_now();
        assert!(res.is_ok());
    }

    #[test]
    fn assert_largest_fractions() {
        let fractions =
            fractional_part_from_subsec_ns(FractionalResolution::SixtyNs, 10u64.pow(9) - 1)
                .unwrap();
        // The value can not be larger than representable by 3 bytes
        // Assert that the maximum resolution can be reached
        assert_eq!(fractions.1, 2_u32.pow(3 * 8) - 2);
    }

    #[test]
    fn add_duration_basic() {
        let mut cuc_stamp = TimeProviderCcsdsEpoch::new(200);
        cuc_stamp.set_fractional_resolution(FractionalResolution::FifteenUs);
        let duration = Duration::from_millis(2500);
        cuc_stamp += duration;
        assert_eq!(cuc_stamp.width_counter_pair().1, 202);
        let fractions = cuc_stamp.width_fractions_pair().unwrap().1;
        let expected_val =
            (0.5 * fractional_res_to_div(FractionalResolution::FifteenUs) as f64).floor() as u32;
        assert_eq!(fractions, expected_val);
        let cuc_stamp2 = cuc_stamp + Duration::from_millis(501);
        // What I would roughly expect
        assert_eq!(cuc_stamp2.counter.1, 203);
        assert!(cuc_stamp2.fractions.unwrap().1 < 100);
        assert!(cuc_stamp2.subsecond_millis().unwrap() <= 1);
    }

    #[test]
    fn add_duration_overflow() {
        let mut cuc_stamp =
            TimeProviderCcsdsEpoch::new_generic(WidthCounterPair(1, 255), None).unwrap();
        let duration = Duration::from_secs(10);
        cuc_stamp += duration;
        assert_eq!(cuc_stamp.counter.1, 10);
    }
}
