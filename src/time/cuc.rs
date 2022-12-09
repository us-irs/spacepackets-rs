//! Module to generate or read CCSDS Unsegmented (CUC) timestamps as specified in
//! [CCSDS 301.0-B-4](https://public.ccsds.org/Pubs/301x0b4e1.pdf) section 3.2 .
//!
//! The core data structure to do this is the [TimeProviderCcsdsEpoch] struct.
use super::*;
use core::fmt::Debug;

const MIN_CUC_LEN: usize = 2;
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
pub fn convert_fractional_part_to_ns(fractional_part: FractionalPart) -> u64 {
    let div = fractional_res_to_div(fractional_part.0);
    assert!(fractional_part.1 < div);
    10_u64.pow(9) * fractional_part.1 as u64 / div as u64
}

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
    // First determine the nanoseconds for the smallest segment given the resolution.
    // Then divide by that to find out the fractional part. An integer division floors
    // which is what we want here.
    let fractional_part = ns / (sec_as_ns / fractional_res_to_div(res) as u64);
    Some(FractionalPart(res, fractional_part as u32))
}

#[derive(Copy, Clone, PartialEq, Eq, Debug)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub enum CucError {
    InvalidCounterWidth(u8),
    InvalidFractionResolution(FractionalResolution),
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
/// fractional field with various available resolutions.
///
/// Having a preamble field of one byte limits the width of the counter
/// type (generally seconds) to 4 bytes and the width of the fractions type to 3 bytes. This limits
/// the maximum time stamp size to [MAX_CUC_LEN_SMALL_PREAMBLE] (8 bytes).
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
    fn build_p_field(counter_width: u8, fractions_width: Option<FractionalResolution>) -> u8 {
        let mut pfield = (CcsdsTimeCodes::CucCcsdsEpoch as u8) << 4;
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

    pub fn len_packed(&self) -> usize {
        Self::len_packed_from_pfield(self.pfield)
    }

    #[inline]
    pub fn len_cntr_from_pfield(pfield: u8) -> u8 {
        ((pfield >> 2) & 0b11) + 1
    }

    #[inline]
    pub fn len_fractions_from_pfield(pfield: u8) -> u8 {
        pfield & 0b11
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

impl TimeProviderCcsdsEpoch {
    pub fn new(counter: u32) -> Self {
        // These values are definitely valid, so it is okay to unwrap here.
        Self::new_generic(WidthCounterPair(4, counter), None).unwrap()
    }

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

    pub fn new_with_submillis_fractions(counter: u32, subsec_fractions: u16) -> Self {
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

    pub fn new_with_fine_fractions(counter: u32, subsec_fractions: u32) -> Result<Self, CucError> {
        Self::new_generic(
            WidthCounterPair(4, counter),
            Some(FractionalPart(
                FractionalResolution::SixtyNs,
                subsec_fractions as u32,
            )),
        )
    }

    pub fn new_with_fractions(
        counter: u32,
        fractions: Option<FractionalPart>,
    ) -> Result<Self, CucError> {
        Self::new_generic(WidthCounterPair(4, counter), fractions)
    }

    pub fn new_u16_counter(counter: u16) -> Self {
        // These values are definitely valid, so it is okay to unwrap here.
        Self::new_generic(WidthCounterPair(2, counter as u32), None).unwrap()
    }

    /// This function will return the current time as a CUC timestamp.
    /// The counter width will always be set to 4 bytes because the normal CCSDS epoch will overflow
    /// when using less than that.
    #[cfg(feature = "std")]
    pub fn from_now(fraction_resolution: FractionalResolution) -> Result<Self, StdTimestampError> {
        let now = SystemTime::now().duration_since(SystemTime::UNIX_EPOCH)?;
        let ccsds_epoch = unix_epoch_to_ccsds_epoch(now.as_secs());
        let fractions =
            fractional_part_from_subsec_ns(fraction_resolution, now.subsec_nanos() as u64);
        Ok(Self {
            pfield: 0,
            counter: WidthCounterPair(4, ccsds_epoch as u32),
            fractions,
        })
    }

    #[cfg(feature = "std")]
    pub fn update_from_now(&mut self) -> Result<(), StdTimestampError> {
        let now = SystemTime::now().duration_since(SystemTime::UNIX_EPOCH)?;
        self.counter.1 = unix_epoch_to_ccsds_epoch(now.as_secs()) as u32;
        if self.fractions.is_some() {
            self.fractions = fractional_part_from_subsec_ns(
                self.fractions.unwrap().0,
                now.subsec_nanos() as u64,
            );
        }
        Ok(())
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
        if let Some(existing_fractions) = self.fractions {
            if existing_fractions.0 != res {
                self.fractions = Some(FractionalPart(res, 0));
            }
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
                u32::from_be_bytes(tmp_buf) as u32
            }
            4 => u32::from_be_bytes(buf[current_idx..current_idx + 4].try_into().unwrap()) as u32,
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
                        u32::from_be_bytes(tmp_buf) as u32,
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
        if bytes.len() < self.len_packed() {
            return Err(TimestampError::ByteConversionError(
                ByteConversionError::ToSliceTooSmall(SizeMissmatch {
                    found: bytes.len(),
                    expected: self.len_packed(),
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
        self.len_packed()
    }

    fn p_field(&self) -> (usize, [u8; 2]) {
        (1, [self.pfield, 0])
    }

    fn ccdsd_time_code(&self) -> CcsdsTimeCodes {
        CcsdsTimeCodes::CucCcsdsEpoch
    }

    /// Please note that this function only works as intended if the time counter resolution
    /// is one second.
    fn unix_seconds(&self) -> i64 {
        ccsds_epoch_to_unix_epoch(self.counter.1 as u64) as i64
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

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::{Datelike, Timelike};
    #[allow(unused_imports)]
    use std::println;

    #[test]
    fn test_basic_zero_epoch() {
        let zero_cuc = TimeProviderCcsdsEpoch::new_generic(WidthCounterPair(4, 0), None);
        assert!(zero_cuc.is_ok());
        let zero_cuc = zero_cuc.unwrap();
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
    fn test_write() {
        let mut buf: [u8; 16] = [0; 16];
        let zero_cuc = TimeProviderCcsdsEpoch::new_generic(WidthCounterPair(4, 0x20102030), None);
        assert!(zero_cuc.is_ok());
        let zero_cuc = zero_cuc.unwrap();
        let res = zero_cuc.write_to_bytes(&mut buf);
        assert!(res.is_ok());
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
            7843137 / (10_u64.pow(9) / fractional_res_to_div(FractionalResolution::FourMs) as u64);
        assert_eq!(fractional_part, 2);
    }

    #[test]
    fn fractional_part_formula_2() {
        let fractional_part =
            12000000 / (10_u64.pow(9) / fractional_res_to_div(FractionalResolution::FourMs) as u64);
        assert_eq!(fractional_part, 3);
    }

    #[test]
    fn fractional_part_formula_3() {
        let one_fraction_with_width_two_in_ns = 10_u64.pow(9) / (2_u32.pow(8 * 2) - 1) as u64;
        assert_eq!(one_fraction_with_width_two_in_ns, 15259);
        let hundred_fractions_and_some = 100 * one_fraction_with_width_two_in_ns + 7000;
        let fractional_part = hundred_fractions_and_some
            / (10_u64.pow(9) / fractional_res_to_div(FractionalResolution::FifteenUs) as u64);
        assert_eq!(fractional_part, 100);
        let hundred_and_one_fractions = 101 * one_fraction_with_width_two_in_ns;
        let fractional_part = hundred_and_one_fractions
            / (10_u64.pow(9) / fractional_res_to_div(FractionalResolution::FifteenUs) as u64);
        assert_eq!(fractional_part, 101);
    }
}
