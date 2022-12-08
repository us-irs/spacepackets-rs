use super::*;
use core::fmt::Debug;

const MIN_CUC_LEN: usize = 2;

#[derive(Copy, Clone, PartialEq, Eq, Debug)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub enum CucError {
    InvalidCounterWidth(u8),
    InvalidFractionWidth(u8),
    InvalidCounter(u8, u64),
    InvalidFractions(u8, u64),
}

impl Display for CucError {
    fn fmt(&self, f: &mut Formatter<'_>) -> core::fmt::Result {
        match self {
            CucError::InvalidCounterWidth(w) => {
                write!(f, "invalid cuc counter byte width {}", w)
            }
            CucError::InvalidFractionWidth(w) => {
                write!(f, "invalid cuc fractional part byte width {}", w)
            }
            CucError::InvalidCounter(w, c) => {
                write!(f, "invalid cuc counter {} for width {}", c, w)
            }
            CucError::InvalidFractions(w, c) => {
                write!(f, "invalid cuc fractional part {} for width {}", c, w)
            }
        }
    }
}

#[cfg(feature = "std")]
impl Error for CucError {}

#[derive(Copy, Clone, PartialEq, Eq, Debug)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct WidthCounterPair(u8, u32);

/// This provider uses the CCSDS epoch. Furthermore the preamble field only has one byte,
/// which allows a time code representation through the year 2094.
///
/// More specifically, only having a preamble field of one byte limits the width of the counter
/// type (generally seconds) to 4 bytes and the width of the fractions type to 3 bytes.
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct TimeProviderCcsdsEpoch {
    pfield: u8,
    counter: WidthCounterPair,
    fractions: Option<WidthCounterPair>,
}

#[inline]
pub fn pfield_len(pfield: u8) -> usize {
    if ((pfield >> 7) & 0b1) == 1 {
        return 2;
    }
    1
}

impl TimeProviderCcsdsEpoch {
    fn build_p_field(counter_width: u8, fractions_width: Option<u8>) -> u8 {
        let mut pfield = (CcsdsTimeCodes::CucCcsdsEpoch as u8) << 4;
        if !(1..=4).contains(&counter_width) {
            // Okay to panic here, this function is private and all input values should
            // have been sanitized
            panic!("invalid counter width {} for cuc timestamp", counter_width);
        }
        pfield |= (counter_width - 1) << 3;
        if let Some(fractions_width) = fractions_width {
            if !(1..=3).contains(&fractions_width) {
                // Okay to panic here, this function is private and all input values should
                // have been sanitized
                panic!(
                    "invalid fractions width {} for cuc timestamp",
                    fractions_width
                );
            }
            pfield |= fractions_width;
        }
        pfield
    }

    fn update_p_field_fractions(&mut self) {
        self.pfield &= !(0b11);
        if let Some(fractions) = self.fractions {
            self.pfield |= fractions.0;
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

    /// Verifies the raw width parameter and returns the actual length, which is the raw
    /// value plus 1.
    fn verify_counter_width(width: u8) -> Result<(), CucError> {
        if width == 0 || width > 4 {
            return Err(CucError::InvalidCounterWidth(width));
        }
        Ok(())
    }

    fn verify_fractions_width(width: u8) -> Result<(), CucError> {
        if width > 3 {
            return Err(CucError::InvalidFractionWidth(width));
        }
        Ok(())
    }

    fn verify_fractions_value(val: WidthCounterPair) -> Result<(), CucError> {
        if val.1 > 2u32.pow((val.0 as u32) * 8) - 1 {
            return Err(CucError::InvalidFractions(val.0, val.1 as u64));
        }
        Ok(())
    }
}

impl TimeProviderCcsdsEpoch {
    pub fn new_default(counter: u32) -> Self {
        // These values are definitely valid, so it is okay to unwrap here.
        Self::new(WidthCounterPair(4, counter), None).unwrap()
    }
    pub fn new_u16_counter(counter: u16) -> Self {
        // These values are definitely valid, so it is okay to unwrap here.
        Self::new(WidthCounterPair(2, counter as u32), None).unwrap()
    }

    pub fn set_fractions(&mut self, fractions: WidthCounterPair) -> Result<(), CucError> {
        Self::verify_fractions_width(fractions.0)?;
        Self::verify_fractions_value(fractions)?;
        self.fractions = Some(fractions);
        self.update_p_field_fractions();
        Ok(())
    }

    pub fn new(
        counter: WidthCounterPair,
        fractions: Option<WidthCounterPair>,
    ) -> Result<Self, CucError> {
        Self::verify_counter_width(counter.0)?;
        if counter.1 > 2u32.pow(counter.0 as u32 * 8) - 1 {
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
                1 => fractions = Some(WidthCounterPair(fractions_len, buf[current_idx] as u32)),
                2 => {
                    fractions = Some(WidthCounterPair(
                        fractions_len,
                        u16::from_be_bytes(buf[current_idx..current_idx + 2].try_into().unwrap())
                            as u32,
                    ))
                }
                3 => {
                    let mut tmp_buf: [u8; 4] = [0; 4];
                    tmp_buf[1..4].copy_from_slice(&buf[current_idx..current_idx + 3]);
                    fractions = Some(WidthCounterPair(
                        fractions_len,
                        u32::from_be_bytes(tmp_buf) as u32,
                    ))
                }
                _ => panic!("unreachable match arm"),
            }
        }
        let provider = Self::new(WidthCounterPair(cntr_len, counter), fractions)?;
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
                1 => bytes[current_idx] = fractions.1 as u8,
                2 => bytes[current_idx..current_idx + 2]
                    .copy_from_slice(&(fractions.1 as u16).to_be_bytes()),
                3 => bytes[current_idx..current_idx + 3]
                    .copy_from_slice(&fractions.1.to_be_bytes()[1..4]),
                // Should also never happen
                _ => panic!("invalid fractions value"),
            }
            current_idx += fractions.0 as usize;
        }
        Ok(current_idx)
    }
}
