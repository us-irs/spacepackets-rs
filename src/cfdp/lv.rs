use crate::cfdp::TlvLvError;
use crate::{ByteConversionError, SizeMissmatch};
use std::prelude::v1::String;

pub const MIN_LV_LEN: usize = 1;

/// Generic CFDP length-value (LV) abstraction.
///
/// This is just a thin wrapper around a raw slice which performs some additional error handling.
pub struct Lv<'a> {
    data: &'a [u8],
}

pub(crate) fn generic_len_check_data_serialization(
    buf: &[u8],
    data: &[u8],
    min_overhead: usize,
) -> Result<(), ByteConversionError> {
    if buf.len() < data.len() + min_overhead {
        return Err(ByteConversionError::ToSliceTooSmall(SizeMissmatch {
            found: buf.len(),
            expected: data.len() + min_overhead,
        }));
    }
    Ok(())
}

pub(crate) fn generic_len_check_deserialization(
    buf: &[u8],
    min_overheader: usize,
) -> Result<(), ByteConversionError> {
    if buf.len() < min_overheader {
        return Err(ByteConversionError::FromSliceTooSmall(SizeMissmatch {
            found: buf.len(),
            expected: MIN_LV_LEN,
        }));
    }
    Ok(())
}
impl<'a> Lv<'a> {
    pub fn new(data: &[u8]) -> Result<Lv, TlvLvError> {
        if data.len() > u8::MAX as usize {
            return Err(TlvLvError::DataTooLarge(data.len()));
        }
        Ok(Lv { data })
    }

    /// Helper function to build a string LV. This is especially useful for the file or directory
    /// path LVs
    pub fn new_from_str(str_slice: &str) -> Result<Lv, TlvLvError> {
        Self::new(str_slice.as_bytes())
    }

    /// Helper function to build a string LV. This is especially useful for the file or directory
    /// path LVs
    #[cfg(feature = "std")]
    pub fn new_from_string(string: &'a String) -> Result<Lv<'a>, TlvLvError> {
        Self::new(string.as_bytes())
    }

    pub fn value(&self) -> &[u8] {
        self.data
    }

    /// Writes the LV to a raw buffer. Please note that the first byte will contain the length
    /// of the value, but the values may not exceed a length of [u8::MAX].
    pub fn write_to_be_bytes(&self, buf: &mut [u8]) -> Result<usize, ByteConversionError> {
        generic_len_check_data_serialization(buf, self.data, MIN_LV_LEN)?;
        Ok(self.write_to_be_bytes_no_len_check(buf))
    }

    /// Reads a LV  from a raw buffer.
    pub fn from_be_bytes(buf: &'a [u8]) -> Result<Lv<'a>, TlvLvError> {
        generic_len_check_deserialization(buf, MIN_LV_LEN)?;
        Self::from_be_bytes_no_len_check(buf)
    }

    pub(crate) fn write_to_be_bytes_no_len_check(&self, buf: &mut [u8]) -> usize {
        // Length check in constructor ensures the length always has a valid value.
        buf[0] = self.data.len() as u8;
        buf[MIN_LV_LEN..self.data.len() + MIN_LV_LEN].copy_from_slice(self.data);
        MIN_LV_LEN + self.data.len()
    }

    pub(crate) fn from_be_bytes_no_len_check(buf: &'a [u8]) -> Result<Lv<'a>, TlvLvError> {
        let value_len = buf[0] as usize;
        if buf.len() < value_len + MIN_LV_LEN {
            return Err(ByteConversionError::FromSliceTooSmall(SizeMissmatch {
                found: buf.len(),
                expected: MIN_LV_LEN + value_len,
            })
            .into());
        }
        Ok(Self {
            data: &buf[MIN_LV_LEN..MIN_LV_LEN + value_len],
        })
    }
}
