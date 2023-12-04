//! Generic CFDP length-value (LV) abstraction as specified in CFDP 5.1.8.
use crate::cfdp::TlvLvError;
use crate::ByteConversionError;
use core::str::Utf8Error;
#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};
#[cfg(feature = "std")]
use std::string::String;

pub const MIN_LV_LEN: usize = 1;

/// Generic CFDP length-value (LV) abstraction as specified in CFDP 5.1.8.
///
/// Please note that this class is zero-copy and does not generate a copy of the value data for
/// both the regular [Self::new] constructor and the [Self::from_bytes] constructor.
///
/// # Lifetimes
///  * `data`: If the LV is generated from a raw bytestream, this will be the lifetime of
///    the raw bytestream. If the LV is generated from a raw slice or a similar data reference,
///    this will be the lifetime of that data reference.
#[derive(Debug, Copy, Clone, Eq)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct Lv<'data> {
    data: &'data [u8],
    // If the LV was generated from a raw bytestream, this will contain the start of the
    // full LV.
    pub(crate) raw_data: Option<&'data [u8]>,
}

impl PartialEq for Lv<'_> {
    fn eq(&self, other: &Self) -> bool {
        self.data == other.data
    }
}

pub(crate) fn generic_len_check_data_serialization(
    buf: &[u8],
    data_len: usize,
    min_overhead: usize,
) -> Result<(), ByteConversionError> {
    if buf.len() < data_len + min_overhead {
        return Err(ByteConversionError::ToSliceTooSmall {
            found: buf.len(),
            expected: data_len + min_overhead,
        });
    }
    Ok(())
}

pub(crate) fn generic_len_check_deserialization(
    buf: &[u8],
    min_overhead: usize,
) -> Result<(), ByteConversionError> {
    if buf.len() < min_overhead {
        return Err(ByteConversionError::FromSliceTooSmall {
            found: buf.len(),
            expected: min_overhead,
        });
    }
    Ok(())
}

impl<'data> Lv<'data> {
    pub fn new(data: &[u8]) -> Result<Lv, TlvLvError> {
        if data.len() > u8::MAX as usize {
            return Err(TlvLvError::DataTooLarge(data.len()));
        }
        Ok(Lv {
            data,
            raw_data: None,
        })
    }

    /// Creates a LV with an empty value field.
    pub fn new_empty() -> Lv<'data> {
        Lv {
            data: &[],
            raw_data: None,
        }
    }

    /// Helper function to build a string LV. This is especially useful for the file or directory
    /// path LVs
    pub fn new_from_str(str_slice: &str) -> Result<Lv, TlvLvError> {
        Self::new(str_slice.as_bytes())
    }

    /// Helper function to build a string LV. This is especially useful for the file or directory
    /// path LVs
    #[cfg(feature = "std")]
    #[cfg_attr(doc_cfg, doc(cfg(feature = "std")))]
    pub fn new_from_string(string: &'data String) -> Result<Lv<'data>, TlvLvError> {
        Self::new(string.as_bytes())
    }

    /// Returns the length of the value part, not including the length byte.
    pub fn len_value(&self) -> usize {
        self.data.len()
    }

    /// Returns the full raw length, including the length byte.
    pub fn len_full(&self) -> usize {
        self.len_value() + 1
    }

    /// Checks whether the value field is empty.
    pub fn is_empty(&self) -> bool {
        self.data.len() == 0
    }

    pub fn value(&self) -> &[u8] {
        self.data
    }

    /// If the LV was generated from a raw bytestream using [Self::from_bytes], the raw start
    /// of the LV can be retrieved with this method.
    pub fn raw_data(&self) -> Option<&[u8]> {
        self.raw_data
    }

    /// Convenience function to extract the value as a [str]. This is useful if the LV is
    /// known to contain a [str], for example being a file name.
    pub fn value_as_str(&self) -> Option<Result<&'data str, Utf8Error>> {
        if self.is_empty() {
            return None;
        }
        Some(core::str::from_utf8(self.data))
    }

    /// Writes the LV to a raw buffer. Please note that the first byte will contain the length
    /// of the value, but the values may not exceed a length of [u8::MAX].
    pub fn write_to_be_bytes(&self, buf: &mut [u8]) -> Result<usize, ByteConversionError> {
        generic_len_check_data_serialization(buf, self.len_value(), MIN_LV_LEN)?;
        Ok(self.write_to_be_bytes_no_len_check(buf))
    }

    /// Reads a LV  from a raw buffer.
    pub fn from_bytes(buf: &'data [u8]) -> Result<Lv<'data>, ByteConversionError> {
        generic_len_check_deserialization(buf, MIN_LV_LEN)?;
        Self::from_be_bytes_no_len_check(buf)
    }

    pub(crate) fn write_to_be_bytes_no_len_check(&self, buf: &mut [u8]) -> usize {
        if self.is_empty() {
            buf[0] = 0;
            return MIN_LV_LEN;
        }
        // Length check in constructor ensures the length always has a valid value.
        buf[0] = self.data.len() as u8;
        buf[MIN_LV_LEN..self.data.len() + MIN_LV_LEN].copy_from_slice(self.data);
        MIN_LV_LEN + self.data.len()
    }

    pub(crate) fn from_be_bytes_no_len_check(
        buf: &'data [u8],
    ) -> Result<Lv<'data>, ByteConversionError> {
        let value_len = buf[0] as usize;
        generic_len_check_deserialization(buf, value_len + MIN_LV_LEN)?;
        Ok(Self {
            data: &buf[MIN_LV_LEN..MIN_LV_LEN + value_len],
            raw_data: Some(buf),
        })
    }
}

#[cfg(test)]
pub mod tests {
    use super::*;
    use alloc::string::ToString;

    use crate::cfdp::TlvLvError;
    use crate::ByteConversionError;
    use std::string::String;

    #[test]
    fn test_basic() {
        let lv_data: [u8; 4] = [1, 2, 3, 4];
        let lv_res = Lv::new(&lv_data);
        assert!(lv_res.is_ok());
        let lv = lv_res.unwrap();
        assert!(!lv.value().is_empty());
        let val = lv.value();
        assert_eq!(val[0], 1);
        assert_eq!(val[1], 2);
        assert_eq!(val[2], 3);
        assert_eq!(val[3], 4);
        assert!(!lv.is_empty());
        assert_eq!(lv.len_full(), 5);
        assert_eq!(lv.len_value(), 4);
    }

    #[test]
    fn test_empty() {
        let lv_empty = Lv::new_empty();
        assert_eq!(lv_empty.len_value(), 0);
        assert_eq!(lv_empty.len_full(), 1);
        assert!(lv_empty.is_empty());
        let mut buf: [u8; 4] = [0xff; 4];
        let res = lv_empty.write_to_be_bytes(&mut buf);
        assert!(res.is_ok());
        let written = res.unwrap();
        assert_eq!(written, 1);
        assert_eq!(buf[0], 0);
    }

    #[test]
    fn test_serialization() {
        let lv_data: [u8; 4] = [1, 2, 3, 4];
        let lv_res = Lv::new(&lv_data);
        assert!(lv_res.is_ok());
        let lv = lv_res.unwrap();
        let mut buf: [u8; 16] = [0; 16];
        let res = lv.write_to_be_bytes(&mut buf);
        assert!(res.is_ok());
        let written = res.unwrap();
        assert_eq!(written, 5);
        assert_eq!(buf[0], 4);
        assert_eq!(buf[1], 1);
        assert_eq!(buf[2], 2);
        assert_eq!(buf[3], 3);
        assert_eq!(buf[4], 4);
    }

    #[test]
    fn test_deserialization() {
        let mut buf: [u8; 16] = [0; 16];
        buf[0] = 4;
        buf[1] = 1;
        buf[2] = 2;
        buf[3] = 3;
        buf[4] = 4;
        let lv = Lv::from_bytes(&buf);
        assert!(lv.is_ok());
        let lv = lv.unwrap();
        assert!(!lv.is_empty());
        assert_eq!(lv.len_value(), 4);
        assert_eq!(lv.len_full(), 5);
        assert!(lv.raw_data().is_some());
        assert_eq!(lv.raw_data().unwrap(), buf);
        let val = lv.value();
        assert_eq!(val[0], 1);
        assert_eq!(val[1], 2);
        assert_eq!(val[2], 3);
        assert_eq!(val[3], 4);
    }

    #[test]
    fn test_deserialization_empty() {
        let buf: [u8; 2] = [0; 2];
        let lv_empty = Lv::from_bytes(&buf);
        assert!(lv_empty.is_ok());
        let lv_empty = lv_empty.unwrap();
        assert!(lv_empty.is_empty());
    }

    #[test]
    fn test_data_too_large() {
        let data_big: [u8; u8::MAX as usize + 1] = [0; u8::MAX as usize + 1];
        let lv = Lv::new(&data_big);
        assert!(lv.is_err());
        let error = lv.unwrap_err();
        if let TlvLvError::DataTooLarge(size) = error {
            assert_eq!(size, u8::MAX as usize + 1);
            assert_eq!(
                error.to_string(),
                "data with size 256 larger than allowed 255 bytes"
            );
        } else {
            panic!("invalid exception {:?}", error)
        }
    }

    #[test]
    fn test_serialization_buf_too_small() {
        let mut buf: [u8; 3] = [0; 3];
        let lv_data: [u8; 4] = [1, 2, 3, 4];
        let lv = Lv::new(&lv_data).unwrap();
        let res = lv.write_to_be_bytes(&mut buf);
        assert!(res.is_err());
        let error = res.unwrap_err();
        if let ByteConversionError::ToSliceTooSmall { found, expected } = error {
            assert_eq!(expected, 5);
            assert_eq!(found, 3);
        } else {
            panic!("invalid error {}", error);
        }
    }

    #[test]
    fn test_deserialization_buf_too_small() {
        let mut buf: [u8; 3] = [0; 3];
        buf[0] = 4;
        let res = Lv::from_bytes(&buf);
        assert!(res.is_err());
        let error = res.unwrap_err();
        if let ByteConversionError::FromSliceTooSmall { found, expected } = error {
            assert_eq!(found, 3);
            assert_eq!(expected, 5);
        } else {
            panic!("invalid error {}", error);
        }
    }

    fn verify_test_str_lv(lv: Lv) {
        let mut buf: [u8; 16] = [0; 16];
        let res = lv.write_to_be_bytes(&mut buf);
        assert!(res.is_ok());
        let res = res.unwrap();
        assert_eq!(res, 8 + 1);
        assert_eq!(buf[0], 8);
        assert_eq!(buf[1], b't');
        assert_eq!(buf[2], b'e');
        assert_eq!(buf[3], b's');
        assert_eq!(buf[4], b't');
        assert_eq!(buf[5], b'.');
        assert_eq!(buf[6], b'b');
        assert_eq!(buf[7], b'i');
        assert_eq!(buf[8], b'n');
    }
    #[test]
    fn test_str_helper() {
        let test_str = "test.bin";
        let str_lv = Lv::new_from_str(test_str);
        assert!(str_lv.is_ok());
        verify_test_str_lv(str_lv.unwrap());
    }

    #[test]
    fn test_string_helper() {
        let string = String::from("test.bin");
        let str_lv = Lv::new_from_string(&string);
        assert!(str_lv.is_ok());
        verify_test_str_lv(str_lv.unwrap());
    }
}
