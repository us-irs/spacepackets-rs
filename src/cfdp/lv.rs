//! Generic CFDP length-value (LV) abstraction as specified in CFDP 5.1.8.
use crate::cfdp::TlvLvError;
use crate::{ByteConversionError, SizeMissmatch};
use core::str::Utf8Error;
#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};
#[cfg(feature = "std")]
use std::string::String;

pub const MIN_LV_LEN: usize = 1;

/// Generic CFDP length-value (LV) abstraction as specified in CFDP 5.1.8.
///
/// # Lifetimes
///  * `data`: If the LV is generated from a raw bytestream, this will be the lifetime of
///    the raw bytestream. If the LV is generated from a raw slice or a similar data reference,
///    this will be the lifetime of that data reference.
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct Lv<'data> {
    data: Option<&'data [u8]>,
}

pub(crate) fn generic_len_check_data_serialization(
    buf: &[u8],
    data_len: usize,
    min_overhead: usize,
) -> Result<(), ByteConversionError> {
    if buf.len() < data_len + min_overhead {
        return Err(ByteConversionError::ToSliceTooSmall(SizeMissmatch {
            found: buf.len(),
            expected: data_len + min_overhead,
        }));
    }
    Ok(())
}

pub(crate) fn generic_len_check_deserialization(
    buf: &[u8],
    min_overhead: usize,
) -> Result<(), ByteConversionError> {
    if buf.len() < min_overhead {
        return Err(ByteConversionError::FromSliceTooSmall(SizeMissmatch {
            found: buf.len(),
            expected: min_overhead,
        }));
    }
    Ok(())
}

impl<'data> Lv<'data> {
    pub fn new(data: &[u8]) -> Result<Lv, TlvLvError> {
        if data.len() > u8::MAX as usize {
            return Err(TlvLvError::DataTooLarge(data.len()));
        }
        Ok(Lv { data: Some(data) })
    }

    /// Creates a LV with an empty value field.
    pub fn new_empty() -> Lv<'data> {
        Lv { data: None }
    }

    /// Helper function to build a string LV. This is especially useful for the file or directory
    /// path LVs
    pub fn new_from_str(str_slice: &str) -> Result<Lv, TlvLvError> {
        Self::new(str_slice.as_bytes())
    }

    /// Helper function to build a string LV. This is especially useful for the file or directory
    /// path LVs
    #[cfg(feature = "std")]
    pub fn new_from_string(string: &'data String) -> Result<Lv<'data>, TlvLvError> {
        Self::new(string.as_bytes())
    }

    /// Returns the length of the value part, not including the length byte.
    pub fn len_value(&self) -> usize {
        if self.data.is_none() {
            return 0;
        }
        self.data.unwrap().len()
    }

    /// Returns the full raw length, including the length byte.
    pub fn len_full(&self) -> usize {
        self.len_value() + 1
    }

    /// Checks whether the value field is empty.
    pub fn is_empty(&self) -> bool {
        self.data.is_none()
    }

    pub fn value(&self) -> Option<&[u8]> {
        self.data
    }

    /// Convenience function to extract the value as a [str]. This is useful if the LV is
    /// known to contain a [str], for example being a file name.
    pub fn value_as_str(&self) -> Option<Result<&'data str, Utf8Error>> {
        self.data?;
        Some(core::str::from_utf8(self.data.unwrap()))
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
        if self.data.is_none() {
            buf[0] = 0;
            return MIN_LV_LEN;
        }
        let data = self.data.unwrap();
        // Length check in constructor ensures the length always has a valid value.
        buf[0] = data.len() as u8;
        buf[MIN_LV_LEN..data.len() + MIN_LV_LEN].copy_from_slice(data);
        MIN_LV_LEN + data.len()
    }

    pub(crate) fn from_be_bytes_no_len_check(
        buf: &'data [u8],
    ) -> Result<Lv<'data>, ByteConversionError> {
        let value_len = buf[0] as usize;
        generic_len_check_deserialization(buf, value_len + MIN_LV_LEN)?;
        let mut data = None;
        if value_len > 0 {
            data = Some(&buf[MIN_LV_LEN..MIN_LV_LEN + value_len])
        }
        Ok(Self { data })
    }
}

#[cfg(test)]
pub mod tests {
    use crate::cfdp::lv::Lv;
    use crate::cfdp::TlvLvError;
    use crate::ByteConversionError;
    use std::string::String;

    #[test]
    fn test_basic() {
        let lv_data: [u8; 4] = [1, 2, 3, 4];
        let lv_res = Lv::new(&lv_data);
        assert!(lv_res.is_ok());
        let lv = lv_res.unwrap();
        assert!(lv.value().is_some());
        let val = lv.value().unwrap();
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
        assert_eq!(lv_empty.value(), None);
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
        assert!(lv.value().is_some());
        assert_eq!(lv.len_value(), 4);
        assert_eq!(lv.len_full(), 5);
        let val = lv.value().unwrap();
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
        assert!(lv_empty.value().is_none());
    }

    #[test]
    fn test_data_too_large() {
        let data_big: [u8; u8::MAX as usize + 1] = [0; u8::MAX as usize + 1];
        let lv = Lv::new(&data_big);
        assert!(lv.is_err());
        let error = lv.unwrap_err();
        if let TlvLvError::DataTooLarge(size) = error {
            assert_eq!(size, u8::MAX as usize + 1);
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
        if let ByteConversionError::ToSliceTooSmall(missmatch) = error {
            assert_eq!(missmatch.expected, 5);
            assert_eq!(missmatch.found, 3);
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
        if let ByteConversionError::FromSliceTooSmall(missmatch) = error {
            assert_eq!(missmatch.found, 3);
            assert_eq!(missmatch.expected, 5);
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
        assert_eq!(buf[1], 't' as u8);
        assert_eq!(buf[2], 'e' as u8);
        assert_eq!(buf[3], 's' as u8);
        assert_eq!(buf[4], 't' as u8);
        assert_eq!(buf[5], '.' as u8);
        assert_eq!(buf[6], 'b' as u8);
        assert_eq!(buf[7], 'i' as u8);
        assert_eq!(buf[8], 'n' as u8);
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
