use crate::ByteConversionError;
use core::fmt::{Debug, Display, Formatter};
#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};
#[cfg(feature = "std")]
use std::error::Error;

pub trait ToBeBytes {
    type ByteArray: AsRef<[u8]>;
    /// Length when written to big endian bytes.
    fn written_len(&self) -> usize;
    fn to_be_bytes(&self) -> Self::ByteArray;
}

impl ToBeBytes for () {
    type ByteArray = [u8; 0];

    #[inline]
    fn written_len(&self) -> usize {
        0
    }

    #[inline]
    fn to_be_bytes(&self) -> Self::ByteArray {
        []
    }
}

impl ToBeBytes for u8 {
    type ByteArray = [u8; 1];

    #[inline]
    fn written_len(&self) -> usize {
        1
    }

    #[inline]
    fn to_be_bytes(&self) -> Self::ByteArray {
        u8::to_be_bytes(*self)
    }
}

impl ToBeBytes for u16 {
    type ByteArray = [u8; 2];

    #[inline]
    fn written_len(&self) -> usize {
        2
    }

    #[inline]
    fn to_be_bytes(&self) -> Self::ByteArray {
        u16::to_be_bytes(*self)
    }
}

impl ToBeBytes for u32 {
    type ByteArray = [u8; 4];

    #[inline]
    fn written_len(&self) -> usize {
        4
    }

    #[inline]
    fn to_be_bytes(&self) -> Self::ByteArray {
        u32::to_be_bytes(*self)
    }
}

impl ToBeBytes for u64 {
    type ByteArray = [u8; 8];

    #[inline]
    fn written_len(&self) -> usize {
        8
    }

    #[inline]
    fn to_be_bytes(&self) -> Self::ByteArray {
        u64::to_be_bytes(*self)
    }
}

pub trait UnsignedEnum {
    /// Size of the unsigned enumeration in bytes.
    fn size(&self) -> usize;
    /// Write the unsigned enumeration to a raw buffer. Returns the written size on success.
    fn write_to_be_bytes(&self, buf: &mut [u8]) -> Result<usize, ByteConversionError>;

    fn value(&self) -> u64;

    #[cfg(feature = "alloc")]
    fn to_vec(&self) -> alloc::vec::Vec<u8> {
        let mut buf = alloc::vec![0; self.size()];
        self.write_to_be_bytes(&mut buf).unwrap();
        buf
    }
}

pub trait UnsignedEnumExt: UnsignedEnum + Debug + Copy + Clone + PartialEq + Eq {}

#[derive(Debug, Copy, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum UnsignedByteFieldError {
    /// Value is too large for specified width of byte field.
    ValueTooLargeForWidth {
        width: usize,
        value: u64,
    },
    /// Only 1, 2, 4 and 8 are allow width values. Optionally contains the expected width if
    /// applicable, for example for conversions.
    InvalidWidth {
        found: usize,
        expected: Option<usize>,
    },
    ByteConversionError(ByteConversionError),
}

impl From<ByteConversionError> for UnsignedByteFieldError {
    #[inline]
    fn from(value: ByteConversionError) -> Self {
        Self::ByteConversionError(value)
    }
}

impl Display for UnsignedByteFieldError {
    fn fmt(&self, f: &mut Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::ByteConversionError(e) => {
                write!(f, "low level byte conversion error: {e}")
            }
            Self::InvalidWidth { found, .. } => {
                write!(f, "invalid width {found}, only 1, 2, 4 and 8 are allowed.")
            }
            Self::ValueTooLargeForWidth { width, value } => {
                write!(f, "value {value} too large for width {width}")
            }
        }
    }
}

#[cfg(feature = "std")]
impl Error for UnsignedByteFieldError {}

/// Type erased variant.
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct UnsignedByteField {
    width: usize,
    value: u64,
}

impl UnsignedByteField {
    #[inline]
    pub const fn new(width: usize, value: u64) -> Self {
        Self { width, value }
    }

    #[inline]
    pub const fn value_const(&self) -> u64 {
        self.value
    }

    #[inline]
    pub fn new_from_be_bytes(width: usize, buf: &[u8]) -> Result<Self, UnsignedByteFieldError> {
        if width > buf.len() {
            return Err(ByteConversionError::FromSliceTooSmall {
                expected: width,
                found: buf.len(),
            }
            .into());
        }
        match width {
            0 => Ok(Self::new(width, 0)),
            1 => Ok(Self::new(width, buf[0] as u64)),
            2 => Ok(Self::new(
                width,
                u16::from_be_bytes(buf[0..2].try_into().unwrap()) as u64,
            )),
            4 => Ok(Self::new(
                width,
                u32::from_be_bytes(buf[0..4].try_into().unwrap()) as u64,
            )),
            8 => Ok(Self::new(
                width,
                u64::from_be_bytes(buf[0..8].try_into().unwrap()),
            )),
            _ => Err(UnsignedByteFieldError::InvalidWidth {
                found: width,
                expected: None,
            }),
        }
    }
}

impl UnsignedEnum for UnsignedByteField {
    #[inline]
    fn size(&self) -> usize {
        self.width
    }

    #[inline]
    fn value(&self) -> u64 {
        self.value_const()
    }

    fn write_to_be_bytes(&self, buf: &mut [u8]) -> Result<usize, ByteConversionError> {
        if buf.len() < self.size() {
            return Err(ByteConversionError::ToSliceTooSmall {
                expected: self.size(),
                found: buf.len(),
            });
        }
        match self.size() {
            0 => Ok(0),
            1 => {
                let u8 = UnsignedByteFieldU8::try_from(*self).unwrap();
                u8.write_to_be_bytes(buf)
            }
            2 => {
                let u16 = UnsignedByteFieldU16::try_from(*self).unwrap();
                u16.write_to_be_bytes(buf)
            }
            4 => {
                let u32 = UnsignedByteFieldU32::try_from(*self).unwrap();
                u32.write_to_be_bytes(buf)
            }
            8 => {
                let u64 = UnsignedByteFieldU64::try_from(*self).unwrap();
                u64.write_to_be_bytes(buf)
            }
            _ => {
                // The API does not allow this.
                panic!("unexpected written length");
            }
        }
    }
}

#[derive(Debug, Copy, Clone, Eq, PartialEq)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct GenericUnsignedByteField<TYPE: Copy + Into<u64>> {
    value: TYPE,
}

impl<TYPE: Copy + Into<u64>> GenericUnsignedByteField<TYPE> {
    pub const fn new(val: TYPE) -> Self {
        Self { value: val }
    }

    pub const fn value_typed(&self) -> TYPE {
        self.value
    }
}

impl<TYPE: Copy + ToBeBytes + Into<u64>> UnsignedEnum for GenericUnsignedByteField<TYPE> {
    #[inline]
    fn size(&self) -> usize {
        self.value.written_len()
    }

    fn write_to_be_bytes(&self, buf: &mut [u8]) -> Result<usize, ByteConversionError> {
        if buf.len() < self.size() {
            return Err(ByteConversionError::ToSliceTooSmall {
                found: buf.len(),
                expected: self.size(),
            });
        }
        buf[..self.size()].copy_from_slice(self.value.to_be_bytes().as_ref());
        Ok(self.value.written_len())
    }

    #[inline]
    fn value(&self) -> u64 {
        self.value_typed().into()
    }
}

pub type UnsignedByteFieldEmpty = GenericUnsignedByteField<()>;
pub type UnsignedByteFieldU8 = GenericUnsignedByteField<u8>;
pub type UnsignedByteFieldU16 = GenericUnsignedByteField<u16>;
pub type UnsignedByteFieldU32 = GenericUnsignedByteField<u32>;
pub type UnsignedByteFieldU64 = GenericUnsignedByteField<u64>;

pub type UbfU8 = UnsignedByteFieldU8;
pub type UbfU16 = UnsignedByteFieldU16;
pub type UbfU32 = UnsignedByteFieldU32;
pub type UbfU64 = UnsignedByteFieldU64;

impl From<UnsignedByteFieldU8> for UnsignedByteField {
    fn from(value: UnsignedByteFieldU8) -> Self {
        Self::new(1, value.value as u64)
    }
}

impl TryFrom<UnsignedByteField> for UnsignedByteFieldU8 {
    type Error = UnsignedByteFieldError;

    #[inline]
    fn try_from(value: UnsignedByteField) -> Result<Self, Self::Error> {
        if value.width != 1 {
            return Err(UnsignedByteFieldError::InvalidWidth {
                found: value.width,
                expected: Some(1),
            });
        }
        Ok(Self::new(value.value as u8))
    }
}

impl From<UnsignedByteFieldU16> for UnsignedByteField {
    #[inline]
    fn from(value: UnsignedByteFieldU16) -> Self {
        Self::new(2, value.value as u64)
    }
}

impl TryFrom<UnsignedByteField> for UnsignedByteFieldU16 {
    type Error = UnsignedByteFieldError;

    #[inline]
    fn try_from(value: UnsignedByteField) -> Result<Self, Self::Error> {
        if value.width != 2 {
            return Err(UnsignedByteFieldError::InvalidWidth {
                found: value.width,
                expected: Some(2),
            });
        }
        Ok(Self::new(value.value as u16))
    }
}

impl From<UnsignedByteFieldU32> for UnsignedByteField {
    #[inline]
    fn from(value: UnsignedByteFieldU32) -> Self {
        Self::new(4, value.value as u64)
    }
}

impl TryFrom<UnsignedByteField> for UnsignedByteFieldU32 {
    type Error = UnsignedByteFieldError;

    #[inline]
    fn try_from(value: UnsignedByteField) -> Result<Self, Self::Error> {
        if value.width != 4 {
            return Err(UnsignedByteFieldError::InvalidWidth {
                found: value.width,
                expected: Some(4),
            });
        }
        Ok(Self::new(value.value as u32))
    }
}

impl From<UnsignedByteFieldU64> for UnsignedByteField {
    #[inline]
    fn from(value: UnsignedByteFieldU64) -> Self {
        Self::new(8, value.value)
    }
}

impl TryFrom<UnsignedByteField> for UnsignedByteFieldU64 {
    type Error = UnsignedByteFieldError;

    #[inline]
    fn try_from(value: UnsignedByteField) -> Result<Self, Self::Error> {
        if value.width != 8 {
            return Err(UnsignedByteFieldError::InvalidWidth {
                found: value.width,
                expected: Some(8),
            });
        }
        Ok(Self::new(value.value))
    }
}

#[cfg(test)]
pub mod tests {
    use crate::util::{
        UnsignedByteField, UnsignedByteFieldError, UnsignedByteFieldU16, UnsignedByteFieldU32,
        UnsignedByteFieldU64, UnsignedByteFieldU8, UnsignedEnum,
    };
    use crate::ByteConversionError;
    use std::format;

    #[test]
    fn test_simple_u8() {
        let u8 = UnsignedByteFieldU8::new(5);
        assert_eq!(u8.size(), 1);
        let mut buf: [u8; 8] = [0; 8];
        let len = u8
            .write_to_be_bytes(&mut buf)
            .expect("writing to raw buffer failed");
        assert_eq!(len, 1);
        assert_eq!(buf[0], 5);
        for val in buf.iter().skip(1) {
            assert_eq!(*val, 0);
        }
        assert_eq!(u8.value_typed(), 5);
        assert_eq!(u8.value(), 5);
    }

    #[test]
    fn test_simple_u16() {
        let u16 = UnsignedByteFieldU16::new(3823);
        assert_eq!(u16.size(), 2);
        let mut buf: [u8; 8] = [0; 8];
        let len = u16
            .write_to_be_bytes(&mut buf)
            .expect("writing to raw buffer failed");
        assert_eq!(len, 2);
        let raw_val = u16::from_be_bytes(buf[0..2].try_into().unwrap());
        assert_eq!(raw_val, 3823);
        for val in buf.iter().skip(2) {
            assert_eq!(*val, 0);
        }
        assert_eq!(u16.value_typed(), 3823);
        assert_eq!(u16.value(), 3823);
    }

    #[test]
    fn test_simple_u32() {
        let u32 = UnsignedByteFieldU32::new(80932);
        assert_eq!(u32.size(), 4);
        let mut buf: [u8; 8] = [0; 8];
        let len = u32
            .write_to_be_bytes(&mut buf)
            .expect("writing to raw buffer failed");
        assert_eq!(len, 4);
        let raw_val = u32::from_be_bytes(buf[0..4].try_into().unwrap());
        assert_eq!(raw_val, 80932);
        (4..8).for_each(|i| {
            assert_eq!(buf[i], 0);
        });
        assert_eq!(u32.value_typed(), 80932);
        assert_eq!(u32.value(), 80932);
    }

    #[test]
    fn test_simple_u64() {
        let u64 = UnsignedByteFieldU64::new(5999999);
        assert_eq!(u64.size(), 8);
        let mut buf: [u8; 8] = [0; 8];
        let len = u64
            .write_to_be_bytes(&mut buf)
            .expect("writing to raw buffer failed");
        assert_eq!(len, 8);
        let raw_val = u64::from_be_bytes(buf[0..8].try_into().unwrap());
        assert_eq!(raw_val, 5999999);
        assert_eq!(u64.value_typed(), 5999999);
        assert_eq!(u64.value(), 5999999);
    }

    #[test]
    fn conversions_u8() {
        let u8 = UnsignedByteFieldU8::new(5);
        let u8_type_erased = UnsignedByteField::from(u8);
        assert_eq!(u8_type_erased.width, 1);
        assert_eq!(u8_type_erased.value, 5);
        let u8_conv_back =
            UnsignedByteFieldU8::try_from(u8_type_erased).expect("conversion failed for u8");
        assert_eq!(u8, u8_conv_back);
        assert_eq!(u8_conv_back.value, 5);
    }

    #[test]
    fn conversion_u8_fails() {
        let field = UnsignedByteField::new(2, 60000);
        let conv_fails = UnsignedByteFieldU8::try_from(field);
        assert!(conv_fails.is_err());
        let err = conv_fails.unwrap_err();
        match err {
            UnsignedByteFieldError::InvalidWidth {
                found,
                expected: Some(expected),
            } => {
                assert_eq!(found, 2);
                assert_eq!(expected, 1);
            }
            _ => {
                panic!("{}", format!("invalid error {err}"))
            }
        }
    }

    #[test]
    fn conversions_u16() {
        let u16 = UnsignedByteFieldU16::new(64444);
        let u16_type_erased = UnsignedByteField::from(u16);
        assert_eq!(u16_type_erased.width, 2);
        assert_eq!(u16_type_erased.value, 64444);
        let u16_conv_back =
            UnsignedByteFieldU16::try_from(u16_type_erased).expect("conversion failed for u16");
        assert_eq!(u16, u16_conv_back);
        assert_eq!(u16_conv_back.value, 64444);
    }

    #[test]
    fn conversion_u16_fails() {
        let field = UnsignedByteField::new(4, 75000);
        let conv_fails = UnsignedByteFieldU16::try_from(field);
        assert!(conv_fails.is_err());
        let err = conv_fails.unwrap_err();
        match err {
            UnsignedByteFieldError::InvalidWidth {
                found,
                expected: Some(expected),
            } => {
                assert_eq!(found, 4);
                assert_eq!(expected, 2);
            }
            _ => {
                panic!("{}", format!("invalid error {err}"))
            }
        }
    }

    #[test]
    fn conversions_u32() {
        let u32 = UnsignedByteFieldU32::new(75000);
        let u32_type_erased = UnsignedByteField::from(u32);
        assert_eq!(u32_type_erased.width, 4);
        assert_eq!(u32_type_erased.value, 75000);
        let u32_conv_back =
            UnsignedByteFieldU32::try_from(u32_type_erased).expect("conversion failed for u32");
        assert_eq!(u32, u32_conv_back);
        assert_eq!(u32_conv_back.value, 75000);
    }

    #[test]
    fn conversion_u32_fails() {
        let field = UnsignedByteField::new(8, 75000);
        let conv_fails = UnsignedByteFieldU32::try_from(field);
        assert!(conv_fails.is_err());
        let err = conv_fails.unwrap_err();
        match err {
            UnsignedByteFieldError::InvalidWidth {
                found,
                expected: Some(expected),
            } => {
                assert_eq!(found, 8);
                assert_eq!(expected, 4);
            }
            _ => {
                panic!("{}", format!("invalid error {err}"))
            }
        }
    }

    #[test]
    fn conversions_u64() {
        let u64 = UnsignedByteFieldU64::new(5999999);
        let u64_type_erased = UnsignedByteField::from(u64);
        assert_eq!(u64_type_erased.width, 8);
        assert_eq!(u64_type_erased.value, 5999999);
        let u64_conv_back =
            UnsignedByteFieldU64::try_from(u64_type_erased).expect("conversion failed for u64");
        assert_eq!(u64, u64_conv_back);
        assert_eq!(u64_conv_back.value, 5999999);
    }

    #[test]
    fn conversion_u64_fails() {
        let field = UnsignedByteField::new(4, 60000);
        let conv_fails = UnsignedByteFieldU64::try_from(field);
        assert!(conv_fails.is_err());
        let err = conv_fails.unwrap_err();
        match err {
            UnsignedByteFieldError::InvalidWidth {
                found,
                expected: Some(expected),
            } => {
                assert_eq!(found, 4);
                assert_eq!(expected, 8);
            }
            _ => {
                panic!("{}", format!("invalid error {err}"))
            }
        }
    }

    #[test]
    fn type_erased_u8_write() {
        let u8 = UnsignedByteField::new(1, 5);
        assert_eq!(u8.size(), 1);
        let mut buf: [u8; 8] = [0; 8];
        u8.write_to_be_bytes(&mut buf)
            .expect("writing to raw buffer failed");
        assert_eq!(buf[0], 5);
        (1..8).for_each(|i| {
            assert_eq!(buf[i], 0);
        });
    }

    #[test]
    fn type_erased_u16_write() {
        let u16 = UnsignedByteField::new(2, 3823);
        assert_eq!(u16.size(), 2);
        let mut buf: [u8; 8] = [0; 8];
        u16.write_to_be_bytes(&mut buf)
            .expect("writing to raw buffer failed");
        let raw_val = u16::from_be_bytes(buf[0..2].try_into().unwrap());
        assert_eq!(raw_val, 3823);
        for val in buf.iter().skip(2) {
            assert_eq!(*val, 0);
        }
    }

    #[test]
    fn type_erased_u32_write() {
        let u32 = UnsignedByteField::new(4, 80932);
        assert_eq!(u32.size(), 4);
        let mut buf: [u8; 8] = [0; 8];
        u32.write_to_be_bytes(&mut buf)
            .expect("writing to raw buffer failed");
        let raw_val = u32::from_be_bytes(buf[0..4].try_into().unwrap());
        assert_eq!(raw_val, 80932);
        (4..8).for_each(|i| {
            assert_eq!(buf[i], 0);
        });
    }

    #[test]
    fn type_erased_u64_write() {
        let u64 = UnsignedByteField::new(8, 5999999);
        assert_eq!(u64.size(), 8);
        let mut buf: [u8; 8] = [0; 8];
        u64.write_to_be_bytes(&mut buf)
            .expect("writing to raw buffer failed");
        let raw_val = u64::from_be_bytes(buf[0..8].try_into().unwrap());
        assert_eq!(raw_val, 5999999);
    }

    #[test]
    fn type_erased_u8_construction() {
        let buf: [u8; 2] = [5, 10];
        let u8 = UnsignedByteField::new_from_be_bytes(1, &buf).expect("construction failed");
        assert_eq!(u8.width, 1);
        assert_eq!(u8.value, 5);
    }

    #[test]
    fn type_erased_u16_construction() {
        let buf: [u8; 2] = [0x10, 0x15];
        let u16 = UnsignedByteField::new_from_be_bytes(2, &buf).expect("construction failed");
        assert_eq!(u16.width, 2);
        assert_eq!(u16.value, 0x1015);
    }

    #[test]
    fn type_erased_u32_construction() {
        let buf: [u8; 4] = [0x01, 0x02, 0x03, 0x04];
        let u32 = UnsignedByteField::new_from_be_bytes(4, &buf).expect("construction failed");
        assert_eq!(u32.width, 4);
        assert_eq!(u32.value, 0x01020304);
    }

    #[test]
    fn type_erased_u64_construction() {
        let buf: [u8; 8] = [0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08];
        let u64 = UnsignedByteField::new_from_be_bytes(8, &buf).expect("construction failed");
        assert_eq!(u64.width, 8);
        assert_eq!(u64.value, 0x0102030405060708);
    }

    #[test]
    fn type_u16_target_buf_too_small() {
        let u16 = UnsignedByteFieldU16::new(500);
        let mut buf: [u8; 1] = [0; 1];
        let res = u16.write_to_be_bytes(&mut buf);
        assert!(res.is_err());
        let err = res.unwrap_err();
        match err {
            ByteConversionError::ToSliceTooSmall { found, expected } => {
                assert_eq!(found, 1);
                assert_eq!(expected, 2);
            }
            _ => {
                panic!("invalid exception")
            }
        }
    }

    #[test]
    fn type_erased_u16_target_buf_too_small() {
        let u16 = UnsignedByteField::new(2, 500);
        let mut buf: [u8; 1] = [0; 1];
        let res = u16.write_to_be_bytes(&mut buf);
        assert!(res.is_err());
        let err = res.unwrap_err();
        match err {
            ByteConversionError::ToSliceTooSmall { found, expected } => {
                assert_eq!(found, 1);
                assert_eq!(expected, 2);
            }
            _ => {
                panic!("invalid exception {}", err)
            }
        }
        let u16 = UnsignedByteField::new_from_be_bytes(2, &buf);
        assert!(u16.is_err());
        let err = u16.unwrap_err();
        if let UnsignedByteFieldError::ByteConversionError(
            ByteConversionError::FromSliceTooSmall { found, expected },
        ) = err
        {
            assert_eq!(expected, 2);
            assert_eq!(found, 1);
        } else {
            panic!("unexpected exception {}", err);
        }
    }

    #[test]
    fn type_u32_target_buf_too_small() {
        let u16 = UnsignedByteFieldU32::new(500);
        let mut buf: [u8; 3] = [0; 3];
        let res = u16.write_to_be_bytes(&mut buf);
        assert!(res.is_err());
        let err = res.unwrap_err();
        match err {
            ByteConversionError::ToSliceTooSmall { found, expected } => {
                assert_eq!(found, 3);
                assert_eq!(expected, 4);
            }
            _ => {
                panic!("invalid exception")
            }
        }
    }
}
