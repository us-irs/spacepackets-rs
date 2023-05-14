use crate::{ByteConversionError, SizeMissmatch};
use core::fmt::Debug;
#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

pub trait ToBeBytes {
    type ByteArray: AsRef<[u8]>;
    /// Length when written to big endian bytes.
    fn written_len(&self) -> usize;
    fn to_be_bytes(&self) -> Self::ByteArray;
}

impl ToBeBytes for () {
    type ByteArray = [u8; 0];

    fn written_len(&self) -> usize {
        0
    }

    fn to_be_bytes(&self) -> Self::ByteArray {
        []
    }
}

impl ToBeBytes for u8 {
    type ByteArray = [u8; 1];

    fn written_len(&self) -> usize {
        1
    }
    fn to_be_bytes(&self) -> Self::ByteArray {
        u8::to_be_bytes(*self)
    }
}

impl ToBeBytes for u16 {
    type ByteArray = [u8; 2];

    fn written_len(&self) -> usize {
        2
    }
    fn to_be_bytes(&self) -> Self::ByteArray {
        u16::to_be_bytes(*self)
    }
}

impl ToBeBytes for u32 {
    type ByteArray = [u8; 4];

    fn written_len(&self) -> usize {
        4
    }
    fn to_be_bytes(&self) -> Self::ByteArray {
        u32::to_be_bytes(*self)
    }
}

impl ToBeBytes for u64 {
    type ByteArray = [u8; 8];

    fn written_len(&self) -> usize {
        8
    }
    fn to_be_bytes(&self) -> Self::ByteArray {
        u64::to_be_bytes(*self)
    }
}

#[allow(clippy::len_without_is_empty)]
pub trait UnsignedEnum {
    fn len(&self) -> usize;
    fn write_to_be_bytes(&self, buf: &mut [u8]) -> Result<(), ByteConversionError>;
}

pub trait UnsignedEnumExt: UnsignedEnum + Debug + Copy + Clone + PartialEq + Eq {}

/// Type erased variant.
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct UnsignedByteField {
    width: usize,
    value: u64,
}

impl UnsignedByteField {
    pub fn new(width: usize, value: u64) -> Self {
        Self { width, value }
    }

    pub fn new_from_be_bytes(width: usize, buf: &[u8]) -> Result<Self, ByteConversionError> {
        if width > buf.len() {
            return Err(ByteConversionError::FromSliceTooSmall(SizeMissmatch {
                found: buf.len(),
                expected: width,
            }));
        }
        match width {
            0 => Ok(Self::new(0, 0)),
            1 => Ok(Self::new(1, buf[0] as u64)),
            2 => Ok(Self::new(
                2,
                u16::from_be_bytes(buf[0..2].try_into().unwrap()) as u64,
            )),
            4 => Ok(Self::new(
                2,
                u32::from_be_bytes(buf[0..4].try_into().unwrap()) as u64,
            )),
            8 => Ok(Self::new(
                2,
                u64::from_be_bytes(buf[0..8].try_into().unwrap()),
            )),
            // TODO: I don't know whether it is a good idea to panic here.
            _ => panic!("invalid width"),
        }
    }
}

impl UnsignedEnum for UnsignedByteField {
    fn len(&self) -> usize {
        self.width
    }

    fn write_to_be_bytes(&self, buf: &mut [u8]) -> Result<(), ByteConversionError> {
        if buf.len() < self.len() {
            return Err(ByteConversionError::ToSliceTooSmall(SizeMissmatch {
                expected: self.len(),
                found: buf.len(),
            }));
        }
        match self.len() {
            0 => Ok(()),
            1 => {
                let u8 = UnsignedU8::try_from(*self).unwrap();
                u8.write_to_be_bytes(buf)
            }
            2 => {
                let u16 = UnsignedU16::try_from(*self).unwrap();
                u16.write_to_be_bytes(buf)
            }
            4 => {
                let u32 = UnsignedU32::try_from(*self).unwrap();
                u32.write_to_be_bytes(buf)
            }
            8 => {
                let u64 = UnsignedU64::try_from(*self).unwrap();
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
pub struct GenericUnsignedByteField<TYPE> {
    val: TYPE,
}

impl<TYPE> GenericUnsignedByteField<TYPE> {
    pub fn new(val: TYPE) -> Self {
        Self { val }
    }
}

impl<TYPE: ToBeBytes> UnsignedEnum for GenericUnsignedByteField<TYPE> {
    fn len(&self) -> usize {
        self.val.written_len()
    }

    fn write_to_be_bytes(&self, buf: &mut [u8]) -> Result<(), ByteConversionError> {
        if buf.len() < self.len() {
            return Err(ByteConversionError::ToSliceTooSmall(SizeMissmatch {
                found: buf.len(),
                expected: self.len(),
            }));
        }
        buf[0..self.len()].copy_from_slice(self.val.to_be_bytes().as_ref());
        Ok(())
    }
}

pub type UnsignedByteFieldEmpty = GenericUnsignedByteField<()>;
pub type UnsignedU8 = GenericUnsignedByteField<u8>;
pub type UnsignedU16 = GenericUnsignedByteField<u16>;
pub type UnsignedU32 = GenericUnsignedByteField<u32>;
pub type UnsignedU64 = GenericUnsignedByteField<u64>;

impl From<UnsignedU8> for UnsignedByteField {
    fn from(value: UnsignedU8) -> Self {
        Self::new(1, value.val as u64)
    }
}

impl TryFrom<UnsignedByteField> for UnsignedU8 {
    type Error = ();

    fn try_from(value: UnsignedByteField) -> Result<Self, ()> {
        if value.value > 2_u64.pow(8) - 1 {
            return Err(());
        }
        Ok(Self::new(value.value as u8))
    }
}

impl From<UnsignedU16> for UnsignedByteField {
    fn from(value: UnsignedU16) -> Self {
        Self::new(2, value.val as u64)
    }
}

impl TryFrom<UnsignedByteField> for UnsignedU16 {
    type Error = ();

    fn try_from(value: UnsignedByteField) -> Result<Self, ()> {
        if value.value > 2_u64.pow(16) - 1 {
            return Err(());
        }
        Ok(Self::new(value.value as u16))
    }
}

impl From<UnsignedU32> for UnsignedByteField {
    fn from(value: UnsignedU32) -> Self {
        Self::new(4, value.val as u64)
    }
}

impl TryFrom<UnsignedByteField> for UnsignedU32 {
    type Error = ();

    fn try_from(value: UnsignedByteField) -> Result<Self, ()> {
        if value.value > 2_u64.pow(32) - 1 {
            return Err(());
        }
        Ok(Self::new(value.value as u32))
    }
}

impl From<UnsignedU64> for UnsignedByteField {
    fn from(value: UnsignedU64) -> Self {
        Self::new(8, value.val)
    }
}

impl TryFrom<UnsignedByteField> for UnsignedU64 {
    type Error = ();

    fn try_from(value: UnsignedByteField) -> Result<Self, ()> {
        if value.value > 2_u64.pow(64) - 1 {
            return Err(());
        }
        Ok(Self::new(value.value))
    }
}
