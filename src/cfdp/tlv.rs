use crate::{ByteConversionError, SizeMissmatch};
use num_enum::{IntoPrimitive, TryFromPrimitive};
#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

pub const MIN_TLV_LEN: usize = 2;

#[derive(Debug, Copy, Clone, PartialEq, Eq, TryFromPrimitive, IntoPrimitive)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[repr(u8)]
pub enum TlvType {
    FilestoreRequest = 0x00,
    FilestoreResponse = 0x01,
    MsgToUser = 0x02,
    FaultHandler = 0x04,
    FlowLabel = 0x05,
    EntityId = 0x06,
}

pub struct Tlv<'a> {
    tlv_type: TlvType,
    data: &'a [u8],
}

#[derive(Debug, Copy, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub enum TlvError {
    DataTooLarge(usize),
    ByteConversionError(ByteConversionError),
    UnknownTlvType(u8),
}

impl From<ByteConversionError> for TlvError {
    fn from(value: ByteConversionError) -> Self {
        Self::ByteConversionError(value)
    }
}

impl<'a> Tlv<'a> {
    pub fn new(tlv_type: TlvType, data: &[u8]) -> Result<Tlv, TlvError> {
        if data.len() > u8::MAX as usize {
            return Err(TlvError::DataTooLarge(data.len()));
        }
        Ok(Tlv { tlv_type, data })
    }

    pub fn write_to_be_bytes(&self, buf: &mut [u8]) -> Result<usize, ByteConversionError> {
        if buf.len() < self.data.len() + MIN_TLV_LEN {
            return Err(ByteConversionError::ToSliceTooSmall(SizeMissmatch {
                found: buf.len(),
                expected: self.data.len() + MIN_TLV_LEN,
            }));
        }
        buf[0] = self.tlv_type as u8;
        // Length check in constructor ensures the length always has a valid value.
        buf[1] = self.data.len() as u8;
        buf[MIN_TLV_LEN..self.data.len() + MIN_TLV_LEN].copy_from_slice(self.data);
        Ok(MIN_TLV_LEN + self.data.len())
    }

    pub fn from_be_bytes(buf: &'a [u8]) -> Result<Tlv<'a>, TlvError> {
        if buf.len() < MIN_TLV_LEN {
            return Err(ByteConversionError::FromSliceTooSmall(SizeMissmatch {
                found: buf.len(),
                expected: MIN_TLV_LEN,
            })
            .into());
        }
        let tlv_type_res = TlvType::try_from(buf[0]);
        if tlv_type_res.is_err() {
            return Err(TlvError::UnknownTlvType(buf[1]));
        }
        let value_len = buf[1] as usize;
        if buf.len() < value_len {
            return Err(ByteConversionError::FromSliceTooSmall(SizeMissmatch {
                found: buf.len(),
                expected: MIN_TLV_LEN + value_len,
            })
            .into());
        }
        Ok(Self {
            tlv_type: tlv_type_res.unwrap(),
            data: &buf[MIN_TLV_LEN..MIN_TLV_LEN + value_len],
        })
    }
}
