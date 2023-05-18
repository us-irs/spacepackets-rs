//! Generic CFDP type-length-value (TLV) abstraction as specified in CFDP 5.1.9.
use crate::cfdp::lv::{
    generic_len_check_data_serialization, generic_len_check_deserialization, Lv, MIN_LV_LEN,
};
use crate::cfdp::TlvLvError;
use crate::ByteConversionError;
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

/// Generic CFDP type-length-value (TLV) abstraction as specified in CFDP 5.1.9.
pub struct Tlv<'a> {
    tlv_type: TlvType,
    lv: Lv<'a>,
}

impl<'a> Tlv<'a> {
    pub fn new(tlv_type: TlvType, data: &[u8]) -> Result<Tlv, TlvLvError> {
        if data.len() > u8::MAX as usize {
            return Err(TlvLvError::DataTooLarge(data.len()));
        }
        Ok(Tlv {
            tlv_type,
            lv: Lv::new(data)?,
        })
    }

    /// Creates a TLV with an empty value field.
    pub fn new_empty(tlv_type: TlvType) -> Tlv<'a> {
        Tlv {
            tlv_type,
            lv: Lv::new_empty(),
        }
    }

    pub fn write_to_be_bytes(&self, buf: &mut [u8]) -> Result<usize, ByteConversionError> {
        generic_len_check_data_serialization(buf, self.len_value(), MIN_TLV_LEN)?;
        buf[0] = self.tlv_type as u8;
        self.lv.write_to_be_bytes_no_len_check(&mut buf[1..]);
        Ok(self.len_full())
    }

    pub fn value(&self) -> Option<&[u8]> {
        self.lv.value()
    }

    /// Returns the length of the value part, not including the length byte.
    pub fn len_value(&self) -> usize {
        self.lv.len_value() + 1
    }

    /// Returns the full raw length, including the length byte.
    pub fn len_full(&self) -> usize {
        self.lv.len_raw() + 1
    }

    /// Checks whether the value field is empty.
    pub fn is_empty(&self) -> bool {
        self.lv.is_empty()
    }

    pub fn from_be_bytes(buf: &'a [u8]) -> Result<Tlv<'a>, TlvLvError> {
        generic_len_check_deserialization(buf, MIN_TLV_LEN)?;
        let tlv_type_res = TlvType::try_from(buf[0]);
        if tlv_type_res.is_err() {
            return Err(TlvLvError::UnknownTlvType(buf[1]));
        }
        Ok(Self {
            tlv_type: tlv_type_res.unwrap(),
            lv: Lv::from_be_bytes(&buf[MIN_LV_LEN..])?,
        })
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn test_basic() {}
}
