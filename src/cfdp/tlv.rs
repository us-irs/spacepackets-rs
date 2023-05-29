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

#[derive(Debug, Copy, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub enum TlvTypeField {
    Standard(TlvType),
    Custom(u8),
}

impl From<u8> for TlvTypeField {
    fn from(value: u8) -> Self {
        match TlvType::try_from(value) {
            Ok(tlv_type) => TlvTypeField::Standard(tlv_type),
            Err(_) => TlvTypeField::Custom(value),
        }
    }
}

impl From<TlvTypeField> for u8 {
    fn from(value: TlvTypeField) -> Self {
        match value {
            TlvTypeField::Standard(std) => std as u8,
            TlvTypeField::Custom(custom) => custom,
        }
    }
}

/// Generic CFDP type-length-value (TLV) abstraction as specified in CFDP 5.1.9.
///
/// # Lifetimes
///  * `data`: If the TLV is generated from a raw bytestream, this will be the lifetime of
///    the raw bytestream. If the TLV is generated from a raw slice or a similar data reference,
///    this will be the lifetime of that data reference.
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct Tlv<'data> {
    tlv_type_field: TlvTypeField,
    #[cfg_attr(feature = "serde", serde(borrow))]
    lv: Lv<'data>,
}

impl<'data> Tlv<'data> {
    pub fn new(tlv_type: TlvType, data: &[u8]) -> Result<Tlv, TlvLvError> {
        Ok(Tlv {
            tlv_type_field: TlvTypeField::Standard(tlv_type),
            lv: Lv::new(data)?,
        })
    }

    /// Creates a TLV with an empty value field.
    pub fn new_empty(tlv_type: TlvType) -> Tlv<'data> {
        Tlv {
            tlv_type_field: TlvTypeField::Standard(tlv_type),
            lv: Lv::new_empty(),
        }
    }

    pub fn tlv_type_field(&self) -> TlvTypeField {
        self.tlv_type_field
    }

    pub fn write_to_be_bytes(&self, buf: &mut [u8]) -> Result<usize, ByteConversionError> {
        generic_len_check_data_serialization(buf, self.len_value(), MIN_TLV_LEN)?;
        buf[0] = self.tlv_type_field.into();
        self.lv.write_to_be_bytes_no_len_check(&mut buf[1..]);
        Ok(self.len_full())
    }

    pub fn value(&self) -> Option<&[u8]> {
        self.lv.value()
    }

    /// Returns the length of the value part, not including the length byte.
    pub fn len_value(&self) -> usize {
        self.lv.len_value()
    }

    /// Returns the full raw length, including the length byte.
    pub fn len_full(&self) -> usize {
        self.lv.len_full() + 1
    }

    /// Checks whether the value field is empty.
    pub fn is_empty(&self) -> bool {
        self.lv.is_empty()
    }

    /// Creates a TLV give a raw bytestream. Please note that is is not necessary to pass the
    /// bytestream with the exact size of the expected TLV. This function will take care
    /// of parsing the length byte, and the length of the parsed TLV can be retrieved using
    /// [len_full].
    pub fn from_bytes(buf: &'data [u8]) -> Result<Tlv<'data>, TlvLvError> {
        generic_len_check_deserialization(buf, MIN_TLV_LEN)?;
        Ok(Self {
            tlv_type_field: TlvTypeField::from(buf[0]),
            lv: Lv::from_bytes(&buf[MIN_LV_LEN..])?,
        })
    }
}

#[cfg(test)]
mod tests {
    use crate::cfdp::tlv::{Tlv, TlvType, TlvTypeField};
    use crate::cfdp::TlvLvError;
    use crate::util::{UbfU8, UnsignedEnum};

    #[test]
    fn test_basic() {
        let entity_id = UbfU8::new(5);
        let mut buf: [u8; 4] = [0; 4];
        assert!(entity_id.write_to_be_bytes(&mut buf).is_ok());
        let tlv_res = Tlv::new(TlvType::EntityId, &buf[0..1]);
        assert!(tlv_res.is_ok());
        let tlv_res = tlv_res.unwrap();
        assert_eq!(
            tlv_res.tlv_type_field(),
            TlvTypeField::Standard(TlvType::EntityId)
        );
        assert_eq!(tlv_res.len_full(), 3);
        assert_eq!(tlv_res.len_value(), 1);
        assert!(!tlv_res.is_empty());
        assert!(tlv_res.value().is_some());
        assert_eq!(tlv_res.value().unwrap()[0], 5);
    }

    #[test]
    fn test_serialization() {
        let entity_id = UbfU8::new(5);
        let mut buf: [u8; 4] = [0; 4];
        assert!(entity_id.write_to_be_bytes(&mut buf).is_ok());
        let tlv_res = Tlv::new(TlvType::EntityId, &buf[0..1]);
        assert!(tlv_res.is_ok());
        let tlv_res = tlv_res.unwrap();
        let mut ser_buf: [u8; 4] = [0; 4];
        assert!(tlv_res.write_to_be_bytes(&mut ser_buf).is_ok());
        assert_eq!(ser_buf[0], TlvType::EntityId as u8);
        assert_eq!(ser_buf[1], 1);
        assert_eq!(ser_buf[2], 5);
    }

    #[test]
    fn test_deserialization() {
        let entity_id = UbfU8::new(5);
        let mut buf: [u8; 4] = [0; 4];
        assert!(entity_id.write_to_be_bytes(&mut buf[2..]).is_ok());
        buf[0] = TlvType::EntityId as u8;
        buf[1] = 1;
        let tlv_from_raw = Tlv::from_bytes(&mut buf);
        assert!(tlv_from_raw.is_ok());
        let tlv_from_raw = tlv_from_raw.unwrap();
        assert_eq!(
            tlv_from_raw.tlv_type_field(),
            TlvTypeField::Standard(TlvType::EntityId)
        );
        assert_eq!(tlv_from_raw.len_value(), 1);
        assert_eq!(tlv_from_raw.len_full(), 3);
        assert!(tlv_from_raw.value().is_some());
        assert_eq!(tlv_from_raw.value().unwrap()[0], 5);
    }

    #[test]
    fn test_empty() {
        let tlv_empty = Tlv::new_empty(TlvType::MsgToUser);
        assert!(tlv_empty.value().is_none());
        assert!(tlv_empty.is_empty());
        assert_eq!(tlv_empty.len_full(), 2);
        assert_eq!(tlv_empty.len_value(), 0);
        assert_eq!(
            tlv_empty.tlv_type_field(),
            TlvTypeField::Standard(TlvType::MsgToUser)
        );
    }

    #[test]
    fn test_empty_serialization() {
        let tlv_empty = Tlv::new_empty(TlvType::MsgToUser);
        let mut buf: [u8; 4] = [0; 4];
        assert!(tlv_empty.write_to_be_bytes(&mut buf).is_ok());
        assert_eq!(buf[0], TlvType::MsgToUser as u8);
        assert_eq!(buf[1], 0);
    }

    #[test]
    fn test_empty_deserialization() {
        let mut buf: [u8; 4] = [0; 4];
        buf[0] = TlvType::MsgToUser as u8;
        buf[1] = 0;
        let tlv_empty = Tlv::from_bytes(&mut buf);
        assert!(tlv_empty.is_ok());
        let tlv_empty = tlv_empty.unwrap();
        assert!(tlv_empty.is_empty());
        assert!(tlv_empty.value().is_none());
        assert_eq!(
            tlv_empty.tlv_type_field(),
            TlvTypeField::Standard(TlvType::MsgToUser)
        );
        assert_eq!(tlv_empty.len_full(), 2);
        assert_eq!(tlv_empty.len_value(), 0);
    }

    #[test]
    fn test_buf_too_large() {
        let buf_too_large: [u8; u8::MAX as usize + 1] = [0; u8::MAX as usize + 1];
        let tlv_res = Tlv::new(TlvType::MsgToUser, &buf_too_large);
        assert!(tlv_res.is_err());
        let error = tlv_res.unwrap_err();
        if let TlvLvError::DataTooLarge(size) = error {
            assert_eq!(size, u8::MAX as usize + 1);
        } else {
            panic!("unexpected error {:?}", error);
        }
    }

    #[test]
    fn test_deserialization_custom_tlv_type() {
        let mut buf: [u8; 4] = [0; 4];
        buf[0] = 3;
        buf[1] = 1;
        buf[2] = 5;
        let tlv = Tlv::from_bytes(&mut buf);
        assert!(tlv.is_ok());
        let tlv = tlv.unwrap();
        assert_eq!(tlv.tlv_type_field(), TlvTypeField::Custom(3));
        assert_eq!(tlv.len_value(), 1);
        assert_eq!(tlv.len_full(), 3);
    }
}
