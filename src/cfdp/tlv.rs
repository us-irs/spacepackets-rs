//! Generic CFDP type-length-value (TLV) abstraction as specified in CFDP 5.1.9.
use crate::cfdp::lv::{
    generic_len_check_data_serialization, generic_len_check_deserialization, Lv, MIN_LV_LEN,
};
use crate::cfdp::TlvLvError;
use crate::util::{UnsignedByteField, UnsignedByteFieldError, UnsignedEnum};
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

#[derive(Debug, Copy, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub enum TlvTypeField {
    Standard(TlvType),
    Custom(u8),
}

#[derive(Debug, Copy, Clone, PartialEq, Eq, TryFromPrimitive, IntoPrimitive)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[repr(u8)]
pub enum FsRequestActionCode {
    CreateFile = 0b0000,
    DeleteFile = 0b0001,
    RenameFile = 0b0010,
    AppendFile = 0b0011,
    ReplaceFile = 0b0100,
    CreateDirectory = 0b0101,
    RemoveDirectory = 0b0110,
    DenyFile = 0b0111,
    DenyDirectory = 0b1000,
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

    pub fn write_to_bytes(&self, buf: &mut [u8]) -> Result<usize, ByteConversionError> {
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

#[derive(Debug, Copy, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct EntityIdTlv {
    entity_id: UnsignedByteField,
}

impl EntityIdTlv {
    pub fn new(entity_id: UnsignedByteField) -> Self {
        Self { entity_id }
    }

    fn len_check(buf: &[u8]) -> Result<(), ByteConversionError> {
        if buf.len() < 2 {
            return Err(ByteConversionError::ToSliceTooSmall(SizeMissmatch {
                found: buf.len(),
                expected: 2,
            }));
        }
        Ok(())
    }

    pub fn len_value(&self) -> usize {
        self.entity_id.len()
    }

    pub fn len_full(&self) -> usize {
        2 + self.entity_id.len()
    }

    pub fn write_to_be_bytes(&self, buf: &mut [u8]) -> Result<usize, ByteConversionError> {
        Self::len_check(buf)?;
        buf[0] = TlvType::EntityId as u8;
        buf[1] = self.entity_id.len() as u8;
        self.entity_id.write_to_be_bytes(&mut buf[2..])
    }

    pub fn from_bytes(buf: &[u8]) -> Result<Self, TlvLvError> {
        Self::len_check(buf)?;
        TlvType::try_from(buf[0]).map_err(|_| {
            TlvLvError::InvalidTlvTypeField((buf[0], Some(TlvType::EntityId as u8)))
        })?;
        let len = buf[1];
        if len != 1 && len != 2 && len != 4 && len != 8 {
            return Err(TlvLvError::InvalidValueLength(len));
        }
        // Okay to unwrap here. The checks before make sure that the deserialization never fails
        let entity_id = UnsignedByteField::new_from_be_bytes(len as usize, &buf[2..]).unwrap();
        Ok(Self { entity_id })
    }

    pub fn to_tlv(self, buf: &mut [u8]) -> Result<Tlv, ByteConversionError> {
        Self::len_check(buf)?;
        self.entity_id
            .write_to_be_bytes(&mut buf[2..2 + self.entity_id.len()])?;
        Tlv::new(TlvType::EntityId, &buf[2..2 + self.entity_id.len()]).map_err(|e| match e {
            TlvLvError::ByteConversionError(e) => e,
            // All other errors are impossible.
            _ => panic!("unexpected TLV error"),
        })
    }
}

impl<'data> TryFrom<Tlv<'data>> for EntityIdTlv {
    type Error = TlvLvError;

    fn try_from(value: Tlv) -> Result<Self, Self::Error> {
        match value.tlv_type_field {
            TlvTypeField::Standard(tlv_type) => {
                if tlv_type != TlvType::EntityId {
                    return Err(TlvLvError::InvalidTlvTypeField((
                        tlv_type as u8,
                        Some(TlvType::EntityId as u8),
                    )));
                }
            }
            TlvTypeField::Custom(val) => {
                return Err(TlvLvError::InvalidTlvTypeField((
                    val,
                    Some(TlvType::EntityId as u8),
                )));
            }
        }
        if value.len_value() != 1
            && value.len_value() != 2
            && value.len_value() != 4
            && value.len_value() != 8
        {
            return Err(TlvLvError::InvalidValueLength(value.len_value() as u8));
        }
        Ok(Self::new(
            UnsignedByteField::new_from_be_bytes(value.len_value(), value.value().unwrap())
                .map_err(|e| match e {
                    UnsignedByteFieldError::ByteConversionError(e) => e,
                    // This can not happen, we checked for the length validity, and the data is always smaller than
                    // 255 bytes.
                    _ => panic!("unexpected error"),
                })?,
        ))
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
        assert!(tlv_res.write_to_bytes(&mut ser_buf).is_ok());
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
        assert!(tlv_empty.write_to_bytes(&mut buf).is_ok());
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
