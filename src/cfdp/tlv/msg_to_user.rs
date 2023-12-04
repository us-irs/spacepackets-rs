//! Abstractions for the Message to User CFDP TLV subtype.
use super::{Tlv, TlvLvError, TlvType, TlvTypeField};
use crate::ByteConversionError;
use delegate::delegate;

#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub struct MsgToUserTlv<'data> {
    pub tlv: Tlv<'data>,
}

impl<'data> MsgToUserTlv<'data> {
    /// Create a new message to user TLV where the type field is set correctly.
    pub fn new(value: &'data [u8]) -> Result<MsgToUserTlv<'data>, TlvLvError> {
        Ok(Self {
            tlv: Tlv::new(TlvType::MsgToUser, value)?,
        })
    }

    delegate! {
        to self.tlv {
            pub fn tlv_type_field(&self) -> TlvTypeField;
            pub fn write_to_bytes(&self, buf: &mut [u8]) -> Result<usize, ByteConversionError>;
            pub fn value(&self) -> &[u8];
            /// Helper method to retrieve the length of the value. Simply calls the [slice::len] method of
            /// [Self::value]
            pub fn len_value(&self) -> usize;
            /// Returns the full raw length, including the length byte.
            pub fn len_full(&self) -> usize;
            /// Checks whether the value field is empty.
            pub fn is_empty(&self) -> bool;
            /// If the TLV was generated from a raw bytestream using [Self::from_bytes], the raw start
            /// of the TLV can be retrieved with this method.
            pub fn raw_data(&self) -> Option<&[u8]>;
        }
    }

    pub fn is_standard_tlv(&self) -> bool {
        true
    }

    pub fn tlv_type(&self) -> Option<TlvType> {
        Some(TlvType::MsgToUser)
    }

    /// Check whether this message is a reserved CFDP message like a Proxy Operation Message.
    pub fn is_reserved_cfdp_msg(&self) -> bool {
        if self.value().len() < 4 {
            return false;
        }
        let value = self.value();
        if value[0] == b'c' && value[1] == b'f' && value[2] == b'd' && value[3] == b'p' {
            return true;
        }
        false
    }

    /// This is a thin wrapper around [Tlv::from_bytes] with the additional type check.
    pub fn from_bytes(buf: &'data [u8]) -> Result<MsgToUserTlv<'data>, TlvLvError> {
        let msg_to_user = Self {
            tlv: Tlv::from_bytes(buf)?,
        };
        match msg_to_user.tlv_type_field() {
            TlvTypeField::Standard(tlv_type) => {
                if tlv_type != TlvType::MsgToUser {
                    return Err(TlvLvError::InvalidTlvTypeField {
                        found: tlv_type as u8,
                        expected: Some(TlvType::MsgToUser as u8),
                    });
                }
            }
            TlvTypeField::Custom(raw) => {
                return Err(TlvLvError::InvalidTlvTypeField{
                    found: raw,
                    expected: Some(TlvType::MsgToUser as u8),
                });
            }
        }
        Ok(msg_to_user)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_basic() {
        let custom_value: [u8; 4] = [1, 2, 3, 4];
        let msg_to_user = MsgToUserTlv::new(&custom_value);
        assert!(msg_to_user.is_ok());
        let msg_to_user = msg_to_user.unwrap();
        assert!(msg_to_user.is_standard_tlv());
        assert_eq!(msg_to_user.tlv_type().unwrap(), TlvType::MsgToUser);
        assert_eq!(msg_to_user.value(), custom_value);
        assert_eq!(msg_to_user.value().len(), 4);
        assert_eq!(msg_to_user.len_value(), 4);
        assert_eq!(msg_to_user.len_full(), 6);
        assert!(!msg_to_user.is_empty());
        assert!(msg_to_user.raw_data().is_none());
        assert!(!msg_to_user.is_reserved_cfdp_msg());
    }

    #[test]
    fn test_reserved_msg() {
        let reserved_str = "cfdp";
        let msg_to_user = MsgToUserTlv::new(reserved_str.as_bytes());
        assert!(msg_to_user.is_ok());
        let msg_to_user = msg_to_user.unwrap();
        assert!(msg_to_user.is_reserved_cfdp_msg());
    }
}
