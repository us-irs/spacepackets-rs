use crate::cfdp::pdu::{
    add_pdu_crc, generic_length_checks_pdu_deserialization, read_fss_field, write_fss_field,
    FileDirectiveType, PduError, PduHeader,
};
use crate::cfdp::tlv::EntityIdTlv;
use crate::cfdp::{ConditionCode, CrcFlag, Direction, LargeFileFlag};
use crate::ByteConversionError;
#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

use super::WritablePduPacket;

/// Finished PDU abstraction.
///
/// For more information, refer to CFDP chapter 5.2.2.
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct EofPdu {
    pdu_header: PduHeader,
    condition_code: ConditionCode,
    file_checksum: u32,
    file_size: u64,
    fault_location: Option<EntityIdTlv>,
}

impl EofPdu {
    pub fn new_no_error(mut pdu_header: PduHeader, file_checksum: u32, file_size: u64) -> Self {
        // Force correct direction flag.
        pdu_header.pdu_conf.direction = Direction::TowardsReceiver;
        let mut eof_pdu = Self {
            pdu_header,
            condition_code: ConditionCode::NoError,
            file_checksum,
            file_size,
            fault_location: None,
        };
        eof_pdu.pdu_header.pdu_datafield_len = eof_pdu.calc_pdu_datafield_len() as u16;
        eof_pdu
    }

    pub fn pdu_header(&self) -> &PduHeader {
        &self.pdu_header
    }

    pub fn condition_code(&self) -> ConditionCode {
        self.condition_code
    }

    pub fn file_checksum(&self) -> u32 {
        self.file_checksum
    }

    pub fn file_size(&self) -> u64 {
        self.file_size
    }

    fn calc_pdu_datafield_len(&self) -> usize {
        // One directive type octet, 4 bits condition code, 4 spare bits.
        let mut len = 2 + core::mem::size_of::<u32>() + 4;
        if self.pdu_header.pdu_conf.file_flag == LargeFileFlag::Large {
            len += 4;
        }
        if let Some(fault_location) = self.fault_location {
            len += fault_location.len_full();
        }
        len
    }

    pub fn from_bytes(buf: &[u8]) -> Result<EofPdu, PduError> {
        let (pdu_header, mut current_idx) = PduHeader::from_bytes(buf)?;
        let full_len_without_crc = pdu_header.verify_length_and_checksum(buf)?;
        let is_large_file = pdu_header.pdu_conf.file_flag == LargeFileFlag::Large;
        let mut min_expected_len = 2 + 4 + 4;
        if is_large_file {
            min_expected_len += 4;
        }
        generic_length_checks_pdu_deserialization(buf, min_expected_len, full_len_without_crc)?;
        let directive_type = FileDirectiveType::try_from(buf[current_idx]).map_err(|_| {
            PduError::InvalidDirectiveType {
                found: buf[current_idx],
                expected: Some(FileDirectiveType::EofPdu),
            }
        })?;
        if directive_type != FileDirectiveType::EofPdu {
            return Err(PduError::WrongDirectiveType {
                found: directive_type,
                expected: FileDirectiveType::EofPdu,
            });
        }
        current_idx += 1;
        let condition_code = ConditionCode::try_from((buf[current_idx] >> 4) & 0b1111)
            .map_err(|_| PduError::InvalidConditionCode((buf[current_idx] >> 4) & 0b1111))?;
        current_idx += 1;
        let file_checksum =
            u32::from_be_bytes(buf[current_idx..current_idx + 4].try_into().unwrap());
        current_idx += 4;
        let (fss_field_len, file_size) =
            read_fss_field(pdu_header.pdu_conf.file_flag, &buf[current_idx..]);
        current_idx += fss_field_len;
        let mut fault_location = None;
        if condition_code != ConditionCode::NoError && current_idx < full_len_without_crc {
            fault_location = Some(EntityIdTlv::from_bytes(&buf[current_idx..])?);
        }
        Ok(Self {
            pdu_header,
            condition_code,
            file_checksum,
            file_size,
            fault_location,
        })
    }
}

impl WritablePduPacket for EofPdu {
    fn write_to_bytes(&self, buf: &mut [u8]) -> Result<usize, PduError> {
        let expected_len = self.len_written();
        if buf.len() < expected_len {
            return Err(ByteConversionError::ToSliceTooSmall {
                found: buf.len(),
                expected: expected_len,
            }
            .into());
        }
        let mut current_idx = self.pdu_header.write_to_bytes(buf)?;
        buf[current_idx] = FileDirectiveType::EofPdu as u8;
        current_idx += 1;
        buf[current_idx] = (self.condition_code as u8) << 4;
        current_idx += 1;
        buf[current_idx..current_idx + 4].copy_from_slice(&self.file_checksum.to_be_bytes());
        current_idx += 4;
        current_idx += write_fss_field(
            self.pdu_header.pdu_conf.file_flag,
            self.file_size,
            &mut buf[current_idx..],
        )?;
        if let Some(fault_location) = self.fault_location {
            current_idx += fault_location.write_to_be_bytes(buf)?;
        }
        if self.pdu_header.pdu_conf.crc_flag == CrcFlag::WithCrc {
            current_idx = add_pdu_crc(buf, current_idx);
        }
        Ok(current_idx)
    }

    fn len_written(&self) -> usize {
        self.pdu_header.header_len() + self.calc_pdu_datafield_len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cfdp::pdu::tests::{common_pdu_conf, verify_raw_header};
    use crate::cfdp::pdu::{FileDirectiveType, PduHeader};
    use crate::cfdp::{ConditionCode, CrcFlag, LargeFileFlag};

    #[test]
    fn test_basic() {
        let pdu_conf = common_pdu_conf(CrcFlag::NoCrc, LargeFileFlag::Normal);
        let pdu_header = PduHeader::new_no_file_data(pdu_conf, 0);
        let eof_pdu = EofPdu::new_no_error(pdu_header, 0x01020304, 12);
        assert_eq!(eof_pdu.len_written(), pdu_header.header_len() + 2 + 4 + 4);
        assert_eq!(eof_pdu.file_checksum(), 0x01020304);
        assert_eq!(eof_pdu.file_size(), 12);
        assert_eq!(eof_pdu.condition_code(), ConditionCode::NoError);
    }

    #[test]
    fn test_serialization() {
        let pdu_conf = common_pdu_conf(CrcFlag::NoCrc, LargeFileFlag::Normal);
        let pdu_header = PduHeader::new_no_file_data(pdu_conf, 0);
        let eof_pdu = EofPdu::new_no_error(pdu_header, 0x01020304, 12);
        let mut buf: [u8; 64] = [0; 64];
        let res = eof_pdu.write_to_bytes(&mut buf);
        assert!(res.is_ok());
        let written = res.unwrap();
        assert_eq!(written, eof_pdu.len_written());
        verify_raw_header(eof_pdu.pdu_header(), &buf);
        let mut current_idx = eof_pdu.pdu_header().header_len();
        buf[current_idx] = FileDirectiveType::EofPdu as u8;
        current_idx += 1;
        assert_eq!(
            (buf[current_idx] >> 4) & 0b1111,
            ConditionCode::NoError as u8
        );
        current_idx += 1;
        assert_eq!(
            u32::from_be_bytes(buf[current_idx..current_idx + 4].try_into().unwrap()),
            0x01020304
        );
        current_idx += 4;
        assert_eq!(
            u32::from_be_bytes(buf[current_idx..current_idx + 4].try_into().unwrap()),
            12
        );
        current_idx += 4;
        assert_eq!(current_idx, written);
    }

    #[test]
    fn test_deserialization() {
        let pdu_conf = common_pdu_conf(CrcFlag::NoCrc, LargeFileFlag::Normal);
        let pdu_header = PduHeader::new_no_file_data(pdu_conf, 0);
        let eof_pdu = EofPdu::new_no_error(pdu_header, 0x01020304, 12);
        let mut buf: [u8; 64] = [0; 64];
        eof_pdu.write_to_bytes(&mut buf).unwrap();
        let eof_read_back = EofPdu::from_bytes(&buf);
        if eof_read_back.is_err() {
            let e = eof_read_back.unwrap_err();
            panic!("deserialization failed with: {e}")
        }
        let eof_read_back = eof_read_back.unwrap();
        assert_eq!(eof_read_back, eof_pdu);
    }

    #[test]
    fn test_write_to_vec() {
        let pdu_conf = common_pdu_conf(CrcFlag::NoCrc, LargeFileFlag::Normal);
        let pdu_header = PduHeader::new_no_file_data(pdu_conf, 0);
        let eof_pdu = EofPdu::new_no_error(pdu_header, 0x01020304, 12);
        let mut buf: [u8; 64] = [0; 64];
        let written = eof_pdu.write_to_bytes(&mut buf).unwrap();
        let pdu_vec = eof_pdu.to_vec().unwrap();
        assert_eq!(buf[0..written], pdu_vec);
    }
}
