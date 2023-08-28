use crate::cfdp::pdu::{
    add_pdu_crc, generic_length_checks_pdu_deserialization, FileDirectiveType, PduError, PduHeader,
};
use crate::cfdp::tlv::{EntityIdTlv, Tlv, TlvType, TlvTypeField};
use crate::cfdp::{ConditionCode, CrcFlag, PduType, TlvLvError};
use crate::ByteConversionError;
use num_enum::{IntoPrimitive, TryFromPrimitive};
#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

#[derive(Debug, Copy, Clone, PartialEq, Eq, TryFromPrimitive, IntoPrimitive)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[repr(u8)]
pub enum DeliveryCode {
    Complete = 0,
    Incomplete = 1,
}

#[derive(Debug, Copy, Clone, PartialEq, Eq, TryFromPrimitive, IntoPrimitive)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[repr(u8)]
pub enum FileStatus {
    DiscardDeliberately = 0b00,
    DiscardedFsRejection = 0b01,
    Retained = 0b10,
    Unreported = 0b11,
}

/// Finished PDU abstraction.
///
/// For more information, refer to CFDP chapter 5.2.3.
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct FinishedPdu<'fs_responses> {
    pdu_header: PduHeader,
    condition_code: ConditionCode,
    delivery_code: DeliveryCode,
    file_status: FileStatus,
    fs_responses: Option<&'fs_responses [u8]>,
    fault_location: Option<EntityIdTlv>,
}

impl<'fs_responses> FinishedPdu<'fs_responses> {
    /// Default finished PDU: No error (no fault location field) and no filestore responses.
    pub fn new_default(
        pdu_header: PduHeader,
        delivery_code: DeliveryCode,
        file_status: FileStatus,
    ) -> Self {
        Self::new_generic(
            pdu_header,
            ConditionCode::NoError,
            delivery_code,
            file_status,
            None,
            None,
        )
    }

    pub fn new_with_error(
        pdu_header: PduHeader,
        condition_code: ConditionCode,
        delivery_code: DeliveryCode,
        file_status: FileStatus,
        fault_location: EntityIdTlv,
    ) -> Self {
        Self::new_generic(
            pdu_header,
            condition_code,
            delivery_code,
            file_status,
            None,
            Some(fault_location),
        )
    }

    pub fn new_generic(
        mut pdu_header: PduHeader,
        condition_code: ConditionCode,
        delivery_code: DeliveryCode,
        file_status: FileStatus,
        fs_responses: Option<&'fs_responses [u8]>,
        fault_location: Option<EntityIdTlv>,
    ) -> Self {
        pdu_header.pdu_type = PduType::FileDirective;
        let mut finished_pdu = Self {
            pdu_header,
            condition_code,
            delivery_code,
            file_status,
            fs_responses,
            fault_location,
        };
        finished_pdu.pdu_header.pdu_datafield_len = finished_pdu.calc_pdu_datafield_len() as u16;
        finished_pdu
    }
    pub fn pdu_header(&self) -> &PduHeader {
        &self.pdu_header
    }

    pub fn written_len(&self) -> usize {
        self.pdu_header.header_len() + self.calc_pdu_datafield_len()
    }

    pub fn condition_code(&self) -> ConditionCode {
        self.condition_code
    }

    pub fn delivery_code(&self) -> DeliveryCode {
        self.delivery_code
    }

    pub fn file_status(&self) -> FileStatus {
        self.file_status
    }

    pub fn filestore_responses(&self) -> Option<&'fs_responses [u8]> {
        self.fs_responses
    }

    pub fn fault_location(&self) -> Option<EntityIdTlv> {
        self.fault_location
    }

    fn calc_pdu_datafield_len(&self) -> usize {
        let mut base_len = 2;
        if let Some(fs_responses) = self.fs_responses {
            base_len += fs_responses.len();
        }
        if let Some(fault_location) = self.fault_location {
            base_len += fault_location.len_full();
        }
        base_len
    }

    pub fn write_to_bytes(&self, buf: &mut [u8]) -> Result<usize, PduError> {
        let expected_len = self.written_len();
        if buf.len() < expected_len {
            return Err(ByteConversionError::ToSliceTooSmall {
                found: buf.len(),
                expected: expected_len,
            }
            .into());
        }

        let mut current_idx = self.pdu_header.write_to_bytes(buf)?;
        buf[current_idx] = FileDirectiveType::FinishedPdu as u8;
        current_idx += 1;
        buf[current_idx] = ((self.condition_code as u8) << 4)
            | ((self.delivery_code as u8) << 2)
            | self.file_status as u8;
        current_idx += 1;
        if let Some(fs_responses) = self.fs_responses {
            buf[current_idx..current_idx + fs_responses.len()].copy_from_slice(fs_responses);
            current_idx += fs_responses.len();
        }
        if let Some(fault_location) = self.fault_location {
            current_idx += fault_location.write_to_be_bytes(&mut buf[current_idx..])?;
        }
        if self.pdu_header.pdu_conf.crc_flag == CrcFlag::WithCrc {
            current_idx = add_pdu_crc(buf, current_idx);
        }
        Ok(current_idx)
    }

    /// Generates [Self] from a raw bytestream.
    pub fn from_bytes(buf: &'fs_responses [u8]) -> Result<Self, PduError> {
        let (pdu_header, mut current_idx) = PduHeader::from_bytes(buf)?;
        let full_len_without_crc = pdu_header.verify_length_and_checksum(buf)?;
        let min_expected_len = current_idx + 2;
        generic_length_checks_pdu_deserialization(buf, min_expected_len, full_len_without_crc)?;
        let directive_type = FileDirectiveType::try_from(buf[current_idx]).map_err(|_| {
            PduError::InvalidDirectiveType {
                found: buf[current_idx],
                expected: Some(FileDirectiveType::FinishedPdu),
            }
        })?;
        if directive_type != FileDirectiveType::FinishedPdu {
            return Err(PduError::WrongDirectiveType {
                found: directive_type,
                expected: FileDirectiveType::FinishedPdu,
            });
        }
        current_idx += 1;
        let condition_code = ConditionCode::try_from((buf[current_idx] >> 4) & 0b1111)
            .map_err(|_| PduError::InvalidConditionCode((buf[current_idx] >> 4) & 0b1111))?;
        // Unwrap is okay here for both of the following operations which can not fail.
        let delivery_code = DeliveryCode::try_from((buf[current_idx] >> 2) & 0b1).unwrap();
        let file_status = FileStatus::try_from(buf[current_idx] & 0b11).unwrap();
        current_idx += 1;
        let (fs_responses, fault_location) =
            Self::parse_tlv_fields(current_idx, full_len_without_crc, buf)?;
        Ok(Self {
            pdu_header,
            condition_code,
            delivery_code,
            file_status,
            fs_responses,
            fault_location,
        })
    }

    fn parse_tlv_fields(
        mut current_idx: usize,
        full_len_without_crc: usize,
        buf: &'fs_responses [u8],
    ) -> Result<(Option<&'fs_responses [u8]>, Option<EntityIdTlv>), PduError> {
        let mut fs_responses = None;
        let mut fault_location = None;
        let start_of_fs_responses = current_idx;
        // There are leftover filestore response(s) and/or a fault location field.
        while current_idx < full_len_without_crc {
            let next_tlv = Tlv::from_bytes(&buf[current_idx..])?;
            match next_tlv.tlv_type_field() {
                TlvTypeField::Standard(tlv_type) => {
                    if tlv_type == TlvType::FilestoreResponse {
                        current_idx += next_tlv.len_full();
                        if current_idx == full_len_without_crc {
                            fs_responses = Some(&buf[start_of_fs_responses..current_idx]);
                        }
                    } else if tlv_type == TlvType::EntityId {
                        // At least one FS response is included.
                        if current_idx > full_len_without_crc {
                            fs_responses = Some(&buf[start_of_fs_responses..current_idx]);
                        }
                        fault_location = Some(EntityIdTlv::from_bytes(&buf[current_idx..])?);
                        current_idx += fault_location.as_ref().unwrap().len_full();
                        // This is considered a configuration error: The entity ID has to be the
                        // last TLV, everything else would break the whole handling of the packet
                        // TLVs.
                        if current_idx != full_len_without_crc {
                            return Err(PduError::FormatError);
                        }
                    } else {
                        return Err(TlvLvError::InvalidTlvTypeField((tlv_type as u8, None)).into());
                    }
                }
                TlvTypeField::Custom(raw) => {
                    return Err(TlvLvError::InvalidTlvTypeField((raw, None)).into());
                }
            }
        }
        Ok((fs_responses, fault_location))
    }
}

#[cfg(test)]
mod tests {
    use crate::cfdp::pdu::finished::{DeliveryCode, FileStatus, FinishedPdu};
    use crate::cfdp::pdu::tests::{common_pdu_conf, verify_raw_header};
    use crate::cfdp::pdu::{FileDirectiveType, PduHeader};
    use crate::cfdp::{ConditionCode, CrcFlag, LargeFileFlag};

    fn generic_finished_pdu(
        crc_flag: CrcFlag,
        fss: LargeFileFlag,
        delivery_code: DeliveryCode,
        file_status: FileStatus,
    ) -> FinishedPdu<'static> {
        let pdu_header = PduHeader::new_no_file_data(common_pdu_conf(crc_flag, fss), 0);
        FinishedPdu::new_default(pdu_header, delivery_code, file_status)
    }

    #[test]
    fn test_basic() {
        let finished_pdu = generic_finished_pdu(
            CrcFlag::NoCrc,
            LargeFileFlag::Normal,
            DeliveryCode::Complete,
            FileStatus::Retained,
        );
        assert_eq!(finished_pdu.condition_code(), ConditionCode::NoError);
        assert_eq!(finished_pdu.delivery_code(), DeliveryCode::Complete);
        assert_eq!(finished_pdu.file_status(), FileStatus::Retained);
        assert_eq!(finished_pdu.filestore_responses(), None);
        assert_eq!(finished_pdu.fault_location(), None);
        assert_eq!(finished_pdu.pdu_header().pdu_datafield_len, 2);
    }

    fn generic_serialization_test_no_error(delivery_code: DeliveryCode, file_status: FileStatus) {
        let finished_pdu = generic_finished_pdu(
            CrcFlag::NoCrc,
            LargeFileFlag::Normal,
            delivery_code,
            file_status,
        );
        let mut buf: [u8; 64] = [0; 64];
        let written = finished_pdu.write_to_bytes(&mut buf);
        assert!(written.is_ok());
        let written = written.unwrap();
        assert_eq!(written, finished_pdu.written_len());
        assert_eq!(written, finished_pdu.pdu_header().header_len() + 2);
        verify_raw_header(finished_pdu.pdu_header(), &buf);
        let mut current_idx = finished_pdu.pdu_header().header_len();
        assert_eq!(buf[current_idx], FileDirectiveType::FinishedPdu as u8);
        current_idx += 1;
        assert_eq!(
            (buf[current_idx] >> 4) & 0b1111,
            ConditionCode::NoError as u8
        );
        assert_eq!((buf[current_idx] >> 2) & 0b1, delivery_code as u8);
        assert_eq!(buf[current_idx] & 0b11, file_status as u8);
        assert_eq!(current_idx + 1, written);
    }

    #[test]
    fn test_serialization_simple() {
        generic_serialization_test_no_error(DeliveryCode::Complete, FileStatus::Retained);
    }

    #[test]
    fn test_serialization_simple_2() {
        generic_serialization_test_no_error(
            DeliveryCode::Incomplete,
            FileStatus::DiscardDeliberately,
        );
    }

    #[test]
    fn test_serialization_simple_3() {
        generic_serialization_test_no_error(DeliveryCode::Incomplete, FileStatus::Unreported);
    }

    #[test]
    fn test_deserialization_simple() {
        let finished_pdu = generic_finished_pdu(
            CrcFlag::NoCrc,
            LargeFileFlag::Normal,
            DeliveryCode::Complete,
            FileStatus::Retained,
        );
        let mut buf: [u8; 64] = [0; 64];
        finished_pdu.write_to_bytes(&mut buf).unwrap();
        let read_back = FinishedPdu::from_bytes(&buf);
        assert!(read_back.is_ok());
        let read_back = read_back.unwrap();
        assert_eq!(finished_pdu, read_back);
    }
}
