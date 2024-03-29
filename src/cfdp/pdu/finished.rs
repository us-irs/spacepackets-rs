use crate::cfdp::pdu::{
    add_pdu_crc, generic_length_checks_pdu_deserialization, FileDirectiveType, PduError, PduHeader,
};
use crate::cfdp::tlv::{
    EntityIdTlv, FilestoreResponseTlv, GenericTlv, Tlv, TlvType, TlvTypeField, WritableTlv,
};
use crate::cfdp::{ConditionCode, CrcFlag, Direction, PduType, TlvLvError};
use crate::ByteConversionError;
use num_enum::{IntoPrimitive, TryFromPrimitive};
#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

use super::{CfdpPdu, WritablePduPacket};

#[derive(Debug, Copy, Clone, PartialEq, Eq, TryFromPrimitive, IntoPrimitive)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
#[repr(u8)]
pub enum DeliveryCode {
    Complete = 0,
    Incomplete = 1,
}

#[derive(Debug, Copy, Clone, PartialEq, Eq, TryFromPrimitive, IntoPrimitive)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
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
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct FinishedPduCreator<'fs_responses> {
    pdu_header: PduHeader,
    condition_code: ConditionCode,
    delivery_code: DeliveryCode,
    file_status: FileStatus,
    fs_responses:
        &'fs_responses [FilestoreResponseTlv<'fs_responses, 'fs_responses, 'fs_responses>],
    fault_location: Option<EntityIdTlv>,
}

impl<'fs_responses> FinishedPduCreator<'fs_responses> {
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
            &[],
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
            &[],
            Some(fault_location),
        )
    }

    pub fn new_generic(
        mut pdu_header: PduHeader,
        condition_code: ConditionCode,
        delivery_code: DeliveryCode,
        file_status: FileStatus,
        fs_responses: &'fs_responses [FilestoreResponseTlv<
            'fs_responses,
            'fs_responses,
            'fs_responses,
        >],
        fault_location: Option<EntityIdTlv>,
    ) -> Self {
        pdu_header.pdu_type = PduType::FileDirective;
        // Enforce correct direction bit.
        pdu_header.pdu_conf.direction = Direction::TowardsSender;
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

    pub fn condition_code(&self) -> ConditionCode {
        self.condition_code
    }

    pub fn delivery_code(&self) -> DeliveryCode {
        self.delivery_code
    }

    pub fn file_status(&self) -> FileStatus {
        self.file_status
    }

    // If there are no filestore responses, an empty slice will be returned.
    pub fn filestore_responses(&self) -> &[FilestoreResponseTlv<'_, '_, '_>] {
        self.fs_responses
    }

    pub fn fault_location(&self) -> Option<EntityIdTlv> {
        self.fault_location
    }

    fn calc_pdu_datafield_len(&self) -> usize {
        let mut datafield_len = 2;
        for fs_response in self.fs_responses {
            datafield_len += fs_response.len_full();
        }
        if let Some(fault_location) = self.fault_location {
            datafield_len += fault_location.len_full();
        }
        if self.crc_flag() == CrcFlag::WithCrc {
            datafield_len += 2;
        }
        datafield_len
    }
}

impl CfdpPdu for FinishedPduCreator<'_> {
    fn pdu_header(&self) -> &PduHeader {
        &self.pdu_header
    }

    fn file_directive_type(&self) -> Option<FileDirectiveType> {
        Some(FileDirectiveType::FinishedPdu)
    }
}

impl WritablePduPacket for FinishedPduCreator<'_> {
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
        buf[current_idx] = FileDirectiveType::FinishedPdu as u8;
        current_idx += 1;
        buf[current_idx] = ((self.condition_code as u8) << 4)
            | ((self.delivery_code as u8) << 2)
            | self.file_status as u8;
        current_idx += 1;
        for fs_responses in self.fs_responses {
            current_idx += fs_responses.write_to_bytes(&mut buf[current_idx..])?;
        }
        if let Some(fault_location) = self.fault_location {
            current_idx += fault_location.write_to_bytes(&mut buf[current_idx..])?;
        }
        if self.crc_flag() == CrcFlag::WithCrc {
            current_idx = add_pdu_crc(buf, current_idx);
        }
        Ok(current_idx)
    }

    fn len_written(&self) -> usize {
        self.pdu_header.header_len() + self.calc_pdu_datafield_len()
    }
}

/// Helper structure to loop through all filestore responses of a read Finished PDU. It should be
/// noted that iterators in Rust are not fallible, but the TLV creation can fail, for example if
/// the raw TLV data is invalid for some reason. In that case, the iterator will yield [None]
/// because there is no way to recover from this.
///
/// The user can accumulate the length of all TLVs yielded by the iterator and compare it against
/// the full length of the options to check whether the iterator was able to parse all TLVs
/// successfully.
pub struct FilestoreResponseIterator<'buf> {
    responses_buf: &'buf [u8],
    current_idx: usize,
}

impl<'buf> Iterator for FilestoreResponseIterator<'buf> {
    type Item = FilestoreResponseTlv<'buf, 'buf, 'buf>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.current_idx == self.responses_buf.len() {
            return None;
        }
        let tlv = FilestoreResponseTlv::from_bytes(&self.responses_buf[self.current_idx..]);
        // There are not really fallible iterators so we can't continue here..
        if tlv.is_err() {
            return None;
        }
        let tlv = tlv.unwrap();
        self.current_idx += tlv.len_full();
        Some(tlv)
    }
}

#[derive(Debug, Copy, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct FinishedPduReader<'buf> {
    pdu_header: PduHeader,
    condition_code: ConditionCode,
    delivery_code: DeliveryCode,
    file_status: FileStatus,
    fs_responses_raw: &'buf [u8],
    fault_location: Option<EntityIdTlv>,
}

impl<'buf> FinishedPduReader<'buf> {
    /// Generates [Self] from a raw bytestream.
    pub fn new(buf: &'buf [u8]) -> Result<Self, PduError> {
        Self::from_bytes(buf)
    }

    /// Generates [Self] from a raw bytestream.
    pub fn from_bytes(buf: &'buf [u8]) -> Result<Self, PduError> {
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
        let (fs_responses_raw, fault_location) =
            Self::parse_tlv_fields(current_idx, full_len_without_crc, buf)?;
        Ok(Self {
            pdu_header,
            condition_code,
            delivery_code,
            file_status,
            fs_responses_raw,
            fault_location,
        })
    }

    pub fn fs_responses_raw(&self) -> &[u8] {
        self.fs_responses_raw
    }

    pub fn fs_responses_iter(&self) -> FilestoreResponseIterator<'_> {
        FilestoreResponseIterator {
            responses_buf: self.fs_responses_raw,
            current_idx: 0,
        }
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

    pub fn fault_location(&self) -> Option<EntityIdTlv> {
        self.fault_location
    }

    fn parse_tlv_fields(
        mut current_idx: usize,
        full_len_without_crc: usize,
        buf: &[u8],
    ) -> Result<(&[u8], Option<EntityIdTlv>), PduError> {
        let mut fs_responses: &[u8] = &[];
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
                            fs_responses = &buf[start_of_fs_responses..current_idx];
                        }
                    } else if tlv_type == TlvType::EntityId {
                        // At least one FS response is included.
                        if current_idx > start_of_fs_responses {
                            fs_responses = &buf[start_of_fs_responses..current_idx];
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
                        return Err(TlvLvError::InvalidTlvTypeField {
                            found: tlv_type.into(),
                            expected: Some(TlvType::FilestoreResponse.into()),
                        }
                        .into());
                    }
                }
                TlvTypeField::Custom(raw) => {
                    return Err(TlvLvError::InvalidTlvTypeField {
                        found: raw,
                        expected: None,
                    }
                    .into());
                }
            }
        }
        Ok((fs_responses, fault_location))
    }
}

impl CfdpPdu for FinishedPduReader<'_> {
    fn pdu_header(&self) -> &PduHeader {
        &self.pdu_header
    }

    fn file_directive_type(&self) -> Option<FileDirectiveType> {
        Some(FileDirectiveType::FinishedPdu)
    }
}

impl PartialEq<FinishedPduCreator<'_>> for FinishedPduReader<'_> {
    fn eq(&self, other: &FinishedPduCreator<'_>) -> bool {
        self.pdu_header == other.pdu_header
            && self.condition_code == other.condition_code
            && self.delivery_code == other.delivery_code
            && self.file_status == other.file_status
            && self.fault_location == other.fault_location
            && self
                .fs_responses_iter()
                .zip(other.filestore_responses().iter())
                .all(|(a, b)| a == *b)
    }
}

impl PartialEq<FinishedPduReader<'_>> for FinishedPduCreator<'_> {
    fn eq(&self, other: &FinishedPduReader<'_>) -> bool {
        other.eq(self)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cfdp::lv::Lv;
    use crate::cfdp::pdu::tests::{
        common_pdu_conf, verify_raw_header, TEST_DEST_ID, TEST_SEQ_NUM, TEST_SRC_ID,
    };
    use crate::cfdp::pdu::{FileDirectiveType, PduHeader};
    use crate::cfdp::tlv::FilestoreResponseTlv;
    use crate::cfdp::{ConditionCode, CrcFlag, Direction, LargeFileFlag, TransmissionMode};

    fn generic_finished_pdu(
        crc_flag: CrcFlag,
        fss: LargeFileFlag,
        delivery_code: DeliveryCode,
        file_status: FileStatus,
    ) -> FinishedPduCreator<'static> {
        let pdu_header = PduHeader::new_no_file_data(common_pdu_conf(crc_flag, fss), 0);
        FinishedPduCreator::new_default(pdu_header, delivery_code, file_status)
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
        assert_eq!(
            finished_pdu.pdu_header().pdu_conf.direction,
            Direction::TowardsSender
        );
        assert_eq!(finished_pdu.delivery_code(), DeliveryCode::Complete);
        assert_eq!(finished_pdu.file_status(), FileStatus::Retained);
        assert_eq!(finished_pdu.filestore_responses(), &[]);
        assert_eq!(finished_pdu.fault_location(), None);
        assert_eq!(finished_pdu.pdu_header().pdu_datafield_len, 2);

        assert_eq!(finished_pdu.crc_flag(), CrcFlag::NoCrc);
        assert_eq!(finished_pdu.file_flag(), LargeFileFlag::Normal);
        assert_eq!(finished_pdu.pdu_type(), PduType::FileDirective);
        assert_eq!(
            finished_pdu.file_directive_type(),
            Some(FileDirectiveType::FinishedPdu)
        );
        assert_eq!(
            finished_pdu.transmission_mode(),
            TransmissionMode::Acknowledged
        );
        assert_eq!(finished_pdu.direction(), Direction::TowardsSender);
        assert_eq!(finished_pdu.source_id(), TEST_SRC_ID.into());
        assert_eq!(finished_pdu.dest_id(), TEST_DEST_ID.into());
        assert_eq!(finished_pdu.transaction_seq_num(), TEST_SEQ_NUM.into());
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
        assert_eq!(written, 9);
        assert_eq!(written, finished_pdu.len_written());
        assert_eq!(written, finished_pdu.pdu_header().header_len() + 2);
        assert_eq!(
            finished_pdu.pdu_header().pdu_conf.direction,
            Direction::TowardsSender
        );
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
    fn test_write_to_vec() {
        let finished_pdu = generic_finished_pdu(
            CrcFlag::NoCrc,
            LargeFileFlag::Normal,
            DeliveryCode::Complete,
            FileStatus::Retained,
        );
        let mut buf: [u8; 64] = [0; 64];
        let written = finished_pdu.write_to_bytes(&mut buf).unwrap();
        let pdu_vec = finished_pdu.to_vec().unwrap();
        assert_eq!(buf[0..written], pdu_vec);
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
        let read_back = FinishedPduReader::from_bytes(&buf);
        assert!(read_back.is_ok());
        let read_back = read_back.unwrap();
        assert_eq!(finished_pdu, read_back);
        // Use all getter functions here explicitely once.
        assert_eq!(finished_pdu.pdu_header(), read_back.pdu_header());
        assert_eq!(finished_pdu.condition_code(), read_back.condition_code());
        assert_eq!(finished_pdu.fault_location(), read_back.fault_location());
        assert_eq!(finished_pdu.file_status(), read_back.file_status());
        assert_eq!(finished_pdu.delivery_code(), read_back.delivery_code());
    }

    #[test]
    fn test_serialization_buf_too_small() {
        let finished_pdu = generic_finished_pdu(
            CrcFlag::NoCrc,
            LargeFileFlag::Normal,
            DeliveryCode::Complete,
            FileStatus::Retained,
        );
        let mut buf: [u8; 8] = [0; 8];
        let error = finished_pdu.write_to_bytes(&mut buf);
        assert!(error.is_err());
        if let PduError::ByteConversion(ByteConversionError::ToSliceTooSmall { found, expected }) =
            error.unwrap_err()
        {
            assert_eq!(found, 8);
            assert_eq!(expected, 9);
        } else {
            panic!("expected to_slice_too_small error");
        }
    }

    #[test]
    fn test_with_crc() {
        let finished_pdu = generic_finished_pdu(
            CrcFlag::WithCrc,
            LargeFileFlag::Normal,
            DeliveryCode::Complete,
            FileStatus::Retained,
        );
        let mut buf: [u8; 64] = [0; 64];
        let written = finished_pdu.write_to_bytes(&mut buf).unwrap();
        assert_eq!(written, finished_pdu.len_written());
        let finished_pdu_from_raw = FinishedPduReader::new(&buf).unwrap();
        assert_eq!(finished_pdu, finished_pdu_from_raw);
        buf[written - 1] -= 1;
        let crc: u16 = ((buf[written - 2] as u16) << 8) as u16 | buf[written - 1] as u16;
        let error = FinishedPduReader::new(&buf).unwrap_err();
        if let PduError::ChecksumError(e) = error {
            assert_eq!(e, crc);
        } else {
            panic!("expected crc error");
        }
    }

    #[test]
    fn test_with_fault_location() {
        let pdu_header =
            PduHeader::new_no_file_data(common_pdu_conf(CrcFlag::NoCrc, LargeFileFlag::Normal), 0);
        let finished_pdu = FinishedPduCreator::new_with_error(
            pdu_header,
            ConditionCode::NakLimitReached,
            DeliveryCode::Incomplete,
            FileStatus::DiscardDeliberately,
            EntityIdTlv::new(TEST_DEST_ID.into()),
        );
        let finished_pdu_vec = finished_pdu.to_vec().unwrap();
        assert_eq!(finished_pdu_vec.len(), 12);
        assert_eq!(finished_pdu_vec[9], TlvType::EntityId.into());
        assert_eq!(finished_pdu_vec[10], 1);
        assert_eq!(finished_pdu_vec[11], TEST_DEST_ID.value_typed());
        assert_eq!(
            finished_pdu.fault_location().unwrap().entity_id(),
            &TEST_DEST_ID.into()
        );
    }

    #[test]
    fn test_deserialization_with_fault_location() {
        let pdu_header =
            PduHeader::new_no_file_data(common_pdu_conf(CrcFlag::NoCrc, LargeFileFlag::Normal), 0);
        let entity_id_tlv = EntityIdTlv::new(TEST_DEST_ID.into());
        let finished_pdu = FinishedPduCreator::new_with_error(
            pdu_header,
            ConditionCode::NakLimitReached,
            DeliveryCode::Incomplete,
            FileStatus::DiscardDeliberately,
            entity_id_tlv,
        );
        let finished_pdu_vec = finished_pdu.to_vec().unwrap();
        let finished_pdu_deserialized = FinishedPduReader::from_bytes(&finished_pdu_vec).unwrap();
        assert_eq!(finished_pdu, finished_pdu_deserialized);
    }

    #[test]
    fn test_deserialization_with_fs_responses() {
        let entity_id_tlv = EntityIdTlv::new(TEST_DEST_ID.into());
        let first_name = "first.txt";
        let first_name_lv = Lv::new_from_str(first_name).unwrap();
        let fs_response_0 = FilestoreResponseTlv::new_no_filestore_message(
            crate::cfdp::tlv::FilestoreActionCode::CreateFile,
            0,
            first_name_lv,
            None,
        )
        .unwrap();
        let fs_response_1 = FilestoreResponseTlv::new_no_filestore_message(
            crate::cfdp::tlv::FilestoreActionCode::DeleteFile,
            0,
            first_name_lv,
            None,
        )
        .unwrap();
        let fs_responses = &[fs_response_0, fs_response_1];

        let pdu_header =
            PduHeader::new_no_file_data(common_pdu_conf(CrcFlag::NoCrc, LargeFileFlag::Normal), 0);
        let finished_pdu = FinishedPduCreator::new_generic(
            pdu_header,
            ConditionCode::NakLimitReached,
            DeliveryCode::Incomplete,
            FileStatus::DiscardDeliberately,
            fs_responses,
            Some(entity_id_tlv),
        );
        let finished_pdu_vec = finished_pdu.to_vec().unwrap();
        let finished_pdu_deserialized = FinishedPduReader::from_bytes(&finished_pdu_vec).unwrap();
        assert_eq!(finished_pdu_deserialized, finished_pdu);
    }

    #[test]
    fn test_deserialization_with_fs_responses_and_fault_location() {
        let first_name = "first.txt";
        let first_name_lv = Lv::new_from_str(first_name).unwrap();
        let fs_response_0 = FilestoreResponseTlv::new_no_filestore_message(
            crate::cfdp::tlv::FilestoreActionCode::CreateFile,
            0,
            first_name_lv,
            None,
        )
        .unwrap();
        let fs_response_1 = FilestoreResponseTlv::new_no_filestore_message(
            crate::cfdp::tlv::FilestoreActionCode::DeleteFile,
            0,
            first_name_lv,
            None,
        )
        .unwrap();
        let fs_responses = &[fs_response_0, fs_response_1];

        let pdu_header =
            PduHeader::new_no_file_data(common_pdu_conf(CrcFlag::NoCrc, LargeFileFlag::Normal), 0);
        let finished_pdu = FinishedPduCreator::new_generic(
            pdu_header,
            ConditionCode::NakLimitReached,
            DeliveryCode::Incomplete,
            FileStatus::DiscardDeliberately,
            fs_responses,
            None,
        );
        let finished_pdu_vec = finished_pdu.to_vec().unwrap();
        let finished_pdu_deserialized = FinishedPduReader::from_bytes(&finished_pdu_vec).unwrap();
        assert_eq!(finished_pdu_deserialized, finished_pdu);
    }
}
