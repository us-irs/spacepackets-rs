use crate::{
    cfdp::{ConditionCode, CrcFlag, Direction, TransactionStatus},
    ByteConversionError,
};

use super::{
    add_pdu_crc, generic_length_checks_pdu_deserialization, CfdpPdu, FileDirectiveType, PduError,
    PduHeader, WritablePduPacket,
};
#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

/// ACK PDU abstraction.
///
/// For more information, refer to CFDP chapter 5.2.4.
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct AckPdu {
    pdu_header: PduHeader,
    directive_code_of_acked_pdu: FileDirectiveType,
    condition_code: ConditionCode,
    transaction_status: TransactionStatus,
}

impl AckPdu {
    pub fn new(
        mut pdu_header: PduHeader,
        directive_code_of_acked_pdu: FileDirectiveType,
        condition_code: ConditionCode,
        transaction_status: TransactionStatus,
    ) -> Result<Self, PduError> {
        if directive_code_of_acked_pdu == FileDirectiveType::EofPdu {
            pdu_header.pdu_conf.direction = Direction::TowardsSender;
        } else if directive_code_of_acked_pdu == FileDirectiveType::FinishedPdu {
            pdu_header.pdu_conf.direction = Direction::TowardsReceiver;
        } else {
            return Err(PduError::InvalidDirectiveType {
                found: directive_code_of_acked_pdu as u8,
                expected: None,
            });
        }
        // Force correct direction flag.
        let mut ack_pdu = Self {
            pdu_header,
            directive_code_of_acked_pdu,
            condition_code,
            transaction_status,
        };
        ack_pdu.pdu_header.pdu_datafield_len = ack_pdu.calc_pdu_datafield_len() as u16;
        Ok(ack_pdu)
    }

    pub fn new_for_eof_pdu(
        pdu_header: PduHeader,
        condition_code: ConditionCode,
        transaction_status: TransactionStatus,
    ) -> Self {
        // Unwrap okay here, [new] can only fail on invalid directive codes.
        Self::new(
            pdu_header,
            FileDirectiveType::EofPdu,
            condition_code,
            transaction_status,
        )
        .unwrap()
    }

    pub fn new_for_finished_pdu(
        pdu_header: PduHeader,
        condition_code: ConditionCode,
        transaction_status: TransactionStatus,
    ) -> Self {
        // Unwrap okay here, [new] can only fail on invalid directive codes.
        Self::new(
            pdu_header,
            FileDirectiveType::FinishedPdu,
            condition_code,
            transaction_status,
        )
        .unwrap()
    }

    pub fn pdu_header(&self) -> &PduHeader {
        &self.pdu_header
    }

    pub fn directive_code_of_acked_pdu(&self) -> FileDirectiveType {
        self.directive_code_of_acked_pdu
    }

    pub fn condition_code(&self) -> ConditionCode {
        self.condition_code
    }

    pub fn transaction_status(&self) -> TransactionStatus {
        self.transaction_status
    }

    fn calc_pdu_datafield_len(&self) -> usize {
        if self.crc_flag() == CrcFlag::WithCrc {
            return 5;
        }
        3
    }

    pub fn from_bytes(buf: &[u8]) -> Result<AckPdu, PduError> {
        let (pdu_header, mut current_idx) = PduHeader::from_bytes(buf)?;
        let full_len_without_crc = pdu_header.verify_length_and_checksum(buf)?;
        generic_length_checks_pdu_deserialization(buf, current_idx + 3, full_len_without_crc)?;
        let directive_type = FileDirectiveType::try_from(buf[current_idx]).map_err(|_| {
            PduError::InvalidDirectiveType {
                found: buf[current_idx],
                expected: Some(FileDirectiveType::AckPdu),
            }
        })?;
        if directive_type != FileDirectiveType::AckPdu {
            return Err(PduError::WrongDirectiveType {
                found: directive_type,
                expected: FileDirectiveType::AckPdu,
            });
        }
        current_idx += 1;
        let acked_directive_type =
            FileDirectiveType::try_from(buf[current_idx] >> 4).map_err(|_| {
                PduError::InvalidDirectiveType {
                    found: buf[current_idx],
                    expected: None,
                }
            })?;
        if acked_directive_type != FileDirectiveType::EofPdu
            && acked_directive_type != FileDirectiveType::FinishedPdu
        {
            return Err(PduError::InvalidDirectiveType {
                found: acked_directive_type as u8,
                expected: None,
            });
        }
        current_idx += 1;
        let condition_code = ConditionCode::try_from((buf[current_idx] >> 4) & 0b1111)
            .map_err(|_| PduError::InvalidConditionCode((buf[current_idx] >> 4) & 0b1111))?;
        let transaction_status = TransactionStatus::try_from(buf[current_idx] & 0b11).unwrap();
        Self::new(
            pdu_header,
            acked_directive_type,
            condition_code,
            transaction_status,
        )
    }
}

impl CfdpPdu for AckPdu {
    fn pdu_header(&self) -> &PduHeader {
        &self.pdu_header
    }

    fn file_directive_type(&self) -> Option<FileDirectiveType> {
        Some(FileDirectiveType::AckPdu)
    }
}

impl WritablePduPacket for AckPdu {
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
        buf[current_idx] = FileDirectiveType::AckPdu as u8;
        current_idx += 1;

        buf[current_idx] = (self.directive_code_of_acked_pdu as u8) << 4;
        if self.directive_code_of_acked_pdu == FileDirectiveType::FinishedPdu {
            // This is the directive subtype code. It needs to be set to 0b0001 if the ACK PDU
            // acknowledges a Finished PDU, and to 0b0000 otherwise.
            buf[current_idx] |= 0b0001;
        }
        current_idx += 1;
        buf[current_idx] = ((self.condition_code as u8) << 4) | (self.transaction_status as u8);
        current_idx += 1;
        if self.crc_flag() == CrcFlag::WithCrc {
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
    use crate::cfdp::{
        pdu::tests::{common_pdu_conf, verify_raw_header, TEST_DEST_ID, TEST_SEQ_NUM, TEST_SRC_ID},
        LargeFileFlag, PduType, TransmissionMode,
    };

    use super::*;

    #[test]
    fn test_basic() {
        let pdu_conf = common_pdu_conf(CrcFlag::NoCrc, LargeFileFlag::Normal);
        let pdu_header = PduHeader::new_no_file_data(pdu_conf, 0);
        let ack_pdu = AckPdu::new(
            pdu_header,
            FileDirectiveType::FinishedPdu,
            ConditionCode::NoError,
            TransactionStatus::Active,
        )
        .expect("creating ACK PDU failed");
        assert_eq!(
            ack_pdu.directive_code_of_acked_pdu(),
            FileDirectiveType::FinishedPdu
        );
        assert_eq!(ack_pdu.condition_code(), ConditionCode::NoError);
        assert_eq!(ack_pdu.transaction_status(), TransactionStatus::Active);

        assert_eq!(ack_pdu.crc_flag(), CrcFlag::NoCrc);
        assert_eq!(ack_pdu.file_flag(), LargeFileFlag::Normal);
        assert_eq!(ack_pdu.pdu_type(), PduType::FileDirective);
        assert_eq!(
            ack_pdu.file_directive_type(),
            Some(FileDirectiveType::AckPdu)
        );
        assert_eq!(ack_pdu.transmission_mode(), TransmissionMode::Acknowledged);
        assert_eq!(ack_pdu.direction(), Direction::TowardsReceiver);
        assert_eq!(ack_pdu.source_id(), TEST_SRC_ID.into());
        assert_eq!(ack_pdu.dest_id(), TEST_DEST_ID.into());
        assert_eq!(ack_pdu.transaction_seq_num(), TEST_SEQ_NUM.into());
    }

    fn generic_serialization_test(
        condition_code: ConditionCode,
        transaction_status: TransactionStatus,
    ) {
        let pdu_conf = common_pdu_conf(CrcFlag::NoCrc, LargeFileFlag::Normal);
        let pdu_header = PduHeader::new_no_file_data(pdu_conf, 0);
        let ack_pdu = AckPdu::new_for_finished_pdu(pdu_header, condition_code, transaction_status);
        let mut buf: [u8; 64] = [0; 64];
        let res = ack_pdu.write_to_bytes(&mut buf);
        assert!(res.is_ok());
        let written = res.unwrap();
        assert_eq!(written, ack_pdu.len_written());
        verify_raw_header(ack_pdu.pdu_header(), &buf);

        assert_eq!(buf[7], FileDirectiveType::AckPdu as u8);
        assert_eq!((buf[8] >> 4) & 0b1111, FileDirectiveType::FinishedPdu as u8);
        assert_eq!(buf[8] & 0b1111, 0b0001);
        assert_eq!(buf[9] >> 4 & 0b1111, condition_code as u8);
        assert_eq!(buf[9] & 0b11, transaction_status as u8);
        assert_eq!(written, 10);
    }

    #[test]
    fn test_serialization_no_error() {
        generic_serialization_test(ConditionCode::NoError, TransactionStatus::Active);
    }

    #[test]
    fn test_serialization_fs_error() {
        generic_serialization_test(ConditionCode::FileSizeError, TransactionStatus::Terminated);
    }

    #[test]
    fn test_deserialization() {
        let pdu_conf = common_pdu_conf(CrcFlag::NoCrc, LargeFileFlag::Normal);
        let pdu_header = PduHeader::new_no_file_data(pdu_conf, 0);
        let ack_pdu = AckPdu::new_for_finished_pdu(
            pdu_header,
            ConditionCode::NoError,
            TransactionStatus::Active,
        );
        let ack_vec = ack_pdu.to_vec().unwrap();
        let ack_deserialized =
            AckPdu::from_bytes(&ack_vec).expect("ACK PDU deserialization failed");
        assert_eq!(ack_deserialized, ack_pdu);
    }

    #[test]
    fn test_with_crc() {
        let pdu_conf = common_pdu_conf(CrcFlag::WithCrc, LargeFileFlag::Normal);
        let pdu_header = PduHeader::new_no_file_data(pdu_conf, 0);
        let ack_pdu = AckPdu::new_for_finished_pdu(
            pdu_header,
            ConditionCode::NoError,
            TransactionStatus::Active,
        );
        let ack_vec = ack_pdu.to_vec().unwrap();
        assert_eq!(ack_vec.len(), ack_pdu.len_written());
        assert_eq!(ack_vec.len(), 12);
        let ack_deserialized =
            AckPdu::from_bytes(&ack_vec).expect("ACK PDU deserialization failed");
        assert_eq!(ack_deserialized, ack_pdu);
    }
}
