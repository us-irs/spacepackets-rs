use crate::cfdp::*;
use crate::util::{UnsignedByteField, UnsignedEnum};
use crate::{ByteConversionError, SizeMissmatch};
use core::fmt::{Display, Formatter};
#[cfg(feature = "std")]
use std::error::Error;

#[derive(Debug, Copy, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub enum PduError {
    ByteConversionError(ByteConversionError),
    /// Found version ID invalid, not equal to [CFDP_VERSION_2].
    CfdpVersionMissmatch(u8),
    /// Invalid length for the entity ID detected. Only the values 1, 2, 4 and 8 are supported.
    InvalidEntityLen(u8),
    /// Invalid length for the entity ID detected. Only the values 1, 2, 4 and 8 are supported.
    InvalidTransactionSeqNumLen(u8),
    /// The first entry will be the source entity ID length, the second one the destination entity
    /// ID length.
    SourceDestIdLenMissmatch((usize, usize)),
}

impl Display for PduError {
    fn fmt(&self, f: &mut Formatter<'_>) -> core::fmt::Result {
        match self {
            PduError::InvalidEntityLen(raw_id) => {
                write!(
                    f,
                    "Invalid entity ID length {raw_id}, only [1, 2, 4, 8] are allowed"
                )
            }
            PduError::InvalidTransactionSeqNumLen(raw_id) => {
                write!(
                    f,
                    "Invalid transaction seq num length {raw_id}, only [1, 2, 4, 8] are allowed"
                )
            }
            PduError::CfdpVersionMissmatch(raw) => {
                write!(
                    f,
                    "cfdp version missmatch, found {raw}, expected {CFDP_VERSION_2}"
                )
            }
            PduError::SourceDestIdLenMissmatch((src_len, dest_len)) => {
                write!(
                    f,
                    "missmatch of source length {src_len} and destination length {dest_len}"
                )
            }
            PduError::ByteConversionError(e) => {
                write!(f, "low level byte conversion error: {e}")
            }
        }
    }
}

#[cfg(feature = "std")]
impl Error for PduError {}

impl From<ByteConversionError> for PduError {
    fn from(value: ByteConversionError) -> Self {
        Self::ByteConversionError(value)
    }
}

/// Common configuration fields for a PDU.
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct CommonPduConfig {
    source_entity_id: UnsignedByteField,
    dest_entity_id: UnsignedByteField,
    pub transaction_seq_num: UnsignedByteField,
    pub trans_mode: TransmissionMode,
    pub file_flag: LargeFileFlag,
    pub crc_flag: CrcFlag,
    pub direction: Direction,
}

// TODO: Builder pattern might be applicable here..
impl CommonPduConfig {
    pub fn new(
        source_id: impl Into<UnsignedByteField>,
        dest_id: impl Into<UnsignedByteField>,
        transaction_seq_num: impl Into<UnsignedByteField>,
        trans_mode: TransmissionMode,
        file_flag: LargeFileFlag,
        crc_flag: CrcFlag,
        direction: Direction,
    ) -> Result<Self, PduError> {
        let source_id = source_id.into();
        let dest_id = dest_id.into();
        let transaction_seq_num = transaction_seq_num.into();
        if source_id.len() != dest_id.len() {
            return Err(PduError::SourceDestIdLenMissmatch((
                source_id.len(),
                dest_id.len(),
            )));
        }
        if source_id.len() != 1
            && source_id.len() != 2
            && source_id.len() != 4
            && source_id.len() != 8
        {
            return Err(PduError::InvalidEntityLen(source_id.len() as u8));
        }
        if transaction_seq_num.len() != 1
            && transaction_seq_num.len() != 2
            && transaction_seq_num.len() != 4
            && transaction_seq_num.len() != 8
        {
            return Err(PduError::InvalidTransactionSeqNumLen(
                transaction_seq_num.len() as u8,
            ));
        }
        Ok(Self {
            source_entity_id: source_id,
            dest_entity_id: dest_id,
            transaction_seq_num,
            trans_mode,
            file_flag,
            crc_flag,
            direction,
        })
    }

    pub fn new_with_defaults(
        source_id: impl Into<UnsignedByteField>,
        dest_id: impl Into<UnsignedByteField>,
        transaction_seq_num: impl Into<UnsignedByteField>,
    ) -> Result<Self, PduError> {
        Self::new(
            source_id,
            dest_id,
            transaction_seq_num,
            TransmissionMode::Acknowledged,
            LargeFileFlag::Normal,
            CrcFlag::NoCrc,
            Direction::TowardsReceiver,
        )
    }

    pub fn source_id(&self) -> UnsignedByteField {
        self.source_entity_id
    }

    pub fn dest_id(&self) -> UnsignedByteField {
        self.dest_entity_id
    }
}

const FIXED_HEADER_LEN: usize = 4;

/// Abstraction for the PDU header common to all CFDP PDUs
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct PduHeader {
    pdu_type: PduType,
    pdu_conf: CommonPduConfig,
    seg_metadata_flag: SegmentMetadataFlag,
    seg_ctrl: SegmentationControl,
    pdu_datafield_len: u16,
}

impl PduHeader {
    pub fn new_for_file_data(
        pdu_conf: CommonPduConfig,
        pdu_datafield_len: u16,
        seg_metadata_flag: SegmentMetadataFlag,
        seg_ctrl: SegmentationControl,
    ) -> Self {
        PduHeader {
            pdu_type: PduType::FileData,
            pdu_conf,
            seg_metadata_flag,
            seg_ctrl,
            pdu_datafield_len,
        }
    }

    pub fn new_no_file_data(pdu_conf: CommonPduConfig, pdu_datafield_len: u16) -> Self {
        PduHeader {
            pdu_type: PduType::FileDirective,
            pdu_conf,
            seg_metadata_flag: SegmentMetadataFlag::NotPresent,
            seg_ctrl: SegmentationControl::NoRecordBoundaryPreservation,
            pdu_datafield_len,
        }
    }

    pub fn write_to_be_bytes(&self, buf: &mut [u8]) -> Result<usize, PduError> {
        if self.pdu_conf.source_entity_id.len() != self.pdu_conf.dest_entity_id.len() {
            return Err(PduError::SourceDestIdLenMissmatch((
                self.pdu_conf.source_entity_id.len(),
                self.pdu_conf.dest_entity_id.len(),
            )));
        }
        if buf.len()
            < FIXED_HEADER_LEN
                + self.pdu_conf.source_entity_id.len()
                + self.pdu_conf.transaction_seq_num.len()
        {
            return Err(ByteConversionError::ToSliceTooSmall(SizeMissmatch {
                found: buf.len(),
                expected: FIXED_HEADER_LEN,
            })
            .into());
        }
        let mut current_idx = 0;
        buf[current_idx] = (CFDP_VERSION_2 << 5)
            | ((self.pdu_type as u8) << 4)
            | ((self.pdu_conf.direction as u8) << 3)
            | ((self.pdu_conf.trans_mode as u8) << 2)
            | ((self.pdu_conf.crc_flag as u8) << 1)
            | (self.pdu_conf.file_flag as u8);
        current_idx += 1;
        buf[current_idx..current_idx + 2].copy_from_slice(&self.pdu_datafield_len.to_be_bytes());
        current_idx += 2;
        buf[current_idx] = ((self.seg_ctrl as u8) << 7)
            | (((self.pdu_conf.source_entity_id.len() - 1) as u8) << 4)
            | ((self.seg_metadata_flag as u8) << 3)
            | ((self.pdu_conf.transaction_seq_num.len() - 1) as u8);
        current_idx += 1;
        self.pdu_conf.source_entity_id.write_to_be_bytes(
            &mut buf[current_idx..current_idx + self.pdu_conf.source_entity_id.len()],
        )?;
        current_idx += self.pdu_conf.source_entity_id.len();
        self.pdu_conf.transaction_seq_num.write_to_be_bytes(
            &mut buf[current_idx..current_idx + self.pdu_conf.transaction_seq_num.len()],
        )?;
        current_idx += self.pdu_conf.transaction_seq_num.len();
        self.pdu_conf.dest_entity_id.write_to_be_bytes(
            &mut buf[current_idx..current_idx + self.pdu_conf.dest_entity_id.len()],
        )?;
        current_idx += self.pdu_conf.dest_entity_id.len();
        Ok(current_idx)
    }

    pub fn from_be_bytes(buf: &[u8]) -> Result<(Self, usize), PduError> {
        if buf.len() < FIXED_HEADER_LEN {
            return Err(PduError::ByteConversionError(
                ByteConversionError::FromSliceTooSmall(SizeMissmatch {
                    found: buf.len(),
                    expected: FIXED_HEADER_LEN,
                }),
            ));
        }
        let cfdp_version_raw = (buf[0] >> 5) & 0b111;
        if cfdp_version_raw != CFDP_VERSION_2 {
            return Err(PduError::CfdpVersionMissmatch(cfdp_version_raw));
        }
        // unwrap for single bit fields: This operation will always succeed.
        let pdu_type = PduType::try_from((buf[0] >> 4) & 0b1).unwrap();
        let direction = Direction::try_from((buf[0] >> 3) & 0b1).unwrap();
        let trans_mode = TransmissionMode::try_from((buf[0] >> 2) & 0b1).unwrap();
        let crc_flag = CrcFlag::try_from((buf[0] >> 1) & 0b1).unwrap();
        let file_flag = LargeFileFlag::try_from(buf[0] & 0b1).unwrap();
        let pdu_datafield_len = u16::from_be_bytes(buf[1..3].try_into().unwrap());
        let seg_ctrl = SegmentationControl::try_from((buf[3] >> 7) & 0b1).unwrap();
        let expected_len_entity_ids = (((buf[3] >> 4) & 0b111) + 1) as usize;
        if (expected_len_entity_ids != 1)
            && (expected_len_entity_ids != 2)
            && (expected_len_entity_ids != 4)
            && (expected_len_entity_ids != 8)
        {
            return Err(PduError::InvalidEntityLen(expected_len_entity_ids as u8));
        }
        let seg_metadata_flag = SegmentMetadataFlag::try_from((buf[3] >> 3) & 0b1).unwrap();
        let expected_len_seq_num = ((buf[3] & 0b111) + 1) as usize;
        if (expected_len_seq_num != 1)
            && (expected_len_seq_num != 2)
            && (expected_len_seq_num != 4)
            && (expected_len_seq_num != 8)
        {
            return Err(PduError::InvalidTransactionSeqNumLen(
                expected_len_seq_num as u8,
            ));
        }
        if buf.len() < (4 + 2 * expected_len_entity_ids + expected_len_seq_num) {
            return Err(ByteConversionError::FromSliceTooSmall(SizeMissmatch {
                found: buf.len(),
                expected: 4 + 2 * expected_len_entity_ids + expected_len_seq_num,
            })
            .into());
        }
        let mut current_idx = 4;
        // It is okay to unwrap here because we checked the validity of the expected length and of
        // the remaining buffer length.
        let source_id =
            UnsignedByteField::new_from_be_bytes(expected_len_entity_ids, &buf[current_idx..])
                .unwrap();
        current_idx += expected_len_entity_ids;
        let transaction_seq_num =
            UnsignedByteField::new_from_be_bytes(expected_len_seq_num, &buf[current_idx..])
                .unwrap();
        current_idx += expected_len_seq_num;
        let dest_id =
            UnsignedByteField::new_from_be_bytes(expected_len_entity_ids, &buf[current_idx..])
                .unwrap();
        current_idx += expected_len_entity_ids;
        let common_pdu_conf = CommonPduConfig::new(
            source_id,
            dest_id,
            transaction_seq_num,
            trans_mode,
            file_flag,
            crc_flag,
            direction,
        )
        .unwrap();
        Ok((
            PduHeader {
                pdu_type,
                pdu_conf: common_pdu_conf,
                seg_metadata_flag,
                seg_ctrl,
                pdu_datafield_len,
            },
            current_idx,
        ))
    }
    pub fn pdu_type(&self) -> PduType {
        self.pdu_type
    }

    pub fn common_pdu_conf(&self) -> &CommonPduConfig {
        &self.pdu_conf
    }

    pub fn seg_metadata_flag(&self) -> SegmentMetadataFlag {
        self.seg_metadata_flag
    }
    pub fn seg_ctrl(&self) -> SegmentationControl {
        self.seg_ctrl
    }
}

#[cfg(test)]
mod tests {
    use crate::cfdp::pdu::{CommonPduConfig, PduError, PduHeader, FIXED_HEADER_LEN};
    use crate::cfdp::{
        CrcFlag, Direction, LargeFileFlag, PduType, SegmentMetadataFlag, SegmentationControl,
        TransmissionMode, CFDP_VERSION_2,
    };
    use crate::util::{UnsignedU16, UnsignedU8};
    use crate::ByteConversionError;
    use std::format;

    #[test]
    fn test_basic_state() {
        let src_id = UnsignedU8::new(1);
        let dest_id = UnsignedU8::new(2);
        let transaction_id = UnsignedU8::new(3);
        let common_pdu_cfg = CommonPduConfig::new_with_defaults(src_id, dest_id, transaction_id)
            .expect("common config creation failed");
        let pdu_header = PduHeader::new_no_file_data(common_pdu_cfg, 5);
        assert_eq!(pdu_header.pdu_type(), PduType::FileDirective);
        let common_conf_ref = pdu_header.common_pdu_conf();
        assert_eq!(*common_conf_ref, common_pdu_cfg);
        // These should be 0 and ignored for non-filedata PDUs
        assert_eq!(
            pdu_header.seg_metadata_flag(),
            SegmentMetadataFlag::NotPresent
        );
        assert_eq!(
            pdu_header.seg_ctrl(),
            SegmentationControl::NoRecordBoundaryPreservation
        );
        assert_eq!(pdu_header.pdu_datafield_len, 5);
    }

    #[test]
    fn test_serialization_1() {
        let src_id = UnsignedU8::new(1);
        let dest_id = UnsignedU8::new(2);
        let transaction_id = UnsignedU8::new(3);
        let common_pdu_cfg = CommonPduConfig::new_with_defaults(src_id, dest_id, transaction_id)
            .expect("common config creation failed");
        let pdu_header = PduHeader::new_no_file_data(common_pdu_cfg, 5);
        let mut buf: [u8; 7] = [0; 7];
        let res = pdu_header.write_to_be_bytes(&mut buf);
        assert!(res.is_ok());
        // 4 byte fixed header plus three bytes src, dest ID and transaction ID
        assert_eq!(res.unwrap(), 7);
        assert_eq!((buf[0] >> 5) & 0b111, CFDP_VERSION_2);
        // File directive
        assert_eq!((buf[0] >> 4) & 1, 0);
        // Towards receiver
        assert_eq!((buf[0] >> 3) & 1, 0);
        // Acknowledged
        assert_eq!((buf[0] >> 2) & 1, 0);
        // No CRC
        assert_eq!((buf[0] >> 1) & 1, 0);
        // Regular file size
        assert_eq!(buf[0] & 1, 0);
        let pdu_datafield_len = u16::from_be_bytes(buf[1..3].try_into().unwrap());
        assert_eq!(pdu_datafield_len, 5);
        // No record boundary preservation
        assert_eq!((buf[3] >> 7) & 1, 0);
        // Entity ID length raw value is actual number of octets - 1 => 0
        assert_eq!((buf[3] >> 4) & 0b111, 0);
        // No segment metadata
        assert_eq!((buf[3] >> 3) & 0b1, 0);
        // Transaction Sequence ID length raw value is actual number of octets - 1 => 0
        assert_eq!(buf[3] & 0b111, 0);
        assert_eq!(buf[4], 1);
        assert_eq!(buf[5], 3);
        assert_eq!(buf[6], 2);
    }

    #[test]
    fn test_deserialization_1() {
        let src_id = UnsignedU8::new(1);
        let dest_id = UnsignedU8::new(2);
        let transaction_id = UnsignedU8::new(3);
        let common_pdu_cfg = CommonPduConfig::new_with_defaults(src_id, dest_id, transaction_id)
            .expect("common config creation failed");
        let pdu_header = PduHeader::new_no_file_data(common_pdu_cfg, 5);
        let mut buf: [u8; 7] = [0; 7];
        let res = pdu_header.write_to_be_bytes(&mut buf);
        assert!(res.is_ok());
        let deser_res = PduHeader::from_be_bytes(&buf);
        assert!(deser_res.is_ok());
        let (header_read_back, read_size) = deser_res.unwrap();
        assert_eq!(read_size, 7);
        assert_eq!(header_read_back, pdu_header);
    }

    #[test]
    fn test_serialization_2() {
        let src_id = UnsignedU16::new(0x0001);
        let dest_id = UnsignedU16::new(0x0203);
        let transaction_id = UnsignedU16::new(0x0405);
        let mut common_pdu_cfg =
            CommonPduConfig::new_with_defaults(src_id, dest_id, transaction_id)
                .expect("common config creation failed");
        common_pdu_cfg.crc_flag = CrcFlag::WithCrc;
        common_pdu_cfg.direction = Direction::TowardsSender;
        common_pdu_cfg.trans_mode = TransmissionMode::Unacknowledged;
        common_pdu_cfg.file_flag = LargeFileFlag::Large;
        let pdu_header = PduHeader::new_for_file_data(
            common_pdu_cfg,
            5,
            SegmentMetadataFlag::Present,
            SegmentationControl::WithRecordBoundaryPreservation,
        );
        let mut buf: [u8; 16] = [0; 16];
        let res = pdu_header.write_to_be_bytes(&mut buf);
        assert!(res.is_ok(), "{}", format!("Result {res:?} not okay"));
        // 4 byte fixed header, 6 bytes additional fields
        assert_eq!(res.unwrap(), 10);
        assert_eq!((buf[0] >> 5) & 0b111, CFDP_VERSION_2);
        // File directive
        assert_eq!((buf[0] >> 4) & 1, 1);
        // Towards sender
        assert_eq!((buf[0] >> 3) & 1, 1);
        // Unacknowledged
        assert_eq!((buf[0] >> 2) & 1, 1);
        // With CRC
        assert_eq!((buf[0] >> 1) & 1, 1);
        // Large file size
        assert_eq!(buf[0] & 1, 1);
        let pdu_datafield_len = u16::from_be_bytes(buf[1..3].try_into().unwrap());
        assert_eq!(pdu_datafield_len, 5);
        // With record boundary preservation
        assert_eq!((buf[3] >> 7) & 1, 1);
        // Entity ID length raw value is actual number of octets - 1 => 1
        assert_eq!((buf[3] >> 4) & 0b111, 1);
        // With segment metadata
        assert_eq!((buf[3] >> 3) & 0b1, 1);
        // Transaction Sequence ID length raw value is actual number of octets - 1 => 1
        assert_eq!(buf[3] & 0b111, 1);
        assert_eq!(u16::from_be_bytes(buf[4..6].try_into().unwrap()), 0x0001);
        assert_eq!(u16::from_be_bytes(buf[6..8].try_into().unwrap()), 0x0405);
        assert_eq!(u16::from_be_bytes(buf[8..10].try_into().unwrap()), 0x0203);
    }

    #[test]
    fn test_deserialization_2() {
        let src_id = UnsignedU16::new(0x0001);
        let dest_id = UnsignedU16::new(0x0203);
        let transaction_id = UnsignedU16::new(0x0405);
        let mut common_pdu_cfg =
            CommonPduConfig::new_with_defaults(src_id, dest_id, transaction_id)
                .expect("common config creation failed");
        common_pdu_cfg.crc_flag = CrcFlag::WithCrc;
        common_pdu_cfg.direction = Direction::TowardsSender;
        common_pdu_cfg.trans_mode = TransmissionMode::Unacknowledged;
        common_pdu_cfg.file_flag = LargeFileFlag::Large;
        let pdu_header = PduHeader::new_for_file_data(
            common_pdu_cfg,
            5,
            SegmentMetadataFlag::Present,
            SegmentationControl::WithRecordBoundaryPreservation,
        );
        let mut buf: [u8; 16] = [0; 16];
        let res = pdu_header.write_to_be_bytes(&mut buf);
        assert!(res.is_ok());
        let deser_res = PduHeader::from_be_bytes(&buf);
        assert!(deser_res.is_ok());
        let (header_read_back, read_size) = deser_res.unwrap();
        assert_eq!(read_size, 10);
        assert_eq!(header_read_back, pdu_header);
    }

    #[test]
    fn test_invalid_raw_version() {
        let src_id = UnsignedU8::new(1);
        let dest_id = UnsignedU8::new(2);
        let transaction_id = UnsignedU8::new(3);
        let common_pdu_cfg = CommonPduConfig::new_with_defaults(src_id, dest_id, transaction_id)
            .expect("common config creation failed");
        let pdu_header = PduHeader::new_no_file_data(common_pdu_cfg, 5);
        let mut buf: [u8; 7] = [0; 7];
        let res = pdu_header.write_to_be_bytes(&mut buf);
        assert!(res.is_ok());
        buf[0] &= !0b1110_0000;
        buf[0] |= (CFDP_VERSION_2 + 1) << 5;
        let res = PduHeader::from_be_bytes(&buf);
        assert!(res.is_err());
        let error = res.unwrap_err();
        if let PduError::CfdpVersionMissmatch(raw_version) = error {
            assert_eq!(raw_version, CFDP_VERSION_2 + 1);
        } else {
            panic!("invalid exception: {}", error);
        }
    }

    #[test]
    fn test_buf_too_small_1() {
        let buf: [u8; 3] = [0; 3];
        let res = PduHeader::from_be_bytes(&buf);
        assert!(res.is_err());
        let error = res.unwrap_err();
        if let PduError::ByteConversionError(ByteConversionError::FromSliceTooSmall(missmatch)) =
            error
        {
            assert_eq!(missmatch.found, 3);
            assert_eq!(missmatch.expected, FIXED_HEADER_LEN);
        } else {
            panic!("invalid exception: {}", error);
        }
    }

    #[test]
    fn test_buf_too_small_2() {
        let src_id = UnsignedU8::new(1);
        let dest_id = UnsignedU8::new(2);
        let transaction_id = UnsignedU8::new(3);
        let common_pdu_cfg = CommonPduConfig::new_with_defaults(src_id, dest_id, transaction_id)
            .expect("common config creation failed");
        let pdu_header = PduHeader::new_no_file_data(common_pdu_cfg, 5);
        let mut buf: [u8; 7] = [0; 7];
        let res = pdu_header.write_to_be_bytes(&mut buf);
        assert!(res.is_ok());
        let header = PduHeader::from_be_bytes(&buf[0..6]);
        assert!(header.is_err());
        let error = header.unwrap_err();
        if let PduError::ByteConversionError(ByteConversionError::FromSliceTooSmall(missmatch)) =
            error
        {
            assert_eq!(missmatch.found, 6);
            assert_eq!(missmatch.expected, 7);
        }
    }
}
