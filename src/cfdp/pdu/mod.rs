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
    transaction_seq_num: UnsignedByteField,
    trans_mode: TransmissionMode,
    file_flag: LargeFileFlag,
    crc_flag: CrcFlag,
    direction: Direction,
}

impl CommonPduConfig {
    pub fn new(
        source_id: UnsignedByteField,
        dest_id: UnsignedByteField,
        transaction_seq_num: UnsignedByteField,
        trans_mode: TransmissionMode,
        file_flag: LargeFileFlag,
        crc_flag: CrcFlag,
        direction: Direction,
    ) -> Result<Self, PduError> {
        if source_id.len() != dest_id.len() {
            return Err(PduError::SourceDestIdLenMissmatch((
                source_id.len(),
                dest_id.len(),
            )));
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
}
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
        seg_metadata_flag: SegmentMetadataFlag,
        seg_ctrl: SegmentationControl,
        pdu_datafield_len: u16,
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
            pdu_type: PduType::FileData,
            pdu_conf,
            seg_metadata_flag: SegmentMetadataFlag::NotPresent,
            seg_ctrl: SegmentationControl::NoRecordBoundaryPreservation,
            pdu_datafield_len,
        }
    }

    pub fn write_to_be_bytes(&self, buf: &mut [u8]) -> Result<(), PduError> {
        if self.pdu_conf.source_entity_id.len() != self.pdu_conf.dest_entity_id.len() {
            return Err(PduError::SourceDestIdLenMissmatch((
                self.pdu_conf.source_entity_id.len(),
                self.pdu_conf.dest_entity_id.len(),
            )));
        }
        if buf.len()
            < 4 + self.pdu_conf.source_entity_id.len() + self.pdu_conf.transaction_seq_num.len()
        {
            return Err(ByteConversionError::ToSliceTooSmall(SizeMissmatch {
                found: buf.len(),
                expected: 4,
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
            | ((self.pdu_conf.source_entity_id.len() as u8) << 4)
            | ((self.seg_metadata_flag as u8) << 3)
            | (self.pdu_conf.transaction_seq_num.len() as u8);
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
        Ok(())
    }

    pub fn from_be_bytes(buf: &[u8]) -> Result<Self, PduError> {
        if buf.len() < 4 {
            return Err(PduError::ByteConversionError(
                ByteConversionError::FromSliceTooSmall(SizeMissmatch {
                    found: buf.len(),
                    expected: 4,
                }),
            ));
        }
        let cfdp_version_raw = buf[0] >> 5 & 0b111;
        if cfdp_version_raw != CFDP_VERSION_2 {
            return Err(PduError::CfdpVersionMissmatch(cfdp_version_raw));
        }
        // Conversion for 1 bit value always works
        let pdu_type = PduType::try_from((buf[0] >> 4) & 0b1).unwrap();
        let direction = Direction::try_from((buf[0] >> 3) & 0b1).unwrap();
        let trans_mode = TransmissionMode::try_from((buf[0] >> 2) & 0b1).unwrap();
        let crc_flag = CrcFlag::try_from((buf[0] >> 1) & 0b1).unwrap();
        let file_flag = LargeFileFlag::try_from(buf[0] & 0b1).unwrap();
        let pdu_datafield_len = u16::from_be_bytes(buf[1..3].try_into().unwrap());
        let seg_ctrl = SegmentationControl::try_from((buf[3] >> 7) & 0b1).unwrap();
        let expected_len_entity_ids = ((buf[3] >> 4) & 0b111) as usize;
        if (expected_len_entity_ids != 1)
            && (expected_len_entity_ids != 2)
            && (expected_len_entity_ids != 4)
            && (expected_len_entity_ids != 8)
        {
            return Err(PduError::InvalidEntityLen(expected_len_entity_ids as u8));
        }
        let seg_metadata_flag = SegmentMetadataFlag::try_from((buf[3] >> 3) & 0b1).unwrap();
        let expected_len_seq_num = (buf[3] & 0b111) as usize;
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
        Ok(PduHeader {
            pdu_type,
            pdu_conf: common_pdu_conf,
            seg_metadata_flag,
            seg_ctrl,
            pdu_datafield_len,
        })
    }
    pub fn pdu_type(&self) -> PduType {
        self.pdu_type
    }

    pub fn common_pdu_conf(&self) -> &CommonPduConfig {
        &self.pdu_conf
    }
}
