//! CFDP Packet Data Unit (PDU) support.
use crate::cfdp::*;
use crate::util::{UnsignedByteField, UnsignedByteFieldU8, UnsignedEnum};
use crate::CRC_CCITT_FALSE;
use crate::{ByteConversionError, SizeMissmatch};
use core::fmt::{Display, Formatter};
#[cfg(feature = "std")]
use std::error::Error;

pub mod eof;
pub mod file_data;
pub mod finished;
pub mod metadata;

#[derive(Debug, Copy, Clone, PartialEq, Eq, TryFromPrimitive, IntoPrimitive)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[repr(u8)]
pub enum FileDirectiveType {
    EofPdu = 0x04,
    FinishedPdu = 0x05,
    AckPdu = 0x06,
    MetadataPdu = 0x07,
    NakPdu = 0x08,
    PromptPdu = 0x09,
    KeepAlivePdu = 0x0c,
}

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
    SourceDestIdLenMissmatch {
        src_id_len: usize,
        dest_id_len: usize,
    },
    WrongDirectiveType {
        found: FileDirectiveType,
        expected: FileDirectiveType,
    },
    /// The directive type field contained a value not in the range of permitted values.
    InvalidDirectiveType {
        found: u8,
        expected: Option<FileDirectiveType>,
    },
    /// Invalid condition code. Contains the raw detected value.
    InvalidConditionCode(u8),
    /// Invalid checksum type which is not part of the checksums listed in the
    /// [SANA Checksum Types registry](https://sanaregistry.org/r/checksum_identifiers/).
    InvalidChecksumType(u8),
    FileSizeTooLarge(u64),
    /// If the CRC flag for a PDU is enabled and the checksum check fails. Contains raw 16-bit CRC.
    ChecksumError(u16),
    /// Generic error for invalid PDU formats.
    FormatError,
    /// Error handling a TLV field.
    TlvLvError(TlvLvError),
}

impl Display for PduError {
    fn fmt(&self, f: &mut Formatter<'_>) -> core::fmt::Result {
        match self {
            PduError::InvalidEntityLen(raw_id) => {
                write!(
                    f,
                    "Invalid PDU entity ID length {raw_id}, only [1, 2, 4, 8] are allowed"
                )
            }
            PduError::InvalidTransactionSeqNumLen(raw_id) => {
                write!(
                    f,
                    "invalid PDUtransaction seq num length {raw_id}, only [1, 2, 4, 8] are allowed"
                )
            }
            PduError::CfdpVersionMissmatch(raw) => {
                write!(
                    f,
                    "cfdp version missmatch, found {raw}, expected {CFDP_VERSION_2}"
                )
            }
            PduError::SourceDestIdLenMissmatch {
                src_id_len,
                dest_id_len,
            } => {
                write!(
                    f,
                    "missmatch of PDU source length {src_id_len} and destination length {dest_id_len}"
                )
            }
            PduError::ByteConversionError(e) => {
                write!(f, "{}", e)
            }
            PduError::FileSizeTooLarge(value) => {
                write!(f, "file size value {value} exceeds allowed 32 bit width")
            }
            PduError::WrongDirectiveType { found, expected } => {
                write!(f, "found directive type {found:?}, expected {expected:?}")
            }
            PduError::InvalidConditionCode(raw_code) => {
                write!(f, "found invalid condition code with raw value {raw_code}")
            }
            PduError::InvalidDirectiveType { found, expected } => {
                write!(
                    f,
                    "invalid directive type value {found}, expected {expected:?}"
                )
            }
            PduError::InvalidChecksumType(checksum_type) => {
                write!(f, "invalid checksum type {checksum_type}")
            }
            PduError::ChecksumError(checksum) => {
                write!(f, "checksum error for CRC {checksum:#04x}")
            }
            PduError::TlvLvError(error) => {
                write!(f, "pdu tlv error: {error}")
            }
            PduError::FormatError => {
                write!(f, "generic PDU format error")
            }
        }
    }
}

#[cfg(feature = "std")]
impl Error for PduError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            PduError::ByteConversionError(e) => Some(e),
            PduError::TlvLvError(e) => Some(e),
            _ => None,
        }
    }
}

impl From<ByteConversionError> for PduError {
    fn from(value: ByteConversionError) -> Self {
        Self::ByteConversionError(value)
    }
}

impl From<TlvLvError> for PduError {
    fn from(e: TlvLvError) -> Self {
        Self::TlvLvError(e)
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
        let (source_id, dest_id) = Self::source_dest_id_check(source_id, dest_id)?;
        let transaction_seq_num = transaction_seq_num.into();
        if transaction_seq_num.size() != 1
            && transaction_seq_num.size() != 2
            && transaction_seq_num.size() != 4
            && transaction_seq_num.size() != 8
        {
            return Err(PduError::InvalidTransactionSeqNumLen(
                transaction_seq_num.size() as u8,
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

    pub fn new_with_byte_fields(
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

    fn source_dest_id_check(
        source_id: impl Into<UnsignedByteField>,
        dest_id: impl Into<UnsignedByteField>,
    ) -> Result<(UnsignedByteField, UnsignedByteField), PduError> {
        let source_id = source_id.into();
        let dest_id = dest_id.into();
        if source_id.size() != dest_id.size() {
            return Err(PduError::SourceDestIdLenMissmatch {
                src_id_len: source_id.size(),
                dest_id_len: dest_id.size(),
            });
        }
        if source_id.size() != 1
            && source_id.size() != 2
            && source_id.size() != 4
            && source_id.size() != 8
        {
            return Err(PduError::InvalidEntityLen(source_id.size() as u8));
        }
        Ok((source_id, dest_id))
    }

    pub fn set_source_and_dest_id(
        &mut self,
        source_id: impl Into<UnsignedByteField>,
        dest_id: impl Into<UnsignedByteField>,
    ) -> Result<(), PduError> {
        let (source_id, dest_id) = Self::source_dest_id_check(source_id, dest_id)?;
        self.source_entity_id = source_id;
        self.dest_entity_id = dest_id;
        Ok(())
    }

    pub fn dest_id(&self) -> UnsignedByteField {
        self.dest_entity_id
    }
}

impl Default for CommonPduConfig {
    /// The defaults for the source ID, destination ID and the transaction sequence number is the
    /// [UnsignedByteFieldU8] with an intitial value of 0
    fn default() -> Self {
        // The new function can not fail for these input parameters.
        Self::new(
            UnsignedByteFieldU8::new(0),
            UnsignedByteFieldU8::new(0),
            UnsignedByteFieldU8::new(0),
            TransmissionMode::Acknowledged,
            LargeFileFlag::Normal,
            CrcFlag::NoCrc,
            Direction::TowardsReceiver,
        )
        .unwrap()
    }
}

pub const FIXED_HEADER_LEN: usize = 4;

/// Abstraction for the PDU header common to all CFDP PDUs.
///
/// For detailed information, refer to chapter 5.1 of the CFDP standard.
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
        Self::new_generic(
            PduType::FileData,
            pdu_conf,
            pdu_datafield_len,
            seg_metadata_flag,
            seg_ctrl,
        )
    }

    pub fn new_for_file_data_default(pdu_conf: CommonPduConfig, pdu_datafield_len: u16) -> Self {
        Self::new_generic(
            PduType::FileData,
            pdu_conf,
            pdu_datafield_len,
            SegmentMetadataFlag::NotPresent,
            SegmentationControl::NoRecordBoundaryPreservation,
        )
    }
    pub fn new_no_file_data(pdu_conf: CommonPduConfig, pdu_datafield_len: u16) -> Self {
        Self::new_generic(
            PduType::FileDirective,
            pdu_conf,
            pdu_datafield_len,
            SegmentMetadataFlag::NotPresent,
            SegmentationControl::NoRecordBoundaryPreservation,
        )
    }

    pub fn new_generic(
        pdu_type: PduType,
        pdu_conf: CommonPduConfig,
        pdu_datafield_len: u16,
        seg_metadata_flag: SegmentMetadataFlag,
        seg_ctrl: SegmentationControl,
    ) -> Self {
        Self {
            pdu_type,
            pdu_conf,
            seg_metadata_flag,
            seg_ctrl,
            pdu_datafield_len,
        }
    }

    /// Returns only the length of the PDU header when written to a raw buffer.
    pub fn header_len(&self) -> usize {
        FIXED_HEADER_LEN
            + self.pdu_conf.source_entity_id.size()
            + self.pdu_conf.transaction_seq_num.size()
            + self.pdu_conf.dest_entity_id.size()
    }

    pub fn pdu_datafield_len(&self) -> usize {
        self.pdu_datafield_len.into()
    }

    /// Returns the full length of the PDU when written to a raw buffer, which is the header length
    /// plus the PDU datafield length.
    pub fn pdu_len(&self) -> usize {
        self.header_len() + self.pdu_datafield_len as usize
    }

    pub fn write_to_bytes(&self, buf: &mut [u8]) -> Result<usize, PduError> {
        // Internal note: There is currently no way to pass a PDU configuration like this, but
        // this check is still kept for defensive programming.
        if self.pdu_conf.source_entity_id.size() != self.pdu_conf.dest_entity_id.size() {
            return Err(PduError::SourceDestIdLenMissmatch {
                src_id_len: self.pdu_conf.source_entity_id.size(),
                dest_id_len: self.pdu_conf.dest_entity_id.size(),
            });
        }
        if buf.len()
            < FIXED_HEADER_LEN
                + self.pdu_conf.source_entity_id.size()
                + self.pdu_conf.transaction_seq_num.size()
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
            | (((self.pdu_conf.source_entity_id.size() - 1) as u8) << 4)
            | ((self.seg_metadata_flag as u8) << 3)
            | ((self.pdu_conf.transaction_seq_num.size() - 1) as u8);
        current_idx += 1;
        self.pdu_conf.source_entity_id.write_to_be_bytes(
            &mut buf[current_idx..current_idx + self.pdu_conf.source_entity_id.size()],
        )?;
        current_idx += self.pdu_conf.source_entity_id.size();
        self.pdu_conf.transaction_seq_num.write_to_be_bytes(
            &mut buf[current_idx..current_idx + self.pdu_conf.transaction_seq_num.size()],
        )?;
        current_idx += self.pdu_conf.transaction_seq_num.size();
        self.pdu_conf.dest_entity_id.write_to_be_bytes(
            &mut buf[current_idx..current_idx + self.pdu_conf.dest_entity_id.size()],
        )?;
        current_idx += self.pdu_conf.dest_entity_id.size();
        Ok(current_idx)
    }

    /// This function first verifies that the buffer can hold the full length of the PDU parsed from
    /// the header. Then, it verifies the checksum as specified in the standard if the CRC flag
    /// of the PDU header is set.
    ///
    /// This function will return the PDU length excluding the 2 CRC bytes on success. If the CRC
    /// flag is not set, it will simply return the PDU length.
    pub fn verify_length_and_checksum(&self, buf: &[u8]) -> Result<usize, PduError> {
        if buf.len() < self.pdu_len() {
            return Err(ByteConversionError::FromSliceTooSmall(SizeMissmatch {
                found: buf.len(),
                expected: self.pdu_len(),
            })
            .into());
        }
        if self.pdu_conf.crc_flag == CrcFlag::WithCrc {
            let mut digest = CRC_CCITT_FALSE.digest();
            digest.update(&buf[..self.pdu_len()]);
            if digest.finalize() != 0 {
                return Err(PduError::ChecksumError(u16::from_be_bytes(
                    buf[self.pdu_len() - 2..self.pdu_len()].try_into().unwrap(),
                )));
            }
            return Ok(self.pdu_len() - 2);
        }
        Ok(self.pdu_len())
    }

    /// Please note that this function will not verify that the passed buffer can hold the full
    /// PDU length. This allows recovering the header portion even if the data field length is
    /// invalid. This function will also not do the CRC procedure specified in chapter 4.1.1
    /// and 4.1.2 because performing the CRC procedure requires the buffer to be large enough
    /// to hold the full PDU.
    ///
    /// Both functions can however be performed with the [Self::verify_length_and_checksum]
    /// function.
    pub fn from_bytes(buf: &[u8]) -> Result<(Self, usize), PduError> {
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

pub(crate) fn write_fss_field(
    file_flag: LargeFileFlag,
    file_size: u64,
    buf: &mut [u8],
) -> Result<usize, PduError> {
    Ok(if file_flag == LargeFileFlag::Large {
        buf[..core::mem::size_of::<u64>()].copy_from_slice(&file_size.to_be_bytes());
        core::mem::size_of::<u64>()
    } else {
        if file_size > u32::MAX as u64 {
            return Err(PduError::FileSizeTooLarge(file_size));
        }
        buf[..core::mem::size_of::<u32>()].copy_from_slice(&(file_size as u32).to_be_bytes());
        core::mem::size_of::<u32>()
    })
}

pub(crate) fn read_fss_field(file_flag: LargeFileFlag, buf: &[u8]) -> (usize, u64) {
    if file_flag == LargeFileFlag::Large {
        (
            core::mem::size_of::<u64>(),
            u64::from_be_bytes(buf[..core::mem::size_of::<u64>()].try_into().unwrap()),
        )
    } else {
        (
            core::mem::size_of::<u32>(),
            u32::from_be_bytes(buf[..core::mem::size_of::<u32>()].try_into().unwrap()).into(),
        )
    }
}

// This is a generic length check applicable to most PDU deserializations. It first checks whether
// a given buffer can hold an expected minimum size, and then it checks whether the PDU datafield
// length is larger than that expected minimum size.
pub(crate) fn generic_length_checks_pdu_deserialization(
    buf: &[u8],
    min_expected_len: usize,
    full_len_without_crc: usize,
) -> Result<(), ByteConversionError> {
    // Buffer too short to hold additional expected minimum datasize.
    if buf.len() < min_expected_len {
        return Err(ByteConversionError::FromSliceTooSmall(SizeMissmatch {
            found: buf.len(),
            expected: min_expected_len,
        }));
    }
    // This can happen if the PDU datafield length value is invalid.
    if full_len_without_crc < min_expected_len {
        return Err(ByteConversionError::FromSliceTooSmall(SizeMissmatch {
            found: full_len_without_crc,
            expected: min_expected_len,
        }));
    }
    Ok(())
}

pub(crate) fn add_pdu_crc(buf: &mut [u8], mut current_idx: usize) -> usize {
    let mut digest = CRC_CCITT_FALSE.digest();
    digest.update(&buf[..current_idx]);
    buf[current_idx..current_idx + 2].copy_from_slice(&digest.finalize().to_be_bytes());
    current_idx += 2;
    current_idx
}

#[cfg(test)]
mod tests {
    use crate::cfdp::pdu::{CommonPduConfig, PduError, PduHeader, FIXED_HEADER_LEN};
    use crate::cfdp::{
        CrcFlag, Direction, LargeFileFlag, PduType, SegmentMetadataFlag, SegmentationControl,
        TransmissionMode, CFDP_VERSION_2,
    };
    use crate::util::{
        UbfU8, UnsignedByteField, UnsignedByteFieldU16, UnsignedByteFieldU8, UnsignedEnum,
    };
    use crate::ByteConversionError;
    use std::format;

    pub(crate) fn common_pdu_conf(crc_flag: CrcFlag, fss: LargeFileFlag) -> CommonPduConfig {
        let src_id = UbfU8::new(5);
        let dest_id = UbfU8::new(10);
        let transaction_seq_num = UbfU8::new(20);
        let mut pdu_conf =
            CommonPduConfig::new_with_byte_fields(src_id, dest_id, transaction_seq_num)
                .expect("Generating common PDU config");
        pdu_conf.crc_flag = crc_flag;
        pdu_conf.file_flag = fss;
        pdu_conf
    }

    pub(crate) fn verify_raw_header(pdu_conf: &PduHeader, buf: &[u8]) {
        assert_eq!((buf[0] >> 5) & 0b111, CFDP_VERSION_2);
        // File directive
        assert_eq!((buf[0] >> 4) & 1, pdu_conf.pdu_type as u8);
        // Towards receiver
        assert_eq!((buf[0] >> 3) & 1, pdu_conf.pdu_conf.direction as u8);
        // Acknowledged
        assert_eq!((buf[0] >> 2) & 1, pdu_conf.pdu_conf.trans_mode as u8);
        // No CRC
        assert_eq!((buf[0] >> 1) & 1, pdu_conf.pdu_conf.crc_flag as u8);
        // Regular file size
        assert_eq!(buf[0] & 1, pdu_conf.pdu_conf.file_flag as u8);
        let pdu_datafield_len = u16::from_be_bytes(buf[1..3].try_into().unwrap());
        assert_eq!(pdu_datafield_len, pdu_conf.pdu_datafield_len);
        // No record boundary preservation
        assert_eq!((buf[3] >> 7) & 1, pdu_conf.seg_ctrl as u8);
        // Entity ID length raw value is actual number of octets - 1 => 0
        let entity_id_len = pdu_conf.pdu_conf.source_entity_id.size();
        assert_eq!((buf[3] >> 4) & 0b111, entity_id_len as u8 - 1);
        // No segment metadata
        assert_eq!((buf[3] >> 3) & 0b1, pdu_conf.seg_metadata_flag as u8);
        // Transaction Sequence ID length raw value is actual number of octets - 1 => 0
        let seq_num_len = pdu_conf.pdu_conf.transaction_seq_num.size();
        assert_eq!(buf[3] & 0b111, seq_num_len as u8 - 1);
        let mut current_idx = 4;
        let mut byte_field_check = |field_len: usize, ubf: &UnsignedByteField| {
            match field_len {
                1 => assert_eq!(buf[current_idx], ubf.value() as u8),
                2 => assert_eq!(
                    u16::from_be_bytes(
                        buf[current_idx..current_idx + field_len]
                            .try_into()
                            .unwrap()
                    ),
                    ubf.value() as u16
                ),
                4 => assert_eq!(
                    u32::from_be_bytes(
                        buf[current_idx..current_idx + field_len]
                            .try_into()
                            .unwrap()
                    ),
                    ubf.value() as u32
                ),
                8 => assert_eq!(
                    u64::from_be_bytes(
                        buf[current_idx..current_idx + field_len]
                            .try_into()
                            .unwrap()
                    ),
                    ubf.value() as u64
                ),
                _ => panic!("invalid entity ID length"),
            }
            current_idx += field_len
        };
        byte_field_check(entity_id_len, &pdu_conf.pdu_conf.source_entity_id);
        byte_field_check(seq_num_len, &pdu_conf.pdu_conf.transaction_seq_num);
        byte_field_check(entity_id_len, &pdu_conf.pdu_conf.dest_entity_id);
    }

    #[test]
    fn test_basic_state() {
        let src_id = UnsignedByteFieldU8::new(1);
        let dest_id = UnsignedByteFieldU8::new(2);
        let transaction_id = UnsignedByteFieldU8::new(3);
        let common_pdu_cfg = CommonPduConfig::new_with_byte_fields(src_id, dest_id, transaction_id)
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
        assert_eq!(pdu_header.header_len(), 7);
    }

    #[test]
    fn test_basic_state_default() {
        let default_conf = CommonPduConfig::default();
        assert_eq!(default_conf.source_id(), UnsignedByteFieldU8::new(0).into());
        assert_eq!(default_conf.dest_id(), UnsignedByteFieldU8::new(0).into());
        assert_eq!(
            default_conf.transaction_seq_num,
            UnsignedByteFieldU8::new(0).into()
        );
        assert_eq!(default_conf.trans_mode, TransmissionMode::Acknowledged);
        assert_eq!(default_conf.direction, Direction::TowardsReceiver);
        assert_eq!(default_conf.crc_flag, CrcFlag::NoCrc);
        assert_eq!(default_conf.file_flag, LargeFileFlag::Normal);
    }

    #[test]
    fn test_pdu_header_setter() {
        let src_id = UnsignedByteFieldU8::new(1);
        let dest_id = UnsignedByteFieldU8::new(2);
        let transaction_id = UnsignedByteFieldU8::new(3);
        let mut common_pdu_cfg =
            CommonPduConfig::new_with_byte_fields(src_id, dest_id, transaction_id)
                .expect("common config creation failed");
        let other_src_id = UnsignedByteFieldU16::new(5);
        let other_dest_id = UnsignedByteFieldU16::new(6);
        let set_result = common_pdu_cfg.set_source_and_dest_id(other_src_id, other_dest_id);
        assert!(set_result.is_ok());
        assert_eq!(common_pdu_cfg.source_id(), other_src_id.into());
        assert_eq!(common_pdu_cfg.dest_id(), other_dest_id.into());
    }

    #[test]
    fn test_serialization_1() {
        let src_id = UnsignedByteFieldU8::new(1);
        let dest_id = UnsignedByteFieldU8::new(2);
        let transaction_id = UnsignedByteFieldU8::new(3);
        let common_pdu_cfg = CommonPduConfig::new_with_byte_fields(src_id, dest_id, transaction_id)
            .expect("common config creation failed");
        let pdu_header = PduHeader::new_no_file_data(common_pdu_cfg, 5);
        let mut buf: [u8; 7] = [0; 7];
        let res = pdu_header.write_to_bytes(&mut buf);
        assert!(res.is_ok());
        // 4 byte fixed header plus three bytes src, dest ID and transaction ID
        assert_eq!(res.unwrap(), 7);
        verify_raw_header(&pdu_header, &buf);
    }

    #[test]
    fn test_deserialization_1() {
        let src_id = UnsignedByteFieldU8::new(1);
        let dest_id = UnsignedByteFieldU8::new(2);
        let transaction_id = UnsignedByteFieldU8::new(3);
        let common_pdu_cfg = CommonPduConfig::new_with_byte_fields(src_id, dest_id, transaction_id)
            .expect("common config creation failed");
        let pdu_header = PduHeader::new_no_file_data(common_pdu_cfg, 5);
        let mut buf: [u8; 7] = [0; 7];
        let res = pdu_header.write_to_bytes(&mut buf);
        assert!(res.is_ok());
        let deser_res = PduHeader::from_bytes(&buf);
        assert!(deser_res.is_ok());
        let (header_read_back, read_size) = deser_res.unwrap();
        assert_eq!(read_size, 7);
        assert_eq!(header_read_back, pdu_header);
    }

    #[test]
    fn test_serialization_2() {
        let src_id = UnsignedByteFieldU16::new(0x0001);
        let dest_id = UnsignedByteFieldU16::new(0x0203);
        let transaction_id = UnsignedByteFieldU16::new(0x0405);
        let mut common_pdu_cfg =
            CommonPduConfig::new_with_byte_fields(src_id, dest_id, transaction_id)
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
        assert_eq!(pdu_header.header_len(), 10);
        let mut buf: [u8; 16] = [0; 16];
        let res = pdu_header.write_to_bytes(&mut buf);
        assert!(res.is_ok(), "{}", format!("Result {res:?} not okay"));
        // 4 byte fixed header, 6 bytes additional fields
        assert_eq!(res.unwrap(), 10);
        verify_raw_header(&pdu_header, &buf);
    }

    #[test]
    fn test_deserialization_2() {
        let src_id = UnsignedByteFieldU16::new(0x0001);
        let dest_id = UnsignedByteFieldU16::new(0x0203);
        let transaction_id = UnsignedByteFieldU16::new(0x0405);
        let mut common_pdu_cfg =
            CommonPduConfig::new_with_byte_fields(src_id, dest_id, transaction_id)
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
        let res = pdu_header.write_to_bytes(&mut buf);
        assert!(res.is_ok());
        let deser_res = PduHeader::from_bytes(&buf);
        assert!(deser_res.is_ok());
        let (header_read_back, read_size) = deser_res.unwrap();
        assert_eq!(read_size, 10);
        assert_eq!(header_read_back, pdu_header);
    }

    #[test]
    fn test_invalid_raw_version() {
        let src_id = UnsignedByteFieldU8::new(1);
        let dest_id = UnsignedByteFieldU8::new(2);
        let transaction_id = UnsignedByteFieldU8::new(3);
        let common_pdu_cfg = CommonPduConfig::new_with_byte_fields(src_id, dest_id, transaction_id)
            .expect("common config creation failed");
        let pdu_header = PduHeader::new_no_file_data(common_pdu_cfg, 5);
        let mut buf: [u8; 7] = [0; 7];
        let res = pdu_header.write_to_bytes(&mut buf);
        assert!(res.is_ok());
        buf[0] &= !0b1110_0000;
        buf[0] |= (CFDP_VERSION_2 + 1) << 5;
        let res = PduHeader::from_bytes(&buf);
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
        let res = PduHeader::from_bytes(&buf);
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
        let src_id = UnsignedByteFieldU8::new(1);
        let dest_id = UnsignedByteFieldU8::new(2);
        let transaction_id = UnsignedByteFieldU8::new(3);
        let common_pdu_cfg = CommonPduConfig::new_with_byte_fields(src_id, dest_id, transaction_id)
            .expect("common config creation failed");
        let pdu_header = PduHeader::new_no_file_data(common_pdu_cfg, 5);
        let mut buf: [u8; 7] = [0; 7];
        let res = pdu_header.write_to_bytes(&mut buf);
        assert!(res.is_ok());
        let header = PduHeader::from_bytes(&buf[0..6]);
        assert!(header.is_err());
        let error = header.unwrap_err();
        if let PduError::ByteConversionError(ByteConversionError::FromSliceTooSmall(missmatch)) =
            error
        {
            assert_eq!(missmatch.found, 6);
            assert_eq!(missmatch.expected, 7);
        }
    }

    #[test]
    fn test_invalid_seq_len() {
        let src_id = UbfU8::new(1);
        let dest_id = UbfU8::new(2);
        let transaction_seq_id = UbfU8::new(3);
        let invalid_byte_field = UnsignedByteField::new(3, 5);
        let pdu_conf_res =
            CommonPduConfig::new_with_byte_fields(src_id, dest_id, invalid_byte_field);
        assert!(pdu_conf_res.is_err());
        let error = pdu_conf_res.unwrap_err();
        if let PduError::InvalidTransactionSeqNumLen(len) = error {
            assert_eq!(len, 3);
        } else {
            panic!("Invalid exception: {}", error)
        }
        let pdu_conf_res = CommonPduConfig::new_with_byte_fields(
            invalid_byte_field,
            invalid_byte_field,
            transaction_seq_id,
        );
        assert!(pdu_conf_res.is_err());
        let error = pdu_conf_res.unwrap_err();
        if let PduError::InvalidEntityLen(len) = error {
            assert_eq!(len, 3);
        } else {
            panic!("Invalid exception: {}", error)
        }
    }
    #[test]
    fn test_missmatch_src_dest_id() {
        let src_id = UnsignedByteField::new(1, 5);
        let dest_id = UnsignedByteField::new(2, 5);
        let transaction_seq_id = UbfU8::new(3);
        let pdu_conf_res =
            CommonPduConfig::new_with_byte_fields(src_id, dest_id, transaction_seq_id);
        assert!(pdu_conf_res.is_err());
        let error = pdu_conf_res.unwrap_err();
        if let PduError::SourceDestIdLenMissmatch((src_len, dest_len)) = error {
            assert_eq!(src_len, 1);
            assert_eq!(dest_len, 2);
        }
    }

    #[test]
    fn test_invalid_raw_src_id_len() {
        let src_id = UnsignedByteFieldU8::new(1);
        let dest_id = UnsignedByteFieldU8::new(2);
        let transaction_id = UnsignedByteFieldU8::new(3);
        let common_pdu_cfg = CommonPduConfig::new_with_byte_fields(src_id, dest_id, transaction_id)
            .expect("common config creation failed");
        let pdu_header = PduHeader::new_no_file_data(common_pdu_cfg, 5);
        let mut buf: [u8; 7] = [0; 7];
        let res = pdu_header.write_to_bytes(&mut buf);
        assert!(res.is_ok());
        buf[3] &= !0b0111_0000;
        // Equivalent to the length of three
        buf[3] |= 0b10 << 4;
        let header_res = PduHeader::from_bytes(&buf);
        assert!(header_res.is_err());
        let error = header_res.unwrap_err();
        if let PduError::InvalidEntityLen(len) = error {
            assert_eq!(len, 3);
        } else {
            panic!("invalid exception {:?}", error)
        }
    }

    #[test]
    fn test_invalid_transaction_seq_id_len() {
        let src_id = UnsignedByteFieldU8::new(1);
        let dest_id = UnsignedByteFieldU8::new(2);
        let transaction_id = UnsignedByteFieldU8::new(3);
        let common_pdu_cfg = CommonPduConfig::new_with_byte_fields(src_id, dest_id, transaction_id)
            .expect("common config creation failed");
        let pdu_header = PduHeader::new_no_file_data(common_pdu_cfg, 5);
        let mut buf: [u8; 7] = [0; 7];
        let res = pdu_header.write_to_bytes(&mut buf);
        assert!(res.is_ok());
        buf[3] &= !0b0000_0111;
        // Equivalent to the length of three
        buf[3] |= 0b10;
        let header_res = PduHeader::from_bytes(&buf);
        assert!(header_res.is_err());
        let error = header_res.unwrap_err();
        if let PduError::InvalidTransactionSeqNumLen(len) = error {
            assert_eq!(len, 3);
        } else {
            panic!("invalid exception {:?}", error)
        }
    }
}
