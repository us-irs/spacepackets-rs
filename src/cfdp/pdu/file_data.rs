use crate::cfdp::pdu::{
    add_pdu_crc, generic_length_checks_pdu_deserialization, read_fss_field, write_fss_field,
    PduError, PduHeader,
};
use crate::cfdp::{CrcFlag, LargeFileFlag, PduType, SegmentMetadataFlag};
use crate::ByteConversionError;
use num_enum::{IntoPrimitive, TryFromPrimitive};
#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

use super::WritablePduPacket;

#[derive(Debug, Copy, Clone, PartialEq, Eq, TryFromPrimitive, IntoPrimitive)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[repr(u8)]
pub enum RecordContinuationState {
    NoStartNoEnd = 0b00,
    StartWithoutEnd = 0b01,
    EndWithoutStart = 0b10,
    StartAndEnd = 0b11,
}

#[derive(Debug, Copy, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct SegmentMetadata<'seg_meta> {
    record_continuation_state: RecordContinuationState,
    metadata: Option<&'seg_meta [u8]>,
}

impl<'seg_meta> SegmentMetadata<'seg_meta> {
    pub fn new(
        record_continuation_state: RecordContinuationState,
        metadata: Option<&'seg_meta [u8]>,
    ) -> Option<Self> {
        if let Some(metadata) = metadata {
            if metadata.len() > 2_usize.pow(6) - 1 {
                return None;
            }
        }
        Some(Self {
            record_continuation_state,
            metadata,
        })
    }

    pub fn written_len(&self) -> usize {
        // Map empty metadata to 0 and slice to its length.
        1 + self.metadata.map_or(0, |meta| meta.len())
    }

    pub(crate) fn write_to_bytes(&self, buf: &mut [u8]) -> Result<usize, ByteConversionError> {
        if buf.len() < self.written_len() {
            return Err(ByteConversionError::ToSliceTooSmall {
                found: buf.len(),
                expected: self.written_len(),
            });
        }
        buf[0] = ((self.record_continuation_state as u8) << 6)
            | self.metadata.map_or(0, |meta| meta.len() as u8);
        if let Some(metadata) = self.metadata {
            buf[1..1 + metadata.len()].copy_from_slice(metadata)
        }
        Ok(self.written_len())
    }

    pub(crate) fn from_bytes(buf: &'seg_meta [u8]) -> Result<Self, ByteConversionError> {
        if buf.is_empty() {
            return Err(ByteConversionError::FromSliceTooSmall {
                found: buf.len(),
                expected: 2,
            });
        }
        let mut metadata = None;
        let seg_metadata_len = (buf[0] & 0b111111) as usize;
        if seg_metadata_len > 0 {
            metadata = Some(&buf[1..1 + seg_metadata_len]);
        }
        Ok(Self {
            // Can't fail, only 2 bits
            record_continuation_state: RecordContinuationState::try_from((buf[0] >> 6) & 0b11)
                .unwrap(),
            metadata,
        })
    }
}

/// File Data PDU abstraction.
///
/// For more information, refer to CFDP chapter 5.3.
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct FileDataPdu<'seg_meta, 'file_data> {
    pdu_header: PduHeader,
    #[cfg_attr(feature = "serde", serde(borrow))]
    segment_metadata: Option<SegmentMetadata<'seg_meta>>,
    offset: u64,
    file_data: &'file_data [u8],
}

impl<'seg_meta, 'file_data> FileDataPdu<'seg_meta, 'file_data> {
    pub fn new_with_seg_metadata(
        pdu_header: PduHeader,
        segment_metadata: SegmentMetadata<'seg_meta>,
        offset: u64,
        file_data: &'file_data [u8],
    ) -> Self {
        Self::new_generic(pdu_header, Some(segment_metadata), offset, file_data)
    }

    pub fn new_no_seg_metadata(
        pdu_header: PduHeader,
        offset: u64,
        file_data: &'file_data [u8],
    ) -> Self {
        Self::new_generic(pdu_header, None, offset, file_data)
    }

    pub fn new_generic(
        mut pdu_header: PduHeader,
        segment_metadata: Option<SegmentMetadata<'seg_meta>>,
        offset: u64,
        file_data: &'file_data [u8],
    ) -> Self {
        pdu_header.pdu_type = PduType::FileData;
        if segment_metadata.is_some() {
            pdu_header.seg_metadata_flag = SegmentMetadataFlag::Present;
        }
        let mut pdu = Self {
            pdu_header,
            segment_metadata,
            offset,
            file_data,
        };
        pdu.pdu_header.pdu_datafield_len = pdu.calc_pdu_datafield_len() as u16;
        pdu
    }

    fn calc_pdu_datafield_len(&self) -> usize {
        let mut len = core::mem::size_of::<u32>();
        if self.pdu_header.pdu_conf.file_flag == LargeFileFlag::Large {
            len += 4;
        }
        if self.segment_metadata.is_some() {
            len += self.segment_metadata.as_ref().unwrap().written_len()
        }
        len += self.file_data.len();
        if self.pdu_header.pdu_conf.crc_flag == CrcFlag::WithCrc {
            len += 2;
        }
        len
    }
    pub fn written_len(&self) -> usize {
        self.pdu_header.header_len() + self.calc_pdu_datafield_len()
    }

    pub fn offset(&self) -> u64 {
        self.offset
    }

    pub fn file_data(&self) -> &'file_data [u8] {
        self.file_data
    }

    pub fn segment_metadata(&self) -> Option<&SegmentMetadata> {
        self.segment_metadata.as_ref()
    }

    pub fn from_bytes<'longest: 'seg_meta + 'file_data>(
        buf: &'longest [u8],
    ) -> Result<Self, PduError> {
        let (pdu_header, mut current_idx) = PduHeader::from_bytes(buf)?;
        let full_len_without_crc = pdu_header.verify_length_and_checksum(buf)?;
        let min_expected_len = current_idx + core::mem::size_of::<u32>();
        generic_length_checks_pdu_deserialization(buf, min_expected_len, full_len_without_crc)?;
        let mut segment_metadata = None;
        if pdu_header.seg_metadata_flag == SegmentMetadataFlag::Present {
            segment_metadata = Some(SegmentMetadata::from_bytes(&buf[current_idx..])?);
            current_idx += segment_metadata.as_ref().unwrap().written_len();
        }
        let (fss, offset) = read_fss_field(pdu_header.pdu_conf.file_flag, &buf[current_idx..]);
        current_idx += fss;
        if current_idx > full_len_without_crc {
            return Err(ByteConversionError::FromSliceTooSmall {
                found: current_idx,
                expected: full_len_without_crc,
            }
            .into());
        }
        Ok(Self {
            pdu_header,
            segment_metadata,
            offset,
            file_data: &buf[current_idx..full_len_without_crc],
        })
    }
}

impl WritablePduPacket for FileDataPdu<'_, '_> {
    fn write_to_bytes(&self, buf: &mut [u8]) -> Result<usize, PduError> {
        if buf.len() < self.written_len() {
            return Err(ByteConversionError::ToSliceTooSmall {
                found: buf.len(),
                expected: self.written_len(),
            }
            .into());
        }
        let mut current_idx = self.pdu_header.write_to_bytes(buf)?;
        if self.segment_metadata.is_some() {
            current_idx += self
                .segment_metadata
                .as_ref()
                .unwrap()
                .write_to_bytes(&mut buf[current_idx..])?;
        }
        current_idx += write_fss_field(
            self.pdu_header.common_pdu_conf().file_flag,
            self.offset,
            &mut buf[current_idx..],
        )?;
        buf[current_idx..current_idx + self.file_data.len()].copy_from_slice(self.file_data);
        current_idx += self.file_data.len();
        if self.pdu_header.pdu_conf.crc_flag == CrcFlag::WithCrc {
            current_idx = add_pdu_crc(buf, current_idx);
        }
        Ok(current_idx)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cfdp::pdu::{CommonPduConfig, PduHeader};
    use crate::cfdp::{SegmentMetadataFlag, SegmentationControl};
    use crate::util::UbfU8;

    #[test]
    fn test_basic() {
        let src_id = UbfU8::new(1);
        let dest_id = UbfU8::new(2);
        let transaction_seq_num = UbfU8::new(3);
        let common_conf =
            CommonPduConfig::new_with_byte_fields(src_id, dest_id, transaction_seq_num).unwrap();
        let pdu_header = PduHeader::new_for_file_data_default(common_conf, 0);
        let file_data: [u8; 4] = [1, 2, 3, 4];
        let fd_pdu = FileDataPdu::new_no_seg_metadata(pdu_header, 10, &file_data);
        assert_eq!(fd_pdu.file_data(), file_data);
        assert_eq!(fd_pdu.offset(), 10);
        assert!(fd_pdu.segment_metadata().is_none());
        assert_eq!(
            fd_pdu.written_len(),
            fd_pdu.pdu_header.header_len() + core::mem::size_of::<u32>() + 4
        );
    }

    #[test]
    fn test_serialization() {
        let src_id = UbfU8::new(1);
        let dest_id = UbfU8::new(2);
        let transaction_seq_num = UbfU8::new(3);
        let common_conf =
            CommonPduConfig::new_with_byte_fields(src_id, dest_id, transaction_seq_num).unwrap();
        let pdu_header = PduHeader::new_for_file_data_default(common_conf, 0);
        let file_data: [u8; 4] = [1, 2, 3, 4];
        let fd_pdu = FileDataPdu::new_no_seg_metadata(pdu_header, 10, &file_data);
        let mut buf: [u8; 32] = [0; 32];
        let res = fd_pdu.write_to_bytes(&mut buf);
        assert!(res.is_ok());
        let written = res.unwrap();
        assert_eq!(
            written,
            fd_pdu.pdu_header.header_len() + core::mem::size_of::<u32>() + 4
        );
        let mut current_idx = fd_pdu.pdu_header.header_len();
        let file_size = u32::from_be_bytes(
            buf[fd_pdu.pdu_header.header_len()..fd_pdu.pdu_header.header_len() + 4]
                .try_into()
                .unwrap(),
        );
        current_idx += 4;
        assert_eq!(file_size, 10);
        assert_eq!(buf[current_idx], 1);
        current_idx += 1;
        assert_eq!(buf[current_idx], 2);
        current_idx += 1;
        assert_eq!(buf[current_idx], 3);
        current_idx += 1;
        assert_eq!(buf[current_idx], 4);
    }

    #[test]
    fn test_deserialization() {
        let src_id = UbfU8::new(1);
        let dest_id = UbfU8::new(2);
        let transaction_seq_num = UbfU8::new(3);
        let common_conf =
            CommonPduConfig::new_with_byte_fields(src_id, dest_id, transaction_seq_num).unwrap();
        let pdu_header = PduHeader::new_for_file_data_default(common_conf, 0);
        let file_data: [u8; 4] = [1, 2, 3, 4];
        let fd_pdu = FileDataPdu::new_no_seg_metadata(pdu_header, 10, &file_data);
        let mut buf: [u8; 32] = [0; 32];
        fd_pdu.write_to_bytes(&mut buf).unwrap();
        let fd_pdu_read_back = FileDataPdu::from_bytes(&buf);
        assert!(fd_pdu_read_back.is_ok());
        let fd_pdu_read_back = fd_pdu_read_back.unwrap();
        assert_eq!(fd_pdu_read_back, fd_pdu);
    }

    #[test]
    fn test_with_seg_metadata_serialization() {
        let src_id = UbfU8::new(1);
        let dest_id = UbfU8::new(2);
        let transaction_seq_num = UbfU8::new(3);
        let common_conf =
            CommonPduConfig::new_with_byte_fields(src_id, dest_id, transaction_seq_num).unwrap();
        let pdu_header = PduHeader::new_for_file_data(
            common_conf,
            0,
            SegmentMetadataFlag::Present,
            SegmentationControl::WithRecordBoundaryPreservation,
        );
        let file_data: [u8; 4] = [1, 2, 3, 4];
        let seg_metadata: [u8; 4] = [4, 3, 2, 1];
        let segment_meta =
            SegmentMetadata::new(RecordContinuationState::StartAndEnd, Some(&seg_metadata))
                .unwrap();
        let fd_pdu = FileDataPdu::new_with_seg_metadata(pdu_header, segment_meta, 10, &file_data);
        assert!(fd_pdu.segment_metadata().is_some());
        assert_eq!(*fd_pdu.segment_metadata().unwrap(), segment_meta);
        assert_eq!(
            fd_pdu.written_len(),
            fd_pdu.pdu_header.header_len()
                + 1
                + seg_metadata.len()
                + core::mem::size_of::<u32>()
                + 4
        );
        let mut buf: [u8; 32] = [0; 32];
        fd_pdu
            .write_to_bytes(&mut buf)
            .expect("writing FD PDU failed");
        let mut current_idx = fd_pdu.pdu_header.header_len();
        assert_eq!(
            RecordContinuationState::try_from((buf[current_idx] >> 6) & 0b11).unwrap(),
            RecordContinuationState::StartAndEnd
        );
        assert_eq!((buf[current_idx] & 0b111111) as usize, seg_metadata.len());
        current_idx += 1;
        assert_eq!(buf[current_idx], 4);
        current_idx += 1;
        assert_eq!(buf[current_idx], 3);
        current_idx += 1;
        assert_eq!(buf[current_idx], 2);
        current_idx += 1;
        assert_eq!(buf[current_idx], 1);
        current_idx += 1;
        // Still verify that the rest is written correctly.
        assert_eq!(
            u32::from_be_bytes(buf[current_idx..current_idx + 4].try_into().unwrap()),
            10
        );
        current_idx += 4;
        assert_eq!(buf[current_idx], 1);
        current_idx += 1;
        assert_eq!(buf[current_idx], 2);
        current_idx += 1;
        assert_eq!(buf[current_idx], 3);
        current_idx += 1;
        assert_eq!(buf[current_idx], 4);
        current_idx += 1;
        assert_eq!(current_idx, fd_pdu.written_len());
    }

    #[test]
    fn test_with_seg_metadata_deserialization() {
        let src_id = UbfU8::new(1);
        let dest_id = UbfU8::new(2);
        let transaction_seq_num = UbfU8::new(3);
        let common_conf =
            CommonPduConfig::new_with_byte_fields(src_id, dest_id, transaction_seq_num).unwrap();
        let pdu_header = PduHeader::new_for_file_data(
            common_conf,
            0,
            SegmentMetadataFlag::Present,
            SegmentationControl::WithRecordBoundaryPreservation,
        );
        let file_data: [u8; 4] = [1, 2, 3, 4];
        let seg_metadata: [u8; 4] = [4, 3, 2, 1];
        let segment_meta =
            SegmentMetadata::new(RecordContinuationState::StartAndEnd, Some(&seg_metadata))
                .unwrap();
        let fd_pdu = FileDataPdu::new_with_seg_metadata(pdu_header, segment_meta, 10, &file_data);
        let mut buf: [u8; 32] = [0; 32];
        fd_pdu
            .write_to_bytes(&mut buf)
            .expect("writing FD PDU failed");
        let fd_pdu_read_back = FileDataPdu::from_bytes(&buf);
        assert!(fd_pdu_read_back.is_ok());
        let fd_pdu_read_back = fd_pdu_read_back.unwrap();
        assert_eq!(fd_pdu_read_back, fd_pdu);
    }
}
