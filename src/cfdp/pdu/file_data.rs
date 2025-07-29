use crate::cfdp::pdu::{
    add_pdu_crc, generic_length_checks_pdu_deserialization, read_fss_field, write_fss_field,
    PduError, PduHeader,
};
use crate::cfdp::{CrcFlag, LargeFileFlag, PduType, SegmentMetadataFlag};
use crate::ByteConversionError;
use num_enum::{IntoPrimitive, TryFromPrimitive};
#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

use super::{CfdpPdu, FileDirectiveType, WritablePduPacket};

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

    pub fn record_continuation_state(&self) -> RecordContinuationState {
        self.record_continuation_state
    }

    pub fn metadata(&self) -> Option<&'seg_meta [u8]> {
        self.metadata
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

#[derive(Debug, Copy, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
struct FdPduBase<'seg_meta> {
    pdu_header: PduHeader,
    #[cfg_attr(feature = "serde", serde(borrow))]
    segment_metadata: Option<SegmentMetadata<'seg_meta>>,
    offset: u64,
}

impl CfdpPdu for FdPduBase<'_> {
    fn pdu_header(&self) -> &PduHeader {
        &self.pdu_header
    }

    fn file_directive_type(&self) -> Option<FileDirectiveType> {
        None
    }
}

impl FdPduBase<'_> {
    fn calc_pdu_datafield_len(&self, file_data_len: u64) -> usize {
        let mut len = core::mem::size_of::<u32>();
        if self.pdu_header.pdu_conf.file_flag == LargeFileFlag::Large {
            len += 4;
        }
        if self.segment_metadata.is_some() {
            len += self.segment_metadata.as_ref().unwrap().written_len()
        }
        len += file_data_len as usize;
        if self.crc_flag() == CrcFlag::WithCrc {
            len += 2;
        }
        len
    }

    fn write_common_fields_to_bytes(&self, buf: &mut [u8]) -> Result<usize, PduError> {
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
        Ok(current_idx)
    }
}

/// File Data PDU abstraction.
///
/// For more information, refer to CFDP chapter 5.3.
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct FileDataPdu<'seg_meta, 'file_data> {
    #[cfg_attr(feature = "serde", serde(borrow))]
    common: FdPduBase<'seg_meta>,
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
            common: FdPduBase {
                pdu_header,
                segment_metadata,
                offset,
            },
            file_data,
        };
        pdu.common.pdu_header.pdu_datafield_len = pdu.calc_pdu_datafield_len() as u16;
        pdu
    }

    fn calc_pdu_datafield_len(&self) -> usize {
        self.common
            .calc_pdu_datafield_len(self.file_data.len() as u64)
    }

    pub fn segment_metadata(&self) -> Option<&SegmentMetadata<'_>> {
        self.common.segment_metadata.as_ref()
    }

    pub fn offset(&self) -> u64 {
        self.common.offset
    }

    pub fn file_data(&self) -> &'file_data [u8] {
        self.file_data
    }

    pub fn from_bytes<'buf: 'seg_meta + 'file_data>(buf: &'buf [u8]) -> Result<Self, PduError> {
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
            common: FdPduBase {
                pdu_header,
                segment_metadata,
                offset,
            },
            file_data: &buf[current_idx..full_len_without_crc],
        })
    }
}
impl CfdpPdu for FileDataPdu<'_, '_> {
    fn pdu_header(&self) -> &PduHeader {
        &self.common.pdu_header
    }

    fn file_directive_type(&self) -> Option<FileDirectiveType> {
        None
    }
}

impl WritablePduPacket for FileDataPdu<'_, '_> {
    fn write_to_bytes(&self, buf: &mut [u8]) -> Result<usize, PduError> {
        if buf.len() < self.len_written() {
            return Err(ByteConversionError::ToSliceTooSmall {
                found: buf.len(),
                expected: self.len_written(),
            }
            .into());
        }

        let mut current_idx = self.common.write_common_fields_to_bytes(buf)?;
        buf[current_idx..current_idx + self.file_data.len()].copy_from_slice(self.file_data);
        current_idx += self.file_data.len();
        if self.crc_flag() == CrcFlag::WithCrc {
            current_idx = add_pdu_crc(buf, current_idx);
        }
        Ok(current_idx)
    }

    fn len_written(&self) -> usize {
        self.common.pdu_header.header_len() + self.calc_pdu_datafield_len()
    }
}

/// File Data PDU creator abstraction.
///
/// This special creator object allows to read into the file data buffer directly. This avoids
/// the need of an additional buffer to create a file data PDU. This structure therefore
/// does not implement the regular [WritablePduPacket] trait.
///
/// For more information, refer to CFDP chapter 5.3.
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct FileDataPduCreatorWithReservedDatafield<'seg_meta> {
    #[cfg_attr(feature = "serde", serde(borrow))]
    common: FdPduBase<'seg_meta>,
    file_data_len: u64,
}

impl<'seg_meta> FileDataPduCreatorWithReservedDatafield<'seg_meta> {
    pub fn new_with_seg_metadata(
        pdu_header: PduHeader,
        segment_metadata: SegmentMetadata<'seg_meta>,
        offset: u64,
        file_data_len: u64,
    ) -> Self {
        Self::new_generic(pdu_header, Some(segment_metadata), offset, file_data_len)
    }

    pub fn new_no_seg_metadata(pdu_header: PduHeader, offset: u64, file_data_len: u64) -> Self {
        Self::new_generic(pdu_header, None, offset, file_data_len)
    }

    pub fn new_generic(
        mut pdu_header: PduHeader,
        segment_metadata: Option<SegmentMetadata<'seg_meta>>,
        offset: u64,
        file_data_len: u64,
    ) -> Self {
        pdu_header.pdu_type = PduType::FileData;
        if segment_metadata.is_some() {
            pdu_header.seg_metadata_flag = SegmentMetadataFlag::Present;
        }
        let mut pdu = Self {
            common: FdPduBase {
                pdu_header,
                segment_metadata,
                offset,
            },
            file_data_len,
        };
        pdu.common.pdu_header.pdu_datafield_len = pdu.calc_pdu_datafield_len() as u16;
        pdu
    }

    fn calc_pdu_datafield_len(&self) -> usize {
        self.common.calc_pdu_datafield_len(self.file_data_len)
    }

    pub fn len_written(&self) -> usize {
        self.common.pdu_header.header_len() + self.calc_pdu_datafield_len()
    }

    /// This function performs a partial write by writing all data except the file data
    /// and the CRC.
    ///
    /// It returns a [FileDataPduCreatorWithUnwrittenData] which provides a mutable slice to
    /// the reserved file data field. The user can read file data into this field directly and
    /// then finish the PDU creation using the [FileDataPduCreatorWithUnwrittenData::finish] call.
    pub fn write_to_bytes_partially<'buf>(
        &self,
        buf: &'buf mut [u8],
    ) -> Result<FileDataPduCreatorWithUnwrittenData<'buf>, PduError> {
        if buf.len() < self.len_written() {
            return Err(ByteConversionError::ToSliceTooSmall {
                found: buf.len(),
                expected: self.len_written(),
            }
            .into());
        }
        let mut current_idx = self.common.write_common_fields_to_bytes(buf)?;
        let file_data_offset = current_idx as u64;
        current_idx += self.file_data_len as usize;
        if self.crc_flag() == CrcFlag::WithCrc {
            current_idx += 2;
        }
        Ok(FileDataPduCreatorWithUnwrittenData {
            write_buf: &mut buf[0..current_idx],
            file_data_offset,
            file_data_len: self.file_data_len,
            needs_crc: self.crc_flag() == CrcFlag::WithCrc,
        })
    }
}

impl CfdpPdu for FileDataPduCreatorWithReservedDatafield<'_> {
    fn pdu_header(&self) -> &PduHeader {
        &self.common.pdu_header
    }

    fn file_directive_type(&self) -> Option<FileDirectiveType> {
        None
    }
}

/// This structure is created with [FileDataPduCreatorWithReservedDatafield::write_to_bytes_partially]
/// and provides an API to read file data from the virtual filesystem into the file data PDU buffer
/// directly.
///
/// This structure provides a mutable slice to the reserved file data field. The user can read
/// file data into this field directly and then finish the PDU creation using the
/// [FileDataPduCreatorWithUnwrittenData::finish] call.
pub struct FileDataPduCreatorWithUnwrittenData<'buf> {
    write_buf: &'buf mut [u8],
    file_data_offset: u64,
    file_data_len: u64,
    needs_crc: bool,
}

impl FileDataPduCreatorWithUnwrittenData<'_> {
    pub fn file_data_field_mut(&mut self) -> &mut [u8] {
        &mut self.write_buf[self.file_data_offset as usize
            ..self.file_data_offset as usize + self.file_data_len as usize]
    }

    /// This functio needs to be called to add a CRC to the file data PDU where applicable.
    ///
    /// It returns the full written size of the PDU.
    pub fn finish(self) -> usize {
        if self.needs_crc {
            add_pdu_crc(
                self.write_buf,
                self.file_data_offset as usize + self.file_data_len as usize,
            );
        }
        self.write_buf.len()
    }
}

/// This function can be used to calculate the maximum allowed file segment size for
/// a given maximum packet length and the segment metadata if there is any.
pub fn calculate_max_file_seg_len_for_max_packet_len_and_pdu_header(
    pdu_header: &PduHeader,
    max_packet_len: usize,
    segment_metadata: Option<&SegmentMetadata>,
) -> usize {
    let mut subtract = pdu_header.header_len();
    if let Some(segment_metadata) = segment_metadata {
        subtract += 1 + segment_metadata.metadata().unwrap().len();
    }
    if pdu_header.common_pdu_conf().file_flag == LargeFileFlag::Large {
        subtract += 8;
    } else {
        subtract += 4;
    }
    if pdu_header.common_pdu_conf().crc_flag == CrcFlag::WithCrc {
        subtract += 2;
    }
    max_packet_len.saturating_sub(subtract)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cfdp::pdu::tests::{TEST_DEST_ID, TEST_SEQ_NUM, TEST_SRC_ID};
    use crate::cfdp::pdu::{CommonPduConfig, PduHeader};
    use crate::cfdp::{Direction, SegmentMetadataFlag, SegmentationControl, TransmissionMode};
    #[cfg(feature = "serde")]
    use postcard::{from_bytes, to_allocvec};

    #[test]
    fn test_basic() {
        let common_conf =
            CommonPduConfig::new_with_byte_fields(TEST_SRC_ID, TEST_DEST_ID, TEST_SEQ_NUM).unwrap();
        let pdu_header = PduHeader::new_for_file_data_default(common_conf, 0);
        let file_data: [u8; 4] = [1, 2, 3, 4];
        let fd_pdu = FileDataPdu::new_no_seg_metadata(pdu_header, 10, &file_data);
        assert_eq!(fd_pdu.file_data(), file_data);
        assert_eq!(fd_pdu.offset(), 10);
        assert!(fd_pdu.segment_metadata().is_none());
        assert_eq!(
            fd_pdu.len_written(),
            fd_pdu.pdu_header().header_len() + core::mem::size_of::<u32>() + 4
        );

        assert_eq!(fd_pdu.crc_flag(), CrcFlag::NoCrc);
        assert_eq!(fd_pdu.file_flag(), LargeFileFlag::Normal);
        assert_eq!(fd_pdu.pdu_type(), PduType::FileData);
        assert_eq!(fd_pdu.file_directive_type(), None);
        assert_eq!(fd_pdu.transmission_mode(), TransmissionMode::Acknowledged);
        assert_eq!(fd_pdu.direction(), Direction::TowardsReceiver);
        assert_eq!(fd_pdu.source_id(), TEST_SRC_ID.into());
        assert_eq!(fd_pdu.dest_id(), TEST_DEST_ID.into());
        assert_eq!(fd_pdu.transaction_seq_num(), TEST_SEQ_NUM.into());
    }

    #[test]
    fn test_serialization() {
        let common_conf =
            CommonPduConfig::new_with_byte_fields(TEST_SRC_ID, TEST_DEST_ID, TEST_SEQ_NUM).unwrap();
        let pdu_header = PduHeader::new_for_file_data_default(common_conf, 0);
        let file_data: [u8; 4] = [1, 2, 3, 4];
        let fd_pdu = FileDataPdu::new_no_seg_metadata(pdu_header, 10, &file_data);
        let mut buf: [u8; 32] = [0; 32];
        let res = fd_pdu.write_to_bytes(&mut buf);
        assert!(res.is_ok());
        let written = res.unwrap();
        assert_eq!(
            written,
            fd_pdu.pdu_header().header_len() + core::mem::size_of::<u32>() + 4
        );
        let mut current_idx = fd_pdu.pdu_header().header_len();
        let file_size = u32::from_be_bytes(
            buf[fd_pdu.pdu_header().header_len()..fd_pdu.pdu_header().header_len() + 4]
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
    fn test_write_to_vec() {
        let common_conf =
            CommonPduConfig::new_with_byte_fields(TEST_SRC_ID, TEST_DEST_ID, TEST_SEQ_NUM).unwrap();
        let pdu_header = PduHeader::new_for_file_data_default(common_conf, 0);
        let file_data: [u8; 4] = [1, 2, 3, 4];
        let fd_pdu = FileDataPdu::new_no_seg_metadata(pdu_header, 10, &file_data);
        let mut buf: [u8; 64] = [0; 64];
        let written = fd_pdu.write_to_bytes(&mut buf).unwrap();
        let pdu_vec = fd_pdu.to_vec().unwrap();
        assert_eq!(buf[0..written], pdu_vec);
    }

    #[test]
    fn test_deserialization() {
        let common_conf =
            CommonPduConfig::new_with_byte_fields(TEST_SRC_ID, TEST_DEST_ID, TEST_SEQ_NUM).unwrap();
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
    fn test_with_crc() {
        let mut common_conf =
            CommonPduConfig::new_with_byte_fields(TEST_SRC_ID, TEST_DEST_ID, TEST_SEQ_NUM).unwrap();
        common_conf.crc_flag = true.into();
        let pdu_header = PduHeader::new_for_file_data_default(common_conf, 0);
        let file_data: [u8; 4] = [1, 2, 3, 4];
        let fd_pdu = FileDataPdu::new_no_seg_metadata(pdu_header, 10, &file_data);
        let mut buf: [u8; 64] = [0; 64];
        let written = fd_pdu.write_to_bytes(&mut buf).unwrap();
        assert_eq!(written, fd_pdu.len_written());
        let finished_pdu_from_raw = FileDataPdu::from_bytes(&buf).unwrap();
        assert_eq!(finished_pdu_from_raw, fd_pdu);
        buf[written - 1] -= 1;
        let crc: u16 = ((buf[written - 2] as u16) << 8) | buf[written - 1] as u16;
        let error = FileDataPdu::from_bytes(&buf).unwrap_err();
        if let PduError::Checksum(e) = error {
            assert_eq!(e, crc);
        } else {
            panic!("expected crc error");
        }
    }

    #[test]
    fn test_with_seg_metadata_serialization() {
        let common_conf =
            CommonPduConfig::new_with_byte_fields(TEST_SRC_ID, TEST_DEST_ID, TEST_SEQ_NUM).unwrap();
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
            fd_pdu.len_written(),
            fd_pdu.pdu_header().header_len()
                + 1
                + seg_metadata.len()
                + core::mem::size_of::<u32>()
                + 4
        );
        let mut buf: [u8; 32] = [0; 32];
        fd_pdu
            .write_to_bytes(&mut buf)
            .expect("writing FD PDU failed");
        let mut current_idx = fd_pdu.pdu_header().header_len();
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
        assert_eq!(current_idx, fd_pdu.len_written());
    }

    #[test]
    fn test_with_seg_metadata_deserialization() {
        let common_conf =
            CommonPduConfig::new_with_byte_fields(TEST_SRC_ID, TEST_DEST_ID, TEST_SEQ_NUM).unwrap();
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

    #[test]
    #[cfg(feature = "serde")]
    fn test_serde_serialization() {
        let common_conf =
            CommonPduConfig::new_with_byte_fields(TEST_SRC_ID, TEST_DEST_ID, TEST_SEQ_NUM).unwrap();
        let pdu_header = PduHeader::new_for_file_data_default(common_conf, 0);
        let file_data: [u8; 4] = [1, 2, 3, 4];
        let fd_pdu = FileDataPdu::new_no_seg_metadata(pdu_header, 10, &file_data);
        let output = to_allocvec(&fd_pdu).unwrap();
        let output_converted_back: FileDataPdu = from_bytes(&output).unwrap();
        assert_eq!(output_converted_back, fd_pdu);
    }

    #[test]
    #[cfg(feature = "serde")]
    fn test_serde_serialization_with_seg_metadata() {
        let common_conf =
            CommonPduConfig::new_with_byte_fields(TEST_SRC_ID, TEST_DEST_ID, TEST_SEQ_NUM).unwrap();
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
        let output = to_allocvec(&fd_pdu).unwrap();
        let output_converted_back: FileDataPdu = from_bytes(&output).unwrap();
        assert_eq!(output_converted_back, fd_pdu);
    }

    #[test]
    fn test_fd_pdu_creator_with_reserved_field_no_crc() {
        let common_conf =
            CommonPduConfig::new_with_byte_fields(TEST_SRC_ID, TEST_DEST_ID, TEST_SEQ_NUM).unwrap();
        let pdu_header = PduHeader::new_for_file_data_default(common_conf, 0);
        let test_str = "hello world!";
        let fd_pdu = FileDataPduCreatorWithReservedDatafield::new_no_seg_metadata(
            pdu_header,
            10,
            test_str.len() as u64,
        );
        let mut write_buf: [u8; 64] = [0; 64];
        let mut pdu_unwritten = fd_pdu
            .write_to_bytes_partially(&mut write_buf)
            .expect("partial write failed");
        pdu_unwritten
            .file_data_field_mut()
            .copy_from_slice(test_str.as_bytes());
        pdu_unwritten.finish();

        let pdu_reader = FileDataPdu::from_bytes(&write_buf).expect("reading file data PDU failed");
        assert_eq!(
            core::str::from_utf8(pdu_reader.file_data()).expect("reading utf8 string failed"),
            "hello world!"
        );
    }

    #[test]
    fn test_fd_pdu_creator_with_reserved_field_with_crc() {
        let mut common_conf =
            CommonPduConfig::new_with_byte_fields(TEST_SRC_ID, TEST_DEST_ID, TEST_SEQ_NUM).unwrap();
        common_conf.crc_flag = true.into();
        let pdu_header = PduHeader::new_for_file_data_default(common_conf, 0);
        let test_str = "hello world!";
        let fd_pdu = FileDataPduCreatorWithReservedDatafield::new_no_seg_metadata(
            pdu_header,
            10,
            test_str.len() as u64,
        );
        let mut write_buf: [u8; 64] = [0; 64];
        let mut pdu_unwritten = fd_pdu
            .write_to_bytes_partially(&mut write_buf)
            .expect("partial write failed");
        pdu_unwritten
            .file_data_field_mut()
            .copy_from_slice(test_str.as_bytes());
        pdu_unwritten.finish();

        let pdu_reader = FileDataPdu::from_bytes(&write_buf).expect("reading file data PDU failed");
        assert_eq!(
            core::str::from_utf8(pdu_reader.file_data()).expect("reading utf8 string failed"),
            "hello world!"
        );
    }

    #[test]
    fn test_fd_pdu_creator_with_reserved_field_with_crc_without_finish_fails() {
        let mut common_conf =
            CommonPduConfig::new_with_byte_fields(TEST_SRC_ID, TEST_DEST_ID, TEST_SEQ_NUM).unwrap();
        common_conf.crc_flag = true.into();
        let pdu_header = PduHeader::new_for_file_data_default(common_conf, 0);
        let test_str = "hello world!";
        let fd_pdu = FileDataPduCreatorWithReservedDatafield::new_no_seg_metadata(
            pdu_header,
            10,
            test_str.len() as u64,
        );
        let mut write_buf: [u8; 64] = [0; 64];
        let mut pdu_unwritten = fd_pdu
            .write_to_bytes_partially(&mut write_buf)
            .expect("partial write failed");
        pdu_unwritten
            .file_data_field_mut()
            .copy_from_slice(test_str.as_bytes());

        let pdu_reader_error = FileDataPdu::from_bytes(&write_buf);
        assert!(pdu_reader_error.is_err());
        let error = pdu_reader_error.unwrap_err();
        match error {
            PduError::Checksum(_) => (),
            _ => {
                panic!("unexpected PDU error {}", error)
            }
        }
    }

    #[test]
    fn test_max_file_seg_calculator_0() {
        let pdu_header = PduHeader::new_for_file_data_default(CommonPduConfig::default(), 0);
        assert_eq!(
            calculate_max_file_seg_len_for_max_packet_len_and_pdu_header(&pdu_header, 64, None),
            53
        );
    }

    #[test]
    fn test_max_file_seg_calculator_1() {
        let common_conf = CommonPduConfig {
            crc_flag: CrcFlag::WithCrc,
            ..Default::default()
        };
        let pdu_header = PduHeader::new_for_file_data_default(common_conf, 0);
        assert_eq!(
            calculate_max_file_seg_len_for_max_packet_len_and_pdu_header(&pdu_header, 64, None),
            51
        );
    }

    #[test]
    fn test_max_file_seg_calculator_2() {
        let common_conf = CommonPduConfig {
            file_flag: LargeFileFlag::Large,
            ..Default::default()
        };
        let pdu_header = PduHeader::new_for_file_data_default(common_conf, 0);
        assert_eq!(
            calculate_max_file_seg_len_for_max_packet_len_and_pdu_header(&pdu_header, 64, None),
            49
        );
    }

    #[test]
    fn test_max_file_seg_calculator_saturating_sub() {
        let common_conf = CommonPduConfig {
            file_flag: LargeFileFlag::Large,
            ..Default::default()
        };
        let pdu_header = PduHeader::new_for_file_data_default(common_conf, 0);
        assert_eq!(
            calculate_max_file_seg_len_for_max_packet_len_and_pdu_header(&pdu_header, 15, None),
            0
        );
        assert_eq!(
            calculate_max_file_seg_len_for_max_packet_len_and_pdu_header(&pdu_header, 14, None),
            0
        );
    }
}
