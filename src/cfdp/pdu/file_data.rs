use crate::cfdp::pdu::{write_file_size, PduError, PduHeader};
use crate::cfdp::{CrcFlag, LargeFileFlag, PduType, SegmentMetadataFlag};
use crate::{ByteConversionError, SizeMissmatch};
use num_enum::{IntoPrimitive, TryFromPrimitive};
#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

#[derive(Debug, Copy, Clone, PartialEq, Eq, TryFromPrimitive, IntoPrimitive)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[repr(u8)]
pub enum RecordContinuationState {
    NoStartNoEnd = 0b00,
    StartWithoutEnd = 0b01,
    EndWithoutStart = 0b10,
    StartAndEnd = 0b11,
}

pub struct SegmentMetadata<'seg_meta> {
    record_continuation_state: RecordContinuationState,
    seg_metadata_len: u8,
    metadata: Option<&'seg_meta [u8]>,
}

impl SegmentMetadata<'_> {
    pub fn written_len(&self) -> usize {
        1 + self.seg_metadata_len as usize
    }

    pub fn write_to_bytes(&self, buf: &mut [u8]) -> Result<usize, ByteConversionError> {
        if buf.len() < self.written_len() {
            return Err(ByteConversionError::ToSliceTooSmall(SizeMissmatch {
                found: buf.len(),
                expected: self.written_len(),
            }));
        }
        buf[0] = ((self.record_continuation_state as u8) << 6) | self.seg_metadata_len;
        if self.metadata.is_some() {
            buf[1..].copy_from_slice(self.metadata.unwrap())
        }
        Ok(self.written_len())
    }
}

pub struct FileDataPdu<'seg_meta, 'file_data> {
    pdu_header: PduHeader,
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
        Self {
            pdu_header,
            segment_metadata,
            offset,
            file_data,
        }
    }

    pub fn written_len(&self) -> usize {
        let mut len = self.pdu_header.header_len();
        if self.segment_metadata.is_some() {
            len += self.segment_metadata.as_ref().unwrap().written_len()
        }
        // Regular file size
        len += core::mem::size_of::<u32>();
        if self.pdu_header.pdu_conf.file_flag == LargeFileFlag::Large {
            len += core::mem::size_of::<u32>();
        }
        len += self.file_data.len();
        if self.pdu_header.pdu_conf.crc_flag == CrcFlag::WithCrc {
            len += 2;
        }
        len
    }

    pub fn write_to_bytes(&self, buf: &mut [u8]) -> Result<usize, PduError> {
        if buf.len() < self.written_len() {
            return Err(ByteConversionError::ToSliceTooSmall(SizeMissmatch {
                found: buf.len(),
                expected: self.written_len(),
            })
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
        write_file_size(
            &mut current_idx,
            self.pdu_header.common_pdu_conf().file_flag,
            self.offset,
            buf,
        )?;
        buf[current_idx..current_idx + self.file_data.len()].copy_from_slice(self.file_data);
        Ok(current_idx)
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn test_basic() {

    }
}