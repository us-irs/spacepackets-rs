use core::marker::PhantomData;

use crate::{
    cfdp::{CrcFlag, Direction, LargeFileFlag},
    ByteConversionError,
};

use super::{
    add_pdu_crc, generic_length_checks_pdu_deserialization, CfdpPdu, FileDirectiveType, PduError,
    PduHeader, WritablePduPacket,
};
#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

/// Special iterator type for the NAK PDU which allows to iterator over both normal and large file
/// segment requests.
pub struct SegmentRequestIter<'a, T> {
    seq_req_start: &'a [u8],
    current_idx: usize,
    phantom: std::marker::PhantomData<T>,
}

trait FromBytes {
    fn from_bytes(bytes: &[u8]) -> Self;
}

impl FromBytes for u32 {
    fn from_bytes(bytes: &[u8]) -> u32 {
        u32::from_be_bytes(bytes.try_into().unwrap())
    }
}

impl FromBytes for u64 {
    fn from_bytes(bytes: &[u8]) -> u64 {
        u64::from_be_bytes(bytes.try_into().unwrap())
    }
}

impl<'a, T> Iterator for SegmentRequestIter<'a, T>
where
    T: FromBytes,
{
    type Item = (T, T);

    fn next(&mut self) -> Option<Self::Item> {
        if self.current_idx + std::mem::size_of::<T>() * 2 > self.seq_req_start.len() {
            return None;
        }

        let start_offset = T::from_bytes(
            &self.seq_req_start[self.current_idx..self.current_idx + std::mem::size_of::<T>()],
        );
        self.current_idx += std::mem::size_of::<T>();

        let end_offset = T::from_bytes(
            &self.seq_req_start[self.current_idx..self.current_idx + std::mem::size_of::<T>()],
        );
        self.current_idx += std::mem::size_of::<T>();

        Some((start_offset, end_offset))
    }
}

/// NAK PDU abstraction.
///
/// For more information, refer to CFDP chapter 5.2.6.
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct NakPdu<'seg_reqs> {
    pdu_header: PduHeader,
    start_of_scope: u64,
    end_of_scope: u64,
    seg_reqs_raw: &'seg_reqs [u8],
}

impl<'seg_reqs> NakPdu<'seg_reqs> {
    pub fn new(
        mut pdu_header: PduHeader,
        start_of_scope: u64,
        end_of_scope: u64,
        seg_reqs_raw: &'seg_reqs [u8],
    ) -> Result<NakPdu, PduError> {
        // Force correct direction flag.
        pdu_header.pdu_conf.direction = Direction::TowardsSender;
        if pdu_header.common_pdu_conf().file_flag == LargeFileFlag::Large {
            if seg_reqs_raw.len() % 16 != 0 {
                return Err(PduError::InvalidSegmentRequestFormat);
            }
        } else {
            if seg_reqs_raw.len() % 8 != 0 {
                return Err(PduError::InvalidSegmentRequestFormat);
            }
            if start_of_scope > u32::MAX as u64 || end_of_scope > u32::MAX as u64 {
                return Err(PduError::InvalidStartOrEndOfScopeValue);
            }
        }
        let mut nak_pdu = Self {
            pdu_header,
            start_of_scope,
            end_of_scope,
            seg_reqs_raw,
        };
        nak_pdu.pdu_header.pdu_datafield_len = nak_pdu.calc_pdu_datafield_len() as u16;
        Ok(nak_pdu)
    }

    pub fn start_of_scope(&self) -> u64 {
        self.start_of_scope
    }

    pub fn end_of_scope(&self) -> u64 {
        self.end_of_scope
    }

    pub fn get_normal_segment_requests_iterator(&self) -> Option<SegmentRequestIter<'_, u32>> {
        if self.file_flag() == LargeFileFlag::Large {
            return None;
        }
        Some(SegmentRequestIter {
            seq_req_start: self.seg_reqs_raw,
            current_idx: 0,
            phantom: PhantomData,
        })
    }

    pub fn get_large_segment_requests_iterator(&self) -> Option<SegmentRequestIter<'_, u64>> {
        if self.file_flag() == LargeFileFlag::Normal {
            return None;
        }
        Some(SegmentRequestIter {
            seq_req_start: self.seg_reqs_raw,
            current_idx: 0,
            phantom: PhantomData,
        })
    }

    pub fn num_segment_reqs(&self) -> usize {
        if self.file_flag() == LargeFileFlag::Large {
            self.seg_reqs_raw.len() / 16
        } else {
            self.seg_reqs_raw.len() / 8
        }
    }

    pub fn pdu_header(&self) -> &PduHeader {
        &self.pdu_header
    }

    fn calc_pdu_datafield_len(&self) -> usize {
        let mut datafield_len = 1;
        if self.file_flag() == LargeFileFlag::Normal {
            datafield_len += 8;
            datafield_len += self.num_segment_reqs() * 8;
        } else {
            datafield_len += 16;
            datafield_len += self.num_segment_reqs() * 16;
        }
        if self.crc_flag() == CrcFlag::WithCrc {
            datafield_len += 2;
        }
        datafield_len
    }

    pub fn from_bytes(buf: &'seg_reqs [u8]) -> Result<NakPdu, PduError> {
        let (pdu_header, mut current_idx) = PduHeader::from_bytes(buf)?;
        let full_len_without_crc = pdu_header.verify_length_and_checksum(buf)?;
        // Minimum length of 9: 1 byte directive field and start and end of scope for normal file
        // size.
        generic_length_checks_pdu_deserialization(buf, 9, full_len_without_crc)?;
        let directive_type = FileDirectiveType::try_from(buf[current_idx]).map_err(|_| {
            PduError::InvalidDirectiveType {
                found: buf[current_idx],
                expected: Some(FileDirectiveType::NakPdu),
            }
        })?;
        if directive_type != FileDirectiveType::NakPdu {
            return Err(PduError::WrongDirectiveType {
                found: directive_type,
                expected: FileDirectiveType::AckPdu,
            });
        }
        current_idx += 1;
        let start_of_scope;
        let end_of_scope;
        if pdu_header.common_pdu_conf().file_flag == LargeFileFlag::Large {
            if current_idx + 16 > buf.len() {
                return Err(PduError::ByteConversionError(
                    ByteConversionError::FromSliceTooSmall {
                        found: buf.len(),
                        expected: current_idx + 16,
                    },
                ));
            }
            start_of_scope =
                u64::from_be_bytes(buf[current_idx..current_idx + 8].try_into().unwrap());
            current_idx += 8;
            end_of_scope =
                u64::from_be_bytes(buf[current_idx..current_idx + 8].try_into().unwrap());
            current_idx += 8;
        } else {
            start_of_scope =
                u64::from_be_bytes(buf[current_idx..current_idx + 4].try_into().unwrap());
            current_idx += 4;
            end_of_scope =
                u64::from_be_bytes(buf[current_idx..current_idx + 4].try_into().unwrap());
            current_idx += 4;
        }
        Self::new(
            pdu_header,
            start_of_scope,
            end_of_scope,
            &buf[current_idx..full_len_without_crc],
        )
    }
}

impl CfdpPdu for NakPdu<'_> {
    fn pdu_header(&self) -> &PduHeader {
        &self.pdu_header
    }

    fn file_directive_type(&self) -> Option<FileDirectiveType> {
        Some(FileDirectiveType::NakPdu)
    }
}

impl WritablePduPacket for NakPdu<'_> {
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
        buf[current_idx] = FileDirectiveType::NakPdu as u8;
        current_idx += 1;

        if self.file_flag() == LargeFileFlag::Large {
            buf[current_idx..current_idx + 8].copy_from_slice(&self.start_of_scope.to_be_bytes());
            current_idx += 8;
            buf[current_idx..current_idx + 8].copy_from_slice(&self.end_of_scope.to_be_bytes());
            current_idx += 8;
            // Unwrap is okay here, we checked the file flag.
            let segments_iter = self.get_large_segment_requests_iterator().unwrap();
            for (next_start_offset, next_end_offset) in segments_iter {
                buf[current_idx..current_idx + 8].copy_from_slice(&next_start_offset.to_be_bytes());
                current_idx += 8;
                buf[current_idx..current_idx + 8].copy_from_slice(&next_end_offset.to_be_bytes());
                current_idx += 8;
            }
        } else {
            // Unwrap is okay here, the API should prevent invalid values which would trigger a
            // panic here.
            let start_of_scope = u32::try_from(self.start_of_scope).unwrap();
            let end_of_scope = u32::try_from(self.end_of_scope).unwrap();
            buf[current_idx..current_idx + 4].copy_from_slice(&start_of_scope.to_be_bytes());
            current_idx += 4;
            buf[current_idx..current_idx + 4].copy_from_slice(&end_of_scope.to_be_bytes());
            current_idx += 4;
            // Unwrap is okay here, we checked the file flag.
            let segments_iter = self.get_normal_segment_requests_iterator().unwrap();
            for (next_start_offset, next_end_offset) in segments_iter {
                buf[current_idx..current_idx + 4].copy_from_slice(&next_start_offset.to_be_bytes());
                current_idx += 4;
                buf[current_idx..current_idx + 4].copy_from_slice(&next_end_offset.to_be_bytes());
                current_idx += 4;
            }
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

#[cfg(test)]
mod tests {}
