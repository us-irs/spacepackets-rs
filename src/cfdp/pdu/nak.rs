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

#[derive(Debug, PartialEq, Eq, Clone)]
pub enum SegmentRequests<'a> {
    U32Pairs(&'a [(u32, u32)]),
    U64Pairs(&'a [(u64, u64)]),
}

/// NAK PDU abstraction specialized in the creation of NAK PDUs.
///
/// It exposes a specialized API which simplifies to generate these NAK PDUs with the
/// format according to CFDP chapter 5.2.6.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct NakPduCreator<'seg_reqs> {
    pdu_header: PduHeader,
    start_of_scope: u64,
    end_of_scope: u64,
    segment_requests: Option<SegmentRequests<'seg_reqs>>,
}

impl<'seg_reqs> NakPduCreator<'seg_reqs> {
    /// This constructor will set the PDU header [LargeFileFlag] field to the correct value if
    /// segment requests are passed to it. If the segment request field is [None], it will remain
    /// to whatever was configured for the PDU header.
    pub fn new(
        mut pdu_header: PduHeader,
        start_of_scope: u64,
        end_of_scope: u64,
        segment_requests: Option<SegmentRequests<'seg_reqs>>,
    ) -> Result<NakPduCreator, PduError> {
        // Force correct direction flag.
        pdu_header.pdu_conf.direction = Direction::TowardsSender;
        if let Some(ref seg_reqs) = segment_requests {
            match seg_reqs {
                SegmentRequests::U32Pairs(_) => {
                    if start_of_scope > u32::MAX as u64 || end_of_scope > u32::MAX as u64 {
                        return Err(PduError::InvalidStartOrEndOfScopeValue);
                    }
                    pdu_header.pdu_conf.file_flag = LargeFileFlag::Normal;
                }
                SegmentRequests::U64Pairs(_) => {
                    pdu_header.pdu_conf.file_flag = LargeFileFlag::Large;
                }
            }
        }
        let mut nak_pdu = Self {
            pdu_header,
            start_of_scope,
            end_of_scope,
            segment_requests,
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

    pub fn segment_requests(&self) -> Option<&SegmentRequests> {
        self.segment_requests.as_ref()
    }

    pub fn num_segment_reqs(&self) -> usize {
        match &self.segment_requests {
            Some(seg_reqs) => match seg_reqs {
                SegmentRequests::U32Pairs(pairs) => pairs.len(),
                SegmentRequests::U64Pairs(pairs) => pairs.len(),
            },
            None => 0,
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
}

impl CfdpPdu for NakPduCreator<'_> {
    fn pdu_header(&self) -> &PduHeader {
        &self.pdu_header
    }

    fn file_directive_type(&self) -> Option<FileDirectiveType> {
        Some(FileDirectiveType::NakPdu)
    }
}

impl WritablePduPacket for NakPduCreator<'_> {
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

        let mut write_start_end_of_scope_normal = || {
            let start_of_scope = u32::try_from(self.start_of_scope).unwrap();
            let end_of_scope = u32::try_from(self.end_of_scope).unwrap();
            buf[current_idx..current_idx + 4].copy_from_slice(&start_of_scope.to_be_bytes());
            current_idx += 4;
            buf[current_idx..current_idx + 4].copy_from_slice(&end_of_scope.to_be_bytes());
            current_idx += 4;
        };
        if let Some(ref seg_reqs) = self.segment_requests {
            match seg_reqs {
                SegmentRequests::U32Pairs(pairs) => {
                    // Unwrap is okay here, the API should prevent invalid values which would trigger a
                    // panic here.
                    write_start_end_of_scope_normal();
                    for (next_start_offset, next_end_offset) in *pairs {
                        buf[current_idx..current_idx + 4]
                            .copy_from_slice(&next_start_offset.to_be_bytes());
                        current_idx += 4;
                        buf[current_idx..current_idx + 4]
                            .copy_from_slice(&next_end_offset.to_be_bytes());
                        current_idx += 4;
                    }
                }
                SegmentRequests::U64Pairs(pairs) => {
                    buf[current_idx..current_idx + 8]
                        .copy_from_slice(&self.start_of_scope.to_be_bytes());
                    current_idx += 8;
                    buf[current_idx..current_idx + 8]
                        .copy_from_slice(&self.end_of_scope.to_be_bytes());
                    current_idx += 8;
                    for (next_start_offset, next_end_offset) in *pairs {
                        buf[current_idx..current_idx + 8]
                            .copy_from_slice(&next_start_offset.to_be_bytes());
                        current_idx += 8;
                        buf[current_idx..current_idx + 8]
                            .copy_from_slice(&next_end_offset.to_be_bytes());
                        current_idx += 8;
                    }
                }
            }
        } else {
            write_start_end_of_scope_normal();
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

/// Special iterator type for the NAK PDU which allows to iterate over both normal and large file
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

/// NAK PDU abstraction specialized in the reading NAK PDUs from a raw bytestream.
///
/// This is a zero-copy class where the segment requests can be read using a special iterator
/// API without the need to copy them.
///
/// The NAK format is expected to be conforming to CFDP chapter 5.2.6.
pub struct NakPduReader<'seg_reqs> {
    pdu_header: PduHeader,
    start_of_scope: u64,
    end_of_scope: u64,
    seg_reqs_raw: &'seg_reqs [u8],
}

impl CfdpPdu for NakPduReader<'_> {
    fn pdu_header(&self) -> &PduHeader {
        &self.pdu_header
    }

    fn file_directive_type(&self) -> Option<FileDirectiveType> {
        Some(FileDirectiveType::NakPdu)
    }
}

impl<'seg_reqs> NakPduReader<'seg_reqs> {
    pub fn from_bytes(buf: &'seg_reqs [u8]) -> Result<NakPduReader, PduError> {
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
        Ok(Self {
            pdu_header,
            start_of_scope,
            end_of_scope,
            seg_reqs_raw: &buf[current_idx..full_len_without_crc],
        })
    }

    pub fn start_of_scope(&self) -> u64 {
        self.start_of_scope
    }

    pub fn end_of_scope(&self) -> u64 {
        self.end_of_scope
    }

    /// This function returns [None] if this NAK PDUs contains segment requests for a large file.
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

    /// This function returns [None] if this NAK PDUs contains segment requests for a normal file.
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
}

#[cfg(test)]
mod tests {
    use crate::cfdp::{
        pdu::tests::{common_pdu_conf, verify_raw_header, TEST_DEST_ID, TEST_SEQ_NUM, TEST_SRC_ID},
        PduType, TransmissionMode,
    };

    use super::*;

    #[test]
    fn test_basic_creator() {
        let pdu_conf = common_pdu_conf(CrcFlag::NoCrc, LargeFileFlag::Normal);
        let pdu_header = PduHeader::new_no_file_data(pdu_conf, 0);
        let nak_pdu =
            NakPduCreator::new(pdu_header, 0, 0, None).expect("creating NAK PDU creator failed");
        assert_eq!(nak_pdu.start_of_scope(), 0);
        assert_eq!(nak_pdu.end_of_scope(), 0);
        assert_eq!(nak_pdu.segment_requests(), None);
        assert_eq!(nak_pdu.num_segment_reqs(), 0);

        assert_eq!(nak_pdu.crc_flag(), CrcFlag::NoCrc);
        assert_eq!(nak_pdu.file_flag(), LargeFileFlag::Normal);
        assert_eq!(nak_pdu.pdu_type(), PduType::FileDirective);
        assert_eq!(
            nak_pdu.file_directive_type(),
            Some(FileDirectiveType::NakPdu),
        );
        assert_eq!(nak_pdu.transmission_mode(), TransmissionMode::Acknowledged);
        assert_eq!(nak_pdu.direction(), Direction::TowardsSender);
        assert_eq!(nak_pdu.source_id(), TEST_SRC_ID.into());
        assert_eq!(nak_pdu.dest_id(), TEST_DEST_ID.into());
        assert_eq!(nak_pdu.transaction_seq_num(), TEST_SEQ_NUM.into());
    }

    #[test]
    fn test_serialization_empty() {
        let pdu_conf = common_pdu_conf(CrcFlag::NoCrc, LargeFileFlag::Normal);
        let pdu_header = PduHeader::new_no_file_data(pdu_conf, 0);
        let nak_pdu = NakPduCreator::new(pdu_header, 100, 300, None)
            .expect("creating NAK PDU creator failed");
        let mut buf: [u8; 64] = [0; 64];
        nak_pdu
            .write_to_bytes(&mut buf)
            .expect("writing NAK PDU to buffer failed");
        verify_raw_header(nak_pdu.pdu_header(), &buf);
        let mut current_idx = nak_pdu.pdu_header().header_len();
        assert_eq!(current_idx + 9, nak_pdu.len_written());
        assert_eq!(buf[current_idx], FileDirectiveType::NakPdu as u8);
        current_idx += 1;
        let start_of_scope =
            u32::from_be_bytes(buf[current_idx..current_idx + 4].try_into().unwrap());
        assert_eq!(start_of_scope, 100);
        current_idx += 4;
        let end_of_scope =
            u32::from_be_bytes(buf[current_idx..current_idx + 4].try_into().unwrap());
        assert_eq!(end_of_scope, 300);
        current_idx += 4;
        assert_eq!(current_idx, nak_pdu.len_written());
    }

    #[test]
    fn test_serialization_one_segment() {

    }
}
