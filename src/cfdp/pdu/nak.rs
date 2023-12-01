use crate::{
    cfdp::{CrcFlag, Direction, LargeFileFlag},
    ByteConversionError,
};
use core::marker::PhantomData;

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

impl SegmentRequests<'_> {
    pub fn is_empty(&self) -> bool {
        match self {
            SegmentRequests::U32Pairs(pairs) => pairs.is_empty(),
            SegmentRequests::U64Pairs(pairs) => pairs.is_empty(),
        }
    }
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
    /// Please note that the start of scope and the end of scope need to be smaller or equal
    /// to [u32::MAX] if the large file flag of the passed PDU configuration is
    /// [LargeFileFlag::Normal].
    ///
    /// ## Errrors
    ///
    pub fn new_no_segment_requests(
        pdu_header: PduHeader,
        start_of_scope: u64,
        end_of_scope: u64,
    ) -> Result<NakPduCreator<'seg_reqs>, PduError> {
        Self::new_generic(pdu_header, start_of_scope, end_of_scope, None)
    }

    /// Default constructor for normal file sizes.
    pub fn new(
        pdu_header: PduHeader,
        start_of_scope: u32,
        end_of_scope: u32,
        segment_requests: &'seg_reqs [(u32, u32)],
    ) -> Result<NakPduCreator, PduError> {
        let mut passed_segment_requests = None;
        if !segment_requests.is_empty() {
            passed_segment_requests = Some(SegmentRequests::U32Pairs(segment_requests));
        }
        Self::new_generic(
            pdu_header,
            start_of_scope.into(),
            end_of_scope.into(),
            passed_segment_requests,
        )
    }

    pub fn new_large_file_size(
        pdu_header: PduHeader,
        start_of_scope: u64,
        end_of_scope: u64,
        segment_requests: &'seg_reqs [(u64, u64)],
    ) -> Result<NakPduCreator, PduError> {
        let mut passed_segment_requests = None;
        if !segment_requests.is_empty() {
            passed_segment_requests = Some(SegmentRequests::U64Pairs(segment_requests));
        }
        Self::new_generic(
            pdu_header,
            start_of_scope,
            end_of_scope,
            passed_segment_requests,
        )
    }

    fn new_generic(
        mut pdu_header: PduHeader,
        start_of_scope: u64,
        end_of_scope: u64,
        segment_requests: Option<SegmentRequests<'seg_reqs>>,
    ) -> Result<NakPduCreator, PduError> {
        // Force correct direction flag.
        pdu_header.pdu_conf.direction = Direction::TowardsSender;
        if let Some(ref segment_requests) = segment_requests {
            match segment_requests {
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
        };
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
#[derive(Debug)]
pub struct SegmentRequestIter<'a, T> {
    seq_req_raw: &'a [u8],
    current_idx: usize,
    phantom: std::marker::PhantomData<T>,
}

pub trait SegReqFromBytes {
    fn from_bytes(bytes: &[u8]) -> Self;
}

impl SegReqFromBytes for u32 {
    fn from_bytes(bytes: &[u8]) -> u32 {
        u32::from_be_bytes(bytes.try_into().unwrap())
    }
}

impl SegReqFromBytes for u64 {
    fn from_bytes(bytes: &[u8]) -> u64 {
        u64::from_be_bytes(bytes.try_into().unwrap())
    }
}

impl<'a, T> Iterator for SegmentRequestIter<'a, T>
where
    T: SegReqFromBytes,
{
    type Item = (T, T);

    fn next(&mut self) -> Option<Self::Item> {
        let value = self.next_at_offset(self.current_idx);
        self.current_idx += 2 * std::mem::size_of::<T>();
        value
    }
}

impl<'a, 'b> PartialEq<SegmentRequests<'a>> for SegmentRequestIter<'b, u32> {
    fn eq(&self, other: &SegmentRequests) -> bool {
        match other {
            SegmentRequests::U32Pairs(pairs) => self.compare_pairs(pairs),
            SegmentRequests::U64Pairs(pairs) => {
                if pairs.is_empty() && self.seq_req_raw.is_empty() {
                    return true;
                }
                false
            }
        }
    }
}

impl<'a, 'b> PartialEq<SegmentRequests<'a>> for SegmentRequestIter<'b, u64> {
    fn eq(&self, other: &SegmentRequests) -> bool {
        match other {
            SegmentRequests::U32Pairs(pairs) => {
                if pairs.is_empty() && self.seq_req_raw.is_empty() {
                    return true;
                }
                false
            }
            SegmentRequests::U64Pairs(pairs) => self.compare_pairs(pairs),
        }
    }
}

impl<'a, T> SegmentRequestIter<'a, T>
where
    T: SegReqFromBytes + PartialEq,
{
    fn compare_pairs(&self, pairs: &[(T, T)]) -> bool {
        if pairs.is_empty() && self.seq_req_raw.is_empty() {
            return true;
        }
        let size = std::mem::size_of::<T>();
        if pairs.len() * 2 * size != self.seq_req_raw.len() {
            return false;
        }

        for (i, pair) in pairs.iter().enumerate() {
            let next_val = self.next_at_offset(i * 2 * size).unwrap();
            if next_val != *pair {
                return false;
            }
        }

        true
    }
}

impl<T: SegReqFromBytes> SegmentRequestIter<'_, T> {
    fn next_at_offset(&self, mut offset: usize) -> Option<(T, T)> {
        if offset + std::mem::size_of::<T>() * 2 > self.seq_req_raw.len() {
            return None;
        }

        let start_offset =
            T::from_bytes(&self.seq_req_raw[offset..offset + std::mem::size_of::<T>()]);
        offset += std::mem::size_of::<T>();

        let end_offset =
            T::from_bytes(&self.seq_req_raw[offset..offset + std::mem::size_of::<T>()]);
        Some((start_offset, end_offset))
    }
}

/// NAK PDU abstraction specialized in the reading NAK PDUs from a raw bytestream.
///
/// This is a zero-copy class where the segment requests can be read using a special iterator
/// API without the need to copy them.
///
/// The NAK format is expected to be conforming to CFDP chapter 5.2.6.
#[derive(Debug, PartialEq, Eq)]
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
    pub fn new(buf: &'seg_reqs [u8]) -> Result<NakPduReader, PduError> {
        Self::from_bytes(buf)
    }

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
                u32::from_be_bytes(buf[current_idx..current_idx + 4].try_into().unwrap()) as u64;
            current_idx += 4;
            end_of_scope =
                u32::from_be_bytes(buf[current_idx..current_idx + 4].try_into().unwrap()) as u64;
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

    pub fn num_segment_reqs(&self) -> usize {
        if self.seg_reqs_raw.is_empty() {
            return 0;
        }
        if self.file_flag() == LargeFileFlag::Normal {
            self.seg_reqs_raw.len() / 8
        } else {
            self.seg_reqs_raw.len() / 16
        }
    }

    /// This function returns [None] if this NAK PDUs contains segment requests for a large file.
    pub fn get_normal_segment_requests_iterator(&self) -> Option<SegmentRequestIter<'_, u32>> {
        if self.file_flag() == LargeFileFlag::Large {
            return None;
        }
        Some(SegmentRequestIter {
            seq_req_raw: self.seg_reqs_raw,
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
            seq_req_raw: self.seg_reqs_raw,
            current_idx: 0,
            phantom: PhantomData,
        })
    }
}

impl<'a, 'b> PartialEq<NakPduCreator<'a>> for NakPduReader<'b> {
    fn eq(&self, other: &NakPduCreator<'a>) -> bool {
        if self.pdu_header() != other.pdu_header()
            || self.end_of_scope() != other.end_of_scope()
            || self.start_of_scope() != other.start_of_scope()
        {
            return false;
        }

        // Check if both segment requests are empty or None
        match (self.seg_reqs_raw.is_empty(), other.segment_requests()) {
            (true, None) => true,
            (true, Some(seg_reqs)) => seg_reqs.is_empty(),
            (false, None) => false,
            _ => {
                // Compare based on file_flag
                if self.file_flag() == LargeFileFlag::Normal {
                    let normal_iter = self.get_normal_segment_requests_iterator().unwrap();
                    normal_iter == *other.segment_requests().unwrap()
                } else {
                    let large_iter = self.get_large_segment_requests_iterator().unwrap();
                    large_iter == *other.segment_requests().unwrap()
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::cfdp::{
        pdu::tests::{common_pdu_conf, verify_raw_header, TEST_DEST_ID, TEST_SEQ_NUM, TEST_SRC_ID},
        PduType, TransmissionMode,
    };

    use super::*;

    fn check_generic_fields(nak_pdu: &impl CfdpPdu) {
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
    fn test_seg_request_api() {
        let seg_req = SegmentRequests::U32Pairs(&[]);
        assert!(seg_req.is_empty());
        let seg_req = SegmentRequests::U64Pairs(&[]);
        assert!(seg_req.is_empty());
    }

    #[test]
    fn test_basic_creator() {
        let pdu_conf = common_pdu_conf(CrcFlag::NoCrc, LargeFileFlag::Normal);
        let pdu_header = PduHeader::new_no_file_data(pdu_conf, 0);
        let nak_pdu = NakPduCreator::new_no_segment_requests(pdu_header, 0, 0)
            .expect("creating NAK PDU creator failed");
        assert_eq!(nak_pdu.start_of_scope(), 0);
        assert_eq!(nak_pdu.end_of_scope(), 0);
        assert_eq!(nak_pdu.segment_requests(), None);
        assert_eq!(nak_pdu.num_segment_reqs(), 0);
        check_generic_fields(&nak_pdu);
    }

    #[test]
    fn test_serialization_empty() {
        let pdu_conf = common_pdu_conf(CrcFlag::NoCrc, LargeFileFlag::Normal);
        let pdu_header = PduHeader::new_no_file_data(pdu_conf, 0);
        let nak_pdu = NakPduCreator::new_no_segment_requests(pdu_header, 100, 300)
            .expect("creating NAK PDU creator failed");
        assert_eq!(nak_pdu.start_of_scope(), 100);
        assert_eq!(nak_pdu.end_of_scope(), 300);
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
    fn test_serialization_two_segments() {
        let pdu_conf = common_pdu_conf(CrcFlag::NoCrc, LargeFileFlag::Normal);
        let pdu_header = PduHeader::new_no_file_data(pdu_conf, 0);
        let nak_pdu = NakPduCreator::new(pdu_header, 100, 300, &[(0, 0), (32, 64)])
            .expect("creating NAK PDU creator failed");
        let mut buf: [u8; 64] = [0; 64];
        nak_pdu
            .write_to_bytes(&mut buf)
            .expect("writing NAK PDU to buffer failed");
        verify_raw_header(nak_pdu.pdu_header(), &buf);
        let mut current_idx = nak_pdu.pdu_header().header_len();
        assert_eq!(current_idx + 9 + 16, nak_pdu.len_written());
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
        let first_seg_start =
            u32::from_be_bytes(buf[current_idx..current_idx + 4].try_into().unwrap());
        assert_eq!(first_seg_start, 0);
        current_idx += 4;
        let first_seg_end =
            u32::from_be_bytes(buf[current_idx..current_idx + 4].try_into().unwrap());
        assert_eq!(first_seg_end, 0);
        current_idx += 4;
        let second_seg_start =
            u32::from_be_bytes(buf[current_idx..current_idx + 4].try_into().unwrap());
        assert_eq!(second_seg_start, 32);
        current_idx += 4;
        let second_seg_end =
            u32::from_be_bytes(buf[current_idx..current_idx + 4].try_into().unwrap());
        assert_eq!(second_seg_end, 64);
        current_idx += 4;
        assert_eq!(current_idx, nak_pdu.len_written());
    }

    #[test]
    fn test_deserialization_empty() {
        let pdu_conf = common_pdu_conf(CrcFlag::NoCrc, LargeFileFlag::Normal);
        let pdu_header = PduHeader::new_no_file_data(pdu_conf, 0);
        let nak_pdu = NakPduCreator::new_no_segment_requests(pdu_header, 100, 300)
            .expect("creating NAK PDU creator failed");
        let mut buf: [u8; 64] = [0; 64];
        nak_pdu
            .write_to_bytes(&mut buf)
            .expect("writing NAK PDU to buffer failed");
        let nak_pdu_deser = NakPduReader::from_bytes(&buf).expect("deserializing NAK PDU failed");
        assert_eq!(nak_pdu_deser, nak_pdu);
        check_generic_fields(&nak_pdu_deser);
    }

    #[test]
    fn test_deserialization_large_segments() {
        let pdu_conf = common_pdu_conf(CrcFlag::NoCrc, LargeFileFlag::Large);
        let pdu_header = PduHeader::new_no_file_data(pdu_conf, 0);
        let nak_pdu =
            NakPduCreator::new_large_file_size(pdu_header, 100, 300, &[(50, 100), (200, 300)])
                .expect("creating NAK PDU creator failed");
        let mut buf: [u8; 128] = [0; 128];
        nak_pdu
            .write_to_bytes(&mut buf)
            .expect("writing NAK PDU to buffer failed");
        let nak_pdu_deser = NakPduReader::from_bytes(&buf).expect("deserializing NAK PDU failed");
        assert_eq!(nak_pdu_deser, nak_pdu);
        assert_eq!(nak_pdu_deser.start_of_scope(), 100);
        assert_eq!(nak_pdu_deser.end_of_scope(), 300);
        assert_eq!(nak_pdu_deser.num_segment_reqs(), 2);
        assert!(nak_pdu_deser
            .get_large_segment_requests_iterator()
            .is_some());
        assert!(nak_pdu_deser
            .get_normal_segment_requests_iterator()
            .is_none());
        assert_eq!(
            nak_pdu_deser
                .get_large_segment_requests_iterator()
                .unwrap()
                .count(),
            2
        );
        for (idx, large_segments) in nak_pdu_deser
            .get_large_segment_requests_iterator()
            .unwrap()
            .enumerate()
        {
            if idx == 0 {
                assert_eq!(large_segments.0, 50);
                assert_eq!(large_segments.1, 100);
            } else {
                assert_eq!(large_segments.0, 200);
                assert_eq!(large_segments.1, 300);
            }
        }
    }

    #[test]
    fn test_deserialization_normal_segments() {
        let pdu_conf = common_pdu_conf(CrcFlag::NoCrc, LargeFileFlag::Normal);
        let pdu_header = PduHeader::new_no_file_data(pdu_conf, 0);
        let nak_pdu = NakPduCreator::new(pdu_header, 100, 300, &[(50, 100), (200, 300)])
            .expect("creating NAK PDU creator failed");
        let mut buf: [u8; 128] = [0; 128];
        nak_pdu
            .write_to_bytes(&mut buf)
            .expect("writing NAK PDU to buffer failed");
        let nak_pdu_deser = NakPduReader::from_bytes(&buf).expect("deserializing NAK PDU failed");
        assert_eq!(nak_pdu_deser, nak_pdu);
        assert_eq!(nak_pdu_deser.start_of_scope(), 100);
        assert_eq!(nak_pdu_deser.end_of_scope(), 300);
        assert_eq!(nak_pdu_deser.num_segment_reqs(), 2);
        assert!(nak_pdu_deser
            .get_normal_segment_requests_iterator()
            .is_some());
        assert!(nak_pdu_deser
            .get_large_segment_requests_iterator()
            .is_none());
        assert_eq!(
            nak_pdu_deser
                .get_normal_segment_requests_iterator()
                .unwrap()
                .count(),
            2
        );
        for (idx, large_segments) in nak_pdu_deser
            .get_normal_segment_requests_iterator()
            .unwrap()
            .enumerate()
        {
            if idx == 0 {
                assert_eq!(large_segments.0, 50);
                assert_eq!(large_segments.1, 100);
            } else {
                assert_eq!(large_segments.0, 200);
                assert_eq!(large_segments.1, 300);
            }
        }
    }

    #[test]
    fn test_empty_is_empty() {
        let pdu_conf = common_pdu_conf(CrcFlag::NoCrc, LargeFileFlag::Normal);
        let pdu_header = PduHeader::new_no_file_data(pdu_conf, 0);
        let nak_pdu_0 =
            NakPduCreator::new(pdu_header, 100, 300, &[]).expect("creating NAK PDU creator failed");
        let nak_pdu_1 = NakPduCreator::new_no_segment_requests(pdu_header, 100, 300)
            .expect("creating NAK PDU creator failed");
        assert_eq!(nak_pdu_0, nak_pdu_1);
        // Assert the segment request is mapped to None.
        assert!(nak_pdu_0.segment_requests().is_none());
    }

    #[test]
    fn test_new_generic_invalid_input() {
        let pdu_conf = common_pdu_conf(CrcFlag::NoCrc, LargeFileFlag::Normal);
        let pdu_header = PduHeader::new_no_file_data(pdu_conf, 0);
        let u32_list = SegmentRequests::U32Pairs(&[(0, 50), (50, 100)]);
        if let Err(PduError::InvalidStartOrEndOfScopeValue) = NakPduCreator::new_generic(
            pdu_header,
            u32::MAX as u64 + 1,
            u32::MAX as u64 + 2,
            Some(u32_list),
        ) {
        } else {
            panic!("API call did not fail");
        }
    }

    #[test]
    fn test_target_buf_too_small() {
        let pdu_conf = common_pdu_conf(CrcFlag::NoCrc, LargeFileFlag::Normal);
        let pdu_header = PduHeader::new_no_file_data(pdu_conf, 0);
        let nak_pdu = NakPduCreator::new_no_segment_requests(pdu_header, 100, 300)
            .expect("creating NAK PDU creator failed");
        assert_eq!(nak_pdu.start_of_scope(), 100);
        assert_eq!(nak_pdu.end_of_scope(), 300);
        let mut buf: [u8; 5] = [0; 5];
        let error = nak_pdu.write_to_bytes(&mut buf);
        assert!(error.is_err());
        let e = error.unwrap_err();
        match e {
            PduError::ByteConversionError(conv_error) => match conv_error {
                ByteConversionError::ToSliceTooSmall { found, expected } => {
                    assert_eq!(expected, nak_pdu.len_written());
                    assert_eq!(found, 5);
                }
                _ => panic!("unexpected error {conv_error}"),
            },
            _ => panic!("unexpected error {e}"),
        }
    }

    #[test]
    fn test_with_crc() {
        let pdu_conf = common_pdu_conf(CrcFlag::WithCrc, LargeFileFlag::Normal);
        let pdu_header = PduHeader::new_no_file_data(pdu_conf, 0);
        let nak_pdu = NakPduCreator::new_no_segment_requests(pdu_header, 0, 0)
            .expect("creating NAK PDU creator failed");
        let mut nak_vec = nak_pdu.to_vec().expect("writing NAK to vector failed");
        assert_eq!(nak_vec.len(), pdu_header.header_len() + 9 + 2);
        assert_eq!(nak_vec.len(), nak_pdu.len_written());
        let nak_pdu_deser = NakPduReader::new(&nak_vec).expect("reading NAK PDU failed");
        assert_eq!(nak_pdu_deser, nak_pdu);
        nak_vec[nak_pdu.len_written() - 1] -= 1;
        let nak_pdu_deser = NakPduReader::new(&nak_vec);
        assert!(nak_pdu_deser.is_err());
        if let Err(PduError::ChecksumError(raw)) = nak_pdu_deser {
            assert_eq!(
                raw,
                u16::from_be_bytes(nak_vec[nak_pdu.len_written() - 2..].try_into().unwrap())
            );
        }
    }
}
