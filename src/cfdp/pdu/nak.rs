use crate::{
    cfdp::{CrcFlag, Direction, LargeFileFlag},
    ByteConversionError,
};

use super::{
    add_pdu_crc, generic_length_checks_pdu_deserialization, CfdpPdu, FileDirectiveType, PduError,
    PduHeader, WritablePduPacket,
};

#[derive(Debug, PartialEq, Eq, Copy, Clone, thiserror::Error)]
#[error("invalid start or end of scope value for NAK PDU")]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct InvalidStartOrEndOfScopeError((u64, u64));

fn calculate_pdu_datafield_len(pdu_header: &PduHeader, num_segment_reqs: usize) -> usize {
    let mut datafield_len = 1;
    if pdu_header.common_pdu_conf().file_flag == LargeFileFlag::Normal {
        datafield_len += 8;
        datafield_len += num_segment_reqs * 8;
    } else {
        datafield_len += 16;
        datafield_len += num_segment_reqs * 16;
    }
    if pdu_header.common_pdu_conf().crc_flag == CrcFlag::WithCrc {
        datafield_len += 2;
    }
    datafield_len
}

fn write_start_and_end_of_scope(
    buf: &mut [u8],
    file_flag: LargeFileFlag,
    mut current_index: usize,
    start_of_scope: u64,
    end_of_scope: u64,
) -> usize {
    if file_flag == LargeFileFlag::Normal {
        let start_of_scope = u32::try_from(start_of_scope).unwrap();
        let end_of_scope = u32::try_from(end_of_scope).unwrap();
        buf[current_index..current_index + 4].copy_from_slice(&start_of_scope.to_be_bytes());
        current_index += 4;
        buf[current_index..current_index + 4].copy_from_slice(&end_of_scope.to_be_bytes());
        current_index += 4;
    } else {
        buf[current_index..current_index + 8].copy_from_slice(&start_of_scope.to_be_bytes());
        current_index += 8;
        buf[current_index..current_index + 8].copy_from_slice(&end_of_scope.to_be_bytes());
        current_index += 8;
    }
    current_index
}

/// This function can be used to retrieve the maximum amount of segment request given a PDU
/// configuration to stay below a certain maximum packet size. This is useful to calculate how many
/// NAK PDUs are required inside a NAK sequence.
pub fn calculate_max_segment_requests(
    mut max_packet_size: usize,
    pdu_header: &PduHeader,
) -> Result<usize, usize> {
    let mut decrement = pdu_header.header_len() + 1;
    if pdu_header.common_pdu_conf().crc_flag == CrcFlag::WithCrc {
        decrement += 2;
    }
    if pdu_header.common_pdu_conf().file_flag == LargeFileFlag::Normal {
        decrement += 8;
    } else {
        decrement += 16;
    }
    if max_packet_size < decrement {
        return Err(max_packet_size);
    }
    max_packet_size -= decrement;
    Ok(
        if pdu_header.common_pdu_conf().file_flag == LargeFileFlag::Normal {
            max_packet_size / 8
        } else {
            max_packet_size / 16
        },
    )
}

/// Helper type to encapsulate both normal file size segment requests and large file size segment
/// requests.
#[derive(Debug, PartialEq, Eq, Clone)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum SegmentRequests<'a> {
    U32Pairs(&'a [(u32, u32)]),
    U64Pairs(&'a [(u64, u64)]),
}

impl SegmentRequests<'_> {
    #[inline]
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
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
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
    pub fn new_no_segment_requests(
        pdu_header: PduHeader,
        start_of_scope: u64,
        end_of_scope: u64,
    ) -> Result<NakPduCreator<'seg_reqs>, InvalidStartOrEndOfScopeError> {
        Self::new(pdu_header, start_of_scope, end_of_scope, None)
    }

    /// Default constructor for normal file sizes.
    pub fn new_normal_file_size(
        pdu_header: PduHeader,
        start_of_scope: u32,
        end_of_scope: u32,
        segment_requests: &'seg_reqs [(u32, u32)],
    ) -> Result<NakPduCreator<'seg_reqs>, InvalidStartOrEndOfScopeError> {
        let mut passed_segment_requests = None;
        if !segment_requests.is_empty() {
            passed_segment_requests = Some(SegmentRequests::U32Pairs(segment_requests));
        }
        Self::new(
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
    ) -> Result<NakPduCreator<'seg_reqs>, InvalidStartOrEndOfScopeError> {
        let mut passed_segment_requests = None;
        if !segment_requests.is_empty() {
            passed_segment_requests = Some(SegmentRequests::U64Pairs(segment_requests));
        }
        Self::new(
            pdu_header,
            start_of_scope,
            end_of_scope,
            passed_segment_requests,
        )
    }

    fn new(
        mut pdu_header: PduHeader,
        start_of_scope: u64,
        end_of_scope: u64,
        segment_requests: Option<SegmentRequests<'seg_reqs>>,
    ) -> Result<NakPduCreator<'seg_reqs>, InvalidStartOrEndOfScopeError> {
        // Force correct direction flag.
        pdu_header.pdu_conf.direction = Direction::TowardsSender;
        if let Some(ref segment_requests) = segment_requests {
            match segment_requests {
                SegmentRequests::U32Pairs(_) => {
                    if start_of_scope > u32::MAX as u64 || end_of_scope > u32::MAX as u64 {
                        return Err(InvalidStartOrEndOfScopeError((
                            start_of_scope,
                            end_of_scope,
                        )));
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

    #[inline]
    pub fn start_of_scope(&self) -> u64 {
        self.start_of_scope
    }

    #[inline]
    pub fn end_of_scope(&self) -> u64 {
        self.end_of_scope
    }

    #[inline]
    pub fn segment_requests(&self) -> Option<&SegmentRequests<'_>> {
        self.segment_requests.as_ref()
    }

    #[inline]
    pub fn num_segment_reqs(&self) -> usize {
        match &self.segment_requests {
            Some(seg_reqs) => match seg_reqs {
                SegmentRequests::U32Pairs(pairs) => pairs.len(),
                SegmentRequests::U64Pairs(pairs) => pairs.len(),
            },
            None => 0,
        }
    }

    #[inline]
    pub fn pdu_header(&self) -> &PduHeader {
        &self.pdu_header
    }

    fn calc_pdu_datafield_len(&self) -> usize {
        calculate_pdu_datafield_len(&self.pdu_header, self.num_segment_reqs())
    }

    /// Write [Self] to the provided buffer and returns the written size.
    pub fn write_to_bytes(&self, buf: &mut [u8]) -> Result<usize, PduError> {
        let expected_len = self.len_written();
        if buf.len() < expected_len {
            return Err(ByteConversionError::ToSliceTooSmall {
                found: buf.len(),
                expected: expected_len,
            }
            .into());
        }
        let mut current_index = self.pdu_header.write_to_bytes(buf)?;
        buf[current_index] = FileDirectiveType::NakPdu as u8;
        current_index += 1;

        current_index = write_start_and_end_of_scope(
            buf,
            self.file_flag(),
            current_index,
            self.start_of_scope,
            self.end_of_scope,
        );
        if let Some(ref seg_reqs) = self.segment_requests {
            match seg_reqs {
                SegmentRequests::U32Pairs(pairs) => {
                    // Unwrap is okay here, the API should prevent invalid values which would trigger a
                    // panic here.
                    for (next_start_offset, next_end_offset) in *pairs {
                        buf[current_index..current_index + 4]
                            .copy_from_slice(&next_start_offset.to_be_bytes());
                        current_index += 4;
                        buf[current_index..current_index + 4]
                            .copy_from_slice(&next_end_offset.to_be_bytes());
                        current_index += 4;
                    }
                }
                SegmentRequests::U64Pairs(pairs) => {
                    for (next_start_offset, next_end_offset) in *pairs {
                        buf[current_index..current_index + 8]
                            .copy_from_slice(&next_start_offset.to_be_bytes());
                        current_index += 8;
                        buf[current_index..current_index + 8]
                            .copy_from_slice(&next_end_offset.to_be_bytes());
                        current_index += 8;
                    }
                }
            }
        }

        if self.crc_flag() == CrcFlag::WithCrc {
            current_index = add_pdu_crc(buf, current_index);
        }
        Ok(current_index)
    }

    #[inline]
    fn len_written(&self) -> usize {
        self.pdu_header.header_len() + self.calc_pdu_datafield_len()
    }
}

impl CfdpPdu for NakPduCreator<'_> {
    #[inline]
    fn pdu_header(&self) -> &PduHeader {
        self.pdu_header()
    }

    #[inline]
    fn file_directive_type(&self) -> Option<FileDirectiveType> {
        Some(FileDirectiveType::NakPdu)
    }
}

impl WritablePduPacket for NakPduCreator<'_> {
    fn write_to_bytes(&self, buf: &mut [u8]) -> Result<usize, PduError> {
        self.write_to_bytes(buf)
    }

    fn len_written(&self) -> usize {
        self.len_written()
    }
}

/// This is a NAK PDU constructor which exposes the sequence list as a mutable slice.
///
/// This avoids the need of a separate slice for the lost segments. Instead, the lost segments
/// can be written into the mutable slice directly. The NAK creation has to be finalized using
/// the [Self::finish] call.
#[derive(Debug)]
pub struct NakPduCreatorWithReservedSeqReqsBuf<'buf> {
    pdu_header: PduHeader,
    num_segment_reqs: usize,
    param_field_offset: usize,
    buf: &'buf mut [u8],
}

impl<'buf> NakPduCreatorWithReservedSeqReqsBuf<'buf> {
    pub fn calculate_max_segment_requests(
        max_packet_size: usize,
        pdu_header: &PduHeader,
    ) -> Result<usize, usize> {
        calculate_max_segment_requests(max_packet_size, pdu_header)
    }

    pub fn new(
        buf: &'buf mut [u8],
        mut pdu_header: PduHeader,
        num_segment_reqs: usize,
    ) -> Result<Self, ByteConversionError> {
        pdu_header.pdu_datafield_len =
            calculate_pdu_datafield_len(&pdu_header, num_segment_reqs) as u16;
        let written_len = pdu_header.header_len() + pdu_header.pdu_datafield_len as usize;
        if buf.len() < written_len {
            return Err(ByteConversionError::ToSliceTooSmall {
                found: buf.len(),
                expected: written_len,
            });
        }
        // Force correct direction flag.
        pdu_header.pdu_conf.direction = Direction::TowardsSender;
        let param_field_offset = pdu_header.header_len() + 1;
        Ok(Self {
            pdu_header,
            num_segment_reqs,
            param_field_offset,
            buf,
        })
    }
}

impl NakPduCreatorWithReservedSeqReqsBuf<'_> {
    #[inline]
    pub fn pdu_header(&self) -> &PduHeader {
        &self.pdu_header
    }

    #[inline]
    pub fn num_segment_reqs(&self) -> usize {
        self.num_segment_reqs
    }

    /// This function allows writing the start and end of scope fields in the mutable
    /// buffer slice directly.
    pub fn set_start_and_end_of_scope(
        &mut self,
        start_of_scope: u64,
        end_of_scope: u64,
    ) -> Result<(), InvalidStartOrEndOfScopeError> {
        if self.pdu_header.common_pdu_conf().file_flag == LargeFileFlag::Normal
            && (start_of_scope > u32::MAX as u64 || end_of_scope > u32::MAX as u64)
        {
            return Err(InvalidStartOrEndOfScopeError((
                start_of_scope,
                end_of_scope,
            )));
        }
        write_start_and_end_of_scope(
            self.buf,
            self.pdu_header.common_pdu_conf().file_flag,
            self.pdu_header.header_len() + 1,
            start_of_scope,
            end_of_scope,
        );
        Ok(())
    }

    pub fn len_written(&self) -> usize {
        self.pdu_header.header_len() + self.calc_pdu_datafield_len()
    }

    /// Mutable accesss to the segment requests buffer.
    #[inline]
    pub fn segment_request_buffer_mut(&mut self) -> &mut [u8] {
        let len = self.segment_request_buffer_len();
        let segment_req_buf_offset = self.segment_request_offset();
        &mut self.buf[segment_req_buf_offset..segment_req_buf_offset + len]
    }

    /// Shared accesss to the segment requests buffer.
    #[inline]
    pub fn segment_request_buffer(&self) -> &[u8] {
        let len = self.segment_request_buffer_len();
        let segment_req_buf_offset = self.segment_request_offset();
        &self.buf[segment_req_buf_offset..segment_req_buf_offset + len]
    }

    #[inline]
    pub fn segment_request_iter(&self) -> SegmentRequestIter<'_> {
        SegmentRequestIter::new(
            self.segment_request_buffer(),
            self.pdu_header.common_pdu_conf().file_flag,
        )
    }

    /// Finalizes the NAK PDU creation.
    ///
    /// It writes all NAK PDU fields which were not written by the dedicated setter methods and
    /// adding the CRC-16 depending on the PDU header configuration.
    pub fn finish(self) -> usize {
        let mut current_idx = self.pdu_header.write_to_bytes(self.buf).unwrap();
        self.buf[current_idx] = FileDirectiveType::NakPdu as u8;
        current_idx += 1;

        if self.pdu_header.common_pdu_conf().file_flag == LargeFileFlag::Large {
            current_idx += 16 + self.num_segment_reqs * 16;
        } else {
            current_idx += 8 + self.num_segment_reqs * 8;
        }

        if self.pdu_header.common_pdu_conf().crc_flag == CrcFlag::WithCrc {
            current_idx = add_pdu_crc(self.buf, current_idx);
        }
        current_idx
    }

    fn calc_pdu_datafield_len(&self) -> usize {
        calculate_pdu_datafield_len(&self.pdu_header, self.num_segment_reqs)
    }

    #[inline]
    fn segment_request_buffer_len(&self) -> usize {
        self.num_segment_reqs
            * if self.pdu_header.common_pdu_conf().file_flag == LargeFileFlag::Normal {
                8
            } else {
                16
            }
    }

    fn segment_request_offset(&self) -> usize {
        self.param_field_offset
            + if self.pdu_header.common_pdu_conf().file_flag == LargeFileFlag::Normal {
                8
            } else {
                16
            }
    }
}

/// Special iterator type for the NAK PDU which allows to iterate over both normal and large file
/// segment requests.
#[derive(Debug)]
pub struct SegmentRequestIter<'a> {
    seq_req_raw: &'a [u8],
    large_file: LargeFileFlag,
    current_idx: usize,
}

impl<'a> SegmentRequestIter<'a> {
    fn new(seq_req_raw: &'a [u8], large_file: LargeFileFlag) -> SegmentRequestIter<'a> {
        SegmentRequestIter {
            seq_req_raw,
            large_file,
            current_idx: 0,
        }
    }
}

impl Iterator for SegmentRequestIter<'_> {
    type Item = (u64, u64);

    fn next(&mut self) -> Option<Self::Item> {
        let value = self.next_at_offset(self.current_idx);
        if value.is_none() {
            return value;
        }
        self.current_idx += 2 * self.increment();
        value
    }
}

impl SegmentRequestIter<'_> {
    const fn increment(&self) -> usize {
        match self.large_file {
            LargeFileFlag::Normal => core::mem::size_of::<u32>(),
            LargeFileFlag::Large => core::mem::size_of::<u64>(),
        }
    }

    fn next_at_offset(&self, mut offset: usize) -> Option<(u64, u64)> {
        let increment = self.increment();
        if offset + increment * 2 > self.seq_req_raw.len() {
            return None;
        }
        match self.large_file {
            LargeFileFlag::Normal => {
                let start_offset = u32::from_be_bytes(
                    self.seq_req_raw[offset..offset + increment]
                        .try_into()
                        .unwrap(),
                );
                offset += increment;
                let end_offset = u32::from_be_bytes(
                    self.seq_req_raw[offset..offset + increment]
                        .try_into()
                        .unwrap(),
                );
                Some((start_offset as u64, end_offset as u64))
            }
            LargeFileFlag::Large => {
                let start_offset = u64::from_be_bytes(
                    self.seq_req_raw[offset..offset + increment]
                        .try_into()
                        .unwrap(),
                );
                offset += increment;
                let end_offset = u64::from_be_bytes(
                    self.seq_req_raw[offset..offset + increment]
                        .try_into()
                        .unwrap(),
                );
                Some((start_offset, end_offset))
            }
        }
    }

    fn compare_pairs<T: Into<u64> + Copy>(&self, pairs: &[(T, T)]) -> bool {
        if pairs.is_empty() && self.seq_req_raw.is_empty() {
            return true;
        }
        if pairs.len() * 2 * self.increment() != self.seq_req_raw.len() {
            return false;
        }

        for (i, pair) in pairs.iter().enumerate() {
            let next_val = self.next_at_offset(i * 2 * self.increment()).unwrap();
            let pair = (pair.0.into(), pair.1.into());
            if next_val != pair {
                return false;
            }
        }

        true
    }
}

impl<'a> PartialEq<SegmentRequests<'a>> for SegmentRequestIter<'_> {
    fn eq(&self, other: &SegmentRequests<'a>) -> bool {
        match other {
            SegmentRequests::U32Pairs(pairs) => self.compare_pairs(pairs),
            SegmentRequests::U64Pairs(pairs) => self.compare_pairs(pairs),
        }
    }
}

/// NAK PDU abstraction specialized in the reading NAK PDUs from a raw bytestream.
///
/// This is a zero-copy class where the segment requests can be read using a special iterator
/// API without the need to copy them.
///
/// The NAK format is expected to be conforming to CFDP chapter 5.2.6.
#[derive(Debug, PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
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
    pub fn new(buf: &'seg_reqs [u8]) -> Result<NakPduReader<'seg_reqs>, PduError> {
        Self::from_bytes(buf)
    }

    pub fn from_bytes(buf: &'seg_reqs [u8]) -> Result<NakPduReader<'seg_reqs>, PduError> {
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
                return Err(PduError::ByteConversion(
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
            if current_idx + 8 > buf.len() {
                return Err(PduError::ByteConversion(
                    ByteConversionError::FromSliceTooSmall {
                        found: buf.len(),
                        expected: current_idx + 8,
                    },
                ));
            }
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
            self.seg_reqs_raw.len() / (2 * core::mem::size_of::<u32>())
        } else {
            self.seg_reqs_raw.len() / (2 * core::mem::size_of::<u64>())
        }
    }

    /// Get a generic segment request iterator.
    pub fn get_segment_requests_iterator(&self) -> Option<SegmentRequestIter<'_>> {
        if self.seg_reqs_raw.is_empty() {
            return None;
        }
        Some(SegmentRequestIter::new(self.seg_reqs_raw, self.file_flag()))
    }
}

impl<'a> PartialEq<NakPduCreator<'a>> for NakPduReader<'_> {
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
                let normal_iter = self.get_segment_requests_iterator().unwrap();
                normal_iter == *other.segment_requests().unwrap()
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use alloc::string::ToString;

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
        let pdu_header = PduHeader::new_for_file_directive(pdu_conf, 0);
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
        let pdu_header = PduHeader::new_for_file_directive(pdu_conf, 0);
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
        let pdu_header = PduHeader::new_for_file_directive(pdu_conf, 0);
        let nak_pdu =
            NakPduCreator::new_normal_file_size(pdu_header, 100, 300, &[(0, 0), (32, 64)])
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
        let pdu_header = PduHeader::new_for_file_directive(pdu_conf, 0);
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
        let pdu_header = PduHeader::new_for_file_directive(pdu_conf, 0);
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
        assert_eq!(
            nak_pdu_deser
                .get_segment_requests_iterator()
                .unwrap()
                .count(),
            2
        );
        let segment_iter = nak_pdu_deser.get_segment_requests_iterator();
        assert!(segment_iter.is_some());
        let segment_iter = segment_iter.unwrap();
        for (idx, segments) in segment_iter.enumerate() {
            if idx == 0 {
                assert_eq!(segments.0, 50);
                assert_eq!(segments.1, 100);
            } else {
                assert_eq!(segments.0, 200);
                assert_eq!(segments.1, 300);
            }
        }
    }

    #[test]
    fn test_deserialization_normal_segments() {
        let pdu_conf = common_pdu_conf(CrcFlag::NoCrc, LargeFileFlag::Normal);
        let pdu_header = PduHeader::new_for_file_directive(pdu_conf, 0);
        let nak_pdu =
            NakPduCreator::new_normal_file_size(pdu_header, 100, 300, &[(50, 100), (200, 300)])
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
        assert_eq!(
            nak_pdu_deser
                .get_segment_requests_iterator()
                .unwrap()
                .count(),
            2
        );
        let segment_iter = nak_pdu_deser.get_segment_requests_iterator();
        assert!(segment_iter.is_some());
        let segment_iter = segment_iter.unwrap();
        for (idx, segments) in segment_iter.enumerate() {
            if idx == 0 {
                assert_eq!(segments.0, 50);
                assert_eq!(segments.1, 100);
            } else {
                assert_eq!(segments.0, 200);
                assert_eq!(segments.1, 300);
            }
        }
    }

    #[test]
    fn test_empty_is_empty() {
        let pdu_conf = common_pdu_conf(CrcFlag::NoCrc, LargeFileFlag::Normal);
        let pdu_header = PduHeader::new_for_file_directive(pdu_conf, 0);
        let nak_pdu_0 = NakPduCreator::new_normal_file_size(pdu_header, 100, 300, &[])
            .expect("creating NAK PDU creator failed");
        let nak_pdu_1 = NakPduCreator::new_no_segment_requests(pdu_header, 100, 300)
            .expect("creating NAK PDU creator failed");
        assert_eq!(nak_pdu_0, nak_pdu_1);
        // Assert the segment request is mapped to None.
        assert!(nak_pdu_0.segment_requests().is_none());
    }

    #[test]
    fn test_new_generic_invalid_input() {
        let pdu_conf = common_pdu_conf(CrcFlag::NoCrc, LargeFileFlag::Normal);
        let pdu_header = PduHeader::new_for_file_directive(pdu_conf, 0);
        let u32_list = SegmentRequests::U32Pairs(&[(0, 50), (50, 100)]);
        //let error = NakPduCreator::new_generic(pdu_header, 100, 300, Some(u32_list));
        let error = NakPduCreator::new(
            pdu_header,
            u32::MAX as u64 + 1,
            u32::MAX as u64 + 2,
            Some(u32_list),
        );
        assert!(error.is_err());
        let error = error.unwrap_err();
        assert_eq!(
            error.to_string(),
            "invalid start or end of scope value for NAK PDU"
        );
    }

    #[test]
    fn test_target_buf_too_small() {
        let pdu_conf = common_pdu_conf(CrcFlag::NoCrc, LargeFileFlag::Normal);
        let pdu_header = PduHeader::new_for_file_directive(pdu_conf, 0);
        let nak_pdu = NakPduCreator::new_no_segment_requests(pdu_header, 100, 300)
            .expect("creating NAK PDU creator failed");
        assert_eq!(nak_pdu.start_of_scope(), 100);
        assert_eq!(nak_pdu.end_of_scope(), 300);
        let mut buf: [u8; 5] = [0; 5];
        let error = nak_pdu.write_to_bytes(&mut buf);
        assert!(error.is_err());
        let e = error.unwrap_err();
        match e {
            PduError::ByteConversion(conv_error) => match conv_error {
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
        let pdu_header = PduHeader::new_for_file_directive(pdu_conf, 0);
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
        if let Err(PduError::Checksum(raw)) = nak_pdu_deser {
            assert_eq!(
                raw,
                u16::from_be_bytes(nak_vec[nak_pdu.len_written() - 2..].try_into().unwrap())
            );
        }
    }

    #[test]
    fn test_with_reserved_lost_segment_buf_no_segments_normal_file_0() {
        let pdu_conf = common_pdu_conf(CrcFlag::NoCrc, LargeFileFlag::Normal);
        let mut buf: [u8; 64] = [0; 64];
        let pdu_header = PduHeader::new_for_file_directive(pdu_conf, 0);
        let mut nak_pdu =
            NakPduCreatorWithReservedSeqReqsBuf::new(&mut buf, pdu_header, 0).unwrap();
        assert_eq!(nak_pdu.len_written(), pdu_header.header_len() + 9);
        assert!(nak_pdu.segment_request_buffer().is_empty());
        assert!(nak_pdu.segment_request_buffer_mut().is_empty());
        assert_eq!(nak_pdu.segment_request_iter().count(), 0);
        let pdu_header = *nak_pdu.pdu_header();
        let len_written = nak_pdu.finish();
        verify_raw_header(&pdu_header, &buf);
        let mut current_idx = pdu_header.header_len();
        assert_eq!(current_idx + 9, len_written);
        assert_eq!(buf[current_idx], FileDirectiveType::NakPdu as u8);
        current_idx += 1;
        let start_of_scope =
            u32::from_be_bytes(buf[current_idx..current_idx + 4].try_into().unwrap());
        current_idx += 4;
        let end_of_scope =
            u32::from_be_bytes(buf[current_idx..current_idx + 4].try_into().unwrap());
        assert_eq!(start_of_scope, 0);
        assert_eq!(end_of_scope, 0);
    }

    #[test]
    fn test_with_reserved_lost_segment_buf_no_segments_normal_file_1() {
        let pdu_conf = common_pdu_conf(CrcFlag::WithCrc, LargeFileFlag::Normal);
        let mut buf: [u8; 64] = [0; 64];
        let pdu_header = PduHeader::new_for_file_directive(pdu_conf, 0);
        let mut nak_pdu =
            NakPduCreatorWithReservedSeqReqsBuf::new(&mut buf, pdu_header, 0).unwrap();
        assert!(nak_pdu.segment_request_buffer().is_empty());
        assert!(nak_pdu.segment_request_buffer_mut().is_empty());
        assert_eq!(nak_pdu.segment_request_iter().count(), 0);
        nak_pdu
            .set_start_and_end_of_scope(100, 200)
            .expect("setting start and end of scope failed");
        let pdu_header = *nak_pdu.pdu_header();
        let len_written = nak_pdu.finish();
        verify_raw_header(&pdu_header, &buf);
        let mut current_idx = pdu_header.header_len();
        assert_eq!(current_idx + 1 + 8 + 2, len_written);
        assert_eq!(buf[current_idx], FileDirectiveType::NakPdu as u8);
        current_idx += 1;
        let start_of_scope =
            u32::from_be_bytes(buf[current_idx..current_idx + 4].try_into().unwrap());
        current_idx += 4;
        let end_of_scope =
            u32::from_be_bytes(buf[current_idx..current_idx + 4].try_into().unwrap());
        assert_eq!(start_of_scope, 100);
        assert_eq!(end_of_scope, 200);
    }

    #[test]
    fn test_with_reserved_lost_segment_buf_no_segments_large_file_0() {
        let pdu_conf = common_pdu_conf(CrcFlag::NoCrc, LargeFileFlag::Large);
        let mut buf: [u8; 64] = [0; 64];
        let pdu_header = PduHeader::new_for_file_directive(pdu_conf, 0);
        let mut nak_pdu =
            NakPduCreatorWithReservedSeqReqsBuf::new(&mut buf, pdu_header, 0).unwrap();
        assert_eq!(nak_pdu.len_written(), pdu_header.header_len() + 1 + 16);
        assert!(nak_pdu.segment_request_buffer().is_empty());
        assert!(nak_pdu.segment_request_buffer_mut().is_empty());
        assert_eq!(nak_pdu.segment_request_iter().count(), 0);
        let pdu_header = *nak_pdu.pdu_header();
        let len_written = nak_pdu.finish();
        verify_raw_header(&pdu_header, &buf);
        let mut current_idx = pdu_header.header_len();
        assert_eq!(current_idx + 1 + 16, len_written);
        assert_eq!(buf[current_idx], FileDirectiveType::NakPdu as u8);
        current_idx += 1;
        let start_of_scope =
            u64::from_be_bytes(buf[current_idx..current_idx + 8].try_into().unwrap());
        current_idx += 8;
        let end_of_scope =
            u64::from_be_bytes(buf[current_idx..current_idx + 8].try_into().unwrap());
        assert_eq!(start_of_scope, 0);
        assert_eq!(end_of_scope, 0);
    }

    #[test]
    fn test_with_reserved_lost_segment_buf_invalid_scope() {
        let pdu_conf = common_pdu_conf(CrcFlag::NoCrc, LargeFileFlag::Normal);
        let mut buf: [u8; 64] = [0; 64];
        let pdu_header = PduHeader::new_for_file_directive(pdu_conf, 0);
        let mut nak_pdu =
            NakPduCreatorWithReservedSeqReqsBuf::new(&mut buf, pdu_header, 2).unwrap();
        assert_eq!(
            nak_pdu
                .set_start_and_end_of_scope(100, u32::MAX as u64 + 1)
                .unwrap_err(),
            InvalidStartOrEndOfScopeError((100, (u32::MAX as u64) + 1))
        );
    }

    #[test]
    fn test_with_reserved_lost_segment_buf_no_segments_large_file_1() {
        let pdu_conf = common_pdu_conf(CrcFlag::NoCrc, LargeFileFlag::Large);
        let mut buf: [u8; 64] = [0; 64];
        let pdu_header = PduHeader::new_for_file_directive(pdu_conf, 0);
        let mut nak_pdu =
            NakPduCreatorWithReservedSeqReqsBuf::new(&mut buf, pdu_header, 0).unwrap();
        assert!(nak_pdu.segment_request_buffer().is_empty());
        assert!(nak_pdu.segment_request_buffer_mut().is_empty());
        assert_eq!(nak_pdu.segment_request_iter().count(), 0);
        nak_pdu
            .set_start_and_end_of_scope(100, u32::MAX as u64 + 1)
            .expect("setting start and end of scope failed");
        assert_eq!(nak_pdu.len_written(), pdu_header.header_len() + 1 + 16);
        let pdu_header = *nak_pdu.pdu_header();
        let len_written = nak_pdu.finish();
        verify_raw_header(&pdu_header, &buf);
        let mut current_idx = pdu_header.header_len();
        assert_eq!(current_idx + 1 + 16, len_written);
        assert_eq!(buf[current_idx], FileDirectiveType::NakPdu as u8);
        current_idx += 1;
        let start_of_scope =
            u64::from_be_bytes(buf[current_idx..current_idx + 8].try_into().unwrap());
        current_idx += 8;
        let end_of_scope =
            u64::from_be_bytes(buf[current_idx..current_idx + 8].try_into().unwrap());
        assert_eq!(start_of_scope, 100);
        assert_eq!(end_of_scope, u32::MAX as u64 + 1);
    }

    #[test]
    fn test_with_reserved_lost_segments_buf_two_segments_normal_file() {
        let num_segments = 2;
        let pdu_conf = common_pdu_conf(CrcFlag::NoCrc, LargeFileFlag::Normal);
        let mut buf: [u8; 64] = [0; 64];
        let pdu_header = PduHeader::new_for_file_directive(pdu_conf, 0);
        let mut nak_pdu =
            NakPduCreatorWithReservedSeqReqsBuf::new(&mut buf, pdu_header, num_segments).unwrap();
        nak_pdu
            .set_start_and_end_of_scope(100, 200)
            .expect("setting start and end of scope failed");
        assert_eq!(nak_pdu.segment_request_buffer().len(), num_segments * 8);
        assert_eq!(nak_pdu.segment_request_buffer_mut().len(), num_segments * 8);
        let seg_req_buf_mut = nak_pdu.segment_request_buffer_mut();
        assert_eq!(seg_req_buf_mut.len(), num_segments * 8);
        // Slice is statically declared here, but the actual purpose is that we can iterate
        // over the slice and fill the mutable segment request slice during the iteration.
        let seg_reqs: [(u32, u32); 2] = [(0, 20), (20, 40)];
        for (i, seg_req) in seg_reqs.iter().enumerate() {
            let offset = i * 8;
            seg_req_buf_mut[offset..offset + 4].copy_from_slice(&seg_req.0.to_be_bytes());
            seg_req_buf_mut[offset + 4..offset + 8].copy_from_slice(&seg_req.1.to_be_bytes());
        }
        let pdu_header = *nak_pdu.pdu_header();
        for (seg1, seg2) in nak_pdu.segment_request_iter().zip(seg_reqs.iter()) {
            assert_eq!(seg1.0 as u32, seg2.0);
            assert_eq!(seg1.1 as u32, seg2.1);
        }
        let len_written = nak_pdu.finish();
        verify_raw_header(&pdu_header, &buf);
        let mut current_idx = pdu_header.header_len();
        assert_eq!(current_idx + 1 + 8 + num_segments * 8, len_written);
        assert_eq!(buf[current_idx], FileDirectiveType::NakPdu as u8);
        current_idx += 1;
        let start_of_scope =
            u32::from_be_bytes(buf[current_idx..current_idx + 4].try_into().unwrap());
        current_idx += 4;
        let end_of_scope =
            u32::from_be_bytes(buf[current_idx..current_idx + 4].try_into().unwrap());
        current_idx += 4;
        assert_eq!(start_of_scope, 100);
        assert_eq!(end_of_scope, 200);
        for seg_req in seg_reqs.iter() {
            let seg_start =
                u32::from_be_bytes(buf[current_idx..current_idx + 4].try_into().unwrap());
            current_idx += 4;
            let seg_end = u32::from_be_bytes(buf[current_idx..current_idx + 4].try_into().unwrap());
            current_idx += 4;
            assert_eq!(seg_start, seg_req.0);
            assert_eq!(seg_end, seg_req.1);
        }
    }

    #[test]
    fn test_with_reserved_lost_segments_buf_two_segments_large_file() {
        let num_segments = 2;
        let pdu_conf = common_pdu_conf(CrcFlag::NoCrc, LargeFileFlag::Large);
        let mut buf: [u8; 128] = [0; 128];
        let pdu_header = PduHeader::new_for_file_directive(pdu_conf, 0);
        let mut nak_pdu =
            NakPduCreatorWithReservedSeqReqsBuf::new(&mut buf, pdu_header, num_segments).unwrap();
        nak_pdu
            .set_start_and_end_of_scope(100, u32::MAX as u64 + 1)
            .expect("setting start and end of scope failed");
        assert_eq!(nak_pdu.segment_request_buffer().len(), num_segments * 16);
        assert_eq!(
            nak_pdu.segment_request_buffer_mut().len(),
            num_segments * 16
        );
        let seg_req_buf_mut = nak_pdu.segment_request_buffer_mut();
        assert_eq!(seg_req_buf_mut.len(), num_segments * 16);
        // Slice is statically declared here, but the actual purpose is that we can iterate
        // over the slice and fill the mutable segment request slice during the iteration.
        let seg_reqs: [(u64, u64); 2] = [(0, 20), (20, u32::MAX as u64 + 1)];
        for (i, seg_req) in seg_reqs.iter().enumerate() {
            let offset = i * 16;
            seg_req_buf_mut[offset..offset + 8].copy_from_slice(&seg_req.0.to_be_bytes());
            seg_req_buf_mut[offset + 8..offset + 16].copy_from_slice(&seg_req.1.to_be_bytes());
        }
        let pdu_header = *nak_pdu.pdu_header();
        for (seg1, seg2) in nak_pdu.segment_request_iter().zip(seg_reqs.iter()) {
            assert_eq!(seg1.0, seg2.0);
            assert_eq!(seg1.1, seg2.1);
        }
        let len_written = nak_pdu.finish();
        verify_raw_header(&pdu_header, &buf);
        let mut current_idx = pdu_header.header_len();
        assert_eq!(current_idx + 1 + 16 + num_segments * 16, len_written);
        assert_eq!(buf[current_idx], FileDirectiveType::NakPdu as u8);
        current_idx += 1;
        let start_of_scope =
            u64::from_be_bytes(buf[current_idx..current_idx + 8].try_into().unwrap());
        current_idx += 8;
        let end_of_scope =
            u64::from_be_bytes(buf[current_idx..current_idx + 8].try_into().unwrap());
        current_idx += 8;
        assert_eq!(start_of_scope, 100);
        assert_eq!(end_of_scope, u32::MAX as u64 + 1);
        for seg_req in seg_reqs.iter() {
            let seg_start =
                u64::from_be_bytes(buf[current_idx..current_idx + 8].try_into().unwrap());
            current_idx += 8;
            let seg_end = u64::from_be_bytes(buf[current_idx..current_idx + 8].try_into().unwrap());
            current_idx += 8;
            assert_eq!(seg_start, seg_req.0);
            assert_eq!(seg_end, seg_req.1);
        }
    }

    #[test]
    fn test_reserved_lost_segment_finish_buf_too_small() {
        let mut buf: [u8; 64] = [0; 64];
        let pdu_conf = common_pdu_conf(CrcFlag::NoCrc, LargeFileFlag::Normal);
        let pdu_header = PduHeader::new_for_file_directive(pdu_conf, 0);
        assert_eq!(
            NakPduCreatorWithReservedSeqReqsBuf::new(&mut buf[0..10], pdu_header, 0).unwrap_err(),
            ByteConversionError::ToSliceTooSmall {
                found: 10,
                expected: pdu_header.header_len() + 1 + 8
            }
        );
    }

    #[test]
    fn test_max_segment_req_calculator() {
        let pdu_conf = common_pdu_conf(CrcFlag::NoCrc, LargeFileFlag::Normal);
        let pdu_header = PduHeader::new_for_file_directive(pdu_conf, 0);

        // 7 byte header, 1 byte directive, 8 bytes start and end of segment, leaves 48 bytes for
        // 6 segment requests (8 bytes each)
        assert_eq!(6, calculate_max_segment_requests(64, &pdu_header).unwrap());
        assert_eq!(
            6,
            NakPduCreatorWithReservedSeqReqsBuf::calculate_max_segment_requests(64, &pdu_header)
                .unwrap()
        );

        assert_eq!(6, calculate_max_segment_requests(65, &pdu_header).unwrap());
        assert_eq!(
            6,
            NakPduCreatorWithReservedSeqReqsBuf::calculate_max_segment_requests(65, &pdu_header)
                .unwrap()
        );

        assert_eq!(5, calculate_max_segment_requests(63, &pdu_header).unwrap());
        assert_eq!(
            5,
            NakPduCreatorWithReservedSeqReqsBuf::calculate_max_segment_requests(63, &pdu_header)
                .unwrap()
        );

        assert_eq!(7, calculate_max_segment_requests(72, &pdu_header).unwrap());
        assert_eq!(
            7,
            NakPduCreatorWithReservedSeqReqsBuf::calculate_max_segment_requests(72, &pdu_header)
                .unwrap()
        );
    }

    #[test]
    fn test_max_segment_req_calculator_large_file() {
        let pdu_conf = common_pdu_conf(CrcFlag::NoCrc, LargeFileFlag::Large);
        let pdu_header = PduHeader::new_for_file_directive(pdu_conf, 0);

        // 7 byte header, 1 byte directive, 16 bytes start and end of segment, leaves 48 bytes for
        // 3 large segment requests (16 bytes each)
        assert_eq!(3, calculate_max_segment_requests(72, &pdu_header).unwrap());
        assert_eq!(
            3,
            NakPduCreatorWithReservedSeqReqsBuf::calculate_max_segment_requests(72, &pdu_header)
                .unwrap()
        );

        assert_eq!(3, calculate_max_segment_requests(73, &pdu_header).unwrap());
        assert_eq!(
            3,
            NakPduCreatorWithReservedSeqReqsBuf::calculate_max_segment_requests(73, &pdu_header)
                .unwrap()
        );

        assert_eq!(2, calculate_max_segment_requests(71, &pdu_header).unwrap());
        assert_eq!(
            2,
            NakPduCreatorWithReservedSeqReqsBuf::calculate_max_segment_requests(71, &pdu_header)
                .unwrap()
        );

        assert_eq!(4, calculate_max_segment_requests(88, &pdu_header).unwrap());
        assert_eq!(
            4,
            NakPduCreatorWithReservedSeqReqsBuf::calculate_max_segment_requests(88, &pdu_header)
                .unwrap()
        );
    }

    #[test]
    fn test_max_segment_req_calculator_large_file_with_crc() {
        let pdu_conf = common_pdu_conf(CrcFlag::WithCrc, LargeFileFlag::Large);
        let pdu_header = PduHeader::new_for_file_directive(pdu_conf, 0);

        // 7 byte header, 1 byte directive, 16 bytes start and end of segment, leaves 48 bytes for
        // 3 large segment requests (16 bytes each)
        assert_eq!(3, calculate_max_segment_requests(74, &pdu_header).unwrap());
        assert_eq!(
            3,
            NakPduCreatorWithReservedSeqReqsBuf::calculate_max_segment_requests(74, &pdu_header)
                .unwrap()
        );

        assert_eq!(3, calculate_max_segment_requests(75, &pdu_header).unwrap());
        assert_eq!(
            3,
            NakPduCreatorWithReservedSeqReqsBuf::calculate_max_segment_requests(75, &pdu_header)
                .unwrap()
        );

        assert_eq!(2, calculate_max_segment_requests(73, &pdu_header).unwrap());
        assert_eq!(
            2,
            NakPduCreatorWithReservedSeqReqsBuf::calculate_max_segment_requests(73, &pdu_header)
                .unwrap()
        );

        assert_eq!(4, calculate_max_segment_requests(90, &pdu_header).unwrap());
        assert_eq!(
            4,
            NakPduCreatorWithReservedSeqReqsBuf::calculate_max_segment_requests(90, &pdu_header)
                .unwrap()
        );
    }
}
