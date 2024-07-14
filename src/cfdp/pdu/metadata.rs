#[cfg(feature = "alloc")]
use super::tlv::TlvOwned;
use crate::cfdp::lv::Lv;
use crate::cfdp::pdu::{
    add_pdu_crc, generic_length_checks_pdu_deserialization, read_fss_field, write_fss_field,
    FileDirectiveType, PduError, PduHeader,
};
use crate::cfdp::tlv::{Tlv, WritableTlv};
use crate::cfdp::{ChecksumType, CrcFlag, Direction, LargeFileFlag, PduType};
use crate::ByteConversionError;
#[cfg(feature = "alloc")]
use alloc::vec::Vec;
#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

use super::tlv::ReadableTlv;
use super::{CfdpPdu, WritablePduPacket};

#[derive(Default, Debug, Copy, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct MetadataGenericParams {
    pub closure_requested: bool,
    pub checksum_type: ChecksumType,
    pub file_size: u64,
}

impl MetadataGenericParams {
    pub fn new(closure_requested: bool, checksum_type: ChecksumType, file_size: u64) -> Self {
        Self {
            closure_requested,
            checksum_type,
            file_size,
        }
    }
}

pub fn build_metadata_opts_from_slice(
    buf: &mut [u8],
    tlvs: &[Tlv],
) -> Result<usize, ByteConversionError> {
    let mut written = 0;
    for tlv in tlvs {
        written += tlv.write_to_bytes(&mut buf[written..])?;
    }
    Ok(written)
}

#[cfg(feature = "alloc")]
pub fn build_metadata_opts_from_vec(
    buf: &mut [u8],
    tlvs: &Vec<Tlv>,
) -> Result<usize, ByteConversionError> {
    build_metadata_opts_from_slice(buf, tlvs.as_slice())
}

#[cfg(feature = "alloc")]
pub fn build_metadata_opts_from_owned_slice(tlvs: &[TlvOwned]) -> Vec<u8> {
    let mut sum_vec = Vec::new();
    for tlv in tlvs {
        sum_vec.extend(tlv.to_vec());
    }
    sum_vec
}

/// Metadata PDU creator abstraction.
///
/// This abstraction exposes a specialized API for creating metadata PDUs as specified in
/// CFDP chapter 5.2.5.
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub struct MetadataPduCreator<'src_name, 'dest_name, 'opts> {
    pdu_header: PduHeader,
    metadata_params: MetadataGenericParams,
    src_file_name: Lv<'src_name>,
    dest_file_name: Lv<'dest_name>,
    options: &'opts [u8],
}

impl<'src_name, 'dest_name, 'opts> MetadataPduCreator<'src_name, 'dest_name, 'opts> {
    pub fn new_no_opts(
        pdu_header: PduHeader,
        metadata_params: MetadataGenericParams,
        src_file_name: Lv<'src_name>,
        dest_file_name: Lv<'dest_name>,
    ) -> Self {
        Self::new(
            pdu_header,
            metadata_params,
            src_file_name,
            dest_file_name,
            &[],
        )
    }

    pub fn new_with_opts(
        pdu_header: PduHeader,
        metadata_params: MetadataGenericParams,
        src_file_name: Lv<'src_name>,
        dest_file_name: Lv<'dest_name>,
        options: &'opts [u8],
    ) -> Self {
        Self::new(
            pdu_header,
            metadata_params,
            src_file_name,
            dest_file_name,
            options,
        )
    }

    pub fn new(
        mut pdu_header: PduHeader,
        metadata_params: MetadataGenericParams,
        src_file_name: Lv<'src_name>,
        dest_file_name: Lv<'dest_name>,
        options: &'opts [u8],
    ) -> Self {
        pdu_header.pdu_type = PduType::FileDirective;
        pdu_header.pdu_conf.direction = Direction::TowardsReceiver;
        let mut pdu = Self {
            pdu_header,
            metadata_params,
            src_file_name,
            dest_file_name,
            options,
        };
        pdu.pdu_header.pdu_datafield_len = pdu.calc_pdu_datafield_len() as u16;
        pdu
    }

    pub fn metadata_params(&self) -> &MetadataGenericParams {
        &self.metadata_params
    }

    pub fn src_file_name(&self) -> Lv<'src_name> {
        self.src_file_name
    }

    pub fn dest_file_name(&self) -> Lv<'dest_name> {
        self.dest_file_name
    }

    pub fn options(&self) -> &'opts [u8] {
        self.options
    }

    /// Yield an iterator which can be used to loop through all options. Returns [None] if the
    /// options field is empty.
    pub fn options_iter(&self) -> OptionsIter<'_> {
        OptionsIter {
            opt_buf: self.options,
            current_idx: 0,
        }
    }

    fn calc_pdu_datafield_len(&self) -> usize {
        // One directve type octet and one byte of the directive parameter field.
        let mut len = 2;
        if self.pdu_header.common_pdu_conf().file_flag == LargeFileFlag::Large {
            len += 8;
        } else {
            len += 4;
        }
        len += self.src_file_name.len_full();
        len += self.dest_file_name.len_full();
        len += self.options().len();
        if self.crc_flag() == CrcFlag::WithCrc {
            len += 2;
        }
        len
    }
}

impl CfdpPdu for MetadataPduCreator<'_, '_, '_> {
    fn pdu_header(&self) -> &PduHeader {
        &self.pdu_header
    }

    fn file_directive_type(&self) -> Option<FileDirectiveType> {
        Some(FileDirectiveType::MetadataPdu)
    }
}

impl WritablePduPacket for MetadataPduCreator<'_, '_, '_> {
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
        buf[current_idx] = FileDirectiveType::MetadataPdu as u8;
        current_idx += 1;
        buf[current_idx] = ((self.metadata_params.closure_requested as u8) << 6)
            | (self.metadata_params.checksum_type as u8);
        current_idx += 1;
        current_idx += write_fss_field(
            self.pdu_header.common_pdu_conf().file_flag,
            self.metadata_params.file_size,
            &mut buf[current_idx..],
        )?;
        current_idx += self
            .src_file_name
            .write_to_be_bytes(&mut buf[current_idx..])?;
        current_idx += self
            .dest_file_name
            .write_to_be_bytes(&mut buf[current_idx..])?;
        buf[current_idx..current_idx + self.options.len()].copy_from_slice(self.options);
        current_idx += self.options.len();
        if self.crc_flag() == CrcFlag::WithCrc {
            current_idx = add_pdu_crc(buf, current_idx);
        }
        Ok(current_idx)
    }

    fn len_written(&self) -> usize {
        self.pdu_header.header_len() + self.calc_pdu_datafield_len()
    }
}

/// Helper structure to loop through all options of a metadata PDU. It should be noted that
/// iterators in Rust are not fallible, but the TLV creation can fail, for example if the raw TLV
/// data is invalid for some reason. In that case, the iterator will yield [None] because there
/// is no way to recover from this.
///
/// The user can accumulate the length of all TLVs yielded by the iterator and compare it against
/// the full length of the options to check whether the iterator was able to parse all TLVs
/// successfully.
pub struct OptionsIter<'opts> {
    opt_buf: &'opts [u8],
    current_idx: usize,
}

impl<'opts> Iterator for OptionsIter<'opts> {
    type Item = Tlv<'opts>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.current_idx == self.opt_buf.len() {
            return None;
        }
        let tlv = Tlv::from_bytes(&self.opt_buf[self.current_idx..]);
        // There are not really fallible iterators so we can't continue here..
        if tlv.is_err() {
            return None;
        }
        let tlv = tlv.unwrap();
        self.current_idx += tlv.len_full();
        Some(tlv)
    }
}

/// Metadata PDU reader abstraction.
///
/// This abstraction exposes a specialized API for reading a metadata PDU with minimal copying
/// involved.
#[derive(Debug)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct MetadataPduReader<'buf> {
    pdu_header: PduHeader,
    metadata_params: MetadataGenericParams,
    #[cfg_attr(feature = "serde", serde(borrow))]
    src_file_name: Lv<'buf>,
    #[cfg_attr(feature = "serde", serde(borrow))]
    dest_file_name: Lv<'buf>,
    options: &'buf [u8],
}

impl<'raw> MetadataPduReader<'raw> {
    pub fn new(buf: &'raw [u8]) -> Result<Self, PduError> {
        Self::from_bytes(buf)
    }

    pub fn from_bytes(buf: &'raw [u8]) -> Result<Self, PduError> {
        let (pdu_header, mut current_idx) = PduHeader::from_bytes(buf)?;
        let full_len_without_crc = pdu_header.verify_length_and_checksum(buf)?;
        let is_large_file = pdu_header.pdu_conf.file_flag == LargeFileFlag::Large;
        // Minimal length: 1 byte + FSS (4 byte) + 2 empty LV (1 byte)
        let mut min_expected_len = current_idx + 7;
        if is_large_file {
            min_expected_len += 4;
        }
        generic_length_checks_pdu_deserialization(buf, min_expected_len, full_len_without_crc)?;
        let directive_type = FileDirectiveType::try_from(buf[current_idx]).map_err(|_| {
            PduError::InvalidDirectiveType {
                found: buf[current_idx],
                expected: Some(FileDirectiveType::MetadataPdu),
            }
        })?;
        if directive_type != FileDirectiveType::MetadataPdu {
            return Err(PduError::WrongDirectiveType {
                found: directive_type,
                expected: FileDirectiveType::MetadataPdu,
            });
        }
        current_idx += 1;
        let (fss_len, file_size) =
            read_fss_field(pdu_header.pdu_conf.file_flag, &buf[current_idx + 1..]);
        let metadata_params = MetadataGenericParams {
            closure_requested: ((buf[current_idx] >> 6) & 0b1) != 0,
            checksum_type: ChecksumType::try_from(buf[current_idx] & 0b1111)
                .map_err(|_| PduError::InvalidChecksumType(buf[current_idx] & 0b1111))?,
            file_size,
        };
        current_idx += 1 + fss_len;
        let src_file_name = Lv::from_bytes(&buf[current_idx..])?;
        current_idx += src_file_name.len_full();
        let dest_file_name = Lv::from_bytes(&buf[current_idx..])?;
        current_idx += dest_file_name.len_full();
        // All left-over bytes are options.
        Ok(Self {
            pdu_header,
            metadata_params,
            src_file_name,
            dest_file_name,
            options: &buf[current_idx..full_len_without_crc],
        })
    }

    /// Yield an iterator which can be used to loop through all options. Returns [None] if the
    /// options field is empty.
    pub fn options_iter(&self) -> Option<OptionsIter<'_>> {
        Some(OptionsIter {
            opt_buf: self.options,
            current_idx: 0,
        })
    }

    pub fn options(&self) -> &'raw [u8] {
        self.options
    }

    pub fn metadata_params(&self) -> &MetadataGenericParams {
        &self.metadata_params
    }

    pub fn src_file_name(&self) -> Lv {
        self.src_file_name
    }

    pub fn dest_file_name(&self) -> Lv {
        self.dest_file_name
    }
}

impl CfdpPdu for MetadataPduReader<'_> {
    fn pdu_header(&self) -> &PduHeader {
        &self.pdu_header
    }

    fn file_directive_type(&self) -> Option<FileDirectiveType> {
        Some(FileDirectiveType::MetadataPdu)
    }
}

#[cfg(test)]
pub mod tests {
    use alloc::string::ToString;

    use crate::cfdp::lv::Lv;
    use crate::cfdp::pdu::metadata::{
        build_metadata_opts_from_slice, build_metadata_opts_from_vec, MetadataGenericParams,
        MetadataPduCreator, MetadataPduReader,
    };
    use crate::cfdp::pdu::tests::{
        common_pdu_conf, verify_raw_header, TEST_DEST_ID, TEST_SEQ_NUM, TEST_SRC_ID,
    };
    use crate::cfdp::pdu::{CfdpPdu, PduError, WritablePduPacket};
    use crate::cfdp::pdu::{FileDirectiveType, PduHeader};
    use crate::cfdp::tlv::{ReadableTlv, Tlv, TlvOwned, TlvType, WritableTlv};
    use crate::cfdp::{
        ChecksumType, CrcFlag, Direction, LargeFileFlag, PduType, SegmentMetadataFlag,
        SegmentationControl, TransmissionMode,
    };
    use std::vec;

    const SRC_FILENAME: &str = "hello-world.txt";
    const DEST_FILENAME: &str = "hello-world2.txt";

    fn generic_metadata_pdu(
        crc_flag: CrcFlag,
        checksum_type: ChecksumType,
        closure_requested: bool,
        fss: LargeFileFlag,
        opts: &[u8],
    ) -> (
        Lv<'static>,
        Lv<'static>,
        MetadataPduCreator<'static, 'static, '_>,
    ) {
        let pdu_header = PduHeader::new_no_file_data(common_pdu_conf(crc_flag, fss), 0);
        let metadata_params = MetadataGenericParams::new(closure_requested, checksum_type, 0x1010);
        let src_filename = Lv::new_from_str(SRC_FILENAME).expect("Generating string LV failed");
        let dest_filename =
            Lv::new_from_str(DEST_FILENAME).expect("Generating destination LV failed");
        (
            src_filename,
            dest_filename,
            MetadataPduCreator::new(
                pdu_header,
                metadata_params,
                src_filename,
                dest_filename,
                opts,
            ),
        )
    }

    #[test]
    fn test_basic() {
        let (src_filename, dest_filename, metadata_pdu) = generic_metadata_pdu(
            CrcFlag::NoCrc,
            ChecksumType::Crc32,
            false,
            LargeFileFlag::Normal,
            &[],
        );
        assert_eq!(
            metadata_pdu.len_written(),
            metadata_pdu.pdu_header().header_len()
                + 1
                + 1
                + 4
                + src_filename.len_full()
                + dest_filename.len_full()
        );
        assert_eq!(metadata_pdu.src_file_name(), src_filename);
        assert_eq!(metadata_pdu.dest_file_name(), dest_filename);
        assert!(metadata_pdu.options().is_empty());
        assert_eq!(metadata_pdu.crc_flag(), CrcFlag::NoCrc);
        assert_eq!(metadata_pdu.file_flag(), LargeFileFlag::Normal);
        assert_eq!(metadata_pdu.pdu_type(), PduType::FileDirective);
        assert!(!metadata_pdu.metadata_params().closure_requested);
        assert_eq!(
            metadata_pdu.metadata_params().checksum_type,
            ChecksumType::Crc32
        );
        assert_eq!(
            metadata_pdu.file_directive_type(),
            Some(FileDirectiveType::MetadataPdu)
        );
        assert_eq!(
            metadata_pdu.transmission_mode(),
            TransmissionMode::Acknowledged
        );
        assert_eq!(metadata_pdu.direction(), Direction::TowardsReceiver);
        assert_eq!(metadata_pdu.source_id(), TEST_SRC_ID.into());
        assert_eq!(metadata_pdu.dest_id(), TEST_DEST_ID.into());
        assert_eq!(metadata_pdu.transaction_seq_num(), TEST_SEQ_NUM.into());
    }

    fn check_metadata_raw_fields(
        metadata_pdu: &MetadataPduCreator,
        buf: &[u8],
        written_bytes: usize,
        checksum_type: ChecksumType,
        closure_requested: bool,
        expected_src_filename: &Lv,
        expected_dest_filename: &Lv,
    ) {
        verify_raw_header(metadata_pdu.pdu_header(), buf);
        assert_eq!(
            written_bytes,
            metadata_pdu.pdu_header.header_len()
                + 1
                + 1
                + 4
                + expected_src_filename.len_full()
                + expected_dest_filename.len_full()
        );
        assert_eq!(buf[7], FileDirectiveType::MetadataPdu as u8);
        assert_eq!(buf[8] >> 6, closure_requested as u8);
        assert_eq!(buf[8] & 0b1111, checksum_type as u8);
        assert_eq!(u32::from_be_bytes(buf[9..13].try_into().unwrap()), 0x1010);
        let mut current_idx = 13;
        let src_name_from_raw =
            Lv::from_bytes(&buf[current_idx..]).expect("Creating source name LV failed");
        assert_eq!(src_name_from_raw, *expected_src_filename);
        current_idx += src_name_from_raw.len_full();
        let dest_name_from_raw =
            Lv::from_bytes(&buf[current_idx..]).expect("Creating dest name LV failed");
        assert_eq!(dest_name_from_raw, *expected_dest_filename);
        current_idx += dest_name_from_raw.len_full();
        // No options, so no additional data here.
        assert_eq!(current_idx, written_bytes);
    }

    #[test]
    fn test_serialization_0() {
        let checksum_type = ChecksumType::Crc32;
        let closure_requested = false;
        let (src_filename, dest_filename, metadata_pdu) = generic_metadata_pdu(
            CrcFlag::NoCrc,
            checksum_type,
            closure_requested,
            LargeFileFlag::Normal,
            &[],
        );
        let mut buf: [u8; 64] = [0; 64];
        let res = metadata_pdu.write_to_bytes(&mut buf);
        assert!(res.is_ok());
        let written = res.unwrap();
        check_metadata_raw_fields(
            &metadata_pdu,
            &buf,
            written,
            checksum_type,
            closure_requested,
            &src_filename,
            &dest_filename,
        );
    }

    #[test]
    fn test_serialization_1() {
        let checksum_type = ChecksumType::Modular;
        let closure_requested = true;
        let (src_filename, dest_filename, metadata_pdu) = generic_metadata_pdu(
            CrcFlag::NoCrc,
            checksum_type,
            closure_requested,
            LargeFileFlag::Normal,
            &[],
        );
        let mut buf: [u8; 64] = [0; 64];
        let res = metadata_pdu.write_to_bytes(&mut buf);
        assert!(res.is_ok());
        let written = res.unwrap();
        check_metadata_raw_fields(
            &metadata_pdu,
            &buf,
            written,
            checksum_type,
            closure_requested,
            &src_filename,
            &dest_filename,
        );
    }

    #[test]
    fn test_write_to_vec() {
        let (_, _, metadata_pdu) = generic_metadata_pdu(
            CrcFlag::NoCrc,
            ChecksumType::Crc32,
            false,
            LargeFileFlag::Normal,
            &[],
        );
        let mut buf: [u8; 64] = [0; 64];
        let pdu_vec = metadata_pdu.to_vec().unwrap();
        let written = metadata_pdu.write_to_bytes(&mut buf).unwrap();
        assert_eq!(buf[0..written], pdu_vec);
    }

    fn compare_read_pdu_to_written_pdu(written: &MetadataPduCreator, read: &MetadataPduReader) {
        assert_eq!(written.metadata_params(), read.metadata_params());
        assert_eq!(written.src_file_name(), read.src_file_name());
        assert_eq!(written.dest_file_name(), read.dest_file_name());
        let opts = written.options_iter();
        for (tlv_written, tlv_read) in opts.zip(read.options_iter().unwrap()) {
            assert_eq!(&tlv_written, &tlv_read);
        }
    }

    #[test]
    fn test_deserialization() {
        let (_, _, metadata_pdu) = generic_metadata_pdu(
            CrcFlag::NoCrc,
            ChecksumType::Crc32,
            true,
            LargeFileFlag::Normal,
            &[],
        );
        let mut buf: [u8; 64] = [0; 64];
        metadata_pdu.write_to_bytes(&mut buf).unwrap();
        let pdu_read_back = MetadataPduReader::from_bytes(&buf);
        assert!(pdu_read_back.is_ok());
        let pdu_read_back = pdu_read_back.unwrap();
        compare_read_pdu_to_written_pdu(&metadata_pdu, &pdu_read_back);
    }

    #[test]
    fn test_with_crc_flag() {
        let (src_filename, dest_filename, metadata_pdu) = generic_metadata_pdu(
            CrcFlag::WithCrc,
            ChecksumType::Crc32,
            true,
            LargeFileFlag::Normal,
            &[],
        );
        assert_eq!(metadata_pdu.crc_flag(), CrcFlag::WithCrc);
        let mut buf: [u8; 64] = [0; 64];
        let write_res = metadata_pdu.write_to_bytes(&mut buf);
        assert!(write_res.is_ok());
        let written = write_res.unwrap();
        assert_eq!(
            written,
            metadata_pdu.pdu_header().header_len()
                + 1
                + 1
                + core::mem::size_of::<u32>()
                + src_filename.len_full()
                + dest_filename.len_full()
                + 2
        );
        assert_eq!(written, metadata_pdu.len_written());
        let pdu_read_back = MetadataPduReader::new(&buf).unwrap();
        compare_read_pdu_to_written_pdu(&metadata_pdu, &pdu_read_back);
    }

    #[test]
    fn test_with_large_file_flag() {
        let (src_filename, dest_filename, metadata_pdu) = generic_metadata_pdu(
            CrcFlag::NoCrc,
            ChecksumType::Crc32,
            false,
            LargeFileFlag::Large,
            &[],
        );
        let mut buf: [u8; 64] = [0; 64];
        let write_res = metadata_pdu.write_to_bytes(&mut buf);
        assert!(write_res.is_ok());
        let written = write_res.unwrap();
        assert_eq!(
            written,
            metadata_pdu.pdu_header().header_len()
                + 1
                + 1
                + core::mem::size_of::<u64>()
                + src_filename.len_full()
                + dest_filename.len_full()
        );
        let pdu_read_back = MetadataPduReader::new(&buf).unwrap();
        compare_read_pdu_to_written_pdu(&metadata_pdu, &pdu_read_back);
    }

    #[test]
    fn test_opts_builders() {
        let tlv1 = Tlv::new_empty(TlvType::FlowLabel);
        let msg_to_user: [u8; 4] = [1, 2, 3, 4];
        let tlv2 = Tlv::new(TlvType::MsgToUser, &msg_to_user).unwrap();
        let tlv_slice = [tlv1, tlv2];
        let mut buf: [u8; 32] = [0; 32];
        let opts = build_metadata_opts_from_slice(&mut buf, &tlv_slice);
        assert!(opts.is_ok());
        let opts_len = opts.unwrap();
        assert_eq!(opts_len, tlv1.len_full() + tlv2.len_full());
        let tlv1_conv_back = Tlv::from_bytes(&buf).unwrap();
        assert_eq!(tlv1_conv_back, tlv1);
        let tlv2_conv_back = Tlv::from_bytes(&buf[tlv1_conv_back.len_full()..]).unwrap();
        assert_eq!(tlv2_conv_back, tlv2);
    }

    #[test]
    fn test_opts_builders_from_vec() {
        let tlv1 = Tlv::new_empty(TlvType::FlowLabel);
        let msg_to_user: [u8; 4] = [1, 2, 3, 4];
        let tlv2 = Tlv::new(TlvType::MsgToUser, &msg_to_user).unwrap();
        let tlv_vec = vec![tlv1, tlv2];
        let mut buf: [u8; 32] = [0; 32];
        let opts = build_metadata_opts_from_vec(&mut buf, &tlv_vec);
        assert!(opts.is_ok());
        let opts_len = opts.unwrap();
        assert_eq!(opts_len, tlv1.len_full() + tlv2.len_full());
        let tlv1_conv_back = Tlv::from_bytes(&buf).unwrap();
        assert_eq!(tlv1_conv_back, tlv1);
        let tlv2_conv_back = Tlv::from_bytes(&buf[tlv1_conv_back.len_full()..]).unwrap();
        assert_eq!(tlv2_conv_back, tlv2);
    }

    #[test]
    fn test_with_opts() {
        let tlv1 = Tlv::new_empty(TlvType::FlowLabel);
        let msg_to_user: [u8; 4] = [1, 2, 3, 4];
        let tlv2 = Tlv::new(TlvType::MsgToUser, &msg_to_user).unwrap();
        let mut tlv_buf: [u8; 64] = [0; 64];
        let opts_len = build_metadata_opts_from_slice(&mut tlv_buf, &[tlv1, tlv2]).unwrap();
        let (src_filename, dest_filename, metadata_pdu) = generic_metadata_pdu(
            CrcFlag::NoCrc,
            ChecksumType::Crc32,
            false,
            LargeFileFlag::Normal,
            &tlv_buf[0..opts_len],
        );
        let mut buf: [u8; 128] = [0; 128];
        let write_res = metadata_pdu.write_to_bytes(&mut buf);
        assert!(write_res.is_ok());
        let written = write_res.unwrap();
        assert_eq!(
            written,
            metadata_pdu.pdu_header.header_len()
                + 1
                + 1
                + 4
                + src_filename.len_full()
                + dest_filename.len_full()
                + opts_len
        );
        let pdu_read_back = MetadataPduReader::from_bytes(&buf).unwrap();
        compare_read_pdu_to_written_pdu(&metadata_pdu, &pdu_read_back);
        let opts_iter = pdu_read_back.options_iter();
        assert!(opts_iter.is_some());
        let opts_iter = opts_iter.unwrap();
        let mut accumulated_len = 0;
        for (idx, opt) in opts_iter.enumerate() {
            if idx == 0 {
                assert_eq!(tlv1, opt);
            } else if idx == 1 {
                assert_eq!(tlv2, opt);
            }
            accumulated_len += opt.len_full();
        }
        assert_eq!(accumulated_len, pdu_read_back.options().len());
    }
    #[test]
    fn test_with_owned_opts() {
        let tlv1 = TlvOwned::new_empty(TlvType::FlowLabel);
        let msg_to_user: [u8; 4] = [1, 2, 3, 4];
        let tlv2 = TlvOwned::new(TlvType::MsgToUser, &msg_to_user).unwrap();
        let mut all_tlvs = tlv1.to_vec();
        all_tlvs.extend(tlv2.to_vec());
        let (src_filename, dest_filename, metadata_pdu) = generic_metadata_pdu(
            CrcFlag::NoCrc,
            ChecksumType::Crc32,
            false,
            LargeFileFlag::Normal,
            &all_tlvs,
        );
        let mut buf: [u8; 128] = [0; 128];
        let write_res = metadata_pdu.write_to_bytes(&mut buf);
        assert!(write_res.is_ok());
        let written = write_res.unwrap();
        assert_eq!(
            written,
            metadata_pdu.pdu_header.header_len()
                + 1
                + 1
                + 4
                + src_filename.len_full()
                + dest_filename.len_full()
                + all_tlvs.len()
        );
        let pdu_read_back = MetadataPduReader::from_bytes(&buf).unwrap();
        compare_read_pdu_to_written_pdu(&metadata_pdu, &pdu_read_back);
        let opts_iter = pdu_read_back.options_iter();
        assert!(opts_iter.is_some());
        let opts_iter = opts_iter.unwrap();
        let mut accumulated_len = 0;
        for (idx, opt) in opts_iter.enumerate() {
            if idx == 0 {
                assert_eq!(tlv1, opt);
            } else if idx == 1 {
                assert_eq!(tlv2, opt);
            }
            accumulated_len += opt.len_full();
        }
        assert_eq!(accumulated_len, pdu_read_back.options().len());
    }

    #[test]
    fn test_invalid_directive_code() {
        let (_, _, metadata_pdu) = generic_metadata_pdu(
            CrcFlag::NoCrc,
            ChecksumType::Crc32,
            true,
            LargeFileFlag::Large,
            &[],
        );
        let mut metadata_vec = metadata_pdu.to_vec().unwrap();
        metadata_vec[7] = 0xff;
        let metadata_error = MetadataPduReader::from_bytes(&metadata_vec);
        assert!(metadata_error.is_err());
        let error = metadata_error.unwrap_err();
        if let PduError::InvalidDirectiveType { found, expected } = error {
            assert_eq!(found, 0xff);
            assert_eq!(expected, Some(FileDirectiveType::MetadataPdu));
            assert_eq!(
                error.to_string(),
                "invalid directive type value 255, expected Some(MetadataPdu)"
            );
        } else {
            panic!("Expected InvalidDirectiveType error, got {:?}", error);
        }
    }

    #[test]
    fn test_wrong_directive_code() {
        let (_, _, metadata_pdu) = generic_metadata_pdu(
            CrcFlag::NoCrc,
            ChecksumType::Crc32,
            false,
            LargeFileFlag::Large,
            &[],
        );
        let mut metadata_vec = metadata_pdu.to_vec().unwrap();
        metadata_vec[7] = FileDirectiveType::EofPdu as u8;
        let metadata_error = MetadataPduReader::from_bytes(&metadata_vec);
        assert!(metadata_error.is_err());
        let error = metadata_error.unwrap_err();
        if let PduError::WrongDirectiveType { found, expected } = error {
            assert_eq!(found, FileDirectiveType::EofPdu);
            assert_eq!(expected, FileDirectiveType::MetadataPdu);
            assert_eq!(
                error.to_string(),
                "found directive type EofPdu, expected MetadataPdu"
            );
        } else {
            panic!("Expected InvalidDirectiveType error, got {:?}", error);
        }
    }
    #[test]
    fn test_corrects_pdu_header() {
        let pdu_header = PduHeader::new_for_file_data(
            common_pdu_conf(CrcFlag::NoCrc, LargeFileFlag::Normal),
            0,
            SegmentMetadataFlag::NotPresent,
            SegmentationControl::NoRecordBoundaryPreservation,
        );
        let metadata_params = MetadataGenericParams::new(false, ChecksumType::Crc32, 10);
        let src_filename = Lv::new_from_str(SRC_FILENAME).expect("Generating string LV failed");
        let dest_filename =
            Lv::new_from_str(DEST_FILENAME).expect("Generating destination LV failed");
        let metadata_pdu = MetadataPduCreator::new_no_opts(
            pdu_header,
            metadata_params,
            src_filename,
            dest_filename,
        );
        assert_eq!(metadata_pdu.pdu_header().pdu_type(), PduType::FileDirective);
    }
}
