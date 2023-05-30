use crate::cfdp::lv::Lv;
use crate::cfdp::pdu::{read_fss_field, write_fss_field, FileDirectiveType, PduError, PduHeader};
use crate::cfdp::tlv::Tlv;
use crate::cfdp::{ChecksumType, CrcFlag, LargeFileFlag, PduType};
use crate::{ByteConversionError, SizeMissmatch, CRC_CCITT_FALSE};
#[cfg(feature = "alloc")]
use alloc::vec::Vec;
#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

#[derive(Debug, Copy, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct MetadataGenericParams {
    closure_requested: bool,
    checksum_type: ChecksumType,
    file_size: u64,
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
        written += tlv.write_to_be_bytes(&mut buf[written..])?;
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

/// Metadata PDU abstraction.
///
/// For more information, refer to CFDP chapter 5.2.5.
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct MetadataPdu<'src_name, 'dest_name, 'opts> {
    pdu_header: PduHeader,
    metadata_params: MetadataGenericParams,
    #[cfg_attr(feature = "serde", serde(borrow))]
    src_file_name: Lv<'src_name>,
    #[cfg_attr(feature = "serde", serde(borrow))]
    dest_file_name: Lv<'dest_name>,
    options: Option<&'opts [u8]>,
}

impl<'src_name, 'dest_name, 'opts> MetadataPdu<'src_name, 'dest_name, 'opts> {
    pub fn new(
        pdu_header: PduHeader,
        metadata_params: MetadataGenericParams,
        src_file_name: Lv<'src_name>,
        dest_file_name: Lv<'dest_name>,
    ) -> Self {
        Self::new_generic(
            pdu_header,
            metadata_params,
            src_file_name,
            dest_file_name,
            None,
        )
    }

    pub fn new_with_opts(
        pdu_header: PduHeader,
        metadata_params: MetadataGenericParams,
        src_file_name: Lv<'src_name>,
        dest_file_name: Lv<'dest_name>,
        options: &'opts [u8],
    ) -> Self {
        Self::new_generic(
            pdu_header,
            metadata_params,
            src_file_name,
            dest_file_name,
            Some(options),
        )
    }

    pub fn new_generic(
        mut pdu_header: PduHeader,
        metadata_params: MetadataGenericParams,
        src_file_name: Lv<'src_name>,
        dest_file_name: Lv<'dest_name>,
        options: Option<&'opts [u8]>,
    ) -> Self {
        pdu_header.pdu_type = PduType::FileDirective;
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

    pub fn src_file_name(&self) -> Lv<'src_name> {
        self.src_file_name
    }

    pub fn dest_file_name(&self) -> Lv<'dest_name> {
        self.dest_file_name
    }

    pub fn options(&self) -> Option<&'opts [u8]> {
        self.options
    }

    /// Yield an iterator which can be used to loop through all options. Returns [None] if the
    /// options field is empty.
    pub fn options_iter(&self) -> Option<OptionsIter<'opts>> {
        self.options?;
        Some(OptionsIter {
            opt_buf: self.options.unwrap(),
            current_idx: 0,
        })
    }

    pub fn written_len(&self) -> usize {
        // One directive type octet, and one byte of the parameter field.
        self.pdu_header.header_len() + self.calc_pdu_datafield_len()
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
        if let Some(opts) = self.options {
            len += opts.len();
        }
        if self.pdu_header.pdu_conf.crc_flag == CrcFlag::WithCrc {
            len += 2;
        }
        len
    }

    pub fn pdu_header(&self) -> &PduHeader {
        &self.pdu_header
    }

    pub fn write_to_bytes(&self, buf: &mut [u8]) -> Result<usize, PduError> {
        let expected_len = self.written_len();
        if buf.len() < expected_len {
            return Err(ByteConversionError::ToSliceTooSmall(SizeMissmatch {
                found: buf.len(),
                expected: expected_len,
            })
            .into());
        }

        let mut current_idx = self.pdu_header.write_to_bytes(buf)?;
        buf[current_idx] = FileDirectiveType::MetadataPdu as u8;
        current_idx += 1;
        buf[current_idx] = ((self.metadata_params.closure_requested as u8) << 7)
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
        if let Some(opts) = self.options {
            buf[current_idx..current_idx + opts.len()].copy_from_slice(opts);
            current_idx += opts.len();
        }
        if self.pdu_header.pdu_conf.crc_flag == CrcFlag::WithCrc {
            let mut digest = CRC_CCITT_FALSE.digest();
            digest.update(&buf[..current_idx]);
            buf[current_idx..current_idx + 2].copy_from_slice(&digest.finalize().to_be_bytes());
            current_idx += 2;
        }
        Ok(current_idx)
    }

    pub fn from_bytes<'longest: 'src_name + 'dest_name + 'opts>(
        buf: &'longest [u8],
    ) -> Result<Self, PduError> {
        let (pdu_header, mut current_idx) = PduHeader::from_bytes(buf)?;
        let full_len_without_crc = pdu_header.verify_length_and_checksum(buf)?;
        let is_large_file = pdu_header.pdu_conf.file_flag == LargeFileFlag::Large;
        // Minimal length: 1 byte + FSS (4 byte) + 2 empty LV (1 byte)
        let mut min_expected_len = current_idx + 7;
        if is_large_file {
            min_expected_len += 4;
        }
        min_expected_len = core::cmp::max(min_expected_len, pdu_header.pdu_len());
        if buf.len() < min_expected_len {
            return Err(ByteConversionError::FromSliceTooSmall(SizeMissmatch {
                found: buf.len(),
                expected: min_expected_len,
            })
            .into());
        }
        let directive_type = FileDirectiveType::try_from(buf[current_idx]).map_err(|_| {
            PduError::InvalidDirectiveType((buf[current_idx], FileDirectiveType::MetadataPdu))
        })?;
        if directive_type != FileDirectiveType::MetadataPdu {
            return Err(PduError::WrongDirectiveType((
                directive_type,
                FileDirectiveType::MetadataPdu,
            )));
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
        let mut options = None;
        if current_idx < full_len_without_crc {
            options = Some(&buf[current_idx..full_len_without_crc]);
        }
        Ok(Self {
            pdu_header,
            metadata_params,
            src_file_name,
            dest_file_name,
            options,
        })
    }
}

#[cfg(test)]
pub mod tests {
    use crate::cfdp::lv::Lv;
    use crate::cfdp::pdu::metadata::{
        build_metadata_opts_from_slice, build_metadata_opts_from_vec, MetadataGenericParams,
        MetadataPdu,
    };
    use crate::cfdp::pdu::tests::verify_raw_header;
    use crate::cfdp::pdu::{CommonPduConfig, FileDirectiveType, PduHeader};
    use crate::cfdp::tlv::{Tlv, TlvType};
    use crate::cfdp::{
        ChecksumType, CrcFlag, LargeFileFlag, PduType, SegmentMetadataFlag, SegmentationControl,
    };
    use crate::util::UbfU8;
    use std::vec;

    const SRC_FILENAME: &'static str = "hello-world.txt";
    const DEST_FILENAME: &'static str = "hello-world2.txt";

    fn common_pdu_conf(crc_flag: CrcFlag, fss: LargeFileFlag) -> CommonPduConfig {
        let src_id = UbfU8::new(5);
        let dest_id = UbfU8::new(10);
        let transaction_seq_num = UbfU8::new(20);
        let mut pdu_conf = CommonPduConfig::new_with_defaults(src_id, dest_id, transaction_seq_num)
            .expect("Generating common PDU config");
        pdu_conf.crc_flag = crc_flag;
        pdu_conf.file_flag = fss;
        pdu_conf
    }

    fn generic_metadata_pdu<'opts>(
        crc_flag: CrcFlag,
        fss: LargeFileFlag,
        opts: Option<&'opts [u8]>,
    ) -> (
        Lv<'static>,
        Lv<'static>,
        MetadataPdu<'static, 'static, 'opts>,
    ) {
        let pdu_header = PduHeader::new_no_file_data(common_pdu_conf(crc_flag, fss), 0);
        let metadata_params = MetadataGenericParams::new(false, ChecksumType::Crc32, 0x1010);
        let src_filename = Lv::new_from_str(SRC_FILENAME).expect("Generating string LV failed");
        let dest_filename =
            Lv::new_from_str(DEST_FILENAME).expect("Generating destination LV failed");
        (
            src_filename,
            dest_filename,
            MetadataPdu::new_generic(
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
        let (src_filename, dest_filename, metadata_pdu) =
            generic_metadata_pdu(CrcFlag::NoCrc, LargeFileFlag::Normal, None);
        assert_eq!(
            metadata_pdu.written_len(),
            metadata_pdu.pdu_header().header_len()
                + 1
                + 1
                + 4
                + src_filename.len_full()
                + dest_filename.len_full()
        );
        assert_eq!(metadata_pdu.src_file_name(), src_filename);
        assert_eq!(metadata_pdu.dest_file_name(), dest_filename);
        assert_eq!(metadata_pdu.options(), None);
    }

    #[test]
    fn test_serialization() {
        let (src_filename, dest_filename, metadata_pdu) =
            generic_metadata_pdu(CrcFlag::NoCrc, LargeFileFlag::Normal, None);
        let mut buf: [u8; 64] = [0; 64];
        let res = metadata_pdu.write_to_bytes(&mut buf);
        assert!(res.is_ok());
        let written = res.unwrap();
        assert_eq!(
            written,
            metadata_pdu.pdu_header.header_len()
                + 1
                + 1
                + 4
                + src_filename.len_full()
                + dest_filename.len_full()
        );
        verify_raw_header(metadata_pdu.pdu_header(), &buf);
        assert_eq!(buf[7], FileDirectiveType::MetadataPdu as u8);
        assert_eq!(buf[8] >> 6, false as u8);
        assert_eq!(buf[8] & 0b1111, ChecksumType::Crc32 as u8);
        assert_eq!(u32::from_be_bytes(buf[9..13].try_into().unwrap()), 0x1010);
        let mut current_idx = 13;
        let src_name_from_raw =
            Lv::from_bytes(&buf[current_idx..]).expect("Creating source name LV failed");
        assert_eq!(src_name_from_raw, src_filename);
        current_idx += src_name_from_raw.len_full();
        let dest_name_from_raw =
            Lv::from_bytes(&buf[current_idx..]).expect("Creating dest name LV failed");
        assert_eq!(dest_name_from_raw, dest_filename);
        current_idx += dest_name_from_raw.len_full();
        // No options, so no additional data here.
        assert_eq!(current_idx, written);
    }

    #[test]
    fn test_deserialization() {
        let (_, _, metadata_pdu) =
            generic_metadata_pdu(CrcFlag::NoCrc, LargeFileFlag::Normal, None);
        let mut buf: [u8; 64] = [0; 64];
        metadata_pdu.write_to_bytes(&mut buf).unwrap();
        let pdu_read_back = MetadataPdu::from_bytes(&buf);
        assert!(pdu_read_back.is_ok());
        let pdu_read_back = pdu_read_back.unwrap();
        assert_eq!(pdu_read_back, metadata_pdu);
    }

    #[test]
    fn test_with_crc_flag() {
        let (src_filename, dest_filename, metadata_pdu) =
            generic_metadata_pdu(CrcFlag::WithCrc, LargeFileFlag::Normal, None);
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
        let pdu_read_back = MetadataPdu::from_bytes(&buf).unwrap();
        assert_eq!(pdu_read_back, metadata_pdu);
    }

    #[test]
    fn test_with_large_file_flag() {
        let (src_filename, dest_filename, metadata_pdu) =
            generic_metadata_pdu(CrcFlag::NoCrc, LargeFileFlag::Large, None);
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
        let pdu_read_back = MetadataPdu::from_bytes(&buf).unwrap();
        assert_eq!(pdu_read_back, metadata_pdu);
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
        let tlv_vec = vec![tlv1, tlv2];
        let mut opts_buf: [u8; 32] = [0; 32];
        let opts_len = build_metadata_opts_from_vec(&mut opts_buf, &tlv_vec).unwrap();
        let (src_filename, dest_filename, metadata_pdu) = generic_metadata_pdu(
            CrcFlag::NoCrc,
            LargeFileFlag::Normal,
            Some(&opts_buf[..opts_len]),
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
        let pdu_read_back = MetadataPdu::from_bytes(&buf).unwrap();
        assert_eq!(pdu_read_back, metadata_pdu);
        let opts_iter = pdu_read_back.options_iter();
        assert!(opts_iter.is_some());
        let opts_iter = opts_iter.unwrap();
        let mut accumulated_len = 0;
        for (idx, opt) in opts_iter.enumerate() {
            assert_eq!(tlv_vec[idx], opt);
            accumulated_len += opt.len_full();
        }
        assert_eq!(accumulated_len, pdu_read_back.options().unwrap().len());
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
        let metadata_pdu =
            MetadataPdu::new(pdu_header, metadata_params, src_filename, dest_filename);
        assert_eq!(metadata_pdu.pdu_header().pdu_type(), PduType::FileDirective);
    }
}
