use crate::cfdp::lv::Lv;
use crate::cfdp::pdu::{FileDirectiveType, PduError, PduHeader};
use crate::cfdp::tlv::Tlv;
use crate::cfdp::{ChecksumType, LargeFileFlag};
use crate::{ByteConversionError, SizeMissmatch};
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
        written += tlv.write_to_be_bytes(buf)?;
    }
    Ok(written)
}

#[cfg(feature = "alloc")]
pub fn build_metadata_opts_from_vec(
    buf: &mut [u8],
    tlvs: Vec<Tlv>,
) -> Result<usize, ByteConversionError> {
    build_metadata_opts_from_slice(buf, tlvs.as_slice())
}

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
        Self::new_with_opts(
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
        options: Option<&'opts [u8]>,
    ) -> Self {
        Self {
            pdu_header,
            metadata_params,
            src_file_name,
            dest_file_name,
            options,
        }
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

    pub fn written_len(&self) -> usize {
        // One directive type octet, and one byte of the parameter field.
        let mut len = self.pdu_header.written_len() + 2;
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
        len
    }
    pub fn write_to_be_bytes(&self, buf: &mut [u8]) -> Result<usize, PduError> {
        let expected_len = self.written_len();
        if buf.len() < expected_len {
            return Err(ByteConversionError::ToSliceTooSmall(SizeMissmatch {
                found: buf.len(),
                expected: expected_len,
            })
            .into());
        }
        let mut current_idx = self.pdu_header.write_to_be_bytes(buf)?;
        buf[current_idx] = FileDirectiveType::MetadataPdu as u8;
        current_idx += 1;
        buf[current_idx] = ((self.metadata_params.closure_requested as u8) << 7)
            | ((self.metadata_params.checksum_type as u8) << 4);
        current_idx += 1;
        if self.pdu_header.common_pdu_conf().file_flag == LargeFileFlag::Large {
            buf[current_idx..current_idx + core::mem::size_of::<u64>()]
                .copy_from_slice(&self.metadata_params.file_size.to_be_bytes());
            current_idx += core::mem::size_of::<u64>()
        } else {
            if self.metadata_params.file_size > u32::MAX as u64 {
                return Err(PduError::FileSizeTooLarge(self.metadata_params.file_size));
            }
            buf[current_idx..current_idx + core::mem::size_of::<u32>()]
                .copy_from_slice(&(self.metadata_params.file_size as u32).to_be_bytes());
            current_idx += core::mem::size_of::<u32>()
        }
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
        Ok(current_idx)
    }
}

#[cfg(test)]
pub mod tests {
    use crate::cfdp::lv::Lv;
    use crate::cfdp::pdu::metadata::{MetadataGenericParams, MetadataPdu};
    use crate::cfdp::pdu::tests::verify_raw_header;
    use crate::cfdp::pdu::{CommonPduConfig, FileDirectiveType, PduHeader};
    use crate::cfdp::ChecksumType;
    use crate::util::UbfU8;

    fn common_pdu_conf() -> CommonPduConfig {
        let src_id = UbfU8::new(5);
        let dest_id = UbfU8::new(10);
        let transaction_seq_num = UbfU8::new(20);
        CommonPduConfig::new_with_defaults(src_id, dest_id, transaction_seq_num)
            .expect("Generating common PDU config")
    }

    #[test]
    fn test_basic() {
        let pdu_header = PduHeader::new_no_file_data(common_pdu_conf(), 0);
        let metadata_params = MetadataGenericParams::new(false, ChecksumType::Crc32, 10);
        let src_filename =
            Lv::new_from_str("hello-world.txt").expect("Generating string LV failed");
        let src_len = src_filename.len_full();
        let dest_filename =
            Lv::new_from_str("hello-world2.txt").expect("Generating destination LV failed");
        let dest_len = dest_filename.len_full();
        let metadata_pdu =
            MetadataPdu::new(pdu_header, metadata_params, src_filename, dest_filename);
        assert_eq!(
            metadata_pdu.written_len(),
            pdu_header.written_len() + 1 + 1 + 4 + src_len + dest_len
        );
        assert_eq!(metadata_pdu.src_file_name(), src_filename);
        assert_eq!(metadata_pdu.dest_file_name(), dest_filename);
        assert_eq!(metadata_pdu.options(), None);
    }

    #[test]
    fn test_serialization() {
        let pdu_header = PduHeader::new_no_file_data(common_pdu_conf(), 0);
        let metadata_params = MetadataGenericParams::new(false, ChecksumType::Crc32, 10);
        let src_filename =
            Lv::new_from_str("hello-world.txt").expect("Generating string LV failed");
        let src_len = src_filename.len_full();
        let dest_filename =
            Lv::new_from_str("hello-world2.txt").expect("Generating destination LV failed");
        let dest_len = dest_filename.len_full();
        let metadata_pdu =
            MetadataPdu::new(pdu_header, metadata_params, src_filename, dest_filename);
        let mut buf: [u8; 64] = [0; 64];
        let res = metadata_pdu.write_to_be_bytes(&mut buf);
        assert!(res.is_ok());
        let written = res.unwrap();
        assert_eq!(
            written,
            pdu_header.written_len() + 1 + 1 + 4 + src_len + dest_len
        );
        verify_raw_header(&pdu_header, &buf);
        assert_eq!(buf[7], FileDirectiveType::MetadataPdu as u8);
    }
}
