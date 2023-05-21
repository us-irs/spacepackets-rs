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

    pub fn written_len(&self) -> usize {
        // One directive type octet
        let mut len = self.pdu_header.written_len() + 1;
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
        current_idx += self.src_file_name.write_to_be_bytes(buf)?;
        current_idx += self.dest_file_name.write_to_be_bytes(buf)?;
        if let Some(opts) = self.options {
            buf[current_idx..current_idx + opts.len()].copy_from_slice(opts);
            current_idx += opts.len();
        }
        Ok(current_idx)
    }
}

#[cfg(test)]
pub mod tests {
    #[test]
    fn test_basic() {}
}
