use crate::cfdp::lv::Lv;
use crate::cfdp::pdu::{FileDirectiveType, PduHeader};
use crate::cfdp::ChecksumType;

pub struct MetadataGenericParams {
    closure_requested: bool,
    checksum_type: ChecksumType,
    file_size: u64,
}

pub struct MetadataPdu<'src_name, 'dest_name> {
    pdu_header: PduHeader,
    file_directive: FileDirectiveType,
    metadata_params: MetadataGenericParams,
    src_file_name: Option<Lv<'src_name>>,
    dest_file_name: Option<Lv<'dest_name>>,
}
