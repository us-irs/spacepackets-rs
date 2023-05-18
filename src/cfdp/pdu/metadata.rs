use crate::cfdp::pdu::{FileDirectiveType, PduHeader};
use crate::cfdp::ChecksumType;

pub struct MetadataParams {
    closure_requested: bool,
    checksum_type: ChecksumType,
    file_size: u64,
    //src_file_name:
}

pub struct MetadataPdu {
    pdu_header: PduHeader,
    file_directive: FileDirectiveType,
    metadata_params: MetadataParams,
}
