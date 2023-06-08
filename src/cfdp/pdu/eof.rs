use crate::cfdp::tlv::EntityIdTlv;
use crate::cfdp::ConditionCode;
#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};
use crate::cfdp::pdu::PduHeader;

#[derive(Debug, Copy, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct EofPdu {
    pdu_header: PduHeader,
    condition_code: ConditionCode,
    file_checksum: u32,
    file_size: u64,
    fault_location: Option<EntityIdTlv>,
}

impl EofPdu {
    pub fn new_no_error(pdu_header: PduHeader, file_checksum: u32, file_size: u64) -> Self {
       Self {
           pdu_header,
           condition_code: ConditionCode::NoError,
           file_checksum,
           file_size,
           fault_location: None
       }
    }
}