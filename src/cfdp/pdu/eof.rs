use crate::cfdp::tlv::EntityIdTlv;
use crate::cfdp::ConditionCode;
#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

#[derive(Debug, Copy, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct EofPdu {
    condition_code: ConditionCode,
    file_checksum: u32,
    file_size: u64,
    fault_location: Option<EntityIdTlv>,
}
