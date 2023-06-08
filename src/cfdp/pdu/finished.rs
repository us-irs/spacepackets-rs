use crate::cfdp::pdu::PduHeader;
use crate::cfdp::ConditionCode;
use num_enum::{IntoPrimitive, TryFromPrimitive};
#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

#[derive(Debug, Copy, Clone, PartialEq, Eq, TryFromPrimitive, IntoPrimitive)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[repr(u8)]
pub enum DeliveryCode {
    Complete = 0,
    Incomplete = 1,
}

#[derive(Debug, Copy, Clone, PartialEq, Eq, TryFromPrimitive, IntoPrimitive)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[repr(u8)]
pub enum FileStatus {
    DiscardDeliberately = 0b00,
    DiscardedFsRejection = 0b01,
    Retained = 0b10,
    Unreported = 0b11,
}

#[derive(Debug, Copy, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct FinishPdu<'fs_responses> {
    pdu_header: PduHeader,
    condition_code: ConditionCode,
    delivery_code: DeliveryCode,
    file_status: FileStatus,
    fs_responses: Optional<&'fs_responses [u8]>,
    // fault_location:
}
