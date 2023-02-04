//! PUS Service 3 Housekeeping
#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};
use num_enum::{IntoPrimitive, TryFromPrimitive};

#[derive(Debug, Eq, PartialEq, Copy, Clone, IntoPrimitive, TryFromPrimitive)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[repr(u8)]
pub enum Subservice {
    TcEnableGeneration = 5,
    TcDisableGeneration = 6,
    TmHkPacket = 25,
    TcGenerateOneShotHk = 27,
    TcModifyCollectionInterval = 31,
}
