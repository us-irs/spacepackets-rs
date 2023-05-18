use crate::ByteConversionError;
use core::fmt::{Display, Formatter};
use num_enum::{IntoPrimitive, TryFromPrimitive};
#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};
#[cfg(feature = "std")]
use std::error::Error;

pub mod lv;
pub mod pdu;
pub mod tlv;

pub const CFDP_VERSION_2_NAME: &str = "CCSDS 727.0-B-5";
pub const CFDP_VERSION_2: u8 = 0b001;

#[derive(Debug, Copy, Clone, PartialEq, Eq, TryFromPrimitive, IntoPrimitive)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[repr(u8)]
pub enum PduType {
    FileDirective = 0,
    FileData = 1,
}

#[derive(Debug, Copy, Clone, PartialEq, Eq, TryFromPrimitive, IntoPrimitive)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[repr(u8)]
pub enum Direction {
    TowardsReceiver = 0,
    TowardsSender = 1,
}

#[derive(Debug, Copy, Clone, PartialEq, Eq, TryFromPrimitive, IntoPrimitive)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[repr(u8)]
pub enum TransmissionMode {
    Acknowledged = 0,
    Unacknowledged = 1,
}

#[derive(Debug, Copy, Clone, PartialEq, Eq, TryFromPrimitive, IntoPrimitive)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[repr(u8)]
pub enum CrcFlag {
    NoCrc = 0,
    WithCrc = 1,
}

/// Always 0 and ignores for File Directive PDUs (CCSDS 727.0-B-5 P.75)
#[derive(Debug, Copy, Clone, PartialEq, Eq, TryFromPrimitive, IntoPrimitive)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[repr(u8)]
pub enum SegmentMetadataFlag {
    NotPresent = 0,
    Present = 1,
}

/// Always 0 and ignores for File Directive PDUs (CCSDS 727.0-B-5 P.75)
#[derive(Debug, Copy, Clone, PartialEq, Eq, TryFromPrimitive, IntoPrimitive)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[repr(u8)]
pub enum SegmentationControl {
    NoRecordBoundaryPreservation = 0,
    WithRecordBoundaryPreservation = 1,
}

#[derive(Debug, Copy, Clone, PartialEq, Eq, TryFromPrimitive, IntoPrimitive)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[repr(u8)]
pub enum FaultHandlerCode {
    NoticeOfCancellation = 0b0001,
    NoticeOfSuspension = 0b0010,
    IgnoreError = 0b0011,
    AbandonTransaction = 0b0100,
}

#[derive(Debug, Copy, Clone, PartialEq, Eq, TryFromPrimitive, IntoPrimitive)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[repr(u8)]
pub enum LenInBytes {
    ZeroOrNone = 0,
    OneByte = 1,
    TwoBytes = 2,
    ThreeBytes = 4,
    FourBytes = 8,
}

#[derive(Debug, Copy, Clone, PartialEq, Eq, TryFromPrimitive, IntoPrimitive)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[repr(u8)]
pub enum ConditionCode {
    /// This is not an error condition for which a faulty handler override can be specified
    NoError = 0b0000,
    PositiveAckLimitReached = 0b0001,
    KeepAliveLimitReached = 0b0010,
    InvalidTransmissionMode = 0b0011,
    FilestoreRejection = 0b0100,
    FileChecksumFailure = 0b0101,
    FileSizeError = 0b0110,
    NakLimitReached = 0b0111,
    InactivityDetected = 0b1000,
    CheckLimitReached = 0b1001,
    UnsupportedChecksumType = 0b1011,
    /// Not an actual fault condition for which fault handler overrides can be specified
    SuspendRequestReceived = 0b1110,
    /// Not an actual fault condition for which fault handler overrides can be specified
    CancelRequestReceived = 0b1111,
}

#[derive(Debug, Copy, Clone, PartialEq, Eq, TryFromPrimitive, IntoPrimitive)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[repr(u8)]
pub enum LargeFileFlag {
    /// 32 bit maximum file size and FSS size
    Normal = 0,
    /// 64 bit maximum file size and FSS size
    Large = 1,
}

/// Checksum types according to the SANA Checksum Types registry
/// https://sanaregistry.org/r/checksum_identifiers/
#[derive(Debug, Copy, Clone, PartialEq, Eq, TryFromPrimitive, IntoPrimitive)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[repr(u8)]
pub enum ChecksumType {
    /// Modular legacy checksum
    Modular = 0,
    Crc32Proximity1 = 1,
    Crc32C = 2,
    /// Polynomial: 0x4C11DB7. Preferred checksum for now.
    Crc32 = 3,
    NullChecksum = 15,
}

pub const NULL_CHECKSUM_U32: [u8; 4] = [0; 4];

#[derive(Debug, Copy, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub enum TlvLvError {
    DataTooLarge(usize),
    ByteConversionError(ByteConversionError),
    /// Only relevant for TLV de-serialization.
    UnknownTlvType(u8),
}

impl From<ByteConversionError> for TlvLvError {
    fn from(value: ByteConversionError) -> Self {
        Self::ByteConversionError(value)
    }
}

impl Display for TlvLvError {
    fn fmt(&self, f: &mut Formatter<'_>) -> core::fmt::Result {
        match self {
            TlvLvError::UnknownTlvType(raw_tlv_id) => {
                write!(f, "unknown TLV type {raw_tlv_id}")
            }
            TlvLvError::DataTooLarge(data_len) => {
                write!(
                    f,
                    "data with size {} larger than allowed {} bytes",
                    data_len,
                    u8::MAX
                )
            }
            TlvLvError::ByteConversionError(e) => {
                write!(f, "{}", e)
            }
        }
    }
}

#[cfg(feature = "std")]
impl Error for TlvLvError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            TlvLvError::ByteConversionError(e) => Some(e),
            _ => None,
        }
    }
}
