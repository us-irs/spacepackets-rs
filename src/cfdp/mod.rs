//! Low-level CCSDS File Delivery Protocol (CFDP) support according to [CCSDS 727.0-B-5](https://public.ccsds.org/Pubs/727x0b5.pdf).
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

/// This is the name of the standard this module is based on.
pub const CFDP_VERSION_2_NAME: &str = "CCSDS 727.0-B-5";
/// Currently, only this version is supported.
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

impl From<bool> for CrcFlag {
    fn from(value: bool) -> Self {
        if value {
            return CrcFlag::WithCrc;
        }
        CrcFlag::NoCrc
    }
}

impl From<CrcFlag> for bool {
    fn from(value: CrcFlag) -> Self {
        if value == CrcFlag::WithCrc {
            return true;
        }
        false
    }
}

/// Always 0 and ignored for File Directive PDUs (CCSDS 727.0-B-5 P.75)
#[derive(Debug, Copy, Clone, PartialEq, Eq, TryFromPrimitive, IntoPrimitive)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[repr(u8)]
pub enum SegmentMetadataFlag {
    NotPresent = 0,
    Present = 1,
}

/// Always 0 and ignored for File Directive PDUs (CCSDS 727.0-B-5 P.75)
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

/// Transaction status for the ACK PDU field according to chapter 5.2.4 of the CFDP standard.
#[derive(Debug, Copy, Clone, PartialEq, Eq, TryFromPrimitive, IntoPrimitive)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[repr(u8)]
pub enum TransactionStatus {
    /// Transaction is not currently active and the CFDP implementation does not retain a
    /// transaction history.
    Undefined = 0b00,
    Active = 0b01,
    /// Transaction was active in the past and was terminated.
    Terminated = 0b10,
    /// The CFDP implementation does retain a tranaction history, and the transaction is not and
    /// never was active at this entity.
    Unrecognized = 0b11,
}

/// Checksum types according to the
/// [SANA Checksum Types registry](https://sanaregistry.org/r/checksum_identifiers/)
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

impl Default for ChecksumType {
    fn default() -> Self {
        Self::NullChecksum
    }
}

pub const NULL_CHECKSUM_U32: [u8; 4] = [0; 4];

#[derive(Debug, Copy, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub enum TlvLvError {
    DataTooLarge(usize),
    ByteConversionError(ByteConversionError),
    /// First value: Found value. Second value: Expected value if there is one.
    InvalidTlvTypeField((u8, Option<u8>)),
    /// Logically invalid value length detected. The value length may not exceed 255 bytes.
    /// Depending on the concrete TLV type, the value length may also be logically invalid.
    InvalidValueLength(usize),
    /// Only applies to filestore requests and responses. Second name was missing where one is
    /// expected.
    SecondNameMissing,
    /// Invalid action code for filestore requests or responses.
    InvalidFilestoreActionCode(u8),
}

impl From<ByteConversionError> for TlvLvError {
    fn from(value: ByteConversionError) -> Self {
        Self::ByteConversionError(value)
    }
}

impl Display for TlvLvError {
    fn fmt(&self, f: &mut Formatter<'_>) -> core::fmt::Result {
        match self {
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
            TlvLvError::InvalidTlvTypeField((found, expected)) => {
                write!(
                    f,
                    "invalid TLV type field, found {found}, possibly expected {expected:?}"
                )
            }
            TlvLvError::InvalidValueLength(len) => {
                write!(f, "invalid value length {len} detected")
            }
            TlvLvError::SecondNameMissing => {
                write!(f, "second name missing for filestore request or response")
            }
            TlvLvError::InvalidFilestoreActionCode(raw) => {
                write!(f, "invalid filestore action code with raw value {raw}")
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
