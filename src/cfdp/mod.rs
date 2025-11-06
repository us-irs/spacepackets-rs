//! Low-level CCSDS File Delivery Protocol (CFDP) support according to [CCSDS 727.0-B-5](https://public.ccsds.org/Pubs/727x0b5.pdf).
use crate::ByteConversionError;
use num_enum::{IntoPrimitive, TryFromPrimitive};
#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

pub mod lv;
pub mod pdu;
pub mod tlv;

/// This is the name of the standard this module is based on.
pub const CFDP_VERSION_2_NAME: &str = "CCSDS 727.0-B-5";
/// Currently, only this version is supported.
pub const CFDP_VERSION_2: u8 = 0b001;

/// PDU type.
#[derive(Debug, PartialEq, Eq, TryFromPrimitive, IntoPrimitive)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
#[bitbybit::bitenum(u1, exhaustive = true)]
#[repr(u8)]
pub enum PduType {
    /// File directive PDU.
    FileDirective = 0,
    /// File data PDU.
    FileData = 1,
}

/// PDU direction.
#[derive(Debug, PartialEq, Eq, TryFromPrimitive, IntoPrimitive)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
#[bitbybit::bitenum(u1, exhaustive = true)]
#[repr(u8)]
pub enum Direction {
    /// Going towards the file receiver.
    TowardsReceiver = 0,
    /// Going towards the file sender.
    TowardsSender = 1,
}

/// PDU transmission mode.
#[derive(Debug, PartialEq, Eq, TryFromPrimitive, IntoPrimitive)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
#[bitbybit::bitenum(u1, exhaustive = true)]
#[repr(u8)]
pub enum TransmissionMode {
    /// Acknowledged (class 1) transfer.
    Acknowledged = 0,
    /// Unacknowledged (class 2) transfer.
    Unacknowledged = 1,
}

/// CRC flag.
#[derive(Debug, PartialEq, Eq, TryFromPrimitive, IntoPrimitive)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
#[bitbybit::bitenum(u1, exhaustive = true)]
#[repr(u8)]
pub enum CrcFlag {
    /// No CRC for the packet.
    NoCrc = 0,
    /// Packet has CRC.
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
#[derive(Debug, PartialEq, Eq, TryFromPrimitive, IntoPrimitive)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
#[bitbybit::bitenum(u1, exhaustive = true)]
#[repr(u8)]
pub enum SegmentMetadataFlag {
    /// Segment metadata not present.
    NotPresent = 0,
    /// Segment metadata present.
    Present = 1,
}

/// Always 0 and ignored for File Directive PDUs (CCSDS 727.0-B-5 P.75)
#[derive(Debug, PartialEq, Eq, TryFromPrimitive, IntoPrimitive)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
#[bitbybit::bitenum(u1, exhaustive = true)]
#[repr(u8)]
pub enum SegmentationControl {
    /// No record boundary preservation.
    NoRecordBoundaryPreservation = 0,
    /// With record boundary preservation.
    WithRecordBoundaryPreservation = 1,
}

/// Fault handler codes according to the CFDP standard.
#[derive(Debug, PartialEq, Eq, TryFromPrimitive, IntoPrimitive)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
#[bitbybit::bitenum(u3, exhaustive = false)]
#[repr(u8)]
pub enum FaultHandlerCode {
    /// Notice of cancellation fault handler code.
    NoticeOfCancellation = 0b0001,
    /// Notice of suspension fault handler code.
    NoticeOfSuspension = 0b0010,
    /// Ignore error fault handler code.
    IgnoreError = 0b0011,
    /// Abandon transaction fault handler code.
    AbandonTransaction = 0b0100,
}

/// CFDP condition codes.
#[derive(Debug, PartialEq, Eq, TryFromPrimitive, IntoPrimitive)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
#[bitbybit::bitenum(u4, exhaustive = false)]
#[repr(u8)]
pub enum ConditionCode {
    /// This is not an error condition for which a faulty handler override can be specified
    NoError = 0b0000,
    /// Positive acknowledgement limit reached.
    PositiveAckLimitReached = 0b0001,
    /// Keep-alive limit reached.
    KeepAliveLimitReached = 0b0010,
    /// Invalid transmission mode.
    InvalidTransmissionMode = 0b0011,
    /// Filestore rejection.
    FilestoreRejection = 0b0100,
    /// File checksum error.
    FileChecksumFailure = 0b0101,
    /// File size error.
    FileSizeError = 0b0110,
    /// NAK limit reached.
    NakLimitReached = 0b0111,
    /// Inactivity detected.
    InactivityDetected = 0b1000,
    /// Check limit reached.
    CheckLimitReached = 0b1010,
    /// Unsupported checksum type.
    UnsupportedChecksumType = 0b1011,
    /// Not an actual fault condition for which fault handler overrides can be specified
    SuspendRequestReceived = 0b1110,
    /// Not an actual fault condition for which fault handler overrides can be specified
    CancelRequestReceived = 0b1111,
}

/// Large file flag.
#[derive(Debug, PartialEq, Eq, TryFromPrimitive, IntoPrimitive)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
#[bitbybit::bitenum(u1, exhaustive = true)]
#[repr(u8)]
pub enum LargeFileFlag {
    /// 32 bit maximum file size and FSS size
    Normal = 0,
    /// 64 bit maximum file size and FSS size
    Large = 1,
}

/// Transaction status for the ACK PDU field according to chapter 5.2.4 of the CFDP standard.
#[derive(Debug, PartialEq, Eq, TryFromPrimitive, IntoPrimitive)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
#[bitbybit::bitenum(u2, exhaustive = true)]
#[repr(u8)]
pub enum TransactionStatus {
    /// Transaction is not currently active and the CFDP implementation does not retain a
    /// transaction history.
    Undefined = 0b00,
    /// Transaction is currently active.
    Active = 0b01,
    /// Transaction was active in the past and was terminated.
    Terminated = 0b10,
    /// The CFDP implementation does retain a tranaction history, and the transaction is not and
    /// never was active at this entity.
    Unrecognized = 0b11,
}

/// Checksum types according to the
/// [SANA Checksum Types registry](https://sanaregistry.org/r/checksum_identifiers/)
#[derive(Default, Debug, Copy, Clone, PartialEq, Eq, TryFromPrimitive, IntoPrimitive)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
#[repr(u8)]
pub enum ChecksumType {
    /// Modular legacy checksum
    Modular = 0,
    /// CRC32 Proximity-1.
    Crc32Proximity1 = 1,
    /// CRC32C.
    Crc32C = 2,
    /// CRC32. Polynomial: 0x4C11DB7. Preferred checksum for now.
    Crc32 = 3,
    /// Null checksum (no checksum).
    #[default]
    NullChecksum = 15,
}

/// Raw null checksum.
pub const NULL_CHECKSUM_U32: [u8; 4] = [0; 4];

/// TLV or LV data larger than allowed [u8::MAX].
#[derive(Debug, Copy, Clone, PartialEq, Eq, thiserror::Error)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
#[error("data with size {0} larger than allowed {max} bytes", max = u8::MAX)]
pub struct TlvLvDataTooLargeError(pub usize);

/// First value: Found value. Second value: Expected value if there is one.
#[derive(Debug, Copy, Clone, PartialEq, Eq, thiserror::Error)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
#[error("invalid TLV type field, found {found}, expected {expected:?}")]
pub struct InvalidTlvTypeFieldError {
    found: u8,
    expected: Option<u8>,
}

/// Generic TLV/LV error.
#[derive(Debug, Copy, Clone, PartialEq, Eq, thiserror::Error)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum TlvLvError {
    /// Data too large error.
    #[error("{0}")]
    DataTooLarge(#[from] TlvLvDataTooLargeError),
    /// Byte conversion error.
    #[error("byte conversion error: {0}")]
    ByteConversion(#[from] ByteConversionError),
    /// Invalid TLV type field error.
    #[error("{0}")]
    InvalidTlvTypeField(#[from] InvalidTlvTypeFieldError),
    /// Invalid value length.
    #[error("invalid value length {0}")]
    InvalidValueLength(usize),
    /// Only applies to filestore requests and responses. Second name was missing where one is
    /// expected.
    #[error("second name missing for filestore request or response")]
    SecondNameMissing,
    /// Invalid action code for filestore requests or responses.
    #[error("invalid action code {0}")]
    InvalidFilestoreActionCode(u8),
}

#[cfg(test)]
mod tests {
    use super::*;
    #[cfg(feature = "serde")]
    use crate::tests::generic_serde_test;

    #[test]
    fn test_crc_from_bool() {
        assert_eq!(CrcFlag::from(false), CrcFlag::NoCrc);
    }

    #[test]
    fn test_crc_flag_to_bool() {
        let is_true: bool = CrcFlag::WithCrc.into();
        assert!(is_true);
        let is_false: bool = CrcFlag::NoCrc.into();
        assert!(!is_false);
    }

    #[test]
    fn test_default_checksum_type() {
        let checksum = ChecksumType::default();
        assert_eq!(checksum, ChecksumType::NullChecksum);
    }

    #[test]
    fn test_fault_handler_code_from_u8() {
        let fault_handler_code_raw = FaultHandlerCode::NoticeOfSuspension as u8;
        let fault_handler_code = FaultHandlerCode::try_from(fault_handler_code_raw).unwrap();
        assert_eq!(fault_handler_code, FaultHandlerCode::NoticeOfSuspension);
    }

    #[test]
    #[cfg(feature = "serde")]
    fn test_serde_impl_pdu_type() {
        generic_serde_test(PduType::FileData);
    }

    #[test]
    #[cfg(feature = "serde")]
    fn test_serde_impl_direction() {
        generic_serde_test(Direction::TowardsReceiver);
    }

    #[test]
    #[cfg(feature = "serde")]
    fn test_serde_impl_transmission_mode() {
        generic_serde_test(TransmissionMode::Unacknowledged);
    }

    #[test]
    #[cfg(feature = "serde")]
    fn test_serde_fault_handler_code() {
        generic_serde_test(FaultHandlerCode::NoticeOfCancellation);
    }
}
