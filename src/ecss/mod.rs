//! Common definitions and helpers required to create PUS TMTC packets according to
//! [ECSS-E-ST-70-41C](https://ecss.nl/standard/ecss-e-st-70-41c-space-engineering-telemetry-and-telecommand-packet-utilization-15-april-2016/)
//!
//! You can find the PUS telecommand definitions in the [crate::tc] module and ithe PUS telemetry definitions
//! inside the [crate::tm] module.
use crate::{ByteConversionError, CcsdsPacket, CRC_CCITT_FALSE};
use core::fmt::{Debug, Display, Formatter};
use core::mem::size_of;
use num_enum::{IntoPrimitive, TryFromPrimitive};
#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};
#[cfg(feature = "std")]
use std::error::Error;

pub mod event;
pub mod hk;
pub mod scheduling;
pub mod verification;

pub type CrcType = u16;
pub const CCSDS_HEADER_LEN: usize = size_of::<crate::zc::SpHeader>();

#[derive(Debug, Copy, Clone, Eq, PartialEq, IntoPrimitive, TryFromPrimitive)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[repr(u8)]
#[non_exhaustive]
pub enum PusServiceId {
    /// Service 1
    Verification = 1,
    /// Service 2
    DeviceAccess = 2,
    /// Service 3
    Housekeeping = 3,
    /// Service 4
    ParameterStatistics = 4,
    /// Service 5
    Event = 5,
    /// Service 6
    MemoryManagement = 6,
    /// Service 8
    Action = 8,
    /// Service 9
    TimeManagement = 9,
    /// Service 11
    Scheduling = 11,
    /// Service 12
    OnBoardMonitoring = 12,
    /// Service 13
    LargePacketTransfer = 13,
    /// Service 14
    RealTimeForwardingControl = 14,
    /// Service 15
    StorageAndRetrival = 15,
    /// Service 17
    Test = 17,
    /// Service 18
    OpsAndProcedures = 18,
    /// Service 19
    EventAction = 19,
    /// Service 20
    Parameter = 20,
    /// Service 21
    RequestSequencing = 21,
    /// Service 22
    PositionBasedScheduling = 22,
    /// Service 23
    FileManagement = 23,
}

/// All PUS versions. Only PUS C is supported by this library.
#[derive(PartialEq, Eq, Copy, Clone, Debug)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub enum PusVersion {
    EsaPus = 0,
    PusA = 1,
    PusC = 2,
    Invalid = 0b1111,
}

impl TryFrom<u8> for PusVersion {
    type Error = ();

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            x if x == PusVersion::EsaPus as u8 => Ok(PusVersion::EsaPus),
            x if x == PusVersion::PusA as u8 => Ok(PusVersion::PusA),
            x if x == PusVersion::PusC as u8 => Ok(PusVersion::PusC),
            _ => Err(()),
        }
    }
}

/// ECSS Packet Type Codes (PTC)s.
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub enum PacketTypeCodes {
    Boolean = 1,
    Enumerated = 2,
    UnsignedInt = 3,
    SignedInt = 4,
    Real = 5,
    BitString = 6,
    OctetString = 7,
    CharString = 8,
    AbsoluteTime = 9,
    RelativeTime = 10,
    Deduced = 11,
    Packet = 12,
}

pub type Ptc = PacketTypeCodes;

/// ECSS Packet Field Codes (PFC)s for the unsigned [Ptc].
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub enum UnsignedPfc {
    OneByte = 4,
    TwelveBits = 8,
    TwoBytes = 12,
    ThreeBytes = 13,
    FourBytes = 14,
    SixBytes = 15,
    EightBytes = 16,
    OneBit = 17,
    TwoBits = 18,
    ThreeBits = 19,
}

/// ECSS Packet Field Codes (PFC)s for the real (floating point) [Ptc].
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub enum RealPfc {
    /// 4 octets simple precision format (IEEE)
    Float = 1,
    /// 8 octets simple precision format (IEEE)
    Double = 2,
    /// 4 octets simple precision format (MIL-STD)
    FloatMilStd = 3,
    /// 8 octets simple precision format (MIL-STD)
    DoubleMilStd = 4,
}

#[derive(Debug, Copy, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub enum PusError {
    VersionNotSupported(PusVersion),
    IncorrectCrc(u16),
    RawDataTooShort(usize),
    NoRawData,
    /// CRC16 needs to be calculated first
    CrcCalculationMissing,
    ByteConversionError(ByteConversionError),
}

impl Display for PusError {
    fn fmt(&self, f: &mut Formatter<'_>) -> core::fmt::Result {
        match self {
            PusError::VersionNotSupported(v) => {
                write!(f, "PUS version {v:?} not supported")
            }
            PusError::IncorrectCrc(crc) => {
                write!(f, "crc16 {crc:#04x} is incorrect")
            }
            PusError::RawDataTooShort(size) => {
                write!(
                    f,
                    "deserialization error, provided raw data with size {size} too short"
                )
            }
            PusError::NoRawData => {
                write!(f, "no raw data provided")
            }
            PusError::CrcCalculationMissing => {
                write!(f, "crc16 was not calculated")
            }
            PusError::ByteConversionError(e) => {
                write!(f, "low level byte conversion error: {e}")
            }
        }
    }
}

#[cfg(feature = "std")]
impl Error for PusError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        if let PusError::ByteConversionError(e) = self {
            return Some(e);
        }
        None
    }
}

impl From<ByteConversionError> for PusError {
    fn from(e: ByteConversionError) -> Self {
        PusError::ByteConversionError(e)
    }
}

/// Generic trait to describe common attributes for both PUS Telecommands (TC) and PUS Telemetry
/// (TM) packets. All PUS packets are also a special type of [CcsdsPacket]s.
pub trait PusPacket: CcsdsPacket {
    const PUS_VERSION: PusVersion = PusVersion::PusC;

    fn pus_version(&self) -> PusVersion;
    fn service(&self) -> u8;
    fn subservice(&self) -> u8;

    fn user_data(&self) -> Option<&[u8]>;
    fn crc16(&self) -> Option<u16>;
}

pub(crate) fn crc_from_raw_data(raw_data: &[u8]) -> Result<u16, PusError> {
    if raw_data.len() < 2 {
        return Err(PusError::RawDataTooShort(raw_data.len()));
    }
    Ok(u16::from_be_bytes(
        raw_data[raw_data.len() - 2..raw_data.len()]
            .try_into()
            .unwrap(),
    ))
}

pub(crate) fn calc_pus_crc16(bytes: &[u8]) -> u16 {
    let mut digest = CRC_CCITT_FALSE.digest();
    digest.update(bytes);
    digest.finalize()
}

pub(crate) fn crc_procedure(
    calc_on_serialization: bool,
    cached_crc16: &Option<u16>,
    start_idx: usize,
    curr_idx: usize,
    slice: &[u8],
) -> Result<u16, PusError> {
    let crc16;
    if calc_on_serialization {
        crc16 = calc_pus_crc16(&slice[start_idx..curr_idx])
    } else if cached_crc16.is_none() {
        return Err(PusError::CrcCalculationMissing);
    } else {
        crc16 = cached_crc16.unwrap();
    }
    Ok(crc16)
}

pub(crate) fn user_data_from_raw(
    current_idx: usize,
    total_len: usize,
    raw_data_len: usize,
    slice: &[u8],
) -> Result<Option<&[u8]>, PusError> {
    match current_idx {
        _ if current_idx == total_len - 2 => Ok(None),
        _ if current_idx > total_len - 2 => Err(PusError::RawDataTooShort(raw_data_len)),
        _ => Ok(Some(&slice[current_idx..total_len - 2])),
    }
}

pub(crate) fn verify_crc16_ccitt_false_from_raw(
    raw_data: &[u8],
    crc16: u16,
) -> Result<(), PusError> {
    let mut digest = CRC_CCITT_FALSE.digest();
    digest.update(raw_data);
    if digest.finalize() == 0 {
        return Ok(());
    }
    Err(PusError::IncorrectCrc(crc16))
}

macro_rules! ccsds_impl {
    () => {
        delegate!(to self.sp_header {
            fn ccsds_version(&self) -> u8;
            fn packet_id(&self) -> crate::PacketId;
            fn psc(&self) -> crate::PacketSequenceCtrl;
            fn data_len(&self) -> u16;
        });
    }
}

macro_rules! sp_header_impls {
    () => {
        delegate!(to self.sp_header {
            pub fn set_apid(&mut self, apid: u16) -> bool;
            pub fn set_seq_count(&mut self, seq_count: u16) -> bool;
            pub fn set_seq_flags(&mut self, seq_flag: SequenceFlags);
        });
    }
}

use crate::util::{GenericUnsignedByteField, ToBeBytes, UnsignedEnum};
pub(crate) use ccsds_impl;
pub(crate) use sp_header_impls;

/// Generic trait for ECSS enumeration which consist of a PFC field denoting their bit length
/// and an unsigned value. The trait makes no assumptions about the actual type of the unsigned
/// value and only requires implementors to implement a function which writes the enumeration into
/// a raw byte format.
pub trait EcssEnumeration: UnsignedEnum {
    /// Packet Format Code, which denotes the number of bits of the enumeration
    fn pfc(&self) -> u8;
}

pub trait EcssEnumerationExt: EcssEnumeration + Debug + Copy + Clone + PartialEq + Eq {}

#[derive(Debug, Copy, Clone, Eq, PartialEq)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct GenericEcssEnumWrapper<TYPE> {
    field: GenericUnsignedByteField<TYPE>,
}

impl<TYPE> GenericEcssEnumWrapper<TYPE> {
    pub const fn ptc() -> PacketTypeCodes {
        PacketTypeCodes::Enumerated
    }

    pub fn new(val: TYPE) -> Self {
        Self {
            field: GenericUnsignedByteField::new(val),
        }
    }
}

impl<TYPE: ToBeBytes> UnsignedEnum for GenericEcssEnumWrapper<TYPE> {
    fn size(&self) -> usize {
        (self.pfc() / 8) as usize
    }

    fn write_to_be_bytes(&self, buf: &mut [u8]) -> Result<usize, ByteConversionError> {
        self.field.write_to_be_bytes(buf)
    }
}

impl<TYPE: ToBeBytes> EcssEnumeration for GenericEcssEnumWrapper<TYPE> {
    fn pfc(&self) -> u8 {
        size_of::<TYPE>() as u8 * 8_u8
    }
}

impl<TYPE: Debug + Copy + Clone + PartialEq + Eq + ToBeBytes> EcssEnumerationExt
    for GenericEcssEnumWrapper<TYPE>
{
}

pub type EcssEnumU8 = GenericEcssEnumWrapper<u8>;
pub type EcssEnumU16 = GenericEcssEnumWrapper<u16>;
pub type EcssEnumU32 = GenericEcssEnumWrapper<u32>;
pub type EcssEnumU64 = GenericEcssEnumWrapper<u64>;

/// Generic trait for PUS packet abstractions which can written to a raw slice as their raw
/// byte representation. This is especially useful for generic abstractions which depend only
/// on the serialization of those packets.
pub trait SerializablePusPacket {
    fn len_packed(&self) -> usize;
    fn write_to_bytes(&self, slice: &mut [u8]) -> Result<usize, PusError>;
}

#[cfg(test)]
mod tests {
    use crate::ecss::{EcssEnumU16, EcssEnumU32, EcssEnumU8, UnsignedEnum};
    use crate::ByteConversionError;

    #[test]
    fn test_enum_u8() {
        let mut buf = [0, 0, 0];
        let my_enum = EcssEnumU8::new(1);
        my_enum
            .write_to_be_bytes(&mut buf[1..2])
            .expect("To byte conversion of u8 failed");
        assert_eq!(buf[1], 1);
    }

    #[test]
    fn test_enum_u16() {
        let mut buf = [0, 0, 0];
        let my_enum = EcssEnumU16::new(0x1f2f);
        my_enum
            .write_to_be_bytes(&mut buf[1..3])
            .expect("To byte conversion of u8 failed");
        assert_eq!(buf[1], 0x1f);
        assert_eq!(buf[2], 0x2f);
    }

    #[test]
    fn test_slice_u16_too_small() {
        let mut buf = [0];
        let my_enum = EcssEnumU16::new(0x1f2f);
        let res = my_enum.write_to_be_bytes(&mut buf[0..1]);
        assert!(res.is_err());
        let error = res.unwrap_err();
        match error {
            ByteConversionError::ToSliceTooSmall(missmatch) => {
                assert_eq!(missmatch.expected, 2);
                assert_eq!(missmatch.found, 1);
            }
            _ => {
                panic!("Unexpected error {:?}", error);
            }
        }
    }

    #[test]
    fn test_enum_u32() {
        let mut buf = [0, 0, 0, 0, 0];
        let my_enum = EcssEnumU32::new(0x1f2f3f4f);
        my_enum
            .write_to_be_bytes(&mut buf[1..5])
            .expect("To byte conversion of u8 failed");
        assert_eq!(buf[1], 0x1f);
        assert_eq!(buf[2], 0x2f);
        assert_eq!(buf[3], 0x3f);
        assert_eq!(buf[4], 0x4f);
    }

    #[test]
    fn test_slice_u32_too_small() {
        let mut buf = [0, 0, 0, 0, 0];
        let my_enum = EcssEnumU32::new(0x1f2f3f4f);
        let res = my_enum.write_to_be_bytes(&mut buf[0..3]);
        assert!(res.is_err());
        let error = res.unwrap_err();
        match error {
            ByteConversionError::ToSliceTooSmall(missmatch) => {
                assert_eq!(missmatch.expected, 4);
                assert_eq!(missmatch.found, 3);
            }
            _ => {
                panic!("Unexpected error {:?}", error);
            }
        }
    }
}
