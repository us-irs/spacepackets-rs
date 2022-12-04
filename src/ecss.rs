//! Common definitions and helpers required to create PUS TMTC packets according to
//! [ECSS-E-ST-70-41C](https://ecss.nl/standard/ecss-e-st-70-41c-space-engineering-telemetry-and-telecommand-packet-utilization-15-april-2016/)
use crate::{ByteConversionError, CcsdsPacket, SizeMissmatch};
use core::fmt::Debug;
use core::mem::size_of;
use crc::{Crc, CRC_16_IBM_3740};
#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

pub type CrcType = u16;

/// CRC algorithm used by the PUS standard.
pub const CRC_CCITT_FALSE: Crc<u16> = Crc::<u16>::new(&CRC_16_IBM_3740);
pub const CCSDS_HEADER_LEN: usize = size_of::<crate::zc::SpHeader>();

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

impl From<ByteConversionError> for PusError {
    fn from(e: ByteConversionError) -> Self {
        PusError::ByteConversionError(e)
    }
}

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

pub(crate) fn verify_crc16_from_raw(raw_data: &[u8], crc16: u16) -> Result<(), PusError> {
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

pub(crate) use ccsds_impl;
pub(crate) use sp_header_impls;

/// Generic trait for ECSS enumeration which consist of a PFC field denoting their bit length
/// and an unsigned value. The trait makes no assumptions about the actual type of the unsigned
/// value and only requires implementors to implement a function which writes the enumeration into
/// a raw byte format.
pub trait EcssEnumeration {
    /// Packet Format Code, which denotes the number of bits of the enumeration
    fn pfc(&self) -> u8;
    fn byte_width(&self) -> usize {
        (self.pfc() / 8) as usize
    }
    fn write_to_be_bytes(&self, buf: &mut [u8]) -> Result<(), ByteConversionError>;
}

pub trait EcssEnumerationExt: EcssEnumeration + Debug + Copy + Clone + PartialEq + Eq {}

pub trait ToBeBytes {
    type ByteArray: AsRef<[u8]>;
    fn to_be_bytes(&self) -> Self::ByteArray;
}

impl ToBeBytes for u8 {
    type ByteArray = [u8; 1];

    fn to_be_bytes(&self) -> Self::ByteArray {
        u8::to_be_bytes(*self)
    }
}

impl ToBeBytes for u16 {
    type ByteArray = [u8; 2];

    fn to_be_bytes(&self) -> Self::ByteArray {
        u16::to_be_bytes(*self)
    }
}

impl ToBeBytes for u32 {
    type ByteArray = [u8; 4];

    fn to_be_bytes(&self) -> Self::ByteArray {
        u32::to_be_bytes(*self)
    }
}

impl ToBeBytes for u64 {
    type ByteArray = [u8; 8];

    fn to_be_bytes(&self) -> Self::ByteArray {
        u64::to_be_bytes(*self)
    }
}

#[derive(Debug, Copy, Clone, Eq, PartialEq)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct GenericEcssEnumWrapper<TYPE> {
    val: TYPE,
}

impl<TYPE> GenericEcssEnumWrapper<TYPE> {
    pub const fn ptc() -> PacketTypeCodes {
        PacketTypeCodes::Enumerated
    }

    pub fn new(val: TYPE) -> Self {
        Self { val }
    }
}

impl<TYPE: ToBeBytes> EcssEnumeration for GenericEcssEnumWrapper<TYPE> {
    fn pfc(&self) -> u8 {
        size_of::<TYPE>() as u8 * 8_u8
    }

    fn write_to_be_bytes(&self, buf: &mut [u8]) -> Result<(), ByteConversionError> {
        if buf.len() < self.byte_width() as usize {
            return Err(ByteConversionError::ToSliceTooSmall(SizeMissmatch {
                found: buf.len(),
                expected: self.byte_width() as usize,
            }));
        }
        buf[0..self.byte_width() as usize].copy_from_slice(self.val.to_be_bytes().as_ref());
        Ok(())
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

#[cfg(test)]
mod tests {
    use crate::ecss::{EcssEnumU16, EcssEnumU32, EcssEnumU8, EcssEnumeration};
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
