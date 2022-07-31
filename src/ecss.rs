//! Common definitions and helpers required to create PUS TMTC packets according to
//! [ECSS-E-ST-70-41C](https://ecss.nl/standard/ecss-e-st-70-41c-space-engineering-telemetry-and-telecommand-packet-utilization-15-april-2016/)
use crate::{CcsdsPacket, PacketError};
use core::mem::size_of;
use crc::{Crc, CRC_16_IBM_3740};
use serde::{Deserialize, Serialize};

pub type CrcType = u16;

/// CRC algorithm used by the PUS standard.
pub const CRC_CCITT_FALSE: Crc<u16> = Crc::<u16>::new(&CRC_16_IBM_3740);
pub const CCSDS_HEADER_LEN: usize = size_of::<crate::zc::SpHeader>();

/// All PUS versions. Only PUS C is supported by this library.
#[derive(PartialEq, Copy, Clone, Serialize, Deserialize, Debug)]
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

#[derive(Debug, Copy, Clone, PartialEq)]
pub enum PusError {
    VersionNotSupported(PusVersion),
    IncorrectCrc(u16),
    RawDataTooShort(usize),
    NoRawData,
    /// CRC16 needs to be calculated first
    CrcCalculationMissing,
    OtherPacketError(PacketError),
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
    curr_idx: usize,
    slice: &[u8],
) -> Result<u16, PusError> {
    let crc16;
    if calc_on_serialization {
        crc16 = calc_pus_crc16(&slice[0..curr_idx])
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

pub(crate) use ccsds_impl;
