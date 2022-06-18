use crate::{CcsdsPacket, PacketError};
use core::mem::size_of;
use crc::{Crc, CRC_16_IBM_3740};
use serde::{Deserialize, Serialize};

/// CRC algorithm used by the PUS standard
pub const CRC_CCITT_FALSE: Crc<u16> = Crc::<u16>::new(&CRC_16_IBM_3740);
pub const CCSDS_HEADER_LEN: usize = size_of::<crate::zc::SpHeader>();

/// All PUS versions. Only PUS C is supported by this library
#[derive(PartialEq, Copy, Clone, Serialize, Deserialize, Debug)]
pub enum PusVersion {
    EsaPus = 0,
    PusA = 1,
    PusC = 2,
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

    fn service(&self) -> u8;
    fn subservice(&self) -> u8;

    fn user_data(&self) -> Option<&[u8]>;
    fn crc16(&self) -> Option<u16>;
}
