/// CRC algorithm used by the PUS standard, the CCSDS TC standard and the CFDP standard, using
/// a [crc::NoTable] as the CRC implementation.
pub const CRC_CCITT_FALSE_NO_TABLE: crc::Crc<u16, crc::NoTable> =
    crc::Crc::<u16, crc::NoTable>::new(&crc::CRC_16_IBM_3740);
/// CRC algorithm used by the PUS standard, the CCSDS TC standard and the CFDP standard, using
/// [crc::Table<1>] as the CRC implementation.
pub const CRC_CCITT_FALSE: crc::Crc<u16> = crc::Crc::<u16>::new(&crc::CRC_16_IBM_3740);
/// CRC algorithm used by the PUS standard, the CCSDS TC standard and the CFDP standard, using
/// a [crc::Table<16>] large table as the CRC implementation.
pub const CRC_CCITT_FALSE_BIG_TABLE: crc::Crc<u16, crc::Table<16>> =
    crc::Crc::<u16, crc::Table<16>>::new(&crc::CRC_16_IBM_3740);
