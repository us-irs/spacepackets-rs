//! This module contains all components required to create a ECSS PUS C telecommand packets according
//! to [ECSS-E-ST-70-41C](https://ecss.nl/standard/ecss-e-st-70-41c-space-engineering-telemetry-and-telecommand-packet-utilization-15-april-2016/).
//!
//! # Examples
//!
//! ```rust
//! use spacepackets::{CcsdsPacket, SpHeader};
//! use spacepackets::ecss::{PusPacket, WritablePusPacket};
//! use spacepackets::ecss::tc::{PusTcCreator, PusTcReader, PusTcSecondaryHeader, CreatorConfig};
//!
//! // Create a ping telecommand with no user application data
//! let pus_tc = PusTcCreator::new_no_app_data(
//!     SpHeader::new_from_apid(0x02),
//!     PusTcSecondaryHeader::new_simple(17, 1),
//!     CreatorConfig::default()
//! );
//! println!("{:?}", pus_tc);
//! assert_eq!(pus_tc.service(), 17);
//! assert_eq!(pus_tc.subservice(), 1);
//! assert_eq!(pus_tc.apid(), 0x02);
//!
//! // Serialize TC into a raw buffer
//! let mut test_buf: [u8; 32] = [0; 32];
//! let size = pus_tc
//!     .write_to_bytes(test_buf.as_mut_slice())
//!     .expect("Error writing TC to buffer");
//! assert_eq!(size, 13);
//! println!("{:?}", &test_buf[0..size]);
//!
//! // Deserialize from the raw byte representation
//! let pus_tc_deserialized = PusTcReader::new(&test_buf).expect("Deserialization failed");
//! assert_eq!(pus_tc.service(), 17);
//! assert_eq!(pus_tc.subservice(), 1);
//! assert_eq!(pus_tc.apid(), 0x02);
//! ```
use crate::crc::{CRC_CCITT_FALSE, CRC_CCITT_FALSE_NO_TABLE};
pub use crate::ecss::CreatorConfig;
use crate::ecss::{
    ccsds_impl, crc_from_raw_data, sp_header_impls, user_data_from_raw,
    verify_crc16_ccitt_false_from_raw_to_pus_error, PusError, PusPacket, PusVersion,
    WritablePusPacket,
};
use crate::SpHeader;
use crate::{ByteConversionError, CcsdsPacket, PacketType, SequenceFlags, CCSDS_HEADER_LEN};
use core::mem::size_of;
use delegate::delegate;
use num_enum::{IntoPrimitive, TryFromPrimitive};
#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};
use zerocopy::{FromBytes, IntoBytes};

#[cfg(feature = "alloc")]
use alloc::vec::Vec;

use super::verify_crc16_ccitt_false_from_raw_to_pus_error_no_table;

/// PUS C secondary header length is fixed
pub const PUC_TC_SECONDARY_HEADER_LEN: usize = size_of::<zc::PusTcSecondaryHeader>();
pub const PUS_TC_MIN_LEN_WITHOUT_APP_DATA: usize = CCSDS_HEADER_LEN + PUC_TC_SECONDARY_HEADER_LEN;
const PUS_VERSION: PusVersion = PusVersion::PusC;

/// Marker trait for PUS telecommand structures.
pub trait IsPusTelecommand {}

#[derive(Debug, Eq, PartialEq, Copy, Clone, IntoPrimitive, TryFromPrimitive)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
#[repr(u8)]
enum AckOpts {
    Acceptance = 0b1000,
    Start = 0b0100,
    Progress = 0b0010,
    Completion = 0b0001,
}

pub const ACK_ALL: u8 = AckOpts::Acceptance as u8
    | AckOpts::Start as u8
    | AckOpts::Progress as u8
    | AckOpts::Completion as u8;

pub trait GenericPusTcSecondaryHeader {
    fn pus_version(&self) -> Result<PusVersion, u8>;
    fn ack_flags(&self) -> u8;
    fn service(&self) -> u8;
    fn subservice(&self) -> u8;
    fn source_id(&self) -> u16;
}

pub mod zc {
    use crate::ecss::tc::GenericPusTcSecondaryHeader;
    use crate::ecss::{PusError, PusVersion};
    use zerocopy::{FromBytes, Immutable, IntoBytes, NetworkEndian, Unaligned, U16};

    #[derive(FromBytes, IntoBytes, Immutable, Unaligned)]
    #[repr(C)]
    pub struct PusTcSecondaryHeader {
        version_ack: u8,
        service: u8,
        subservice: u8,
        source_id: U16<NetworkEndian>,
    }

    impl TryFrom<crate::ecss::tc::PusTcSecondaryHeader> for PusTcSecondaryHeader {
        type Error = PusError;
        fn try_from(value: crate::ecss::tc::PusTcSecondaryHeader) -> Result<Self, Self::Error> {
            if value.version != PusVersion::PusC {
                return Err(PusError::VersionNotSupported(value.version as u8));
            }
            Ok(PusTcSecondaryHeader {
                version_ack: ((value.version as u8) << 4) | value.ack,
                service: value.service,
                subservice: value.subservice,
                source_id: U16::from(value.source_id),
            })
        }
    }

    impl GenericPusTcSecondaryHeader for PusTcSecondaryHeader {
        #[inline]
        fn pus_version(&self) -> Result<PusVersion, u8> {
            PusVersion::try_from((self.version_ack >> 4) & 0b1111)
        }

        #[inline]
        fn ack_flags(&self) -> u8 {
            self.version_ack & 0b1111
        }

        #[inline]
        fn service(&self) -> u8 {
            self.service
        }

        #[inline]
        fn subservice(&self) -> u8 {
            self.subservice
        }

        #[inline]
        fn source_id(&self) -> u16 {
            self.source_id.get()
        }
    }
}

#[derive(PartialEq, Eq, Copy, Clone, Debug)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct PusTcSecondaryHeader {
    pub service: u8,
    pub subservice: u8,
    pub source_id: u16,
    pub ack: u8,
    pub version: PusVersion,
}

impl GenericPusTcSecondaryHeader for PusTcSecondaryHeader {
    #[inline]
    fn pus_version(&self) -> Result<PusVersion, u8> {
        Ok(self.version)
    }

    #[inline]
    fn ack_flags(&self) -> u8 {
        self.ack
    }

    #[inline]
    fn service(&self) -> u8 {
        self.service
    }

    #[inline]
    fn subservice(&self) -> u8 {
        self.subservice
    }

    #[inline]
    fn source_id(&self) -> u16 {
        self.source_id
    }
}

impl TryFrom<zc::PusTcSecondaryHeader> for PusTcSecondaryHeader {
    type Error = ();

    fn try_from(value: zc::PusTcSecondaryHeader) -> Result<Self, Self::Error> {
        Ok(PusTcSecondaryHeader {
            service: value.service(),
            subservice: value.subservice(),
            source_id: value.source_id(),
            ack: value.ack_flags(),
            version: PUS_VERSION,
        })
    }
}

impl PusTcSecondaryHeader {
    #[inline]
    pub fn new_simple(service: u8, subservice: u8) -> Self {
        PusTcSecondaryHeader {
            service,
            subservice,
            ack: ACK_ALL,
            source_id: 0,
            version: PusVersion::PusC,
        }
    }

    #[inline]
    pub fn new(service: u8, subservice: u8, ack: u8, source_id: u16) -> Self {
        PusTcSecondaryHeader {
            service,
            subservice,
            ack: ack & 0b1111,
            source_id,
            version: PusVersion::PusC,
        }
    }
}

/// This class can be used to create PUS C telecommand packet. It is the primary data structure to
/// generate the raw byte representation of a PUS telecommand.
///
/// This class also derives the [serde::Serialize] and [serde::Deserialize] trait if the
/// [serde] feature is used, which allows to send around TC packets in a raw byte format using a
/// serde provider like [postcard](https://docs.rs/postcard/latest/postcard/).
///
/// There is no spare bytes support yet.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct PusTcCreator<'app_data> {
    sp_header: SpHeader,
    pub sec_header: PusTcSecondaryHeader,
    app_data: &'app_data [u8],
    has_checksum: bool,
}

impl<'app_data> PusTcCreator<'app_data> {
    /// Generates a new struct instance.
    ///
    /// # Arguments
    ///
    /// * `sp_header` - Space packet header information. The correct packet type and the secondary
    ///   header flag are set correctly by the constructor.
    /// * `sec_header` - Information contained in the data field header, including the service
    ///   and subservice type
    /// * `app_data` - Custom application data
    /// * `packet_config` - Common configuration options for TC packet creation
    #[inline]
    pub fn new(
        mut sp_header: SpHeader,
        sec_header: PusTcSecondaryHeader,
        app_data: &'app_data [u8],
        packet_config: CreatorConfig,
    ) -> Self {
        sp_header.set_packet_type(PacketType::Tc);
        sp_header.set_sec_header_flag();
        let mut pus_tc = Self {
            sp_header,
            app_data,
            sec_header,
            has_checksum: packet_config.has_checksum,
        };
        if packet_config.set_ccsds_len {
            pus_tc.update_ccsds_data_len();
        }
        pus_tc
    }

    /// Simplified version of the [Self::new] function which allows to only specify service
    /// and subservice instead of the full PUS TC secondary header.
    #[inline]
    pub fn new_simple(
        sph: SpHeader,
        service: u8,
        subservice: u8,
        app_data: &'app_data [u8],
        packet_config: CreatorConfig,
    ) -> Self {
        Self::new(
            sph,
            PusTcSecondaryHeader::new(service, subservice, ACK_ALL, 0),
            app_data,
            packet_config,
        )
    }

    #[inline]
    pub fn new_no_app_data(
        sp_header: SpHeader,
        sec_header: PusTcSecondaryHeader,
        packet_config: CreatorConfig,
    ) -> Self {
        Self::new(sp_header, sec_header, &[], packet_config)
    }

    #[inline]
    pub fn sp_header(&self) -> &SpHeader {
        &self.sp_header
    }

    #[inline]
    pub fn sp_header_mut(&mut self) -> &mut SpHeader {
        &mut self.sp_header
    }

    #[inline]
    pub fn set_ack_field(&mut self, ack: u8) -> bool {
        if ack > 0b1111 {
            return false;
        }
        self.sec_header.ack = ack & 0b1111;
        true
    }

    #[inline]
    pub fn set_source_id(&mut self, source_id: u16) {
        self.sec_header.source_id = source_id;
    }

    sp_header_impls!();

    /// Calculate the CCSDS space packet data length field and sets it
    /// This is called automatically if the `set_ccsds_len` argument in the [Self::new] call was
    /// used.
    /// If this was not done or the application data is set or changed after construction,
    /// this function needs to be called to ensure that the data length field of the CCSDS header
    /// is set correctly.
    #[inline]
    pub fn update_ccsds_data_len(&mut self) {
        self.sp_header.data_len =
            self.len_written() as u16 - size_of::<crate::zc::SpHeader>() as u16 - 1;
    }

    /// This function calculates and returns the CRC16 for the current packet.
    pub fn calc_own_crc16(&self) -> u16 {
        let mut digest = CRC_CCITT_FALSE.digest();
        let sph_zc = crate::zc::SpHeader::from(self.sp_header);
        digest.update(sph_zc.as_bytes());
        let pus_tc_header = zc::PusTcSecondaryHeader::try_from(self.sec_header).unwrap();
        digest.update(pus_tc_header.as_bytes());
        digest.update(self.app_data);
        digest.finalize()
    }

    /// This function calculates and returns the CRC16 for the current packet.
    pub fn calc_own_crc16_no_table(&self) -> u16 {
        let mut digest = CRC_CCITT_FALSE_NO_TABLE.digest();
        let sph_zc = crate::zc::SpHeader::from(self.sp_header);
        digest.update(sph_zc.as_bytes());
        let pus_tc_header = zc::PusTcSecondaryHeader::try_from(self.sec_header).unwrap();
        digest.update(pus_tc_header.as_bytes());
        digest.update(self.app_data);
        digest.finalize()
    }

    #[inline]
    pub fn has_checksum(&self) -> bool {
        self.has_checksum
    }

    #[cfg(feature = "alloc")]
    pub fn append_to_vec(&self, vec: &mut Vec<u8>) -> usize {
        let sph_zc = crate::zc::SpHeader::from(self.sp_header);
        let mut appended_len = PUS_TC_MIN_LEN_WITHOUT_APP_DATA;
        appended_len += self.app_data.len();
        let start_idx = vec.len();
        vec.extend_from_slice(sph_zc.as_bytes());
        // The PUS version is hardcoded to PUS C
        let pus_tc_header = zc::PusTcSecondaryHeader::try_from(self.sec_header).unwrap();
        vec.extend_from_slice(pus_tc_header.as_bytes());
        vec.extend_from_slice(self.app_data);
        if self.has_checksum() {
            let mut digest = CRC_CCITT_FALSE.digest();
            digest.update(&vec[start_idx..start_idx + appended_len]);
            vec.extend_from_slice(&digest.finalize().to_be_bytes());
            appended_len += 2;
        }
        appended_len
    }

    /// Write the raw PUS byte representation to a provided buffer.
    pub fn write_to_bytes(&self, slice: &mut [u8]) -> Result<usize, ByteConversionError> {
        let writer_unfinalized = self.common_write(slice)?;
        Ok(writer_unfinalized.finalize())
    }

    /// Write the raw PUS byte representation to a provided buffer.
    pub fn write_to_bytes_crc_no_table(
        &self,
        slice: &mut [u8],
    ) -> Result<usize, ByteConversionError> {
        let writer_unfinalized = self.common_write(slice)?;
        Ok(writer_unfinalized.finalize_checksum_no_table())
    }

    /// Write the raw PUS byte representation to a provided buffer.
    pub fn write_to_bytes_no_crc(&self, slice: &mut [u8]) -> Result<usize, ByteConversionError> {
        let writer_unfinalized = self.common_write(slice)?;
        Ok(writer_unfinalized.finalize_no_checksum())
    }

    fn common_write<'a>(
        &self,
        slice: &'a mut [u8],
    ) -> Result<PusTcCreatorWithReservedAppData<'a>, ByteConversionError> {
        if self.len_written() > slice.len() {
            return Err(ByteConversionError::ToSliceTooSmall {
                found: slice.len(),
                expected: self.len_written(),
            });
        }
        let mut writer_unfinalized = PusTcCreatorWithReservedAppData::write_to_bytes_partially(
            slice,
            self.sp_header,
            self.sec_header,
            self.app_data.len(),
            self.has_checksum,
        )?;
        writer_unfinalized
            .app_data_mut()
            .copy_from_slice(self.app_data);
        Ok(writer_unfinalized)
    }
}

impl WritablePusPacket for PusTcCreator<'_> {
    #[inline]
    fn len_written(&self) -> usize {
        let mut len = PUS_TC_MIN_LEN_WITHOUT_APP_DATA + self.app_data.len();
        if self.has_checksum() {
            len += 2;
        }
        len
    }

    #[inline]
    fn has_checksum(&self) -> bool {
        self.has_checksum()
    }

    /// Write the raw PUS byte representation to a provided buffer.
    fn write_to_bytes_no_checksum(&self, slice: &mut [u8]) -> Result<usize, PusError> {
        Ok(Self::write_to_bytes_no_crc(self, slice)?)
    }

    fn write_to_bytes(&self, slice: &mut [u8]) -> Result<usize, PusError> {
        Ok(Self::write_to_bytes(self, slice)?)
    }

    fn write_to_bytes_checksum_no_table(&self, slice: &mut [u8]) -> Result<usize, PusError> {
        Ok(Self::write_to_bytes_crc_no_table(self, slice)?)
    }
}

impl CcsdsPacket for PusTcCreator<'_> {
    ccsds_impl!();
}

impl PusPacket for PusTcCreator<'_> {
    delegate!(to self.sec_header {
        #[inline]
        fn pus_version(&self) -> Result<PusVersion, u8>;
        #[inline]
        fn service(&self) -> u8;
        #[inline]
        fn subservice(&self) -> u8;
    });

    #[inline]
    fn user_data(&self) -> &[u8] {
        self.app_data
    }

    #[inline]
    fn checksum(&self) -> Option<u16> {
        if !self.has_checksum {
            return None;
        }
        Some(self.calc_own_crc16())
    }

    fn has_checksum(&self) -> bool {
        self.has_checksum
    }
}

impl GenericPusTcSecondaryHeader for PusTcCreator<'_> {
    delegate!(to self.sec_header {
        #[inline]
        fn pus_version(&self) -> Result<PusVersion, u8>;
        #[inline]
        fn service(&self) -> u8;
        #[inline]
        fn subservice(&self) -> u8;
        #[inline]
        fn source_id(&self) -> u16;
        #[inline]
        fn ack_flags(&self) -> u8;
    });
}

impl IsPusTelecommand for PusTcCreator<'_> {}

/// A specialized variant of [PusTcCreator] designed for efficiency when handling large source
/// data.
///
/// Unlike [PusTcCreator], this type does not require the user to provide the application data
/// as a separate slice. Instead, it allows writing the application data directly into the provided
/// serialization buffer. This eliminates the need for an intermediate buffer and the associated
/// memory copy, improving performance, particularly when working with large payloads.
///
/// **Important:** The total length of the source data must be known and specified in advance
/// to ensure correct serialization behavior.
///
/// Note that this abstraction intentionally omits certain trait implementations that are available
/// on [PusTcCreator], as they are not applicable in this optimized usage pattern.
pub struct PusTcCreatorWithReservedAppData<'buf> {
    buf: &'buf mut [u8],
    app_data_offset: usize,
    full_len: usize,
    has_checksum: bool,
}

impl<'buf> PusTcCreatorWithReservedAppData<'buf> {
    /// Generates a new instance with reserved space for the user application data.
    ///
    /// # Arguments
    ///
    /// * `sp_header` - Space packet header information. The correct packet type and the secondary
    ///   header flag are set correctly by the constructor.
    /// * `sec_header` - Information contained in the secondary header, including the service
    ///   and subservice type
    /// * `app_data_len` - Custom application data length
    #[inline]
    pub fn new(
        buf: &'buf mut [u8],
        mut sp_header: SpHeader,
        sec_header: PusTcSecondaryHeader,
        app_data_len: usize,
        has_checksum: bool,
    ) -> Result<Self, ByteConversionError> {
        sp_header.set_packet_type(PacketType::Tc);
        sp_header.set_sec_header_flag();
        let mut len_written = PUS_TC_MIN_LEN_WITHOUT_APP_DATA + app_data_len;
        if has_checksum {
            len_written += 2;
        }
        if len_written > buf.len() {
            return Err(ByteConversionError::ToSliceTooSmall {
                found: buf.len(),
                expected: len_written,
            });
        }
        sp_header.data_len = len_written as u16 - size_of::<crate::zc::SpHeader>() as u16 - 1;
        Self::write_to_bytes_partially(buf, sp_header, sec_header, app_data_len, has_checksum)
    }

    fn write_to_bytes_partially(
        buf: &'buf mut [u8],
        sp_header: SpHeader,
        sec_header: PusTcSecondaryHeader,
        app_data_len: usize,
        has_checksum: bool,
    ) -> Result<Self, ByteConversionError> {
        let mut curr_idx = 0;
        sp_header.write_to_be_bytes(&mut buf[0..CCSDS_HEADER_LEN])?;
        curr_idx += CCSDS_HEADER_LEN;
        let sec_header_len = size_of::<zc::PusTcSecondaryHeader>();
        let sec_header_zc = zc::PusTcSecondaryHeader::try_from(sec_header).unwrap();
        sec_header_zc
            .write_to(&mut buf[curr_idx..curr_idx + sec_header_len])
            .map_err(|_| ByteConversionError::ZeroCopyToError)?;
        curr_idx += sec_header_len;
        let app_data_offset = curr_idx;
        curr_idx += app_data_len;
        if has_checksum {
            curr_idx += 2;
        }
        Ok(Self {
            buf,
            app_data_offset,
            full_len: curr_idx,
            has_checksum,
        })
    }

    #[inline]
    pub const fn len_written(&self) -> usize {
        self.full_len
    }

    /// Mutable access to the application data buffer.
    #[inline]
    pub fn app_data_mut(&mut self) -> &mut [u8] {
        let end_index = if self.has_checksum {
            self.full_len - 2
        } else {
            self.full_len
        };
        &mut self.buf[self.app_data_offset..end_index]
    }

    /// Access to the source data buffer.
    #[inline]
    pub fn app_data(&self) -> &[u8] {
        let end_index = if self.has_checksum {
            self.full_len - 2
        } else {
            self.full_len
        };
        &self.buf[self.app_data_offset..end_index]
    }

    #[inline]
    pub fn app_data_len(&self) -> usize {
        let mut len = self.full_len - self.app_data_offset;
        if self.has_checksum {
            len -= 2;
        }
        len
    }

    /// Finalize the TC packet by calculating and writing the CRC16 if checksum generation is
    /// enabled.
    ///
    /// Returns the full packet length.
    pub fn finalize(self) -> usize {
        let written_len = self.len_written();
        if self.has_checksum {
            let mut digest = CRC_CCITT_FALSE.digest();
            digest.update(&self.buf[0..written_len - 2]);
            self.buf[self.full_len - 2..written_len]
                .copy_from_slice(&digest.finalize().to_be_bytes());
        }
        written_len
    }

    /// Finalize the TC packet by calculating and writing the CRC16 using a table-less
    /// implementation if checksum genration is enabled.
    ///
    /// Returns the full packet length.
    pub fn finalize_checksum_no_table(self) -> usize {
        let written_len = self.len_written();
        if self.has_checksum {
            let mut digest = CRC_CCITT_FALSE_NO_TABLE.digest();
            digest.update(&self.buf[0..written_len - 2]);
            self.buf[self.full_len - 2..written_len]
                .copy_from_slice(&digest.finalize().to_be_bytes());
        }
        written_len
    }

    /// Finalize the TC packet without writing the CRC16 checksum.
    ///
    /// Returns the length WITHOUT the CRC16 checksum.
    #[inline]
    pub fn finalize_no_checksum(self) -> usize {
        if self.has_checksum {
            self.full_len - 2
        } else {
            self.full_len
        }
    }
}

/// This class can be used to read a PUS TC telecommand from raw memory.
///
/// This class also derives the [serde::Serialize] and [serde::Deserialize] trait if the
/// [serde] feature is used, which allows to send around TC packets in a raw byte format using a
/// serde provider like [postcard](https://docs.rs/postcard/latest/postcard/).
///
/// There is no spare bytes support yet.
///
/// # Lifetimes
///
/// * `'raw_data` - Lifetime of the provided raw slice.
#[derive(Eq, Copy, Clone, Debug)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct PusTcReader<'raw_data> {
    #[cfg_attr(feature = "serde", serde(skip))]
    raw_data: &'raw_data [u8],
    sp_header: SpHeader,
    sec_header: PusTcSecondaryHeader,
    app_data: &'raw_data [u8],
    crc16: Option<u16>,
}

impl<'raw_data> PusTcReader<'raw_data> {
    /// Create a [PusTcReader] instance from a raw slice. The given packet should have a
    /// a CRC16-CCITT checksum which is also verified.
    ///
    /// On success, it returns a tuple containing the instance and the found byte length of the
    /// packet. This function also expects a CRC16 checksum and will verify it.
    pub fn new(slice: &'raw_data [u8]) -> Result<Self, PusError> {
        let pus_tc = Self::new_no_checksum_verification(slice, true)?;
        // Unwrap for CRC16 okay, should always have some value.
        verify_crc16_ccitt_false_from_raw_to_pus_error(pus_tc.raw_data(), pus_tc.crc16().unwrap())?;
        Ok(pus_tc)
    }

    /// Similar to [PusTcReader::new], but uses a table-less CRC16 algorithm which can reduce
    /// binary size and memory usage.
    pub fn new_checksum_no_table(slice: &'raw_data [u8]) -> Result<Self, PusError> {
        let pus_tc = Self::new_no_checksum_verification(slice, true)?;
        // Unwrap for CRC16 okay, should always have some value.
        verify_crc16_ccitt_false_from_raw_to_pus_error_no_table(
            pus_tc.raw_data(),
            pus_tc.crc16().unwrap(),
        )?;
        Ok(pus_tc)
    }

    /// Read a PUS TC from a raw slice where no checksum is expected.
    pub fn new_no_checksum(slice: &'raw_data [u8]) -> Result<Self, PusError> {
        Self::new_no_checksum_verification(slice, false)
    }

    /// Create a new [Self] instance without verifying the checksum, even if the packet has one.
    pub fn new_no_checksum_verification(
        slice: &'raw_data [u8],
        has_checksum: bool,
    ) -> Result<Self, PusError> {
        let raw_data_len = slice.len();
        if raw_data_len < PUS_TC_MIN_LEN_WITHOUT_APP_DATA {
            return Err(ByteConversionError::FromSliceTooSmall {
                found: raw_data_len,
                expected: PUS_TC_MIN_LEN_WITHOUT_APP_DATA,
            }
            .into());
        }
        let mut current_idx = 0;
        let (sp_header, _) = SpHeader::from_be_bytes(&slice[0..CCSDS_HEADER_LEN])?;
        current_idx += CCSDS_HEADER_LEN;
        let total_len = sp_header.packet_len();
        if raw_data_len < total_len {
            return Err(ByteConversionError::FromSliceTooSmall {
                found: raw_data_len,
                expected: total_len,
            }
            .into());
        }
        if total_len < PUS_TC_MIN_LEN_WITHOUT_APP_DATA {
            return Err(ByteConversionError::FromSliceTooSmall {
                found: total_len,
                expected: PUS_TC_MIN_LEN_WITHOUT_APP_DATA,
            }
            .into());
        }
        let sec_header = zc::PusTcSecondaryHeader::read_from_bytes(
            &slice[current_idx..current_idx + PUC_TC_SECONDARY_HEADER_LEN],
        )
        .map_err(|_| ByteConversionError::ZeroCopyFromError)?;
        current_idx += PUC_TC_SECONDARY_HEADER_LEN;
        let raw_data = &slice[0..total_len];
        let mut crc16 = None;
        if has_checksum {
            crc16 = Some(crc_from_raw_data(&slice[total_len - 2..total_len])?);
        }
        Ok(Self {
            sp_header,
            sec_header: PusTcSecondaryHeader::try_from(sec_header).unwrap(),
            raw_data,
            app_data: user_data_from_raw(current_idx, total_len, slice, has_checksum)?,
            crc16,
        })
    }

    #[inline]
    pub fn app_data(&self) -> &[u8] {
        self.user_data()
    }

    #[inline]
    pub fn raw_data(&self) -> &[u8] {
        self.raw_data
    }

    #[inline]
    pub fn len_packed(&self) -> usize {
        self.sp_header.packet_len()
    }

    #[inline]
    pub fn sp_header(&self) -> &SpHeader {
        &self.sp_header
    }

    #[inline]
    pub fn crc16(&self) -> Option<u16> {
        self.crc16
    }
}

impl PartialEq for PusTcReader<'_> {
    #[inline]
    fn eq(&self, other: &Self) -> bool {
        self.raw_data == other.raw_data
    }
}

impl CcsdsPacket for PusTcReader<'_> {
    ccsds_impl!();
}

impl PusPacket for PusTcReader<'_> {
    delegate!(to self.sec_header {
        #[inline]
        fn pus_version(&self) -> Result<PusVersion, u8>;
        #[inline]
        fn service(&self) -> u8;
        #[inline]
        fn subservice(&self) -> u8;
    });

    fn has_checksum(&self) -> bool {
        self.crc16.is_some()
    }

    #[inline]
    fn user_data(&self) -> &[u8] {
        self.app_data
    }

    #[inline]
    fn checksum(&self) -> Option<u16> {
        self.crc16
    }
}

impl GenericPusTcSecondaryHeader for PusTcReader<'_> {
    delegate!(to self.sec_header {
        #[inline]
        fn pus_version(&self) -> Result<PusVersion, u8>;
        #[inline]
        fn service(&self) -> u8;
        #[inline]
        fn subservice(&self) -> u8;
        #[inline]
        fn source_id(&self) -> u16;
        #[inline]
        fn ack_flags(&self) -> u8;
    });
}

impl IsPusTelecommand for PusTcReader<'_> {}

impl PartialEq<PusTcCreator<'_>> for PusTcReader<'_> {
    fn eq(&self, other: &PusTcCreator) -> bool {
        self.sp_header == other.sp_header
            && self.sec_header == other.sec_header
            && self.app_data == other.app_data
    }
}

impl PartialEq<PusTcReader<'_>> for PusTcCreator<'_> {
    fn eq(&self, other: &PusTcReader) -> bool {
        self.sp_header == other.sp_header
            && self.sec_header == other.sec_header
            && self.app_data == other.app_data
    }
}

#[cfg(all(test, feature = "std"))]
mod tests {
    use super::*;
    use crate::ecss::PusVersion::PusC;
    use crate::ecss::{PusError, PusPacket, WritablePusPacket};
    use crate::{ByteConversionError, SpHeader};
    use crate::{CcsdsPacket, SequenceFlags};
    use alloc::string::ToString;
    use alloc::vec::Vec;
    #[cfg(feature = "serde")]
    use postcard::{from_bytes, to_allocvec};

    fn base_ping_tc_full_ctor() -> PusTcCreator<'static> {
        let sph = SpHeader::new_for_unseg_tc_checked(0x02, 0x34, 0).unwrap();
        let tc_header = PusTcSecondaryHeader::new_simple(17, 1);
        PusTcCreator::new_no_app_data(sph, tc_header, CreatorConfig::default())
    }

    fn base_ping_tc_full_ctor_no_checksum() -> PusTcCreator<'static> {
        let sph = SpHeader::new_for_unseg_tc_checked(0x02, 0x34, 0).unwrap();
        let tc_header = PusTcSecondaryHeader::new_simple(17, 1);
        PusTcCreator::new_no_app_data(
            sph,
            tc_header,
            CreatorConfig {
                set_ccsds_len: true,
                has_checksum: false,
            },
        )
    }

    fn base_ping_tc_simple_ctor() -> PusTcCreator<'static> {
        let sph = SpHeader::new_for_unseg_tc_checked(0x02, 0x34, 0).unwrap();
        PusTcCreator::new_simple(sph, 17, 1, &[], CreatorConfig::default())
    }

    fn base_ping_tc_simple_ctor_no_checksum() -> PusTcCreator<'static> {
        let sph = SpHeader::new_for_unseg_tc_checked(0x02, 0x34, 0).unwrap();
        PusTcCreator::new_simple(
            sph,
            17,
            1,
            &[],
            CreatorConfig {
                set_ccsds_len: true,
                has_checksum: false,
            },
        )
    }

    fn base_ping_tc_simple_ctor_with_app_data(
        app_data: &'static [u8],
        has_checksum: bool,
    ) -> PusTcCreator<'static> {
        let sph = SpHeader::new_for_unseg_tc_checked(0x02, 0x34, 0).unwrap();
        PusTcCreator::new_simple(
            sph,
            17,
            1,
            app_data,
            CreatorConfig {
                set_ccsds_len: true,
                has_checksum,
            },
        )
    }

    #[test]
    fn test_tc_fields() {
        let pus_tc = base_ping_tc_full_ctor();
        verify_test_tc(&pus_tc, false, true, 13);
    }

    #[test]
    fn test_tc_fields_no_checksum() {
        let pus_tc = base_ping_tc_full_ctor_no_checksum();
        verify_test_tc(&pus_tc, false, false, 11);
    }

    #[test]
    fn test_serialization() {
        let pus_tc = base_ping_tc_simple_ctor();
        let mut test_buf: [u8; 32] = [0; 32];
        let size = pus_tc
            .write_to_bytes(test_buf.as_mut_slice())
            .expect("Error writing TC to buffer");
        assert_eq!(size, 13);
        assert_eq!(
            pus_tc.checksum().unwrap(),
            u16::from_be_bytes(test_buf[size - 2..size].try_into().unwrap())
        );
    }

    #[test]
    fn test_serialization_no_checksum() {
        let pus_tc = base_ping_tc_simple_ctor_no_checksum();
        let mut test_buf: [u8; 32] = [0; 32];
        let size = pus_tc
            .write_to_bytes(test_buf.as_mut_slice())
            .expect("Error writing TC to buffer");
        assert_eq!(size, 11);
        assert_eq!(0, u16::from_be_bytes(test_buf[11..13].try_into().unwrap()));
        verify_test_tc(&pus_tc, false, false, 11);
    }

    #[test]
    fn test_serialization_with_trait_1() {
        let pus_tc = base_ping_tc_simple_ctor();
        let mut test_buf: [u8; 32] = [0; 32];
        let size = WritablePusPacket::write_to_bytes(&pus_tc, test_buf.as_mut_slice())
            .expect("Error writing TC to buffer");
        assert_eq!(size, 13);
        assert_eq!(
            pus_tc.checksum().unwrap(),
            u16::from_be_bytes(test_buf[size - 2..size].try_into().unwrap())
        );
    }

    #[test]
    fn test_serialization_with_trait_2() {
        let pus_tc = base_ping_tc_simple_ctor();
        let mut test_buf: [u8; 32] = [0; 32];
        let size =
            WritablePusPacket::write_to_bytes_checksum_no_table(&pus_tc, test_buf.as_mut_slice())
                .expect("Error writing TC to buffer");
        assert_eq!(size, 13);
        assert_eq!(
            pus_tc.checksum().unwrap(),
            u16::from_be_bytes(test_buf[size - 2..size].try_into().unwrap())
        );
    }

    #[test]
    fn test_serialization_crc_no_table() {
        let pus_tc = base_ping_tc_simple_ctor();
        let mut test_buf: [u8; 32] = [0; 32];
        let size = pus_tc
            .write_to_bytes_crc_no_table(test_buf.as_mut_slice())
            .expect("error writing tc to buffer");
        assert_eq!(size, 13);
        assert_eq!(
            pus_tc.checksum().unwrap(),
            u16::from_be_bytes(test_buf[size - 2..size].try_into().unwrap())
        );
    }

    #[test]
    fn test_serialization_no_checksum_generation() {
        let pus_tc = base_ping_tc_simple_ctor();
        let mut test_buf: [u8; 32] = [0; 32];
        let size = pus_tc
            .write_to_bytes_no_crc(test_buf.as_mut_slice())
            .expect("error writing tc to buffer");
        assert_eq!(size, 11);
        assert_eq!(test_buf[11], 0);
        assert_eq!(test_buf[12], 0);
    }

    #[test]
    fn test_serialization_no_checksum_with_trait() {
        let pus_tc = base_ping_tc_simple_ctor();
        let mut test_buf: [u8; 32] = [0; 32];
        let size = WritablePusPacket::write_to_bytes_no_checksum(&pus_tc, test_buf.as_mut_slice())
            .expect("error writing tc to buffer");
        assert_eq!(size, 11);
        assert_eq!(test_buf[11], 0);
        assert_eq!(test_buf[12], 0);
    }

    #[test]
    fn test_deserialization() {
        let pus_tc = base_ping_tc_simple_ctor();
        let mut test_buf: [u8; 32] = [0; 32];
        let size = pus_tc
            .write_to_bytes(test_buf.as_mut_slice())
            .expect("Error writing TC to buffer");
        assert_eq!(size, 13);
        let tc_from_raw =
            PusTcReader::new(&test_buf).expect("Creating PUS TC struct from raw buffer failed");
        assert_eq!(tc_from_raw.packet_len(), 13);
        verify_test_tc_with_reader(&tc_from_raw, false, 13);
        assert!(tc_from_raw.user_data().is_empty());
        verify_test_tc_raw(&test_buf);
        verify_crc_no_app_data(&test_buf);
    }

    #[test]
    fn test_deserialization_alt_ctor() {
        let sph = SpHeader::new_for_unseg_tc_checked(0x02, 0x34, 0).unwrap();
        let tc_header = PusTcSecondaryHeader::new_simple(17, 1);
        let mut test_buf: [u8; 32] = [0; 32];
        let mut pus_tc =
            PusTcCreatorWithReservedAppData::new(&mut test_buf, sph, tc_header, 0, true).unwrap();
        assert_eq!(pus_tc.len_written(), 13);
        assert_eq!(pus_tc.app_data_len(), 0);
        assert_eq!(pus_tc.app_data(), &[]);
        assert_eq!(pus_tc.app_data_mut(), &[]);
        let size = pus_tc.finalize();
        assert_eq!(size, 13);
        let tc_from_raw =
            PusTcReader::new(&test_buf).expect("Creating PUS TC struct from raw buffer failed");
        assert_eq!(tc_from_raw.packet_len(), 13);
        verify_test_tc_with_reader(&tc_from_raw, false, 13);
        assert!(tc_from_raw.user_data().is_empty());
        verify_test_tc_raw(&test_buf);
        verify_crc_no_app_data(&test_buf);
    }

    #[test]
    fn test_deserialization_no_table() {
        let pus_tc = base_ping_tc_simple_ctor();
        let mut test_buf: [u8; 32] = [0; 32];
        let size = pus_tc
            .write_to_bytes(test_buf.as_mut_slice())
            .expect("Error writing TC to buffer");
        assert_eq!(size, 13);
        let tc_from_raw = PusTcReader::new_checksum_no_table(&test_buf)
            .expect("Creating PUS TC struct from raw buffer failed");
        assert_eq!(tc_from_raw.packet_len(), 13);
        verify_test_tc_with_reader(&tc_from_raw, false, 13);
        assert!(tc_from_raw.user_data().is_empty());
        verify_test_tc_raw(&test_buf);
        verify_crc_no_app_data(&test_buf);
    }

    #[test]
    fn test_writing_into_vec() {
        let pus_tc = base_ping_tc_simple_ctor();
        let tc_vec = pus_tc.to_vec().expect("Error writing TC to buffer");
        assert_eq!(tc_vec.len(), 13);
        let tc_from_raw = PusTcReader::new(tc_vec.as_slice())
            .expect("Creating PUS TC struct from raw buffer failed");
        assert_eq!(tc_from_raw.packet_len(), 13);
        verify_test_tc_with_reader(&tc_from_raw, false, 13);
        assert!(tc_from_raw.user_data().is_empty());
        verify_test_tc_raw(&tc_vec);
        verify_crc_no_app_data(&tc_vec);
    }

    #[test]
    fn test_update_func() {
        let sph = SpHeader::new_for_unseg_tc_checked(0x02, 0x34, 0).unwrap();
        let mut tc = PusTcCreator::new_simple(
            sph,
            17,
            1,
            &[],
            CreatorConfig {
                set_ccsds_len: false,
                has_checksum: true,
            },
        );
        assert_eq!(tc.data_len(), 0);
        tc.update_ccsds_data_len();
        assert_eq!(tc.data_len(), 6);
    }

    #[test]
    fn test_deserialization_with_app_data() {
        let pus_tc = base_ping_tc_simple_ctor_with_app_data(&[1, 2, 3], true);
        let mut test_buf: [u8; 32] = [0; 32];
        let size = pus_tc
            .write_to_bytes(test_buf.as_mut_slice())
            .expect("Error writing TC to buffer");
        assert_eq!(size, 16);
        let tc_from_raw =
            PusTcReader::new(&test_buf).expect("Creating PUS TC struct from raw buffer failed");
        assert_eq!(tc_from_raw.packet_len(), 16);
        verify_test_tc_with_reader(&tc_from_raw, true, 16);
        let user_data = tc_from_raw.user_data();
        assert_eq!(tc_from_raw.user_data(), tc_from_raw.app_data());
        assert_eq!(tc_from_raw.raw_data(), &test_buf[..size]);
        assert_eq!(
            tc_from_raw.checksum().unwrap(),
            u16::from_be_bytes(test_buf[size - 2..size].try_into().unwrap())
        );
        assert_eq!(user_data[0], 1);
        assert_eq!(user_data[1], 2);
        assert_eq!(user_data[2], 3);
    }

    #[test]
    fn test_deserialization_with_app_data_no_checksum() {
        let pus_tc = base_ping_tc_simple_ctor_with_app_data(&[1, 2, 3], false);
        let mut test_buf: [u8; 32] = [0; 32];
        let size = pus_tc
            .write_to_bytes(test_buf.as_mut_slice())
            .expect("Error writing TC to buffer");
        assert_eq!(size, 14);
        let tc_from_raw = PusTcReader::new_no_checksum(&test_buf)
            .expect("Creating PUS TC struct from raw buffer failed");
        assert_eq!(tc_from_raw.packet_len(), 14);
        verify_test_tc_with_reader(&tc_from_raw, true, 14);
        let user_data = tc_from_raw.user_data();
        assert_eq!(tc_from_raw.user_data(), tc_from_raw.app_data());
        assert_eq!(tc_from_raw.raw_data(), &test_buf[..size]);
        assert_eq!(
            0,
            u16::from_be_bytes(test_buf[size..size + 2].try_into().unwrap())
        );
        assert_eq!(user_data[0], 1);
        assert_eq!(user_data[1], 2);
        assert_eq!(user_data[2], 3);
    }

    #[test]
    fn test_reader_eq() {
        let pus_tc = base_ping_tc_simple_ctor_with_app_data(&[1, 2, 3], true);
        let mut test_buf: [u8; 32] = [0; 32];
        pus_tc
            .write_to_bytes(test_buf.as_mut_slice())
            .expect("Error writing TC to buffer");
        let tc_from_raw_0 =
            PusTcReader::new(&test_buf).expect("Creating PUS TC struct from raw buffer failed");
        let tc_from_raw_1 =
            PusTcReader::new(&test_buf).expect("Creating PUS TC struct from raw buffer failed");
        assert_eq!(tc_from_raw_0, tc_from_raw_1);
    }

    #[test]
    fn test_vec_ser_deser() {
        let pus_tc = base_ping_tc_simple_ctor();
        let mut test_vec = Vec::new();
        let size = pus_tc.append_to_vec(&mut test_vec);
        assert_eq!(size, 13);
        verify_test_tc_raw(&test_vec.as_slice());
        verify_crc_no_app_data(&test_vec.as_slice());
    }

    #[test]
    fn test_incorrect_crc() {
        let pus_tc = base_ping_tc_simple_ctor();
        let mut test_buf: [u8; 32] = [0; 32];
        pus_tc
            .write_to_bytes(test_buf.as_mut_slice())
            .expect("Error writing TC to buffer");
        test_buf[12] = 0;
        test_buf[11] = 0;
        let res = PusTcReader::new(&test_buf);
        assert!(res.is_err());
        let err = res.unwrap_err();
        if let PusError::ChecksumFailure(crc) = err {
            assert_eq!(crc, 0);
            assert_eq!(
                err.to_string(),
                "checksum verification for crc16 0x0000 failed"
            );
        } else {
            panic!("unexpected error {err}");
        }
    }

    #[test]
    fn test_manual_crc_calculation() {
        let pus_tc = base_ping_tc_simple_ctor();
        let mut test_buf: [u8; 32] = [0; 32];
        pus_tc.calc_own_crc16();
        pus_tc
            .write_to_bytes(test_buf.as_mut_slice())
            .expect("Error writing TC to buffer");
        verify_test_tc_raw(&test_buf);
        verify_crc_no_app_data(&test_buf);
    }

    #[test]
    fn test_with_application_data_vec() {
        let pus_tc = base_ping_tc_simple_ctor_with_app_data(&[1, 2, 3], true);
        verify_test_tc(&pus_tc, true, true, 16);
        let mut test_vec = Vec::new();
        let size = pus_tc.append_to_vec(&mut test_vec);
        assert_eq!(test_vec[11], 1);
        assert_eq!(test_vec[12], 2);
        assert_eq!(test_vec[13], 3);
        assert_eq!(size, 16);
    }

    #[test]
    fn test_write_buf_too_small() {
        let pus_tc = base_ping_tc_simple_ctor();
        let mut test_buf = [0; 12];
        let res = pus_tc.write_to_bytes(test_buf.as_mut_slice());
        assert!(res.is_err());
        let err = res.unwrap_err();
        assert_eq!(
            err,
            ByteConversionError::ToSliceTooSmall {
                found: 12,
                expected: 13
            }
        );
        assert_eq!(
            err.to_string(),
            "target slice with size 12 is too small, expected size of at least 13"
        );
    }

    #[test]
    fn test_with_application_data_buf() {
        let pus_tc = base_ping_tc_simple_ctor_with_app_data(&[1, 2, 3], true);
        verify_test_tc(&pus_tc, true, true, 16);
        let mut test_buf: [u8; 32] = [0; 32];
        let size = pus_tc
            .write_to_bytes(test_buf.as_mut_slice())
            .expect("Error writing TC to buffer");
        assert_eq!(test_buf[11], 1);
        assert_eq!(test_buf[12], 2);
        assert_eq!(test_buf[13], 3);
        assert_eq!(size, 16);
    }

    #[test]
    fn test_custom_setters() {
        let mut pus_tc = base_ping_tc_simple_ctor();
        let mut test_buf: [u8; 32] = [0; 32];
        pus_tc.set_apid(0x7ff);
        pus_tc.set_seq_count(0x3fff);
        pus_tc.set_ack_field(0b11);
        pus_tc.set_source_id(0xffff);
        pus_tc.set_seq_flags(SequenceFlags::Unsegmented);
        assert_eq!(pus_tc.source_id(), 0xffff);
        assert_eq!(pus_tc.seq_count(), 0x3fff);
        assert_eq!(pus_tc.ack_flags(), 0b11);
        assert_eq!(pus_tc.apid(), 0x7ff);
        assert_eq!(pus_tc.sequence_flags(), SequenceFlags::Unsegmented);
        pus_tc.calc_own_crc16();
        pus_tc
            .write_to_bytes(test_buf.as_mut_slice())
            .expect("Error writing TC to buffer");
        assert_eq!(test_buf[0], 0x1f);
        assert_eq!(test_buf[1], 0xff);
        assert_eq!(test_buf[2], 0xff);
        assert_eq!(test_buf[3], 0xff);
        assert_eq!(test_buf[6], 0x23);
        // Source ID 0
        assert_eq!(test_buf[9], 0xff);
        assert_eq!(test_buf[10], 0xff);
    }

    fn verify_test_tc(
        tc: &PusTcCreator,
        has_user_data: bool,
        has_checksum: bool,
        exp_full_len: usize,
    ) {
        verify_test_tc_generic(tc);
        if !has_user_data {
            assert!(tc.user_data().is_empty());
        }
        let mut comp_header =
            SpHeader::new_for_unseg_tc_checked(0x02, 0x34, exp_full_len as u16 - 7).unwrap();
        comp_header.set_sec_header_flag();

        assert_eq!(tc.has_checksum(), has_checksum);
        assert_eq!(tc.checksum().is_some(), has_checksum);
        assert_eq!(PusPacket::has_checksum(tc), has_checksum);
        assert_eq!(WritablePusPacket::has_checksum(tc), has_checksum);
        assert_eq!(*tc.sp_header(), comp_header);
    }

    fn verify_test_tc_with_reader(tc: &PusTcReader, has_user_data: bool, exp_full_len: usize) {
        verify_test_tc_generic(tc);
        if !has_user_data {
            assert!(tc.user_data().is_empty());
        }
        assert_eq!(tc.len_packed(), exp_full_len);
        let mut comp_header =
            SpHeader::new_for_unseg_tc_checked(0x02, 0x34, exp_full_len as u16 - 7).unwrap();
        comp_header.set_sec_header_flag();
        assert_eq!(*tc.sp_header(), comp_header);
    }

    fn verify_test_tc_generic(tc: &(impl PusPacket + GenericPusTcSecondaryHeader)) {
        assert_eq!(PusPacket::service(tc), 17);
        assert_eq!(GenericPusTcSecondaryHeader::service(tc), 17);
        assert_eq!(PusPacket::subservice(tc), 1);
        assert_eq!(GenericPusTcSecondaryHeader::subservice(tc), 1);
        assert!(tc.sec_header_flag());
        assert_eq!(PusPacket::pus_version(tc).unwrap(), PusC);
        assert_eq!(tc.seq_count(), 0x34);
        assert_eq!(tc.source_id(), 0);
        assert_eq!(tc.apid(), 0x02);
        assert_eq!(tc.ack_flags(), ACK_ALL);
        assert_eq!(PusPacket::pus_version(tc).unwrap(), PusVersion::PusC);
        assert_eq!(
            GenericPusTcSecondaryHeader::pus_version(tc).unwrap(),
            PusVersion::PusC
        );
    }
    fn verify_test_tc_raw(slice: &impl AsRef<[u8]>) {
        // Reference comparison implementation:
        // https://github.com/us-irs/py-spacepackets/blob/v0.13.0/tests/ecss/test_pus_tc.py
        let slice = slice.as_ref();
        // 0x1801 is the generic
        assert_eq!(slice[0], 0x18);
        // APID is 0x01
        assert_eq!(slice[1], 0x02);
        // Unsegmented packets
        assert_eq!(slice[2], 0xc0);
        // Sequence count 0x34
        assert_eq!(slice[3], 0x34);
        assert_eq!(slice[4], 0x00);
        // Space data length of 6 equals total packet length of 13
        assert_eq!(slice[5], 0x06);
        // PUS Version C 0b0010 and ACK flags 0b1111
        assert_eq!(slice[6], 0x2f);
        // Service 17
        assert_eq!(slice[7], 0x11);
        // Subservice 1
        assert_eq!(slice[8], 0x01);
        // Source ID 0
        assert_eq!(slice[9], 0x00);
        assert_eq!(slice[10], 0x00);
    }

    fn verify_crc_no_app_data(slice: &impl AsRef<[u8]>) {
        // Reference comparison implementation:
        // https://github.com/us-irs/py-spacepackets/blob/v0.13.0/tests/ecss/test_pus_tc.py
        let slice = slice.as_ref();
        assert_eq!(slice[11], 0xee);
        assert_eq!(slice[12], 0x63);
    }

    #[test]
    fn partial_eq_pus_tc() {
        // new vs new simple
        let pus_tc_1 = base_ping_tc_simple_ctor();
        let pus_tc_2 = base_ping_tc_full_ctor();
        assert_eq!(pus_tc_1, pus_tc_2);
    }

    #[test]
    fn partial_eq_serialized_vs_derialized() {
        let pus_tc = base_ping_tc_simple_ctor();
        let mut buf = [0; 32];
        pus_tc.write_to_bytes(&mut buf).unwrap();
        assert_eq!(pus_tc, PusTcReader::new(&buf).unwrap());
        assert_eq!(PusTcReader::new(&buf).unwrap(), pus_tc);
    }

    #[test]
    fn test_ack_opts_from_raw() {
        let ack_opts_raw = AckOpts::Start as u8;
        let ack_opts = AckOpts::try_from(ack_opts_raw).unwrap();
        assert_eq!(ack_opts, AckOpts::Start);
    }

    #[test]
    fn test_reader_buf_too_small() {
        let app_data = &[1, 2, 3, 4];
        let pus_tc = base_ping_tc_simple_ctor_with_app_data(app_data, true);
        let mut buf = [0; 32];
        let written_len = pus_tc.write_to_bytes(&mut buf).unwrap();
        let error = PusTcReader::new(&buf[0..PUS_TC_MIN_LEN_WITHOUT_APP_DATA + 1]);
        assert!(error.is_err());
        let error = error.unwrap_err();
        if let PusError::ByteConversion(ByteConversionError::FromSliceTooSmall {
            found,
            expected,
        }) = error
        {
            assert_eq!(found, PUS_TC_MIN_LEN_WITHOUT_APP_DATA + 1);
            assert_eq!(expected, written_len);
        } else {
            panic!("unexpected error {error}")
        }
    }

    #[test]
    fn test_reader_input_too_small() {
        let buf: [u8; 5] = [0; 5];
        let error = PusTcReader::new(&buf);
        assert!(error.is_err());
        let error = error.unwrap_err();
        if let PusError::ByteConversion(ByteConversionError::FromSliceTooSmall {
            found,
            expected,
        }) = error
        {
            assert_eq!(found, 5);
            assert_eq!(expected, PUS_TC_MIN_LEN_WITHOUT_APP_DATA);
        } else {
            panic!("unexpected error {error}")
        }
    }

    #[test]
    #[cfg(feature = "serde")]
    fn test_serialization_tc_serde() {
        let pus_tc = base_ping_tc_simple_ctor();
        let output = to_allocvec(&pus_tc).unwrap();
        let output_converted_back: PusTcCreator = from_bytes(&output).unwrap();
        assert_eq!(output_converted_back, pus_tc);
    }
}
