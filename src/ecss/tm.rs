//! This module contains all components required to create a ECSS PUS C telemetry packets according
//! to [ECSS-E-ST-70-41C](https://ecss.nl/standard/ecss-e-st-70-41c-space-engineering-telemetry-and-telecommand-packet-utilization-15-april-2016/).
//!
//! # Examples
//!
//! ```rust
//! use spacepackets::time::TimeWriter;
//! use spacepackets::time::cds::CdsTime;
//! use spacepackets::{CcsdsPacket, SpHeader};
//! use spacepackets::ecss::{PusPacket, WritablePusPacket};
//! use spacepackets::ecss::tm::{PusTmCreator, PusTmReader, PusTmSecondaryHeader, CreatorConfig};
//! use arbitrary_int::u11;
//!
//! let mut time_buf: [u8; 7] = [0; 7];
//! let time_now = CdsTime::now_with_u16_days().expect("creating CDS timestamp failed");
//! // This can definitely hold the timestamp, so it is okay to unwrap.
//! time_now.write_to_bytes(&mut time_buf).unwrap();
//!
//! // Create a ping telemetry with no user source data
//! let ping_tm = PusTmCreator::new_no_source_data(
//!     SpHeader::new_from_apid(u11::new(0x02)),
//!     PusTmSecondaryHeader::new_simple(17, 2, &time_buf),
//!     CreatorConfig::default()
//! );
//! println!("{:?}", ping_tm);
//! assert_eq!(ping_tm.service(), 17);
//! assert_eq!(ping_tm.subservice(), 2);
//! assert_eq!(ping_tm.apid().value(), 0x02);
//!
//! // Serialize TM into a raw buffer
//! let mut test_buf: [u8; 32] = [0; 32];
//! let written_size = ping_tm
//!     .write_to_bytes(test_buf.as_mut_slice())
//!     .expect("Error writing TC to buffer");
//! assert_eq!(written_size, 22);
//! println!("{:?}", &test_buf[0..written_size]);
//!
//! // Deserialize from the raw byte representation
//! let ping_tm_reader = PusTmReader::new(&test_buf, 7).expect("Deserialization failed");
//! assert_eq!(written_size, ping_tm_reader.packet_len());
//! assert_eq!(ping_tm_reader.service(), 17);
//! assert_eq!(ping_tm_reader.subservice(), 2);
//! assert_eq!(ping_tm_reader.apid().value(), 0x02);
//! assert_eq!(ping_tm_reader.timestamp(), &time_buf);
//! ```
use crate::crc::{CRC_CCITT_FALSE, CRC_CCITT_FALSE_NO_TABLE};
pub use crate::ecss::CreatorConfig;
use crate::ecss::{
    calc_pus_crc16, ccsds_impl, crc_from_raw_data, sp_header_impls, user_data_from_raw,
    verify_crc16_ccitt_false_from_raw_to_pus_error, PusError, PusPacket, PusVersion,
    WritablePusPacket,
};
use crate::{
    ByteConversionError, CcsdsPacket, PacketType, SequenceFlags, SpHeader, CCSDS_HEADER_LEN,
    MAX_APID,
};
use arbitrary_int::traits::Integer;
use arbitrary_int::{u11, u14, u3, u4};
use core::mem::size_of;
#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};
use zerocopy::{FromBytes, IntoBytes};

#[cfg(feature = "alloc")]
use alloc::vec::Vec;
use delegate::delegate;

use crate::time::{TimeWriter, TimestampError};

use self::zc::PusTmSecHeaderWithoutTimestamp;

use super::verify_crc16_ccitt_false_from_raw_to_pus_error_no_table;

pub trait IsPusTelemetry {}

/// Length without timestamp
pub const PUS_TM_MIN_SEC_HEADER_LEN: usize = 7;
pub const PUS_TM_MIN_LEN_WITHOUT_SOURCE_DATA: usize = CCSDS_HEADER_LEN + PUS_TM_MIN_SEC_HEADER_LEN;

pub trait GenericPusTmSecondaryHeader {
    fn pus_version(&self) -> Result<PusVersion, u4>;
    fn sc_time_ref_status(&self) -> u4;
    fn service(&self) -> u8;
    fn subservice(&self) -> u8;
    fn msg_counter(&self) -> u16;
    fn dest_id(&self) -> u16;
}

pub mod zc {
    use super::GenericPusTmSecondaryHeader;
    use crate::ecss::{PusError, PusVersion};
    use arbitrary_int::{traits::Integer as _, u4};
    use zerocopy::{FromBytes, Immutable, IntoBytes, NetworkEndian, Unaligned, U16};

    #[derive(FromBytes, IntoBytes, Immutable, Unaligned)]
    #[repr(C)]
    pub struct PusTmSecHeaderWithoutTimestamp {
        pus_version_and_sc_time_ref_status: u8,
        service: u8,
        subservice: u8,
        msg_counter: U16<NetworkEndian>,
        dest_id: U16<NetworkEndian>,
    }

    pub struct PusTmSecHeader<'slice> {
        pub(crate) zc_header: PusTmSecHeaderWithoutTimestamp,
        pub(crate) timestamp: &'slice [u8],
    }

    impl TryFrom<crate::ecss::tm::PusTmSecondaryHeader<'_>> for PusTmSecHeaderWithoutTimestamp {
        type Error = PusError;
        fn try_from(header: crate::ecss::tm::PusTmSecondaryHeader) -> Result<Self, Self::Error> {
            if header.pus_version != PusVersion::PusC {
                return Err(PusError::VersionNotSupported(u4::new(
                    header.pus_version as u8,
                )));
            }
            Ok(PusTmSecHeaderWithoutTimestamp {
                pus_version_and_sc_time_ref_status: ((header.pus_version as u8) << 4)
                    | header.sc_time_ref_status.as_u8(),
                service: header.service,
                subservice: header.subservice,
                msg_counter: U16::from(header.msg_counter),
                dest_id: U16::from(header.dest_id),
            })
        }
    }

    impl GenericPusTmSecondaryHeader for PusTmSecHeaderWithoutTimestamp {
        #[inline]
        fn pus_version(&self) -> Result<PusVersion, u4> {
            PusVersion::try_from(u4::new(
                (self.pus_version_and_sc_time_ref_status >> 4) & 0b1111,
            ))
        }

        #[inline]
        fn sc_time_ref_status(&self) -> u4 {
            u4::new(self.pus_version_and_sc_time_ref_status & 0b1111)
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
        fn msg_counter(&self) -> u16 {
            self.msg_counter.get()
        }

        #[inline]
        fn dest_id(&self) -> u16 {
            self.dest_id.get()
        }
    }
}

#[derive(PartialEq, Eq, Copy, Clone, Debug)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct PusTmSecondaryHeader<'stamp> {
    pus_version: PusVersion,
    pub sc_time_ref_status: u4,
    pub service: u8,
    pub subservice: u8,
    pub msg_counter: u16,
    pub dest_id: u16,
    pub timestamp: &'stamp [u8],
}

impl<'stamp> PusTmSecondaryHeader<'stamp> {
    #[inline]
    pub fn new_simple(service: u8, subservice: u8, timestamp: &'stamp [u8]) -> Self {
        Self::new(service, subservice, 0, 0, timestamp)
    }

    /// Like [Self::new_simple] but without a timestamp.
    #[inline]
    pub fn new_simple_no_timestamp(service: u8, subservice: u8) -> Self {
        Self::new(service, subservice, 0, 0, &[])
    }

    #[inline]
    pub fn new(
        service: u8,
        subservice: u8,
        msg_counter: u16,
        dest_id: u16,
        timestamp: &'stamp [u8],
    ) -> Self {
        PusTmSecondaryHeader {
            pus_version: PusVersion::PusC,
            sc_time_ref_status: u4::new(0),
            service,
            subservice,
            msg_counter,
            dest_id,
            timestamp,
        }
    }
}

impl GenericPusTmSecondaryHeader for PusTmSecondaryHeader<'_> {
    #[inline]
    fn pus_version(&self) -> Result<PusVersion, u4> {
        Ok(self.pus_version)
    }

    #[inline]
    fn sc_time_ref_status(&self) -> u4 {
        self.sc_time_ref_status
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
    fn msg_counter(&self) -> u16 {
        self.msg_counter
    }

    #[inline]
    fn dest_id(&self) -> u16 {
        self.dest_id
    }
}

impl<'slice> TryFrom<zc::PusTmSecHeader<'slice>> for PusTmSecondaryHeader<'slice> {
    type Error = PusError;

    #[inline]
    fn try_from(sec_header: zc::PusTmSecHeader<'slice>) -> Result<Self, Self::Error> {
        let version = sec_header.zc_header.pus_version();
        if let Err(e) = version {
            return Err(PusError::VersionNotSupported(e));
        }
        Ok(PusTmSecondaryHeader {
            pus_version: version.unwrap(),
            sc_time_ref_status: sec_header.zc_header.sc_time_ref_status(),
            service: sec_header.zc_header.service(),
            subservice: sec_header.zc_header.subservice(),
            msg_counter: sec_header.zc_header.msg_counter(),
            dest_id: sec_header.zc_header.dest_id(),
            timestamp: sec_header.timestamp,
        })
    }
}

/// This class models the PUS C telemetry packet. It is the primary data structure to generate the
/// raw byte representation of PUS telemetry.
///
/// This class also derives the [serde::Serialize] and [serde::Deserialize] trait if the [serde]
/// feature is used which allows to send around TM packets in a raw byte format using a serde
/// provider like [postcard](https://docs.rs/postcard/latest/postcard/).
///
/// There is no spare bytes support yet.
///
/// # Lifetimes
///
/// * `'time` - This is the lifetime of the user provided timestamp.
/// * `'src_data` - This is the lifetime of the user provided source data.
#[derive(Eq, Debug, Copy, Clone)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct PusTmCreator<'time, 'src_data> {
    pub sp_header: SpHeader,
    #[cfg_attr(feature = "serde", serde(borrow))]
    pub sec_header: PusTmSecondaryHeader<'time>,
    source_data: &'src_data [u8],
    /// If this is set to false, a manual call to [Self::calc_own_crc16] or
    /// [Self::update_packet_fields] is necessary for the serialized or cached CRC16 to be valid.
    pub calc_crc_on_serialization: bool,
    has_checksum: bool,
}

impl<'time, 'src_data> PusTmCreator<'time, 'src_data> {
    /// Generates a new struct instance.
    ///
    /// # Arguments
    ///
    /// * `sp_header` - Space packet header information. The correct packet type and the secondary
    ///   header flag are set correctly by the constructor.
    /// * `sec_header` - Information contained in the secondary header, including the service
    ///   and subservice type
    /// * `source_data` - Custom application data
    /// * `packet_config` - Common configuration options for TM packet creation
    #[inline]
    pub fn new(
        mut sp_header: SpHeader,
        sec_header: PusTmSecondaryHeader<'time>,
        source_data: &'src_data [u8],
        packet_config: CreatorConfig,
    ) -> Self {
        sp_header.set_packet_type(PacketType::Tm);
        sp_header.set_sec_header_flag();
        let mut pus_tm = Self {
            sp_header,
            source_data,
            sec_header,
            calc_crc_on_serialization: true,
            has_checksum: packet_config.has_checksum,
        };
        if packet_config.set_ccsds_len {
            pus_tm.update_ccsds_data_len();
        }
        pus_tm
    }

    #[inline]
    pub fn new_simple(
        sp_header: SpHeader,
        service: u8,
        subservice: u8,
        time_provider: &impl TimeWriter,
        stamp_buf: &'time mut [u8],
        source_data: &'src_data [u8],
        packet_config: CreatorConfig,
    ) -> Result<Self, TimestampError> {
        let stamp_size = time_provider.write_to_bytes(stamp_buf)?;
        let sec_header =
            PusTmSecondaryHeader::new_simple(service, subservice, &stamp_buf[0..stamp_size]);
        Ok(Self::new(sp_header, sec_header, source_data, packet_config))
    }

    #[inline]
    pub fn new_no_source_data(
        sp_header: SpHeader,
        sec_header: PusTmSecondaryHeader<'time>,
        packet_config: CreatorConfig,
    ) -> Self {
        Self::new(sp_header, sec_header, &[], packet_config)
    }

    #[inline]
    fn has_checksum(&self) -> bool {
        self.has_checksum
    }

    #[inline]
    pub fn timestamp(&self) -> &[u8] {
        self.sec_header.timestamp
    }

    #[inline]
    pub fn source_data(&self) -> &[u8] {
        self.source_data
    }

    #[inline]
    pub fn set_dest_id(&mut self, dest_id: u16) {
        self.sec_header.dest_id = dest_id;
    }

    #[inline]
    pub fn set_msg_counter(&mut self, msg_counter: u16) {
        self.sec_header.msg_counter = msg_counter
    }

    #[inline]
    pub fn set_sc_time_ref_status(&mut self, sc_time_ref_status: u4) {
        self.sec_header.sc_time_ref_status = sc_time_ref_status;
    }

    sp_header_impls!();

    /// This is called automatically if the `set_ccsds_len` argument in the [Self::new] call was
    /// used.
    /// If this was not done or the time stamp or source data is set or changed after construction,
    /// this function needs to be called to ensure that the data length field of the CCSDS header
    /// is set correctly
    #[inline]
    pub fn update_ccsds_data_len(&mut self) {
        self.sp_header.data_len =
            self.len_written() as u16 - size_of::<crate::zc::SpHeader>() as u16 - 1;
    }

    /// This function should be called before the TM packet is serialized if
    /// [Self::calc_crc_on_serialization] is set to False. It will calculate and cache the CRC16.
    pub fn calc_own_crc16(&self) -> u16 {
        let mut digest = CRC_CCITT_FALSE.digest();
        let sph_zc = crate::zc::SpHeader::from(self.sp_header);
        digest.update(sph_zc.as_bytes());
        let pus_tc_header = zc::PusTmSecHeaderWithoutTimestamp::try_from(self.sec_header).unwrap();
        digest.update(pus_tc_header.as_bytes());
        digest.update(self.sec_header.timestamp);
        digest.update(self.source_data);
        digest.finalize()
    }

    /// This helper function calls both [Self::update_ccsds_data_len] and [Self::calc_own_crc16]
    #[inline]
    pub fn update_packet_fields(&mut self) {
        self.update_ccsds_data_len();
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
    ) -> Result<PusTmCreatorWithReservedSourceData<'a>, ByteConversionError> {
        if self.len_written() > slice.len() {
            return Err(ByteConversionError::ToSliceTooSmall {
                found: slice.len(),
                expected: self.len_written(),
            });
        }
        let mut writer_unfinalized = PusTmCreatorWithReservedSourceData::write_to_bytes_partially(
            slice,
            self.sp_header,
            self.sec_header,
            self.source_data.len(),
            self.has_checksum,
        )?;
        writer_unfinalized
            .source_data_mut()
            .copy_from_slice(self.source_data);
        Ok(writer_unfinalized)
    }

    /// Append the raw PUS byte representation to a provided [alloc::vec::Vec]
    #[cfg(feature = "alloc")]
    pub fn append_to_vec(&self, vec: &mut Vec<u8>) -> Result<usize, PusError> {
        let sph_zc = crate::zc::SpHeader::from(self.sp_header);
        let mut appended_len = PUS_TM_MIN_LEN_WITHOUT_SOURCE_DATA + self.sec_header.timestamp.len();
        if self.has_checksum {
            appended_len += 2;
        }
        appended_len += self.source_data.len();
        let start_idx = vec.len();
        vec.extend_from_slice(sph_zc.as_bytes());
        // The PUS version is hardcoded to PUS C
        let sec_header = zc::PusTmSecHeaderWithoutTimestamp::try_from(self.sec_header).unwrap();
        vec.extend_from_slice(sec_header.as_bytes());
        vec.extend_from_slice(self.sec_header.timestamp);
        vec.extend_from_slice(self.source_data);
        if self.has_checksum {
            let mut digest = CRC_CCITT_FALSE.digest();
            digest.update(&vec[start_idx..start_idx + appended_len - 2]);
            vec.extend_from_slice(&digest.finalize().to_be_bytes());
        }
        Ok(appended_len)
    }
}

impl WritablePusPacket for PusTmCreator<'_, '_> {
    #[inline]
    fn len_written(&self) -> usize {
        let mut len = PUS_TM_MIN_LEN_WITHOUT_SOURCE_DATA
            + self.sec_header.timestamp.len()
            + self.source_data.len();
        if self.has_checksum {
            len += 2
        }
        len
    }

    /// Currently, checksum is always added.
    fn has_checksum(&self) -> bool {
        self.has_checksum
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

impl PartialEq for PusTmCreator<'_, '_> {
    #[inline]
    fn eq(&self, other: &Self) -> bool {
        self.sp_header == other.sp_header
            && self.sec_header == other.sec_header
            && self.source_data == other.source_data
    }
}

impl CcsdsPacket for PusTmCreator<'_, '_> {
    ccsds_impl!();
}

impl PusPacket for PusTmCreator<'_, '_> {
    #[inline]
    fn pus_version(&self) -> Result<PusVersion, u4> {
        Ok(self.sec_header.pus_version)
    }

    #[inline]
    fn has_checksum(&self) -> bool {
        self.has_checksum()
    }

    delegate!(to self.sec_header {
        #[inline]
        fn service(&self) -> u8;
        #[inline]
        fn subservice(&self) -> u8;
    });

    #[inline]
    fn user_data(&self) -> &[u8] {
        self.source_data
    }

    #[inline]
    fn checksum(&self) -> Option<u16> {
        if !self.has_checksum {
            return None;
        }
        Some(self.calc_own_crc16())
    }
}

impl GenericPusTmSecondaryHeader for PusTmCreator<'_, '_> {
    delegate!(to self.sec_header {
        #[inline]
        fn pus_version(&self) -> Result<PusVersion, u4>;
        #[inline]
        fn service(&self) -> u8;
        #[inline]
        fn subservice(&self) -> u8;
        #[inline]
        fn dest_id(&self) -> u16;
        #[inline]
        fn msg_counter(&self) -> u16;
        #[inline]
        fn sc_time_ref_status(&self) -> u4;
    });
}

impl IsPusTelemetry for PusTmCreator<'_, '_> {}

/// A specialized variant of [PusTmCreator] designed for efficiency when handling large source
/// data.
///
/// Unlike [PusTmCreator], this type does not require the user to provide the source data
/// as a separate slice. Instead, it allows writing the source data directly into the provided
/// serialization buffer. This eliminates the need for an intermediate buffer and the associated
/// memory copy, improving performance, particularly when working with large payloads.
///
/// **Important:** The total length of the source data must be known and specified in advance
/// to ensure correct serialization behavior.
///
/// Note that this abstraction intentionally omits certain trait implementations that are available
/// on [PusTmCreator], as they are not applicable in this optimized usage pattern.
pub struct PusTmCreatorWithReservedSourceData<'buf> {
    buf: &'buf mut [u8],
    source_data_offset: usize,
    full_len: usize,
    has_checksum: bool,
}

impl<'buf> PusTmCreatorWithReservedSourceData<'buf> {
    /// Generates a new instance with reserved space for the user source data.
    ///
    /// # Arguments
    ///
    /// * `sp_header` - Space packet header information. The correct packet type and the secondary
    ///   header flag are set correctly by the constructor.
    /// * `sec_header` - Information contained in the secondary header, including the service
    ///   and subservice type
    /// * `src_data_len` - Custom source data length
    #[inline]
    pub fn new(
        buf: &'buf mut [u8],
        mut sp_header: SpHeader,
        sec_header: PusTmSecondaryHeader,
        src_data_len: usize,
        has_checksum: bool,
    ) -> Result<Self, ByteConversionError> {
        sp_header.set_packet_type(PacketType::Tm);
        sp_header.set_sec_header_flag();
        let mut len_written =
            PUS_TM_MIN_LEN_WITHOUT_SOURCE_DATA + sec_header.timestamp.len() + src_data_len;
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
        Self::write_to_bytes_partially(buf, sp_header, sec_header, src_data_len, has_checksum)
    }

    fn write_to_bytes_partially(
        buf: &'buf mut [u8],
        sp_header: SpHeader,
        sec_header: PusTmSecondaryHeader,
        src_data_len: usize,
        has_checksum: bool,
    ) -> Result<Self, ByteConversionError> {
        let mut curr_idx = 0;
        sp_header.write_to_be_bytes(&mut buf[0..CCSDS_HEADER_LEN])?;
        curr_idx += CCSDS_HEADER_LEN;
        let sec_header_len = size_of::<zc::PusTmSecHeaderWithoutTimestamp>();
        let sec_header_zc = zc::PusTmSecHeaderWithoutTimestamp::try_from(sec_header).unwrap();
        // Unwrap okay, this can not fail.
        sec_header_zc
            .write_to(&mut buf[curr_idx..curr_idx + sec_header_len])
            .unwrap();
        curr_idx += sec_header_len;
        buf[curr_idx..curr_idx + sec_header.timestamp.len()].copy_from_slice(sec_header.timestamp);
        curr_idx += sec_header.timestamp.len();
        let source_data_offset = curr_idx;
        curr_idx += src_data_len;
        if has_checksum {
            curr_idx += 2;
        }
        Ok(Self {
            buf,
            source_data_offset,
            full_len: curr_idx,
            has_checksum,
        })
    }

    #[inline]
    pub const fn len_written(&self) -> usize {
        self.full_len
    }

    /// Mutable access to the source data buffer.
    #[inline]
    pub fn source_data_mut(&mut self) -> &mut [u8] {
        if self.has_checksum {
            &mut self.buf[self.source_data_offset..self.full_len - 2]
        } else {
            &mut self.buf[self.source_data_offset..self.full_len]
        }
    }

    /// Access to the source data buffer.
    #[inline]
    pub fn source_data(&self) -> &[u8] {
        if self.has_checksum {
            &self.buf[self.source_data_offset..self.full_len - 2]
        } else {
            &self.buf[self.source_data_offset..self.full_len]
        }
    }

    #[inline]
    pub fn source_data_len(&self) -> usize {
        let mut len = self.full_len - self.source_data_offset;
        if self.has_checksum {
            len -= 2;
        }
        len
    }

    /// Finalize the TM packet by calculating and writing the CRC16.
    ///
    /// Returns the full packet length.
    pub fn finalize(self) -> usize {
        if self.has_checksum {
            let mut digest = CRC_CCITT_FALSE.digest();
            digest.update(&self.buf[0..self.full_len - 2]);
            self.buf[self.full_len - 2..self.full_len]
                .copy_from_slice(&digest.finalize().to_be_bytes());
        }
        self.full_len
    }

    /// Finalize the TM packet by calculating and writing the CRC16 using a table-less
    /// implementation.
    ///
    /// Returns the full packet length.
    pub fn finalize_checksum_no_table(self) -> usize {
        if self.has_checksum {
            let mut digest = CRC_CCITT_FALSE_NO_TABLE.digest();
            digest.update(&self.buf[0..self.full_len - 2]);
            self.buf[self.full_len - 2..self.full_len]
                .copy_from_slice(&digest.finalize().to_be_bytes());
        }
        self.full_len
    }

    /// Finalize the TM packet without writing the CRC16.
    ///
    /// Returns the length WITHOUT the CRC16.
    #[inline]
    pub fn finalize_no_checksum(self) -> usize {
        if self.has_checksum {
            self.full_len - 2
        } else {
            self.full_len
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct ReaderConfig {
    pub timestamp_len: usize,
    pub has_checksum: bool,
}

/// This class models the PUS C telemetry packet. It is the primary data structure to read
/// a telemetry packet from raw bytes.
///
/// This class also derives the [serde::Serialize] and [serde::Deserialize] trait if the [serde]
/// feature is used which allows to send around TM packets in a raw byte format using a serde
/// provider like [postcard](https://docs.rs/postcard/latest/postcard/).
///
/// There is no spare bytes support yet.
///
/// # Lifetimes
///
/// * `'raw_data` - Lifetime of the raw slice this class is constructed from.
#[derive(Eq, Debug, Copy, Clone)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct PusTmReader<'raw_data> {
    pub sp_header: SpHeader,
    pub sec_header: PusTmSecondaryHeader<'raw_data>,
    #[cfg_attr(feature = "serde", serde(skip))]
    raw_data: &'raw_data [u8],
    source_data: &'raw_data [u8],
    // CRC-16-CCITT checksum.
    checksum: Option<u16>,
}

impl<'raw_data> PusTmReader<'raw_data> {
    /// Create a [PusTmReader] instance from a raw slice. On success, it returns a tuple containing
    /// the instance and the found byte length of the packet. The timestamp length needs to be
    /// known beforehand.
    ///
    /// This function will verify the CRC-16-CCITT of the PUS packet and will return an appropriate
    /// [PusError] if the check fails.
    pub fn new(slice: &'raw_data [u8], timestamp_len: usize) -> Result<Self, PusError> {
        let tc = Self::new_no_checksum_verification(
            slice,
            ReaderConfig {
                timestamp_len,
                has_checksum: true,
            },
        )?;
        verify_crc16_ccitt_false_from_raw_to_pus_error(tc.raw_data(), tc.checksum().unwrap())?;
        Ok(tc)
    }

    /// Like [PusTmReader::new] but uses a table-less CRC implementation.
    pub fn new_checksum_no_table(
        slice: &'raw_data [u8],
        timestamp_len: usize,
    ) -> Result<Self, PusError> {
        let tc = Self::new_no_checksum_verification(
            slice,
            ReaderConfig {
                timestamp_len,
                has_checksum: true,
            },
        )?;
        verify_crc16_ccitt_false_from_raw_to_pus_error_no_table(
            tc.raw_data(),
            tc.checksum().unwrap(),
        )?;
        Ok(tc)
    }

    pub fn new_no_checksum(slice: &'raw_data [u8], timestamp_len: usize) -> Result<Self, PusError> {
        Self::new_no_checksum_verification(
            slice,
            ReaderConfig {
                timestamp_len,
                has_checksum: false,
            },
        )
    }
    pub fn new_no_checksum_verification(
        slice: &'raw_data [u8],
        reader_config: ReaderConfig,
    ) -> Result<Self, PusError> {
        let raw_data_len = slice.len();
        if raw_data_len < PUS_TM_MIN_LEN_WITHOUT_SOURCE_DATA {
            return Err(ByteConversionError::FromSliceTooSmall {
                found: raw_data_len,
                expected: PUS_TM_MIN_LEN_WITHOUT_SOURCE_DATA,
            }
            .into());
        }
        let mut current_idx = 0;
        let (sp_header, _) = SpHeader::from_be_bytes(&slice[0..CCSDS_HEADER_LEN])?;
        current_idx += 6;
        let total_len = sp_header.packet_len();
        if raw_data_len < total_len {
            return Err(ByteConversionError::FromSliceTooSmall {
                found: raw_data_len,
                expected: total_len,
            }
            .into());
        }
        if total_len < PUS_TM_MIN_LEN_WITHOUT_SOURCE_DATA {
            return Err(ByteConversionError::FromSliceTooSmall {
                found: total_len,
                expected: PUS_TM_MIN_LEN_WITHOUT_SOURCE_DATA,
            }
            .into());
        }
        let sec_header_len = core::mem::size_of::<zc::PusTmSecHeaderWithoutTimestamp>();
        // Unwrap okay, this can not fail.
        let sec_header_zc = zc::PusTmSecHeaderWithoutTimestamp::read_from_bytes(
            &slice[current_idx..current_idx + sec_header_len],
        )
        .unwrap();
        current_idx += PUS_TM_MIN_SEC_HEADER_LEN;
        let zc_sec_header_wrapper = zc::PusTmSecHeader {
            zc_header: sec_header_zc,
            timestamp: &slice[current_idx..current_idx + reader_config.timestamp_len],
        };
        current_idx += reader_config.timestamp_len;
        let raw_data = &slice[0..total_len];
        let mut crc16 = None;
        if reader_config.has_checksum {
            crc16 = Some(crc_from_raw_data(raw_data)?);
        }
        Ok(Self {
            sp_header,
            sec_header: PusTmSecondaryHeader::try_from(zc_sec_header_wrapper).unwrap(),
            raw_data,
            source_data: user_data_from_raw(
                current_idx,
                total_len,
                slice,
                reader_config.has_checksum,
            )?,
            checksum: crc16,
        })
    }

    #[inline]
    pub fn len_packed(&self) -> usize {
        self.sp_header.packet_len()
    }

    #[inline]
    pub fn source_data(&self) -> &[u8] {
        self.user_data()
    }

    #[inline]
    pub fn timestamp(&self) -> &[u8] {
        self.sec_header.timestamp
    }

    #[inline]
    pub fn checksum(&self) -> Option<u16> {
        self.checksum
    }

    /// This function will return the slice [Self] was constructed from.
    #[inline]
    pub fn raw_data(&self) -> &[u8] {
        self.raw_data
    }
}

impl PartialEq for PusTmReader<'_> {
    fn eq(&self, other: &Self) -> bool {
        self.sec_header == other.sec_header
            && self.source_data == other.source_data
            && self.sp_header == other.sp_header
            && self.checksum == other.checksum
    }
}

impl CcsdsPacket for PusTmReader<'_> {
    ccsds_impl!();
}

impl PusPacket for PusTmReader<'_> {
    delegate!(to self.sec_header {
        #[inline]
        fn pus_version(&self) -> Result<PusVersion, u4>;
        #[inline]
        fn service(&self) -> u8;
        #[inline]
        fn subservice(&self) -> u8;
    });

    #[inline]
    fn has_checksum(&self) -> bool {
        self.checksum.is_some()
    }

    #[inline]
    fn user_data(&self) -> &[u8] {
        self.source_data
    }

    #[inline]
    fn checksum(&self) -> Option<u16> {
        self.checksum()
    }
}

impl GenericPusTmSecondaryHeader for PusTmReader<'_> {
    delegate!(to self.sec_header {
        #[inline]
        fn pus_version(&self) -> Result<PusVersion, u4>;
        #[inline]
        fn service(&self) -> u8;
        #[inline]
        fn subservice(&self) -> u8;
        #[inline]
        fn dest_id(&self) -> u16;
        #[inline]
        fn msg_counter(&self) -> u16;
        #[inline]
        fn sc_time_ref_status(&self) -> u4;
    });
}

impl IsPusTelemetry for PusTmReader<'_> {}

impl PartialEq<PusTmCreator<'_, '_>> for PusTmReader<'_> {
    fn eq(&self, other: &PusTmCreator<'_, '_>) -> bool {
        self.sp_header == other.sp_header
            && self.sec_header == other.sec_header
            && self.source_data == other.source_data
    }
}

impl PartialEq<PusTmReader<'_>> for PusTmCreator<'_, '_> {
    fn eq(&self, other: &PusTmReader<'_>) -> bool {
        self.sp_header == other.sp_header
            && self.sec_header == other.sec_header
            && self.source_data == other.source_data
    }
}

/// This is a helper class to update certain fields in a raw PUS telemetry packet directly in place.
/// This can be more efficient than creating a full [PusTmReader], modifying the fields and then
/// writing it back to another buffer.
///
/// Please note that the [Self::finish] method has to be called for the PUS TM CRC16 to be valid
/// after changing fields of the TM packet. Furthermore, the constructor of this class will not
/// do any checks except basic length checks to ensure that all relevant fields can be updated and
/// all methods can be called without a panic. If a full validity check of the PUS TM packet is
/// required, it is recommended to construct a full [PusTmReader] object from the raw bytestream
/// first.
pub struct PusTmZeroCopyWriter<'raw> {
    raw_tm: &'raw mut [u8],
    timestamp_len: usize,
    has_checksum: bool,
}

impl<'raw> PusTmZeroCopyWriter<'raw> {
    /// This function will not do any other checks on the raw data other than a length check
    /// for all internal fields which can be updated.
    ///
    /// It is the responsibility of the user to ensure the raw slice contains a valid telemetry
    /// packet.
    pub fn new(raw_tm: &'raw mut [u8], timestamp_len: usize, has_checksum: bool) -> Option<Self> {
        let raw_tm_len = raw_tm.len();
        let min_len = CCSDS_HEADER_LEN
            + PUS_TM_MIN_SEC_HEADER_LEN
            + timestamp_len
            + if has_checksum { 2 } else { 0 };
        if raw_tm_len < min_len {
            return None;
        }
        let sp_header = crate::zc::SpHeader::read_from_bytes(&raw_tm[0..CCSDS_HEADER_LEN]).unwrap();
        if raw_tm_len < sp_header.packet_len() {
            return None;
        }
        let writer = Self {
            raw_tm: &mut raw_tm[..sp_header.packet_len()],
            timestamp_len,
            has_checksum,
        };
        Some(writer)
    }

    /// Set the sequence count. Returns false and does not update the value if the passed value
    /// exceeds [MAX_APID].
    #[inline]
    pub fn set_apid(&mut self, apid: u11) -> bool {
        // Clear APID part of the raw packet ID
        let updated_apid = ((((self.raw_tm[0] as u16) << 8) | self.raw_tm[1] as u16)
            & !MAX_APID.as_u16())
            | apid.as_u16();
        self.raw_tm[0..2].copy_from_slice(&updated_apid.to_be_bytes());
        true
    }

    /// This function sets the message counter in the PUS TM secondary header.
    #[inline]
    pub fn set_msg_count(&mut self, msg_count: u16) {
        self.raw_tm[9..11].copy_from_slice(&msg_count.to_be_bytes());
    }

    /// This function sets the destination ID in the PUS TM secondary header.
    #[inline]
    pub fn set_destination_id(&mut self, dest_id: u16) {
        self.raw_tm[11..13].copy_from_slice(&dest_id.to_be_bytes())
    }

    /// Helper API to generate the space packet header portion of the PUS TM from the raw memory.
    #[inline]
    pub fn sp_header(&self) -> crate::zc::SpHeader {
        // Valid minimum length of packet was checked before.
        crate::zc::SpHeader::read_from_bytes(&self.raw_tm[0..CCSDS_HEADER_LEN]).unwrap()
    }

    /// Helper API to generate the portion of the secondary header without a timestamp from the
    /// raw memory.
    #[inline]
    pub fn sec_header_without_timestamp(&self) -> PusTmSecHeaderWithoutTimestamp {
        // Valid minimum length of packet was checked before.
        PusTmSecHeaderWithoutTimestamp::read_from_bytes(
            &self.raw_tm[CCSDS_HEADER_LEN..CCSDS_HEADER_LEN + PUS_TM_MIN_SEC_HEADER_LEN],
        )
        .unwrap()
    }

    #[inline]
    pub fn set_seq_count(&mut self, seq_count: u14) -> bool {
        let new_psc = (u16::from_be_bytes(self.raw_tm[2..4].try_into().unwrap()) & 0xC000)
            | seq_count.as_u16();
        self.raw_tm[2..4].copy_from_slice(&new_psc.to_be_bytes());
        true
    }

    /// This method has to be called after modifying fields to ensure the CRC16 of the telemetry
    /// packet remains valid.
    pub fn finish(self) {
        if self.has_checksum {
            let slice_len = self.raw_tm.len();
            let crc16 = calc_pus_crc16(&self.raw_tm[..slice_len - 2]);
            self.raw_tm[slice_len - 2..].copy_from_slice(&crc16.to_be_bytes());
        }
    }
}

impl CcsdsPacket for PusTmZeroCopyWriter<'_> {
    #[inline]
    fn ccsds_version(&self) -> u3 {
        self.sp_header().ccsds_version()
    }

    #[inline]
    fn packet_id(&self) -> crate::PacketId {
        self.sp_header().packet_id()
    }

    #[inline]
    fn psc(&self) -> crate::PacketSequenceControl {
        self.sp_header().psc()
    }

    #[inline]
    fn data_len(&self) -> u16 {
        self.sp_header().data_len()
    }
}

impl PusPacket for PusTmZeroCopyWriter<'_> {
    #[inline]
    fn pus_version(&self) -> Result<PusVersion, u4> {
        self.sec_header_without_timestamp().pus_version()
    }

    #[inline]
    fn service(&self) -> u8 {
        self.raw_tm[7]
    }

    #[inline]
    fn has_checksum(&self) -> bool {
        self.has_checksum
    }

    #[inline]
    fn subservice(&self) -> u8 {
        self.raw_tm[8]
    }

    #[inline]
    fn user_data(&self) -> &[u8] {
        if self.has_checksum {
            &self.raw_tm[CCSDS_HEADER_LEN + PUS_TM_MIN_SEC_HEADER_LEN + self.timestamp_len
                ..self.sp_header().packet_len() - 2]
        } else {
            &self.raw_tm[CCSDS_HEADER_LEN + PUS_TM_MIN_SEC_HEADER_LEN + self.timestamp_len
                ..self.sp_header().packet_len()]
        }
    }

    #[inline]
    fn checksum(&self) -> Option<u16> {
        if !self.has_checksum {
            return None;
        }
        Some(u16::from_be_bytes(
            self.raw_tm[self.sp_header().packet_len() - 2..self.sp_header().packet_len()]
                .try_into()
                .unwrap(),
        ))
    }
}

impl GenericPusTmSecondaryHeader for PusTmZeroCopyWriter<'_> {
    delegate! {
        to self.sec_header_without_timestamp() {
            #[inline]
            fn pus_version(&self) -> Result<PusVersion, u4>;
            #[inline]
            fn sc_time_ref_status(&self) -> u4;
            #[inline]
            fn msg_counter(&self) -> u16;
            #[inline]
            fn dest_id(&self) -> u16;
        }
    }

    #[inline]
    fn service(&self) -> u8 {
        PusPacket::service(self)
    }

    #[inline]
    fn subservice(&self) -> u8 {
        PusPacket::subservice(self)
    }
}

#[cfg(test)]
mod tests {
    use alloc::string::ToString;

    use super::*;
    use crate::time::cds::CdsTime;
    #[cfg(feature = "serde")]
    use crate::time::CcsdsTimeProvider;
    use crate::SpHeader;
    use crate::{ecss::PusVersion::PusC, MAX_SEQ_COUNT};
    #[cfg(feature = "serde")]
    use postcard::{from_bytes, to_allocvec};

    const DUMMY_DATA: &[u8] = &[0, 1, 2];

    fn base_ping_reply_full_ctor<'a, 'b>(timestamp: &'a [u8]) -> PusTmCreator<'a, 'b> {
        let sph = SpHeader::new_for_unseg_tm(u11::new(0x123), u14::new(0x234), 0);
        let tm_header = PusTmSecondaryHeader::new_simple(17, 2, timestamp);
        PusTmCreator::new_no_source_data(sph, tm_header, CreatorConfig::default())
    }

    fn base_ping_reply_full_ctor_no_checksum<'a, 'b>(timestamp: &'a [u8]) -> PusTmCreator<'a, 'b> {
        let sph = SpHeader::new_for_unseg_tm(u11::new(0x123), u14::new(0x234), 0);
        let tm_header = PusTmSecondaryHeader::new_simple(17, 2, timestamp);
        PusTmCreator::new_no_source_data(
            sph,
            tm_header,
            CreatorConfig {
                set_ccsds_len: true,
                has_checksum: false,
            },
        )
    }
    fn ping_reply_with_data<'a, 'b>(timestamp: &'a [u8]) -> PusTmCreator<'a, 'b> {
        let sph = SpHeader::new_for_unseg_tm(u11::new(0x123), u14::new(0x234), 0);
        let tm_header = PusTmSecondaryHeader::new_simple(17, 2, timestamp);
        PusTmCreator::new(sph, tm_header, DUMMY_DATA, CreatorConfig::default())
    }

    fn base_hk_reply<'a, 'b>(timestamp: &'a [u8], src_data: &'b [u8]) -> PusTmCreator<'a, 'b> {
        let sph = SpHeader::new_for_unseg_tm(u11::new(0x123), u14::new(0x234), 0);
        let tc_header = PusTmSecondaryHeader::new_simple(3, 5, timestamp);
        PusTmCreator::new(sph, tc_header, src_data, CreatorConfig::default())
    }

    fn base_hk_reply_no_checksum<'a, 'b>(
        timestamp: &'a [u8],
        src_data: &'b [u8],
    ) -> PusTmCreator<'a, 'b> {
        let sph = SpHeader::new_for_unseg_tm(u11::new(0x123), u14::new(0x234), 0);
        let tc_header = PusTmSecondaryHeader::new_simple(3, 5, timestamp);
        PusTmCreator::new(
            sph,
            tc_header,
            src_data,
            CreatorConfig {
                set_ccsds_len: true,
                has_checksum: false,
            },
        )
    }

    fn dummy_timestamp() -> &'static [u8] {
        &[0, 1, 2, 3, 4, 5, 6]
    }

    #[test]
    fn test_basic() {
        let timestamp = dummy_timestamp();
        let pus_tm = base_ping_reply_full_ctor(timestamp);
        verify_ping_reply(&pus_tm, false, 22, dummy_timestamp(), true);
    }

    #[test]
    fn test_basic_no_checksum() {
        let timestamp = dummy_timestamp();
        let pus_tm = base_ping_reply_full_ctor_no_checksum(timestamp);
        verify_ping_reply(&pus_tm, false, 20, dummy_timestamp(), false);
    }

    #[test]
    fn test_basic_simple_api() {
        let sph = SpHeader::new_for_unseg_tm(u11::new(0x123), u14::new(0x234), 0);
        let time_provider = CdsTime::new_with_u16_days(0, 0);
        let mut stamp_buf: [u8; 8] = [0; 8];
        let pus_tm = PusTmCreator::new_simple(
            sph,
            17,
            2,
            &time_provider,
            &mut stamp_buf,
            &[],
            CreatorConfig::default(),
        )
        .unwrap();
        verify_ping_reply(&pus_tm, false, 22, &[64, 0, 0, 0, 0, 0, 0], true);
    }

    #[test]
    fn test_serialization_no_source_data() {
        let timestamp = dummy_timestamp();
        let pus_tm = base_ping_reply_full_ctor(timestamp);
        let mut buf: [u8; 32] = [0; 32];
        let ser_len = pus_tm
            .write_to_bytes(&mut buf)
            .expect("Serialization failed");
        assert_eq!(ser_len, 22);
        verify_raw_ping_reply(pus_tm.checksum(), &buf, true);
    }

    #[test]
    fn test_serialization_no_source_data_alt_ctor() {
        let timestamp = dummy_timestamp();
        let sph = SpHeader::new_for_unseg_tm(u11::new(0x123), u14::new(0x234), 0);
        let tm_header = PusTmSecondaryHeader::new_simple(17, 2, timestamp);
        let mut buf: [u8; 32] = [0; 32];
        let mut pus_tm =
            PusTmCreatorWithReservedSourceData::new(&mut buf, sph, tm_header, 0, true).unwrap();
        assert_eq!(pus_tm.source_data_len(), 0);
        assert_eq!(pus_tm.source_data(), &[]);
        assert_eq!(pus_tm.source_data_mut(), &[]);
        let ser_len = pus_tm.finalize();
        assert_eq!(ser_len, 22);
        verify_raw_ping_reply(None, &buf, true);
    }

    #[test]
    fn test_serialization_no_source_data_alt_ctor_no_checksum_verification() {
        let timestamp = dummy_timestamp();
        let sph = SpHeader::new_for_unseg_tm(u11::new(0x123), u14::new(0x234), 0);
        let tm_header = PusTmSecondaryHeader::new_simple(17, 2, timestamp);
        let mut buf: [u8; 32] = [0; 32];
        let mut pus_tm =
            PusTmCreatorWithReservedSourceData::new(&mut buf, sph, tm_header, 0, true).unwrap();
        assert_eq!(pus_tm.source_data_len(), 0);
        assert_eq!(pus_tm.source_data(), &[]);
        assert_eq!(pus_tm.source_data_mut(), &[]);
        let ser_len = pus_tm.finalize_no_checksum();
        assert_eq!(ser_len, 20);
        verify_raw_ping_reply_no_checksum(&buf, 22);
        assert_eq!(buf[20], 0);
        assert_eq!(buf[21], 0);
    }

    #[test]
    fn test_serialization_no_source_data_alt_ctor_no_checksum() {
        let timestamp = dummy_timestamp();
        let sph = SpHeader::new_for_unseg_tm(u11::new(0x123), u14::new(0x234), 0);
        let tm_header = PusTmSecondaryHeader::new_simple(17, 2, timestamp);
        let mut buf: [u8; 32] = [0; 32];
        let mut pus_tm =
            PusTmCreatorWithReservedSourceData::new(&mut buf, sph, tm_header, 0, false).unwrap();
        assert_eq!(pus_tm.source_data_len(), 0);
        assert_eq!(pus_tm.source_data(), &[]);
        assert_eq!(pus_tm.source_data_mut(), &[]);
        let ser_len = pus_tm.finalize_no_checksum();
        assert_eq!(ser_len, 20);
        verify_raw_ping_reply_no_checksum(&buf, 20);
        assert_eq!(buf[20], 0);
        assert_eq!(buf[21], 0);
    }

    #[test]
    fn test_serialization_no_source_data_no_table() {
        let timestamp = dummy_timestamp();
        let pus_tm = base_ping_reply_full_ctor(timestamp);
        let mut buf: [u8; 32] = [0; 32];
        let ser_len = pus_tm
            .write_to_bytes_crc_no_table(&mut buf)
            .expect("Serialization failed");
        assert_eq!(ser_len, 22);
        verify_raw_ping_reply(pus_tm.checksum(), &buf, true);
    }

    #[test]
    fn test_serialization_no_source_data_no_crc() {
        let timestamp = dummy_timestamp();
        let pus_tm = base_ping_reply_full_ctor(timestamp);
        let mut buf: [u8; 32] = [0; 32];
        let ser_len = pus_tm
            .write_to_bytes_no_crc(&mut buf)
            .expect("Serialization failed");
        assert_eq!(ser_len, 20);
        assert_eq!(buf[20], 0);
        assert_eq!(buf[21], 0);
    }

    #[test]
    fn test_serialization_with_source_data() {
        let src_data = [1, 2, 3];
        let hk_reply = base_hk_reply(dummy_timestamp(), &src_data);
        let mut buf: [u8; 32] = [0; 32];
        let ser_len = hk_reply
            .write_to_bytes(&mut buf)
            .expect("Serialization failed");
        assert_eq!(ser_len, 25);
        assert_eq!(buf[20], 1);
        assert_eq!(buf[21], 2);
        assert_eq!(buf[22], 3);
        let crc16 = u16::from_be_bytes([buf[23], buf[24]]);
        assert_eq!(crc16, hk_reply.checksum().unwrap());
    }

    #[test]
    fn test_serialization_with_source_data_no_checksum() {
        let src_data = [1, 2, 3];
        let hk_reply = base_hk_reply_no_checksum(dummy_timestamp(), &src_data);
        let mut buf: [u8; 32] = [0; 32];
        let ser_len = hk_reply
            .write_to_bytes(&mut buf)
            .expect("Serialization failed");
        assert_eq!(ser_len, 23);
        assert_eq!(buf[20], 1);
        assert_eq!(buf[21], 2);
        assert_eq!(buf[22], 3);
        let crc16 = u16::from_be_bytes([buf[23], buf[24]]);
        assert_eq!(crc16, 0);
    }

    #[test]
    fn test_serialization_with_source_data_alt_ctor() {
        let src_data = &[1, 2, 3];
        let mut buf: [u8; 32] = [0; 32];
        let sph = SpHeader::new_for_unseg_tm(u11::new(0x123), u14::new(0x234), 0);
        let tc_header = PusTmSecondaryHeader::new_simple(3, 5, dummy_timestamp());
        let mut hk_reply_unwritten =
            PusTmCreatorWithReservedSourceData::new(&mut buf, sph, tc_header, 3, true).unwrap();
        assert_eq!(hk_reply_unwritten.source_data_len(), 3);
        assert_eq!(hk_reply_unwritten.source_data(), &[0, 0, 0]);
        assert_eq!(hk_reply_unwritten.source_data_mut(), &[0, 0, 0]);
        let source_data_mut = hk_reply_unwritten.source_data_mut();
        source_data_mut.copy_from_slice(src_data);
        let ser_len = hk_reply_unwritten.finalize();
        assert_eq!(ser_len, 25);
        assert_eq!(buf[20], 1);
        assert_eq!(buf[21], 2);
        assert_eq!(buf[22], 3);
    }

    #[test]
    fn test_serialization_with_source_data_alt_ctor_no_table() {
        let src_data = &[1, 2, 3];
        let mut buf: [u8; 32] = [0; 32];
        let sph = SpHeader::new_for_unseg_tm(u11::new(0x123), u14::new(0x234), 0);
        let tc_header = PusTmSecondaryHeader::new_simple(3, 5, dummy_timestamp());
        let mut hk_reply_unwritten =
            PusTmCreatorWithReservedSourceData::new(&mut buf, sph, tc_header, 3, true).unwrap();
        assert_eq!(hk_reply_unwritten.source_data_len(), 3);
        assert_eq!(hk_reply_unwritten.source_data(), &[0, 0, 0]);
        assert_eq!(hk_reply_unwritten.source_data_mut(), &[0, 0, 0]);
        let source_data_mut = hk_reply_unwritten.source_data_mut();
        source_data_mut.copy_from_slice(src_data);
        let ser_len = hk_reply_unwritten.finalize_checksum_no_table();
        assert_eq!(ser_len, 25);
        assert_eq!(buf[20], 1);
        assert_eq!(buf[21], 2);
        assert_eq!(buf[22], 3);
    }

    #[test]
    fn test_setters() {
        let timestamp = dummy_timestamp();
        let mut pus_tm = base_ping_reply_full_ctor(timestamp);
        pus_tm.set_sc_time_ref_status(u4::new(0b1010));
        pus_tm.set_dest_id(0x7fff);
        pus_tm.set_msg_counter(0x1f1f);
        assert_eq!(pus_tm.sc_time_ref_status().value(), 0b1010);
        assert_eq!(pus_tm.dest_id(), 0x7fff);
        assert_eq!(pus_tm.msg_counter(), 0x1f1f);
        pus_tm.set_apid(u11::new(0x7ff));
        assert_eq!(pus_tm.apid().value(), 0x7ff);
    }

    #[test]
    fn test_write_into_vec() {
        let timestamp = dummy_timestamp();
        let pus_tm = base_ping_reply_full_ctor(timestamp);
        let tm_vec = pus_tm.to_vec().expect("Serialization failed");
        assert_eq!(tm_vec.len(), 22);
        let tm_deserialized =
            PusTmReader::new(tm_vec.as_slice(), 7).expect("Deserialization failed");
        assert_eq!(tm_vec.len(), tm_deserialized.packet_len());
        verify_ping_reply_with_reader(&tm_deserialized, false, 22, dummy_timestamp());
    }

    #[test]
    fn test_deserialization_no_source_data() {
        let timestamp = dummy_timestamp();
        let pus_tm = base_ping_reply_full_ctor(timestamp);
        let mut buf: [u8; 32] = [0; 32];
        let ser_len = pus_tm
            .write_to_bytes(&mut buf)
            .expect("Serialization failed");
        assert_eq!(ser_len, 22);
        let tm_deserialized = PusTmReader::new(&buf, 7).expect("Deserialization failed");
        assert_eq!(ser_len, tm_deserialized.packet_len());
        assert_eq!(tm_deserialized.user_data(), tm_deserialized.source_data());
        assert_eq!(tm_deserialized.raw_data(), &buf[..ser_len]);
        assert_eq!(
            tm_deserialized.checksum().unwrap(),
            pus_tm.checksum().unwrap()
        );
        verify_ping_reply_with_reader(&tm_deserialized, false, 22, dummy_timestamp());
    }

    #[test]
    fn test_deserialization_no_source_data_with_trait() {
        let timestamp = dummy_timestamp();
        let pus_tm = base_ping_reply_full_ctor(timestamp);
        let mut buf: [u8; 32] = [0; 32];
        let ser_len =
            WritablePusPacket::write_to_bytes(&pus_tm, &mut buf).expect("Serialization failed");
        assert_eq!(ser_len, 22);
        let tm_deserialized = PusTmReader::new(&buf, 7).expect("Deserialization failed");
        assert_eq!(ser_len, tm_deserialized.packet_len());
        assert_eq!(tm_deserialized.user_data(), tm_deserialized.source_data());
        assert_eq!(tm_deserialized.raw_data(), &buf[..ser_len]);
        assert_eq!(
            tm_deserialized.checksum().unwrap(),
            pus_tm.checksum().unwrap()
        );
        verify_ping_reply_with_reader(&tm_deserialized, false, 22, dummy_timestamp());
    }

    #[test]
    fn test_deserialization_with_source_data() {
        let src_data = [4, 3, 2, 1];
        let reply = base_hk_reply(dummy_timestamp(), &src_data);
        let mut buf: [u8; 32] = [0; 32];
        let ser_len =
            WritablePusPacket::write_to_bytes(&reply, &mut buf).expect("Serialization failed");
        assert_eq!(ser_len, 26);
        let tm_deserialized = PusTmReader::new(&buf, 7).expect("Deserialization failed");
        assert_eq!(ser_len, tm_deserialized.packet_len());
        assert_eq!(tm_deserialized.user_data(), src_data);
        assert_eq!(reply.checksum(), tm_deserialized.checksum());
    }

    #[test]
    fn test_deserialization_with_source_data_no_checksum() {
        let src_data = [4, 3, 2, 1];
        let reply = base_hk_reply_no_checksum(dummy_timestamp(), &src_data);
        let mut buf: [u8; 32] = [0; 32];
        let ser_len =
            WritablePusPacket::write_to_bytes(&reply, &mut buf).expect("Serialization failed");
        assert_eq!(ser_len, 24);
        let tm_deserialized =
            PusTmReader::new_no_checksum(&buf, 7).expect("Deserialization failed");
        assert_eq!(ser_len, tm_deserialized.packet_len());
        assert_eq!(tm_deserialized.user_data(), src_data);
        assert_eq!(reply.checksum(), tm_deserialized.checksum());
    }

    #[test]
    fn test_deserialization_no_table() {
        let timestamp = dummy_timestamp();
        let pus_tm = base_ping_reply_full_ctor(timestamp);
        let mut buf: [u8; 32] = [0; 32];
        let ser_len = pus_tm
            .write_to_bytes(&mut buf)
            .expect("Serialization failed");
        assert_eq!(ser_len, 22);
        let tm_deserialized =
            PusTmReader::new_checksum_no_table(&buf, 7).expect("Deserialization failed");
        assert_eq!(ser_len, tm_deserialized.packet_len());
        assert_eq!(tm_deserialized.user_data(), tm_deserialized.source_data());
        assert_eq!(tm_deserialized.raw_data(), &buf[..ser_len]);
        assert_eq!(
            tm_deserialized.checksum().unwrap(),
            pus_tm.checksum().unwrap()
        );
        verify_ping_reply_with_reader(&tm_deserialized, false, 22, dummy_timestamp());
    }

    #[test]
    fn test_deserialization_faulty_crc() {
        let timestamp = dummy_timestamp();
        let pus_tm = base_ping_reply_full_ctor(timestamp);
        let mut buf: [u8; 32] = [0; 32];
        let ser_len = pus_tm
            .write_to_bytes(&mut buf)
            .expect("Serialization failed");
        assert_eq!(ser_len, 22);
        buf[ser_len - 2] = 0;
        buf[ser_len - 1] = 0;
        let tm_error = PusTmReader::new(&buf, 7);
        assert!(tm_error.is_err());
        let tm_error = tm_error.unwrap_err();
        if let PusError::ChecksumFailure(crc) = tm_error {
            assert_eq!(crc, 0);
            assert_eq!(
                tm_error.to_string(),
                "checksum verification for crc16 0x0000 failed"
            );
        }
    }

    #[test]
    fn test_manual_field_update() {
        let sph = SpHeader::new_for_unseg_tm(u11::new(0x123), u14::new(0x234), 0);
        let tc_header = PusTmSecondaryHeader::new_simple(17, 2, dummy_timestamp());
        let mut tm = PusTmCreator::new_no_source_data(
            sph,
            tc_header,
            CreatorConfig {
                set_ccsds_len: false,
                has_checksum: true,
            },
        );
        tm.calc_crc_on_serialization = false;
        assert_eq!(tm.data_len(), 0x00);
        let mut buf: [u8; 32] = [0; 32];
        tm.update_ccsds_data_len();
        assert_eq!(tm.data_len(), 15);
        tm.calc_own_crc16();
        let res = tm.write_to_bytes(&mut buf);
        assert!(res.is_ok());
        tm.sp_header.data_len = 0;
        tm.update_packet_fields();
        assert_eq!(tm.data_len(), 15);
    }

    #[test]
    fn test_target_buf_too_small() {
        let timestamp = dummy_timestamp();
        let pus_tm = base_ping_reply_full_ctor(timestamp);
        let mut buf: [u8; 16] = [0; 16];
        let res = pus_tm.write_to_bytes(&mut buf);
        assert!(res.is_err());
        let error = res.unwrap_err();
        if let ByteConversionError::ToSliceTooSmall { found, expected } = error {
            assert_eq!(expected, 22);
            assert_eq!(found, 16);
        } else {
            panic!("Invalid error {:?}", error);
        }
    }

    #[test]
    #[cfg(feature = "alloc")]
    fn test_append_to_vec() {
        let timestamp = dummy_timestamp();
        let pus_tm = base_ping_reply_full_ctor(timestamp);
        let mut vec = Vec::new();
        let res = pus_tm.append_to_vec(&mut vec);
        assert!(res.is_ok());
        assert_eq!(res.unwrap(), 22);
        verify_raw_ping_reply(pus_tm.checksum(), vec.as_slice(), true);
    }

    #[test]
    #[cfg(feature = "alloc")]
    fn test_append_to_vec_no_checksum() {
        let timestamp = dummy_timestamp();
        let pus_tm = base_ping_reply_full_ctor_no_checksum(timestamp);
        let mut vec = Vec::new();
        let res = pus_tm.append_to_vec(&mut vec);
        assert!(res.is_ok());
        assert_eq!(res.unwrap(), 20);
        verify_raw_ping_reply(pus_tm.checksum(), vec.as_slice(), false);
    }

    #[test]
    #[cfg(feature = "alloc")]
    fn test_append_to_vec_with_src_data() {
        let src_data = [1, 2, 3];
        let hk_reply = base_hk_reply(dummy_timestamp(), &src_data);
        let mut vec = Vec::new();
        vec.push(4);
        let res = hk_reply.append_to_vec(&mut vec);
        assert!(res.is_ok());
        assert_eq!(res.unwrap(), 25);
        assert_eq!(vec.len(), 26);
    }

    fn verify_raw_ping_reply_no_checksum(buf: &[u8], expected_len: usize) {
        // Secondary header is set -> 0b0000_1001 , APID occupies last bit of first byte
        assert_eq!(buf[0], 0x09);
        // Rest of APID 0x123
        assert_eq!(buf[1], 0x23);
        // Unsegmented is the default, and first byte of 0x234 occupies this byte as well
        assert_eq!(buf[2], 0xc2);
        assert_eq!(buf[3], 0x34);
        assert_eq!(
            (((buf[4] as u16) << 8) | buf[5] as u16) as usize,
            expected_len - 7
        );
        // SC time ref status is 0
        assert_eq!(buf[6], (PusC as u8) << 4);
        assert_eq!(buf[7], 17);
        assert_eq!(buf[8], 2);
        // MSG counter 0
        assert_eq!(buf[9], 0x00);
        assert_eq!(buf[10], 0x00);
        // Destination ID
        assert_eq!(buf[11], 0x00);
        assert_eq!(buf[12], 0x00);
        // Timestamp
        assert_eq!(&buf[13..20], dummy_timestamp());
    }

    fn verify_raw_ping_reply(crc16: Option<u16>, buf: &[u8], has_checksum: bool) {
        if !has_checksum {
            verify_raw_ping_reply_no_checksum(buf, 20);
            if buf.len() > 20 {
                let crc16_read = u16::from_be_bytes([buf[20], buf[21]]);
                assert_eq!(crc16_read, 0);
            }
            return;
        }
        verify_raw_ping_reply_no_checksum(buf, 22);
        if let Some(crc16) = crc16 {
            let mut digest = CRC_CCITT_FALSE.digest();
            digest.update(&buf[0..20]);
            let crc16_calced = digest.finalize();
            let crc16_read = u16::from_be_bytes([buf[20], buf[21]]);
            assert_eq!(crc16_read, crc16_calced);
            assert_eq!(((crc16 >> 8) & 0xff) as u8, buf[20]);
            assert_eq!((crc16 & 0xff) as u8, buf[21]);
        }
    }

    fn verify_ping_reply(
        tm: &PusTmCreator,
        has_user_data: bool,
        exp_full_len: usize,
        exp_timestamp: &[u8],
        has_checksum: bool,
    ) {
        assert_eq!(tm.len_written(), exp_full_len);
        assert_eq!(tm.timestamp(), exp_timestamp);
        assert_eq!(tm.source_data(), tm.user_data());
        verify_ping_reply_generic(tm, has_user_data, exp_full_len);
        assert_eq!(tm.has_checksum(), has_checksum);
        assert_eq!(tm.checksum().is_some(), has_checksum);
        assert_eq!(PusPacket::has_checksum(tm), has_checksum);
        assert_eq!(WritablePusPacket::has_checksum(tm), has_checksum);
    }

    fn verify_ping_reply_with_reader(
        tm: &PusTmReader,
        has_user_data: bool,
        exp_full_len: usize,
        exp_timestamp: &[u8],
    ) {
        assert_eq!(tm.len_packed(), exp_full_len);
        assert_eq!(tm.timestamp(), exp_timestamp);
        verify_ping_reply_generic(tm, has_user_data, exp_full_len);
    }

    fn verify_ping_reply_generic(
        tm: &(impl GenericPusTmSecondaryHeader + PusPacket),
        has_user_data: bool,
        exp_full_len: usize,
    ) {
        assert!(tm.is_tm());
        assert_eq!(PusPacket::service(tm), 17);
        assert_eq!(GenericPusTmSecondaryHeader::service(tm), 17);
        assert_eq!(PusPacket::subservice(tm), 2);
        assert_eq!(GenericPusTmSecondaryHeader::subservice(tm), 2);
        assert!(tm.sec_header_flag());
        if has_user_data {
            assert!(!tm.user_data().is_empty());
        }
        assert_eq!(PusPacket::pus_version(tm).unwrap(), PusC);
        assert_eq!(tm.apid().value(), 0x123);
        assert_eq!(tm.seq_count().value(), 0x234);
        assert_eq!(PusPacket::pus_version(tm).unwrap(), PusVersion::PusC);
        assert_eq!(
            GenericPusTmSecondaryHeader::pus_version(tm).unwrap(),
            PusVersion::PusC
        );
        assert_eq!(tm.data_len(), exp_full_len as u16 - 7);
        assert_eq!(tm.dest_id(), 0x0000);
        assert_eq!(tm.msg_counter(), 0x0000);
        assert_eq!(tm.sc_time_ref_status().value(), 0b0000);
    }

    #[test]
    fn partial_eq_pus_tm() {
        let timestamp = dummy_timestamp();
        let pus_tm_1 = base_ping_reply_full_ctor(timestamp);
        let pus_tm_2 = base_ping_reply_full_ctor(timestamp);
        assert_eq!(pus_tm_1, pus_tm_2);
    }

    #[test]
    fn partial_eq_serialized_vs_derialized() {
        let timestamp = dummy_timestamp();
        let pus_tm = base_ping_reply_full_ctor(timestamp);
        let mut buf = [0; 32];
        pus_tm.write_to_bytes(&mut buf).unwrap();
        assert_eq!(pus_tm, PusTmReader::new(&buf, timestamp.len()).unwrap());
    }

    #[test]
    fn test_zero_copy_writer() {
        let ping_tm = base_ping_reply_full_ctor(dummy_timestamp());
        let mut buf: [u8; 64] = [0; 64];
        let tm_size = ping_tm
            .write_to_bytes(&mut buf)
            .expect("writing PUS ping TM failed");
        let mut writer = PusTmZeroCopyWriter::new(&mut buf[..tm_size], 7, true)
            .expect("Creating zero copy writer failed");
        writer.set_destination_id(55);
        writer.set_msg_count(100);
        writer.set_seq_count(MAX_SEQ_COUNT);
        writer.set_apid(MAX_APID);
        writer.finish();
        // This performs all necessary checks, including the CRC check.
        let tm_read_back = PusTmReader::new(&buf, 7).expect("Re-creating PUS TM failed");
        assert_eq!(tm_read_back.packet_len(), tm_size);
        assert_eq!(tm_read_back.msg_counter(), 100);
        assert_eq!(tm_read_back.dest_id(), 55);
        assert_eq!(tm_read_back.seq_count(), MAX_SEQ_COUNT);
        assert_eq!(tm_read_back.apid(), MAX_APID);
    }

    #[test]
    fn test_zero_copy_writer_ccsds_api() {
        let ping_tm = base_ping_reply_full_ctor(dummy_timestamp());
        let mut buf: [u8; 64] = [0; 64];
        let tm_size = ping_tm
            .write_to_bytes(&mut buf)
            .expect("writing PUS ping TM failed");
        let mut writer = PusTmZeroCopyWriter::new(&mut buf[..tm_size], 7, true)
            .expect("Creating zero copy writer failed");
        writer.set_destination_id(55);
        writer.set_msg_count(100);
        writer.set_seq_count(MAX_SEQ_COUNT);
        writer.set_apid(MAX_APID);
        assert_eq!(PusPacket::service(&writer), 17);
        assert_eq!(PusPacket::subservice(&writer), 2);
        assert_eq!(writer.apid(), MAX_APID);
        assert_eq!(writer.seq_count(), MAX_SEQ_COUNT);
    }

    #[test]
    fn test_zero_copy_pus_api() {
        let ping_tm = ping_reply_with_data(dummy_timestamp());
        let mut buf: [u8; 64] = [0; 64];
        let tm_size = ping_tm
            .write_to_bytes(&mut buf)
            .expect("writing PUS ping TM failed");
        let crc16_raw = u16::from_be_bytes(buf[tm_size - 2..tm_size].try_into().unwrap());
        let mut writer = PusTmZeroCopyWriter::new(&mut buf[..tm_size], 7, true)
            .expect("Creating zero copy writer failed");
        writer.set_destination_id(55);
        writer.set_msg_count(100);
        writer.set_seq_count(MAX_SEQ_COUNT);
        writer.set_apid(MAX_APID);
        assert_eq!(PusPacket::service(&writer), 17);
        assert_eq!(PusPacket::subservice(&writer), 2);
        assert_eq!(writer.dest_id(), 55);
        assert_eq!(writer.msg_counter(), 100);
        assert_eq!(writer.sec_header_without_timestamp().dest_id(), 55);
        assert_eq!(writer.sec_header_without_timestamp().msg_counter(), 100);
        assert_eq!(writer.user_data(), DUMMY_DATA);
        // Need to check crc16 before finish, because finish will update the CRC.
        let crc16 = writer.checksum();
        assert!(crc16.is_some());
        assert_eq!(crc16.unwrap(), crc16_raw);
        writer.finish();
    }

    #[test]
    fn test_sec_header_without_stamp() {
        let sec_header = PusTmSecondaryHeader::new_simple_no_timestamp(17, 1);
        assert_eq!(sec_header.timestamp, &[]);
    }

    #[test]
    fn test_reader_partial_eq() {
        let timestamp = dummy_timestamp();
        let pus_tm = base_ping_reply_full_ctor(timestamp);
        let mut buf = [0; 32];
        pus_tm.write_to_bytes(&mut buf).unwrap();
        let tm_0 = PusTmReader::new(&buf, timestamp.len()).unwrap();
        let tm_1 = PusTmReader::new(&buf, timestamp.len()).unwrap();
        assert_eq!(tm_0, tm_1);
    }
    #[test]
    fn test_reader_buf_too_small_2() {
        let timestamp = dummy_timestamp();
        let pus_tm = base_ping_reply_full_ctor(timestamp);
        let mut buf = [0; 32];
        let written = pus_tm.write_to_bytes(&mut buf).unwrap();
        let tm_error = PusTmReader::new(
            &buf[0..PUS_TM_MIN_LEN_WITHOUT_SOURCE_DATA + 1],
            timestamp.len(),
        );
        assert!(tm_error.is_err());
        let tm_error = tm_error.unwrap_err();
        if let PusError::ByteConversion(ByteConversionError::FromSliceTooSmall {
            found,
            expected,
        }) = tm_error
        {
            assert_eq!(found, PUS_TM_MIN_LEN_WITHOUT_SOURCE_DATA + 1);
            assert_eq!(expected, written);
        } else {
            panic!("unexpected error {tm_error}")
        }
    }
    #[test]
    fn test_reader_buf_too_small() {
        let timestamp = dummy_timestamp();
        let pus_tm = base_ping_reply_full_ctor(timestamp);
        let mut buf = [0; 32];
        pus_tm.write_to_bytes(&mut buf).unwrap();
        let tm_error = PusTmReader::new(&buf[0..5], timestamp.len());
        assert!(tm_error.is_err());
        let tm_error = tm_error.unwrap_err();
        if let PusError::ByteConversion(ByteConversionError::FromSliceTooSmall {
            found,
            expected,
        }) = tm_error
        {
            assert_eq!(found, 5);
            assert_eq!(expected, PUS_TM_MIN_LEN_WITHOUT_SOURCE_DATA);
        } else {
            panic!("unexpected error {tm_error}")
        }
    }

    #[test]
    #[cfg(feature = "serde")]
    fn test_serialization_creator_serde() {
        let sph = SpHeader::new_for_unseg_tm(u11::new(0x123), u14::new(0x234), 0);
        let time_provider = CdsTime::new_with_u16_days(0, 0);
        let mut stamp_buf: [u8; 8] = [0; 8];
        let pus_tm = PusTmCreator::new_simple(
            sph,
            17,
            2,
            &time_provider,
            &mut stamp_buf,
            &[],
            CreatorConfig::default(),
        )
        .unwrap();

        let output = to_allocvec(&pus_tm).unwrap();
        let output_converted_back: PusTmCreator = from_bytes(&output).unwrap();
        assert_eq!(output_converted_back, pus_tm);
    }

    #[test]
    #[cfg(feature = "serde")]
    fn test_serialization_reader_serde() {
        let sph = SpHeader::new_for_unseg_tm(u11::new(0x123), u14::new(0x234), 0);
        let time_provider = CdsTime::new_with_u16_days(0, 0);
        let mut stamp_buf: [u8; 8] = [0; 8];
        let pus_tm = PusTmCreator::new_simple(
            sph,
            17,
            2,
            &time_provider,
            &mut stamp_buf,
            &[],
            CreatorConfig::default(),
        )
        .unwrap();
        let pus_tm_vec = pus_tm.to_vec().unwrap();
        let tm_reader = PusTmReader::new(&pus_tm_vec, time_provider.len_as_bytes()).unwrap();
        let output = to_allocvec(&tm_reader).unwrap();
        let output_converted_back: PusTmReader = from_bytes(&output).unwrap();
        assert_eq!(output_converted_back, tm_reader);
    }
}
