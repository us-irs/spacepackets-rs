//! This module contains all components required to create ECSS PUS A legacy telemetry.
//!
//! # Examples
//!
//! ```rust
//! use spacepackets::time::TimeWriter;
//! use spacepackets::time::cds::CdsTime;
//! use spacepackets::{CcsdsPacket, SpHeader};
//! use spacepackets::ecss::{PusPacket, WritablePusPacket};
//! use spacepackets::ecss::tm_pus_a::{
//!     PusTmCreator,
//!     PusTmReader,
//!     PusTmSecondaryHeader,
//!     SecondaryHeaderParameters
//! };
//!
//! let mut time_buf: [u8; 7] = [0; 7];
//! let time_now = CdsTime::now_with_u16_days().expect("creating CDS timestamp failed");
//! // This can definitely hold the timestamp, so it is okay to unwrap.
//! time_now.write_to_bytes(&mut time_buf).unwrap();
//!
//! // Create a ping telemetry with no user source data
//! let ping_tm = PusTmCreator::new_no_source_data(
//!     SpHeader::new_from_apid(0x02),
//!     PusTmSecondaryHeader::new_simple(17, 2, &time_buf),
//!     true
//! );
//! println!("{:?}", ping_tm);
//! assert_eq!(ping_tm.service(), 17);
//! assert_eq!(ping_tm.subservice(), 2);
//! assert_eq!(ping_tm.apid(), 0x02);
//!
//! // Serialize TM into a raw buffer
//! let mut test_buf: [u8; 32] = [0; 32];
//! let written_size = ping_tm
//!     .write_to_bytes(test_buf.as_mut_slice())
//!     .expect("Error writing TC to buffer");
//! assert_eq!(written_size, 18);
//! println!("{:?}", &test_buf[0..written_size]);
//!
//! // Deserialize from the raw byte representation
//! let ping_tm_reader = PusTmReader::new(&test_buf, &SecondaryHeaderParameters::new_minimal(7)).expect("deserialization failed");
//! assert_eq!(written_size, ping_tm_reader.packet_len());
//! assert_eq!(ping_tm_reader.service(), 17);
//! assert_eq!(ping_tm_reader.subservice(), 2);
//! assert_eq!(ping_tm_reader.apid(), 0x02);
//! assert_eq!(ping_tm_reader.timestamp(), &time_buf);
//! ```
use crate::crc::{CRC_CCITT_FALSE, CRC_CCITT_FALSE_NO_TABLE};
use crate::ecss::{
    calc_pus_crc16, ccsds_impl, crc_from_raw_data, sp_header_impls, user_data_from_raw,
    verify_crc16_ccitt_false_from_raw_to_pus_error, CrcType, PusError, PusPacket, PusVersion,
    WritablePusPacket,
};
use crate::util::{UnsignedByteField, UnsignedEnum};
use crate::{
    ByteConversionError, CcsdsPacket, PacketType, SequenceFlags, SpHeader, CCSDS_HEADER_LEN,
    MAX_APID, MAX_SEQ_COUNT,
};
use core::mem::size_of;
#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};
use zerocopy::{FromBytes, IntoBytes};

#[cfg(feature = "alloc")]
use alloc::vec::Vec;
use delegate::delegate;

use crate::time::{TimeWriter, TimestampError};

use super::verify_crc16_ccitt_false_from_raw_to_pus_error_no_table;

pub trait IsPusTelemetry {}

/// Length without timestamp
pub const PUS_TM_MIN_SEC_HEADER_LEN: usize = 3;
pub const PUS_TM_MIN_LEN_WITHOUT_SOURCE_DATA: usize =
    CCSDS_HEADER_LEN + PUS_TM_MIN_SEC_HEADER_LEN + size_of::<CrcType>();

pub trait GenericPusTmSecondaryHeader {
    fn pus_version(&self) -> PusVersion;
    fn service(&self) -> u8;
    fn subservice(&self) -> u8;
    fn msg_counter(&self) -> Option<u8>;
    fn dest_id(&self) -> Option<UnsignedByteField>;
    fn spare_bytes(&self) -> usize;
}

#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub struct SecondaryHeaderParameters {
    pub timestamp_len: usize,
    pub has_msg_counter: bool,
    pub dest_id_len: Option<usize>,
    pub spare_bytes: usize,
}

impl SecondaryHeaderParameters {
    pub const fn new_minimal(timestamp_len: usize) -> Self {
        Self {
            timestamp_len,
            has_msg_counter: false,
            dest_id_len: None,
            spare_bytes: 0,
        }
    }
}

#[derive(PartialEq, Eq, Copy, Clone, Debug)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct PusTmSecondaryHeader<'stamp> {
    pus_version: PusVersion,
    pub service: u8,
    pub subservice: u8,
    pub msg_counter: Option<u8>,
    pub dest_id: Option<UnsignedByteField>,
    pub timestamp: &'stamp [u8],
    pub spare_bytes: usize,
}

impl<'stamp> PusTmSecondaryHeader<'stamp> {
    #[inline]
    pub fn new_simple(service: u8, subservice: u8, timestamp: &'stamp [u8]) -> Self {
        Self::new(service, subservice, None, None, timestamp, 0)
    }

    /// Like [Self::new_simple] but without a timestamp.
    #[inline]
    pub fn new_simple_no_timestamp(service: u8, subservice: u8) -> Self {
        Self::new(service, subservice, None, None, &[], 0)
    }

    #[inline]
    pub fn new(
        service: u8,
        subservice: u8,
        msg_counter: Option<u8>,
        dest_id: Option<UnsignedByteField>,
        timestamp: &'stamp [u8],
        spare_bytes: usize,
    ) -> Self {
        PusTmSecondaryHeader {
            pus_version: PusVersion::PusA,
            service,
            subservice,
            msg_counter,
            dest_id,
            timestamp,
            spare_bytes,
        }
    }

    pub fn from_bytes(
        buf: &'stamp [u8],
        params: &SecondaryHeaderParameters,
    ) -> Result<PusTmSecondaryHeader<'stamp>, PusError> {
        let sec_header_len = Self::len_for_params(params);
        if buf.len() < sec_header_len {
            return Err(ByteConversionError::FromSliceTooSmall {
                found: buf.len(),
                expected: sec_header_len,
            }
            .into());
        }
        let pus_version = PusVersion::try_from((buf[0] >> 4) & 0x0F);
        if let Err(version_raw) = pus_version {
            return Err(PusError::VersionNotSupported(version_raw));
        }
        let pus_version = pus_version.unwrap();
        if pus_version != PusVersion::PusA {
            return Err(PusError::VersionNotSupported(pus_version as u8));
        }
        let mut msg_counter = None;
        let mut current_idx = 3;
        if params.has_msg_counter {
            msg_counter = Some(buf[current_idx]);
            current_idx += 1;
        }
        let mut dest_id = None;
        if let Some(dest_id_len) = params.dest_id_len {
            dest_id = Some(
                UnsignedByteField::new_from_be_bytes(
                    dest_id_len,
                    &buf[current_idx..current_idx + dest_id_len],
                )
                .unwrap(),
            );
            current_idx += dest_id_len;
        }
        Ok(Self {
            pus_version,
            service: buf[1],
            subservice: buf[2],
            msg_counter,
            dest_id,
            timestamp: &buf[current_idx..current_idx + params.timestamp_len],
            spare_bytes: params.spare_bytes,
        })
    }

    pub fn write_to_be_bytes(&self, buf: &mut [u8]) -> Result<usize, ByteConversionError> {
        let written_len = self.written_len();
        if buf.len() < written_len {
            return Err(ByteConversionError::ToSliceTooSmall {
                found: buf.len(),
                expected: PUS_TM_MIN_SEC_HEADER_LEN,
            });
        }
        buf[0] = (self.pus_version as u8) << 4;
        buf[1] = self.service;
        buf[2] = self.subservice;
        let mut current_idx = 3;
        if let Some(msg_counter) = self.msg_counter {
            buf[current_idx] = msg_counter;
            current_idx += 1;
        }
        if let Some(dest_id) = self.dest_id {
            dest_id.write_to_be_bytes(&mut buf[current_idx..current_idx + dest_id.size()])?;
            current_idx += dest_id.size();
        }
        buf[current_idx..current_idx + self.timestamp.len()].copy_from_slice(self.timestamp);
        current_idx += self.timestamp.len();
        if self.spare_bytes > 0 {
            buf[current_idx..current_idx + self.spare_bytes].fill(0);
        }
        Ok(written_len)
    }

    #[cfg(feature = "alloc")]
    pub fn to_vec(&self) -> Vec<u8> {
        let mut vec = alloc::vec![0; self.written_len()];
        self.write_to_be_bytes(&mut vec).unwrap();
        vec
    }

    pub fn written_len(&self) -> usize {
        let mut len = PUS_TM_MIN_SEC_HEADER_LEN + self.timestamp.len() + self.spare_bytes;
        if let Some(dest_id) = self.dest_id {
            len += dest_id.size();
        }
        if self.msg_counter.is_some() {
            len += 1;
        }
        len
    }

    pub fn len_for_params(params: &SecondaryHeaderParameters) -> usize {
        let mut len = PUS_TM_MIN_SEC_HEADER_LEN + params.timestamp_len + params.spare_bytes;
        if let Some(dest_id) = params.dest_id_len {
            len += dest_id;
        }
        if params.has_msg_counter {
            len += 1;
        }
        len
    }
}

impl GenericPusTmSecondaryHeader for PusTmSecondaryHeader<'_> {
    #[inline]
    fn pus_version(&self) -> PusVersion {
        self.pus_version
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
    fn msg_counter(&self) -> Option<u8> {
        self.msg_counter
    }

    #[inline]
    fn dest_id(&self) -> Option<UnsignedByteField> {
        self.dest_id
    }

    #[inline]
    fn spare_bytes(&self) -> usize {
        self.spare_bytes
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
    /// * `set_ccsds_len` - Can be used to automatically update the CCSDS space packet data length
    ///   field. If this is not set to true, [Self::update_ccsds_data_len] can be called to set
    ///   the correct value to this field manually
    #[inline]
    pub fn new(
        mut sp_header: SpHeader,
        sec_header: PusTmSecondaryHeader<'time>,
        source_data: &'src_data [u8],
        set_ccsds_len: bool,
    ) -> Self {
        sp_header.set_packet_type(PacketType::Tm);
        sp_header.set_sec_header_flag();
        let mut pus_tm = Self {
            sp_header,
            source_data,
            sec_header,
            calc_crc_on_serialization: true,
        };
        if set_ccsds_len {
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
        set_ccsds_len: bool,
    ) -> Result<Self, TimestampError> {
        let stamp_size = time_provider.write_to_bytes(stamp_buf)?;
        let sec_header =
            PusTmSecondaryHeader::new_simple(service, subservice, &stamp_buf[0..stamp_size]);
        Ok(Self::new(sp_header, sec_header, source_data, set_ccsds_len))
    }

    #[inline]
    pub fn new_no_source_data(
        sp_header: SpHeader,
        sec_header: PusTmSecondaryHeader<'time>,
        set_ccsds_len: bool,
    ) -> Self {
        Self::new(sp_header, sec_header, &[], set_ccsds_len)
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
    pub fn set_dest_id(&mut self, dest_id: Option<UnsignedByteField>) {
        self.sec_header.dest_id = dest_id;
    }

    #[inline]
    pub fn set_msg_counter(&mut self, msg_counter: Option<u8>) {
        self.sec_header.msg_counter = msg_counter
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
        let mut fixed_header_part: [u8; PUS_TM_MIN_SEC_HEADER_LEN] = [0; PUS_TM_MIN_SEC_HEADER_LEN];
        fixed_header_part[0] = (self.sec_header.pus_version() as u8) << 4;
        fixed_header_part[1] = self.sec_header.service;
        fixed_header_part[2] = self.sec_header.subservice;

        digest.update(fixed_header_part.as_slice());
        if let Some(msg_counter) = self.sec_header.msg_counter {
            digest.update(&[msg_counter]);
        }
        if let Some(dest_id) = self.sec_header.dest_id {
            let mut dest_id_buf: [u8; core::mem::size_of::<u64>()] =
                [0; core::mem::size_of::<u64>()];
            // Unwrap okay, this can never fail because we created a buffer with the largest
            // possible size.
            let len = dest_id.write_to_be_bytes(&mut dest_id_buf).unwrap();
            digest.update(&dest_id_buf[0..len]);
        }
        digest.update(self.sec_header.timestamp);
        for _ in 0..self.sec_header.spare_bytes {
            digest.update(&[0]);
        }
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
        Ok(writer_unfinalized.finalize_crc_no_table())
    }

    /// Write the raw PUS byte representation to a provided buffer.
    pub fn write_to_bytes_no_crc(&self, slice: &mut [u8]) -> Result<usize, ByteConversionError> {
        let writer_unfinalized = self.common_write(slice)?;
        Ok(writer_unfinalized.finalize_no_crc())
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
        appended_len += self.source_data.len();
        let start_idx = vec.len();
        vec.extend_from_slice(sph_zc.as_bytes());
        vec.extend_from_slice(&self.sec_header.to_vec());
        vec.extend_from_slice(self.source_data);
        let mut digest = CRC_CCITT_FALSE.digest();
        digest.update(&vec[start_idx..start_idx + appended_len - 2]);
        vec.extend_from_slice(&digest.finalize().to_be_bytes());
        Ok(appended_len)
    }
}

impl WritablePusPacket for PusTmCreator<'_, '_> {
    #[inline]
    fn len_written(&self) -> usize {
        CCSDS_HEADER_LEN + self.sec_header.written_len() + self.source_data.len() + 2
    }

    /// Currently, checksum is always added.
    fn has_checksum(&self) -> bool {
        true
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
    fn pus_version(&self) -> Result<PusVersion, u8> {
        Ok(self.sec_header.pus_version)
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
        Some(self.calc_own_crc16())
    }
}

impl GenericPusTmSecondaryHeader for PusTmCreator<'_, '_> {
    delegate!(to self.sec_header {
        #[inline]
        fn pus_version(&self) -> PusVersion;
        #[inline]
        fn service(&self) -> u8;
        #[inline]
        fn subservice(&self) -> u8;
        #[inline]
        fn dest_id(&self) -> Option<UnsignedByteField>;
        #[inline]
        fn msg_counter(&self) -> Option<u8>;
        #[inline]
        fn spare_bytes(&self) -> usize;
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
    ) -> Result<Self, ByteConversionError> {
        sp_header.set_packet_type(PacketType::Tm);
        sp_header.set_sec_header_flag();
        let len_written =
            PUS_TM_MIN_LEN_WITHOUT_SOURCE_DATA + sec_header.timestamp.len() + src_data_len;
        if len_written > buf.len() {
            return Err(ByteConversionError::ToSliceTooSmall {
                found: buf.len(),
                expected: len_written,
            });
        }
        sp_header.data_len = len_written as u16 - size_of::<crate::zc::SpHeader>() as u16 - 1;
        Self::write_to_bytes_partially(buf, sp_header, sec_header, src_data_len)
    }

    fn write_to_bytes_partially(
        buf: &'buf mut [u8],
        sp_header: SpHeader,
        sec_header: PusTmSecondaryHeader,
        src_data_len: usize,
    ) -> Result<Self, ByteConversionError> {
        let mut curr_idx = 0;
        sp_header.write_to_be_bytes(&mut buf[0..CCSDS_HEADER_LEN])?;
        curr_idx += CCSDS_HEADER_LEN;
        curr_idx += sec_header.write_to_be_bytes(&mut buf[CCSDS_HEADER_LEN..])?;
        let source_data_offset = curr_idx;
        curr_idx += src_data_len;
        Ok(Self {
            buf,
            source_data_offset,
            full_len: curr_idx + 2,
        })
    }

    #[inline]
    pub const fn len_written(&self) -> usize {
        self.full_len
    }

    /// Mutable access to the source data buffer.
    #[inline]
    pub fn source_data_mut(&mut self) -> &mut [u8] {
        &mut self.buf[self.source_data_offset..self.full_len - 2]
    }

    /// Access to the source data buffer.
    #[inline]
    pub fn source_data(&self) -> &[u8] {
        &self.buf[self.source_data_offset..self.full_len - 2]
    }

    #[inline]
    pub fn source_data_len(&self) -> usize {
        self.full_len - 2 - self.source_data_offset
    }

    /// Finalize the TM packet by calculating and writing the CRC16.
    ///
    /// Returns the full packet length.
    pub fn finalize(self) -> usize {
        let mut digest = CRC_CCITT_FALSE.digest();
        digest.update(&self.buf[0..self.full_len - 2]);
        self.buf[self.full_len - 2..self.full_len]
            .copy_from_slice(&digest.finalize().to_be_bytes());
        self.full_len
    }

    /// Finalize the TM packet by calculating and writing the CRC16 using a table-less
    /// implementation.
    ///
    /// Returns the full packet length.
    pub fn finalize_crc_no_table(self) -> usize {
        let mut digest = CRC_CCITT_FALSE_NO_TABLE.digest();
        digest.update(&self.buf[0..self.full_len - 2]);
        self.buf[self.full_len - 2..self.full_len]
            .copy_from_slice(&digest.finalize().to_be_bytes());
        self.full_len
    }

    /// Finalize the TM packet without writing the CRC16.
    ///
    /// Returns the length WITHOUT the CRC16.
    #[inline]
    pub fn finalize_no_crc(self) -> usize {
        self.full_len - 2
    }
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
    crc16: u16,
}

impl<'raw_data> PusTmReader<'raw_data> {
    /// Create a [PusTmReader] instance from a raw slice. On success, it returns a tuple containing
    /// the instance and the found byte length of the packet. The timestamp length needs to be
    /// known beforehand.
    ///
    /// This function will check the CRC-16 of the PUS packet and will return an appropriate
    /// [PusError] if the check fails.
    pub fn new(
        slice: &'raw_data [u8],
        sec_header_params: &SecondaryHeaderParameters,
    ) -> Result<Self, PusError> {
        let tc = Self::new_no_crc_check(slice, sec_header_params)?;
        verify_crc16_ccitt_false_from_raw_to_pus_error(tc.raw_data(), tc.crc16)?;
        Ok(tc)
    }

    /// Like [PusTmReader::new] but uses a table-less CRC implementation.
    pub fn new_crc_no_table(
        slice: &'raw_data [u8],
        sec_header_params: &SecondaryHeaderParameters,
    ) -> Result<Self, PusError> {
        let tc = Self::new_no_crc_check(slice, sec_header_params)?;
        verify_crc16_ccitt_false_from_raw_to_pus_error_no_table(tc.raw_data(), tc.crc16)?;
        Ok(tc)
    }

    pub fn new_no_crc_check(
        slice: &'raw_data [u8],
        sec_header_params: &SecondaryHeaderParameters,
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
        current_idx += CCSDS_HEADER_LEN;
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
        let sec_header =
            PusTmSecondaryHeader::from_bytes(&slice[current_idx..], sec_header_params)?;
        current_idx += sec_header.written_len();
        let raw_data = &slice[0..total_len];
        Ok(Self {
            sp_header,
            sec_header,
            raw_data: &slice[0..total_len],
            source_data: user_data_from_raw(current_idx, total_len, slice, true)?,
            crc16: crc_from_raw_data(raw_data)?,
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
    pub fn crc16(&self) -> u16 {
        self.crc16
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
            && self.crc16 == other.crc16
    }
}

impl CcsdsPacket for PusTmReader<'_> {
    ccsds_impl!();
}

impl PusPacket for PusTmReader<'_> {
    #[inline]
    fn pus_version(&self) -> Result<PusVersion, u8> {
        Ok(self.sec_header.pus_version)
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
        Some(self.crc16())
    }
}

impl GenericPusTmSecondaryHeader for PusTmReader<'_> {
    delegate!(to self.sec_header {
        #[inline]
        fn pus_version(&self) -> PusVersion;
        #[inline]
        fn service(&self) -> u8;
        #[inline]
        fn subservice(&self) -> u8;
        #[inline]
        fn dest_id(&self) -> Option<UnsignedByteField>;
        #[inline]
        fn msg_counter(&self) -> Option<u8>;
        #[inline]
        fn spare_bytes(&self) -> usize;
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

#[derive(Debug, thiserror::Error)]
#[error("this field is not present in the secondary header")]
pub struct SecondaryHeaderFieldNotPresentError;

#[derive(Debug, thiserror::Error)]
pub enum DestIdOperationError {
    #[error("this field is not present in the secondary header")]
    FieldNotPresent(#[from] SecondaryHeaderFieldNotPresentError),
    #[error("invalid byte field length")]
    InvalidFieldLen,
    #[error("byte conversion error")]
    ByteConversionError(#[from] ByteConversionError),
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
    sec_header_params: SecondaryHeaderParameters,
}

impl<'raw> PusTmZeroCopyWriter<'raw> {
    /// This function will not do any other checks on the raw data other than a length check
    /// for all internal fields which can be updated.
    ///
    /// It is the responsibility of the user to ensure the raw slice contains a valid telemetry
    /// packet.
    pub fn new(
        raw_tm: &'raw mut [u8],
        sec_header_params: &SecondaryHeaderParameters,
    ) -> Option<Self> {
        let raw_tm_len = raw_tm.len();
        if raw_tm_len
            < CCSDS_HEADER_LEN + PUS_TM_MIN_SEC_HEADER_LEN + sec_header_params.timestamp_len
        {
            return None;
        }
        let sp_header = crate::zc::SpHeader::read_from_bytes(&raw_tm[0..CCSDS_HEADER_LEN]).unwrap();
        if raw_tm_len < sp_header.packet_len() {
            return None;
        }
        let writer = Self {
            raw_tm: &mut raw_tm[..sp_header.packet_len()],
            sec_header_params: *sec_header_params,
        };
        Some(writer)
    }

    /// Set the sequence count. Returns false and does not update the value if the passed value
    /// exceeds [MAX_APID].
    #[inline]
    pub fn set_apid(&mut self, apid: u16) -> bool {
        if apid > MAX_APID {
            return false;
        }
        // Clear APID part of the raw packet ID
        let updated_apid =
            ((((self.raw_tm[0] as u16) << 8) | self.raw_tm[1] as u16) & !MAX_APID) | apid;
        self.raw_tm[0..2].copy_from_slice(&updated_apid.to_be_bytes());
        true
    }

    pub fn dest_id(&self) -> Result<Option<UnsignedByteField>, ByteConversionError> {
        if self.sec_header_params.dest_id_len.is_none() {
            return Ok(None);
        }
        let mut base_idx = 10;
        if self.sec_header_params.has_msg_counter {
            base_idx += 1;
        }
        let dest_id_len = self.sec_header_params.dest_id_len.unwrap();
        if self.raw_tm.len() < base_idx + dest_id_len {
            return Err(ByteConversionError::FromSliceTooSmall {
                found: self.raw_tm.len(),
                expected: base_idx + dest_id_len,
            });
        }
        Ok(Some(
            UnsignedByteField::new_from_be_bytes(
                dest_id_len,
                &self.raw_tm[base_idx..base_idx + dest_id_len],
            )
            .unwrap(),
        ))
    }

    pub fn msg_counter(&self) -> Option<u8> {
        if !self.sec_header_params.has_msg_counter {
            return None;
        }
        Some(self.raw_tm[9])
    }

    /// This function sets the message counter in the PUS TM secondary header.
    ///
    /// Please note that usage of this function is only valid if the secondary header has a
    /// packet subcounter field, which is a manged parameter which might not be present.
    #[inline]
    pub fn set_msg_count(
        &mut self,
        msg_count: u8,
    ) -> Result<(), SecondaryHeaderFieldNotPresentError> {
        if !self.sec_header_params.has_msg_counter {
            return Err(SecondaryHeaderFieldNotPresentError);
        }
        self.raw_tm[9] = msg_count;
        Ok(())
    }

    /// This function sets the destination ID in the PUS TM secondary header.
    #[inline]
    pub fn set_destination_id(
        &mut self,
        dest_id: UnsignedByteField,
    ) -> Result<(), DestIdOperationError> {
        if self.sec_header_params.dest_id_len.is_none() {
            return Err(SecondaryHeaderFieldNotPresentError.into());
        }
        let dest_id_len = self.sec_header_params.dest_id_len.unwrap();
        if dest_id.size() != dest_id_len {
            return Err(DestIdOperationError::InvalidFieldLen);
        }
        let mut base_idx = 10;
        if self.sec_header_params.has_msg_counter {
            base_idx += 1;
        }
        if self.raw_tm.len() < base_idx + dest_id_len {
            return Err(DestIdOperationError::ByteConversionError(
                ByteConversionError::ToSliceTooSmall {
                    found: self.raw_tm.len(),
                    expected: base_idx + dest_id_len,
                },
            ));
        }
        dest_id
            .write_to_be_bytes(&mut self.raw_tm[base_idx..base_idx + dest_id_len])
            .unwrap();
        Ok(())
    }

    /// Helper API to generate the space packet header portion of the PUS TM from the raw memory.
    #[inline]
    pub fn sp_header(&self) -> crate::zc::SpHeader {
        // Valid minimum length of packet was checked before.
        crate::zc::SpHeader::read_from_bytes(&self.raw_tm[0..CCSDS_HEADER_LEN]).unwrap()
    }

    /// Set the sequence count. Returns false and does not update the value if the passed value
    /// exceeds [MAX_SEQ_COUNT].
    #[inline]
    pub fn set_seq_count(&mut self, seq_count: u16) -> bool {
        if seq_count > MAX_SEQ_COUNT {
            return false;
        }
        let new_psc =
            (u16::from_be_bytes(self.raw_tm[2..4].try_into().unwrap()) & 0xC000) | seq_count;
        self.raw_tm[2..4].copy_from_slice(&new_psc.to_be_bytes());
        true
    }

    /// This method has to be called after modifying fields to ensure the CRC16 of the telemetry
    /// packet remains valid.
    pub fn finish(self) {
        let slice_len = self.raw_tm.len();
        let crc16 = calc_pus_crc16(&self.raw_tm[..slice_len - 2]);
        self.raw_tm[slice_len - 2..].copy_from_slice(&crc16.to_be_bytes());
    }
}

impl CcsdsPacket for PusTmZeroCopyWriter<'_> {
    #[inline]
    fn ccsds_version(&self) -> u8 {
        self.sp_header().ccsds_version()
    }

    #[inline]
    fn packet_id(&self) -> crate::PacketId {
        self.sp_header().packet_id()
    }

    #[inline]
    fn psc(&self) -> crate::PacketSequenceCtrl {
        self.sp_header().psc()
    }

    #[inline]
    fn data_len(&self) -> u16 {
        self.sp_header().data_len()
    }
}

impl PusPacket for PusTmZeroCopyWriter<'_> {
    #[inline]
    fn pus_version(&self) -> Result<PusVersion, u8> {
        PusVersion::try_from(self.raw_tm[6])
    }

    #[inline]
    fn service(&self) -> u8 {
        self.raw_tm[7]
    }

    #[inline]
    fn subservice(&self) -> u8 {
        self.raw_tm[8]
    }

    #[inline]
    fn user_data(&self) -> &[u8] {
        &self.raw_tm[CCSDS_HEADER_LEN
            + PUS_TM_MIN_SEC_HEADER_LEN
            + self.sec_header_params.timestamp_len
            ..self.sp_header().packet_len() - 2]
    }

    #[inline]
    fn checksum(&self) -> Option<u16> {
        Some(u16::from_be_bytes(
            self.raw_tm[self.sp_header().packet_len() - 2..self.sp_header().packet_len()]
                .try_into()
                .unwrap(),
        ))
    }
}

#[cfg(test)]
mod tests {
    use alloc::string::ToString;

    use super::*;
    use crate::time::cds::CdsTime;
    use crate::SpHeader;
    use crate::{ecss::PusVersion::PusA, util::UnsignedByteFieldU16};
    #[cfg(feature = "serde")]
    use postcard::{from_bytes, to_allocvec};

    const DUMMY_DATA: &[u8] = &[0, 1, 2];
    const MIN_SEC_HEADER_PARAMS: SecondaryHeaderParameters =
        SecondaryHeaderParameters::new_minimal(7);

    fn ping_reply_no_data<'a, 'b>(
        timestamp: &'a [u8],
        dest_id: Option<UnsignedByteField>,
    ) -> PusTmCreator<'a, 'b> {
        let sph = SpHeader::new_for_unseg_tm_checked(0x123, 0x234, 0).unwrap();
        let mut tm_header = PusTmSecondaryHeader::new_simple(17, 2, timestamp);
        tm_header.dest_id = dest_id;
        PusTmCreator::new_no_source_data(sph, tm_header, true)
    }

    fn ping_reply_with_data_and_additional_fields<'a, 'b>(
        data: &'b [u8],
        msg_counter: Option<u8>,
        dest_id: Option<UnsignedByteField>,
        timestamp: &'a [u8],
    ) -> PusTmCreator<'a, 'b> {
        let sph = SpHeader::new_for_unseg_tm_checked(0x123, 0x234, 0).unwrap();
        let tm_header = PusTmSecondaryHeader::new(17, 2, msg_counter, dest_id, timestamp, 0);
        PusTmCreator::new(sph, tm_header, data, true)
    }

    fn ping_reply_with_data<'a, 'b>(data: &'b [u8], timestamp: &'a [u8]) -> PusTmCreator<'a, 'b> {
        let sph = SpHeader::new_for_unseg_tm_checked(0x123, 0x234, 0).unwrap();
        let tm_header = PusTmSecondaryHeader::new_simple(17, 2, timestamp);
        PusTmCreator::new(sph, tm_header, data, true)
    }

    fn base_hk_reply<'a, 'b>(timestamp: &'a [u8], src_data: &'b [u8]) -> PusTmCreator<'a, 'b> {
        let sph = SpHeader::new_for_unseg_tm_checked(0x123, 0x234, 0).unwrap();
        let tc_header = PusTmSecondaryHeader::new_simple(3, 5, timestamp);
        PusTmCreator::new(sph, tc_header, src_data, true)
    }

    fn dummy_timestamp() -> &'static [u8] {
        &[0, 1, 2, 3, 4, 5, 6]
    }

    #[test]
    fn test_basic() {
        let timestamp = dummy_timestamp();
        let pus_tm = ping_reply_no_data(timestamp, None);
        verify_ping_reply(&pus_tm, false, 18, dummy_timestamp(), None, None);
    }

    #[test]
    fn test_basic_simple_api() {
        let sph = SpHeader::new_for_unseg_tm_checked(0x123, 0x234, 0).unwrap();
        let time_provider = CdsTime::new_with_u16_days(0, 0);
        let mut stamp_buf: [u8; 8] = [0; 8];
        let pus_tm =
            PusTmCreator::new_simple(sph, 17, 2, &time_provider, &mut stamp_buf, &[], true)
                .unwrap();
        verify_ping_reply(&pus_tm, false, 18, &[64, 0, 0, 0, 0, 0, 0], None, None);
    }

    #[test]
    fn test_basic_simple_api_with_dest_id_msg_counter() {
        let msg_counter = Some(5);
        let dest_id = Some(UnsignedByteFieldU16::new(0x1f1f).into());
        let pus_tm = ping_reply_with_data_and_additional_fields(
            &[],
            msg_counter,
            dest_id,
            dummy_timestamp(),
        );
        verify_ping_reply(&pus_tm, false, 21, dummy_timestamp(), dest_id, msg_counter);
    }

    #[test]
    fn test_basic_simple_api_with_dest_id() {
        let msg_counter = None;
        let dest_id = Some(UnsignedByteFieldU16::new(0x1f1f).into());
        let pus_tm = ping_reply_with_data_and_additional_fields(
            &[],
            msg_counter,
            dest_id,
            dummy_timestamp(),
        );
        verify_ping_reply(&pus_tm, false, 20, dummy_timestamp(), dest_id, msg_counter);
    }

    #[test]
    fn test_basic_simple_api_with_msg_counter() {
        let msg_counter = Some(5);
        let dest_id = None;
        let pus_tm = ping_reply_with_data_and_additional_fields(
            &[],
            msg_counter,
            dest_id,
            dummy_timestamp(),
        );
        verify_ping_reply(&pus_tm, false, 19, dummy_timestamp(), dest_id, msg_counter);
    }

    #[test]
    fn test_serialization_no_source_data() {
        let timestamp = dummy_timestamp();
        let pus_tm = ping_reply_no_data(timestamp, None);
        let mut buf: [u8; 32] = [0; 32];
        let ser_len = pus_tm
            .write_to_bytes(&mut buf)
            .expect("Serialization failed");
        assert_eq!(ser_len, 18);
        verify_raw_ping_reply(pus_tm.checksum(), &buf, ser_len, None, None);
    }

    #[test]
    fn test_serialization_with_additional_fields() {
        let msg_counter = Some(5);
        let dest_id = Some(UnsignedByteFieldU16::new(0x1f1f).into());
        let pus_tm = ping_reply_with_data_and_additional_fields(
            &[],
            msg_counter,
            dest_id,
            dummy_timestamp(),
        );
        let mut buf: [u8; 32] = [0; 32];
        let ser_len = pus_tm
            .write_to_bytes(&mut buf)
            .expect("Serialization failed");
        assert_eq!(ser_len, 21);
        verify_raw_ping_reply(pus_tm.checksum(), &buf, ser_len, msg_counter, dest_id);
    }

    #[test]
    fn test_serialization_with_dest_id() {
        let msg_counter = None;
        let dest_id = Some(UnsignedByteFieldU16::new(0x1f1f).into());
        let pus_tm = ping_reply_with_data_and_additional_fields(
            &[],
            msg_counter,
            dest_id,
            dummy_timestamp(),
        );
        let mut buf: [u8; 32] = [0; 32];
        let ser_len = pus_tm
            .write_to_bytes(&mut buf)
            .expect("Serialization failed");
        assert_eq!(ser_len, 20);
        verify_raw_ping_reply(pus_tm.checksum(), &buf, ser_len, msg_counter, dest_id);
    }

    #[test]
    fn test_serialization_with_msg_counter() {
        let msg_counter = Some(5);
        let dest_id = None;
        let pus_tm = ping_reply_with_data_and_additional_fields(
            &[],
            msg_counter,
            dest_id,
            dummy_timestamp(),
        );
        let mut buf: [u8; 32] = [0; 32];
        let ser_len = pus_tm
            .write_to_bytes(&mut buf)
            .expect("Serialization failed");
        assert_eq!(ser_len, 19);
        verify_raw_ping_reply(pus_tm.checksum(), &buf, ser_len, msg_counter, dest_id);
    }

    #[test]
    fn test_serialization_no_source_data_alt_ctor() {
        let timestamp = dummy_timestamp();
        let sph = SpHeader::new_for_unseg_tm_checked(0x123, 0x234, 0).unwrap();
        let tm_header = PusTmSecondaryHeader::new_simple(17, 2, timestamp);
        let mut buf: [u8; 32] = [0; 32];
        let mut pus_tm =
            PusTmCreatorWithReservedSourceData::new(&mut buf, sph, tm_header, 0).unwrap();
        assert_eq!(pus_tm.source_data_len(), 0);
        assert_eq!(pus_tm.source_data(), &[]);
        assert_eq!(pus_tm.source_data_mut(), &[]);
        let ser_len = pus_tm.finalize();
        assert_eq!(ser_len, 18);
        verify_raw_ping_reply(None, &buf, ser_len, None, None);
    }

    #[test]
    fn test_serialization_no_source_data_alt_ctor_no_crc() {
        let timestamp = dummy_timestamp();
        let sph = SpHeader::new_for_unseg_tm_checked(0x123, 0x234, 0).unwrap();
        let tm_header = PusTmSecondaryHeader::new_simple(17, 2, timestamp);
        let mut buf: [u8; 32] = [0; 32];
        let mut pus_tm =
            PusTmCreatorWithReservedSourceData::new(&mut buf, sph, tm_header, 0).unwrap();
        assert_eq!(pus_tm.source_data_len(), 0);
        assert_eq!(pus_tm.source_data(), &[]);
        assert_eq!(pus_tm.source_data_mut(), &[]);
        let ser_len = pus_tm.finalize_no_crc();
        assert_eq!(ser_len, 16);
        verify_raw_ping_reply_no_crc(&buf, None, None);
        assert_eq!(buf[16], 0);
        assert_eq!(buf[17], 0);
    }

    #[test]
    fn test_serialization_no_source_data_no_table() {
        let timestamp = dummy_timestamp();
        let pus_tm = ping_reply_no_data(timestamp, None);
        let mut buf: [u8; 32] = [0; 32];
        let ser_len = pus_tm
            .write_to_bytes_crc_no_table(&mut buf)
            .expect("Serialization failed");
        assert_eq!(ser_len, 18);
        verify_raw_ping_reply(pus_tm.checksum(), &buf, ser_len, None, None);
    }

    #[test]
    fn test_serialization_no_source_data_no_crc() {
        let timestamp = dummy_timestamp();
        let pus_tm = ping_reply_no_data(timestamp, None);
        let mut buf: [u8; 32] = [0; 32];
        let ser_len = pus_tm
            .write_to_bytes_no_crc(&mut buf)
            .expect("Serialization failed");
        assert_eq!(ser_len, 16);
        assert_eq!(buf[16], 0);
        assert_eq!(buf[17], 0);
    }

    #[test]
    fn test_serialization_with_source_data() {
        let src_data = [1, 2, 3];
        let hk_reply = base_hk_reply(dummy_timestamp(), &src_data);
        let mut buf: [u8; 32] = [0; 32];
        let ser_len = hk_reply
            .write_to_bytes(&mut buf)
            .expect("Serialization failed");
        assert_eq!(ser_len, 21);
        assert_eq!(buf[16], 1);
        assert_eq!(buf[17], 2);
        assert_eq!(buf[18], 3);
    }

    #[test]
    fn test_serialization_with_source_data_alt_ctor() {
        let src_data = &[1, 2, 3];
        let mut buf: [u8; 32] = [0; 32];
        let sph = SpHeader::new_for_unseg_tm_checked(0x123, 0x234, 0).unwrap();
        let tc_header = PusTmSecondaryHeader::new_simple(3, 5, dummy_timestamp());
        let mut hk_reply_unwritten =
            PusTmCreatorWithReservedSourceData::new(&mut buf, sph, tc_header, 3).unwrap();
        assert_eq!(hk_reply_unwritten.source_data_len(), 3);
        assert_eq!(hk_reply_unwritten.source_data(), &[0, 0, 0]);
        assert_eq!(hk_reply_unwritten.source_data_mut(), &[0, 0, 0]);
        let source_data_mut = hk_reply_unwritten.source_data_mut();
        source_data_mut.copy_from_slice(src_data);
        let ser_len = hk_reply_unwritten.finalize();
        assert_eq!(ser_len, 21);
        assert_eq!(buf[16], 1);
        assert_eq!(buf[17], 2);
        assert_eq!(buf[18], 3);
    }

    #[test]
    fn test_serialization_with_source_data_alt_ctor_no_table() {
        let src_data = &[1, 2, 3];
        let mut buf: [u8; 32] = [0; 32];
        let sph = SpHeader::new_for_unseg_tm_checked(0x123, 0x234, 0).unwrap();
        let tc_header = PusTmSecondaryHeader::new_simple(3, 5, dummy_timestamp());
        let mut hk_reply_unwritten =
            PusTmCreatorWithReservedSourceData::new(&mut buf, sph, tc_header, 3).unwrap();
        assert_eq!(hk_reply_unwritten.source_data_len(), 3);
        assert_eq!(hk_reply_unwritten.source_data(), &[0, 0, 0]);
        assert_eq!(hk_reply_unwritten.source_data_mut(), &[0, 0, 0]);
        let source_data_mut = hk_reply_unwritten.source_data_mut();
        source_data_mut.copy_from_slice(src_data);
        let ser_len = hk_reply_unwritten.finalize_crc_no_table();
        assert_eq!(ser_len, 21);
        assert_eq!(buf[16], 1);
        assert_eq!(buf[17], 2);
        assert_eq!(buf[18], 3);
    }

    #[test]
    fn test_setters() {
        let timestamp = dummy_timestamp();
        let mut pus_tm = ping_reply_no_data(timestamp, None);
        let u16_dest_id = UnsignedByteFieldU16::new(0x7fff).into();
        pus_tm.set_dest_id(Some(u16_dest_id));
        pus_tm.set_msg_counter(Some(0x1f));
        assert_eq!(pus_tm.dest_id(), Some(u16_dest_id));
        assert_eq!(pus_tm.msg_counter(), Some(0x1f));
        assert!(pus_tm.set_apid(0x7ff));
        assert_eq!(pus_tm.apid(), 0x7ff);
    }

    #[test]
    fn test_write_into_vec() {
        let timestamp = dummy_timestamp();
        let pus_tm = ping_reply_no_data(timestamp, None);
        let tm_vec = pus_tm.to_vec().expect("Serialization failed");
        assert_eq!(tm_vec.len(), 18);
        let tm_deserialized = PusTmReader::new(tm_vec.as_slice(), &MIN_SEC_HEADER_PARAMS)
            .expect("Deserialization failed");
        assert_eq!(tm_vec.len(), tm_deserialized.packet_len());
        verify_ping_reply_with_reader(&tm_deserialized, false, 18, dummy_timestamp(), None, None);
    }

    #[test]
    fn test_deserialization_no_source_data() {
        let timestamp = dummy_timestamp();
        let pus_tm = ping_reply_no_data(timestamp, None);
        let mut buf: [u8; 32] = [0; 32];
        let ser_len = pus_tm
            .write_to_bytes(&mut buf)
            .expect("Serialization failed");
        assert_eq!(ser_len, 18);
        let tm_deserialized =
            PusTmReader::new(&buf, &MIN_SEC_HEADER_PARAMS).expect("Deserialization failed");
        assert_eq!(ser_len, tm_deserialized.packet_len());
        assert_eq!(tm_deserialized.user_data(), tm_deserialized.source_data());
        assert_eq!(tm_deserialized.raw_data(), &buf[..ser_len]);
        assert_eq!(tm_deserialized.crc16(), pus_tm.checksum().unwrap());
        verify_ping_reply_with_reader(&tm_deserialized, false, 18, dummy_timestamp(), None, None);
    }

    fn generic_test_deserialization_no_source_data_with_additional_fields(
        src_data: &[u8],
        expected_full_len: usize,
        msg_counter: Option<u8>,
        dest_id: Option<UnsignedByteField>,
    ) {
        let timestamp = dummy_timestamp();
        let pus_tm =
            ping_reply_with_data_and_additional_fields(src_data, msg_counter, dest_id, timestamp);
        let mut buf: [u8; 32] = [0; 32];
        let ser_len = pus_tm
            .write_to_bytes(&mut buf)
            .expect("Serialization failed");
        assert_eq!(ser_len, expected_full_len);
        let tm_deserialized = PusTmReader::new(
            &buf,
            &SecondaryHeaderParameters {
                timestamp_len: 7,
                has_msg_counter: msg_counter.is_some(),
                dest_id_len: dest_id.as_ref().map(|id| id.size()),
                spare_bytes: 0,
            },
        )
        .expect("Deserialization failed");
        assert_eq!(ser_len, tm_deserialized.packet_len());
        assert_eq!(tm_deserialized.user_data(), tm_deserialized.source_data());
        assert_eq!(tm_deserialized.raw_data(), &buf[..ser_len]);
        assert_eq!(tm_deserialized.crc16(), pus_tm.checksum().unwrap());
        verify_ping_reply_with_reader(
            &tm_deserialized,
            false,
            expected_full_len,
            dummy_timestamp(),
            dest_id,
            msg_counter,
        );
    }

    #[test]
    fn test_deserialization_with_source_data_dest_id_msg_counter() {
        let msg_counter = Some(5);
        let dest_id = Some(UnsignedByteFieldU16::new(0x1f1f).into());
        generic_test_deserialization_no_source_data_with_additional_fields(
            &[1, 2, 3],
            24,
            msg_counter,
            dest_id,
        );
    }

    #[test]
    fn test_deserialization_no_source_data_with_dest_id_msg_counter() {
        let msg_counter = Some(5);
        let dest_id = Some(UnsignedByteFieldU16::new(0x1f1f).into());
        generic_test_deserialization_no_source_data_with_additional_fields(
            &[],
            21,
            msg_counter,
            dest_id,
        );
    }

    #[test]
    fn test_deserialization_no_source_data_with_msg_counter() {
        let msg_counter = Some(5);
        let dest_id = None;
        generic_test_deserialization_no_source_data_with_additional_fields(
            &[],
            19,
            msg_counter,
            dest_id,
        );
    }

    #[test]
    fn test_deserialization_no_source_data_with_dest_id() {
        let msg_counter = None;
        let dest_id = Some(UnsignedByteFieldU16::new(0x1f1f).into());
        generic_test_deserialization_no_source_data_with_additional_fields(
            &[],
            20,
            msg_counter,
            dest_id,
        );
    }

    #[test]
    fn test_deserialization_no_source_data_with_trait() {
        let timestamp = dummy_timestamp();
        let pus_tm = ping_reply_no_data(timestamp, None);
        let mut buf: [u8; 32] = [0; 32];
        let ser_len =
            WritablePusPacket::write_to_bytes(&pus_tm, &mut buf).expect("Serialization failed");
        assert_eq!(ser_len, 18);
        let tm_deserialized =
            PusTmReader::new(&buf, &MIN_SEC_HEADER_PARAMS).expect("Deserialization failed");
        assert_eq!(ser_len, tm_deserialized.packet_len());
        assert_eq!(tm_deserialized.user_data(), tm_deserialized.source_data());
        assert_eq!(tm_deserialized.raw_data(), &buf[..ser_len]);
        assert_eq!(tm_deserialized.crc16(), pus_tm.checksum().unwrap());
        verify_ping_reply_with_reader(&tm_deserialized, false, 18, dummy_timestamp(), None, None);
    }

    #[test]
    fn test_deserialization_no_table() {
        let timestamp = dummy_timestamp();
        let pus_tm = ping_reply_no_data(timestamp, None);
        let mut buf: [u8; 32] = [0; 32];
        let ser_len = pus_tm
            .write_to_bytes(&mut buf)
            .expect("Serialization failed");
        assert_eq!(ser_len, 18);
        let tm_deserialized = PusTmReader::new_crc_no_table(&buf, &MIN_SEC_HEADER_PARAMS)
            .expect("Deserialization failed");
        assert_eq!(ser_len, tm_deserialized.packet_len());
        assert_eq!(tm_deserialized.user_data(), tm_deserialized.source_data());
        assert_eq!(tm_deserialized.raw_data(), &buf[..ser_len]);
        assert_eq!(tm_deserialized.crc16(), pus_tm.checksum().unwrap());
        verify_ping_reply_with_reader(&tm_deserialized, false, 18, dummy_timestamp(), None, None);
    }

    #[test]
    fn test_deserialization_faulty_crc() {
        let timestamp = dummy_timestamp();
        let pus_tm = ping_reply_no_data(timestamp, None);
        let mut buf: [u8; 32] = [0; 32];
        let ser_len = pus_tm
            .write_to_bytes(&mut buf)
            .expect("Serialization failed");
        assert_eq!(ser_len, 18);
        buf[ser_len - 2] = 0;
        buf[ser_len - 1] = 0;
        let tm_error = PusTmReader::new(&buf, &MIN_SEC_HEADER_PARAMS);
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
        let sph = SpHeader::new_for_unseg_tm_checked(0x123, 0x234, 0).unwrap();
        let tc_header = PusTmSecondaryHeader::new_simple(17, 2, dummy_timestamp());
        let mut tm = PusTmCreator::new_no_source_data(sph, tc_header, false);
        tm.calc_crc_on_serialization = false;
        assert_eq!(tm.data_len(), 0x00);
        let mut buf: [u8; 32] = [0; 32];
        tm.update_ccsds_data_len();
        assert_eq!(tm.data_len(), 11);
        tm.calc_own_crc16();
        let res = tm.write_to_bytes(&mut buf);
        assert!(res.is_ok());
        tm.sp_header.data_len = 0;
        tm.update_packet_fields();
        assert_eq!(tm.data_len(), 11);
    }

    #[test]
    fn test_target_buf_too_small() {
        let timestamp = dummy_timestamp();
        let pus_tm = ping_reply_no_data(timestamp, None);
        let mut buf: [u8; 16] = [0; 16];
        let res = pus_tm.write_to_bytes(&mut buf);
        assert!(res.is_err());
        let error = res.unwrap_err();
        if let ByteConversionError::ToSliceTooSmall { found, expected } = error {
            assert_eq!(expected, 18);
            assert_eq!(found, 16);
        } else {
            panic!("Invalid error {:?}", error);
        }
    }

    #[test]
    #[cfg(feature = "alloc")]
    fn test_append_to_vec() {
        let timestamp = dummy_timestamp();
        let pus_tm = ping_reply_no_data(timestamp, None);
        let mut vec = Vec::new();
        let res = pus_tm.append_to_vec(&mut vec);
        assert!(res.is_ok());
        assert_eq!(res.unwrap(), 18);
        verify_raw_ping_reply(pus_tm.checksum(), vec.as_slice(), res.unwrap(), None, None);
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
        assert_eq!(res.unwrap(), 21);
        assert_eq!(vec.len(), 22);
    }

    fn verify_raw_ping_reply_no_crc(
        buf: &[u8],
        msg_counter: Option<u8>,
        dest_id: Option<UnsignedByteField>,
    ) {
        // Secondary header is set -> 0b0000_1001 , APID occupies last bit of first byte
        assert_eq!(buf[0], 0x09);
        // Rest of APID 0x123
        assert_eq!(buf[1], 0x23);
        // Unsegmented is the default, and first byte of 0x234 occupies this byte as well
        assert_eq!(buf[2], 0xc2);
        assert_eq!(buf[3], 0x34);
        let mut expected_len = 11;
        if let Some(dest_id) = dest_id {
            expected_len += dest_id.size();
        }
        if msg_counter.is_some() {
            expected_len += 1;
        }
        assert_eq!(((buf[4] as u16) << 8) | buf[5] as u16, expected_len as u16);
        assert_eq!(buf[6], (PusA as u8) << 4);
        assert_eq!(buf[7], 17);
        assert_eq!(buf[8], 2);
        let mut current_idx = 9;
        if let Some(msg_counter) = msg_counter {
            assert_eq!(buf[current_idx], msg_counter);
            current_idx += 1;
        }
        if let Some(dest_id) = dest_id {
            let extracted_dest_id =
                UnsignedByteField::new_from_be_bytes(dest_id.size(), &buf[current_idx..])
                    .expect("Failed to extract destination ID");
            assert_eq!(extracted_dest_id, dest_id);
            current_idx += dest_id.size();
        }
        // Timestamp
        assert_eq!(
            &buf[current_idx..current_idx + dummy_timestamp().len()],
            dummy_timestamp()
        );
    }

    fn verify_raw_ping_reply(
        crc16: Option<u16>,
        buf: &[u8],
        exp_full_len: usize,
        msg_counter: Option<u8>,
        dest_id: Option<UnsignedByteField>,
    ) {
        verify_raw_ping_reply_no_crc(buf, msg_counter, dest_id);
        let mut digest = CRC_CCITT_FALSE.digest();
        digest.update(&buf[0..exp_full_len - 2]);
        let crc16_calced = digest.finalize();
        let crc16_read = u16::from_be_bytes([buf[exp_full_len - 2], buf[exp_full_len - 1]]);
        assert_eq!(crc16_read, crc16_calced);
        if let Some(crc16) = crc16 {
            assert_eq!(((crc16 >> 8) & 0xff) as u8, buf[exp_full_len - 2]);
            assert_eq!((crc16 & 0xff) as u8, buf[exp_full_len - 1]);
        }
    }

    fn verify_ping_reply(
        tm: &PusTmCreator,
        has_user_data: bool,
        exp_full_len: usize,
        exp_timestamp: &[u8],
        dest_id: Option<UnsignedByteField>,
        msg_counter: Option<u8>,
    ) {
        assert_eq!(tm.len_written(), exp_full_len);
        assert_eq!(tm.timestamp(), exp_timestamp);
        assert_eq!(tm.source_data(), tm.user_data());
        verify_ping_reply_generic(tm, has_user_data, exp_full_len, dest_id, msg_counter);
    }

    fn verify_ping_reply_with_reader(
        tm: &PusTmReader,
        has_user_data: bool,
        exp_full_len: usize,
        exp_timestamp: &[u8],
        dest_id: Option<UnsignedByteField>,
        msg_counter: Option<u8>,
    ) {
        assert_eq!(tm.len_packed(), exp_full_len);
        assert_eq!(tm.timestamp(), exp_timestamp);
        verify_ping_reply_generic(tm, has_user_data, exp_full_len, dest_id, msg_counter);
    }

    fn verify_ping_reply_generic(
        tm: &(impl GenericPusTmSecondaryHeader + PusPacket),
        has_user_data: bool,
        exp_full_len: usize,
        dest_id: Option<UnsignedByteField>,
        msg_counter: Option<u8>,
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
        assert_eq!(tm.apid(), 0x123);
        assert_eq!(tm.seq_count(), 0x234);
        assert_eq!(PusPacket::pus_version(tm).unwrap(), PusVersion::PusA);
        assert_eq!(
            GenericPusTmSecondaryHeader::pus_version(tm),
            PusVersion::PusA
        );
        assert_eq!(tm.data_len(), exp_full_len as u16 - 7);
        assert_eq!(tm.dest_id(), dest_id);
        assert_eq!(tm.msg_counter(), msg_counter);
    }

    #[test]
    fn partial_eq_pus_tm() {
        let timestamp = dummy_timestamp();
        let pus_tm_1 = ping_reply_no_data(timestamp, None);
        let pus_tm_2 = ping_reply_no_data(timestamp, None);
        assert_eq!(pus_tm_1, pus_tm_2);
    }

    #[test]
    fn partial_eq_serialized_vs_derialized() {
        let timestamp = dummy_timestamp();
        let pus_tm = ping_reply_no_data(timestamp, None);
        let mut buf = [0; 32];
        pus_tm.write_to_bytes(&mut buf).unwrap();
        assert_eq!(
            pus_tm,
            PusTmReader::new(&buf, &MIN_SEC_HEADER_PARAMS).unwrap()
        );
    }

    #[test]
    fn test_zero_copy_writer() {
        let ping_tm = ping_reply_no_data(dummy_timestamp(), None);
        let mut buf: [u8; 64] = [0; 64];
        let tm_size = ping_tm
            .write_to_bytes(&mut buf)
            .expect("writing PUS ping TM failed");
        let mut writer = PusTmZeroCopyWriter::new(&mut buf[..tm_size], &MIN_SEC_HEADER_PARAMS)
            .expect("Creating zero copy writer failed");
        writer.set_seq_count(MAX_SEQ_COUNT);
        writer.set_apid(MAX_APID);
        assert!(!writer.set_apid(MAX_APID + 1));
        assert!(!writer.set_apid(MAX_SEQ_COUNT + 1));
        writer.finish();
        // This performs all necessary checks, including the CRC check.
        let tm_read_back =
            PusTmReader::new(&buf, &MIN_SEC_HEADER_PARAMS).expect("Re-creating PUS TM failed");
        assert_eq!(tm_read_back.packet_len(), tm_size);
        assert!(tm_read_back.msg_counter().is_none());
        assert!(tm_read_back.dest_id().is_none());
        assert_eq!(tm_read_back.seq_count(), MAX_SEQ_COUNT);
        assert_eq!(tm_read_back.apid(), MAX_APID);
    }

    #[test]
    fn test_zero_copy_writer_ccsds_api() {
        let dest_id = UnsignedByteFieldU16::new(0x1f1f);
        let ping_tm = ping_reply_no_data(dummy_timestamp(), Some(dest_id.into()));
        let mut buf: [u8; 64] = [0; 64];
        let tm_size = ping_tm
            .write_to_bytes(&mut buf)
            .expect("writing PUS ping TM failed");
        let mut writer = PusTmZeroCopyWriter::new(
            &mut buf[..tm_size],
            &SecondaryHeaderParameters {
                timestamp_len: dummy_timestamp().len(),
                has_msg_counter: false,
                dest_id_len: Some(2),
                spare_bytes: 0,
            },
        )
        .expect("Creating zero copy writer failed");
        writer.set_seq_count(MAX_SEQ_COUNT);
        writer.set_apid(MAX_APID);
        writer
            .set_destination_id(UnsignedByteFieldU16::new(0xf1f1).into())
            .unwrap();
        assert_eq!(PusPacket::service(&writer), 17);
        assert_eq!(PusPacket::subservice(&writer), 2);
        assert_eq!(
            writer.dest_id().unwrap().unwrap(),
            UnsignedByteFieldU16::new(0xf1f1).into()
        );
        assert_eq!(writer.apid(), MAX_APID);
        assert_eq!(writer.seq_count(), MAX_SEQ_COUNT);
    }

    #[test]
    fn test_zero_copy_pus_api() {
        let ping_tm = ping_reply_with_data(DUMMY_DATA, dummy_timestamp());
        let mut buf: [u8; 64] = [0; 64];
        let tm_size = ping_tm
            .write_to_bytes(&mut buf)
            .expect("writing PUS ping TM failed");
        let crc16_raw = u16::from_be_bytes(buf[tm_size - 2..tm_size].try_into().unwrap());
        let mut writer = PusTmZeroCopyWriter::new(&mut buf[..tm_size], &MIN_SEC_HEADER_PARAMS)
            .expect("Creating zero copy writer failed");
        writer.set_seq_count(MAX_SEQ_COUNT);
        writer.set_apid(MAX_APID);
        assert_eq!(PusPacket::service(&writer), 17);
        assert_eq!(PusPacket::subservice(&writer), 2);
        assert!(writer.dest_id().unwrap().is_none());
        assert!(writer.msg_counter().is_none());
        if let Err(err) = writer.set_destination_id(UnsignedByteFieldU16::new(0xf1f1).into()) {
            matches!(err, DestIdOperationError::FieldNotPresent(_));
        } else {
            panic!("setting destination ID should have failed");
        }
        if let Err(err) = writer.set_msg_count(22) {
            matches!(err, SecondaryHeaderFieldNotPresentError);
        } else {
            panic!("setting destination ID should have failed");
        }
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
        let pus_tm = ping_reply_no_data(timestamp, None);
        let mut buf = [0; 32];
        pus_tm.write_to_bytes(&mut buf).unwrap();
        let tm_0 = PusTmReader::new(&buf, &MIN_SEC_HEADER_PARAMS).unwrap();
        let tm_1 = PusTmReader::new(&buf, &MIN_SEC_HEADER_PARAMS).unwrap();
        assert_eq!(tm_0, tm_1);
    }
    #[test]
    fn test_reader_buf_too_small_2() {
        let timestamp = dummy_timestamp();
        let pus_tm = ping_reply_no_data(timestamp, None);
        let mut buf = [0; 32];
        let written = pus_tm.write_to_bytes(&mut buf).unwrap();
        let tm_error = PusTmReader::new(
            &buf[0..PUS_TM_MIN_LEN_WITHOUT_SOURCE_DATA + 1],
            &MIN_SEC_HEADER_PARAMS,
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
        let pus_tm = ping_reply_no_data(timestamp, None);
        let mut buf = [0; 32];
        pus_tm.write_to_bytes(&mut buf).unwrap();
        let tm_error = PusTmReader::new(&buf[0..5], &MIN_SEC_HEADER_PARAMS);
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
        let sph = SpHeader::new_for_unseg_tm_checked(0x123, 0x234, 0).unwrap();
        let time_provider = CdsTime::new_with_u16_days(0, 0);
        let mut stamp_buf: [u8; 8] = [0; 8];
        let pus_tm =
            PusTmCreator::new_simple(sph, 17, 2, &time_provider, &mut stamp_buf, &[], true)
                .unwrap();

        let output = to_allocvec(&pus_tm).unwrap();
        let output_converted_back: PusTmCreator = from_bytes(&output).unwrap();
        assert_eq!(output_converted_back, pus_tm);
    }

    #[test]
    #[cfg(feature = "serde")]
    fn test_serialization_reader_serde() {
        let sph = SpHeader::new_for_unseg_tm_checked(0x123, 0x234, 0).unwrap();
        let time_provider = CdsTime::new_with_u16_days(0, 0);
        let mut stamp_buf: [u8; 8] = [0; 8];
        let pus_tm =
            PusTmCreator::new_simple(sph, 17, 2, &time_provider, &mut stamp_buf, &[], true)
                .unwrap();
        let pus_tm_vec = pus_tm.to_vec().unwrap();
        let tm_reader = PusTmReader::new(&pus_tm_vec, &MIN_SEC_HEADER_PARAMS).unwrap();
        let output = to_allocvec(&tm_reader).unwrap();
        let output_converted_back: PusTmReader = from_bytes(&output).unwrap();
        assert_eq!(output_converted_back, tm_reader);
    }
}
