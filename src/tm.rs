//! This module contains all components required to create a ECSS PUS C telemetry packets according
//! to [ECSS-E-ST-70-41C](https://ecss.nl/standard/ecss-e-st-70-41c-space-engineering-telemetry-and-telecommand-packet-utilization-15-april-2016/).
use crate::ecss::{
    ccsds_impl, crc_from_raw_data, crc_procedure, user_data_from_raw, verify_crc16_from_raw,
    CrcType, PusError, PusPacket, PusVersion, CRC_CCITT_FALSE,
};
use crate::{CcsdsPacket, PacketError, PacketType, SizeMissmatch, SpHeader, CCSDS_HEADER_LEN};
use core::mem::size_of;
use serde::{Deserialize, Serialize};
use zerocopy::AsBytes;

#[cfg(feature = "alloc")]
use alloc::vec::Vec;
use delegate::delegate;

/// Length without timestamp
pub const PUC_TM_MIN_SEC_HEADER_LEN: usize = 7;
pub const PUS_TM_MIN_LEN_WITHOUT_SOURCE_DATA: usize =
    CCSDS_HEADER_LEN + PUC_TM_MIN_SEC_HEADER_LEN + size_of::<CrcType>();

pub trait PusTmSecondaryHeaderT {
    fn pus_version(&self) -> PusVersion;
    fn sc_time_ref_status(&self) -> u8;
    fn service(&self) -> u8;
    fn subservice(&self) -> u8;
    fn msg_counter(&self) -> u16;
    fn dest_id(&self) -> u16;
}

pub mod zc {
    use crate::ecss::{PusError, PusVersion};
    use zerocopy::{AsBytes, FromBytes, NetworkEndian, Unaligned, U16};

    #[derive(FromBytes, AsBytes, Unaligned)]
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

    impl TryFrom<crate::tm::PusTmSecondaryHeader<'_>> for PusTmSecHeaderWithoutTimestamp {
        type Error = PusError;
        fn try_from(header: crate::tm::PusTmSecondaryHeader) -> Result<Self, Self::Error> {
            if header.pus_version != PusVersion::PusC {
                return Err(PusError::VersionNotSupported(header.pus_version));
            }
            Ok(PusTmSecHeaderWithoutTimestamp {
                pus_version_and_sc_time_ref_status: ((header.pus_version as u8) << 4)
                    | header.sc_time_ref_status,
                service: header.service,
                subservice: header.subservice,
                msg_counter: U16::from(header.msg_counter),
                dest_id: U16::from(header.dest_id),
            })
        }
    }

    impl PusTmSecHeaderWithoutTimestamp {
        pub fn to_bytes(&self, slice: &mut [u8]) -> Option<()> {
            self.write_to(slice)
        }

        pub fn from_bytes(slice: &[u8]) -> Option<Self> {
            Self::read_from(slice)
        }
    }

    impl super::PusTmSecondaryHeaderT for PusTmSecHeaderWithoutTimestamp {
        fn pus_version(&self) -> PusVersion {
            PusVersion::try_from(self.pus_version_and_sc_time_ref_status >> 4 & 0b1111)
                .unwrap_or(PusVersion::Invalid)
        }

        fn sc_time_ref_status(&self) -> u8 {
            self.pus_version_and_sc_time_ref_status & 0b1111
        }

        fn service(&self) -> u8 {
            self.service
        }

        fn subservice(&self) -> u8 {
            self.subservice
        }

        fn msg_counter(&self) -> u16 {
            self.msg_counter.get()
        }

        fn dest_id(&self) -> u16 {
            self.dest_id.get()
        }
    }
}

#[derive(PartialEq, Serialize, Deserialize, Copy, Clone, Debug)]
pub struct PusTmSecondaryHeader<'slice> {
    pus_version: PusVersion,
    pub sc_time_ref_status: u8,
    pub service: u8,
    pub subservice: u8,
    pub msg_counter: u16,
    pub dest_id: u16,
    pub time_stamp: &'slice [u8],
}

impl<'slice> PusTmSecondaryHeader<'slice> {
    pub fn new_simple(service: u8, subservice: u8, time_stamp: &'slice [u8]) -> Self {
        PusTmSecondaryHeader {
            pus_version: PusVersion::PusC,
            sc_time_ref_status: 0,
            service,
            subservice,
            msg_counter: 0,
            dest_id: 0,
            time_stamp,
        }
    }

    pub fn new(
        service: u8,
        subservice: u8,
        msg_counter: u16,
        dest_id: u16,
        time_stamp: &'slice [u8],
    ) -> Self {
        PusTmSecondaryHeader {
            pus_version: PusVersion::PusC,
            sc_time_ref_status: 0,
            service,
            subservice,
            msg_counter,
            dest_id,
            time_stamp,
        }
    }
}

impl PusTmSecondaryHeaderT for PusTmSecondaryHeader<'_> {
    fn pus_version(&self) -> PusVersion {
        self.pus_version
    }

    fn sc_time_ref_status(&self) -> u8 {
        self.sc_time_ref_status
    }

    fn service(&self) -> u8 {
        self.service
    }

    fn subservice(&self) -> u8 {
        self.subservice
    }

    fn msg_counter(&self) -> u16 {
        self.msg_counter
    }

    fn dest_id(&self) -> u16 {
        self.dest_id
    }
}

impl<'slice> TryFrom<zc::PusTmSecHeader<'slice>> for PusTmSecondaryHeader<'slice> {
    type Error = ();

    fn try_from(sec_header: zc::PusTmSecHeader<'slice>) -> Result<Self, Self::Error> {
        Ok(PusTmSecondaryHeader {
            pus_version: sec_header.zc_header.pus_version(),
            sc_time_ref_status: sec_header.zc_header.sc_time_ref_status(),
            service: sec_header.zc_header.service(),
            subservice: sec_header.zc_header.subservice(),
            msg_counter: sec_header.zc_header.msg_counter(),
            dest_id: sec_header.zc_header.dest_id(),
            time_stamp: sec_header.timestamp,
        })
    }
}

/// This class models a PUS telemetry and which can also be used. It is the primary data
/// structure to generate the raw byte representation of PUS telemetry or to
/// deserialize from one from raw bytes.
///
/// This class also derives the [serde::Serialize] and [serde::Deserialize] trait which allows
/// to send around TM packets in a raw byte format using a serde provider like
/// [postcard](https://docs.rs/postcard/latest/postcard/).
///
/// There is no spare bytes support yet.
#[derive(PartialEq, Serialize, Deserialize, Debug, Copy, Clone)]
pub struct PusTm<'slice> {
    pub sp_header: SpHeader,
    pub sec_header: PusTmSecondaryHeader<'slice>,
    /// If this is set to false, a manual call to [PusTm::calc_own_crc16] or
    /// [PusTm::update_packet_fields] is necessary for the serialized or cached CRC16 to be valid.
    pub calc_crc_on_serialization: bool,
    #[serde(skip)]
    raw_data: Option<&'slice [u8]>,
    source_data: Option<&'slice [u8]>,
    crc16: Option<u16>,
}

impl<'slice> PusTm<'slice> {
    /// Generates a new struct instance.
    ///
    /// # Arguments
    ///
    /// * `sp_header` - Space packet header information. The correct packet type will be set
    ///     automatically
    /// * `sec_header` - Information contained in the secondary header, including the service
    ///     and subservice type
    /// * `app_data` - Custom application data
    /// * `set_ccsds_len` - Can be used to automatically update the CCSDS space packet data length
    ///     field. If this is not set to true, [PusTm::update_ccsds_data_len] can be called to set
    ///     the correct value to this field manually
    pub fn new(
        sp_header: &mut SpHeader,
        sec_header: PusTmSecondaryHeader<'slice>,
        source_data: Option<&'slice [u8]>,
        set_ccsds_len: bool,
    ) -> Self {
        sp_header.set_packet_type(PacketType::Tm);
        sp_header.set_sec_header_flag();
        let mut pus_tm = PusTm {
            sp_header: *sp_header,
            raw_data: None,
            source_data,
            sec_header,
            calc_crc_on_serialization: true,
            crc16: None,
        };
        if set_ccsds_len {
            pus_tm.update_ccsds_data_len();
        }
        pus_tm
    }

    pub fn len_packed(&self) -> usize {
        let mut length = PUS_TM_MIN_LEN_WITHOUT_SOURCE_DATA;
        length += self.sec_header.time_stamp.len();
        if let Some(src_data) = self.source_data {
            length += src_data.len();
        }
        length
    }

    /// This is called automatically if the `set_ccsds_len` argument in the [PusTm::new] call was
    /// used.
    /// If this was not done or the time stamp or source data is set or changed after construction,
    /// this function needs to be called to ensure that the data length field of the CCSDS header
    /// is set correctly
    pub fn update_ccsds_data_len(&mut self) {
        self.sp_header.data_len =
            self.len_packed() as u16 - size_of::<crate::zc::SpHeader>() as u16 - 1;
    }

    /// This function should be called before the TM packet is serialized if
    /// [PusTm.calc_crc_on_serialization] is set to False. It will calculate and cache the CRC16.
    pub fn calc_own_crc16(&mut self) {
        let mut digest = CRC_CCITT_FALSE.digest();
        let sph_zc = crate::zc::SpHeader::from(self.sp_header);
        digest.update(sph_zc.as_bytes());
        let pus_tc_header = zc::PusTmSecHeaderWithoutTimestamp::try_from(self.sec_header).unwrap();
        digest.update(pus_tc_header.as_bytes());
        digest.update(self.sec_header.time_stamp);
        if let Some(src_data) = self.source_data {
            digest.update(src_data);
        }
        self.crc16 = Some(digest.finalize())
    }

    /// This helper function calls both [PusTm.update_ccsds_data_len] and [PusTm.calc_own_crc16]
    pub fn update_packet_fields(&mut self) {
        self.update_ccsds_data_len();
        self.calc_own_crc16();
    }

    /// Write the raw PUS byte representation to a provided buffer.
    pub fn write_to(&self, slice: &mut [u8]) -> Result<usize, PusError> {
        let mut curr_idx = 0;
        let sph_zc = crate::zc::SpHeader::from(self.sp_header);
        let total_size = self.len_packed();
        if total_size > slice.len() {
            return Err(PusError::OtherPacketError(
                PacketError::ToBytesSliceTooSmall(SizeMissmatch {
                    found: slice.len(),
                    expected: total_size,
                }),
            ));
        }
        sph_zc
            .to_bytes(&mut slice[curr_idx..curr_idx + 6])
            .ok_or(PusError::OtherPacketError(
                PacketError::ToBytesZeroCopyError,
            ))?;

        curr_idx += CCSDS_HEADER_LEN;
        let sec_header_len = size_of::<zc::PusTmSecHeaderWithoutTimestamp>();
        let sec_header = zc::PusTmSecHeaderWithoutTimestamp::try_from(self.sec_header).unwrap();
        sec_header
            .to_bytes(&mut slice[curr_idx..curr_idx + sec_header_len])
            .ok_or(PusError::OtherPacketError(
                PacketError::ToBytesZeroCopyError,
            ))?;
        curr_idx += sec_header_len;

        slice[curr_idx..].copy_from_slice(self.sec_header.time_stamp);
        curr_idx += self.sec_header.time_stamp.len();
        if let Some(src_data) = self.source_data {
            slice[curr_idx..curr_idx + src_data.len()].copy_from_slice(src_data);
            curr_idx += src_data.len();
        }
        let crc16 = crc_procedure(self.calc_crc_on_serialization, &self.crc16, curr_idx, slice)?;
        slice[curr_idx..curr_idx + 2].copy_from_slice(crc16.to_be_bytes().as_slice());
        curr_idx += 2;
        Ok(curr_idx)
    }

    /// Append the raw PUS byte representation to a provided [alloc::vec::Vec]
    #[cfg(feature = "alloc")]
    pub fn append_to_vec(&self, vec: &mut Vec<u8>) -> Result<usize, PusError> {
        let sph_zc = crate::zc::SpHeader::from(self.sp_header);
        let mut appended_len =
            PUS_TM_MIN_LEN_WITHOUT_SOURCE_DATA + self.sec_header.time_stamp.len();
        if let Some(src_data) = self.source_data {
            appended_len += src_data.len();
        };
        let start_idx = vec.len();
        let mut curr_idx = vec.len();
        vec.extend_from_slice(sph_zc.as_bytes());
        curr_idx += sph_zc.as_bytes().len();
        // The PUS version is hardcoded to PUS C
        let sec_header = zc::PusTmSecHeaderWithoutTimestamp::try_from(self.sec_header).unwrap();
        vec.extend_from_slice(sec_header.as_bytes());
        curr_idx += sec_header.as_bytes().len();
        vec.extend_from_slice(self.sec_header.time_stamp);
        curr_idx += self.sec_header.time_stamp.len();
        if let Some(src_data) = self.source_data {
            vec.extend_from_slice(src_data);
            curr_idx += src_data.len();
        }
        let crc16 = crc_procedure(
            self.calc_crc_on_serialization,
            &self.crc16,
            curr_idx,
            &vec[start_idx..curr_idx],
        )?;
        vec.extend_from_slice(crc16.to_be_bytes().as_slice());
        Ok(appended_len)
    }

    /// Create a [PusTm] instance from a raw slice. On success, it returns a tuple containing
    /// the instance and the found byte length of the packet. The timestamp length needs to be
    /// known beforehand.
    pub fn new_from_raw_slice(
        slice: &'slice [u8],
        timestamp_len: usize,
    ) -> Result<(Self, usize), PusError> {
        let raw_data_len = slice.len();
        if raw_data_len < PUS_TM_MIN_LEN_WITHOUT_SOURCE_DATA {
            return Err(PusError::RawDataTooShort(raw_data_len));
        }
        let mut current_idx = 0;
        let sph = crate::zc::SpHeader::from_bytes(&slice[current_idx..current_idx + 6]).ok_or(
            PusError::OtherPacketError(PacketError::FromBytesZeroCopyError),
        )?;
        current_idx += 6;
        let total_len = sph.total_len();
        if raw_data_len < total_len || total_len < PUS_TM_MIN_LEN_WITHOUT_SOURCE_DATA {
            return Err(PusError::RawDataTooShort(raw_data_len));
        }
        let sec_header_zc = zc::PusTmSecHeaderWithoutTimestamp::from_bytes(
            &slice[current_idx..current_idx + PUC_TM_MIN_SEC_HEADER_LEN],
        )
        .ok_or(PusError::OtherPacketError(
            PacketError::FromBytesZeroCopyError,
        ))?;
        current_idx += PUC_TM_MIN_SEC_HEADER_LEN;
        let zc_sec_header_wrapper = zc::PusTmSecHeader {
            zc_header: sec_header_zc,
            timestamp: &slice[current_idx..current_idx + timestamp_len],
        };
        current_idx += timestamp_len;
        let raw_data = &slice[0..total_len];
        let pus_tm = PusTm {
            sp_header: SpHeader::from(sph),
            sec_header: PusTmSecondaryHeader::try_from(zc_sec_header_wrapper).unwrap(),
            raw_data: Some(&slice[0..total_len]),
            source_data: user_data_from_raw(current_idx, total_len, raw_data_len, slice)?,
            calc_crc_on_serialization: false,
            crc16: Some(crc_from_raw_data(raw_data)?),
        };
        verify_crc16_from_raw(raw_data, pus_tm.crc16.expect("CRC16 invalid"))?;
        Ok((pus_tm, total_len))
    }
}

//noinspection RsTraitImplementation
impl CcsdsPacket for PusTm<'_> {
    ccsds_impl!();
}

//noinspection RsTraitImplementation
impl PusPacket for PusTm<'_> {
    delegate!(to self.sec_header {
        fn pus_version(&self) -> PusVersion;
        fn service(&self) -> u8;
        fn subservice(&self) -> u8;
    });

    fn user_data(&self) -> Option<&[u8]> {
        self.source_data
    }

    fn crc16(&self) -> Option<u16> {
        self.crc16
    }
}

#[cfg(test)]
mod tests {}
