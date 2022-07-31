use crate::ecss::{crc_procedure, CrcType, PusError, PusVersion, CRC_CCITT_FALSE};
use crate::{PacketError, PacketType, SizeMissmatch, SpHeader, CCSDS_HEADER_LEN};
use core::mem::size_of;
use serde::{Deserialize, Serialize};
use zerocopy::AsBytes;

#[cfg(feature = "alloc")]
use alloc::vec::Vec;

/// Length without timestamp
pub const PUC_TM_MIN_SEC_HEADER_LEN: usize = 7;
pub const PUS_TM_MIN_LEN_WITHOUT_SOURCE_DATA: usize =
    CCSDS_HEADER_LEN + PUC_TM_MIN_SEC_HEADER_LEN + size_of::<CrcType>();

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

/// This struct models a PUS telemetry and which can also be used. It is the primary data
/// structure to generate the raw byte representation of PUS telemetry or to
/// deserialize from one from raw bytes.
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
    /// * `pus_params` - Information contained in the data field header, including the service
    ///     and subservice type
    /// * `set_ccsds_len` - Can be used to automatically update the CCSDS space packet data length
    ///     field. If this is not set to true, [PusTm::update_ccsds_data_len] can be called to set
    ///     the correct value to this field manually
    /// * `app_data` - Custom application data
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

    /// This is called automatically if the [set_ccsds_len] argument in the [new] call was used.
    /// If this was not done or the time stamp or source data is set or changed after construction,
    /// this function needs to be called to ensure that the data length field of the CCSDS header
    /// is set correctly
    pub fn update_ccsds_data_len(&mut self) {
        self.sp_header.data_len =
            self.len_packed() as u16 - size_of::<crate::zc::SpHeader>() as u16 - 1;
    }

    /// This function should be called before the TM packet is serialized if
    /// [calc_crc_on_serialization] is set to False. It will calculate and cache the CRC16.
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

    /// This helper function calls both [update_ccsds_data_len] and [calc_own_crc16]
    pub fn update_packet_fields(&mut self) {
        self.update_ccsds_data_len();
        self.calc_own_crc16();
    }

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

    #[cfg(feature = "alloc")]
    pub fn append_to_vec(&self, vec: &mut Vec<u8>) -> Result<usize, PusError> {
        let sph_zc = crate::zc::SpHeader::from(self.sp_header);
        let mut appended_len = PUS_TM_MIN_LEN_WITHOUT_SOURCE_DATA + self.sec_header.time_stamp.len();
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
}

#[cfg(test)]
mod tests {}
