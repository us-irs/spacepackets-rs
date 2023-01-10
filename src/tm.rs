//! This module contains all components required to create a ECSS PUS C telemetry packets according
//! to [ECSS-E-ST-70-41C](https://ecss.nl/standard/ecss-e-st-70-41c-space-engineering-telemetry-and-telecommand-packet-utilization-15-april-2016/).
use crate::ecss::{
    ccsds_impl, crc_from_raw_data, crc_procedure, sp_header_impls, user_data_from_raw,
    verify_crc16_from_raw, CrcType, PusError, PusPacket, PusVersion, CRC_CCITT_FALSE,
};
use crate::{
    ByteConversionError, CcsdsPacket, PacketType, SequenceFlags, SizeMissmatch, SpHeader,
    CCSDS_HEADER_LEN,
};
use core::mem::size_of;
#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};
use zerocopy::AsBytes;

#[cfg(feature = "alloc")]
use alloc::vec::Vec;
use delegate::delegate;

/// Length without timestamp
pub const PUC_TM_MIN_SEC_HEADER_LEN: usize = 7;
pub const PUS_TM_MIN_LEN_WITHOUT_SOURCE_DATA: usize =
    CCSDS_HEADER_LEN + PUC_TM_MIN_SEC_HEADER_LEN + size_of::<CrcType>();

pub trait GenericPusTmSecondaryHeader {
    fn pus_version(&self) -> PusVersion;
    fn sc_time_ref_status(&self) -> u8;
    fn service(&self) -> u8;
    fn subservice(&self) -> u8;
    fn msg_counter(&self) -> u16;
    fn dest_id(&self) -> u16;
}

pub mod zc {
    use super::GenericPusTmSecondaryHeader;
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
        pub fn write_to_bytes(&self, slice: &mut [u8]) -> Option<()> {
            self.write_to(slice)
        }

        pub fn from_bytes(slice: &[u8]) -> Option<Self> {
            Self::read_from(slice)
        }
    }

    impl GenericPusTmSecondaryHeader for PusTmSecHeaderWithoutTimestamp {
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

#[derive(PartialEq, Eq, Copy, Clone, Debug)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct PusTmSecondaryHeader<'stamp> {
    pus_version: PusVersion,
    pub sc_time_ref_status: u8,
    pub service: u8,
    pub subservice: u8,
    pub msg_counter: u16,
    pub dest_id: u16,
    pub time_stamp: &'stamp [u8],
}

impl<'stamp> PusTmSecondaryHeader<'stamp> {
    pub fn new_simple(service: u8, subservice: u8, time_stamp: &'stamp [u8]) -> Self {
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
        time_stamp: &'stamp [u8],
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

impl GenericPusTmSecondaryHeader for PusTmSecondaryHeader<'_> {
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
/// This class also derives the [serde::Serialize] and [serde::Deserialize] trait if the [serde]
/// feature is used which allows to send around TM packets in a raw byte format using a serde
/// provider like [postcard](https://docs.rs/postcard/latest/postcard/).
///
/// There is no spare bytes support yet.
///
/// # Lifetimes
///
/// * `'src_data` - Life time of a buffer where the user provided time stamp and source data will
///    be serialized into.
#[derive(PartialEq, Eq, Debug, Copy, Clone)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct PusTm<'src_data> {
    pub sp_header: SpHeader,
    pub sec_header: PusTmSecondaryHeader<'src_data>,
    /// If this is set to false, a manual call to [PusTm::calc_own_crc16] or
    /// [PusTm::update_packet_fields] is necessary for the serialized or cached CRC16 to be valid.
    pub calc_crc_on_serialization: bool,
    #[cfg_attr(feature = "serde", serde(skip))]
    raw_data: Option<&'src_data [u8]>,
    source_data: Option<&'src_data [u8]>,
    crc16: Option<u16>,
}

impl<'src_data> PusTm<'src_data> {
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
        sec_header: PusTmSecondaryHeader<'src_data>,
        source_data: Option<&'src_data [u8]>,
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

    pub fn time_stamp(&self) -> &'src_data [u8] {
        self.sec_header.time_stamp
    }

    pub fn source_data(&self) -> Option<&'src_data [u8]> {
        self.source_data
    }

    pub fn set_dest_id(&mut self, dest_id: u16) {
        self.sec_header.dest_id = dest_id;
    }

    pub fn set_msg_counter(&mut self, msg_counter: u16) {
        self.sec_header.msg_counter = msg_counter
    }

    pub fn set_sc_time_ref_status(&mut self, sc_time_ref_status: u8) {
        self.sec_header.sc_time_ref_status = sc_time_ref_status & 0b1111;
    }

    sp_header_impls!();

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
    pub fn write_to_bytes(&self, slice: &mut [u8]) -> Result<usize, PusError> {
        let mut curr_idx = 0;
        let total_size = self.len_packed();
        if total_size > slice.len() {
            return Err(ByteConversionError::ToSliceTooSmall(SizeMissmatch {
                found: slice.len(),
                expected: total_size,
            })
            .into());
        }
        self.sp_header
            .write_to_be_bytes(&mut slice[0..CCSDS_HEADER_LEN])?;
        curr_idx += CCSDS_HEADER_LEN;
        let sec_header_len = size_of::<zc::PusTmSecHeaderWithoutTimestamp>();
        let sec_header = zc::PusTmSecHeaderWithoutTimestamp::try_from(self.sec_header).unwrap();
        sec_header
            .write_to_bytes(&mut slice[curr_idx..curr_idx + sec_header_len])
            .ok_or(ByteConversionError::ZeroCopyToError)?;
        curr_idx += sec_header_len;
        let timestamp_len = self.sec_header.time_stamp.len();
        slice[curr_idx..curr_idx + timestamp_len].copy_from_slice(self.sec_header.time_stamp);
        curr_idx += timestamp_len;
        if let Some(src_data) = self.source_data {
            slice[curr_idx..curr_idx + src_data.len()].copy_from_slice(src_data);
            curr_idx += src_data.len();
        }
        let crc16 = crc_procedure(
            self.calc_crc_on_serialization,
            &self.crc16,
            0,
            curr_idx,
            slice,
        )?;
        slice[curr_idx..curr_idx + 2].copy_from_slice(crc16.to_be_bytes().as_slice());
        curr_idx += 2;
        Ok(curr_idx)
    }

    /// Append the raw PUS byte representation to a provided [alloc::vec::Vec]
    #[cfg(feature = "alloc")]
    #[cfg_attr(doc_cfg, doc(cfg(feature = "alloc")))]
    pub fn append_to_vec(&self, vec: &mut Vec<u8>) -> Result<usize, PusError> {
        let sph_zc = crate::zc::SpHeader::from(self.sp_header);
        let mut appended_len =
            PUS_TM_MIN_LEN_WITHOUT_SOURCE_DATA + self.sec_header.time_stamp.len();
        if let Some(src_data) = self.source_data {
            appended_len += src_data.len();
        };
        let start_idx = vec.len();
        let mut ser_len = 0;
        vec.extend_from_slice(sph_zc.as_bytes());
        ser_len += sph_zc.as_bytes().len();
        // The PUS version is hardcoded to PUS C
        let sec_header = zc::PusTmSecHeaderWithoutTimestamp::try_from(self.sec_header).unwrap();
        vec.extend_from_slice(sec_header.as_bytes());
        ser_len += sec_header.as_bytes().len();
        vec.extend_from_slice(self.sec_header.time_stamp);
        ser_len += self.sec_header.time_stamp.len();
        if let Some(src_data) = self.source_data {
            vec.extend_from_slice(src_data);
            ser_len += src_data.len();
        }
        let crc16 = crc_procedure(
            self.calc_crc_on_serialization,
            &self.crc16,
            start_idx,
            ser_len,
            &vec[start_idx..start_idx + ser_len],
        )?;
        vec.extend_from_slice(crc16.to_be_bytes().as_slice());
        Ok(appended_len)
    }

    /// Create a [PusTm] instance from a raw slice. On success, it returns a tuple containing
    /// the instance and the found byte length of the packet. The timestamp length needs to be
    /// known beforehand.
    pub fn from_bytes(
        slice: &'src_data [u8],
        timestamp_len: usize,
    ) -> Result<(Self, usize), PusError> {
        let raw_data_len = slice.len();
        if raw_data_len < PUS_TM_MIN_LEN_WITHOUT_SOURCE_DATA {
            return Err(PusError::RawDataTooShort(raw_data_len));
        }
        let mut current_idx = 0;
        let (sp_header, _) = SpHeader::from_be_bytes(&slice[0..CCSDS_HEADER_LEN])?;
        current_idx += 6;
        let total_len = sp_header.total_len();
        if raw_data_len < total_len || total_len < PUS_TM_MIN_LEN_WITHOUT_SOURCE_DATA {
            return Err(PusError::RawDataTooShort(raw_data_len));
        }
        let sec_header_zc = zc::PusTmSecHeaderWithoutTimestamp::from_bytes(
            &slice[current_idx..current_idx + PUC_TM_MIN_SEC_HEADER_LEN],
        )
        .ok_or(ByteConversionError::ZeroCopyFromError)?;
        current_idx += PUC_TM_MIN_SEC_HEADER_LEN;
        let zc_sec_header_wrapper = zc::PusTmSecHeader {
            zc_header: sec_header_zc,
            timestamp: &slice[current_idx..current_idx + timestamp_len],
        };
        current_idx += timestamp_len;
        let raw_data = &slice[0..total_len];
        let pus_tm = PusTm {
            sp_header,
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

//noinspection RsTraitImplementation
impl GenericPusTmSecondaryHeader for PusTm<'_> {
    delegate!(to self.sec_header {
        fn pus_version(&self) -> PusVersion;
        fn service(&self) -> u8;
        fn subservice(&self) -> u8;
        fn dest_id(&self) -> u16;
        fn msg_counter(&self) -> u16;
        fn sc_time_ref_status(&self) -> u8;
    });
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ecss::PusVersion::PusC;
    use crate::SpHeader;

    fn base_ping_reply_full_ctor(time_stamp: &[u8]) -> PusTm {
        let mut sph = SpHeader::tm_unseg(0x123, 0x234, 0).unwrap();
        let tc_header = PusTmSecondaryHeader::new_simple(17, 2, &time_stamp);
        PusTm::new(&mut sph, tc_header, None, true)
    }

    fn base_hk_reply<'a>(time_stamp: &'a [u8], src_data: &'a [u8]) -> PusTm<'a> {
        let mut sph = SpHeader::tm_unseg(0x123, 0x234, 0).unwrap();
        let tc_header = PusTmSecondaryHeader::new_simple(3, 5, &time_stamp);
        PusTm::new(&mut sph, tc_header, Some(src_data), true)
    }

    fn dummy_time_stamp() -> &'static [u8] {
        return &[0, 1, 2, 3, 4, 5, 6];
    }

    #[test]
    fn test_basic() {
        let time_stamp = dummy_time_stamp();
        let pus_tm = base_ping_reply_full_ctor(&time_stamp);
        verify_ping_reply(&pus_tm, false, 22, dummy_time_stamp());
    }

    #[test]
    fn test_serialization_no_source_data() {
        let time_stamp = dummy_time_stamp();
        let pus_tm = base_ping_reply_full_ctor(&time_stamp);
        let mut buf: [u8; 32] = [0; 32];
        let ser_len = pus_tm
            .write_to_bytes(&mut buf)
            .expect("Serialization failed");
        assert_eq!(ser_len, 22);
        verify_raw_ping_reply(&buf);
    }

    #[test]
    fn test_serialization_with_source_data() {
        let src_data = [1, 2, 3];
        let hk_reply = base_hk_reply(dummy_time_stamp(), &src_data);
        let mut buf: [u8; 32] = [0; 32];
        let ser_len = hk_reply
            .write_to_bytes(&mut buf)
            .expect("Serialization failed");
        assert_eq!(ser_len, 25);
        assert_eq!(buf[20], 1);
        assert_eq!(buf[21], 2);
        assert_eq!(buf[22], 3);
    }

    #[test]
    fn test_setters() {
        let time_stamp = dummy_time_stamp();
        let mut pus_tm = base_ping_reply_full_ctor(&time_stamp);
        pus_tm.set_sc_time_ref_status(0b1010);
        pus_tm.set_dest_id(0x7fff);
        pus_tm.set_msg_counter(0x1f1f);
        assert_eq!(pus_tm.sc_time_ref_status(), 0b1010);
        assert_eq!(pus_tm.dest_id(), 0x7fff);
        assert_eq!(pus_tm.msg_counter(), 0x1f1f);
        assert!(pus_tm.set_apid(0x7ff));
        assert_eq!(pus_tm.apid(), 0x7ff);
    }

    #[test]
    fn test_deserialization_no_source_data() {
        let time_stamp = dummy_time_stamp();
        let pus_tm = base_ping_reply_full_ctor(&time_stamp);
        let mut buf: [u8; 32] = [0; 32];
        let ser_len = pus_tm
            .write_to_bytes(&mut buf)
            .expect("Serialization failed");
        assert_eq!(ser_len, 22);
        let (tm_deserialized, size) = PusTm::from_bytes(&buf, 7).expect("Deserialization failed");
        assert_eq!(ser_len, size);
        verify_ping_reply(&tm_deserialized, false, 22, dummy_time_stamp());
    }

    #[test]
    fn test_manual_field_update() {
        let mut sph = SpHeader::tm_unseg(0x123, 0x234, 0).unwrap();
        let tc_header = PusTmSecondaryHeader::new_simple(17, 2, dummy_time_stamp());
        let mut tm = PusTm::new(&mut sph, tc_header, None, false);
        tm.calc_crc_on_serialization = false;
        assert_eq!(tm.data_len(), 0x00);
        let mut buf: [u8; 32] = [0; 32];
        let res = tm.write_to_bytes(&mut buf);
        assert!(res.is_err());
        assert!(matches!(res.unwrap_err(), PusError::CrcCalculationMissing));
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
        let time_stamp = dummy_time_stamp();
        let pus_tm = base_ping_reply_full_ctor(&time_stamp);
        let mut buf: [u8; 16] = [0; 16];
        let res = pus_tm.write_to_bytes(&mut buf);
        assert!(res.is_err());
        let error = res.unwrap_err();
        assert!(matches!(error, PusError::ByteConversionError { .. }));
        match error {
            PusError::ByteConversionError(err) => match err {
                ByteConversionError::ToSliceTooSmall(size_missmatch) => {
                    assert_eq!(size_missmatch.expected, 22);
                    assert_eq!(size_missmatch.found, 16);
                }
                _ => panic!("Invalid PUS error {:?}", err),
            },
            _ => {
                panic!("Invalid error {:?}", error);
            }
        }
    }

    #[test]
    #[cfg(feature = "alloc")]
    fn test_append_to_vec() {
        let time_stamp = dummy_time_stamp();
        let pus_tm = base_ping_reply_full_ctor(&time_stamp);
        let mut vec = Vec::new();
        let res = pus_tm.append_to_vec(&mut vec);
        assert!(res.is_ok());
        assert_eq!(res.unwrap(), 22);
        verify_raw_ping_reply(vec.as_slice());
    }

    #[test]
    #[cfg(feature = "alloc")]
    fn test_append_to_vec_with_src_data() {
        let src_data = [1, 2, 3];
        let hk_reply = base_hk_reply(dummy_time_stamp(), &src_data);
        let mut vec = Vec::new();
        vec.push(4);
        let res = hk_reply.append_to_vec(&mut vec);
        assert!(res.is_ok());
        assert_eq!(res.unwrap(), 25);
        assert_eq!(vec.len(), 26);
    }

    fn verify_raw_ping_reply(buf: &[u8]) {
        // Secondary header is set -> 0b0000_1001 , APID occupies last bit of first byte
        assert_eq!(buf[0], 0x09);
        // Rest of APID 0x123
        assert_eq!(buf[1], 0x23);
        // Unsegmented is the default, and first byte of 0x234 occupies this byte as well
        assert_eq!(buf[2], 0xc2);
        assert_eq!(buf[3], 0x34);
        assert_eq!(((buf[4] as u16) << 8) | buf[5] as u16, 15);
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
        assert_eq!(&buf[13..20], dummy_time_stamp());
        let mut digest = CRC_CCITT_FALSE.digest();
        digest.update(&buf[0..20]);
        let crc16 = digest.finalize();
        assert_eq!(((crc16 >> 8) & 0xff) as u8, buf[20]);
        assert_eq!((crc16 & 0xff) as u8, buf[21]);
    }

    fn verify_ping_reply(
        tm: &PusTm,
        has_user_data: bool,
        exp_full_len: usize,
        exp_time_stamp: &[u8],
    ) {
        assert!(tm.is_tm());
        assert_eq!(PusPacket::service(tm), 17);
        assert_eq!(PusPacket::subservice(tm), 2);
        assert!(tm.sec_header_flag());
        assert_eq!(tm.len_packed(), exp_full_len);
        assert_eq!(tm.time_stamp(), exp_time_stamp);
        if has_user_data {
            assert!(!tm.user_data().is_none());
        }
        assert_eq!(PusPacket::pus_version(tm), PusC);
        assert_eq!(tm.apid(), 0x123);
        assert_eq!(tm.seq_count(), 0x234);
        assert_eq!(tm.data_len(), exp_full_len as u16 - 7);
        assert_eq!(tm.dest_id(), 0x0000);
        assert_eq!(tm.msg_counter(), 0x0000);
        assert_eq!(tm.sc_time_ref_status(), 0b0000);
    }
}
