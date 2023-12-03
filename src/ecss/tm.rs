//! This module contains all components required to create a ECSS PUS C telemetry packets according
//! to [ECSS-E-ST-70-41C](https://ecss.nl/standard/ecss-e-st-70-41c-space-engineering-telemetry-and-telecommand-packet-utilization-15-april-2016/).
use crate::ecss::{
    calc_pus_crc16, ccsds_impl, crc_from_raw_data, sp_header_impls, user_data_from_raw,
    verify_crc16_ccitt_false_from_raw_to_pus_error, CrcType, PusError, PusPacket, PusVersion,
    WritablePusPacket,
};
use crate::{
    ByteConversionError, CcsdsPacket, PacketType, SequenceFlags, SpHeader, CCSDS_HEADER_LEN,
    CRC_CCITT_FALSE, MAX_APID, MAX_SEQ_COUNT,
};
use core::mem::size_of;
#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};
use zerocopy::AsBytes;

#[cfg(feature = "alloc")]
use alloc::vec::Vec;
use delegate::delegate;

use crate::time::{TimeWriter, TimestampError};
pub use legacy_tm::*;

pub trait IsPusTelemetry {}

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
    use zerocopy::{AsBytes, FromBytes, FromZeroes, NetworkEndian, Unaligned, U16};

    #[derive(FromBytes, FromZeroes, AsBytes, Unaligned)]
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
    pub timestamp: &'stamp [u8],
}

impl<'stamp> PusTmSecondaryHeader<'stamp> {
    pub fn new_simple(service: u8, subservice: u8, timestamp: &'stamp [u8]) -> Self {
        Self::new(service, subservice, 0, 0, Some(timestamp))
    }

    /// Like [Self::new_simple] but without a timestamp.
    pub fn new_simple_no_timestamp(service: u8, subservice: u8) -> Self {
        Self::new(service, subservice, 0, 0, None)
    }

    pub fn new(
        service: u8,
        subservice: u8,
        msg_counter: u16,
        dest_id: u16,
        timestamp: Option<&'stamp [u8]>,
    ) -> Self {
        PusTmSecondaryHeader {
            pus_version: PusVersion::PusC,
            sc_time_ref_status: 0,
            service,
            subservice,
            msg_counter,
            dest_id,
            timestamp: timestamp.unwrap_or(&[]),
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
            timestamp: sec_header.timestamp,
        })
    }
}

pub mod legacy_tm {
    use crate::ecss::tm::{
        zc, GenericPusTmSecondaryHeader, IsPusTelemetry, PusTmSecondaryHeader,
        PUC_TM_MIN_SEC_HEADER_LEN, PUS_TM_MIN_LEN_WITHOUT_SOURCE_DATA,
    };
    use crate::ecss::PusVersion;
    use crate::ecss::{
        ccsds_impl, crc_from_raw_data, crc_procedure, sp_header_impls, user_data_from_raw,
        verify_crc16_ccitt_false_from_raw_to_pus_error, PusError, PusPacket, WritablePusPacket,
        CCSDS_HEADER_LEN,
    };
    use crate::SequenceFlags;
    use crate::{ByteConversionError, CcsdsPacket, PacketType, SpHeader, CRC_CCITT_FALSE};
    use core::mem::size_of;
    use zerocopy::AsBytes;

    #[cfg(feature = "serde")]
    use serde::{Deserialize, Serialize};

    #[cfg(feature = "alloc")]
    use alloc::vec::Vec;
    use delegate::delegate;

    /// This class models the PUS C telemetry packet. It is the primary data structure to generate the
    /// raw byte representation of PUS telemetry or to deserialize from one from raw bytes.
    ///
    /// This class also derives the [serde::Serialize] and [serde::Deserialize] trait if the [serde]
    /// feature is used which allows to send around TM packets in a raw byte format using a serde
    /// provider like [postcard](https://docs.rs/postcard/latest/postcard/).
    ///
    /// There is no spare bytes support yet.
    ///
    /// # Lifetimes
    ///
    /// * `'raw_data` - If the TM is not constructed from a raw slice, this will be the life time of
    ///    a buffer where the user provided time stamp and source data will be serialized into. If it
    ///    is, this is the lifetime of the raw byte slice it is constructed from.
    #[derive(Eq, Debug, Copy, Clone)]
    #[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
    pub struct PusTm<'raw_data> {
        pub sp_header: SpHeader,
        pub sec_header: PusTmSecondaryHeader<'raw_data>,
        /// If this is set to false, a manual call to [PusTm::calc_own_crc16] or
        /// [PusTm::update_packet_fields] is necessary for the serialized or cached CRC16 to be valid.
        pub calc_crc_on_serialization: bool,
        #[cfg_attr(feature = "serde", serde(skip))]
        raw_data: Option<&'raw_data [u8]>,
        source_data: &'raw_data [u8],
        crc16: Option<u16>,
    }

    impl<'raw_data> PusTm<'raw_data> {
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
        #[deprecated(
            since = "0.7.0",
            note = "Use specialized PusTmCreator or PusTmReader classes instead"
        )]
        pub fn new(
            sp_header: &mut SpHeader,
            sec_header: PusTmSecondaryHeader<'raw_data>,
            source_data: Option<&'raw_data [u8]>,
            set_ccsds_len: bool,
        ) -> Self {
            sp_header.set_packet_type(PacketType::Tm);
            sp_header.set_sec_header_flag();
            let mut pus_tm = PusTm {
                sp_header: *sp_header,
                raw_data: None,
                source_data: source_data.unwrap_or(&[]),
                sec_header,
                calc_crc_on_serialization: true,
                crc16: None,
            };
            if set_ccsds_len {
                pus_tm.update_ccsds_data_len();
            }
            pus_tm
        }

        pub fn timestamp(&self) -> &[u8] {
            self.sec_header.timestamp
        }

        pub fn source_data(&self) -> &[u8] {
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
                self.len_written() as u16 - size_of::<crate::zc::SpHeader>() as u16 - 1;
        }

        /// This function should be called before the TM packet is serialized if
        /// [PusTm.calc_crc_on_serialization] is set to False. It will calculate and cache the CRC16.
        pub fn calc_own_crc16(&mut self) {
            let mut digest = CRC_CCITT_FALSE.digest();
            let sph_zc = crate::zc::SpHeader::from(self.sp_header);
            digest.update(sph_zc.as_bytes());
            let pus_tc_header =
                zc::PusTmSecHeaderWithoutTimestamp::try_from(self.sec_header).unwrap();
            digest.update(pus_tc_header.as_bytes());
            digest.update(self.sec_header.timestamp);
            digest.update(self.source_data);
            self.crc16 = Some(digest.finalize())
        }

        /// This helper function calls both [PusTm.update_ccsds_data_len] and [PusTm.calc_own_crc16]
        pub fn update_packet_fields(&mut self) {
            self.update_ccsds_data_len();
            self.calc_own_crc16();
        }

        /// Append the raw PUS byte representation to a provided [alloc::vec::Vec]
        #[cfg(feature = "alloc")]
        #[cfg_attr(doc_cfg, doc(cfg(feature = "alloc")))]
        pub fn append_to_vec(&self, vec: &mut Vec<u8>) -> Result<usize, PusError> {
            let sph_zc = crate::zc::SpHeader::from(self.sp_header);
            let mut appended_len = PUS_TM_MIN_LEN_WITHOUT_SOURCE_DATA;
            appended_len += self.sec_header.timestamp.len();
            appended_len += self.source_data.len();
            let start_idx = vec.len();
            let mut ser_len = 0;
            vec.extend_from_slice(sph_zc.as_bytes());
            ser_len += sph_zc.as_bytes().len();
            // The PUS version is hardcoded to PUS C
            let sec_header = zc::PusTmSecHeaderWithoutTimestamp::try_from(self.sec_header).unwrap();
            vec.extend_from_slice(sec_header.as_bytes());
            ser_len += sec_header.as_bytes().len();
            ser_len += self.sec_header.timestamp.len();
            vec.extend_from_slice(self.sec_header.timestamp);
            vec.extend_from_slice(self.source_data);
            ser_len += self.source_data.len();
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
        #[deprecated(
            since = "0.7.0",
            note = "Use specialized PusTmCreator or PusTmReader classes instead"
        )]
        pub fn from_bytes(
            slice: &'raw_data [u8],
            timestamp_len: usize,
        ) -> Result<(Self, usize), PusError> {
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
            let total_len = sp_header.total_len();
            if raw_data_len < total_len {
                return Err(ByteConversionError::FromSliceTooSmall {
                    found: raw_data_len,
                    expected: PUS_TM_MIN_LEN_WITHOUT_SOURCE_DATA,
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
                source_data: user_data_from_raw(current_idx, total_len, slice)?,
                calc_crc_on_serialization: false,
                crc16: Some(crc_from_raw_data(raw_data)?),
            };
            verify_crc16_ccitt_false_from_raw_to_pus_error(
                raw_data,
                pus_tm.crc16.expect("CRC16 invalid"),
            )?;
            Ok((pus_tm, total_len))
        }

        /// If [Self] was constructed [Self::from_bytes], this function will return the slice it was
        /// constructed from. Otherwise, [None] will be returned.
        pub fn raw_bytes(&self) -> Option<&'raw_data [u8]> {
            self.raw_data
        }
    }

    impl WritablePusPacket for PusTm<'_> {
        fn len_written(&self) -> usize {
            PUS_TM_MIN_LEN_WITHOUT_SOURCE_DATA
                + self.sec_header.timestamp.len()
                + self.source_data.len()
        }
        /// Write the raw PUS byte representation to a provided buffer.
        fn write_to_bytes(&self, slice: &mut [u8]) -> Result<usize, PusError> {
            let mut curr_idx = 0;
            let total_size = self.len_written();
            if total_size > slice.len() {
                return Err(ByteConversionError::ToSliceTooSmall {
                    found: slice.len(),
                    expected: total_size,
                }
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
            slice[curr_idx..curr_idx + self.sec_header.timestamp.len()]
                .copy_from_slice(self.sec_header.timestamp);
            curr_idx += self.sec_header.timestamp.len();
            slice[curr_idx..curr_idx + self.source_data.len()].copy_from_slice(self.source_data);
            curr_idx += self.source_data.len();
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
    }

    impl PartialEq for PusTm<'_> {
        fn eq(&self, other: &Self) -> bool {
            self.sp_header == other.sp_header
                && self.sec_header == other.sec_header
                && self.source_data == other.source_data
        }
    }

    impl CcsdsPacket for PusTm<'_> {
        ccsds_impl!();
    }

    impl PusPacket for PusTm<'_> {
        delegate!(to self.sec_header {
            fn pus_version(&self) -> PusVersion;
            fn service(&self) -> u8;
            fn subservice(&self) -> u8;
        });

        fn user_data(&self) -> &[u8] {
            self.source_data
        }

        fn crc16(&self) -> Option<u16> {
            self.crc16
        }
    }

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

    impl IsPusTelemetry for PusTm<'_> {}
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
/// * `'raw_data` - This is the lifetime of the user provided time stamp and source data.
#[derive(Eq, Debug, Copy, Clone)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct PusTmCreator<'raw_data> {
    pub sp_header: SpHeader,
    pub sec_header: PusTmSecondaryHeader<'raw_data>,
    source_data: &'raw_data [u8],
    /// If this is set to false, a manual call to [PusTm::calc_own_crc16] or
    /// [PusTm::update_packet_fields] is necessary for the serialized or cached CRC16 to be valid.
    pub calc_crc_on_serialization: bool,
}

impl<'raw_data> PusTmCreator<'raw_data> {
    /// Generates a new struct instance.
    ///
    /// # Arguments
    ///
    /// * `sp_header` - Space packet header information. The correct packet type will be set
    ///     automatically
    /// * `sec_header` - Information contained in the secondary header, including the service
    ///     and subservice type
    /// * `source_data` - Custom application data
    /// * `set_ccsds_len` - Can be used to automatically update the CCSDS space packet data length
    ///     field. If this is not set to true, [PusTm::update_ccsds_data_len] can be called to set
    ///     the correct value to this field manually
    pub fn new(
        sp_header: &mut SpHeader,
        sec_header: PusTmSecondaryHeader<'raw_data>,
        source_data: &'raw_data [u8],
        set_ccsds_len: bool,
    ) -> Self {
        sp_header.set_packet_type(PacketType::Tm);
        sp_header.set_sec_header_flag();
        let mut pus_tm = Self {
            sp_header: *sp_header,
            source_data,
            sec_header,
            calc_crc_on_serialization: true,
        };
        if set_ccsds_len {
            pus_tm.update_ccsds_data_len();
        }
        pus_tm
    }

    pub fn new_simple(
        sp_header: &mut SpHeader,
        service: u8,
        subservice: u8,
        time_provider: &impl TimeWriter,
        stamp_buf: &'raw_data mut [u8],
        source_data: &'raw_data [u8],
        set_ccsds_len: bool,
    ) -> Result<Self, TimestampError> {
        let stamp_size = time_provider.write_to_bytes(stamp_buf)?;
        let sec_header =
            PusTmSecondaryHeader::new_simple(service, subservice, &stamp_buf[0..stamp_size]);
        Ok(Self::new(sp_header, sec_header, source_data, set_ccsds_len))
    }

    pub fn new_no_source_data(
        sp_header: &mut SpHeader,
        sec_header: PusTmSecondaryHeader<'raw_data>,
        set_ccsds_len: bool,
    ) -> Self {
        sp_header.set_packet_type(PacketType::Tm);
        sp_header.set_sec_header_flag();
        let mut pus_tm = Self {
            sp_header: *sp_header,
            source_data: &[],
            sec_header,
            calc_crc_on_serialization: true,
        };
        if set_ccsds_len {
            pus_tm.update_ccsds_data_len();
        }
        pus_tm
    }
    pub fn timestamp(&self) -> &[u8] {
        self.sec_header.timestamp
    }

    pub fn source_data(&self) -> &[u8] {
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
            self.len_written() as u16 - size_of::<crate::zc::SpHeader>() as u16 - 1;
    }

    /// This function should be called before the TM packet is serialized if
    /// [PusTm.calc_crc_on_serialization] is set to False. It will calculate and cache the CRC16.
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

    /// This helper function calls both [PusTm.update_ccsds_data_len] and [PusTm.calc_own_crc16]
    pub fn update_packet_fields(&mut self) {
        self.update_ccsds_data_len();
    }

    /// Append the raw PUS byte representation to a provided [alloc::vec::Vec]
    #[cfg(feature = "alloc")]
    #[cfg_attr(doc_cfg, doc(cfg(feature = "alloc")))]
    pub fn append_to_vec(&self, vec: &mut Vec<u8>) -> Result<usize, PusError> {
        let sph_zc = crate::zc::SpHeader::from(self.sp_header);
        let mut appended_len = PUS_TM_MIN_LEN_WITHOUT_SOURCE_DATA + self.sec_header.timestamp.len();
        appended_len += self.source_data.len();
        let start_idx = vec.len();
        vec.extend_from_slice(sph_zc.as_bytes());
        // The PUS version is hardcoded to PUS C
        let sec_header = zc::PusTmSecHeaderWithoutTimestamp::try_from(self.sec_header).unwrap();
        vec.extend_from_slice(sec_header.as_bytes());
        vec.extend_from_slice(self.sec_header.timestamp);
        vec.extend_from_slice(self.source_data);
        let mut digest = CRC_CCITT_FALSE.digest();
        digest.update(&vec[start_idx..start_idx + appended_len - 2]);
        vec.extend_from_slice(&digest.finalize().to_be_bytes());
        Ok(appended_len)
    }
}

impl WritablePusPacket for PusTmCreator<'_> {
    fn len_written(&self) -> usize {
        PUS_TM_MIN_LEN_WITHOUT_SOURCE_DATA
            + self.sec_header.timestamp.len()
            + self.source_data.len()
    }
    /// Write the raw PUS byte representation to a provided buffer.
    fn write_to_bytes(&self, slice: &mut [u8]) -> Result<usize, PusError> {
        let mut curr_idx = 0;
        let total_size = self.len_written();
        if total_size > slice.len() {
            return Err(ByteConversionError::ToSliceTooSmall {
                found: slice.len(),
                expected: total_size,
            }
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
        slice[curr_idx..curr_idx + self.sec_header.timestamp.len()]
            .copy_from_slice(self.sec_header.timestamp);
        curr_idx += self.sec_header.timestamp.len();
        slice[curr_idx..curr_idx + self.source_data.len()].copy_from_slice(self.source_data);
        curr_idx += self.source_data.len();
        let mut digest = CRC_CCITT_FALSE.digest();
        digest.update(&slice[0..curr_idx]);
        slice[curr_idx..curr_idx + 2].copy_from_slice(&digest.finalize().to_be_bytes());
        curr_idx += 2;
        Ok(curr_idx)
    }
}

impl PartialEq for PusTmCreator<'_> {
    fn eq(&self, other: &Self) -> bool {
        self.sp_header == other.sp_header
            && self.sec_header == other.sec_header
            && self.source_data == other.source_data
    }
}

impl CcsdsPacket for PusTmCreator<'_> {
    ccsds_impl!();
}

impl PusPacket for PusTmCreator<'_> {
    delegate!(to self.sec_header {
        fn pus_version(&self) -> PusVersion;
        fn service(&self) -> u8;
        fn subservice(&self) -> u8;
    });

    fn user_data(&self) -> &[u8] {
        self.source_data
    }

    fn crc16(&self) -> Option<u16> {
        Some(self.calc_own_crc16())
    }
}

impl GenericPusTmSecondaryHeader for PusTmCreator<'_> {
    delegate!(to self.sec_header {
        fn pus_version(&self) -> PusVersion;
        fn service(&self) -> u8;
        fn subservice(&self) -> u8;
        fn dest_id(&self) -> u16;
        fn msg_counter(&self) -> u16;
        fn sc_time_ref_status(&self) -> u8;
    });
}

impl IsPusTelemetry for PusTmCreator<'_> {}

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
    pub fn new(slice: &'raw_data [u8], timestamp_len: usize) -> Result<(Self, usize), PusError> {
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
        let total_len = sp_header.total_len();
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
        let pus_tm = Self {
            sp_header,
            sec_header: PusTmSecondaryHeader::try_from(zc_sec_header_wrapper).unwrap(),
            raw_data: &slice[0..total_len],
            source_data: user_data_from_raw(current_idx, total_len, slice)?,
            crc16: crc_from_raw_data(raw_data)?,
        };
        verify_crc16_ccitt_false_from_raw_to_pus_error(raw_data, pus_tm.crc16)?;
        Ok((pus_tm, total_len))
    }

    pub fn len_packed(&self) -> usize {
        self.sp_header.total_len()
    }

    pub fn source_data(&self) -> &[u8] {
        self.user_data()
    }

    pub fn timestamp(&self) -> &[u8] {
        self.sec_header.timestamp
    }

    /// This function will return the slice [Self] was constructed from.
    pub fn raw_data(&self) -> &[u8] {
        self.raw_data
    }
}

impl PartialEq for PusTmReader<'_> {
    fn eq(&self, other: &Self) -> bool {
        self.raw_data == other.raw_data
    }
}

impl CcsdsPacket for PusTmReader<'_> {
    ccsds_impl!();
}

impl PusPacket for PusTmReader<'_> {
    delegate!(to self.sec_header {
        fn pus_version(&self) -> PusVersion;
        fn service(&self) -> u8;
        fn subservice(&self) -> u8;
    });

    fn user_data(&self) -> &[u8] {
        self.source_data
    }

    fn crc16(&self) -> Option<u16> {
        Some(self.crc16)
    }
}

impl GenericPusTmSecondaryHeader for PusTmReader<'_> {
    delegate!(to self.sec_header {
        fn pus_version(&self) -> PusVersion;
        fn service(&self) -> u8;
        fn subservice(&self) -> u8;
        fn dest_id(&self) -> u16;
        fn msg_counter(&self) -> u16;
        fn sc_time_ref_status(&self) -> u8;
    });
}

impl IsPusTelemetry for PusTmReader<'_> {}

impl PartialEq<PusTmCreator<'_>> for PusTmReader<'_> {
    fn eq(&self, other: &PusTmCreator<'_>) -> bool {
        self.sp_header == other.sp_header
            && self.sec_header == other.sec_header
            && self.source_data == other.source_data
    }
}

impl PartialEq<PusTmReader<'_>> for PusTmCreator<'_> {
    fn eq(&self, other: &PusTmReader<'_>) -> bool {
        self.sp_header == other.sp_header
            && self.sec_header == other.sec_header
            && self.source_data == other.source_data
    }
}

/// This is a helper class to update certain fields in a raw PUS telemetry packet directly in place.
/// This can be more efficient than creating a full [PusTm], modifying the fields and then writing
/// it back to another buffer.
///
/// Please note that the [Self::finish] method has to be called for the PUS TM CRC16 to be valid
/// after changing fields of the TM packet. Furthermore, the constructor of this class will not
/// do any checks except a length check to ensure that all relevant fields can be updated without
/// a panic. If a full validity check of the PUS TM packet is required, it is recommended
/// to construct a full [PusTm] object from the raw bytestream first.
pub struct PusTmZeroCopyWriter<'raw> {
    raw_tm: &'raw mut [u8],
}

impl<'raw> PusTmZeroCopyWriter<'raw> {
    /// This function will not do any other checks on the raw data other than a length check
    /// for all internal fields which can be updated. It is the responsibility of the user to ensure
    /// the raw slice contains a valid telemetry packet. The slice should have the exact length
    /// of the telemetry packet for this class to work properly.
    pub fn new(raw_tm: &'raw mut [u8]) -> Option<Self> {
        if raw_tm.len() < 13 {
            return None;
        }
        Some(Self { raw_tm })
    }

    pub fn service(&self) -> u8 {
        self.raw_tm[7]
    }

    pub fn subservice(&self) -> u8 {
        self.raw_tm[8]
    }

    /// Set the sequence count. Returns false and does not update the value if the passed value
    /// exceeds [MAX_APID].
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

    /// This function sets the message counter in the PUS TM secondary header.
    pub fn set_msg_count(&mut self, msg_count: u16) {
        self.raw_tm[9..11].copy_from_slice(&msg_count.to_be_bytes());
    }

    /// This function sets the destination ID in the PUS TM secondary header.
    pub fn set_destination_id(&mut self, dest_id: u16) {
        self.raw_tm[11..13].copy_from_slice(&dest_id.to_be_bytes())
    }

    /// Set the sequence count. Returns false and does not update the value if the passed value
    /// exceeds [MAX_SEQ_COUNT].
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

#[cfg(test)]
mod tests {
    use alloc::string::ToString;

    use super::*;
    use crate::ecss::PusVersion::PusC;
    use crate::time::cds::TimeProvider;
    use crate::SpHeader;

    fn base_ping_reply_full_ctor(timestamp: &[u8]) -> PusTmCreator {
        let mut sph = SpHeader::tm_unseg(0x123, 0x234, 0).unwrap();
        let tm_header = PusTmSecondaryHeader::new_simple(17, 2, timestamp);
        PusTmCreator::new_no_source_data(&mut sph, tm_header, true)
    }

    fn base_hk_reply<'a>(timestamp: &'a [u8], src_data: &'a [u8]) -> PusTmCreator<'a> {
        let mut sph = SpHeader::tm_unseg(0x123, 0x234, 0).unwrap();
        let tc_header = PusTmSecondaryHeader::new_simple(3, 5, timestamp);
        PusTmCreator::new(&mut sph, tc_header, src_data, true)
    }

    fn dummy_timestamp() -> &'static [u8] {
        &[0, 1, 2, 3, 4, 5, 6]
    }

    #[test]
    fn test_basic() {
        let timestamp = dummy_timestamp();
        let pus_tm = base_ping_reply_full_ctor(timestamp);
        verify_ping_reply(&pus_tm, false, 22, dummy_timestamp());
    }
    #[test]
    fn test_basic_simple_api() {
        let mut sph = SpHeader::tm_unseg(0x123, 0x234, 0).unwrap();
        let time_provider = TimeProvider::new_with_u16_days(0, 0);
        let mut stamp_buf: [u8; 8] = [0; 8];
        let pus_tm =
            PusTmCreator::new_simple(&mut sph, 17, 2, &time_provider, &mut stamp_buf, &[], true)
                .unwrap();
        verify_ping_reply(&pus_tm, false, 22, &[64, 0, 0, 0, 0, 0, 0]);
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
        verify_raw_ping_reply(pus_tm.crc16().unwrap(), &buf);
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
    }

    #[test]
    fn test_setters() {
        let timestamp = dummy_timestamp();
        let mut pus_tm = base_ping_reply_full_ctor(timestamp);
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
    fn test_write_into_vec() {
        let timestamp = dummy_timestamp();
        let pus_tm = base_ping_reply_full_ctor(timestamp);
        let tm_vec = pus_tm.to_vec().expect("Serialization failed");
        assert_eq!(tm_vec.len(), 22);
        let (tm_deserialized, size) =
            PusTmReader::new(tm_vec.as_slice(), 7).expect("Deserialization failed");
        assert_eq!(tm_vec.len(), size);
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
        let (tm_deserialized, size) = PusTmReader::new(&buf, 7).expect("Deserialization failed");
        assert_eq!(ser_len, size);
        assert_eq!(tm_deserialized.user_data(), tm_deserialized.source_data());
        assert_eq!(tm_deserialized.raw_data(), &buf[..ser_len]);
        assert_eq!(tm_deserialized.crc16().unwrap(), pus_tm.crc16().unwrap());
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
        let mut sph = SpHeader::tm_unseg(0x123, 0x234, 0).unwrap();
        let tc_header = PusTmSecondaryHeader::new_simple(17, 2, dummy_timestamp());
        let mut tm = PusTmCreator::new_no_source_data(&mut sph, tc_header, false);
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
        assert!(matches!(error, PusError::ByteConversion { .. }));
        match error {
            PusError::ByteConversion(err) => match err {
                ByteConversionError::ToSliceTooSmall { found, expected } => {
                    assert_eq!(expected, 22);
                    assert_eq!(found, 16);
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
        let timestamp = dummy_timestamp();
        let pus_tm = base_ping_reply_full_ctor(timestamp);
        let mut vec = Vec::new();
        let res = pus_tm.append_to_vec(&mut vec);
        assert!(res.is_ok());
        assert_eq!(res.unwrap(), 22);
        verify_raw_ping_reply(pus_tm.crc16().unwrap(), vec.as_slice());
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

    fn verify_raw_ping_reply(crc16: u16, buf: &[u8]) {
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
        assert_eq!(&buf[13..20], dummy_timestamp());
        let mut digest = CRC_CCITT_FALSE.digest();
        digest.update(&buf[0..20]);
        let crc16_calced = digest.finalize();
        assert_eq!(((crc16 >> 8) & 0xff) as u8, buf[20]);
        assert_eq!((crc16 & 0xff) as u8, buf[21]);
        assert_eq!(crc16, crc16_calced);
    }

    fn verify_ping_reply(
        tm: &PusTmCreator,
        has_user_data: bool,
        exp_full_len: usize,
        exp_timestamp: &[u8],
    ) {
        assert_eq!(tm.len_written(), exp_full_len);
        assert_eq!(tm.timestamp(), exp_timestamp);
        assert_eq!(tm.source_data(), tm.user_data());
        verify_ping_reply_generic(tm, has_user_data, exp_full_len);
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
        tm: &(impl CcsdsPacket + GenericPusTmSecondaryHeader + PusPacket),
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
        assert_eq!(PusPacket::pus_version(tm), PusC);
        assert_eq!(tm.apid(), 0x123);
        assert_eq!(tm.seq_count(), 0x234);
        assert_eq!(PusPacket::pus_version(tm), PusVersion::PusC);
        assert_eq!(
            GenericPusTmSecondaryHeader::pus_version(tm),
            PusVersion::PusC
        );
        assert_eq!(tm.data_len(), exp_full_len as u16 - 7);
        assert_eq!(tm.dest_id(), 0x0000);
        assert_eq!(tm.msg_counter(), 0x0000);
        assert_eq!(tm.sc_time_ref_status(), 0b0000);
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
        assert_eq!(pus_tm, PusTmReader::new(&buf, timestamp.len()).unwrap().0);
    }

    #[test]
    fn test_zero_copy_writer() {
        let ping_tm = base_ping_reply_full_ctor(dummy_timestamp());
        let mut buf: [u8; 64] = [0; 64];
        let tm_size = ping_tm
            .write_to_bytes(&mut buf)
            .expect("writing PUS ping TM failed");
        let mut writer = PusTmZeroCopyWriter::new(&mut buf[..tm_size])
            .expect("Creating zero copy writer failed");
        writer.set_destination_id(55);
        writer.set_msg_count(100);
        writer.set_seq_count(MAX_SEQ_COUNT);
        writer.set_apid(MAX_APID);
        assert!(!writer.set_apid(MAX_APID + 1));
        assert!(!writer.set_apid(MAX_SEQ_COUNT + 1));
        assert_eq!(writer.service(), 17);
        assert_eq!(writer.subservice(), 2);
        writer.finish();
        // This performs all necessary checks, including the CRC check.
        let (tm_read_back, tm_size_read_back) =
            PusTmReader::new(&buf, 7).expect("Re-creating PUS TM failed");
        assert_eq!(tm_size_read_back, tm_size);
        assert_eq!(tm_read_back.msg_counter(), 100);
        assert_eq!(tm_read_back.dest_id(), 55);
        assert_eq!(tm_read_back.seq_count(), MAX_SEQ_COUNT);
        assert_eq!(tm_read_back.apid(), MAX_APID);
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
        let (tm_0, _) = PusTmReader::new(&buf, timestamp.len()).unwrap();
        let (tm_1, _) = PusTmReader::new(&buf, timestamp.len()).unwrap();
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
}
