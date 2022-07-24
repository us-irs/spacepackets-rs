use crate::ecss::{PusError, PusPacket, PusVersion, CRC_CCITT_FALSE};
use crate::ser::SpHeader;
use crate::{CcsdsPacket, PacketError, PacketType, SequenceFlags, CCSDS_HEADER_LEN};
use alloc::vec::Vec;
use core::mem::size_of;
use delegate::delegate;
use serde::{Deserialize, Serialize};
use zerocopy::AsBytes;

type CrcType = u16;

/// PUS C secondary header length is fixed
pub const PUC_TC_SECONDARY_HEADER_LEN: usize = size_of::<zc::PusTcDataFieldHeader>();
pub const PUS_TC_MIN_LEN_WITHOUT_APP_DATA: usize =
    CCSDS_HEADER_LEN + PUC_TC_SECONDARY_HEADER_LEN + size_of::<CrcType>();
const PUS_VERSION: PusVersion = PusVersion::PusC;

#[derive(Copy, Clone, PartialEq, Debug)]
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

pub trait PusTcSecondaryHeader {
    fn ack_flags(&self) -> u8;
    fn service(&self) -> u8;
    fn subservice(&self) -> u8;
    fn source_id(&self) -> u16;
}

pub mod zc {
    use crate::ecss::{PusError, PusVersion};
    use crate::tc::PusTcSecondaryHeader;
    use zerocopy::{AsBytes, FromBytes, NetworkEndian, Unaligned, U16};

    #[derive(FromBytes, AsBytes, Unaligned)]
    #[repr(C)]
    pub struct PusTcDataFieldHeader {
        version_ack: u8,
        service: u8,
        subservice: u8,
        source_id: U16<NetworkEndian>,
    }

    impl TryFrom<crate::tc::PusTcDataFieldHeader> for PusTcDataFieldHeader {
        type Error = PusError;
        fn try_from(value: crate::tc::PusTcDataFieldHeader) -> Result<Self, Self::Error> {
            if value.version != PusVersion::PusC {
                return Err(PusError::VersionNotSupported(value.version));
            }
            Ok(PusTcDataFieldHeader {
                version_ack: ((value.version as u8) << 4) | value.ack,
                service: value.service,
                subservice: value.subservice,
                source_id: U16::from(value.source_id),
            })
        }
    }

    impl PusTcSecondaryHeader for PusTcDataFieldHeader {
        fn ack_flags(&self) -> u8 {
            self.version_ack & 0b1111
        }

        fn service(&self) -> u8 {
            self.service
        }

        fn subservice(&self) -> u8 {
            self.subservice
        }

        fn source_id(&self) -> u16 {
            self.source_id.get()
        }
    }

    impl PusTcDataFieldHeader {
        pub fn to_bytes(&self, slice: &mut (impl AsMut<[u8]> + ?Sized)) -> Option<()> {
            self.write_to(slice.as_mut())
        }

        pub fn from_bytes(slice: &(impl AsRef<[u8]> + ?Sized)) -> Option<Self> {
            Self::read_from(slice.as_ref())
        }
    }
}

#[derive(PartialEq, Copy, Clone, Serialize, Deserialize, Debug)]
pub struct PusTcDataFieldHeader {
    pub service: u8,
    pub subservice: u8,
    pub source_id: u16,
    pub ack: u8,
    pub version: PusVersion,
}

impl PusTcSecondaryHeader for PusTcDataFieldHeader {
    fn ack_flags(&self) -> u8 {
        self.ack
    }

    fn service(&self) -> u8 {
        self.service
    }

    fn subservice(&self) -> u8 {
        self.subservice
    }

    fn source_id(&self) -> u16 {
        self.source_id
    }
}
impl TryFrom<zc::PusTcDataFieldHeader> for PusTcDataFieldHeader {
    type Error = ();

    fn try_from(value: zc::PusTcDataFieldHeader) -> Result<Self, Self::Error> {
        Ok(PusTcDataFieldHeader {
            service: value.service(),
            subservice: value.subservice(),
            source_id: value.source_id(),
            ack: value.ack_flags(),
            version: PUS_VERSION,
        })
    }
}

impl PusTcDataFieldHeader {
    pub fn new_simple(service: u8, subservice: u8) -> Self {
        PusTcDataFieldHeader {
            service,
            subservice,
            ack: ACK_ALL,
            source_id: 0,
            version: PusVersion::PusC,
        }
    }

    pub fn new(service: u8, subservice: u8, ack: u8, source_id: u16) -> Self {
        PusTcDataFieldHeader {
            service,
            subservice,
            ack: ack & 0b1111,
            source_id,
            version: PusVersion::PusC,
        }
    }
}

/// This struct models a PUS telecommand and which can also be used. It is the primary data
/// structure to generate the raw byte representation of a PUS telecommand or to
/// deserialize from one from raw bytes.
///
/// There is no spare bytes support.
#[derive(PartialEq, Copy, Clone, Serialize, Deserialize, Debug)]
pub struct PusTc<'slice> {
    pub sph: SpHeader,
    pub data_field_header: PusTcDataFieldHeader,
    /// If this is set to false, a manual call to [PusTc::calc_own_crc16] is necessary for the
    /// serialized or cached CRC16 to be valid.
    pub calc_crc_on_serialization: bool,
    #[serde(skip)]
    raw_data: Option<&'slice [u8]>,
    app_data: Option<&'slice [u8]>,
    crc16: Option<u16>,
}

impl<'slice> PusTc<'slice> {
    /// Generates a new struct instance.
    ///
    /// # Arguments
    ///
    /// * `sph` - Space packet header information. The correct packet type will be set
    ///     automatically
    /// * `pus_params` - Information contained in the data field header, including the service
    ///     and subservice type
    /// * `set_ccsds_len` - Can be used to automatically update the CCSDS space packet data length
    ///     field. If this is not set to true, [PusTc::update_ccsds_data_len] can be called to set
    ///     the correct value to this field manually
    /// * `app_data` - Custom application data
    pub fn new(
        sph: &mut SpHeader,
        pus_params: PusTcDataFieldHeader,
        app_data: Option<&'slice [u8]>,
        set_ccsds_len: bool,
    ) -> Self {
        sph.packet_id.ptype = PacketType::Tc;
        let mut pus_tc = PusTc {
            sph: *sph,
            raw_data: None,
            app_data,
            data_field_header: pus_params,
            calc_crc_on_serialization: true,
            crc16: None,
        };
        if set_ccsds_len {
            pus_tc.update_ccsds_data_len();
        }
        pus_tc
    }

    /// Simplified version of the [PusTc::new] function which allows to only specify service and
    /// subservice instead of the full PUS TC secondary header
    pub fn new_simple(
        sph: &mut SpHeader,
        service: u8,
        subservice: u8,
        app_data: Option<&'slice [u8]>,
        set_ccsds_len: bool,
    ) -> Self {
        Self::new(
            sph,
            PusTcDataFieldHeader::new(service, subservice, ACK_ALL, 0),
            app_data,
            set_ccsds_len,
        )
    }

    pub fn len_packed(&self) -> usize {
        let mut length = PUS_TC_MIN_LEN_WITHOUT_APP_DATA;
        if let Some(app_data) = self.app_data {
            length += app_data.len();
        }
        length
    }

    pub fn set_seq_flags(&mut self, seq_flag: SequenceFlags) {
        self.sph.psc.seq_flags = seq_flag;
    }

    pub fn set_ack_field(&mut self, ack: u8) -> bool {
        if ack > 0b1111 {
            return false;
        }
        self.data_field_header.ack = ack & 0b1111;
        true
    }

    pub fn set_source_id(&mut self, source_id: u16) {
        self.data_field_header.source_id = source_id;
    }

    /// Forwards the call to [crate::PacketId::set_apid]
    pub fn set_apid(&mut self, apid: u16) -> bool {
        self.sph.packet_id.set_apid(apid)
    }

    /// Forwards the call to [crate::PacketSequenceCtrl::set_seq_count]
    pub fn set_seq_count(&mut self, seq_count: u16) -> bool {
        self.sph.psc.set_seq_count(seq_count)
    }

    /// Calculate the CCSDS space packet data length field and sets it
    pub fn update_ccsds_data_len(&mut self) {
        self.sph.data_len = self.len_packed() as u16 - size_of::<crate::zc::SpHeader>() as u16 - 1;
    }

    fn crc_from_raw_data(&self) -> Result<u16, PusError> {
        if let Some(raw_data) = self.raw_data {
            if raw_data.len() < 2 {
                return Err(PusError::RawDataTooShort(raw_data.len()));
            }
            return Ok(u16::from_be_bytes(
                raw_data[raw_data.len() - 2..raw_data.len()]
                    .try_into()
                    .unwrap(),
            ));
        }
        Err(PusError::NoRawData)
    }

    pub fn calc_crc16(bytes: &[u8]) -> u16 {
        let mut digest = CRC_CCITT_FALSE.digest();
        digest.update(bytes);
        digest.finalize()
    }

    pub fn calc_own_crc16(&mut self) {
        let mut digest = CRC_CCITT_FALSE.digest();
        let sph_zc = crate::zc::SpHeader::from(self.sph);
        digest.update(sph_zc.as_bytes());
        let pus_tc_header = zc::PusTcDataFieldHeader::try_from(self.data_field_header).unwrap();
        digest.update(pus_tc_header.as_bytes());
        if let Some(app_data) = self.app_data {
            digest.update(app_data);
        }
        self.crc16 = Some(digest.finalize())
    }

    /// This function updates two important internal fields: The CCSDS packet length in the
    /// space packet header and the CRC16 field. This function should be called before
    /// the TC packet is serialized
    pub fn update_packet_fields(&mut self) {
        self.update_ccsds_data_len();
        self.calc_own_crc16();
    }

    pub fn copy_to_buf(&self, slice: &mut (impl AsMut<[u8]> + ?Sized)) -> Result<usize, PusError> {
        let mut_slice = slice.as_mut();
        let mut curr_idx = 0;
        let sph_zc = crate::zc::SpHeader::from(self.sph);
        let tc_header_len = size_of::<zc::PusTcDataFieldHeader>();
        let mut total_size = PUS_TC_MIN_LEN_WITHOUT_APP_DATA;
        if let Some(app_data) = self.app_data {
            total_size += app_data.len();
        };
        if total_size > mut_slice.len() {
            return Err(PusError::OtherPacketError(
                PacketError::ToBytesSliceTooSmall(total_size),
            ));
        }
        sph_zc
            .to_bytes(&mut mut_slice[curr_idx..curr_idx + 6])
            .ok_or(PusError::OtherPacketError(
                PacketError::ToBytesZeroCopyError,
            ))?;
        curr_idx += 6;
        // The PUS version is hardcoded to PUS C
        let pus_tc_header = zc::PusTcDataFieldHeader::try_from(self.data_field_header).unwrap();

        pus_tc_header
            .to_bytes(&mut mut_slice[curr_idx..curr_idx + tc_header_len])
            .ok_or(PusError::OtherPacketError(
                PacketError::ToBytesZeroCopyError,
            ))?;
        curr_idx += tc_header_len;
        if let Some(app_data) = self.app_data {
            mut_slice[curr_idx..curr_idx + app_data.len()].copy_from_slice(app_data);
            curr_idx += app_data.len();
        }
        let crc16;
        if self.calc_crc_on_serialization {
            crc16 = Self::calc_crc16(&mut_slice[0..curr_idx])
        } else if self.crc16.is_none() {
            return Err(PusError::CrcCalculationMissing);
        } else {
            crc16 = self.crc16.unwrap();
        }
        mut_slice[curr_idx..curr_idx + 2].copy_from_slice(crc16.to_be_bytes().as_slice());
        curr_idx += 2;
        Ok(curr_idx)
    }

    pub fn append_to_vec(&self, vec: &mut Vec<u8>) -> Result<usize, PusError> {
        let sph_zc = crate::zc::SpHeader::from(self.sph);
        let mut appended_len = PUS_TC_MIN_LEN_WITHOUT_APP_DATA;
        if let Some(app_data) = self.app_data {
            appended_len += app_data.len();
        };
        let start_idx = vec.len();
        let mut curr_idx = vec.len();
        vec.extend_from_slice(sph_zc.as_bytes());
        curr_idx += sph_zc.as_bytes().len();
        // The PUS version is hardcoded to PUS C
        let pus_tc_header = zc::PusTcDataFieldHeader::try_from(self.data_field_header).unwrap();
        vec.extend_from_slice(pus_tc_header.as_bytes());
        curr_idx += pus_tc_header.as_bytes().len();
        if let Some(app_data) = self.app_data {
            vec.extend_from_slice(app_data);
            curr_idx += app_data.len();
        }
        let crc16;
        if self.calc_crc_on_serialization {
            crc16 = Self::calc_crc16(&vec[start_idx..curr_idx])
        } else if self.crc16.is_none() {
            return Err(PusError::CrcCalculationMissing);
        } else {
            crc16 = self.crc16.unwrap();
        }
        vec.extend_from_slice(crc16.to_be_bytes().as_slice());
        Ok(appended_len)
    }

    /// Create a PusTc instance from a raw slice. On success, it returns a tuple containing
    /// the instance and the found byte length of the packet
    pub fn new_from_raw_slice(
        slice: &'slice (impl AsRef<[u8]> + ?Sized),
    ) -> Result<(Self, usize), PusError> {
        let slice_ref = slice.as_ref();
        let raw_data_len = slice_ref.len();
        if raw_data_len < PUS_TC_MIN_LEN_WITHOUT_APP_DATA {
            return Err(PusError::RawDataTooShort(raw_data_len));
        }
        let mut current_idx = 0;
        let sph = crate::zc::SpHeader::from_bytes(&slice_ref[current_idx..current_idx + 6]).ok_or(
            PusError::OtherPacketError(PacketError::FromBytesZeroCopyError),
        )?;
        current_idx += 6;
        let total_len = sph.total_len();
        if raw_data_len < total_len || total_len < PUS_TC_MIN_LEN_WITHOUT_APP_DATA {
            return Err(PusError::RawDataTooShort(raw_data_len));
        }
        let sec_header = crate::tc::zc::PusTcDataFieldHeader::from_bytes(
            &slice_ref[current_idx..current_idx + PUC_TC_SECONDARY_HEADER_LEN],
        )
        .ok_or(PusError::OtherPacketError(
            PacketError::FromBytesZeroCopyError,
        ))?;
        current_idx += PUC_TC_SECONDARY_HEADER_LEN;
        let mut pus_tc = PusTc {
            sph: SpHeader::from(sph),
            data_field_header: PusTcDataFieldHeader::try_from(sec_header).unwrap(),
            raw_data: Some(slice_ref),
            app_data: match current_idx {
                _ if current_idx == total_len - 2 => None,
                _ if current_idx > total_len - 2 => {
                    return Err(PusError::RawDataTooShort(raw_data_len))
                }
                _ => Some(&slice_ref[current_idx..total_len - 2]),
            },
            calc_crc_on_serialization: false,
            crc16: None,
        };
        pus_tc.crc_from_raw_data()?;
        pus_tc.verify()?;
        Ok((pus_tc, total_len))
    }

    fn verify(&mut self) -> Result<(), PusError> {
        let mut digest = CRC_CCITT_FALSE.digest();
        if self.raw_data.is_none() {
            return Err(PusError::NoRawData);
        }
        let raw_data = self.raw_data.unwrap();
        digest.update(raw_data.as_ref());
        if digest.finalize() == 0 {
            return Ok(());
        }
        let crc16 = self.crc_from_raw_data()?;
        Err(PusError::IncorrectCrc(crc16))
    }
}

//noinspection RsTraitImplementation
impl CcsdsPacket for PusTc<'_> {
    delegate!(to self.sph {
        fn ccsds_version(&self) -> u8;
        fn packet_id(&self) -> crate::PacketId;
        fn psc(&self) -> crate::PacketSequenceCtrl;
        fn data_len(&self) -> u16;
    });
}

//noinspection RsTraitImplementation
impl PusPacket for PusTc<'_> {
    delegate!(to self.data_field_header {
        fn service(&self) -> u8;
        fn subservice(&self) -> u8;
    });

    fn user_data(&self) -> Option<&[u8]> {
        self.app_data
    }

    fn crc16(&self) -> Option<u16> {
        self.crc16
    }
}

//noinspection RsTraitImplementation
impl PusTcSecondaryHeader for PusTc<'_> {
    delegate!(to self.data_field_header {
        fn service(&self) -> u8;
        fn subservice(&self) -> u8;
        fn source_id(&self) -> u16;
        fn ack_flags(&self) -> u8;
    });
}
#[cfg(test)]
mod tests {
    use crate::ecss::{PusError, PusPacket};
    use crate::ser::SpHeader;
    use crate::tc::ACK_ALL;
    use crate::tc::{PusTc, PusTcDataFieldHeader, PusTcSecondaryHeader};
    use crate::{CcsdsPacket, SequenceFlags};
    use alloc::vec::Vec;

    fn base_ping_tc_full_ctor() -> PusTc<'static> {
        let mut sph = SpHeader::tc(0x02, 0x34, 0).unwrap();
        let tc_header = PusTcDataFieldHeader::new_simple(17, 1);
        PusTc::new(&mut sph, tc_header, None, true)
    }

    fn base_ping_tc_simple_ctor() -> PusTc<'static> {
        let mut sph = SpHeader::tc(0x02, 0x34, 0).unwrap();
        PusTc::new_simple(&mut sph, 17, 1, None, true)
    }

    fn base_ping_tc_simple_ctor_with_app_data(app_data: &'static [u8]) -> PusTc<'static> {
        let mut sph = SpHeader::tc(0x02, 0x34, 0).unwrap();
        PusTc::new_simple(&mut sph, 17, 1, Some(app_data), true)
    }

    #[test]
    fn test_tc_fields() {
        let pus_tc = base_ping_tc_full_ctor();
        assert_eq!(pus_tc.crc16(), None);
        verify_test_tc(&pus_tc, false, 13);
    }

    #[test]
    fn test_serialization() {
        let pus_tc = base_ping_tc_simple_ctor();
        let mut test_buf: [u8; 32] = [0; 32];
        let size = pus_tc
            .copy_to_buf(test_buf.as_mut_slice())
            .expect("Error writing TC to buffer");
        assert_eq!(size, 13);
    }
    #[test]
    fn test_deserialization() {
        let pus_tc = base_ping_tc_simple_ctor();
        let mut test_buf: [u8; 32] = [0; 32];
        let size = pus_tc
            .copy_to_buf(test_buf.as_mut_slice())
            .expect("Error writing TC to buffer");
        assert_eq!(size, 13);
        let (tc_from_raw, size) = PusTc::new_from_raw_slice(&test_buf)
            .expect("Creating PUS TC struct from raw buffer failed");
        assert_eq!(size, 13);
        verify_test_tc(&tc_from_raw, false, 13);
        verify_test_tc_raw(&test_buf);
        verify_crc_no_app_data(&test_buf);
    }

    #[test]
    fn test_vec_ser_deser() {
        let pus_tc = base_ping_tc_simple_ctor();
        let mut test_vec = Vec::new();
        let size = pus_tc
            .append_to_vec(&mut test_vec)
            .expect("Error writing TC to vector");
        assert_eq!(size, 13);
        verify_test_tc_raw(&test_vec.as_slice());
        verify_crc_no_app_data(&test_vec.as_slice());
    }

    #[test]
    fn test_incorrect_crc() {
        let pus_tc = base_ping_tc_simple_ctor();
        let mut test_buf: [u8; 32] = [0; 32];
        pus_tc
            .copy_to_buf(test_buf.as_mut_slice())
            .expect("Error writing TC to buffer");
        test_buf[12] = 0;
        let res = PusTc::new_from_raw_slice(&test_buf);
        assert!(res.is_err());
        let err = res.unwrap_err();
        assert!(matches!(err, PusError::IncorrectCrc { .. }));
    }

    #[test]
    fn test_manual_crc_calculation() {
        let mut pus_tc = base_ping_tc_simple_ctor();
        pus_tc.calc_crc_on_serialization = false;
        let mut test_buf: [u8; 32] = [0; 32];
        pus_tc.calc_own_crc16();
        pus_tc
            .copy_to_buf(test_buf.as_mut_slice())
            .expect("Error writing TC to buffer");
        verify_test_tc_raw(&test_buf);
        verify_crc_no_app_data(&test_buf);
    }

    #[test]
    fn test_manual_crc_calculation_no_calc_call() {
        let mut pus_tc = base_ping_tc_simple_ctor();
        pus_tc.calc_crc_on_serialization = false;
        let mut test_buf: [u8; 32] = [0; 32];
        let res = pus_tc.copy_to_buf(test_buf.as_mut_slice());
        assert!(res.is_err());
        let err = res.unwrap_err();
        assert!(matches!(err, PusError::CrcCalculationMissing { .. }));
    }

    #[test]
    fn test_with_application_data_vec() {
        let pus_tc = base_ping_tc_simple_ctor_with_app_data(&[1, 2, 3]);
        verify_test_tc(&pus_tc, true, 16);
        let mut test_vec = Vec::new();
        let size = pus_tc
            .append_to_vec(&mut test_vec)
            .expect("Error writing TC to vector");
        assert_eq!(test_vec[11], 1);
        assert_eq!(test_vec[12], 2);
        assert_eq!(test_vec[13], 3);
        assert_eq!(size, 16);
    }

    #[test]
    fn test_with_application_data_buf() {
        let pus_tc = base_ping_tc_simple_ctor_with_app_data(&[1, 2, 3]);
        verify_test_tc(&pus_tc, true, 16);
        let mut test_buf: [u8; 32] = [0; 32];
        let size = pus_tc
            .copy_to_buf(test_buf.as_mut_slice())
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
            .copy_to_buf(test_buf.as_mut_slice())
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

    fn verify_test_tc(tc: &PusTc, has_user_data: bool, exp_full_len: usize) {
        assert_eq!(PusPacket::service(tc), 17);
        assert_eq!(PusPacket::subservice(tc), 1);
        if !has_user_data {
            assert_eq!(tc.user_data(), None);
        }
        assert_eq!(tc.seq_count(), 0x34);
        assert_eq!(tc.source_id(), 0);
        assert_eq!(tc.apid(), 0x02);
        assert_eq!(tc.ack_flags(), ACK_ALL);
        assert_eq!(tc.len_packed(), exp_full_len);
        assert_eq!(
            tc.sph,
            SpHeader::tc(0x02, 0x34, exp_full_len as u16 - 7).unwrap()
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
}
