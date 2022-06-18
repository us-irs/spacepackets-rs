//! # Space related components including CCSDS and ECSS packet standards
#![no_std]
extern crate alloc;

use crate::ecss::CCSDS_HEADER_LEN;
use serde::{Deserialize, Serialize};

pub mod ecss;
pub mod tc;
pub mod tm;

#[derive(Debug, Copy, Clone, PartialEq)]
pub enum PacketError {
    /// The passed slice is too small. Returns the required size of the failed size chgeck
    ToBytesSliceTooSmall(usize),
    /// The [zerocopy] library failed to write to bytes
    ToBytesZeroCopyError,
    FromBytesZeroCopyError,
}

#[derive(Serialize, Deserialize, Debug, PartialEq, Copy, Clone)]
pub enum PacketType {
    Tm = 0,
    Tc = 1,
}

impl TryFrom<u8> for PacketType {
    type Error = ();

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            x if x == PacketType::Tm as u8 => Ok(PacketType::Tm),
            x if x == PacketType::Tc as u8 => Ok(PacketType::Tc),
            _ => Err(()),
        }
    }
}

pub fn packet_type_in_raw_packet_id(packet_id: u16) -> PacketType {
    PacketType::try_from((packet_id >> 12) as u8 & 0b1).unwrap()
}

#[derive(Serialize, Deserialize, Debug, PartialEq, Copy, Clone)]
pub enum SequenceFlags {
    ContinuationSegment = 0b00,
    FirstSegment = 0b01,
    LastSegment = 0b10,
    Unsegmented = 0b11,
}

impl TryFrom<u8> for SequenceFlags {
    type Error = ();

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            x if x == SequenceFlags::ContinuationSegment as u8 => {
                Ok(SequenceFlags::ContinuationSegment)
            }
            x if x == SequenceFlags::FirstSegment as u8 => Ok(SequenceFlags::FirstSegment),
            x if x == SequenceFlags::LastSegment as u8 => Ok(SequenceFlags::LastSegment),
            x if x == SequenceFlags::Unsegmented as u8 => Ok(SequenceFlags::Unsegmented),
            _ => Err(()),
        }
    }
}

#[derive(Serialize, Deserialize, Debug, PartialEq, Copy, Clone)]
pub struct PacketId {
    pub ptype: PacketType,
    pub sec_header_flag: bool,
    apid: u16,
}

impl PacketId {
    pub fn new(ptype: PacketType, sec_header_flag: bool, apid: u16) -> Option<PacketId> {
        let mut pid = PacketId {
            ptype,
            sec_header_flag,
            apid: 0,
        };
        pid.set_apid(apid).then(|| pid)
    }

    pub fn set_apid(&mut self, apid: u16) -> bool {
        if apid > num::pow(2, 11) - 1 {
            return false;
        }
        self.apid = apid;
        true
    }

    pub fn apid(&self) -> u16 {
        self.apid
    }

    pub fn raw(&self) -> u16 {
        ((self.ptype as u16) << 12) | ((self.sec_header_flag as u16) << 11) | self.apid
    }
}

impl From<u16> for PacketId {
    fn from(raw_id: u16) -> Self {
        PacketId {
            ptype: PacketType::try_from(((raw_id >> 12) & 0b1) as u8).unwrap(),
            sec_header_flag: ((raw_id >> 11) & 0b1) != 0,
            apid: raw_id & 0x7FF,
        }
    }
}

#[derive(Serialize, Deserialize, Debug, PartialEq, Copy, Clone)]
pub struct PacketSequenceCtrl {
    pub seq_flags: SequenceFlags,
    ssc: u16,
}

impl PacketSequenceCtrl {
    pub fn new(seq_flags: SequenceFlags, ssc: u16) -> Option<PacketSequenceCtrl> {
        let mut psc = PacketSequenceCtrl { seq_flags, ssc: 0 };
        psc.set_ssc(ssc).then(|| psc)
    }
    pub fn raw(&self) -> u16 {
        ((self.seq_flags as u16) << 14) | self.ssc
    }

    pub fn set_ssc(&mut self, ssc: u16) -> bool {
        if ssc > num::pow(2, 14) - 1 {
            return false;
        }
        self.ssc = ssc;
        true
    }

    pub fn ssc(&self) -> u16 {
        self.ssc
    }
}

impl From<u16> for PacketSequenceCtrl {
    fn from(raw_id: u16) -> Self {
        PacketSequenceCtrl {
            seq_flags: SequenceFlags::try_from(((raw_id >> 14) & 0b11) as u8).unwrap(),
            ssc: raw_id & SSC_MASK,
        }
    }
}

macro_rules! sph_from_other {
    ($Self: path, $other: path) => {
        impl From<$other> for $Self {
            fn from(other: $other) -> Self {
                Self::from_composite_fields(
                    other.packet_id(),
                    other.psc(),
                    other.data_len(),
                    Some(other.ccsds_version()),
                )
            }
        }
    };
}

const SSC_MASK: u16 = 0x3FFF;
const VERSION_MASK: u16 = 0xE000;

/// Generic trait to access fields of a CCSDS space packet header according to CCSDS 133.0-B-2
pub trait CcsdsPacket {
    fn ccsds_version(&self) -> u8;
    fn packet_id(&self) -> PacketId;
    fn psc(&self) -> PacketSequenceCtrl;

    /// Retrieve data length field
    fn data_len(&self) -> u16;
    /// Retrieve the total packet size based on the data length field
    fn total_len(&self) -> usize {
        usize::from(self.data_len()) + CCSDS_HEADER_LEN + 1
    }

    /// Retrieve 13 bit Packet Identification field. Can usually be retrieved with a bitwise AND
    /// of the first 2 bytes with 0x1FFF
    #[inline]
    fn packet_id_raw(&self) -> u16 {
        self.packet_id().raw()
    }
    /// Retrieve Packet Sequence Count
    #[inline]
    fn psc_raw(&self) -> u16 {
        self.psc().raw()
    }

    #[inline]
    /// Retrieve Packet Type (TM: 0, TC: 1)
    fn ptype(&self) -> PacketType {
        // This call should never fail because only 0 and 1 can be passed to the try_from call
        self.packet_id().ptype
    }

    #[inline]
    fn is_tm(&self) -> bool {
        self.ptype() == PacketType::Tm
    }

    #[inline]
    fn is_tc(&self) -> bool {
        self.ptype() == PacketType::Tc
    }

    /// Retrieve the secondary header flag. Returns true if a secondary header is present
    /// and false if it is not
    #[inline]
    fn sec_header_flag(&self) -> bool {
        self.packet_id().sec_header_flag
    }

    /// Retrieve Application Process ID
    #[inline]
    fn apid(&self) -> u16 {
        self.packet_id().apid
    }

    #[inline]
    fn ssc(&self) -> u16 {
        self.psc().ssc
    }

    #[inline]
    fn sequence_flags(&self) -> SequenceFlags {
        // This call should never fail because the mask ensures that only valid values are passed
        // into the try_from function
        self.psc().seq_flags
    }
}

pub trait CcsdsPrimaryHeader {
    fn from_composite_fields(
        packet_id: PacketId,
        psc: PacketSequenceCtrl,
        data_len: u16,
        version: Option<u8>,
    ) -> Self;
}

pub mod ser {
    use crate::{
        CcsdsPacket, CcsdsPrimaryHeader, PacketId, PacketSequenceCtrl, PacketType, SequenceFlags,
    };

    /// Space Packet Primary Header according to CCSDS 133.0-B-2
    #[derive(serde::Serialize, serde::Deserialize, Debug, PartialEq, Copy, Clone)]
    pub struct SpHeader {
        pub version: u8,
        pub packet_id: PacketId,
        pub psc: PacketSequenceCtrl,
        pub data_len: u16,
    }
    impl Default for SpHeader {
        fn default() -> Self {
            SpHeader {
                version: 0,
                packet_id: PacketId {
                    ptype: PacketType::Tm,
                    apid: 0,
                    sec_header_flag: true,
                },
                psc: PacketSequenceCtrl {
                    seq_flags: SequenceFlags::Unsegmented,
                    ssc: 0,
                },
                data_len: 0,
            }
        }
    }
    impl SpHeader {
        pub fn new(apid: u16, ptype: PacketType, ssc: u16, data_len: u16) -> Option<Self> {
            if ssc > num::pow(2, 14) - 1 || apid > num::pow(2, 11) - 1 {
                return None;
            }
            let mut header = SpHeader::default();
            header.packet_id.apid = apid;
            header.packet_id.ptype = ptype;
            header.psc.ssc = ssc;
            header.data_len = data_len;
            Some(header)
        }

        pub fn tm(apid: u16, ssc: u16, data_len: u16) -> Option<Self> {
            Self::new(apid, PacketType::Tm, ssc, data_len)
        }

        pub fn tc(apid: u16, ssc: u16, data_len: u16) -> Option<Self> {
            Self::new(apid, PacketType::Tc, ssc, data_len)
        }
    }

    impl CcsdsPacket for SpHeader {
        #[inline]
        fn ccsds_version(&self) -> u8 {
            self.version
        }

        #[inline]
        fn packet_id(&self) -> PacketId {
            self.packet_id
        }

        #[inline]
        fn psc(&self) -> PacketSequenceCtrl {
            self.psc
        }

        #[inline]
        fn data_len(&self) -> u16 {
            self.data_len
        }
    }

    impl CcsdsPrimaryHeader for SpHeader {
        fn from_composite_fields(
            packet_id: PacketId,
            psc: PacketSequenceCtrl,
            data_len: u16,
            version: Option<u8>,
        ) -> Self {
            let mut version_to_set = 0b000;
            if let Some(version) = version {
                version_to_set = version;
            }
            SpHeader {
                version: version_to_set,
                packet_id,
                psc,
                data_len,
            }
        }
    }

    sph_from_other!(SpHeader, crate::zc::SpHeader);
}

pub mod zc {
    use crate::{CcsdsPacket, CcsdsPrimaryHeader, PacketId, PacketSequenceCtrl, VERSION_MASK};
    use zerocopy::byteorder::NetworkEndian;
    use zerocopy::{AsBytes, FromBytes, Unaligned, U16};

    #[derive(FromBytes, AsBytes, Unaligned, Debug)]
    #[repr(C)]
    pub struct SpHeader {
        version_packet_id: U16<NetworkEndian>,
        psc: U16<NetworkEndian>,
        data_len: U16<NetworkEndian>,
    }

    impl SpHeader {
        pub fn new(
            packet_id: PacketId,
            psc: PacketSequenceCtrl,
            data_len: u16,
            version: Option<u8>,
        ) -> Self {
            let mut version_packet_id = packet_id.raw();
            if let Some(version) = version {
                version_packet_id = ((version as u16) << 13) | packet_id.raw()
            }
            SpHeader {
                version_packet_id: U16::from(version_packet_id),
                psc: U16::from(psc.raw()),
                data_len: U16::from(data_len),
            }
        }

        pub fn from_bytes(slice: &(impl AsRef<[u8]> + ?Sized)) -> Option<Self> {
            SpHeader::read_from(slice.as_ref())
        }

        pub fn to_bytes(&self, slice: &mut (impl AsMut<[u8]> + ?Sized)) -> Option<()> {
            self.write_to(slice.as_mut())
        }
    }

    impl CcsdsPacket for SpHeader {
        #[inline]
        fn ccsds_version(&self) -> u8 {
            ((self.version_packet_id.get() >> 13) as u8) & 0b111
        }

        fn packet_id(&self) -> PacketId {
            PacketId::from(self.packet_id_raw())
        }
        fn psc(&self) -> PacketSequenceCtrl {
            PacketSequenceCtrl::from(self.psc_raw())
        }

        #[inline]
        fn data_len(&self) -> u16 {
            self.data_len.get()
        }

        fn packet_id_raw(&self) -> u16 {
            self.version_packet_id.get() & (!VERSION_MASK)
        }

        fn psc_raw(&self) -> u16 {
            self.psc.get()
        }
    }

    impl CcsdsPrimaryHeader for SpHeader {
        fn from_composite_fields(
            packet_id: PacketId,
            psc: PacketSequenceCtrl,
            data_len: u16,
            version: Option<u8>,
        ) -> Self {
            SpHeader::new(packet_id, psc, data_len, version)
        }
    }

    sph_from_other!(SpHeader, crate::ser::SpHeader);
}

#[cfg(test)]
mod tests {
    use crate::ser::SpHeader;
    use crate::{
        packet_type_in_raw_packet_id, zc, CcsdsPacket, CcsdsPrimaryHeader, PacketId,
        PacketSequenceCtrl, PacketType, SequenceFlags,
    };
    use alloc::vec;
    use postcard::{from_bytes, to_stdvec};

    #[test]
    fn test_helpers() {
        assert_eq!(
            SequenceFlags::try_from(0b00).expect("SEQ flag creation failed"),
            SequenceFlags::ContinuationSegment
        );
        assert_eq!(
            SequenceFlags::try_from(0b01).expect("SEQ flag creation failed"),
            SequenceFlags::FirstSegment
        );
        assert_eq!(
            SequenceFlags::try_from(0b10).expect("SEQ flag creation failed"),
            SequenceFlags::LastSegment
        );
        assert_eq!(
            SequenceFlags::try_from(0b11).expect("SEQ flag creation failed"),
            SequenceFlags::Unsegmented
        );
        assert!(SequenceFlags::try_from(0b100).is_err());
        assert!(PacketType::try_from(0b10).is_err());
        let packet_id =
            PacketId::new(PacketType::Tm, false, 0x42).expect("Packet ID creation failed");
        assert_eq!(packet_id.raw(), 0x0042);
        let packet_id_from_raw = PacketId::from(packet_id.raw());
        assert_eq!(
            packet_type_in_raw_packet_id(packet_id.raw()),
            PacketType::Tm
        );
        assert_eq!(packet_id_from_raw, packet_id);

        let packet_id_invalid = PacketId::new(PacketType::Tc, true, 0xFFFF);
        assert!(packet_id_invalid.is_none());
        let packet_id_from_new = PacketId::new(PacketType::Tm, false, 0x42).unwrap();
        assert_eq!(packet_id_from_new, packet_id);
        let mut psc = PacketSequenceCtrl::new(SequenceFlags::ContinuationSegment, 77)
            .expect("PSC creation failed");
        assert_eq!(psc.raw(), 77);
        let psc_from_raw = PacketSequenceCtrl::from(psc.raw());
        assert_eq!(psc_from_raw, psc);
        // Fails because SSC is limited to 14 bits
        assert!(!psc.set_ssc(num::pow(2, 15)));
        assert_eq!(psc.raw(), 77);

        let psc_invalid = PacketSequenceCtrl::new(SequenceFlags::FirstSegment, 0xFFFF);
        assert!(psc_invalid.is_none());
        let psc_from_new = PacketSequenceCtrl::new(SequenceFlags::ContinuationSegment, 77).unwrap();
        assert_eq!(psc_from_new, psc);
    }

    #[test]
    fn test_serde_sph() {
        let sp_header = SpHeader::tc(0x42, 12, 0).expect("Error creating SP header");
        assert_eq!(sp_header.ccsds_version(), 0b000);
        assert!(sp_header.is_tc());
        assert!(sp_header.sec_header_flag());
        assert_eq!(sp_header.ptype(), PacketType::Tc);
        assert_eq!(sp_header.ssc(), 12);
        assert_eq!(sp_header.apid(), 0x42);
        assert_eq!(sp_header.sequence_flags(), SequenceFlags::Unsegmented);
        assert_eq!(sp_header.data_len(), 0);
        let output = to_stdvec(&sp_header).unwrap();
        let sp_header: SpHeader = from_bytes(&output).unwrap();
        assert_eq!(sp_header.version, 0b000);
        assert!(sp_header.packet_id.sec_header_flag);
        assert_eq!(sp_header.ptype(), PacketType::Tc);
        assert_eq!(sp_header.ssc(), 12);
        assert_eq!(sp_header.apid(), 0x42);
        assert_eq!(sp_header.sequence_flags(), SequenceFlags::Unsegmented);
        assert_eq!(sp_header.packet_id_raw(), 0x1842);
        assert_eq!(sp_header.psc_raw(), 0xC00C);
        assert_eq!(sp_header.ccsds_version(), 0b000);
        assert_eq!(sp_header.data_len, 0);

        let sp_header = SpHeader::tm(0x7, 22, 36).expect("Error creating SP header");
        assert_eq!(sp_header.ccsds_version(), 0b000);
        assert!(sp_header.is_tm());
        assert!(sp_header.sec_header_flag());
        assert_eq!(sp_header.ptype(), PacketType::Tm);
        assert_eq!(sp_header.ssc(), 22);
        assert_eq!(sp_header.apid(), 0x07);
        assert_eq!(sp_header.sequence_flags(), SequenceFlags::Unsegmented);
        assert_eq!(sp_header.packet_id_raw(), 0x0807);
        assert_eq!(sp_header.psc_raw(), 0xC016);
        assert_eq!(sp_header.data_len(), 36);
        assert_eq!(sp_header.ccsds_version(), 0b000);

        let from_comp_fields = SpHeader::from_composite_fields(
            PacketId::new(PacketType::Tc, true, 0x42).unwrap(),
            PacketSequenceCtrl::new(SequenceFlags::Unsegmented, 0x7).unwrap(),
            0,
            None,
        );
        assert_eq!(from_comp_fields.ptype(), PacketType::Tc);
        assert_eq!(from_comp_fields.apid(), 0x42);
        assert!(from_comp_fields.sec_header_flag());
        assert_eq!(
            from_comp_fields.sequence_flags(),
            SequenceFlags::Unsegmented
        );
        assert_eq!(from_comp_fields.ssc(), 0x7);
        assert_eq!(from_comp_fields.data_len(), 0);
    }

    #[test]
    fn test_zc_sph() {
        use zerocopy::AsBytes;

        let sp_header =
            SpHeader::tc(0x7FF, num::pow(2, 14) - 1, 0).expect("Error creating SP header");
        assert_eq!(sp_header.ptype(), PacketType::Tc);
        assert_eq!(sp_header.apid(), 0x7FF);
        assert_eq!(sp_header.data_len(), 0);
        assert_eq!(sp_header.ccsds_version(), 0b000);
        assert!(sp_header.is_tc());
        let sp_header_zc = zc::SpHeader::from(sp_header);
        let slice = sp_header_zc.as_bytes();
        assert_eq!(slice.len(), 6);
        assert_eq!(slice[0], 0x1F);
        assert_eq!(slice[1], 0xFF);
        assert_eq!(slice[2], 0xFF);
        assert_eq!(slice[3], 0xFF);
        assert_eq!(slice[4], 0x00);
        assert_eq!(slice[5], 0x00);

        let mut slice = [0; 6];
        sp_header_zc.write_to(slice.as_mut_slice());
        assert_eq!(slice.len(), 6);
        assert_eq!(slice[0], 0x1F);
        assert_eq!(slice[1], 0xFF);
        assert_eq!(slice[2], 0xFF);
        assert_eq!(slice[3], 0xFF);
        assert_eq!(slice[4], 0x00);
        assert_eq!(slice[5], 0x00);

        let mut test_vec = vec![0_u8; 6];
        let slice = test_vec.as_mut_slice();
        sp_header_zc.write_to(slice);
        let slice = test_vec.as_slice();
        assert_eq!(slice.len(), 6);
        assert_eq!(slice[0], 0x1F);
        assert_eq!(slice[1], 0xFF);
        assert_eq!(slice[2], 0xFF);
        assert_eq!(slice[3], 0xFF);
        assert_eq!(slice[4], 0x00);
        assert_eq!(slice[5], 0x00);

        let sp_header = zc::SpHeader::from_bytes(slice);
        assert!(sp_header.is_some());
        let sp_header = sp_header.unwrap();
        assert_eq!(sp_header.ccsds_version(), 0b000);
        assert_eq!(sp_header.packet_id_raw(), 0x1FFF);
        assert_eq!(sp_header.apid(), 0x7FF);
        assert_eq!(sp_header.ptype(), PacketType::Tc);
        assert_eq!(sp_header.data_len(), 0);
    }
}
