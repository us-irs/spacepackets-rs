//! # CCSDS and ECSS packet standards implementations
//!
//! This crate contains generic implementations for various
//! CCSDS (Consultative Committee for Space Data Systems) and
//! ECSS (European Cooperation for Space Standardization) packet standards.
//! Currently, this includes the following components:
//!
//!  - Space Packet implementation according to
//!    [CCSDS Blue Book 133.0-B-2](https://public.ccsds.org/Pubs/133x0b2e1.pdf)
//!  - CCSDS File Delivery Protocol (CFDP) packet implementations according to
//!    [CCSDS Blue Book 727.0-B-5](https://public.ccsds.org/Pubs/727x0b5.pdf)
//!  - PUS Telecommand and PUS Telemetry implementation according to the
//!    [ECSS-E-ST-70-41C standard](https://ecss.nl/standard/ecss-e-st-70-41c-space-engineering-telemetry-and-telecommand-packet-utilization-15-april-2016/).
//!  - CUC (CCSDS Unsegmented Time Code) implementation according to
//!    [CCSDS 301.0-B-4 3.2](https://public.ccsds.org/Pubs/301x0b4e1.pdf)
//!  - CDS (CCSDS Day Segmented Time Code) implementation according to
//!    [CCSDS 301.0-B-4 3.3](https://public.ccsds.org/Pubs/301x0b4e1.pdf)
//!  - Some helper types to support ASCII timecodes as specified in
//!    [CCSDS 301.0-B-4 3.5](https://public.ccsds.org/Pubs/301x0b4e1.pdf)
//!
//! ## Features
//!
//! `spacepackets` supports various runtime environments and is also suitable for `no_std` environments.
//!
//! ### Default features
//!
//!  - [`std`](https://doc.rust-lang.org/std/): Enables functionality relying on the standard library.
//!  - [`alloc`](https://doc.rust-lang.org/alloc/): Enables features which operate on containers
//!    like [`alloc::vec::Vec`](https://doc.rust-lang.org/beta/alloc/vec/struct.Vec.html).
//!    Enabled by the `std` feature.
//!
//! ### Optional features
//!
//!  - [`serde`](https://serde.rs/): Adds `serde` support for most types by adding `Serialize` and
//!    `Deserialize` `derives.
//!  - [`chrono`](https://crates.io/crates/chrono): Add basic support for the `chrono` time library.
//!  - [`timelib`](https://crates.io/crates/time): Add basic support for the `time` time library.
//!  - [`defmt`](https://defmt.ferrous-systems.com/): Add support for the `defmt` by adding the
//!    [`defmt::Format`](https://defmt.ferrous-systems.com/format) derive on many types.
//!
//! ## Module
//!
//! This module contains helpers and data structures to generate Space Packets according to the
//! [CCSDS 133.0-B-2](https://public.ccsds.org/Pubs/133x0b2e1.pdf). This includes the
//! [SpHeader] class to generate the Space Packet Header component common to all space packets.
//!
//! ## Example
//!
//! ```rust
//! use spacepackets::SpHeader;
//! let sp_header = SpHeader::new_for_unseg_tc_checked(0x42, 12, 1).expect("error creating CCSDS TC header");
//! println!("{:?}", sp_header);
//! let mut ccsds_buf: [u8; 32] = [0; 32];
//! sp_header.write_to_be_bytes(&mut ccsds_buf).expect("Writing CCSDS TC header failed");
//! println!("{:x?}", &ccsds_buf[0..6]);
//! ```
#![no_std]
#![cfg_attr(docsrs, feature(doc_auto_cfg))]
#[cfg(feature = "alloc")]
extern crate alloc;
#[cfg(any(feature = "std", test))]
extern crate std;

use core::{fmt::Debug, hash::Hash};
use delegate::delegate;
use zerocopy::{FromBytes, IntoBytes};

#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

pub mod cfdp;
pub mod crc;
pub mod ecss;
pub mod seq_count;
pub mod time;
pub mod util;

mod private {
    pub trait Sealed {}
}

pub const CCSDS_HEADER_LEN: usize = core::mem::size_of::<crate::zc::SpHeader>();

pub const MAX_APID: u16 = 2u16.pow(11) - 1;
pub const MAX_SEQ_COUNT: u16 = 2u16.pow(14) - 1;

/// Generic error type when converting to and from raw byte slices.
#[derive(Debug, Copy, Clone, PartialEq, Eq, thiserror::Error)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum ByteConversionError {
    /// The passed slice is too small. Returns the passed slice length and expected minimum size
    #[error("target slice with size {found} is too small, expected size of at least {expected}")]
    ToSliceTooSmall { found: usize, expected: usize },
    /// The provider buffer is too small. Returns the passed slice length and expected minimum size
    #[error("source slice with size {found} too small, expected at least {expected} bytes")]
    FromSliceTooSmall { found: usize, expected: usize },
    /// The [zerocopy] library failed to write to bytes
    #[error("zerocopy serialization error")]
    ZeroCopyToError,
    /// The [zerocopy] library failed to read from bytes
    #[error("zerocopy deserialization error")]
    ZeroCopyFromError,
}

/// CCSDS packet type enumeration.
#[derive(Debug, PartialEq, Eq, Copy, Clone)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
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

#[derive(Debug, PartialEq, Eq, Copy, Clone)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
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

/// Abstraction for the CCSDS Packet ID, which forms the last thirteen bits
/// of the first two bytes in the CCSDS primary header.
#[derive(Debug, Eq, Copy, Clone)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct PacketId {
    pub ptype: PacketType,
    pub sec_header_flag: bool,
    apid: u16,
}

impl PartialEq for PacketId {
    #[inline]
    fn eq(&self, other: &Self) -> bool {
        self.raw().eq(&other.raw())
    }
}

impl PartialOrd for PacketId {
    #[inline]
    fn partial_cmp(&self, other: &Self) -> Option<core::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for PacketId {
    #[inline]
    fn cmp(&self, other: &Self) -> core::cmp::Ordering {
        self.raw().cmp(&other.raw())
    }
}

impl Hash for PacketId {
    fn hash<H: core::hash::Hasher>(&self, state: &mut H) {
        let raw = self.raw();
        raw.hash(state);
    }
}

impl Default for PacketId {
    #[inline]
    fn default() -> Self {
        PacketId {
            ptype: PacketType::Tm,
            sec_header_flag: false,
            apid: 0,
        }
    }
}

impl PacketId {
    /// This constructor will panic if the passed APID exceeds [MAX_APID].
    /// Use the checked constructor variants to avoid panics.
    #[inline]
    pub const fn new_for_tc(sec_header: bool, apid: u16) -> Self {
        Self::new(PacketType::Tc, sec_header, apid)
    }

    /// This constructor will panic if the passed APID exceeds [MAX_APID].
    /// Use the checked constructor variants to avoid panics.
    #[inline]
    pub const fn new_for_tm(sec_header: bool, apid: u16) -> Self {
        Self::new(PacketType::Tm, sec_header, apid)
    }

    #[inline]
    pub fn new_for_tc_checked(sec_header: bool, apid: u16) -> Option<Self> {
        Self::new_checked(PacketType::Tc, sec_header, apid)
    }

    #[inline]
    pub fn new_for_tm_checked(sec_header: bool, apid: u16) -> Option<Self> {
        Self::new_checked(PacketType::Tm, sec_header, apid)
    }

    /// This constructor will panic if the passed APID exceeds [MAX_APID].
    /// Use the checked variants to avoid panics.
    #[inline]
    pub const fn new(ptype: PacketType, sec_header: bool, apid: u16) -> Self {
        if apid > MAX_APID {
            panic!("APID too large");
        }
        PacketId {
            ptype,
            sec_header_flag: sec_header,
            apid,
        }
    }

    #[inline]
    pub fn new_checked(ptype: PacketType, sec_header_flag: bool, apid: u16) -> Option<PacketId> {
        if apid > MAX_APID {
            return None;
        }
        Some(PacketId::new(ptype, sec_header_flag, apid))
    }

    /// Set a new Application Process ID (APID). If the passed number is invalid, the APID will
    /// not be set and false will be returned. The maximum allowed value for the 11-bit field is
    /// 2047
    #[inline]
    pub fn set_apid(&mut self, apid: u16) -> bool {
        if apid > MAX_APID {
            return false;
        }
        self.apid = apid;
        true
    }

    #[inline]
    pub fn apid(&self) -> u16 {
        self.apid
    }

    #[inline]
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

/// Abstraction for the CCSDS Packet Sequence Control (PSC) field which is the
/// third and the fourth byte in the CCSDS primary header.
#[derive(Debug, PartialEq, Eq, Copy, Clone)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct PacketSequenceCtrl {
    pub seq_flags: SequenceFlags,
    seq_count: u16,
}

impl PacketSequenceCtrl {
    /// This constructor panics if the sequence count exceeds [MAX_SEQ_COUNT].
    /// Use [Self::new_checked] to avoid panics.
    #[inline]
    pub const fn new(seq_flags: SequenceFlags, seq_count: u16) -> PacketSequenceCtrl {
        if seq_count > MAX_SEQ_COUNT {
            panic!("Sequence count too large");
        }
        PacketSequenceCtrl {
            seq_flags,
            seq_count,
        }
    }

    /// Returns [None] if the passed sequence count exceeds [MAX_SEQ_COUNT].
    #[inline]
    pub fn new_checked(seq_flags: SequenceFlags, seq_count: u16) -> Option<PacketSequenceCtrl> {
        if seq_count > MAX_SEQ_COUNT {
            return None;
        }
        Some(PacketSequenceCtrl::new(seq_flags, seq_count))
    }

    #[inline]
    pub fn raw(&self) -> u16 {
        ((self.seq_flags as u16) << 14) | self.seq_count
    }

    /// Set a new sequence count. If the passed number is invalid, the sequence count will not be
    /// set and false will be returned. The maximum allowed value for the 14-bit field is 16383.
    #[inline]
    pub fn set_seq_count(&mut self, ssc: u16) -> bool {
        if ssc > MAX_SEQ_COUNT {
            return false;
        }
        self.seq_count = ssc;
        true
    }

    #[inline]
    pub fn seq_count(&self) -> u16 {
        self.seq_count
    }
}

impl From<u16> for PacketSequenceCtrl {
    fn from(raw_id: u16) -> Self {
        PacketSequenceCtrl {
            seq_flags: SequenceFlags::try_from(((raw_id >> 14) & 0b11) as u8).unwrap(),
            seq_count: raw_id & SSC_MASK,
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

/// Generic trait to access fields of a CCSDS space packet header according to CCSDS 133.0-B-2.
pub trait CcsdsPacket {
    fn ccsds_version(&self) -> u8;
    fn packet_id(&self) -> PacketId;
    fn psc(&self) -> PacketSequenceCtrl;

    /// Retrieve data length field
    fn data_len(&self) -> u16;
    /// Retrieve the total packet size based on the data length field
    #[inline]
    fn total_len(&self) -> usize {
        usize::from(self.data_len()) + CCSDS_HEADER_LEN + 1
    }

    /// Retrieve 13 bit Packet Identification field. Can usually be retrieved with a bitwise AND
    /// of the first 2 bytes with 0x1FFF.
    #[inline]
    fn packet_id_raw(&self) -> u16 {
        self.packet_id().raw()
    }
    /// Retrieve Packet Sequence Count
    #[inline]
    fn psc_raw(&self) -> u16 {
        self.psc().raw()
    }

    /// Retrieve Packet Type (TM: 0, TC: 1).
    #[inline]
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
    /// and false if it is not.
    #[inline]
    fn sec_header_flag(&self) -> bool {
        self.packet_id().sec_header_flag
    }

    /// Retrieve Application Process ID.
    #[inline]
    fn apid(&self) -> u16 {
        self.packet_id().apid
    }

    #[inline]
    fn seq_count(&self) -> u16 {
        self.psc().seq_count
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

/// Space Packet Primary Header according to CCSDS 133.0-B-2.
///
/// # Arguments
///
/// * `version` - CCSDS version field, occupies the first 3 bits of the raw header. Will generally
///   be set to 0b000 in all constructors provided by this crate.
/// * `packet_id` - Packet Identifier, which can also be used as a start marker. Occupies the last
///   13 bits of the first two bytes of the raw header
/// * `psc` - Packet Sequence Control, occupies the third and fourth byte of the raw header
/// * `data_len` - Data length field occupies the fifth and the sixth byte of the raw header
#[derive(Debug, PartialEq, Eq, Copy, Clone)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct SpHeader {
    pub version: u8,
    pub packet_id: PacketId,
    pub psc: PacketSequenceCtrl,
    pub data_len: u16,
}

pub type SpacePacketHeader = SpHeader;

impl Default for SpHeader {
    /// The default function sets the sequence flag field to [SequenceFlags::Unsegmented] and the
    /// data length to 0.
    #[inline]
    fn default() -> Self {
        SpHeader {
            version: 0,
            packet_id: PacketId::default(),
            psc: PacketSequenceCtrl {
                seq_flags: SequenceFlags::Unsegmented,
                seq_count: 0,
            },
            data_len: 0,
        }
    }
}

impl SpHeader {
    #[inline]
    pub const fn new(packet_id: PacketId, psc: PacketSequenceCtrl, data_len: u16) -> Self {
        Self {
            version: 0,
            packet_id,
            psc,
            data_len,
        }
    }

    /// This constructor sets the sequence flag field to [SequenceFlags::Unsegmented] and the data
    /// length to 0.
    ///
    /// This constructor will panic if the APID exceeds [MAX_APID].
    #[inline]
    pub const fn new_from_apid(apid: u16) -> Self {
        SpHeader {
            version: 0,
            packet_id: PacketId::new(PacketType::Tm, false, apid),
            psc: PacketSequenceCtrl {
                seq_flags: SequenceFlags::Unsegmented,
                seq_count: 0,
            },
            data_len: 0,
        }
    }

    /// Checked variant of [Self::new_from_apid].
    #[inline]
    pub fn new_from_apid_checked(apid: u16) -> Option<Self> {
        Some(SpHeader {
            version: 0,
            packet_id: PacketId::new_checked(PacketType::Tm, false, apid)?,
            psc: PacketSequenceCtrl {
                seq_flags: SequenceFlags::Unsegmented,
                seq_count: 0,
            },
            data_len: 0,
        })
    }

    /// This constructor panics if the passed APID exceeds [MAX_APID] or the passed packet sequence
    /// count exceeds [MAX_SEQ_COUNT].
    ///
    /// The checked constructor variants can be used to avoid panics.
    #[inline]
    pub const fn new_from_fields(
        ptype: PacketType,
        sec_header: bool,
        apid: u16,
        seq_flags: SequenceFlags,
        seq_count: u16,
        data_len: u16,
    ) -> Self {
        if seq_count > MAX_SEQ_COUNT {
            panic!("Sequence count is too large");
        }
        if apid > MAX_APID {
            panic!("APID is too large");
        }
        Self {
            psc: PacketSequenceCtrl::new(seq_flags, seq_count),
            packet_id: PacketId::new(ptype, sec_header, apid),
            data_len,
            version: 0,
        }
    }

    /// Create a new Space Packet Header instance which can be used to create generic
    /// Space Packets.
    ///
    /// This will return [None] if the APID or sequence count argument
    /// exceed [MAX_APID] or [MAX_SEQ_COUNT] respectively. The version field is set to 0b000.
    #[inline]
    pub fn new_from_fields_checked(
        ptype: PacketType,
        sec_header: bool,
        apid: u16,
        seq_flags: SequenceFlags,
        seq_count: u16,
        data_len: u16,
    ) -> Option<Self> {
        if seq_count > MAX_SEQ_COUNT || apid > MAX_APID {
            return None;
        }
        Some(SpHeader::new_from_fields(
            ptype, sec_header, apid, seq_flags, seq_count, data_len,
        ))
    }

    /// Helper function for telemetry space packet headers. The packet type field will be
    /// set accordingly. The secondary header flag field is set to false.
    #[inline]
    pub fn new_for_tm_checked(
        apid: u16,
        seq_flags: SequenceFlags,
        seq_count: u16,
        data_len: u16,
    ) -> Option<Self> {
        Self::new_from_fields_checked(PacketType::Tm, false, apid, seq_flags, seq_count, data_len)
    }

    /// Helper function for telemetry space packet headers. The packet type field will be
    /// set accordingly. The secondary header flag field is set to false.
    #[inline]
    pub fn new_for_tc_checked(
        apid: u16,
        seq_flags: SequenceFlags,
        seq_count: u16,
        data_len: u16,
    ) -> Option<Self> {
        Self::new_from_fields_checked(PacketType::Tc, false, apid, seq_flags, seq_count, data_len)
    }

    /// This is an unchecked constructor which can panic on invalid input.
    #[inline]
    pub const fn new_for_tm(
        apid: u16,
        seq_flags: SequenceFlags,
        seq_count: u16,
        data_len: u16,
    ) -> Self {
        Self::new_from_fields(PacketType::Tm, false, apid, seq_flags, seq_count, data_len)
    }

    /// This is an unchecked constructor which can panic on invalid input.
    #[inline]
    pub const fn new_for_tc(
        apid: u16,
        seq_flags: SequenceFlags,
        seq_count: u16,
        data_len: u16,
    ) -> Self {
        Self::new_from_fields(PacketType::Tc, false, apid, seq_flags, seq_count, data_len)
    }

    /// Variant of [SpHeader::new_for_tm_checked] which sets the sequence flag field to [SequenceFlags::Unsegmented]
    #[inline]
    pub fn new_for_unseg_tm_checked(apid: u16, seq_count: u16, data_len: u16) -> Option<Self> {
        Self::new_for_tm_checked(apid, SequenceFlags::Unsegmented, seq_count, data_len)
    }

    /// Variant of [SpHeader::new_for_tc_checked] which sets the sequence flag field to [SequenceFlags::Unsegmented]
    #[inline]
    pub fn new_for_unseg_tc_checked(apid: u16, seq_count: u16, data_len: u16) -> Option<Self> {
        Self::new_for_tc_checked(apid, SequenceFlags::Unsegmented, seq_count, data_len)
    }

    /// Variant of [SpHeader::new_for_tc] which sets the sequence flag field to [SequenceFlags::Unsegmented].
    ///
    /// This is an unchecked constructor which can panic on invalid input.
    #[inline]
    pub const fn new_for_unseg_tc(apid: u16, seq_count: u16, data_len: u16) -> Self {
        Self::new_for_tc(apid, SequenceFlags::Unsegmented, seq_count, data_len)
    }

    /// Variant of [SpHeader::new_for_tm] which sets the sequence flag field to [SequenceFlags::Unsegmented].
    ///
    /// This is an unchecked constructor which can panic on invalid input.
    #[inline]
    pub const fn new_for_unseg_tm(apid: u16, seq_count: u16, data_len: u16) -> Self {
        Self::new_for_tm(apid, SequenceFlags::Unsegmented, seq_count, data_len)
    }

    delegate! {
        to self.packet_id {
            /// Returns [false] and fails if the APID exceeds [MAX_APID]
            #[inline]
            pub fn set_apid(&mut self, apid: u16) -> bool;
        }
    }

    delegate! {
        to self.psc {
            /// Returns [false] and fails if the sequence count exceeds [MAX_SEQ_COUNT]
            #[inline]
            pub fn set_seq_count(&mut self, seq_count: u16) -> bool;
        }
    }

    #[inline]
    pub fn set_seq_flags(&mut self, seq_flags: SequenceFlags) {
        self.psc.seq_flags = seq_flags;
    }

    #[inline]
    pub fn set_sec_header_flag(&mut self) {
        self.packet_id.sec_header_flag = true;
    }

    #[inline]
    pub fn clear_sec_header_flag(&mut self) {
        self.packet_id.sec_header_flag = false;
    }

    #[inline]
    pub fn set_packet_type(&mut self, packet_type: PacketType) {
        self.packet_id.ptype = packet_type;
    }

    /// Create a struct from a raw slice where the fields have network endianness (big).
    /// This function also returns the remaining part of the passed slice starting past the read
    /// CCSDS header.
    pub fn from_be_bytes(buf: &[u8]) -> Result<(Self, &[u8]), ByteConversionError> {
        if buf.len() < CCSDS_HEADER_LEN {
            return Err(ByteConversionError::FromSliceTooSmall {
                found: buf.len(),
                expected: CCSDS_HEADER_LEN,
            });
        }
        let zc_header = zc::SpHeader::read_from_bytes(&buf[0..CCSDS_HEADER_LEN])
            .map_err(|_| ByteConversionError::ZeroCopyFromError)?;
        Ok((Self::from(zc_header), &buf[CCSDS_HEADER_LEN..]))
    }

    /// Write the header to a raw buffer using big endian format. This function returns the
    /// remaining part of the passed slice starting past the written CCSDS header.
    pub fn write_to_be_bytes<'a>(
        &self,
        buf: &'a mut [u8],
    ) -> Result<&'a mut [u8], ByteConversionError> {
        if buf.len() < CCSDS_HEADER_LEN {
            return Err(ByteConversionError::FromSliceTooSmall {
                found: buf.len(),
                expected: CCSDS_HEADER_LEN,
            });
        }
        let zc_header: zc::SpHeader = zc::SpHeader::from(*self);
        zc_header
            .write_to(&mut buf[0..CCSDS_HEADER_LEN])
            .map_err(|_| ByteConversionError::ZeroCopyToError)?;
        Ok(&mut buf[CCSDS_HEADER_LEN..])
    }

    /// Create a vector containing the CCSDS header.
    #[cfg(feature = "alloc")]
    pub fn to_vec(&self) -> alloc::vec::Vec<u8> {
        let mut vec = alloc::vec![0; CCSDS_HEADER_LEN];
        // This can not fail.
        self.write_to_be_bytes(&mut vec[..]).unwrap();
        vec
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
    #[inline]
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

pub mod zc {
    use crate::{CcsdsPacket, CcsdsPrimaryHeader, PacketId, PacketSequenceCtrl, VERSION_MASK};
    use zerocopy::byteorder::NetworkEndian;
    use zerocopy::{FromBytes, Immutable, IntoBytes, Unaligned, U16};

    #[derive(FromBytes, IntoBytes, Immutable, Unaligned, Debug)]
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
    }

    impl CcsdsPacket for SpHeader {
        #[inline]
        fn ccsds_version(&self) -> u8 {
            ((self.version_packet_id.get() >> 13) as u8) & 0b111
        }

        #[inline]
        fn packet_id(&self) -> PacketId {
            PacketId::from(self.packet_id_raw())
        }

        #[inline]
        fn psc(&self) -> PacketSequenceCtrl {
            PacketSequenceCtrl::from(self.psc_raw())
        }

        #[inline]
        fn data_len(&self) -> u16 {
            self.data_len.get()
        }

        #[inline]
        fn packet_id_raw(&self) -> u16 {
            self.version_packet_id.get() & (!VERSION_MASK)
        }

        #[inline]
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

    sph_from_other!(SpHeader, crate::SpHeader);
}

#[cfg(all(test, feature = "std"))]
pub(crate) mod tests {
    use std::collections::HashSet;

    #[allow(unused_imports)]
    use crate::ByteConversionError;
    #[cfg(feature = "serde")]
    use crate::CcsdsPrimaryHeader;
    use crate::{
        packet_type_in_raw_packet_id, zc, CcsdsPacket, PacketId, PacketSequenceCtrl, PacketType,
    };
    use crate::{SequenceFlags, SpHeader};
    use alloc::vec;
    #[cfg(feature = "serde")]
    use core::fmt::Debug;
    use num_traits::pow;
    #[cfg(feature = "serde")]
    use postcard::{from_bytes, to_allocvec};
    #[cfg(feature = "serde")]
    use serde::{de::DeserializeOwned, Serialize};
    use zerocopy::FromBytes;

    const CONST_SP: SpHeader = SpHeader::new(
        PacketId::new_for_tc(true, 0x36),
        PacketSequenceCtrl::new(SequenceFlags::ContinuationSegment, 0x88),
        0x90,
    );

    const PACKET_ID_TM: PacketId = PacketId::new_for_tm(true, 0x22);

    #[cfg(feature = "serde")]
    pub(crate) fn generic_serde_test<T: Serialize + DeserializeOwned + PartialEq + Debug>(
        value: T,
    ) {
        let output: alloc::vec::Vec<u8> = to_allocvec(&value).unwrap();
        let output_converted_back: T = from_bytes(&output).unwrap();
        assert_eq!(output_converted_back, value);
    }

    #[test]
    #[allow(clippy::assertions_on_constants)]
    fn verify_const_packet_id() {
        assert_eq!(PACKET_ID_TM.apid(), 0x22);
        assert!(PACKET_ID_TM.sec_header_flag);
        assert_eq!(PACKET_ID_TM.ptype, PacketType::Tm);
        let const_tc_id = PacketId::new_for_tc(true, 0x23);
        assert_eq!(const_tc_id.ptype, PacketType::Tc);
    }

    #[test]
    fn test_default_packet_id() {
        let id_default = PacketId::default();
        assert_eq!(id_default.ptype, PacketType::Tm);
        assert_eq!(id_default.apid, 0x000);
        assert!(!id_default.sec_header_flag);
    }

    #[test]
    fn test_packet_id_ctors() {
        let packet_id = PacketId::new_checked(PacketType::Tc, true, 0x1ff);
        assert!(packet_id.is_some());
        let packet_id = packet_id.unwrap();
        assert_eq!(packet_id.apid(), 0x1ff);
        assert_eq!(packet_id.ptype, PacketType::Tc);
        assert!(packet_id.sec_header_flag);
        let packet_id_tc = PacketId::new_for_tc_checked(true, 0x1ff);
        assert!(packet_id_tc.is_some());
        let packet_id_tc = packet_id_tc.unwrap();
        assert_eq!(packet_id_tc, packet_id);
        let packet_id_tm = PacketId::new_for_tm_checked(true, 0x2ff);
        assert!(packet_id_tm.is_some());
        let packet_id_tm = packet_id_tm.unwrap();
        assert!(packet_id_tm.sec_header_flag);
        assert_eq!(packet_id_tm.ptype, PacketType::Tm);
        assert_eq!(packet_id_tm.apid, 0x2ff);
    }

    #[test]
    fn verify_const_sp_header() {
        assert!(CONST_SP.sec_header_flag());
        assert_eq!(CONST_SP.apid(), 0x36);
        assert_eq!(
            CONST_SP.sequence_flags(),
            SequenceFlags::ContinuationSegment
        );
        assert_eq!(CONST_SP.seq_count(), 0x88);
        assert_eq!(CONST_SP.data_len, 0x90);
    }

    #[test]
    fn test_seq_flag_helpers() {
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
    }

    #[test]
    fn test_packet_type_helper() {
        assert_eq!(PacketType::try_from(0b00).unwrap(), PacketType::Tm);
        assert_eq!(PacketType::try_from(0b01).unwrap(), PacketType::Tc);
        assert!(PacketType::try_from(0b10).is_err());
    }

    #[test]
    fn test_packet_id() {
        let packet_id =
            PacketId::new_checked(PacketType::Tm, false, 0x42).expect("Packet ID creation failed");
        assert_eq!(packet_id.raw(), 0x0042);
        let packet_id_from_raw = PacketId::from(packet_id.raw());
        assert_eq!(
            packet_type_in_raw_packet_id(packet_id.raw()),
            PacketType::Tm
        );
        assert_eq!(packet_id_from_raw, packet_id);
        let packet_id_from_new = PacketId::new_checked(PacketType::Tm, false, 0x42).unwrap();
        assert_eq!(packet_id_from_new, packet_id);
    }

    #[test]
    fn test_invalid_packet_id() {
        let packet_id_invalid = PacketId::new_checked(PacketType::Tc, true, 0xFFFF);
        assert!(packet_id_invalid.is_none());
    }

    #[test]
    fn test_invalid_apid_setter() {
        let mut packet_id =
            PacketId::new_checked(PacketType::Tm, false, 0x42).expect("Packet ID creation failed");
        assert!(!packet_id.set_apid(0xffff));
    }

    #[test]
    fn test_invalid_seq_count() {
        let mut psc = PacketSequenceCtrl::new_checked(SequenceFlags::ContinuationSegment, 77)
            .expect("PSC creation failed");
        assert_eq!(psc.seq_count(), 77);
        assert!(!psc.set_seq_count(0xffff));
    }

    #[test]
    fn test_packet_seq_ctrl() {
        let mut psc = PacketSequenceCtrl::new_checked(SequenceFlags::ContinuationSegment, 77)
            .expect("PSC creation failed");
        assert_eq!(psc.raw(), 77);
        let psc_from_raw = PacketSequenceCtrl::from(psc.raw());
        assert_eq!(psc_from_raw, psc);
        // Fails because SSC is limited to 14 bits
        assert!(!psc.set_seq_count(2u16.pow(15)));
        assert_eq!(psc.raw(), 77);

        let psc_invalid = PacketSequenceCtrl::new_checked(SequenceFlags::FirstSegment, 0xFFFF);
        assert!(psc_invalid.is_none());
        let psc_from_new =
            PacketSequenceCtrl::new_checked(SequenceFlags::ContinuationSegment, 77).unwrap();
        assert_eq!(psc_from_new, psc);
    }

    #[test]
    #[cfg(feature = "serde")]
    fn test_serde_sph() {
        let sp_header =
            SpHeader::new_for_unseg_tc_checked(0x42, 12, 0).expect("Error creating SP header");
        assert_eq!(sp_header.ccsds_version(), 0b000);
        assert!(sp_header.is_tc());
        assert!(!sp_header.sec_header_flag());
        assert_eq!(sp_header.ptype(), PacketType::Tc);
        assert_eq!(sp_header.seq_count(), 12);
        assert_eq!(sp_header.apid(), 0x42);
        assert_eq!(sp_header.sequence_flags(), SequenceFlags::Unsegmented);
        assert_eq!(sp_header.data_len(), 0);
        let output = to_allocvec(&sp_header).unwrap();
        let sp_header: SpHeader = from_bytes(&output).unwrap();
        assert_eq!(sp_header.version, 0b000);
        assert!(!sp_header.packet_id.sec_header_flag);
        assert_eq!(sp_header.ptype(), PacketType::Tc);
        assert_eq!(sp_header.seq_count(), 12);
        assert_eq!(sp_header.apid(), 0x42);
        assert_eq!(sp_header.sequence_flags(), SequenceFlags::Unsegmented);
        assert_eq!(sp_header.packet_id_raw(), 0x1042);
        assert_eq!(sp_header.psc_raw(), 0xC00C);
        assert_eq!(sp_header.ccsds_version(), 0b000);
        assert_eq!(sp_header.data_len, 0);

        let sp_header =
            SpHeader::new_for_unseg_tm_checked(0x7, 22, 36).expect("Error creating SP header");
        assert_eq!(sp_header.ccsds_version(), 0b000);
        assert!(sp_header.is_tm());
        assert!(!sp_header.sec_header_flag());
        assert_eq!(sp_header.ptype(), PacketType::Tm);
        assert_eq!(sp_header.seq_count(), 22);
        assert_eq!(sp_header.apid(), 0x07);
        assert_eq!(sp_header.sequence_flags(), SequenceFlags::Unsegmented);
        assert_eq!(sp_header.packet_id_raw(), 0x0007);
        assert_eq!(sp_header.psc_raw(), 0xC016);
        assert_eq!(sp_header.data_len(), 36);
        assert_eq!(sp_header.ccsds_version(), 0b000);

        let from_comp_fields = SpHeader::from_composite_fields(
            PacketId::new(PacketType::Tc, true, 0x42),
            PacketSequenceCtrl::new(SequenceFlags::Unsegmented, 0x7),
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
        assert_eq!(from_comp_fields.seq_count(), 0x7);
        assert_eq!(from_comp_fields.data_len(), 0);
    }

    #[test]
    fn test_setters() {
        let sp_header = SpHeader::new_for_tc_checked(0x42, SequenceFlags::Unsegmented, 25, 0);
        assert!(sp_header.is_some());
        let mut sp_header = sp_header.unwrap();
        sp_header.set_apid(0x12);
        assert_eq!(sp_header.apid(), 0x12);
        sp_header.set_sec_header_flag();
        assert!(sp_header.sec_header_flag());
        sp_header.clear_sec_header_flag();
        assert!(!sp_header.sec_header_flag());
        assert_eq!(sp_header.ptype(), PacketType::Tc);
        sp_header.set_packet_type(PacketType::Tm);
        assert_eq!(sp_header.ptype(), PacketType::Tm);
        sp_header.set_seq_count(0x45);
        assert_eq!(sp_header.seq_count(), 0x45);
    }

    #[test]
    fn test_tc_ctor() {
        let sp_header = SpHeader::new_for_tc_checked(0x42, SequenceFlags::Unsegmented, 25, 0);
        assert!(sp_header.is_some());
        let sp_header = sp_header.unwrap();
        verify_sp_fields(PacketType::Tc, &sp_header);
    }

    #[test]
    fn test_tc_ctor_unseg() {
        let sp_header = SpHeader::new_for_unseg_tc_checked(0x42, 25, 0);
        assert!(sp_header.is_some());
        let sp_header = sp_header.unwrap();
        verify_sp_fields(PacketType::Tc, &sp_header);
    }

    #[test]
    fn test_tc_ctor_unseg_const() {
        let sp_header = SpHeader::new_for_unseg_tc(0x42, 25, 0);
        verify_sp_fields(PacketType::Tc, &sp_header);
    }

    #[test]
    fn test_tm_ctor() {
        let sp_header = SpHeader::new_for_tm_checked(0x42, SequenceFlags::Unsegmented, 25, 0);
        assert!(sp_header.is_some());
        let sp_header = sp_header.unwrap();
        verify_sp_fields(PacketType::Tm, &sp_header);
    }

    #[test]
    fn test_tm_ctor_const() {
        let sp_header = SpHeader::new_for_tm(0x42, SequenceFlags::Unsegmented, 25, 0);
        verify_sp_fields(PacketType::Tm, &sp_header);
    }

    #[test]
    fn test_tm_ctor_unseg() {
        let sp_header = SpHeader::new_for_unseg_tm_checked(0x42, 25, 0);
        assert!(sp_header.is_some());
        let sp_header = sp_header.unwrap();
        verify_sp_fields(PacketType::Tm, &sp_header);
    }

    fn verify_sp_fields(ptype: PacketType, sp_header: &SpHeader) {
        assert_eq!(sp_header.ptype(), ptype);
        assert_eq!(sp_header.sequence_flags(), SequenceFlags::Unsegmented);
        assert_eq!(sp_header.apid(), 0x42);
        assert_eq!(sp_header.seq_count(), 25);
        assert_eq!(sp_header.data_len(), 0);
    }

    #[test]
    fn test_zc_sph() {
        use zerocopy::IntoBytes;

        let sp_header = SpHeader::new_for_unseg_tc_checked(0x7FF, pow(2, 14) - 1, 0)
            .expect("Error creating SP header");
        assert_eq!(sp_header.ptype(), PacketType::Tc);
        assert_eq!(sp_header.apid(), 0x7FF);
        assert_eq!(sp_header.data_len(), 0);
        assert_eq!(sp_header.ccsds_version(), 0b000);
        assert!(sp_header.is_tc());
        let sp_header_zc = zc::SpHeader::from(sp_header);
        let slice = sp_header_zc.as_bytes();
        assert_eq!(slice.len(), 6);
        assert_eq!(slice[0], 0x17);
        assert_eq!(slice[1], 0xFF);
        assert_eq!(slice[2], 0xFF);
        assert_eq!(slice[3], 0xFF);
        assert_eq!(slice[4], 0x00);
        assert_eq!(slice[5], 0x00);

        let mut slice = [0; 6];
        sp_header_zc.write_to(slice.as_mut_slice()).unwrap();
        assert_eq!(slice.len(), 6);
        assert_eq!(slice[0], 0x17);
        assert_eq!(slice[1], 0xFF);
        assert_eq!(slice[2], 0xFF);
        assert_eq!(slice[3], 0xFF);
        assert_eq!(slice[4], 0x00);
        assert_eq!(slice[5], 0x00);

        let mut test_vec = vec![0_u8; 6];
        let slice = test_vec.as_mut_slice();
        sp_header_zc.write_to(slice).unwrap();
        let slice = test_vec.as_slice();
        assert_eq!(slice.len(), 6);
        assert_eq!(slice[0], 0x17);
        assert_eq!(slice[1], 0xFF);
        assert_eq!(slice[2], 0xFF);
        assert_eq!(slice[3], 0xFF);
        assert_eq!(slice[4], 0x00);
        assert_eq!(slice[5], 0x00);

        let sp_header = zc::SpHeader::read_from_bytes(slice);
        assert!(sp_header.is_ok());
        let sp_header = sp_header.unwrap();
        assert_eq!(sp_header.ccsds_version(), 0b000);
        assert_eq!(sp_header.packet_id_raw(), 0x17FF);
        assert_eq!(sp_header.apid(), 0x7FF);
        assert_eq!(sp_header.ptype(), PacketType::Tc);
        assert_eq!(sp_header.data_len(), 0);
    }

    #[test]
    fn packet_id_ord_partial_ord() {
        let packet_id_small = PacketId::from(1_u16);
        let packet_id_larger = PacketId::from(2_u16);
        assert!(packet_id_small < packet_id_larger);
        assert!(packet_id_larger > packet_id_small);
        assert_eq!(
            packet_id_small.cmp(&packet_id_larger),
            core::cmp::Ordering::Less
        );
    }

    #[test]
    fn packet_id_hashable() {
        let mut id_set = HashSet::new();
        id_set.insert(PacketId::from(1_u16));
    }

    #[test]
    fn sp_header_from_apid() {
        let sp_header = SpHeader::new_from_apid(0x03);
        assert_eq!(sp_header.apid(), 0x03);
        assert_eq!(sp_header.data_len(), 0);
    }

    #[test]
    fn sp_header_from_apid_checked() {
        let sp_header = SpHeader::new_from_apid_checked(0x03).unwrap();
        assert_eq!(sp_header.apid(), 0x03);
        assert_eq!(sp_header.data_len(), 0);
    }

    #[cfg(feature = "defmt")]
    fn is_defmt_format<T: defmt::Format>(_t: T) {}

    #[test]
    #[cfg(feature = "defmt")]
    fn test_defmt_format() {
        is_defmt_format(ByteConversionError::ToSliceTooSmall {
            found: 1,
            expected: 2,
        });
    }

    #[test]
    fn test_sp_header_as_vec() {
        let sp_header = SpHeader::new_for_unseg_tc(0x42, 25, 1);
        let sp_header_as_vec = sp_header.to_vec();
        let sp_header_read_back = SpHeader::from_be_bytes(&sp_header_as_vec)
            .expect("Error reading back SP header")
            .0;
        assert_eq!(sp_header, sp_header_read_back);
    }
}
