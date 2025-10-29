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
//!  - [`portable-atomic`]: Basic support for `portable-atomic` crate in addition to the support
//!    for core atomic types. This support requires atomic CAS support enabled in the portable
//!    atomic crate.
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
//! use arbitrary_int::{u11, u14};
//!
//! let sp_header = SpHeader::new_for_unseg_tc(u11::new(0x42), u14::new(12), 1);
//! println!("{:?}", sp_header);
//! let mut ccsds_buf: [u8; 32] = [0; 32];
//! sp_header.write_to_be_bytes(&mut ccsds_buf).expect("Writing CCSDS TC header failed");
//! println!("{:x?}", &ccsds_buf[0..6]);
//! ```
#![no_std]
#![cfg_attr(docsrs, feature(doc_cfg))]
#[cfg(feature = "alloc")]
extern crate alloc;
#[cfg(any(feature = "std", test))]
extern crate std;

use arbitrary_int::{prelude::*, u11, u14};
use core::{fmt::Debug, hash::Hash};
use delegate::delegate;
use zerocopy::{FromBytes, IntoBytes};

#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

use crate::crc::CRC_CCITT_FALSE;

pub mod cfdp;
pub mod crc;
pub mod ecss;
pub mod seq_count;
pub mod time;
pub mod uslp;
pub mod util;

mod private {
    pub trait Sealed {}
}

/// Length of the CCSDS header.
pub const CCSDS_HEADER_LEN: usize = core::mem::size_of::<crate::zc::SpHeader>();

/// Maximum allowed value for the 11-bit APID.
pub const MAX_APID: u11 = u11::MAX;
/// Maximum allowed value for the 14-bit APID.
pub const MAX_SEQ_COUNT: u14 = u14::MAX;

/// Checksum types currently provided by the CCSDS packet support.
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[non_exhaustive]
pub enum ChecksumType {
    Crc16CcittFalse,
}

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
}

#[derive(Debug, Copy, Clone, PartialEq, Eq, thiserror::Error)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum ZeroCopyError {
    /// The [zerocopy] library failed to write to bytes
    #[error("zerocopy serialization error")]
    ZeroCopyToError,
    /// The [zerocopy] library failed to read from bytes
    #[error("zerocopy deserialization error")]
    ZeroCopyFromError,
}

/// Invalid payload length which is bounded by [u16::MAX]
#[derive(thiserror::Error, Debug)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[error("invalid payload length: {0}")]
pub struct InvalidPayloadLengthError(usize);

#[derive(thiserror::Error, Debug)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub enum CcsdsPacketCreationError {
    #[error("byte conversion: {0}")]
    ByteConversion(#[from] ByteConversionError),
    #[error("invalid payload length: {0}")]
    InvalidPayloadLength(#[from] InvalidPayloadLengthError),
}

/// CCSDS packet type enumeration.
#[derive(Debug, PartialEq, Eq, num_enum::TryFromPrimitive)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
#[bitbybit::bitenum(u1, exhaustive = true)]
#[repr(u8)]
pub enum PacketType {
    Tm = 0,
    Tc = 1,
}

#[derive(Debug, PartialEq, Eq, num_enum::TryFromPrimitive)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
#[bitbybit::bitenum(u2, exhaustive = true)]
#[repr(u8)]
pub enum SequenceFlags {
    ContinuationSegment = 0b00,
    FirstSegment = 0b01,
    LastSegment = 0b10,
    Unsegmented = 0b11,
}

#[inline]
pub fn packet_type_in_raw_packet_id(packet_id: u16) -> PacketType {
    PacketType::try_from((packet_id >> 12) as u8 & 0b1).unwrap()
}

/// Calculate the full CCSDS packet length for a given user data length and optional checksum type.
///
/// Returns [None] if the calculated length allowed by the CCSDS data length field.
#[inline]
pub const fn ccsds_packet_len_for_user_data_len(
    data_len: usize,
    checksum: Option<ChecksumType>,
) -> Option<usize> {
    // Special case: A value of zero is not allowed for the data length field.
    if data_len == 0 {
        return Some(7);
    }
    let checksum_len = match checksum {
        Some(ChecksumType::Crc16CcittFalse) => 2,
        None => 0,
    };
    let len = data_len
        .saturating_add(CCSDS_HEADER_LEN)
        .saturating_add(checksum_len);
    if len - CCSDS_HEADER_LEN - 1 > u16::MAX as usize {
        return None;
    }
    Some(len)
}

#[inline]
pub fn ccsds_packet_len_for_user_data_len_with_checksum(data_len: usize) -> Option<usize> {
    ccsds_packet_len_for_user_data_len(data_len, Some(ChecksumType::Crc16CcittFalse))
}

/// Abstraction for the CCSDS Packet ID, which forms the last thirteen bits
/// of the first two bytes in the CCSDS primary header.
#[derive(Debug, Eq, Copy, Clone)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct PacketId {
    pub packet_type: PacketType,
    pub sec_header_flag: bool,
    pub apid: u11,
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
            packet_type: PacketType::Tm,
            sec_header_flag: false,
            apid: u11::new(0),
        }
    }
}

impl PacketId {
    #[inline]
    pub const fn new_for_tc(sec_header: bool, apid: u11) -> Self {
        Self::new(PacketType::Tc, sec_header, apid)
    }

    #[inline]
    pub const fn new_for_tm(sec_header: bool, apid: u11) -> Self {
        Self::new(PacketType::Tm, sec_header, apid)
    }

    #[inline]
    pub const fn new(packet_type: PacketType, sec_header_flag: bool, apid: u11) -> Self {
        PacketId {
            packet_type,
            sec_header_flag,
            apid,
        }
    }

    /// Set a new Application Process ID (APID). If the passed number is invalid, the APID will
    /// not be set and false will be returned. The maximum allowed value for the 11-bit field is
    /// 2047
    #[inline]
    pub fn set_apid(&mut self, apid: u11) {
        self.apid = apid;
    }

    /// 11-bit CCSDS Application Process ID (APID) field.
    #[inline]
    pub const fn apid(&self) -> u11 {
        self.apid
    }

    #[inline]
    pub const fn raw(&self) -> u16 {
        ((self.packet_type as u16) << 12)
            | ((self.sec_header_flag as u16) << 11)
            | self.apid.value()
    }
}

impl From<u16> for PacketId {
    fn from(raw_id: u16) -> Self {
        PacketId {
            packet_type: PacketType::try_from(((raw_id >> 12) & 0b1) as u8).unwrap(),
            sec_header_flag: ((raw_id >> 11) & 0b1) != 0,
            apid: u11::new(raw_id & 0x7FF),
        }
    }
}

#[deprecated(since = "0.16.0", note = "use PacketSequenceControl instead")]
pub type PacketSequenceCtrl = PacketSequenceControl;

/// Abstraction for the CCSDS Packet Sequence Control (PSC) field which is the
/// third and the fourth byte in the CCSDS primary header.
#[derive(Debug, PartialEq, Eq, Copy, Clone)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct PacketSequenceControl {
    pub seq_flags: SequenceFlags,
    pub seq_count: u14,
}

impl PacketSequenceControl {
    #[inline]
    pub const fn new(seq_flags: SequenceFlags, seq_count: u14) -> PacketSequenceControl {
        PacketSequenceControl {
            seq_flags,
            seq_count,
        }
    }

    #[inline]
    pub const fn raw(&self) -> u16 {
        ((self.seq_flags as u16) << 14) | self.seq_count.value()
    }
}

impl From<u16> for PacketSequenceControl {
    fn from(raw_id: u16) -> Self {
        PacketSequenceControl {
            seq_flags: SequenceFlags::try_from(((raw_id >> 14) & 0b11) as u8).unwrap(),
            seq_count: u14::new(raw_id & SSC_MASK),
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
    fn ccsds_version(&self) -> u3;
    fn packet_id(&self) -> PacketId;
    fn psc(&self) -> PacketSequenceControl;

    /// Retrieve data length field
    fn data_len(&self) -> u16;

    /// Retrieve the total packet size based on the data length field
    #[inline]
    fn packet_len(&self) -> usize {
        usize::from(self.data_len()) + CCSDS_HEADER_LEN + 1
    }

    #[deprecated(since = "0.16.0", note = "use packet_len instead")]
    #[inline]
    fn total_len(&self) -> usize {
        self.packet_len()
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

    #[inline]
    fn packet_type(&self) -> PacketType {
        // This call should never fail because only 0 and 1 can be passed to the try_from call
        self.packet_id().packet_type
    }

    #[inline]
    fn is_tm(&self) -> bool {
        self.packet_type() == PacketType::Tm
    }

    #[inline]
    fn is_tc(&self) -> bool {
        self.packet_type() == PacketType::Tc
    }

    /// Retrieve the secondary header flag. Returns true if a secondary header is present
    /// and false if it is not.
    #[inline]
    fn sec_header_flag(&self) -> bool {
        self.packet_id().sec_header_flag
    }

    /// Retrieve Application Process ID.
    #[inline]
    fn apid(&self) -> u11 {
        self.packet_id().apid
    }

    #[inline]
    fn seq_count(&self) -> u14 {
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
        psc: PacketSequenceControl,
        data_len: u16,
        version: Option<u3>,
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
pub struct SpacePacketHeader {
    pub version: u3,
    pub packet_id: PacketId,
    pub psc: PacketSequenceControl,
    pub data_len: u16,
}

pub type SpHeader = SpacePacketHeader;

impl Default for SpacePacketHeader {
    /// The default function sets the sequence flag field to [SequenceFlags::Unsegmented] and the
    /// data length to 0.
    #[inline]
    fn default() -> Self {
        SpHeader {
            version: u3::new(0),
            packet_id: PacketId::default(),
            psc: PacketSequenceControl {
                seq_flags: SequenceFlags::Unsegmented,
                seq_count: u14::new(0),
            },
            data_len: 0,
        }
    }
}

impl SpacePacketHeader {
    pub const LENGTH: usize = CCSDS_HEADER_LEN;

    #[inline]
    pub const fn new(packet_id: PacketId, psc: PacketSequenceControl, data_len: u16) -> Self {
        Self {
            version: u3::new(0),
            packet_id,
            psc,
            data_len,
        }
    }

    /// This constructor sets the sequence flag field to [SequenceFlags::Unsegmented] and the data
    /// length to 0.
    #[inline]
    pub const fn new_from_apid(apid: u11) -> Self {
        Self {
            version: u3::new(0b000),
            packet_id: PacketId::new(PacketType::Tm, false, apid),
            psc: PacketSequenceControl {
                seq_flags: SequenceFlags::Unsegmented,
                seq_count: u14::new(0),
            },
            data_len: 0,
        }
    }

    #[inline]
    pub const fn new_from_fields(
        ptype: PacketType,
        sec_header: bool,
        apid: u11,
        seq_flags: SequenceFlags,
        seq_count: u14,
        data_len: u16,
    ) -> Self {
        Self {
            psc: PacketSequenceControl::new(seq_flags, seq_count),
            packet_id: PacketId::new(ptype, sec_header, apid),
            data_len,
            version: u3::new(0b000),
        }
    }

    #[inline]
    pub const fn new_for_tm(
        apid: u11,
        seq_flags: SequenceFlags,
        seq_count: u14,
        data_len: u16,
    ) -> Self {
        Self::new_from_fields(PacketType::Tm, false, apid, seq_flags, seq_count, data_len)
    }

    #[inline]
    pub const fn new_for_tc(
        apid: u11,
        seq_flags: SequenceFlags,
        seq_count: u14,
        data_len: u16,
    ) -> Self {
        Self::new_from_fields(PacketType::Tc, false, apid, seq_flags, seq_count, data_len)
    }

    /// Variant of [SpHeader::new_for_tc] which sets the sequence flag field to [SequenceFlags::Unsegmented].
    #[inline]
    pub const fn new_for_unseg_tc(apid: u11, seq_count: u14, data_len: u16) -> Self {
        Self::new_for_tc(apid, SequenceFlags::Unsegmented, seq_count, data_len)
    }

    /// Variant of [SpHeader::new_for_tm] which sets the sequence flag field to [SequenceFlags::Unsegmented].
    #[inline]
    pub const fn new_for_unseg_tm(apid: u11, seq_count: u14, data_len: u16) -> Self {
        Self::new_for_tm(apid, SequenceFlags::Unsegmented, seq_count, data_len)
    }

    delegate! {
        to self.packet_id {
            #[inline]
            pub fn set_apid(&mut self, apid: u11);
        }
    }

    /// Retrieve the total packet size based on the data length field
    #[inline]
    pub fn packet_len(&self) -> usize {
        usize::from(self.data_len()) + Self::LENGTH + 1
    }

    #[inline]
    pub fn set_seq_count(&mut self, seq_count: u14) {
        self.psc.seq_count = seq_count;
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
        self.packet_id.packet_type = packet_type;
    }

    /// Create a struct from a raw slice where the fields have network endianness (big).
    /// This function also returns the remaining part of the passed slice starting past the read
    /// CCSDS header.
    pub fn from_be_bytes(buf: &[u8]) -> Result<(Self, &[u8]), ByteConversionError> {
        if buf.len() < Self::LENGTH {
            return Err(ByteConversionError::FromSliceTooSmall {
                found: buf.len(),
                expected: CCSDS_HEADER_LEN,
            });
        }
        // Unwrap okay, this can not fail.
        let zc_header = zc::SpHeader::read_from_bytes(&buf[0..Self::LENGTH]).unwrap();
        Ok((Self::from(zc_header), &buf[Self::LENGTH..]))
    }

    /// Write the header to a raw buffer using big endian format. This function returns the
    /// remaining part of the passed slice starting past the written CCSDS header.
    pub fn write_to_be_bytes<'a>(
        &self,
        buf: &'a mut [u8],
    ) -> Result<&'a mut [u8], ByteConversionError> {
        if buf.len() < Self::LENGTH {
            return Err(ByteConversionError::ToSliceTooSmall {
                found: buf.len(),
                expected: CCSDS_HEADER_LEN,
            });
        }
        let zc_header: zc::SpHeader = zc::SpHeader::from(*self);
        // Unwrap okay, this can not fail.
        zc_header.write_to(&mut buf[0..Self::LENGTH]).unwrap();
        Ok(&mut buf[Self::LENGTH..])
    }

    /// Create a vector containing the CCSDS header.
    #[cfg(feature = "alloc")]
    pub fn to_vec(&self) -> alloc::vec::Vec<u8> {
        let mut vec = alloc::vec![0; Self::LENGTH];
        // This can not fail.
        self.write_to_be_bytes(&mut vec[..]).unwrap();
        vec
    }
}

impl CcsdsPacket for SpacePacketHeader {
    /// CCSDS version field.
    #[inline]
    fn ccsds_version(&self) -> u3 {
        self.version
    }

    /// Full packet length.
    #[inline]
    fn packet_len(&self) -> usize {
        self.packet_len()
    }

    /// CCSDS packet ID field.
    #[inline]
    fn packet_id(&self) -> PacketId {
        self.packet_id
    }

    /// CCSDS packet sequence control.
    #[inline]
    fn psc(&self) -> PacketSequenceControl {
        self.psc
    }

    /// CCSDS data length field.
    #[inline]
    fn data_len(&self) -> u16 {
        self.data_len
    }
}

impl CcsdsPrimaryHeader for SpacePacketHeader {
    #[inline]
    fn from_composite_fields(
        packet_id: PacketId,
        psc: PacketSequenceControl,
        data_len: u16,
        version: Option<u3>,
    ) -> Self {
        let mut version_to_set = u3::new(0b000);
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
    use crate::{CcsdsPacket, CcsdsPrimaryHeader, PacketId, PacketSequenceControl, VERSION_MASK};
    use arbitrary_int::traits::Integer;
    use arbitrary_int::u3;
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
            psc: PacketSequenceControl,
            data_len: u16,
            version: Option<u3>,
        ) -> Self {
            let mut version_packet_id = packet_id.raw();
            if let Some(version) = version {
                version_packet_id = (version.as_u16() << 13) | packet_id.raw()
            }
            SpHeader {
                version_packet_id: U16::from(version_packet_id),
                psc: U16::from(psc.raw()),
                data_len: U16::from(data_len),
            }
        }
    }

    impl CcsdsPacket for SpHeader {
        /// CCSDS version field.
        #[inline]
        fn ccsds_version(&self) -> u3 {
            u3::new(((self.version_packet_id.get() >> 13) as u8) & 0b111)
        }

        /// CCSDS packet ID field.
        #[inline]
        fn packet_id(&self) -> PacketId {
            PacketId::from(self.packet_id_raw())
        }

        /// CCSDS packet sequence control field.
        #[inline]
        fn psc(&self) -> PacketSequenceControl {
            PacketSequenceControl::from(self.psc_raw())
        }

        /// CCSDS data length field.
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
            psc: PacketSequenceControl,
            data_len: u16,
            version: Option<u3>,
        ) -> Self {
            SpHeader::new(packet_id, psc, data_len, version)
        }
    }

    sph_from_other!(SpHeader, crate::SpHeader);
}

/// CCSDS packet creator with optional support for a CRC16 CCITT checksum appended to the
/// end of the packet and support for copying into the user buffer directly.
///
/// This packet creator variant reserves memory based on the required user data length specified
/// by the user and then provides mutable or shared access to that memory. This is useful
/// to avoid an additional slice for the user data and allow copying data directly
/// into the packet.
///
/// Please note that packet creation has to be completed using the [Self::finish] call.
#[derive(Debug)]
pub struct CcsdsPacketCreatorWithReservedData<'buf> {
    sp_header: SpHeader,
    buf: &'buf mut [u8],
    checksum: Option<ChecksumType>,
}

impl<'buf> CcsdsPacketCreatorWithReservedData<'buf> {
    pub const HEADER_LEN: usize = CCSDS_HEADER_LEN;

    #[inline]
    pub fn packet_len_for_user_data_with_checksum(user_data_len: usize) -> Option<usize> {
        ccsds_packet_len_for_user_data_len(user_data_len, Some(ChecksumType::Crc16CcittFalse))
    }

    /// Generic constructor.
    pub fn new(
        mut sp_header: SpacePacketHeader,
        packet_type: PacketType,
        packet_data_len: usize,
        buf: &'buf mut [u8],
        checksum: Option<ChecksumType>,
    ) -> Result<Self, CcsdsPacketCreationError> {
        let full_packet_len = match checksum {
            Some(crc_type) => match crc_type {
                ChecksumType::Crc16CcittFalse => CCSDS_HEADER_LEN + packet_data_len + 2,
            },
            None => {
                // Special case: At least one byte of user data is required.
                if packet_data_len == 0 {
                    CCSDS_HEADER_LEN + 1
                } else {
                    CCSDS_HEADER_LEN + packet_data_len
                }
            }
        };
        if full_packet_len > buf.len() {
            return Err(ByteConversionError::ToSliceTooSmall {
                found: buf.len(),
                expected: full_packet_len,
            }
            .into());
        }
        if full_packet_len - CCSDS_HEADER_LEN - 1 > u16::MAX as usize {
            return Err(InvalidPayloadLengthError(packet_data_len).into());
        }
        sp_header.data_len = (full_packet_len - CCSDS_HEADER_LEN - 1) as u16;
        sp_header.packet_id.packet_type = packet_type;

        Ok(Self {
            sp_header,
            buf: buf[0..full_packet_len].as_mut(),
            checksum,
        })
    }

    /// Constructor which always appends a CRC16 checksum at the packet end.
    pub fn new_with_checksum(
        sp_header: SpHeader,
        packet_type: PacketType,
        payload_len: usize,
        buf: &'buf mut [u8],
    ) -> Result<Self, CcsdsPacketCreationError> {
        Self::new(
            sp_header,
            packet_type,
            payload_len,
            buf,
            Some(ChecksumType::Crc16CcittFalse),
        )
    }

    /// Constructor for telemetry packets which always appends a CRC16 checksum at the packet end.
    pub fn new_tm_with_checksum(
        sp_header: SpHeader,
        payload_len: usize,
        buf: &'buf mut [u8],
    ) -> Result<Self, CcsdsPacketCreationError> {
        Self::new(
            sp_header,
            PacketType::Tm,
            payload_len,
            buf,
            Some(ChecksumType::Crc16CcittFalse),
        )
    }

    /// Constructor for telecommand packets which always appends a CRC16 checksum at the packet
    /// end.
    pub fn new_tc_with_checksum(
        sp_header: SpHeader,
        payload_len: usize,
        buf: &'buf mut [u8],
    ) -> Result<Self, CcsdsPacketCreationError> {
        Self::new(
            sp_header,
            PacketType::Tc,
            payload_len,
            buf,
            Some(ChecksumType::Crc16CcittFalse),
        )
    }
}

impl CcsdsPacketCreatorWithReservedData<'_> {
    #[inline]
    pub fn raw_buffer(&self) -> &[u8] {
        self.buf
    }

    #[inline]
    pub fn packet_len(&self) -> usize {
        <Self as CcsdsPacket>::packet_len(self)
    }

    /// Space pacekt header.
    #[inline]
    pub fn sp_header(&self) -> &SpHeader {
        &self.sp_header
    }

    /// Mutable access to the packet data field.
    #[inline]
    pub fn packet_data_mut(&mut self) -> &mut [u8] {
        let len = self.packet_len();
        match self.checksum {
            Some(ChecksumType::Crc16CcittFalse) => &mut self.buf[CCSDS_HEADER_LEN..len - 2],
            None => &mut self.buf[CCSDS_HEADER_LEN..len],
        }
    }

    /// Read-only access to the packet data field.
    #[inline]
    pub fn packet_data(&mut self) -> &[u8] {
        let len = self.packet_len();
        match self.checksum {
            Some(ChecksumType::Crc16CcittFalse) => &self.buf[CCSDS_HEADER_LEN..len - 2],
            None => &self.buf[CCSDS_HEADER_LEN..len],
        }
    }

    /// Finish the packet generation process.
    ///
    /// This packet writes the space packet header. It also calculates and appends the CRC
    /// checksum when configured to do so.
    pub fn finish(self) -> usize {
        self.sp_header
            .write_to_be_bytes(&mut self.buf[0..CCSDS_HEADER_LEN])
            .unwrap();
        let len = self.packet_len();
        match self.checksum {
            Some(ChecksumType::Crc16CcittFalse) => {
                let crc16 = CRC_CCITT_FALSE.checksum(&self.buf[0..len - 2]);
                self.buf[len - 2..len].copy_from_slice(&crc16.to_be_bytes());
            }
            None => (),
        };
        len
    }
}

impl CcsdsPacket for CcsdsPacketCreatorWithReservedData<'_> {
    /// CCSDS version field.
    #[inline]
    fn ccsds_version(&self) -> arbitrary_int::u3 {
        self.sp_header.ccsds_version()
    }

    /// CCSDS packet ID field.
    #[inline]
    fn packet_id(&self) -> PacketId {
        self.sp_header.packet_id()
    }

    /// CCSDS packet sequence control field.
    #[inline]
    fn psc(&self) -> PacketSequenceControl {
        self.sp_header.psc()
    }

    /// CCSDS data length field.
    #[inline]
    fn data_len(&self) -> u16 {
        self.sp_header.data_len()
    }
}

/// CCSDS packet creator with optional support for a CRC16 CCITT checksum appended to the
/// end of the packet.
#[derive(Debug)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct CcsdsPacketCreator<'app_data> {
    sp_header: SpHeader,
    packet_data: &'app_data [u8],
    checksum: Option<ChecksumType>,
}

impl<'app_data> CcsdsPacketCreator<'app_data> {
    pub const HEADER_LEN: usize = CCSDS_HEADER_LEN;

    /// Helper function which can be used to determine the full packet length from the user
    /// data length, assuming there is a CRC16 appended at the packet.
    #[inline]
    pub fn packet_len_for_user_data_with_checksum(user_data_len: usize) -> Option<usize> {
        ccsds_packet_len_for_user_data_len(user_data_len, Some(ChecksumType::Crc16CcittFalse))
    }

    /// Generic constructor.
    pub fn new(
        mut sp_header: SpHeader,
        packet_type: PacketType,
        packet_data: &'app_data [u8],
        checksum: Option<ChecksumType>,
    ) -> Result<Self, CcsdsPacketCreationError> {
        sp_header.data_len = (packet_data.len()
            + match checksum {
                Some(ChecksumType::Crc16CcittFalse) => 2,
                None => 0,
            }
            - 1) as u16;
        let full_packet_len = match checksum {
            Some(crc_type) => match crc_type {
                ChecksumType::Crc16CcittFalse => CCSDS_HEADER_LEN + packet_data.len() + 2,
            },
            None => {
                // Special case: At least one byte of user data is required.
                if packet_data.is_empty() {
                    CCSDS_HEADER_LEN + 1
                } else {
                    CCSDS_HEADER_LEN + packet_data.len()
                }
            }
        };
        if full_packet_len - CCSDS_HEADER_LEN - 1 > u16::MAX as usize {
            return Err(InvalidPayloadLengthError(packet_data.len()).into());
        }
        sp_header.data_len = (full_packet_len - CCSDS_HEADER_LEN - 1) as u16;
        sp_header.packet_id.packet_type = packet_type;
        Ok(Self {
            sp_header,
            packet_data,
            checksum,
        })
    }

    /// Constructor which always appends a CRC16 checksum at the packet end.
    pub fn new_with_checksum(
        sp_header: SpHeader,
        packet_type: PacketType,
        app_data: &'app_data [u8],
    ) -> Result<Self, CcsdsPacketCreationError> {
        Self::new(
            sp_header,
            packet_type,
            app_data,
            Some(ChecksumType::Crc16CcittFalse),
        )
    }

    /// Constructor for telemetry which always appends a CRC16 checksum at the packet end.
    pub fn new_tm_with_checksum(
        sp_header: SpHeader,
        app_data: &'app_data [u8],
    ) -> Result<Self, CcsdsPacketCreationError> {
        Self::new(
            sp_header,
            PacketType::Tm,
            app_data,
            Some(ChecksumType::Crc16CcittFalse),
        )
    }

    /// Constructor for telecommands which always appends a CRC16 checksum at the packet end.
    pub fn new_tc_with_checksum(
        sp_header: SpHeader,
        app_data: &'app_data [u8],
    ) -> Result<Self, CcsdsPacketCreationError> {
        Self::new(
            sp_header,
            PacketType::Tc,
            app_data,
            Some(ChecksumType::Crc16CcittFalse),
        )
    }
}

impl CcsdsPacketCreator<'_> {
    /// Full length when written to bytes.
    pub fn len_written(&self) -> usize {
        ccsds_packet_len_for_user_data_len(self.packet_data.len(), self.checksum).unwrap()
    }

    /// Write the CCSDS packet to the provided buffer.
    pub fn write_to_bytes(&self, buf: &mut [u8]) -> Result<usize, ByteConversionError> {
        let len_written = self.len_written();
        if len_written > buf.len() {
            return Err(ByteConversionError::ToSliceTooSmall {
                found: buf.len(),
                expected: len_written,
            });
        }
        self.sp_header
            .write_to_be_bytes(&mut buf[0..CCSDS_HEADER_LEN])?;
        buf[CCSDS_HEADER_LEN..CCSDS_HEADER_LEN + self.packet_data.len()]
            .copy_from_slice(self.packet_data);
        match self.checksum {
            Some(ChecksumType::Crc16CcittFalse) => {
                let crc16 = CRC_CCITT_FALSE.checksum(&buf[0..len_written - 2]);
                buf[len_written - 2..len_written].copy_from_slice(&crc16.to_be_bytes());
            }
            None => (),
        };
        Ok(len_written)
    }

    pub fn sp_header(&self) -> &SpHeader {
        &self.sp_header
    }

    /// Create a CCSDS packet as a vector.
    #[cfg(feature = "alloc")]
    pub fn to_vec(&self) -> alloc::vec::Vec<u8> {
        let mut vec = alloc::vec![0u8; self.len_written()];
        // Can not fail, unless we messed up the len_written method..
        self.write_to_bytes(&mut vec).unwrap();
        vec
    }
}

#[derive(thiserror::Error, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub enum CcsdsPacketReadError {
    #[error("byte conversion: {0}")]
    ByteConversion(#[from] ByteConversionError),
    #[error("CRC error")]
    CrcError,
}

/// CCSDS packet reader structure.
#[derive(Debug)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct CcsdsPacketReader<'buf> {
    sp_header: SpHeader,
    packet_data: &'buf [u8],
}

impl<'buf> CcsdsPacketReader<'buf> {
    pub const HEADER_LEN: usize = CCSDS_HEADER_LEN;

    pub fn new_with_checksum(
        buf: &'buf [u8],
    ) -> Result<CcsdsPacketReader<'buf>, CcsdsPacketReadError> {
        Self::new(buf, Some(ChecksumType::Crc16CcittFalse))
    }

    pub fn new(
        buf: &'buf [u8],
        checksum: Option<ChecksumType>,
    ) -> Result<Self, CcsdsPacketReadError> {
        let sp_header = SpHeader::from_be_bytes(&buf[0..CCSDS_HEADER_LEN])?.0;
        if sp_header.packet_len() > buf.len() {
            return Err(ByteConversionError::FromSliceTooSmall {
                found: sp_header.packet_len(),
                expected: buf.len(),
            }
            .into());
        }
        let user_data = match checksum {
            Some(ChecksumType::Crc16CcittFalse) => {
                if CRC_CCITT_FALSE.checksum(&buf[0..sp_header.packet_len()]) != 0 {
                    return Err(CcsdsPacketReadError::CrcError);
                }
                &buf[CCSDS_HEADER_LEN..sp_header.packet_len() - 2]
            }
            None => &buf[CCSDS_HEADER_LEN..sp_header.packet_len()],
        };
        Ok(Self {
            sp_header,
            packet_data: user_data,
        })
    }
}

impl CcsdsPacketReader<'_> {
    /// Space pacekt header.
    #[inline]
    pub fn sp_header(&self) -> &SpHeader {
        &self.sp_header
    }

    /// CCSDS packet type.
    #[inline]
    pub fn packet_type(&self) -> PacketType {
        self.sp_header.packet_id.packet_type
    }

    /// Read-only access to the packet data field.
    #[inline]
    pub fn packet_data(&self) -> &[u8] {
        self.packet_data
    }

    /// 11-bit Application Process ID field.
    #[inline]
    pub fn apid(&self) -> u11 {
        self.sp_header.apid()
    }

    /// CCSDS packet ID field.
    #[inline]
    pub fn packet_id(&self) -> PacketId {
        self.sp_header.packet_id()
    }

    /// Packet sequence control field.
    #[inline]
    pub fn psc(&self) -> PacketSequenceControl {
        self.sp_header.psc()
    }

    /// Full packet length with the CCSDS header.
    #[inline]
    pub fn packet_len(&self) -> usize {
        <Self as CcsdsPacket>::packet_len(self)
    }

    /// Packet data length field.
    #[inline]
    pub fn data_len(&self) -> u16 {
        self.sp_header.data_len()
    }
}

impl CcsdsPacket for CcsdsPacketReader<'_> {
    /// CCSDS version field.
    #[inline]
    fn ccsds_version(&self) -> arbitrary_int::u3 {
        self.sp_header.ccsds_version()
    }

    /// Packet ID field.
    #[inline]
    fn packet_id(&self) -> PacketId {
        self.packet_id()
    }

    /// Packet sequence control field.
    #[inline]
    fn psc(&self) -> PacketSequenceControl {
        self.psc()
    }

    /// Packet data length without the CCSDS header.
    #[inline]
    fn data_len(&self) -> u16 {
        self.data_len()
    }
}

#[cfg(all(test, feature = "std"))]
pub(crate) mod tests {
    use std::collections::HashSet;

    use super::*;
    use crate::crc::CRC_CCITT_FALSE;
    #[allow(unused_imports)]
    use crate::ByteConversionError;
    #[cfg(feature = "serde")]
    use crate::CcsdsPrimaryHeader;
    use crate::{SequenceFlags, SpHeader};
    use alloc::vec;
    use arbitrary_int::{u11, u14};
    #[cfg(feature = "serde")]
    use core::fmt::Debug;
    #[cfg(feature = "serde")]
    use postcard::{from_bytes, to_allocvec};
    #[cfg(feature = "serde")]
    use serde::{de::DeserializeOwned, Serialize};
    use zerocopy::FromBytes;

    const CONST_SP: SpHeader = SpHeader::new(
        PacketId::new_for_tc(true, u11::new(0x36)),
        PacketSequenceControl::new(SequenceFlags::ContinuationSegment, u14::new(0x88)),
        0x90,
    );

    const PACKET_ID_TM: PacketId = PacketId::new_for_tm(true, u11::new(0x22));

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
        assert_eq!(PACKET_ID_TM.apid().value(), 0x22);
        assert!(PACKET_ID_TM.sec_header_flag);
        assert_eq!(PACKET_ID_TM.packet_type, PacketType::Tm);
        let const_tc_id = PacketId::new_for_tc(true, u11::new(0x23));
        assert_eq!(const_tc_id.packet_type, PacketType::Tc);
    }

    #[test]
    fn test_default_packet_id() {
        let id_default = PacketId::default();
        assert_eq!(id_default.packet_type, PacketType::Tm);
        assert_eq!(id_default.apid.value(), 0x000);
        assert!(!id_default.sec_header_flag);
    }

    #[test]
    fn test_packet_id_ctors() {
        let packet_id = PacketId::new(PacketType::Tc, true, u11::new(0x1ff));
        assert_eq!(packet_id.apid().value(), 0x1ff);
        assert_eq!(packet_id.packet_type, PacketType::Tc);
        assert!(packet_id.sec_header_flag);
        let packet_id_tc = PacketId::new_for_tc(true, u11::new(0x1ff));
        assert_eq!(packet_id_tc, packet_id);
        let packet_id_tm = PacketId::new_for_tm(true, u11::new(0x2ff));
        assert!(packet_id_tm.sec_header_flag);
        assert_eq!(packet_id_tm.packet_type, PacketType::Tm);
        assert_eq!(packet_id_tm.apid, u11::new(0x2ff));
    }

    #[test]
    fn verify_const_sp_header() {
        assert!(CONST_SP.sec_header_flag());
        assert_eq!(CONST_SP.apid().value(), 0x36);
        assert_eq!(
            CONST_SP.sequence_flags(),
            SequenceFlags::ContinuationSegment
        );
        assert_eq!(CONST_SP.seq_count().value(), 0x88);
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
        let packet_id = PacketId::new(PacketType::Tm, false, u11::new(0x42));
        assert_eq!(packet_id.raw(), 0x0042);
        let packet_id_from_raw = PacketId::from(packet_id.raw());
        assert_eq!(
            packet_type_in_raw_packet_id(packet_id.raw()),
            PacketType::Tm
        );
        assert_eq!(packet_id_from_raw, packet_id);
        let packet_id_from_new = PacketId::new(PacketType::Tm, false, u11::new(0x42));
        assert_eq!(packet_id_from_new, packet_id);
    }

    #[test]
    fn test_packet_seq_ctrl() {
        let psc = PacketSequenceControl::new(SequenceFlags::ContinuationSegment, u14::new(77));
        assert_eq!(psc.raw(), 77);
        let psc_from_raw = PacketSequenceControl::from(psc.raw());
        assert_eq!(psc_from_raw, psc);
    }

    #[test]
    #[cfg(feature = "serde")]
    fn test_serde_sph() {
        let sp_header = SpHeader::new_for_unseg_tc(u11::new(0x42), u14::new(12), 0);
        assert_eq!(sp_header.ccsds_version().value(), 0b000);
        assert!(sp_header.is_tc());
        assert!(!sp_header.sec_header_flag());
        assert_eq!(sp_header.packet_type(), PacketType::Tc);
        assert_eq!(sp_header.seq_count().value(), 12);
        assert_eq!(sp_header.apid().value(), 0x42);
        assert_eq!(sp_header.sequence_flags(), SequenceFlags::Unsegmented);
        assert_eq!(sp_header.data_len(), 0);
        let output = to_allocvec(&sp_header).unwrap();
        let sp_header: SpHeader = from_bytes(&output).unwrap();
        assert_eq!(sp_header.version.value(), 0b000);
        assert!(!sp_header.packet_id.sec_header_flag);
        assert_eq!(sp_header.packet_type(), PacketType::Tc);
        assert_eq!(sp_header.seq_count().value(), 12);
        assert_eq!(sp_header.apid().value(), 0x42);
        assert_eq!(sp_header.sequence_flags(), SequenceFlags::Unsegmented);
        assert_eq!(sp_header.packet_id_raw(), 0x1042);
        assert_eq!(sp_header.psc_raw(), 0xC00C);
        assert_eq!(sp_header.ccsds_version().value(), 0b000);
        assert_eq!(sp_header.data_len, 0);

        let sp_header = SpHeader::new_for_unseg_tm(u11::new(0x7), u14::new(22), 36);
        assert_eq!(sp_header.ccsds_version().value(), 0b000);
        assert!(sp_header.is_tm());
        assert!(!sp_header.sec_header_flag());
        assert_eq!(sp_header.packet_type(), PacketType::Tm);
        assert_eq!(sp_header.seq_count().value(), 22);
        assert_eq!(sp_header.apid().value(), 0x07);
        assert_eq!(sp_header.sequence_flags(), SequenceFlags::Unsegmented);
        assert_eq!(sp_header.packet_id_raw(), 0x0007);
        assert_eq!(sp_header.psc_raw(), 0xC016);
        assert_eq!(sp_header.data_len(), 36);
        assert_eq!(sp_header.ccsds_version().value(), 0b000);

        let from_comp_fields = SpHeader::from_composite_fields(
            PacketId::new(PacketType::Tc, true, u11::new(0x42)),
            PacketSequenceControl::new(SequenceFlags::Unsegmented, u14::new(0x7)),
            0,
            None,
        );
        assert_eq!(from_comp_fields.packet_type(), PacketType::Tc);
        assert_eq!(from_comp_fields.apid().value(), 0x42);
        assert!(from_comp_fields.sec_header_flag());
        assert_eq!(
            from_comp_fields.sequence_flags(),
            SequenceFlags::Unsegmented
        );
        assert_eq!(from_comp_fields.seq_count().value(), 0x7);
        assert_eq!(from_comp_fields.data_len(), 0);
    }

    #[test]
    fn test_setters() {
        let mut sp_header =
            SpHeader::new_for_tc(u11::new(0x42), SequenceFlags::Unsegmented, u14::new(25), 0);
        sp_header.set_apid(u11::new(0x12));
        assert_eq!(sp_header.apid().as_u16(), 0x12);
        sp_header.set_sec_header_flag();
        assert!(sp_header.sec_header_flag());
        sp_header.clear_sec_header_flag();
        assert!(!sp_header.sec_header_flag());
        assert_eq!(sp_header.packet_type(), PacketType::Tc);
        sp_header.set_packet_type(PacketType::Tm);
        assert_eq!(sp_header.packet_type(), PacketType::Tm);
        sp_header.set_seq_count(u14::new(0x45));
        assert_eq!(sp_header.seq_count().as_u16(), 0x45);
    }

    #[test]
    fn test_tc_ctor() {
        let sp_header =
            SpHeader::new_for_tc(u11::new(0x42), SequenceFlags::Unsegmented, u14::new(25), 0);
        verify_sp_fields(PacketType::Tc, &sp_header);
    }

    #[test]
    fn test_tc_ctor_unseg() {
        let sp_header = SpHeader::new_for_unseg_tc(u11::new(0x42), u14::new(25), 0);
        verify_sp_fields(PacketType::Tc, &sp_header);
    }

    #[test]
    fn test_tc_ctor_unseg_const() {
        let sp_header = SpHeader::new_for_unseg_tc(u11::new(0x42), u14::new(25), 0);
        verify_sp_fields(PacketType::Tc, &sp_header);
    }

    #[test]
    fn test_tm_ctor() {
        let sp_header =
            SpHeader::new_for_tm(u11::new(0x42), SequenceFlags::Unsegmented, u14::new(25), 0);
        verify_sp_fields(PacketType::Tm, &sp_header);
    }

    #[test]
    fn test_tm_ctor_const() {
        let sp_header =
            SpHeader::new_for_tm(u11::new(0x42), SequenceFlags::Unsegmented, u14::new(25), 0);
        verify_sp_fields(PacketType::Tm, &sp_header);
    }

    #[test]
    fn test_tm_ctor_unseg() {
        let sp_header = SpHeader::new_for_unseg_tm(u11::new(0x42), u14::new(25), 0);
        verify_sp_fields(PacketType::Tm, &sp_header);
    }

    fn verify_sp_fields(ptype: PacketType, sp_header: &SpHeader) {
        assert_eq!(sp_header.packet_type(), ptype);
        assert_eq!(sp_header.sequence_flags(), SequenceFlags::Unsegmented);
        assert_eq!(sp_header.apid().value(), 0x42);
        assert_eq!(sp_header.seq_count(), u14::new(25));
        assert_eq!(sp_header.data_len(), 0);
    }

    #[test]
    fn test_zc_sph() {
        use zerocopy::IntoBytes;

        let sp_header = SpHeader::new_for_unseg_tc(u11::MAX, u14::MAX, 0);
        assert_eq!(sp_header.packet_type(), PacketType::Tc);
        assert_eq!(sp_header.apid().value(), 0x7FF);
        assert_eq!(sp_header.data_len(), 0);
        assert_eq!(sp_header.ccsds_version().value(), 0b000);
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
        assert_eq!(sp_header.ccsds_version().value(), 0b000);
        assert_eq!(sp_header.packet_id_raw(), 0x17FF);
        assert_eq!(sp_header.apid().value(), 0x7FF);
        assert_eq!(sp_header.packet_type(), PacketType::Tc);
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
        let sp_header = SpHeader::new_from_apid(u11::new(0x03));
        assert_eq!(sp_header.apid().value(), 0x03);
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
        let sp_header = SpHeader::new_for_unseg_tc(u11::new(0x42), u14::new(25), 1);
        let sp_header_as_vec = sp_header.to_vec();
        let sp_header_read_back = SpHeader::from_be_bytes(&sp_header_as_vec)
            .expect("Error reading back SP header")
            .0;
        assert_eq!(sp_header, sp_header_read_back);
    }

    #[test]
    fn test_ccsds_size_function() {
        assert_eq!(ccsds_packet_len_for_user_data_len(1, None).unwrap(), 7);
        // Special case: One dummy byte is required.
        assert_eq!(ccsds_packet_len_for_user_data_len(0, None).unwrap(), 7);
        assert_eq!(
            ccsds_packet_len_for_user_data_len(1, Some(ChecksumType::Crc16CcittFalse)).unwrap(),
            9
        );
        assert_eq!(
            ccsds_packet_len_for_user_data_len_with_checksum(1).unwrap(),
            9
        );
    }

    #[test]
    fn test_ccsds_size_function_invalid_size_no_checksum() {
        // This works, because the data field is the user data length minus 1.
        assert!(ccsds_packet_len_for_user_data_len(u16::MAX as usize + 1, None).is_some());
        // This does not work, data field length exceeded.
        assert!(ccsds_packet_len_for_user_data_len(u16::MAX as usize + 2, None).is_none());
    }

    #[test]
    fn test_ccsds_size_function_invalid_size_with_checksum() {
        // 2 less bytes available because of the checksum.
        assert!(ccsds_packet_len_for_user_data_len(
            u16::MAX as usize - 1,
            Some(ChecksumType::Crc16CcittFalse)
        )
        .is_some());
        // This is too much.
        assert!(ccsds_packet_len_for_user_data_len(
            u16::MAX as usize,
            Some(ChecksumType::Crc16CcittFalse)
        )
        .is_none());
    }

    #[test]
    fn test_ccsds_creator_api() {
        let mut buf: [u8; 32] = [0; 32];
        let mut packet_creator = CcsdsPacketCreatorWithReservedData::new(
            SpacePacketHeader::new_from_apid(u11::new(0x1)),
            PacketType::Tc,
            4,
            &mut buf,
            Some(ChecksumType::Crc16CcittFalse),
        )
        .unwrap();
        assert_eq!(packet_creator.packet_len(), 12);
        assert_eq!(packet_creator.raw_buffer().len(), 12);
        assert_eq!(packet_creator.data_len(), 5);
        assert_eq!(packet_creator.apid().value(), 0x1);
        assert_eq!(packet_creator.packet_data_mut(), &mut [0, 0, 0, 0]);
        assert_eq!(packet_creator.packet_data(), &[0, 0, 0, 0]);
    }

    #[test]
    fn test_ccsds_creator_api_no_checksum() {
        let mut buf: [u8; 32] = [0; 32];
        let mut packet_creator = CcsdsPacketCreatorWithReservedData::new(
            SpacePacketHeader::new_from_apid(u11::new(0x1)),
            PacketType::Tc,
            4,
            &mut buf,
            None,
        )
        .unwrap();
        assert_eq!(packet_creator.packet_len(), 10);
        assert_eq!(packet_creator.data_len(), 3);
        assert_eq!(packet_creator.apid().value(), 0x1);
        assert_eq!(packet_creator.packet_data_mut(), &mut [0, 0, 0, 0]);
        assert_eq!(packet_creator.packet_data(), &[0, 0, 0, 0]);
    }

    #[test]
    fn test_ccsds_creator_creation_with_reserved_data_alt_ctor() {
        let mut buf: [u8; 32] = [0; 32];
        let data = [1, 2, 3, 4];
        let mut packet_creator = CcsdsPacketCreatorWithReservedData::new_with_checksum(
            SpacePacketHeader::new_from_apid(u11::new(0x1)),
            PacketType::Tc,
            4,
            &mut buf,
        )
        .unwrap();
        packet_creator.packet_data_mut().copy_from_slice(&data);
        let written_len = packet_creator.finish();
        assert_eq!(
            CcsdsPacketCreatorWithReservedData::packet_len_for_user_data_with_checksum(4).unwrap(),
            written_len
        );
        assert_eq!(CRC_CCITT_FALSE.checksum(&buf[0..written_len]), 0);
        let sp_header = SpacePacketHeader::from_be_bytes(
            &buf[0..CcsdsPacketCreatorWithReservedData::HEADER_LEN],
        )
        .unwrap()
        .0;
        assert_eq!(sp_header.apid().value(), 0x1);
        assert_eq!(buf[6], 1);
        assert_eq!(buf[7], 2);
        assert_eq!(buf[8], 3);
        assert_eq!(buf[9], 4);
        assert_eq!(buf[12], 0);
    }

    #[test]
    fn test_ccsds_creator_creation_with_reserved_data() {
        let mut buf: [u8; 32] = [0; 32];
        let data = [1, 2, 3, 4];
        let mut packet_creator = CcsdsPacketCreatorWithReservedData::new(
            SpacePacketHeader::new_from_apid(u11::new(0x1)),
            PacketType::Tc,
            4,
            &mut buf,
            Some(ChecksumType::Crc16CcittFalse),
        )
        .unwrap();
        packet_creator.packet_data_mut().copy_from_slice(&data);
        let written_len = packet_creator.finish();
        assert_eq!(
            CcsdsPacketCreatorWithReservedData::packet_len_for_user_data_with_checksum(4).unwrap(),
            written_len
        );
        assert_eq!(CRC_CCITT_FALSE.checksum(&buf[0..written_len]), 0);
        let sp_header = SpacePacketHeader::from_be_bytes(
            &buf[0..CcsdsPacketCreatorWithReservedData::HEADER_LEN],
        )
        .unwrap()
        .0;
        assert_eq!(sp_header.apid().value(), 0x1);
        assert_eq!(sp_header.packet_type(), PacketType::Tc);
        assert_eq!(buf[6], 1);
        assert_eq!(buf[7], 2);
        assert_eq!(buf[8], 3);
        assert_eq!(buf[9], 4);
        assert_eq!(buf[12], 0);
    }

    #[test]
    fn test_ccsds_creator_creation_empty_user_data_no_checksum() {
        let mut buf: [u8; 32] = [0; 32];
        let packet_creator = CcsdsPacketCreatorWithReservedData::new(
            SpacePacketHeader::new_from_apid(u11::new(0x1)),
            PacketType::Tc,
            0,
            &mut buf,
            None,
        )
        .unwrap();
        // Special case.
        assert_eq!(packet_creator.packet_len(), 7);
        packet_creator.finish();
        let reader = CcsdsPacketReader::new(&buf[0..7], None).unwrap();
        // Enforced 1 byte packet length.
        assert_eq!(reader.packet_data(), &[0]);
        assert_eq!(reader.packet_len(), 7);
    }

    #[test]
    fn test_ccsds_creator_creation_buf_too_small() {
        let mut buf: [u8; 8] = [0; 8];
        let packet_creator = CcsdsPacketCreatorWithReservedData::new(
            SpacePacketHeader::new_from_apid(u11::new(0x1)),
            PacketType::Tc,
            4,
            &mut buf,
            None,
        );
        assert!(packet_creator.is_err());
        matches!(
            packet_creator.unwrap_err(),
            CcsdsPacketCreationError::ByteConversion(ByteConversionError::ToSliceTooSmall {
                found: 8,
                expected: 10
            })
        );
    }

    #[test]
    fn test_ccsds_creator_creation_with_reserved_data_tc_api() {
        let mut buf: [u8; 32] = [0; 32];
        let data = [1, 2, 3, 4];
        let mut packet_creator = CcsdsPacketCreatorWithReservedData::new_tc_with_checksum(
            SpacePacketHeader::new_from_apid(u11::new(0x1)),
            4,
            &mut buf,
        )
        .unwrap();
        packet_creator.packet_data_mut().copy_from_slice(&data);
        let written_len = packet_creator.finish();
        assert_eq!(
            CcsdsPacketCreatorWithReservedData::packet_len_for_user_data_with_checksum(4).unwrap(),
            written_len
        );
        assert_eq!(CRC_CCITT_FALSE.checksum(&buf[0..written_len]), 0);
        let sp_header = SpacePacketHeader::from_be_bytes(
            &buf[0..CcsdsPacketCreatorWithReservedData::HEADER_LEN],
        )
        .unwrap()
        .0;
        assert_eq!(sp_header.apid().value(), 0x1);
        assert_eq!(sp_header.packet_type(), PacketType::Tc);
        assert_eq!(buf[6], 1);
        assert_eq!(buf[7], 2);
        assert_eq!(buf[8], 3);
        assert_eq!(buf[9], 4);
        assert_eq!(buf[12], 0);
    }

    #[test]
    fn test_ccsds_creator_creation_with_reserved_data_tm_api() {
        let mut buf: [u8; 32] = [0; 32];
        let data = [1, 2, 3, 4];
        let mut packet_creator = CcsdsPacketCreatorWithReservedData::new_tm_with_checksum(
            SpacePacketHeader::new_from_apid(u11::new(0x1)),
            4,
            &mut buf,
        )
        .unwrap();
        packet_creator.packet_data_mut().copy_from_slice(&data);
        let written_len = packet_creator.finish();
        assert_eq!(
            CcsdsPacketCreatorWithReservedData::packet_len_for_user_data_with_checksum(4).unwrap(),
            written_len
        );
        assert_eq!(CRC_CCITT_FALSE.checksum(&buf[0..written_len]), 0);
        let sp_header = SpacePacketHeader::from_be_bytes(
            &buf[0..CcsdsPacketCreatorWithReservedData::HEADER_LEN],
        )
        .unwrap()
        .0;
        assert_eq!(sp_header.apid().value(), 0x1);
        assert_eq!(sp_header.packet_type(), PacketType::Tm);
        assert_eq!(buf[6], 1);
        assert_eq!(buf[7], 2);
        assert_eq!(buf[8], 3);
        assert_eq!(buf[9], 4);
        assert_eq!(buf[12], 0);
    }

    #[test]
    fn test_ccsds_creator_creation_with_reserved_data_no_checksum() {
        let mut buf: [u8; 32] = [0; 32];
        let data = [1, 2, 3, 4];
        let mut packet_creator = CcsdsPacketCreatorWithReservedData::new(
            SpacePacketHeader::new_from_apid(u11::new(0x1)),
            PacketType::Tc,
            4,
            &mut buf,
            None,
        )
        .unwrap();
        packet_creator.packet_data_mut().copy_from_slice(&data);
        let written_len = packet_creator.finish();
        assert_eq!(written_len, 10);
        let sp_header = SpacePacketHeader::from_be_bytes(
            &buf[0..CcsdsPacketCreatorWithReservedData::HEADER_LEN],
        )
        .unwrap()
        .0;
        assert_eq!(sp_header.apid().value(), 0x1);
        assert_eq!(buf[6], 1);
        assert_eq!(buf[7], 2);
        assert_eq!(buf[8], 3);
        assert_eq!(buf[9], 4);
        assert_eq!(buf[10], 0);
        assert_eq!(buf[11], 0);
    }
    fn generic_ccsds_creator_test(alt_api: bool) {
        let data = [1, 2, 3, 4];
        let packet_creator = if alt_api {
            CcsdsPacketCreator::new(
                SpacePacketHeader::new_from_apid(u11::new(0x1)),
                PacketType::Tc,
                &data,
                Some(ChecksumType::Crc16CcittFalse),
            )
            .unwrap()
        } else {
            CcsdsPacketCreator::new_with_checksum(
                SpacePacketHeader::new_from_apid(u11::new(0x1)),
                PacketType::Tc,
                &data,
            )
            .unwrap()
        };
        let packet_raw = packet_creator.to_vec();
        assert_eq!(CRC_CCITT_FALSE.checksum(&packet_raw), 0);
        let sp_header = SpacePacketHeader::from_be_bytes(
            &packet_raw[0..CcsdsPacketCreatorWithReservedData::HEADER_LEN],
        )
        .unwrap()
        .0;
        assert_eq!(sp_header.apid().value(), 0x1);
        assert_eq!(sp_header.packet_type(), PacketType::Tc);
        assert_eq!(packet_raw[6], 1);
        assert_eq!(packet_raw[7], 2);
        assert_eq!(packet_raw[8], 3);
        assert_eq!(packet_raw[9], 4);
    }

    #[test]
    fn test_ccsds_creator_creation() {
        generic_ccsds_creator_test(false);
    }

    #[test]
    fn test_ccsds_creator_creation_alt() {
        generic_ccsds_creator_test(true);
    }

    #[test]
    fn test_ccsds_creator_creation_alt_tc() {
        let data = [1, 2, 3, 4];
        let packet_creator = CcsdsPacketCreator::new_tc_with_checksum(
            SpacePacketHeader::new_from_apid(u11::new(0x1)),
            &data,
        )
        .unwrap();
        let packet_raw = packet_creator.to_vec();
        assert_eq!(CRC_CCITT_FALSE.checksum(&packet_raw), 0);
        let sp_header = SpacePacketHeader::from_be_bytes(
            &packet_raw[0..CcsdsPacketCreatorWithReservedData::HEADER_LEN],
        )
        .unwrap()
        .0;
        assert_eq!(sp_header.apid().value(), 0x1);
        assert_eq!(sp_header.packet_type(), PacketType::Tc);
        assert_eq!(packet_raw[6], 1);
        assert_eq!(packet_raw[7], 2);
        assert_eq!(packet_raw[8], 3);
        assert_eq!(packet_raw[9], 4);
    }

    #[test]
    fn test_ccsds_creator_creation_alt_tm() {
        let data = [1, 2, 3, 4];
        let packet_creator = CcsdsPacketCreator::new_tm_with_checksum(
            SpacePacketHeader::new_from_apid(u11::new(0x1)),
            &data,
        )
        .unwrap();
        let packet_raw = packet_creator.to_vec();
        assert_eq!(CRC_CCITT_FALSE.checksum(&packet_raw), 0);
        let sp_header = SpacePacketHeader::from_be_bytes(
            &packet_raw[0..CcsdsPacketCreatorWithReservedData::HEADER_LEN],
        )
        .unwrap()
        .0;
        assert_eq!(sp_header.apid().value(), 0x1);
        assert_eq!(sp_header.packet_type(), PacketType::Tm);
        assert_eq!(packet_raw[6], 1);
        assert_eq!(packet_raw[7], 2);
        assert_eq!(packet_raw[8], 3);
        assert_eq!(packet_raw[9], 4);
    }

    fn generic_ccsds_reader_test(packet_type: PacketType) {
        let data = [1, 2, 3, 4];
        let packet_creator = CcsdsPacketCreator::new(
            SpacePacketHeader::new_from_apid(u11::new(0x1)),
            packet_type,
            &data,
            Some(ChecksumType::Crc16CcittFalse),
        )
        .unwrap();
        let packet_raw = packet_creator.to_vec();
        assert_eq!(
            CcsdsPacketCreator::packet_len_for_user_data_with_checksum(4).unwrap(),
            packet_raw.len()
        );
        let reader = CcsdsPacketReader::new_with_checksum(&packet_raw).unwrap();
        assert_eq!(reader.sp_header(), packet_creator.sp_header());
        assert_eq!(reader.packet_data(), &data);
        assert_eq!(reader.apid(), u11::new(0x1));
        assert_eq!(
            reader.packet_id(),
            PacketId::new(packet_type, false, u11::new(0x1))
        );
        assert_eq!(
            reader.psc(),
            PacketSequenceControl::new(SequenceFlags::Unsegmented, u14::new(0x0))
        );
        assert_eq!(reader.packet_len(), packet_raw.len());
        assert_eq!(reader.packet_type(), packet_type);
        assert_eq!(reader.data_len() as usize, packet_raw.len() - 7);
    }

    #[test]
    fn test_ccsds_reader_tc() {
        generic_ccsds_reader_test(PacketType::Tc);
    }

    #[test]
    fn test_ccsds_reader_tm() {
        generic_ccsds_reader_test(PacketType::Tm);
    }

    #[test]
    fn test_ccsds_reader_no_checksum() {
        let data = [1, 2, 3, 4];
        let packet_creator = CcsdsPacketCreator::new(
            SpacePacketHeader::new_from_apid(u11::new(0x1)),
            PacketType::Tc,
            &data,
            None,
        )
        .unwrap();
        let packet_raw = packet_creator.to_vec();
        let reader = CcsdsPacketReader::new(&packet_raw, None).unwrap();
        assert_eq!(reader.sp_header(), packet_creator.sp_header());
        assert_eq!(reader.packet_data(), &data);
        assert_eq!(reader.apid(), u11::new(0x1));
        assert_eq!(
            reader.packet_id(),
            PacketId::new(PacketType::Tc, false, u11::new(0x1))
        );
        assert_eq!(
            reader.psc(),
            PacketSequenceControl::new(SequenceFlags::Unsegmented, u14::new(0x0))
        );
        assert_eq!(reader.packet_len(), packet_raw.len());
        assert_eq!(reader.packet_type(), PacketType::Tc);
        assert_eq!(reader.data_len() as usize, packet_raw.len() - 7);
    }

    #[test]
    fn test_ccsds_reader_buf_too_small() {
        let data = [1, 2, 3, 4];
        let packet_creator = CcsdsPacketCreator::new(
            SpacePacketHeader::new_from_apid(u11::new(0x1)),
            PacketType::Tc,
            &data,
            None,
        )
        .unwrap();
        let packet_raw = packet_creator.to_vec();
        let reader_error = CcsdsPacketReader::new(&packet_raw[0..8], None);
        assert!(reader_error.is_err());
        let error = reader_error.unwrap_err();
        matches!(
            error,
            CcsdsPacketReadError::ByteConversion(ByteConversionError::FromSliceTooSmall {
                found: 8,
                expected: 10
            })
        );
    }

    #[test]
    fn test_ccsds_checksum_error() {
        let data = [1, 2, 3, 4];
        let packet_creator = CcsdsPacketCreator::new_tc_with_checksum(
            SpacePacketHeader::new_from_apid(u11::new(0x1)),
            &data,
        )
        .unwrap();
        let mut packet_raw = packet_creator.to_vec();
        *packet_raw.last_mut().unwrap() = 0;
        let reader_error = CcsdsPacketReader::new_with_checksum(&packet_raw);
        assert!(reader_error.is_err());
        assert_eq!(reader_error.unwrap_err(), CcsdsPacketReadError::CrcError);
    }

    #[test]
    fn sp_header_to_buf_too_small() {
        let sph = SpacePacketHeader::new_from_apid(u11::new(0x01));
        let mut buf: [u8; 5] = [0; 5];
        assert_eq!(
            sph.write_to_be_bytes(&mut buf).unwrap_err(),
            ByteConversionError::ToSliceTooSmall {
                found: 5,
                expected: 6
            }
        );
    }

    #[test]
    fn sp_header_from_buf_too_small() {
        let buf: [u8; 5] = [0; 5];
        let sph = SpacePacketHeader::from_be_bytes(&buf);
        assert_eq!(
            sph.unwrap_err(),
            ByteConversionError::FromSliceTooSmall {
                found: 5,
                expected: 6
            }
        );
    }

    #[test]
    fn sp_header_default() {
        let sph = SpacePacketHeader::default();
        assert_eq!(sph.packet_id(), PacketId::default());
        assert_eq!(sph.apid().value(), 0);
        assert_eq!(
            sph.psc(),
            PacketSequenceControl::new(SequenceFlags::Unsegmented, u14::new(0))
        );
        assert_eq!(sph.data_len(), 0);
    }
}
