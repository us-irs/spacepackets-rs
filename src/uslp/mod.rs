//! # Support of the CCSDS Unified Space Data Link Protocol (USLP)
#![deny(missing_docs)]
use arbitrary_int::{prelude::*, u4, u6};

use crate::{crc::CRC_CCITT_FALSE, ByteConversionError};

/// Only this version is supported by the library
pub const USLP_VERSION_NUMBER: u8 = 0b1100;

/// Identifies the association of the data contained in the transfer frame.
#[derive(Debug, PartialEq, Eq, num_enum::TryFromPrimitive, num_enum::IntoPrimitive)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
#[bitbybit::bitenum(u1, exhaustive = true)]
#[repr(u8)]
pub enum SourceOrDestField {
    /// SCID refers to the source of the transfer frame.
    Source = 0,
    /// SCID refers to the destination of the transfer frame.
    Dest = 1,
}

/// Bypass sequence control flag.
#[derive(Debug, PartialEq, Eq, num_enum::TryFromPrimitive, num_enum::IntoPrimitive)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
#[bitbybit::bitenum(u1, exhaustive = true)]
#[repr(u8)]
pub enum BypassSequenceControlFlag {
    /// Acceptance of this frame on the receiving end is subject to normal frame acceptance
    /// checks of FARM.
    SequenceControlledQoS = 0,
    /// Frame Acceptance Checks of FARM by the receiving end shall be bypassed.
    ExpeditedQoS = 1,
}

/// Protcol Control Command Flag.
#[derive(
    Debug, Copy, Clone, PartialEq, Eq, num_enum::TryFromPrimitive, num_enum::IntoPrimitive,
)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
#[repr(u8)]
pub enum ProtocolControlCommandFlag {
    /// Transfer frame data field contains user data.
    TfdfContainsUserData = 0,
    /// Transfer frame data field contains protocol information.
    TfdfContainsProtocolInfo = 1,
}

/// USLP error enumeration.
#[derive(Debug, Copy, Clone, PartialEq, Eq, thiserror::Error)]
pub enum UslpError {
    /// Byte conversion error.
    #[error("byte conversion error: {0}")]
    ByteConversion(#[from] ByteConversionError),
    /// Header is truncated, which is not supported.
    #[error("header is truncated, which is not supported")]
    HeaderIsTruncated,
    /// Invalid protocol ID.
    #[error("invalid protocol id: {0}")]
    InvalidProtocolId(u8),
    /// Invalid construction rule.
    #[error("invalid construction rule: {0}")]
    InvalidConstructionRule(u8),
    /// Invalid version number.
    #[error("invalid version number: {0}")]
    InvalidVersionNumber(u8),
    /// Checksum failure.
    #[error("checksum failure")]
    ChecksumFailure(u16),
}

/// FHP or LVO field is not valid for the given construction rule.
#[derive(Debug, Copy, Clone, PartialEq, Eq, thiserror::Error)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
#[error("FHP or LVO field invalid for given construction rule")]
pub struct FhpLvoError(pub ConstructionRule);

/// Invalid value for length.
#[derive(Debug, Copy, Clone, PartialEq, Eq, thiserror::Error)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
#[error("invalid value for length of the field")]
pub struct InvalidValueForLenError {
    value: u64,
    len: u3,
}

/// Primary header of a USLP transfer frame.
#[derive(Debug, Copy, Clone, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct PrimaryHeader {
    /// Spacecraft ID.
    pub spacecraft_id: u16,
    /// Source or destination identifier.
    pub source_or_dest_field: SourceOrDestField,
    /// Virtual channel ID.
    pub vc_id: u6,
    /// MAP ID.
    pub map_id: u4,
    frame_len_field: u16,
    /// Bypass sequence control flag.
    pub sequence_control_flag: BypassSequenceControlFlag,
    /// Procol control command flag.
    pub protocol_control_command_flag: ProtocolControlCommandFlag,
    /// Operational control field flag.
    pub ocf_flag: bool,
    vc_frame_count_len: u3,
    vc_frame_count: u64,
}

impl PrimaryHeader {
    /// Generic constructor.
    pub fn new(
        spacecraft_id: u16,
        source_or_dest_field: SourceOrDestField,
        vc_id: u6,
        map_id: u4,
        frame_len: u16,
    ) -> Result<Self, UslpError> {
        Ok(Self {
            spacecraft_id,
            source_or_dest_field,
            vc_id,
            map_id,
            frame_len_field: frame_len.saturating_sub(1),
            sequence_control_flag: BypassSequenceControlFlag::SequenceControlledQoS,
            protocol_control_command_flag: ProtocolControlCommandFlag::TfdfContainsUserData,
            ocf_flag: false,
            vc_frame_count_len: u3::ZERO,
            vc_frame_count: 0,
        })
    }

    /// Set the virtual channel frame count.
    pub fn set_vc_frame_count(
        &mut self,
        count_len: u3,
        count: u64,
    ) -> Result<(), InvalidValueForLenError> {
        if count > 2_u64.pow(count_len.as_u32() * 8) - 1 {
            return Err(InvalidValueForLenError {
                value: count,
                len: count_len,
            });
        }
        self.vc_frame_count_len = count_len;
        self.vc_frame_count = count;
        Ok(())
    }

    /// Virtual channel frame count.
    #[inline]
    pub fn vc_frame_count(&self) -> u64 {
        self.vc_frame_count
    }

    /// Length of the virtual channel frame count field.
    #[inline]
    pub fn vc_frame_count_len(&self) -> u3 {
        self.vc_frame_count_len
    }

    /// Parse [Self] from raw bytes.
    pub fn from_bytes(buf: &[u8]) -> Result<Self, UslpError> {
        if buf.len() < 4 {
            return Err(ByteConversionError::FromSliceTooSmall {
                found: buf.len(),
                expected: 4,
            }
            .into());
        }
        // Can only deal with regular frames for now.
        if (buf[3] & 0b1) == 1 {
            return Err(UslpError::HeaderIsTruncated);
        }
        // We could check this above, but this is a better error for the case where the user
        // tries to read a truncated frame.
        if buf.len() < 7 {
            return Err(ByteConversionError::FromSliceTooSmall {
                found: buf.len(),
                expected: 7,
            }
            .into());
        }
        let version_number = (buf[0] >> 4) & 0b1111;
        if version_number != USLP_VERSION_NUMBER {
            return Err(UslpError::InvalidVersionNumber(version_number));
        }
        let source_or_dest_field = match (buf[2] >> 3) & 1 {
            0 => SourceOrDestField::Source,
            1 => SourceOrDestField::Dest,
            _ => unreachable!(),
        };
        let vc_frame_count_len = u3::new(buf[6] & 0b111);
        if buf.len() < 7 + vc_frame_count_len.as_usize() {
            return Err(ByteConversionError::FromSliceTooSmall {
                found: buf.len(),
                expected: 7 + vc_frame_count_len.as_usize(),
            }
            .into());
        }
        let vc_frame_count = match vc_frame_count_len.value() {
            1 => buf[7] as u64,
            2 => u16::from_be_bytes(buf[7..9].try_into().unwrap()) as u64,
            4 => u32::from_be_bytes(buf[7..11].try_into().unwrap()) as u64,
            len => {
                let mut vcf_count = 0u64;
                let mut end = len;
                for byte in buf[7..7 + len as usize].iter() {
                    vcf_count |= (*byte as u64) << ((end - 1) * 8);
                    end -= 1;
                }
                vcf_count
            }
        };
        Ok(Self {
            spacecraft_id: (((buf[0] as u16) & 0b1111) << 12)
                | ((buf[1] as u16) << 4)
                | ((buf[2] as u16) >> 4) & 0b1111,
            source_or_dest_field,
            vc_id: u6::new(((buf[2] & 0b111) << 3) | (buf[3] >> 5) & 0b111),
            map_id: u4::new((buf[3] >> 1) & 0b1111),
            frame_len_field: ((buf[4] as u16) << 8) | buf[5] as u16,
            sequence_control_flag: ((buf[6] >> 7) & 0b1).try_into().unwrap(),
            protocol_control_command_flag: ((buf[6] >> 6) & 0b1).try_into().unwrap(),
            ocf_flag: ((buf[6] >> 3) & 0b1) != 0,
            vc_frame_count_len,
            vc_frame_count,
        })
    }

    /// Write primary header to bytes.
    pub fn write_to_bytes(&self, buf: &mut [u8]) -> Result<usize, ByteConversionError> {
        if buf.len() < self.len_header() {
            return Err(ByteConversionError::ToSliceTooSmall {
                found: buf.len(),
                expected: self.len_header(),
            });
        }
        buf[0] = (USLP_VERSION_NUMBER << 4) | ((self.spacecraft_id >> 12) as u8) & 0b1111;
        buf[1] = (self.spacecraft_id >> 4) as u8;
        buf[2] = (((self.spacecraft_id & 0b1111) as u8) << 4)
            | ((self.source_or_dest_field as u8) << 3)
            | (self.vc_id.as_u8() >> 3) & 0b111;
        buf[3] = ((self.vc_id.as_u8() & 0b111) << 5) | (self.map_id.as_u8() << 1);
        buf[4..6].copy_from_slice(&self.frame_len_field.to_be_bytes());
        buf[6] = ((self.sequence_control_flag as u8) << 7)
            | ((self.protocol_control_command_flag as u8) << 6)
            | ((self.ocf_flag as u8) << 3)
            | self.vc_frame_count_len.as_u8();
        let mut packet_idx = 7;
        for idx in (0..self.vc_frame_count_len.value()).rev() {
            buf[packet_idx] = ((self.vc_frame_count >> (idx * 8)) & 0xff) as u8;
            packet_idx += 1;
        }
        Ok(self.len_header())
    }

    /// Write [self] to a newly allocated [alloc::vec::Vec] and return it.
    #[cfg(feature = "alloc")]
    pub fn to_vec(&self) -> alloc::vec::Vec<u8> {
        let mut vec = alloc::vec![0; self.len_header()];
        self.write_to_bytes(&mut vec).unwrap();
        vec
    }

    /// Set frame length field.
    #[inline(always)]
    pub fn set_frame_len(&mut self, frame_len: usize) {
        // 4.1.2.7.2
        // The field contains a length count C that equals one fewer than the total octets
        // in the transfer frame.
        self.frame_len_field = frame_len.saturating_sub(1) as u16;
    }

    /// Length of primary header when written to bytes.
    #[inline(always)]
    pub fn len_header(&self) -> usize {
        7 + self.vc_frame_count_len.as_usize()
    }

    /// Length of the entire frame.
    #[inline(always)]
    pub fn len_frame(&self) -> usize {
        // 4.1.2.7.2
        // The field contains a length count C that equals one fewer than the total octets
        // in the transfer frame.
        self.frame_len_field as usize + 1
    }
}

/// Custom implementation which skips the check whether the VC frame count length field is equal.
/// Only the actual VC count value is compared.
impl PartialEq for PrimaryHeader {
    fn eq(&self, other: &Self) -> bool {
        self.spacecraft_id == other.spacecraft_id
            && self.source_or_dest_field == other.source_or_dest_field
            && self.vc_id == other.vc_id
            && self.map_id == other.map_id
            && self.frame_len_field == other.frame_len_field
            && self.sequence_control_flag == other.sequence_control_flag
            && self.protocol_control_command_flag == other.protocol_control_command_flag
            && self.ocf_flag == other.ocf_flag
            && self.vc_frame_count == other.vc_frame_count
    }
}

/// USLP protocol ID enumeration.
#[derive(Debug, PartialEq, Eq, num_enum::TryFromPrimitive, num_enum::IntoPrimitive)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
#[bitbybit::bitenum(u5, exhaustive = false)]
#[repr(u8)]
#[non_exhaustive]
pub enum UslpProtocolId {
    /// Space packets or encapsulation packets.
    SpacePacketsOrEncapsulation = 0b00000,
    /// COP-1 control commands within the TFDZ.
    Cop1ControlCommands = 0b00001,
    /// COP-P control commands within the TFDZ.
    CopPControlCommands = 0b00010,
    /// SDLS control commands within the TFDZ.
    Sdls = 0b00011,
    /// User defined octet stream.
    UserDefinedOctetStream = 0b00100,
    /// Proximity-1 Supervisory Protocol Data Units (SPDUs) within the TFDZ.
    Spdu = 0b00111,
    /// Entire fixed-length TFDZ contains idle data.
    Idle = 0b11111,
}

/// USLP construction rule enumeration.
#[derive(Debug, PartialEq, Eq, num_enum::TryFromPrimitive, num_enum::IntoPrimitive)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
#[bitbybit::bitenum(u3, exhaustive = true)]
#[repr(u8)]
pub enum ConstructionRule {
    /// Indicated fixed-length TFDZ whose contents are CCSDS packets concatenated together, which
    /// span transfer frame boundaries. The First Header Pointer (FHP) is required for packet
    /// extraction.
    PacketSpanningMultipleFrames = 0b000,
    /// Start of a MAPA SDU or VCA SDU.
    StartOfMapaSduOrVcaSdu = 0b001,
    /// Continuing portion of a MAPA SDU.
    ContinuingPortionOfMapaSdu = 0b010,
    /// Octet stream.
    OctetStream = 0b011,
    /// Starting segment.
    StartingSegment = 0b100,
    /// Continuing segment.
    ContinuingSegment = 0b101,
    /// Last segment.
    LastSegment = 0b110,
    /// No segmentation.
    NoSegmentation = 0b111,
}

impl ConstructionRule {
    /// Is the construction rule applicable to fixed-length TFDZs?
    #[inline]
    pub const fn applicable_to_fixed_len_tfdz(&self) -> bool {
        match self {
            ConstructionRule::PacketSpanningMultipleFrames => true,
            ConstructionRule::StartOfMapaSduOrVcaSdu => true,
            ConstructionRule::ContinuingPortionOfMapaSdu => true,
            ConstructionRule::OctetStream => false,
            ConstructionRule::StartingSegment => false,
            ConstructionRule::ContinuingSegment => false,
            ConstructionRule::LastSegment => false,
            ConstructionRule::NoSegmentation => false,
        }
    }
}

/// Transfer frame data field header.
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub struct TransferFrameDataFieldHeader {
    /// Construction rule for the TFDZ.
    construction_rule: ConstructionRule,
    uslp_protocol_id: UslpProtocolId,
    /// First header or last valid octet pointer. Only present if the constuction rule indicated
    /// a fixed-length TFDZ.
    fhp_or_lvo: Option<u16>,
}

impl TransferFrameDataFieldHeader {
    /// Constructor for the transfer frame data field header.
    ///
    /// This constructor also checks whether the passed first header pointer or last valid octet
    /// field is compatible to the construction rule.
    pub const fn new(
        construction_rule: ConstructionRule,
        uslp_protocol_id: UslpProtocolId,
        fhp_or_lvo: Option<u16>,
    ) -> Result<Self, FhpLvoError> {
        if (construction_rule.applicable_to_fixed_len_tfdz() && fhp_or_lvo.is_none())
            || (!construction_rule.applicable_to_fixed_len_tfdz() && fhp_or_lvo.is_some())
        {
            return Err(FhpLvoError(construction_rule));
        }
        Ok(Self {
            construction_rule,
            uslp_protocol_id,
            fhp_or_lvo,
        })
    }

    /// Length of the header when written to bytes.
    #[inline]
    pub const fn len_header(&self) -> usize {
        if self.construction_rule.applicable_to_fixed_len_tfdz() {
            3
        } else {
            1
        }
    }

    /// Construction rule.
    #[inline]
    pub const fn construction_rule(&self) -> ConstructionRule {
        self.construction_rule
    }

    /// USLP protocol ID.
    #[inline]
    pub const fn uslp_protocol_id(&self) -> UslpProtocolId {
        self.uslp_protocol_id
    }

    /// FHP or LVO field when present.
    #[inline]
    pub const fn fhp_or_lvo(&self) -> Option<u16> {
        self.fhp_or_lvo
    }

    /// Parse [Self] from raw bytes.
    pub fn from_bytes(buf: &[u8]) -> Result<Self, UslpError> {
        if buf.is_empty() {
            return Err(ByteConversionError::FromSliceTooSmall {
                found: 0,
                expected: 1,
            }
            .into());
        }
        let construction_rule = ConstructionRule::try_from((buf[0] >> 5) & 0b111)
            .map_err(|e| UslpError::InvalidConstructionRule(e.number))?;
        let mut fhp_or_lvo = None;
        if construction_rule.applicable_to_fixed_len_tfdz() {
            if buf.len() < 3 {
                return Err(ByteConversionError::FromSliceTooSmall {
                    found: buf.len(),
                    expected: 3,
                }
                .into());
            }
            fhp_or_lvo = Some(u16::from_be_bytes(buf[1..3].try_into().unwrap()));
        }
        Ok(Self {
            construction_rule,
            uslp_protocol_id: UslpProtocolId::try_from(buf[0] & 0b11111)
                .map_err(|e| UslpError::InvalidProtocolId(e.number))?,
            fhp_or_lvo,
        })
    }

    /// Write [self] to the provided byte buffer.
    pub fn write_to_bytes(&self, buf: &mut [u8]) -> Result<usize, ByteConversionError> {
        let full_len = self.len_header();
        if buf.len() < full_len {
            return Err(ByteConversionError::ToSliceTooSmall {
                found: buf.len(),
                expected: full_len,
            });
        }
        buf[0] = ((self.construction_rule as u8) << 5) | (self.uslp_protocol_id as u8 & 0b11111);
        if let Some(fhp_or_lvo) = self.fhp_or_lvo {
            buf[1..3].copy_from_slice(&fhp_or_lvo.to_be_bytes());
        }
        Ok(full_len)
    }
}

/// Simple USLP transfer frame creator.
pub struct TransferFrameCreator<'data> {
    primary_header: PrimaryHeader,
    data_field_header: TransferFrameDataFieldHeader,
    data: &'data [u8],
    operational_control_field: Option<u32>,
    has_fecf: bool,
}

impl<'data> TransferFrameCreator<'data> {
    /// Constructor.
    ///
    /// If the operational control field is present, the OCF flag in the primary header will
    /// be set accordingly. The frame length field of the [PrimaryHeader] is also updated according
    /// to the provided arguments.
    pub fn new(
        mut primary_header: PrimaryHeader,
        data_field_header: TransferFrameDataFieldHeader,
        data: &'data [u8],
        op_control_field: Option<u32>,
        has_fecf: bool,
    ) -> Self {
        if op_control_field.is_some() {
            primary_header.ocf_flag = true;
        }
        let mut frame = Self {
            primary_header,
            data_field_header,
            data,
            operational_control_field: op_control_field,
            has_fecf,
        };
        frame.primary_header.set_frame_len(frame.len_written());
        frame
    }

    /// Length of the frame when written to bytes.
    pub fn len_written(&self) -> usize {
        self.primary_header.len_header()
            + self.data_field_header.len_header()
            + self.data.len()
            + if self.operational_control_field.is_some() {
                4
            } else {
                0
            }
            + if self.has_fecf { 2 } else { 0 }
    }

    /// Write [self] to the provided byte buffer.
    pub fn write_to_bytes(&self, buf: &mut [u8]) -> Result<usize, ByteConversionError> {
        let full_len = self.len_written();
        if full_len > buf.len() {
            return Err(ByteConversionError::ToSliceTooSmall {
                found: buf.len(),
                expected: full_len,
            });
        }
        let mut current_index = 0;
        current_index += self.primary_header.write_to_bytes(buf)?;

        current_index += self
            .data_field_header
            .write_to_bytes(&mut buf[self.primary_header.len_header()..])?;
        buf[current_index..current_index + self.data.len()].copy_from_slice(self.data);
        current_index += self.data.len();

        if let Some(ocf) = self.operational_control_field {
            buf[current_index..current_index + 4].copy_from_slice(&ocf.to_be_bytes());
            current_index += 4;
        }
        if self.has_fecf {
            let mut digest = CRC_CCITT_FALSE.digest();
            digest.update(&buf[0..current_index]);
            let crc = digest.finalize();
            buf[current_index..current_index + 2].copy_from_slice(&crc.to_be_bytes());
            current_index += 2;
        }
        Ok(current_index)
    }

    /// Write [self] to a newly allocated [alloc::vec::Vec] and return it.
    #[cfg(feature = "alloc")]
    pub fn to_vec(&self) -> alloc::vec::Vec<u8> {
        let mut vec = alloc::vec![0; self.len_written()];
        self.write_to_bytes(&mut vec).unwrap();
        vec
    }
}

/// Simple USLP transfer frame reader.
///
/// Currently, only insert zone lengths of 0 are supported.
#[derive(Debug)]
pub struct TransferFrameReader<'buf> {
    primary_header: PrimaryHeader,
    data_field_header: TransferFrameDataFieldHeader,
    data: &'buf [u8],
    operational_control_field: Option<u32>,
}

impl<'buf> TransferFrameReader<'buf> {
    /// This function assumes an insert zone length of 0.
    pub fn from_bytes(
        buf: &'buf [u8],
        has_fecf: bool,
    ) -> Result<TransferFrameReader<'buf>, UslpError> {
        let primary_header = PrimaryHeader::from_bytes(buf)?;
        if primary_header.len_frame() > buf.len() {
            return Err(ByteConversionError::FromSliceTooSmall {
                expected: primary_header.len_frame(),
                found: buf.len(),
            }
            .into());
        }
        let data_field_header =
            TransferFrameDataFieldHeader::from_bytes(&buf[primary_header.len_header()..])?;
        let data_idx = primary_header.len_header() + data_field_header.len_header();
        let frame_len = primary_header.len_frame();
        let mut operational_control_field = None;
        let mut data_len = frame_len - data_idx;
        if has_fecf {
            data_len -= 2;
        }
        if primary_header.ocf_flag {
            data_len -= 4;
            operational_control_field = Some(u32::from_be_bytes(
                buf[data_idx + data_len..data_idx + data_len + 4]
                    .try_into()
                    .unwrap(),
            ));
        }
        if has_fecf {
            let mut digest = CRC_CCITT_FALSE.digest();
            digest.update(&buf[0..frame_len]);
            if digest.finalize() != 0 {
                return Err(UslpError::ChecksumFailure(u16::from_be_bytes(
                    buf[frame_len - 2..frame_len].try_into().unwrap(),
                )));
            }
        }
        Ok(Self {
            primary_header,
            data_field_header,
            data: buf[data_idx..data_idx + data_len].try_into().unwrap(),
            operational_control_field,
        })
    }

    /// Length of the entire frame.
    #[inline]
    pub fn len_frame(&self) -> usize {
        self.primary_header.len_frame()
    }

    /// Primary header.
    #[inline]
    pub fn primary_header(&self) -> &PrimaryHeader {
        &self.primary_header
    }

    /// Transfer frame data field header.
    #[inline]
    pub fn data_field_header(&self) -> &TransferFrameDataFieldHeader {
        &self.data_field_header
    }

    /// Data contained in the transfer frame data field.
    #[inline]
    pub fn data(&self) -> &'buf [u8] {
        self.data
    }

    /// Operational control field when present.
    #[inline]
    pub fn operational_control_field(&self) -> Option<u32> {
        self.operational_control_field
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn common_basic_check(buf: &[u8]) {
        assert_eq!(buf[0] >> 4, USLP_VERSION_NUMBER);
        // First four bits SCID.
        assert_eq!(buf[0] & 0b1111, 0b1010);
        // Next eight bits SCID.
        assert_eq!(buf[1], 0b01011100);
        // Last four bits SCID.
        assert_eq!(buf[2] >> 4, 0b0011);
        assert_eq!((buf[2] >> 3) & 0b1, SourceOrDestField::Dest as u8);
        // First three bits VCID.
        assert_eq!(buf[2] & 0b111, 0b110);
        // Last three bits VCID.
        assert_eq!(buf[3] >> 5, 0b101);
        // MAP ID
        assert_eq!((buf[3] >> 1) & 0b1111, 0b1010);
        // End of primary header flag
        assert_eq!(buf[3] & 0b1, 0);
        assert_eq!(u16::from_be_bytes(buf[4..6].try_into().unwrap()), 0x2344);
    }

    #[test]
    fn test_basic_0() {
        let mut buf: [u8; 8] = [0; 8];
        // Should be all zeros after writing.
        buf[6] = 0xff;
        let primary_header = PrimaryHeader::new(
            0b10100101_11000011,
            SourceOrDestField::Dest,
            u6::new(0b110101),
            u4::new(0b1010),
            0x2345,
        )
        .unwrap();
        // Virtual channel count 0.
        assert_eq!(primary_header.write_to_bytes(&mut buf).unwrap(), 7);
        common_basic_check(&buf);
        assert_eq!(primary_header.vc_frame_count_len().value(), 0);
        assert_eq!(primary_header.vc_frame_count(), 0);
        // Bypass / Sequence Control Flag.
        assert_eq!(
            (buf[6] >> 7) & 0b1,
            BypassSequenceControlFlag::SequenceControlledQoS as u8
        );
        // Protocol Control Command Flag.
        assert_eq!(
            (buf[6] >> 6) & 0b1,
            ProtocolControlCommandFlag::TfdfContainsUserData as u8
        );
        // OCF flag.
        assert_eq!((buf[6] >> 3) & 0b1, false as u8);
        // VCF count length.
        assert_eq!(buf[6] & 0b111, 0);
    }

    #[test]
    fn test_basic_1() {
        let mut buf: [u8; 16] = [0; 16];
        // Should be all zeros after writing.
        buf[6] = 0xff;
        let mut primary_header = PrimaryHeader::new(
            0b10100101_11000011,
            SourceOrDestField::Dest,
            u6::new(0b110101),
            u4::new(0b1010),
            0x2345,
        )
        .unwrap();
        primary_header.sequence_control_flag = BypassSequenceControlFlag::ExpeditedQoS;
        primary_header.protocol_control_command_flag =
            ProtocolControlCommandFlag::TfdfContainsProtocolInfo;
        primary_header.ocf_flag = true;
        primary_header
            .set_vc_frame_count(u3::new(4), 0x12345678)
            .unwrap();
        // Virtual channel count 4.
        assert_eq!(primary_header.write_to_bytes(&mut buf).unwrap(), 11);
        assert_eq!(primary_header.vc_frame_count_len().value(), 4);
        assert_eq!(primary_header.vc_frame_count(), 0x12345678);
        common_basic_check(&buf);
        // Bypass / Sequence Control Flag.
        assert_eq!(
            (buf[6] >> 7) & 0b1,
            BypassSequenceControlFlag::ExpeditedQoS as u8
        );
        // Protocol Control Command Flag.
        assert_eq!(
            (buf[6] >> 6) & 0b1,
            ProtocolControlCommandFlag::TfdfContainsProtocolInfo as u8
        );
        // OCF flag.
        assert_eq!((buf[6] >> 3) & 0b1, true as u8);
        // VCF count length.
        assert_eq!(buf[6] & 0b111, 4);
        assert_eq!(
            u32::from_be_bytes(buf[7..11].try_into().unwrap()),
            0x12345678
        );
    }

    #[test]
    fn test_vcf_count_len_two() {
        let mut buf: [u8; 16] = [0; 16];
        // Should be all zeros after writing.
        buf[6] = 0xff;
        let mut primary_header = PrimaryHeader::new(
            0b10100101_11000011,
            SourceOrDestField::Dest,
            u6::new(0b110101),
            u4::new(0b1010),
            0x2345,
        )
        .unwrap();
        primary_header.set_vc_frame_count(u3::new(2), 5).unwrap();
        assert_eq!(primary_header.vc_frame_count_len().value(), 2);
        assert_eq!(primary_header.vc_frame_count(), 5);
        assert_eq!(primary_header.write_to_bytes(&mut buf).unwrap(), 9);
        assert_eq!(buf[6] & 0b111, 2);
        assert_eq!(u16::from_be_bytes(buf[7..9].try_into().unwrap()), 5);

        let primary_header = PrimaryHeader::from_bytes(&buf).unwrap();
        assert_eq!(primary_header.vc_frame_count_len().value(), 2);
        assert_eq!(primary_header.vc_frame_count(), 5);
    }

    #[test]
    fn test_vcf_count_len_one() {
        let mut buf: [u8; 16] = [0; 16];
        // Should be all zeros after writing.
        buf[6] = 0xff;
        let mut primary_header = PrimaryHeader::new(
            0b10100101_11000011,
            SourceOrDestField::Dest,
            u6::new(0b110101),
            u4::new(0b1010),
            0x2345,
        )
        .unwrap();
        primary_header.set_vc_frame_count(u3::new(1), 255).unwrap();
        assert_eq!(primary_header.vc_frame_count_len().value(), 1);
        assert_eq!(primary_header.vc_frame_count(), 255);
        assert_eq!(primary_header.write_to_bytes(&mut buf).unwrap(), 8);
        assert_eq!(buf[6] & 0b111, 1);
        assert_eq!(buf[7], 255);

        let primary_header = PrimaryHeader::from_bytes(&buf).unwrap();
        assert_eq!(primary_header.vc_frame_count_len().value(), 1);
        assert_eq!(primary_header.vc_frame_count(), 255);
    }

    #[test]
    fn test_reading_0() {
        let mut buf: [u8; 8] = [0; 8];
        let primary_header = PrimaryHeader::new(
            0b10100101_11000011,
            SourceOrDestField::Dest,
            u6::new(0b110101),
            u4::new(0b1010),
            0x2345,
        )
        .unwrap();
        assert_eq!(primary_header.write_to_bytes(&mut buf).unwrap(), 7);
        let parsed_header = PrimaryHeader::from_bytes(&buf).unwrap();
        assert_eq!(parsed_header, primary_header);
    }

    #[test]
    fn test_reading_1() {
        let mut buf: [u8; 16] = [0; 16];
        let mut primary_header = PrimaryHeader::new(
            0b10100101_11000011,
            SourceOrDestField::Dest,
            u6::new(0b110101),
            u4::new(0b1010),
            0x2345,
        )
        .unwrap();
        primary_header.sequence_control_flag = BypassSequenceControlFlag::ExpeditedQoS;
        primary_header.protocol_control_command_flag =
            ProtocolControlCommandFlag::TfdfContainsProtocolInfo;
        primary_header.ocf_flag = true;
        primary_header
            .set_vc_frame_count(u3::new(4), 0x12345678)
            .unwrap();
        assert_eq!(primary_header.write_to_bytes(&mut buf).unwrap(), 11);
        let parsed_header = PrimaryHeader::from_bytes(&buf).unwrap();
        assert_eq!(parsed_header, primary_header);
    }

    #[test]
    fn test_invalid_vc_count() {
        let mut primary_header = PrimaryHeader::new(
            0b10100101_11000011,
            SourceOrDestField::Dest,
            u6::new(0b110101),
            u4::new(0b1010),
            0x2345,
        )
        .unwrap();
        matches!(
            primary_header.set_vc_frame_count(u3::ZERO, 1).unwrap_err(),
            InvalidValueForLenError {
                value: 1,
                len: u3::ZERO
            }
        );
        let len = u3::new(1);
        assert_eq!(
            primary_header
                .set_vc_frame_count(u3::new(1), 256)
                .unwrap_err(),
            InvalidValueForLenError { value: 256, len }
        );
    }

    #[test]
    fn test_frame_parser() {
        let mut buf: [u8; 32] = [0; 32];
        // Build a variable frame manually.
        let mut primary_header = PrimaryHeader::new(
            0x01,
            SourceOrDestField::Dest,
            u6::new(0b110101),
            u4::new(0b1010),
            0,
        )
        .unwrap();
        let header_len = primary_header.len_header();
        buf[header_len] = ((ConstructionRule::NoSegmentation as u8) << 5)
            | (UslpProtocolId::UserDefinedOctetStream as u8) & 0b11111;
        buf[header_len + 1] = 0x42;
        // 1 byte TFDH, 1 byte data, 2 bytes CRC.
        primary_header.set_frame_len(header_len + 4);
        primary_header.write_to_bytes(&mut buf).unwrap();
        // Calculate and write CRC16.
        let mut digest = CRC_CCITT_FALSE.digest();
        digest.update(&buf[0..header_len + 2]);
        buf[header_len + 2..header_len + 4].copy_from_slice(&digest.finalize().to_be_bytes());
        // Now parse the frame.
        let frame = TransferFrameReader::from_bytes(&buf, true).unwrap();
        assert_eq!(*frame.primary_header(), primary_header);
        assert_eq!(frame.data().len(), 1);
        assert_eq!(frame.data()[0], 0x42);
        assert_eq!(
            frame.data_field_header().uslp_protocol_id(),
            UslpProtocolId::UserDefinedOctetStream
        );
        assert_eq!(
            frame.data_field_header().construction_rule(),
            ConstructionRule::NoSegmentation
        );
        assert!(frame.data_field_header().fhp_or_lvo().is_none());
        assert_eq!(frame.len_frame(), 11);
        assert!(frame.operational_control_field().is_none());
    }

    #[test]
    fn test_frame_parser_invalid_checksum() {
        let mut buf: [u8; 32] = [0; 32];
        // Build a variable frame manually.
        let mut primary_header = PrimaryHeader::new(
            0x01,
            SourceOrDestField::Dest,
            u6::new(0b110101),
            u4::new(0b1010),
            0,
        )
        .unwrap();
        let header_len = primary_header.len_header();
        buf[header_len] = ((ConstructionRule::NoSegmentation as u8) << 5)
            | (UslpProtocolId::UserDefinedOctetStream as u8) & 0b11111;
        buf[header_len + 1] = 0x42;
        // 1 byte TFDH, 1 byte data, 2 bytes CRC.
        primary_header.set_frame_len(header_len + 4);
        primary_header.write_to_bytes(&mut buf).unwrap();
        // Now parse the frame without having calculated the checksum.
        match TransferFrameReader::from_bytes(&buf, true) {
            Ok(_) => panic!("transfer frame read call did not fail"),
            Err(e) => {
                assert_eq!(e, UslpError::ChecksumFailure(0));
            }
        }
    }

    #[test]
    fn test_frame_parser_buf_too_small() {
        let mut buf: [u8; 32] = [0; 32];
        // Build a variable frame manually.
        let mut primary_header = PrimaryHeader::new(
            0x01,
            SourceOrDestField::Dest,
            u6::new(0b110101),
            u4::new(0b1010),
            0,
        )
        .unwrap();
        let header_len = primary_header.len_header();
        buf[header_len] = ((ConstructionRule::NoSegmentation as u8) << 5)
            | (UslpProtocolId::UserDefinedOctetStream as u8) & 0b11111;
        buf[header_len + 1] = 0x42;
        // 1 byte TFDH, 1 byte data, 2 bytes CRC.
        primary_header.set_frame_len(header_len + 4);
        primary_header.write_to_bytes(&mut buf).unwrap();
        // Now parse the frame.
        let error = TransferFrameReader::from_bytes(&buf[0..7], true).unwrap_err();
        assert_eq!(
            error,
            ByteConversionError::FromSliceTooSmall {
                expected: primary_header.len_frame(),
                found: 7
            }
            .into()
        );
    }

    #[test]
    fn test_from_bytes_too_small_0() {
        let buf: [u8; 3] = [0; 3];
        assert_eq!(
            PrimaryHeader::from_bytes(&buf).unwrap_err(),
            ByteConversionError::FromSliceTooSmall {
                found: 3,
                expected: 4
            }
            .into()
        );
    }

    #[test]
    fn test_from_bytes_too_small_1() {
        let buf: [u8; 6] = [0; 6];
        assert_eq!(
            PrimaryHeader::from_bytes(&buf).unwrap_err(),
            ByteConversionError::FromSliceTooSmall {
                found: 6,
                expected: 7
            }
            .into()
        );
    }

    #[test]
    fn test_from_bytes_truncated_not_supported() {
        let mut buf: [u8; 7] = [0; 7];
        let primary_header = PrimaryHeader::new(
            0x01,
            SourceOrDestField::Dest,
            u6::new(0b110101),
            u4::new(0b1010),
            0,
        )
        .unwrap();
        primary_header.write_to_bytes(&mut buf).unwrap();
        // Set truncated header flag manually.
        buf[3] |= 0b1;
        assert_eq!(
            PrimaryHeader::from_bytes(&buf).unwrap_err(),
            UslpError::HeaderIsTruncated
        );
    }

    #[test]
    fn test_from_bytes_too_small_2() {
        let mut buf: [u8; 16] = [0; 16];
        // Should be all zeros after writing.
        buf[6] = 0xff;
        let mut primary_header = PrimaryHeader::new(
            0b10100101_11000011,
            SourceOrDestField::Dest,
            u6::new(0b110101),
            u4::new(0b1010),
            0x2345,
        )
        .unwrap();
        primary_header
            .set_vc_frame_count(u3::new(4), 0x12345678)
            .unwrap();
        primary_header.write_to_bytes(&mut buf).unwrap();

        assert_eq!(
            PrimaryHeader::from_bytes(&buf[0..8]).unwrap_err(),
            UslpError::ByteConversion(ByteConversionError::FromSliceTooSmall {
                found: 8,
                expected: 11
            })
        );
    }

    #[test]
    fn test_invalid_version_number() {
        let mut buf: [u8; 7] = [0; 7];
        let primary_header = PrimaryHeader::new(
            0x01,
            SourceOrDestField::Dest,
            u6::new(0b110101),
            u4::new(0b1010),
            0,
        )
        .unwrap();
        primary_header.write_to_bytes(&mut buf).unwrap();
        buf[0] &= 0b00001111;
        assert_eq!(
            PrimaryHeader::from_bytes(&buf).unwrap_err(),
            UslpError::InvalidVersionNumber(0)
        );
    }

    #[test]
    fn test_primary_header_buf_too_small() {
        let primary_header = PrimaryHeader::new(
            0b10100101_11000011,
            SourceOrDestField::Dest,
            u6::new(0b110101),
            u4::new(0b1010),
            0x2345,
        )
        .unwrap();
        if let Err(ByteConversionError::ToSliceTooSmall { found, expected }) =
            primary_header.write_to_bytes(&mut [0; 4])
        {
            assert_eq!(found, 4);
            assert_eq!(expected, 7);
        } else {
            panic!("writing primary header did not fail or failed with wrong error");
        }
    }

    #[test]
    fn test_applicability_contr_rules() {
        assert!(ConstructionRule::PacketSpanningMultipleFrames.applicable_to_fixed_len_tfdz());
        assert!(ConstructionRule::StartOfMapaSduOrVcaSdu.applicable_to_fixed_len_tfdz());
        assert!(ConstructionRule::ContinuingPortionOfMapaSdu.applicable_to_fixed_len_tfdz());
        assert!(!ConstructionRule::OctetStream.applicable_to_fixed_len_tfdz());
        assert!(!ConstructionRule::StartingSegment.applicable_to_fixed_len_tfdz());
        assert!(!ConstructionRule::ContinuingSegment.applicable_to_fixed_len_tfdz());
        assert!(!ConstructionRule::LastSegment.applicable_to_fixed_len_tfdz());
        assert!(!ConstructionRule::NoSegmentation.applicable_to_fixed_len_tfdz());
    }

    #[test]
    fn test_header_len_correctness() {
        let mut tfdh = TransferFrameDataFieldHeader {
            construction_rule: ConstructionRule::PacketSpanningMultipleFrames,
            uslp_protocol_id: UslpProtocolId::UserDefinedOctetStream,
            fhp_or_lvo: Some(0),
        };
        assert_eq!(tfdh.len_header(), 3);
        tfdh = TransferFrameDataFieldHeader {
            construction_rule: ConstructionRule::StartOfMapaSduOrVcaSdu,
            uslp_protocol_id: UslpProtocolId::UserDefinedOctetStream,
            fhp_or_lvo: Some(0),
        };
        assert_eq!(tfdh.len_header(), 3);
        tfdh = TransferFrameDataFieldHeader {
            construction_rule: ConstructionRule::ContinuingPortionOfMapaSdu,
            uslp_protocol_id: UslpProtocolId::UserDefinedOctetStream,
            fhp_or_lvo: Some(0),
        };
        assert_eq!(tfdh.len_header(), 3);
        tfdh = TransferFrameDataFieldHeader {
            construction_rule: ConstructionRule::OctetStream,
            uslp_protocol_id: UslpProtocolId::UserDefinedOctetStream,
            fhp_or_lvo: None,
        };
        assert_eq!(tfdh.len_header(), 1);
    }

    #[test]
    fn test_frame_data_field_header_from_bytes_too_small() {
        let buf: [u8; 0] = [];
        assert_eq!(
            TransferFrameDataFieldHeader::from_bytes(&buf).unwrap_err(),
            ByteConversionError::FromSliceTooSmall {
                found: 0,
                expected: 1
            }
            .into()
        );
    }

    #[test]
    fn test_frame_creator() {
        // Relying on the reader implementation for now.
        let mut primary_header = PrimaryHeader::new(
            0x1234,
            SourceOrDestField::Source,
            u6::new(0b101010),
            u4::new(0b0101),
            0,
        )
        .unwrap();
        let data_field_header = TransferFrameDataFieldHeader {
            construction_rule: ConstructionRule::NoSegmentation,
            uslp_protocol_id: UslpProtocolId::UserDefinedOctetStream,
            fhp_or_lvo: None,
        };
        let data = [1, 2, 3, 4];
        let frame_creator =
            TransferFrameCreator::new(primary_header, data_field_header, &data, None, true);
        let mut buf: [u8; 64] = [0; 64];
        assert_eq!(frame_creator.len_written(), 14);
        let written = frame_creator.write_to_bytes(&mut buf).unwrap();
        assert_eq!(written, 14);
        assert_eq!(written, frame_creator.len_written());
        let reader = TransferFrameReader::from_bytes(&buf, true).unwrap();
        primary_header.set_frame_len(written);
        assert_eq!(reader.primary_header(), &primary_header);
        assert_eq!(reader.data_field_header(), &data_field_header);
        assert_eq!(reader.data(), &data);
        assert!(reader.operational_control_field().is_none());
        assert_eq!(reader.len_frame(), 14);
    }

    #[test]
    fn test_frame_creator_using_vec() {
        // Relying on the reader implementation for now.
        let mut primary_header = PrimaryHeader::new(
            0x1234,
            SourceOrDestField::Source,
            u6::new(0b101010),
            u4::new(0b0101),
            0,
        )
        .unwrap();
        let data_field_header = TransferFrameDataFieldHeader {
            construction_rule: ConstructionRule::NoSegmentation,
            uslp_protocol_id: UslpProtocolId::UserDefinedOctetStream,
            fhp_or_lvo: None,
        };
        let data = [1, 2, 3, 4];
        let frame_creator =
            TransferFrameCreator::new(primary_header, data_field_header, &data, None, true);
        assert_eq!(frame_creator.len_written(), 14);
        let vec = frame_creator.to_vec();
        assert_eq!(vec.len(), 14);
        assert_eq!(vec.len(), frame_creator.len_written());
        let reader = TransferFrameReader::from_bytes(&vec, true).unwrap();
        primary_header.set_frame_len(vec.len());
        assert_eq!(reader.primary_header(), &primary_header);
        assert_eq!(reader.data_field_header(), &data_field_header);
        assert_eq!(reader.data(), &data);
        assert!(reader.operational_control_field().is_none());
        assert_eq!(reader.len_frame(), 14);
    }

    #[test]
    fn test_frame_creator_with_op_ctrl() {
        // Relying on the reader implementation for now.
        let mut primary_header = PrimaryHeader::new(
            0x1234,
            SourceOrDestField::Source,
            u6::new(0b101010),
            u4::new(0b0101),
            0,
        )
        .unwrap();
        let data_field_header = TransferFrameDataFieldHeader::new(
            ConstructionRule::NoSegmentation,
            UslpProtocolId::UserDefinedOctetStream,
            None,
        )
        .unwrap();
        let data = [1, 2, 3, 4];
        let frame_creator =
            TransferFrameCreator::new(primary_header, data_field_header, &data, Some(4), true);
        let mut buf: [u8; 64] = [0; 64];
        assert_eq!(frame_creator.len_written(), 18);
        let written = frame_creator.write_to_bytes(&mut buf).unwrap();
        assert_eq!(written, 18);
        assert_eq!(written, frame_creator.len_written());
        let reader = TransferFrameReader::from_bytes(&buf, true).unwrap();
        primary_header.set_frame_len(written);
        primary_header.ocf_flag = true;
        assert_eq!(reader.primary_header(), &primary_header);
        assert_eq!(reader.data_field_header(), &data_field_header);
        assert_eq!(reader.data(), &data);
        assert_eq!(reader.operational_control_field().unwrap(), 4);
        assert_eq!(reader.len_frame(), 18);
    }
}
