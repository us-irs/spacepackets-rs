use crate::ByteConversionError;

const USLP_VERSION_NUMBER: u8 = 0b1100;

/// Identifies the association of the data contained in the transfer frame.
#[derive(
    Debug, Copy, Clone, PartialEq, Eq, num_enum::TryFromPrimitive, num_enum::IntoPrimitive,
)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
#[repr(u8)]
pub enum SourceOrDestField {
    /// SCID refers to the source of the transfer frame.
    Source = 0,
    /// SCID refers to the destination of the transfer frame.
    Dest = 1,
}

#[derive(
    Debug, Copy, Clone, PartialEq, Eq, num_enum::TryFromPrimitive, num_enum::IntoPrimitive,
)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
#[repr(u8)]
pub enum BypassSequenceControlFlag {
    /// Acceptance of this frame on the receiving end is subject to normal frame acceptance
    /// checks of FARM.
    SequenceControlledQoS = 0,
    /// Frame Acceptance Checks of FARM by the receiving end shall be bypassed.
    ExpeditedQoS = 1,
}

#[derive(
    Debug, Copy, Clone, PartialEq, Eq, num_enum::TryFromPrimitive, num_enum::IntoPrimitive,
)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
#[repr(u8)]
pub enum ProtocolControlCommandFlag {
    TfdfContainsUserData,
    TfdfContainsProtocolInfo,
}

#[derive(Debug, Copy, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct PrimaryHeader {
    spacecraft_id: u16,
    source_or_dest_field: SourceOrDestField,
    vc_id: u8,
    map_id: u8,
    frame_len: u16,
    sequence_control_flag: BypassSequenceControlFlag,
    protocol_control_command_flag: ProtocolControlCommandFlag,
    ocf_flag: bool,
    vc_frame_count_len: u8,
    vc_frame_count: u64,
}

#[derive(Debug)]
pub enum UslpError {
    ByteConversion(ByteConversionError),
    HeaderIsTruncated,
    InvalidVersionNumber(u8),
}

impl From<ByteConversionError> for UslpError {
    fn from(value: ByteConversionError) -> Self {
        Self::ByteConversion(value)
    }
}

impl PrimaryHeader {
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
        let vc_frame_count_len = buf[6] & 0b111;
        if buf.len() < 7 + vc_frame_count_len as usize {
            return Err(ByteConversionError::FromSliceTooSmall {
                found: buf.len(),
                expected: 7 + vc_frame_count_len as usize,
            }
            .into());
        }
        let vc_frame_count = match vc_frame_count_len {
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
            vc_id: ((buf[2] & 0b111) << 3) | (buf[3] >> 5) & 0b111,
            map_id: (buf[3] >> 1) & 0b1111,
            frame_len: ((buf[4] as u16) << 8) | buf[5] as u16,
            sequence_control_flag: ((buf[6] >> 7) & 0b1).try_into().unwrap(),
            protocol_control_command_flag: ((buf[6] >> 6) & 0b1).try_into().unwrap(),
            ocf_flag: ((buf[6] >> 3) & 0b1) != 0,
            vc_frame_count_len,
            vc_frame_count,
        })
    }
}

#[derive(Debug, Copy, Clone, PartialEq, Eq, num_enum::TryFromPrimitive, num_enum::IntoPrimitive)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
#[repr(u8)]
#[non_exhaustive]
pub enum UslpProtocolId {
    SpacePacketsOrEncapsulation = 0b00000,
    /// COP-1 control commands within the TFDZ.
    Cop1ControlCommands = 0b00001,
    /// COP-P control commands within the TFDZ.
    CopPControlCommands = 0b00010,
    /// SDLS control commands within the TFDZ.
    Sdls = 0b00011,
    UserDefinedOctetStream = 0b00100,
    /// Proximity-1 Supervisory Protocol Data Units (SPDUs) within the TFDZ.
    Spdu = 0b00111,
    /// Entire fixed-length TFDZ contains idle data.
    Idle = 0b11111,
}

#[derive(
    Debug, Copy, Clone, PartialEq, Eq, num_enum::TryFromPrimitive, num_enum::IntoPrimitive,
)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
#[repr(u8)]
pub enum ConstructionRule {
    /// Indicated fixed-length TFDZ whose contents are CCSDS packets concatenated together, which
    /// span transfer frame boundaries. The First Header Pointer (FHP) is required for packet
    /// extraction.
    PacketSpanningMultipleFrames = 0b000,
    StartOfMapaSduOrVcaSdu = 0b001,
    ContinuingPortionOfMapaSdu = 0b010,
    OctetStream = 0b011,
    StartingSegment = 0b100,
    ContinuingSegment = 0b101,
    LastSegment = 0b110,
    NoSegmentation = 0b111,
}

impl ConstructionRule {
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

pub struct TransferFrameDataFieldHeader {
    /// Construction rule for the TFDZ.
    construction_rule: ConstructionRule,
    uslp_protocol_id: UslpProtocolId,
    /// First header or last valid octet pointer
    fhp_or_lvo: Option<u16>,
}

impl TransferFrameDataFieldHeader {

    pub fn construction_rule(&self) -> ConstructionRule {
        self.construction_rule
    }

    pub fn uslp_protocol_id(&self) -> UslpProtocolId {
        self.uslp_protocol_id
    }

    pub fn fhp_or_lvo(&self) -> Option<u16> {
        self.fhp_or_lvo
    }

    pub fn from_bytes(buf: &[u8]) -> Option<Self> {
        if buf.len() < 1 {
            return None;
        }
        let construction_rule = ConstructionRule::try_from((buf[0] >> 5) & 0b111).ok()?;
        let mut fhp_or_lvo = None;
        if construction_rule.applicable_to_fixed_len_tfdz() {
            if buf.len() < 3 {
                return None;
            }
            fhp_or_lvo = Some(u16::from_be_bytes(buf[1..3].try_into().unwrap()));
        }
        Some(Self {
            construction_rule,
            uslp_protocol_id: (buf[0] & 0b11111).try_into().ok()?,
            fhp_or_lvo,
        })
    }
}

pub struct TransferFrameReader<'buf> {
    header: PrimaryHeader,
    data_field_header: TransferFrameDataFieldHeader,
    data: &'buf [u8],
    operational_control_field: u32,
}

impl<'buf> TransferFrameReader<'buf> {
    /// This function assumes an insert zone length of 0
    pub fn from_bytes(buf: &[u8], has_fecf: bool) -> Result<Self, UslpError> {
        let primary_header = PrimaryHeader::from_bytes(buf)?;
        Ok(Self {
            header: primary_header,
            data_field_header: todo!(),
            data: todo!(),
            operational_control_field: todo!(),
        })
    }
}

#[cfg(test)]
mod tests {}
