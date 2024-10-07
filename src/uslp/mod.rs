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

#[cfg(test)]
mod tests {}
