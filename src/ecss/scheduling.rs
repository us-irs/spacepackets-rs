//! PUS Service 11 Scheduling
use core::fmt::Display;

use num_enum::{IntoPrimitive, TryFromPrimitive};
#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

use crate::{
    time::{TimeWriter, TimestampError},
    util::ToBeBytes,
    ByteConversionError,
};

use super::{PusError, WritablePusPacket};

#[derive(Debug, PartialEq, Eq, Copy, Clone, IntoPrimitive, TryFromPrimitive)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[repr(u8)]
pub enum Subservice {
    // Core subservices
    TcEnableScheduling = 1,
    TcDisableScheduling = 2,
    TcResetScheduling = 3,
    TcInsertActivity = 4,
    TcDeleteActivityByRequestId = 5,
    TcDeleteActivitiesByFilter = 6,

    // Time shift subservices
    TcTimeShiftActivityWithRequestId = 7,
    TcTimeShiftActivitiesByFilter = 8,
    TcTimeShiftAll = 15,

    // Reporting subservices
    TcDetailReportByRequestId = 9,
    TmDetailReport = 10,
    TcDetailReportByFilter = 11,
    TcSummaryReportByRequestId = 12,
    TmSummaryReport = 13,
    TcSummaryReportByFilter = 14,
    TcDetailReportAll = 16,
    TcSummaryReportAll = 17,

    // Subschedule subservices
    TcReportSubscheduleStatus = 18,
    TmReportSubscheduleStatus = 19,
    TcEnableSubschedule = 20,
    TcDisableSubschedule = 21,

    // Group subservices
    TcCreateScheduleGroup = 22,
    TcDeleteScheduleGroup = 23,
    TcEnableScheduleGroup = 24,
    TcDisableScheduleGroup = 25,
    TcReportAllGroupsStatus = 26,
    TmReportAllGroupsStatus = 27,
}

/// This status applies to sub-schedules and groups as well as specified in ECSS-E-ST-70-41C 8.11.3
#[derive(Debug, PartialEq, Eq, Copy, Clone)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub enum SchedStatus {
    Disabled = 0,
    Enabled = 1,
}

impl From<bool> for SchedStatus {
    fn from(value: bool) -> Self {
        if value {
            SchedStatus::Enabled
        } else {
            SchedStatus::Disabled
        }
    }
}

/// Time window types as specified in  ECSS-E-ST-70-41C 8.11.3
#[derive(Debug, PartialEq, Eq, Copy, Clone)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub enum TimeWindowType {
    SelectAll = 0,
    TimeTagToTimeTag = 1,
    FromTimeTag = 2,
    ToTimeTag = 3,
}

#[derive(Debug, PartialEq, Eq, Copy, Clone)]
pub enum ScheduleTcGenerationError {
    ByteConversionError(ByteConversionError),
    TimestampError(TimestampError),
    PusError(PusError),
}

impl From<ByteConversionError> for ScheduleTcGenerationError {
    fn from(error: ByteConversionError) -> Self {
        Self::ByteConversionError(error)
    }
}

impl From<TimestampError> for ScheduleTcGenerationError {
    fn from(error: TimestampError) -> Self {
        Self::TimestampError(error)
    }
}

impl From<PusError> for ScheduleTcGenerationError {
    fn from(error: PusError) -> Self {
        Self::PusError(error)
    }
}

impl Display for ScheduleTcGenerationError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let const_str = "pus schedule tc generation:";
        match self {
            Self::PusError(e) => {
                write!(f, "{const_str} {e}")
            }
            Self::ByteConversionError(e) => {
                write!(f, "{const_str} {e}")
            }
            Self::TimestampError(e) => {
                write!(f, "{const_str} {e}")
            }
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for ScheduleTcGenerationError {}

/// Helper function to generate the application data for a PUS telecommand to insert an
/// activity into a time-based schedule according to ECSS-E-ST-70-41C 8.11.2.4
///
/// Please note that the N field is set to a [u16] unsigned bytefield with the value 1.
pub fn generate_insert_telecommand_app_data(
    buf: &mut [u8],
    release_time: &impl TimeWriter,
    request: &impl WritablePusPacket,
) -> Result<usize, ScheduleTcGenerationError> {
    let required_len = 2 + release_time.len_written() + request.len_written();
    if required_len > buf.len() {
        return Err(ByteConversionError::ToSliceTooSmall {
            found: buf.len(),
            expected: required_len,
        }
        .into());
    }
    let mut current_len = 0;
    let n = 1_u16;
    buf[current_len..current_len + 2].copy_from_slice(&n.to_be_bytes());
    current_len += 2;
    current_len += release_time
        .write_to_bytes(&mut buf[current_len..current_len + release_time.len_written()])?;
    current_len +=
        request.write_to_bytes(&mut buf[current_len..current_len + request.len_written()])?;
    Ok(current_len)
}

/// This function is similar to [generate_insert_telecommand_app_data] but returns the application
/// data as a [alloc::vec::Vec].
#[cfg(feature = "alloc")]
pub fn generate_insert_telecommand_app_data_as_vec(
    release_time: &impl TimeWriter,
    request: &impl WritablePusPacket,
) -> Result<alloc::vec::Vec<u8>, ScheduleTcGenerationError> {
    let mut vec = alloc::vec::Vec::new();
    vec.extend_from_slice(&1_u16.to_be_bytes());
    vec.append(&mut release_time.to_vec()?);
    vec.append(&mut request.to_vec()?);
    Ok(vec)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[cfg(feature = "serde")]
    use crate::tests::generic_serde_test;
    use crate::{
        ecss::tc::{PusTcCreator, PusTcReader, PusTcSecondaryHeader},
        time::cds,
        PacketId, PacketSequenceCtrl, PacketType, SpHeader,
    };

    #[test]
    fn test_bool_conv_0() {
        let enabled = true;
        let status: SchedStatus = enabled.into();
        assert_eq!(status, SchedStatus::Enabled)
    }

    #[test]
    fn test_bool_conv_1() {
        let enabled = false;
        let status: SchedStatus = enabled.into();
        assert_eq!(status, SchedStatus::Disabled)
    }

    #[test]
    fn test_conv_into_u8() {
        let subservice: u8 = Subservice::TcCreateScheduleGroup.into();
        assert_eq!(subservice, 22);
    }

    #[test]
    fn test_conv_from_u8() {
        let subservice: Subservice = 22u8.try_into().unwrap();
        assert_eq!(subservice, Subservice::TcCreateScheduleGroup);
    }

    #[test]
    #[cfg(feature = "serde")]
    fn test_serde_subservice_id() {
        generic_serde_test(Subservice::TcEnableScheduling);
    }

    #[test]
    #[cfg(feature = "serde")]
    fn test_serde_sched_status() {
        generic_serde_test(SchedStatus::Enabled);
    }

    #[test]
    #[cfg(feature = "serde")]
    fn test_serde_time_window_type() {
        generic_serde_test(TimeWindowType::SelectAll);
    }

    #[test]
    fn test_generic_insert_app_data_test() {
        let time_writer = cds::TimeProvider::new_with_u16_days(1, 1);
        let mut sph = SpHeader::new(
            PacketId::const_new(PacketType::Tc, true, 0x002),
            PacketSequenceCtrl::const_new(crate::SequenceFlags::Unsegmented, 5),
            0,
        );
        let sec_header = PusTcSecondaryHeader::new_simple(17, 1);
        let ping_tc = PusTcCreator::new_no_app_data(&mut sph, sec_header, true);
        let mut buf: [u8; 64] = [0; 64];
        let result = generate_insert_telecommand_app_data(&mut buf, &time_writer, &ping_tc);
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), 2 + 7 + ping_tc.len_written());
        let n = u16::from_be_bytes(buf[0..2].try_into().unwrap());
        assert_eq!(n, 1);
        let time_reader = cds::TimeProvider::from_bytes_with_u16_days(&buf[2..2 + 7]).unwrap();
        assert_eq!(time_reader, time_writer);
        let pus_tc_reader = PusTcReader::new(&buf[9..]).unwrap().0;
        assert_eq!(pus_tc_reader, ping_tc);
    }

    #[test]
    fn test_generic_insert_app_data_test_as_vec() {
        let time_writer = cds::TimeProvider::new_with_u16_days(1, 1);
        let mut sph = SpHeader::new(
            PacketId::const_new(PacketType::Tc, true, 0x002),
            PacketSequenceCtrl::const_new(crate::SequenceFlags::Unsegmented, 5),
            0,
        );
        let sec_header = PusTcSecondaryHeader::new_simple(17, 1);
        let ping_tc = PusTcCreator::new_no_app_data(&mut sph, sec_header, true);
        let mut buf: [u8; 64] = [0; 64];
        generate_insert_telecommand_app_data(&mut buf, &time_writer, &ping_tc).unwrap();
        let vec = generate_insert_telecommand_app_data_as_vec(&time_writer, &ping_tc)
            .expect("vec generation failed");
        assert_eq!(&buf[..vec.len()], vec);
    }
}
