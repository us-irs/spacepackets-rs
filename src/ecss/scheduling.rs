//! PUS Service 11 Scheduling
use num_enum::{IntoPrimitive, TryFromPrimitive};
#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

/// Scheduling service subtype ID.
#[derive(Debug, PartialEq, Eq, Copy, Clone, IntoPrimitive, TryFromPrimitive)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
#[repr(u8)]
pub enum MessageSubtypeId {
    // Core subservices
    /// Telecommand - Enable scheduling.
    TcEnableScheduling = 1,
    /// Telecommand - Disable scheduling.
    TcDisableScheduling = 2,
    /// Telecommand - Reset scheduling.
    TcResetScheduling = 3,
    /// Telecommand - Insert activity.
    TcInsertActivity = 4,
    /// Telecommand - Delete activity by request ID.
    TcDeleteActivityByRequestId = 5,
    /// Telecommand - Delete activity by filter.
    TcDeleteActivitiesByFilter = 6,

    // Time shift subservices
    /// Telecommand - Time shift activity by request ID.
    TcTimeShiftActivityWithRequestId = 7,
    /// Telecommand - Time shift activity by filter.
    TcTimeShiftActivitiesByFilter = 8,
    /// Telecommand - Time shift all.
    TcTimeShiftAll = 15,

    // Reporting subservices
    /// Telecommand - Detail report by request ID.
    TcDetailReportByRequestId = 9,
    /// Telemetry - Detail report.
    TmDetailReport = 10,
    /// Telecommand - Detail report by filter.
    TcDetailReportByFilter = 11,
    /// Telecommand - Summary report by request ID.
    TcSummaryReportByRequestId = 12,
    /// Telemetry - Summary report.
    TmSummaryReport = 13,
    /// Telecommand - Summary report by filter.
    TcSummaryReportByFilter = 14,
    /// Telecommand - Detail report all.
    TcDetailReportAll = 16,
    /// Telecommand - Summary report all.
    TcSummaryReportAll = 17,

    // Subschedule subservices
    /// Telecommand - Report subschedule status.
    TcReportSubscheduleStatus = 18,
    /// Telemetry - Subschedule status report.
    TmReportSubscheduleStatus = 19,
    /// Telecommand - Enable subschedule.
    TcEnableSubschedule = 20,
    /// Telecommand - Disable subschedule.
    TcDisableSubschedule = 21,

    // Group subservices
    /// Telecommand - Create schedule group.
    TcCreateScheduleGroup = 22,
    /// Telecommand - Delete schedule group.
    TcDeleteScheduleGroup = 23,
    /// Telecommand - Enable schedule group.
    TcEnableScheduleGroup = 24,
    /// Telecommand - Disable schedule group.
    TcDisableScheduleGroup = 25,
    /// Telecommand - Report all group status.
    TcReportAllGroupsStatus = 26,
    /// Telemetry - All group status report.
    TmReportAllGroupsStatus = 27,
}

/// This status applies to sub-schedules and groups as well as specified in ECSS-E-ST-70-41C 8.11.3
#[derive(Debug, PartialEq, Eq, Copy, Clone)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub enum SchedStatus {
    /// Scheduling disabled.
    Disabled = 0,
    /// Scheduling enabled.
    Enabled = 1,
}

impl From<bool> for SchedStatus {
    #[inline]
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
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub enum TimeWindowType {
    /// Select all.
    SelectAll = 0,
    /// From time tag to time tag.
    TimeTagToTimeTag = 1,
    /// Starting from a time tag.
    FromTimeTag = 2,
    /// Until a time tag.
    ToTimeTag = 3,
}

#[cfg(test)]
mod tests {
    use super::*;
    #[cfg(feature = "serde")]
    use crate::tests::generic_serde_test;

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
        let subservice: u8 = MessageSubtypeId::TcCreateScheduleGroup.into();
        assert_eq!(subservice, 22);
    }

    #[test]
    fn test_conv_from_u8() {
        let subservice: MessageSubtypeId = 22u8.try_into().unwrap();
        assert_eq!(subservice, MessageSubtypeId::TcCreateScheduleGroup);
    }

    #[test]
    #[cfg(feature = "serde")]
    fn test_serde_subservice_id() {
        generic_serde_test(MessageSubtypeId::TcEnableScheduling);
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
}
