//! PUS Service 11 Scheduling
use num_enum::{IntoPrimitive, TryFromPrimitive};
#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

#[derive(Debug, PartialEq, Eq, Copy, Clone, IntoPrimitive, TryFromPrimitive)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
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
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub enum SchedStatus {
    Disabled = 0,
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
    SelectAll = 0,
    TimeTagToTimeTag = 1,
    FromTimeTag = 2,
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
}
