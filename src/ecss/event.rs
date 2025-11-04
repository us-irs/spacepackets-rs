//! PUS Service 5 Events
use num_enum::{IntoPrimitive, TryFromPrimitive};
#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

/// Event service subtype ID.
#[derive(Debug, Eq, PartialEq, Copy, Clone, IntoPrimitive, TryFromPrimitive)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[repr(u8)]
pub enum MessageSubtypeId {
    /// Telemetry - Info report.
    TmInfoReport = 1,
    /// Telemetry - Low severity report.
    TmLowSeverityReport = 2,
    /// Telemetry - Medium severity report.
    TmMediumSeverityReport = 3,
    /// Telemetry - High severity report.
    TmHighSeverityReport = 4,
    /// Telecommand - Enable event generation.
    TcEnableEventGeneration = 5,
    /// Telecommand - Disable event generation.
    TcDisableEventGeneration = 6,
    /// Telecommand - Report disabled list.
    TcReportDisabledList = 7,
    /// Telemetry - Disabled events report.
    TmDisabledEventsReport = 8,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_conv_into_u8() {
        let subservice: u8 = MessageSubtypeId::TmLowSeverityReport.into();
        assert_eq!(subservice, 2);
    }

    #[test]
    fn test_conv_from_u8() {
        let subservice: MessageSubtypeId = 2.try_into().unwrap();
        assert_eq!(subservice, MessageSubtypeId::TmLowSeverityReport);
    }

    #[test]
    fn test_conv_fails() {
        let conversion = MessageSubtypeId::try_from(9);
        assert!(conversion.is_err());
        let err = conversion.unwrap_err();
        assert_eq!(err.number, 9);
    }
}
