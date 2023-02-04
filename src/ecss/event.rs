//! PUS Service 5 Events
#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};
use num_enum::{IntoPrimitive, TryFromPrimitive};

#[derive(Debug, Eq, PartialEq, Copy, Clone, IntoPrimitive, TryFromPrimitive)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[repr(u8)]
pub enum Subservice {
    TmInfoReport = 1,
    TmLowSeverityReport = 2,
    TmMediumSeverityReport = 3,
    TmHighSeverityReport = 4,
    TcEnableEventGeneration = 5,
    TcDisableEventGeneration = 6,
    TcReportDisabledList = 7,
    TmDisabledEventsReport = 8,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_conv_into_u8() {
        let subservice: u8 = Subservice::TmLowSeverityReport.into();
        assert_eq!(subservice, 2);
    }

    #[test]
    fn test_conv_from_u8() {
        let subservice: Subservice = 2.try_into().unwrap();
        assert_eq!(subservice, Subservice::TmLowSeverityReport);
    }

    #[test]
    fn test_conv_fails() {
        let conversion = Subservice::try_from(9);
        assert!(conversion.is_err());
        let err = conversion.unwrap_err();
        assert_eq!(err.number, 9);
    }
}
