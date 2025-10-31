//! PUS Service 3 Housekeeping
use num_enum::{IntoPrimitive, TryFromPrimitive};
#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

#[derive(Debug, Eq, PartialEq, Copy, Clone, IntoPrimitive, TryFromPrimitive)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
#[repr(u8)]
pub enum Subservice {
    // Regular HK
    /// Telecommand - Create Housekeeping Report Structure.
    TcCreateHkReportStructure = 1,
    /// Telecommand - Delete HK report structures.
    TcDeleteHkReportStructures = 3,
    /// Telecommand - Enable HK generation.
    TcEnableHkGeneration = 5,
    /// Telecommand - Disable HK generation.
    TcDisableHkGeneration = 6,
    /// Telecommand - Report HK report structures.
    TcReportHkReportStructures = 9,
    /// Telemetry - HK report.
    TmHkPacket = 25,
    /// Telecommand - Generate one-shot report.
    TcGenerateOneShotHk = 27,
    /// Telecommand - Modify collection interval.
    TcModifyHkCollectionInterval = 31,

    // Diagnostics HK
    TcCreateDiagReportStructure = 2,
    TcDeleteDiagReportStructures = 4,
    TcEnableDiagGeneration = 7,
    TcDisableDiagGeneration = 8,
    TmHkStructuresReport = 10,
    TcReportDiagReportStructures = 11,
    TmDiagStructuresReport = 12,
    TmDiagPacket = 26,
    TcGenerateOneShotDiag = 28,
    TcModifyDiagCollectionInterval = 32,
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_try_from_u8() {
        let hk_report_subservice_raw = 25;
        let hk_report: Subservice = Subservice::try_from(hk_report_subservice_raw).unwrap();
        assert_eq!(hk_report, Subservice::TmHkPacket);
    }

    #[test]
    fn test_into_u8() {
        let hk_report_raw: u8 = Subservice::TmHkPacket.into();
        assert_eq!(hk_report_raw, 25);
    }

    #[test]
    fn test_partial_eq() {
        let hk_report_raw = Subservice::TmHkPacket;
        assert_ne!(hk_report_raw, Subservice::TcGenerateOneShotHk);
        assert_eq!(hk_report_raw, Subservice::TmHkPacket);
    }
    #[test]
    fn test_copy_clone() {
        let hk_report = Subservice::TmHkPacket;
        let hk_report_copy = hk_report;
        assert_eq!(hk_report, hk_report_copy);
    }
}
