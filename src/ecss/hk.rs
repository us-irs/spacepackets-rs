//! PUS Service 3 Housekeeping
use num_enum::{IntoPrimitive, TryFromPrimitive};
#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

/// Housekeeping service subtype ID.
#[derive(Debug, Eq, PartialEq, Copy, Clone, IntoPrimitive, TryFromPrimitive)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
#[repr(u8)]
pub enum MessageSubtypeId {
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

    /// Telecommand - Create diagnostics report structures.
    TcCreateDiagReportStructure = 2,
    /// Telecommand - Delete diagnostics report structures.
    TcDeleteDiagReportStructures = 4,
    /// Telecommand - Enable diagnostics generation.
    TcEnableDiagGeneration = 7,
    /// Telecommand - Disable diagnostics generation.
    TcDisableDiagGeneration = 8,
    /// Telemetry - HK structures report.
    TmHkStructuresReport = 10,
    /// Telecommand - Report diagnostics report structures.
    TcReportDiagReportStructures = 11,
    /// Telemetry - Diagnostics report structures.
    TmDiagStructuresReport = 12,
    /// Telemetry - Diagnostics packet.
    TmDiagPacket = 26,
    /// Telecommand - Generate one-shot diagnostics report.
    TcGenerateOneShotDiag = 28,
    /// Telecommand - Modify diagnostics interval report.
    TcModifyDiagCollectionInterval = 32,
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_try_from_u8() {
        let hk_report_subservice_raw = 25;
        let hk_report: MessageSubtypeId =
            MessageSubtypeId::try_from(hk_report_subservice_raw).unwrap();
        assert_eq!(hk_report, MessageSubtypeId::TmHkPacket);
    }

    #[test]
    fn test_into_u8() {
        let hk_report_raw: u8 = MessageSubtypeId::TmHkPacket.into();
        assert_eq!(hk_report_raw, 25);
    }

    #[test]
    fn test_partial_eq() {
        let hk_report_raw = MessageSubtypeId::TmHkPacket;
        assert_ne!(hk_report_raw, MessageSubtypeId::TcGenerateOneShotHk);
        assert_eq!(hk_report_raw, MessageSubtypeId::TmHkPacket);
    }
    #[test]
    fn test_copy_clone() {
        let hk_report = MessageSubtypeId::TmHkPacket;
        let hk_report_copy = hk_report;
        assert_eq!(hk_report, hk_report_copy);
    }
}
