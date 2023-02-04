//! PUS Service 3 Housekeeping
use num_enum::{IntoPrimitive, TryFromPrimitive};
#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

#[derive(Debug, Eq, PartialEq, Copy, Clone, IntoPrimitive, TryFromPrimitive)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[repr(u8)]
pub enum Subservice {
    // Regular HK
    TcCreateHkReportStructure = 1,
    TcDeleteHkReportStructures = 3,
    TcEnableHkGeneration = 5,
    TcDisableHkGeneration = 6,
    TcReportHkReportStructures = 9,
    TmHkPacket = 25,
    TcGenerateOneShotHk = 27,
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
