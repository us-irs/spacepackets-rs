//! PUS Service 1 Verification
use num_enum::{IntoPrimitive, TryFromPrimitive};
#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

/// Message subtype ID.
#[derive(Debug, Eq, PartialEq, Copy, Clone, IntoPrimitive, TryFromPrimitive)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
#[repr(u8)]
pub enum MessageSubtypeId {
    /// Telemetry - Acceptance success.
    TmAcceptanceSuccess = 1,
    /// Telemetry - Acceptance failure.
    TmAcceptanceFailure = 2,
    /// Telemetry - Start success.
    TmStartSuccess = 3,
    /// Telemetry - Start failure.
    TmStartFailure = 4,
    /// Telemetry - Step success.
    TmStepSuccess = 5,
    /// Telemetry - Step failure.
    TmStepFailure = 6,
    /// Telemetry - Completion success.
    TmCompletionSuccess = 7,
    /// Telemetry - Completion failure.
    TmCompletionFailure = 8,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_conv_into_u8() {
        let subservice: u8 = MessageSubtypeId::TmCompletionSuccess.into();
        assert_eq!(subservice, 7);
    }

    #[test]
    fn test_conv_from_u8() {
        let subservice: MessageSubtypeId = 7.try_into().unwrap();
        assert_eq!(subservice, MessageSubtypeId::TmCompletionSuccess);
    }
}
