//! PUS Service 1 Verification
use num_enum::{IntoPrimitive, TryFromPrimitive};
#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

#[derive(Debug, Eq, PartialEq, Copy, Clone, IntoPrimitive, TryFromPrimitive)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[repr(u8)]
pub enum Subservice {
    TmAcceptanceSuccess = 1,
    TmAcceptanceFailure = 2,
    TmStartSuccess = 3,
    TmStartFailure = 4,
    TmStepSuccess = 5,
    TmStepFailure = 6,
    TmCompletionSuccess = 7,
    TmCompletionFailure = 8,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_conv_into_u8() {
        let subservice: u8 = Subservice::TmCompletionSuccess.into();
        assert_eq!(subservice, 7);
    }

    #[test]
    fn test_conv_from_u8() {
        let subservice: Subservice = 7.try_into().unwrap();
        assert_eq!(subservice, Subservice::TmCompletionSuccess);
    }
}
