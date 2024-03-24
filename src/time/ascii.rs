//! Module to generate the ASCII timecodes specified in
//! [CCSDS 301.0-B-4](https://public.ccsds.org/Pubs/301x0b4e1.pdf) section 3.5 .
//! See [chrono::DateTime::format] for a usage example of the generated
//! [chrono::format::DelayedFormat] structs.
#[cfg(all(feature = "alloc", feature = "chrono"))]
pub use alloc_mod_chrono::*;

/// Tuple of format string and formatted size for time code A.
///
/// Format: YYYY-MM-DDThh:mm:ss.ddd
///
/// Three digits are used for the decimal fraction
pub const FMT_STR_CODE_A_WITH_SIZE: (&str, usize) = ("%FT%T%.3f", 23);
/// Tuple of format string and formatted size for time code A.
///
///  Format: YYYY-MM-DDThh:mm:ss.dddZ
///
/// Three digits are used for the decimal fraction and a terminator is added at the end.
pub const FMT_STR_CODE_A_TERMINATED_WITH_SIZE: (&str, usize) = ("%FT%T%.3fZ", 24);

/// Tuple of format string and formatted size for time code A.
///
/// Format: YYYY-DDDThh:mm:ss.ddd
///
/// Three digits are used for the decimal fraction
pub const FMT_STR_CODE_B_WITH_SIZE: (&str, usize) = ("%Y-%jT%T%.3f", 21);
/// Tuple of format string and formatted size for time code A.
///
/// Format: YYYY-DDDThh:mm:ss.dddZ
///
/// Three digits are used for the decimal fraction and a terminator is added at the end.
pub const FMT_STR_CODE_B_TERMINATED_WITH_SIZE: (&str, usize) = ("%Y-%jT%T%.3fZ", 22);

#[cfg(all(feature = "alloc", feature = "chrono"))]
pub mod alloc_mod_chrono {
    use super::*;
    use chrono::{
        format::{DelayedFormat, StrftimeItems},
        DateTime, Utc,
    };

    /// Generates a time code formatter using the [FMT_STR_CODE_A_WITH_SIZE] format.
    pub fn generate_time_code_a(date: &DateTime<Utc>) -> DelayedFormat<StrftimeItems<'static>> {
        date.format(FMT_STR_CODE_A_WITH_SIZE.0)
    }

    /// Generates a time code formatter using the [FMT_STR_CODE_A_TERMINATED_WITH_SIZE] format.
    pub fn generate_time_code_a_terminated(
        date: &DateTime<Utc>,
    ) -> DelayedFormat<StrftimeItems<'static>> {
        date.format(FMT_STR_CODE_A_TERMINATED_WITH_SIZE.0)
    }

    /// Generates a time code formatter using the [FMT_STR_CODE_B_WITH_SIZE] format.
    pub fn generate_time_code_b(date: &DateTime<Utc>) -> DelayedFormat<StrftimeItems<'static>> {
        date.format(FMT_STR_CODE_B_WITH_SIZE.0)
    }

    /// Generates a time code formatter using the [FMT_STR_CODE_B_TERMINATED_WITH_SIZE] format.
    pub fn generate_time_code_b_terminated(
        date: &DateTime<Utc>,
    ) -> DelayedFormat<StrftimeItems<'static>> {
        date.format(FMT_STR_CODE_B_TERMINATED_WITH_SIZE.0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;
    use std::format;

    #[test]
    fn test_ascii_timestamp_a_unterminated() {
        let date = Utc::now();
        let stamp_formatter = generate_time_code_a(&date);
        let stamp = format!("{}", stamp_formatter);
        let t_sep = stamp.find('T');
        assert!(t_sep.is_some());
        assert_eq!(t_sep.unwrap(), 10);
        assert_eq!(stamp.len(), FMT_STR_CODE_A_WITH_SIZE.1);
    }

    #[test]
    fn test_ascii_timestamp_a_terminated() {
        let date = Utc::now();
        let stamp_formatter = generate_time_code_a_terminated(&date);
        let stamp = format!("{}", stamp_formatter);
        let t_sep = stamp.find('T');
        assert!(t_sep.is_some());
        assert_eq!(t_sep.unwrap(), 10);
        let z_terminator = stamp.find('Z');
        assert!(z_terminator.is_some());
        assert_eq!(
            z_terminator.unwrap(),
            FMT_STR_CODE_A_TERMINATED_WITH_SIZE.1 - 1
        );
        assert_eq!(stamp.len(), FMT_STR_CODE_A_TERMINATED_WITH_SIZE.1);
    }

    #[test]
    fn test_ascii_timestamp_b_unterminated() {
        let date = Utc::now();
        let stamp_formatter = generate_time_code_b(&date);
        let stamp = format!("{}", stamp_formatter);
        let t_sep = stamp.find('T');
        assert!(t_sep.is_some());
        assert_eq!(t_sep.unwrap(), 8);
        assert_eq!(stamp.len(), FMT_STR_CODE_B_WITH_SIZE.1);
    }

    #[test]
    fn test_ascii_timestamp_b_terminated() {
        let date = Utc::now();
        let stamp_formatter = generate_time_code_b_terminated(&date);
        let stamp = format!("{}", stamp_formatter);
        let t_sep = stamp.find('T');
        assert!(t_sep.is_some());
        assert_eq!(t_sep.unwrap(), 8);
        let z_terminator = stamp.find('Z');
        assert!(z_terminator.is_some());
        assert_eq!(
            z_terminator.unwrap(),
            FMT_STR_CODE_B_TERMINATED_WITH_SIZE.1 - 1
        );
        assert_eq!(stamp.len(), FMT_STR_CODE_B_TERMINATED_WITH_SIZE.1);
    }
}
