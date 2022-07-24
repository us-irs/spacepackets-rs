use crate::PacketError;
#[cfg(feature = "std")]
use std::time::SystemTime;

pub const CDS_SHORT_LEN: usize = 7;
pub const DAYS_CCSDS_TO_UNIX: i32 = -4383;
pub const SECONDS_PER_DAY: u32 = 86400;

pub enum CcsdsTimeCodes {
    None = 0,
    CucCcsdsEpoch = 0b001,
    CucAgencyEpoch = 0b010,
    Cds = 0b100,
    Ccs = 0b101,
}

#[cfg(feature = "std")]
pub fn seconds_since_epoch() -> f64 {
    SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .expect("System time generation failed")
        .as_secs_f64()
}

/// Convert UNIX days to CCSDS days
///
///  - CCSDS epoch: 1958 January 1
///  - UNIX Epoch: 1970 January 1
pub const fn unix_to_ccsds_days(unix_days: i32) -> i32 {
    unix_days - DAYS_CCSDS_TO_UNIX
}

/// Convert CCSDS days to UNIX days
///
///  - CCSDS epoch: 1958 January 1
///  - UNIX Epoch: 1970 January 1
pub const fn ccsds_to_unix_days(unix_days: i32) -> i32 {
    unix_days + DAYS_CCSDS_TO_UNIX
}

/// Trait for generic CCSDS time providers
trait CcsdsTimeProvider {
    fn len(&self) -> usize;
    fn write_to_bytes(&self, bytes: &mut (impl AsMut<[u8]> + ?Sized)) -> Result<(), PacketError>;
    /// Returns the pfield of the time provider. The pfield can have one or two bytes depending
    /// on the extension bit (first bit). The time provider should returns a tuple where the first
    /// entry denotes the length of the pfield and the second entry is the value of the pfield
    /// in big endian format.
    fn p_field(&self) -> (usize, [u8; 2]);
    fn ccdsd_time_code(&self) -> CcsdsTimeCodes;
    fn as_unix_seconds(&self) -> u64;
}

pub struct CdsShortTimeProvider {
    pfield: u8,
    ccsds_days: u16,
    ms_of_day: u32,
    unix_seconds: u64,
}

impl CdsShortTimeProvider {
    pub fn new(ccsds_days: u16, ms_of_day: u32) -> Self {
        let mut provider = Self {
            pfield: (CcsdsTimeCodes::Cds as u8) << 4,
            ccsds_days,
            ms_of_day,
            unix_seconds: 0,
        };
        provider.calc_unix_seconds();
        provider
    }

    #[cfg(feature = "std")]
    pub fn ms_of_day_using_sysclock() -> u32 {
        Self::ms_of_day(seconds_since_epoch())
    }

    pub fn ms_of_day(seconds_since_epoch: f64) -> u32 {
        let fraction_ms = seconds_since_epoch - seconds_since_epoch.floor();
        let ms_of_day: u32 =
            (((seconds_since_epoch.floor() as u32 % SECONDS_PER_DAY) * 1000) as f64 + fraction_ms)
                .floor() as u32;
        ms_of_day
    }

    fn calc_unix_seconds(&mut self) {
        let unix_days = ccsds_to_unix_days(self.ccsds_days as i32);
        self.unix_seconds = unix_days as u64 * (24 * 60 * 60);
        let seconds_of_day = (self.ms_of_day as f32 / 1000.0).floor() as u64;
        self.unix_seconds += seconds_of_day;
    }
}
impl CcsdsTimeProvider for CdsShortTimeProvider {
    fn len(&self) -> usize {
        CDS_SHORT_LEN
    }

    fn write_to_bytes(&self, bytes: &mut (impl AsMut<[u8]> + ?Sized)) -> Result<(), PacketError> {
        let slice = bytes.as_mut();
        if slice.len() < self.len() {
            return Err(PacketError::ToBytesSliceTooSmall(slice.len()));
        }
        slice[0] = self.pfield;
        slice[1..3].copy_from_slice(self.ccsds_days.to_be_bytes().as_slice());
        slice[4..].copy_from_slice(self.ms_of_day.to_be_bytes().as_slice());
        Ok(())
    }

    fn p_field(&self) -> (usize, [u8; 2]) {
        (1, [self.pfield, 0])
    }

    fn ccdsd_time_code(&self) -> CcsdsTimeCodes {
        CcsdsTimeCodes::Cds
    }

    fn as_unix_seconds(&self) -> u64 {
        self.unix_seconds
    }
}
