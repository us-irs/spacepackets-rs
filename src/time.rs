enum CcsdsTimeCodes {
    None = 0,
    CucCcsdsEpoch = 0b001,
    CucAgencyEpoch = 0b010,
    Cds = 0b100,
    Ccs = 0b101
}

/// Trait for generic CCSDS time providers
trait CcsdsTimeProvider {
    fn write_to_bytes(&self, bytes: impl AsMut<u8>);
    /// Returns the pfield of the time provider. The pfield can have one or two bytes depending
    /// on the extension bit (first bit). The time provider should returns a tuple where the first
    /// entry denotes the length of the pfield and the second entry is the value of the pfield
    /// in big endian format.
    fn pfield(&self) -> (usize, u16);
    fn ccdsd_time_code(&self) -> CcsdsTimeCodes;
    fn as_unix_seconds(&self) -> u64;
}

struct CdsShortTimeProvider {}

impl CcsdsTimeProvider for CdsShortTimeProvider {
    fn write_to_bytes(&self, bytes: impl AsMut<u8>) {
        todo!()
    }

    fn pfield(&self) -> (usize, u16) {
        todo!()
    }

    fn ccdsd_time_code(&self) -> CcsdsTimeCodes {
        todo!()
    }

    fn as_unix_seconds(&self) -> u64 {
        todo!()
    }
}
