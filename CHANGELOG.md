Change Log
=======

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](http://keepachangelog.com/)
and this project adheres to [Semantic Versioning](http://semver.org/).

# [unreleased]

## Added

- CDS timestamp: Added constructor function to create the time provider
  from `chrono::DateTime<Utc>` and a generic UNIX timestamp (`i64` seconds
  and subsecond milliseconds).

# [v0.4.2] 14.01.2023

## Fixed

- CDS timestamp: Fixed another small logic error for stamp creation from the current
  time with picosecond precision.
  PR: https://egit.irs.uni-stuttgart.de/rust/spacepackets/pulls/8

# [v0.4.1] 14.01.2023

## Fixed

- CDS timestamp: The conversion function from the current time were buggy
  when specifying picoseconds precision, which could lead to overflow
  multiplications and/or incorrect precision fields.
  PR: https://egit.irs.uni-stuttgart.de/rust/spacepackets/pulls/7

# [v0.4.0] 10.01.2023

## Fixed

- Remove `Default` derive on CDS time provider. This can lead to uninitialized preamble fields.

## Changed

- `serde` support is now optional and behind the `serde` feature.
- `PusTcSecondaryHeaderT` trait renamed to `GenericPusTcSecondaryHeader`.
- `PusTmSecondaryHeaderT` trait renamed to `GenericPusTmSecondaryHeader`.
- `SpHeader`: Former `tc` and `tm` methods now named `tc_unseg` and `tm_unseg`.
  Former `new` method now called `new_from_single_fields`.
- `SpHeader`: Renamed `from_bytes` to `from_be_bytes`.
  The function now returns the remaining slice as well.
- All CDS specific functionality was moved into the `cds` submodule of the `time`
  module. `CdsShortTimeProvider` was renamed to `TimeProvider`.
  PR: https://egit.irs.uni-stuttgart.de/rust/spacepackets/pulls/3

## Added

- `SpHeader` getter function `sp_header` added for `PusTc`
  PR: https://egit.irs.uni-stuttgart.de/rust/spacepackets/pulls/6
- Added PFC enumerations: `ecss::UnsignedPfc` and `ecss::RealPfc`.
  PR: https://egit.irs.uni-stuttgart.de/rust/spacepackets/pulls/5
- Added `std::error::Error` implementation for all error enumerations if the `std` feature
  is enabled.
- CUC timestamp implementation as specified in CCSDS 301.0-B-4 section 3.2.
  PR: https://egit.irs.uni-stuttgart.de/rust/spacepackets/pulls/4/files
- ACII timestamps as specified in CCSDS 301.0-B-4 section 3.5.
- Added MSRV in `Cargo.toml` with the `rust-version` field set to Rust 1.60.
- `serde` `Serialize` and `Deserialize` added to all types.
- Added `const` constructors for `PacketId`, `PacketSeqCtrl` and
  `SpHeader`.
- Added `PartialEq` and `Eq` `derive`s to `TimeProvider`.
- `SpHeader`: Added serialization function into raw format `write_to_be_bytes`.
- Added 24-bit day field support for CDS short. The bit width is configured at type level
  via a generic parameter type passed to the `cds::TimeProvider`
- Added submillisecond precision support for `cds::TimeProvider`

# [v0.3.1] 03.12.2022

- Small fix for faulty docs.rs build

# [v0.3.0] 01.12.2022

## Added

- `EcssEnumerationExt` trait which implements `Debug`, `Copy`, `Clone`,
  `PartialEq` and `Eq` in addition to `EcssEnumeration`

## Changed

- `EcssEnumeration` trait: Rename `write_to_bytes`
  to `write_to_be_bytes`

# [v0.2.0] 13.09.2022

## Added

- Basic support for ECSS enumeration types for u8, u16, u32 and u64

## Changed

- Better names for generic error enumerations: `PacketError` renamed to `ByteConversionError`
- CCSDS module: `ssc` abbreviations fully replaced by better name `seq_count`
- Time module: `CcsdsTimeProvider::date_time` now has `Option<DateTime<Utc>>` as
  a returnvalue instead of `DateTime<Utc>`
- `PusTc` and `PusTm`: `new_from_raw_slice` renamed to simpler `from_bytes`

# [v0.1.0] 16.08.2022

Initial release with CCSDS Space Packet Primary Header implementation and basic PUS TC and TM
implementations.
