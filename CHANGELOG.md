Change Log
=======

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](http://keepachangelog.com/)
and this project adheres to [Semantic Versioning](http://semver.org/).

# [unreleased]

## Changed

- `serde` support is now optional and behind the `serde` feature.
- `PusTcSecondaryHeaderT` trait renamed to `GenericPusTcSecondaryHeader`
- `PusTmSecondaryHeaderT` trait renamed to `GenericPusTmSecondaryHeader`.
- `SpHeader`: Former `tc` and `tm` methods now named `tc_unseg` and `tm_unseg`.
  Former `new` method now called `new_from_single_fields`.
- `SpHeader`: Renamed `from_bytes` to `from_be_bytes`.
  The function now returns the remaining slice as well.

## Added

- `serde` `Serialize` and `Deserialize` added to all types.
- Added `const` constructors for `PacketId`, `PacketSeqCtrl` and
  `SpHeader`.
- Added `PartialEq` and `Eq` `derive`s to `CdsShortTimeProvider`.
- `SpHeader`: Added serialization function into raw format `write_to_be_bytes`.

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
