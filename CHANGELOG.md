Change Log
=======

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](http://keepachangelog.com/)
and this project adheres to [Semantic Versioning](http://semver.org/).

# [unreleased]

## Changed

- The `Tlv` and `Lv` API return `&[u8]` instead of `Option<&[u8]>`.

## Added

- Added `raw_data` API for `Tlv` and `Lv` to retrieve the whole `Lv`/`Tlv` slice if the object
  was created from a raw bytestream.
- Added `MsgToUserTlv` helper class which wraps a regular `Tlv` and adds some useful functionality.

# [v0.7.0-beta.0] 2023-08-16

- Moved MSRV from v1.60 to v1.61.

## Changed

- `PusPacket` trait: `user_data` now returns `&[u8]` instead of `Option<&[u8]>`. Empty user data
  can simply be an empty slice.
- Moved ECSS TC components from `tc` to `ecss.tc`.
- Moved ECSS TM components from `tm` to `ecss.tm`.
- Converted `PusTc` class to more specialized `PusTcCreator` and `PusTcReader`
  classes. The old `PusTc` class is deprecated now.
- Converted `PusTm` class to more specialized `PusTmCreator` and `PusTmReader`
  classes. The old `PusTm` class is deprecated now.
- Implement `Display` and `Error` for `StdTimestampError` properly.
- Remove some redundant `Error` suffixes for enum error variants.
- `CommonPduConfig`: `new_with_defaults` replaced by `new_with_byte_fields`.

## Added

- `source_data` and `app_data` API provided for PUS TM and PUS TC reader classes. These simply
  call `user_data` but are also in line with the PUS packet standard names for those fields.
- Added new marker trait `IsPusTelemetry` implemented by `PusTmCreator` and `PusTmReader`.
- Added new marker trait `IsPusTelecommand` implemented by `PusTcCreator` and `PusTcReader`.
- `metadata_param` getter method for the `MetadataPdu` object.
- `Default` impl for CFDP `ChecksumType`
- `Default` impl for CFDP `CommonPduConfig`

## Fixed

- All `MetadataGenericParam` fields are now public.
- New setter method `set_source_and_dest_id` for `CommonPduConfig`.

# [v0.6.0] 2023-07-06

## Added

- Added new `util` module which contains the following (new) helper modules:
  - `UnsignedEnum` trait as an abstraction for unsigned byte fields with variable lengths. It is
    not tied to the ECSS PFC value like the `EcssEnumeration` trait. The method to retrieve
    the size of the unsigned enumeration in bytes is now called `size`.
  - `GenericUnsignedByteField<TYPE>` and helper typedefs `UnsignedU8`, `UnsignedU16`, `UnsignedU32`
    and `UnsignedU64` as helper types implementing `UnsignedEnum`
  - `UnsignedByteField` as a type-erased helper.
- Initial CFDP support: Added PDU packet implementation.
- Added `SerializablePusPacket` as a generic abstraction for PUS packets which are
  writable.
- Added new `PusTmZeroCopyWriter` class which allows to set fields on a raw TM packet,
  which might be more efficient that modification and re-writing a packet with the
  `PusTm` object.

## Changed
 
- The `EcssEnumeration` now requires the `UnsignedEnum` trait and only adds the `pfc` method to it.
- Renamed `byte_width` usages to `size` (part of new `UnsignedEnum` trait)
- Moved `ecss::CRC_CCITT_FALSE` CRC constant to the root module. This CRC type is not just used by
  the PUS standard, but by the CCSDS Telecommand standard and the CFDP standard as well.

# [v0.5.4] 2023-02-12

## Added

- `Clone` trait requirement for `time::cds::ProvidesDaysLen` trait.
- Added `Copy` and `Clone` derives for `DaysLen16Bits` and `DaysLen24Bits`.

# [v0.5.3] 2023-02-05

## Added

- `num_enum` dependency to avoid boilerplate code for primtive to enum conversions, for example
  for the PUS subservices.
- `ecss.event` module containing a `Subservice` enum.
- `ecss.verification` module containing a `Subservice` enum.
- `ecss.scheduling` module containing a `Subservice` enum and some other helper enumerations.
- `ecss.hk` module containing a `Subservice` enum.

## Changed

- Added missing Service IDs to `ecss.PusServiceId` and marked in `#[non_exhaustive]`.

## Fixed

- `time.UnixTimestamp`: All constructors and `From` conversions now use the `new` constructor,
  which should cause a correct conversion of 0 subsecond milliseconds to a `None` value.

# [v0.5.2] 2023-01-26

## Added

- Added `.gitignore`.

## Fixed

- Correct implementation of Trait `PartialEq` for `PusTc` and `PusTm`. The previous auto-derivation
  were incorrect because they also compared fields unrelated to the raw byte representation.

## Changed

- Renamed `PusTc` `raw` method to `raw_bytes` and add better docs to avoid confusion.
  Deprecate `raw` to avoid breaking change.
- Added `raw_bytes` method to `PusTm`.

# [v0.5.1] 2023-01-22

## Added

- `time::cds::TimeProvider`
  - Add `Ord` and `PartialOrd`, use custom `PartialEq` impl to account for precision correctly.
  - Add `precision_as_ns` function which converts microsecond and picosecond precision values
    into nanoseconds.
  - Add conversion trait to convert `cds::TimeProvider<DaysLen16Bits>` into
    `cds::TimeProvider<DaysLen24Bits>` and vice-versa.
- `time::UnixTimestamp`
  - Add `Ord` and `PartialOrd` implementations.
  - Add `Add<Duration>` and `AddAssign<Duration>` implementations.

## Fixed

- `time::cds::TimeProvider`: Fixed a bug where subsecond milliseconds were not accounted for
  when the provider has no submillisecond precision.

# [v0.5.0] 2023-01-20

The timestamp of `PusTm` is now optional. See Added and Changed section for details.

## Added

- `PusTmSecondaryHeader`: New `new_simple_no_timestamp` API to create secondary header without
  timestamp.
- `PusTm`: Add `new_simple_no_timestamp` method to create TM without timestamp
- New `UnixTimestamp` abstraction which contains the unix seconds as an `i64`
  and an optional subsecond millisecond counter (`u16`)
- `MS_PER_DAY` constant.
- CUC: Added `from_date_time` and `from_unix_stamp` constructors for time provider.
- CUC: Add `Add<Duration>` and `AddAssign<Duration>` impl for time provider.

### CDS time module

- Implement `Add<Duration>` and `AddAssign<Duration>` for time providers, which allows
  easily adding offsets to the providers.
- Implement `TryFrom<DateTime<Utc>>` for time providers.
- `get_dyn_time_provider_from_bytes`: Requires `alloc` support and returns
  the correct `TimeProvider` instance wrapped as a boxed trait object
  `Box<DynCdsTimeProvider>` by checking the length of days field.
- Added constructor function to create the time provider
  from `chrono::DateTime<Utc>` and a generic UNIX timestamp (`i64` seconds
  and subsecond milliseconds).
- `MAX_DAYS_24_BITS` which contains maximum value which can be supplied
  to the days field of a CDS time provider with 24 bits days field width.
- New `CdsTimestamp` trait which encapsulates common fields for all CDS time providers.
- `from_unix_secs_with_u24_days` and `from_unix_secs_with_u16_days` which create
   the time provider from a `UnixTimestamp` reference.
- `from_dt_with_u16_days`, `from_dt_with_u24_days` and their `..._us_precision` and
   `..._ps_precision` variants which allow to create time providers from
   a `chrono::DateTime<Utc>`.
- Add `from_bytes_with_u24_days` and `from_bytes_with_u16_days` associated methods

## Changed


- (breaking) `unix_epoch_to_ccsds_epoch`: Expect and return `i64` instead of `u64` now.
- (breaking) `ccsds_epoch_to_unix_epoch`: Expect and return `i64` instead of `u64` now.
- (breaking) `PusTmSecondaryHeader`: Timestamp is optional now, which translates to a
  timestamp of size 0.
- (breaking): `PusTm`: Renamed `time_stamp` method to `timestamp`, also returns
  `Optional<&'src_data [u8]>` now.
- (breaking): `PusTmSecondaryHeader`: Renamed `time_stamp` field to `timestamp` for consistency.
- (breaking): Renamed `from_now_with_u24_days_and_us_prec` to `from_now_with_u24_days_us_precision`.
  Also did the same for the `u16` variant.
- (breaking): Renamed `from_now_with_u24_days_and_ps_prec` to `from_now_with_u24_days_ps_precision`.
  Also did the same for the `u16` variant.
- `CcsdsTimeProvider` trait (breaking):
  - Add new `unix_stamp` method returning the new `UnixTimeStamp` struct.
  - Add new  `subsecond_millis` method returning counter `Option<u16>`.
  - Default impl for `unix_stamp` which re-uses `subsecond_millis` and
    existing `unix_seconds` method.
- `TimestampError` (breaking): Add `DateBeforeCcsdsEpoch` error type
  because new CDS API allow supplying invalid date times before CCSDS epoch.
  Make `TimestampError` with `#[non_exhaustive]` attribute to prevent
  future breakages if new error variants are added.

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
