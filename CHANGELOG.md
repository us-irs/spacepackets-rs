Change Log
=======

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](http://keepachangelog.com/)
and this project adheres to [Semantic Versioning](http://semver.org/).

# [unreleased]

## Changed

- CFDP NAK PDU `SegmentRequestIter` is not generic over the file size anymore. Instead, the
  iterator returns pairs of `u64` for both large and normal file size.
- `PusVersion::VersionNotSupported` contains raw version number instead of `PusVersion` enum now
  to make it more flexible.
- `pus_version` API now returns a `Result<PusVersion, u8>` instead of a `PusVersion` to allow
  modelling invalid version numbers properly.
- Renamed `CcsdsPacket::total_len` to `CcsdsPacket::packet_len`
- Renamed `SequenceCountProvider` to `SequenceCounter`
- Renamed `SeqCountProviderSimple` to `SequenceCounterSimple`
- Renamed `CcsdsSimpleSeqCountProvider` to `SequenceCounterCcsdsSimple`
- Renamed `SeqCountProviderSync` to `SequenceCounterSync`
- Renamed `PusPacket::opt_crc16` to `PusPacket::checksum`
- ECSS checksum generation is now optional as specified in the standard. Added `has_checksum`
  parameters for ECSS TM/TC creators and readers to reflect this.

## Removed

- `PusVersion::Invalid`, which will be modelled with `Result<PusVersion, u8>` now.

## Added

- Added PUS A legacy support for telecommands inside the `ecss.tc_pus_a` module
- Added `SequenceCounter::increment_mut` and `SequenceCounter::get_and_increment_mut`
- Implemented `SequenceCounter` for `Atomic` unsigned types and references of them
- `PusPacket::has_checksum` and `WritablePusPacket::has_checksum`

# [v0.15.0] 2025-07-18

## Added

- `PusTcCreatorWithReservedAppData` and `PusTmCreatorWithReservedSourceData` constructor variants
  which allow writing source/app data into the serialization buffer directly without
  requiring an extra buffer.

# [v0.14.0] 2025-05-10

## Changed

- Moved CRC constants/implementations to dedicated `crc` module.
- `crc::CRC_CCITT_FALSE_NO_TABLE` and `crc::CRC_CCITT_FALSE_BIG_TABLE` variants.
- Renamed `PusPacket::crc16` to `PusPacket::opt_crc16`.

## Added

- `WritablePusPacket::write_to_bytes_crc_no_table` and `WritablePusPacket::write_to_bytes_no_crc`
  variants.
- `PusTmReader::new_crc_no_table` and `PusTcReader::new_crc_no_table` variants.
- `crc16` methods for PUS TM and PUS TC reader.
- PUS TM and PUS TC reader now return the reader instance directly instead of a tuple of the reader
  and the read size. The instance `total_len` method can be used to retrieve the read lenght.

# [v0.13.1] 2025-03-21

- Bugfix due to operator precendence for `PusTcSecondaryHeader::pus_version`,
  `PusTcSecondaryHeaderWithoutTimestamp::pus_version`, `CdsTime::from_bytes_with_u16_days` and
  `CdsTime::from_bytes_with_u24_days`

# [v0.13.0] 2024-11-08

- Bumped MSRV to 1.81.0
- Bump `zerocopy` to v0.8.0
- Bump `thiserror` to v2.0.0

## Changed

- Migrated all Error implementations to thiserror, improved some naming and error handling in
  general

# [v0.12.0] 2024-09-10

- Bumped MSRV to 1.70.0

## Added

- Added new `cfdp::tlv::TlvOwned` type which erases the lifetime and is clonable.
- Dedicated `cfdp::tlv::TlvLvDataTooLarge` error struct for APIs where this is the only possible
  API error.
- Added File Data PDU API which expects the expected file data size and then exposes the unwritten
  file data field as a mutable slice. This allows to read data from the virtual file system
  API to the file data buffer without an intermediate buffer.
- Generic `EofPdu::new` constructor.
- Added generic sequence counter module.
- Added `MsgToUserTlv::to_tlv` converter which reduced the type and converts
  it to a generic `Tlv`.
- Implemented `From<MsgToUserTlv> for Tlv` converter trait.
- Added CFDP maximum file segment length calculator method `calculate_max_file_seg_len_for_max_packet_len_and_pdu_header`

## Added and Changed

- Added new `ReadableTlv` to avoid some boilerplate code and have a common abstraction implemented
  for both `Tlv` and `TlvOwned` to read the raw TLV data field and its length.
- Replaced `cfdp::tlv::TlvLvError` by `cfdp::tlv::TlvLvDataTooLarge` where applicable.

## Fixed

- Fixed an error in the EOF writer which wrote the fault location to the wrong buffer position.
- cfdp `ConditionCode::CheckLimitReached` previous had the wrong numerical value of `0b1001` (9)
  and now has the correct value of `0b1010` (10).

## Changed

- Minor documentation build updates.
- Increased delegate version range to v0.13

# [v0.11.2] 2024-05-19

- Bumped MSRV to 1.68.2

## Fixed

- Removed `defmt::Format` impl for `MetadataPduCreator` which seems to be problematic.

# [v0.11.1] 2024-04-22

## Fixed

- The default data length for for `SpHeader` constructors where the data field length is not
  specified is now 0.
- The `SpHeader::new_from_fields` is public now.

## Added

- `SpHeader::to_vec` method.

# [v0.11.0] 2024-04-16

## Changed

- Moved `CCSDS_HEADER_LEN` constant to the crate root.

## Added

- Added `SpacePacketHeader` type alias for `SpHeader` type.

# [v0.11.0-rc.2] 2024-04-04

## Changed

- Renamed `PacketId` and `PacketSequenceCtrl` `new` method to `new_checked` and former
  `new_const` method to `new`.
- Renamed `tc`, `tm`, `tc_unseg` and `tm_unseg` variants for `PacketId` and `SpHeader`
  to `new_for_tc_checked`, `new_for_tm_checked`, `new_for_unseg_tc_checked` and
  `new_for_unseg_tm_checked`.
- `PusTmCreator` and `PusTcCreator` now expect a regular instance of `SpHeader` instead of
  a mutable reference.

## Added

- `SpHeader::new_from_apid` and `SpHeader::new_from_apid_checked` constructor.
- `#[inline]` attribute for a lot of small functions.

# [v0.11.0-rc.1] 2024-04-03

Major API changes for the time API. If you are using the time API, it is strongly recommended
to check all the API changes in the **Changed** chapter.

## Fixed

- CUC timestamp was fixed to include leap second corrections because it is based on the TAI
  time reference. The default CUC time object do not implement `CcsdsTimeProvider` anymore
  because the trait methods require cached leap second information. This task is now performed
  by the `cuc::CucTimeWithLeapSecs` which implements the trait.

## Added

- `From<$EcssEnum$TY> from $TY` for the ECSS enum type definitions.
- Added basic support conversions to the `time` library. Introduce new `chrono` and `timelib`
  feature gate.
- Added `CcsdsTimeProvider::timelib_date_time`.
- Optional support for `defmt` by adding optional `defmt::Format` derives for common types.

## Changed

- `PusTcCreator::new_simple` now expects a valid slice for the source data instead of an optional
  slice. For telecommands without application data, `&[]` can be passed.
- `PusTmSecondaryHeader` constructors now expects a valid slice for the time stamp instead of an
  optional slice.
- Renamed `CcsdsTimeProvider::date_time` to `CcsdsTimeProvider::chrono_date_time`
- Renamed `CcsdsTimeCodes` to `CcsdsTimeCode`
- Renamed `cds::TimeProvider` to `cds::CdsTime`
- Renamed `cuc::TimeProviderCcsdsEpoch` to `cuc::CucTime`
- `UnixTimestamp` renamed to `UnixTime`
- `UnixTime` seconds are now private and can be retrieved using the `secs` member method.
- `UnixTime::new` renamed to `UnixTime::new_checked`.
- `UnixTime::secs` renamed to `UnixTime::as_secs`.
- `UnixTime` now has a nanosecond subsecond precision. The `new` constructor now expects
   nanoseconds as the second argument.
- Added new `UnixTime::new_subsec_millis` and `UnixTime::new_subsec_millis_checked` API
  to still allow creating a timestamp with only millisecond subsecond resolution.
- `CcsdsTimeProvider` now has a new `subsec_nanos` method in addition to a default
  implementation for the `subsec_millis` method.
- `CcsdsTimeProvider::date_time` renamed to `CcsdsTimeProvider::chrono_date_time`.
- Added `UnixTime::MIN`, `UnixTime::MAX` and `UnixTime::EPOCH`.
- Added `UnixTime::timelib_date_time`.
- Error handling for ECSS and time module is more granular now, with a new
  `DateBeforeCcsdsEpochError` error and a `DateBeforeCcsdsEpoch` enum variant for both
  `CdsError` and `CucError`.
- `PusTmCreator` now has two lifetimes: One for the raw source data buffer and one for the
  raw timestamp.
- Time API `from_now*` API renamed to `now*`.

## Removed

- Legacy `PusTm` and `PusTc` objects.

# [v0.11.0-rc.0] 2024-03-04

## Added

- `From<$TY>` for the `EcssEnum$TY` ECSS enum type definitions.
- `Sub` implementation for `UnixTimestamp` to calculate the duration between two timestamps.

## Changed

- `CcsdsTimeProvider` `subsecond_millis` function now returns `u16` instead of `Option<u16>`.
- `UnixTimestamp` `subsecond_millis` function now returns `u16` instead of `Option<u16>`.

# [v0.10.0] 2024-02-17

## Added

- Added `value` and `to_vec` methods for the `UnsignedEnum` trait. The value is returned as
  as `u64`. Renamed former `value` method on `GenericUnsignedByteField` to `value_typed`.
- Added `value_const` const function for `UnsignedByteField` type.
- Added `value_typed` const functions for `GenericUnsignedByteField` and `GenericEcssEnumWrapper`.

# [v0.9.0] 2024-02-07

## Added

- `CcsdsPacket`, `PusPacket` and `GenericPusTmSecondaryHeader` implementation for
  `PusTmZeroCopyWriter`.
- Additional length checks for `PusTmZeroCopyWriter`.

## Changed

- `PusTmZeroCopyWriter`: Added additional timestamp length argument for `new` constructor.

## Fixed

- Typo: `PUC_TM_MIN_HEADER_LEN` -> `PUS_TM_MIN_HEADER_LEN`

# [v0.8.1] 2024-02-05

## Fixed

- Added `pub` visibility for `PacketSequenceCtrl::const_new`.

# [v0.8.0] 2024-02-05

## Added

- Added `len_written` and `to_vec` methods to the `TimeWriter` trait.

# [v0.7.0] 2024-02-01

# [v0.7.0-beta.4] 2024-01-23

## Fixed

- `MetadataPduCreator`: The serialization function shifted the closure requested information
  to the wrong position (first reserved bit) inside the raw content field.

# [v0.7.0-beta.3] 2023-12-06

## Added

- Add `WritablePduPacket` trait which is a common trait of all CFDP PDU implementations.
- Add `CfdpPdu` trait which exposes fields and attributes common to all CFDP PDUs.
- Add `GenericTlv` and `WritableTlv` trait as abstractions for the various TLV types.

## Fixed

- Set the direction field inside the PDU header field correctly explicitely for all CFDP PDU
  packets.

## Changed

- Split up `FinishedPdu`into `FinishedPduCreator` and `FinishedPduReader` to expose specialized
  APIs.
- Split up `MetadataPdu`into `MetadataPduCreator` and `MetadataPduReader` to expose specialized
  APIs.
- Cleaned up CUC time implementation. Added `width` and `counter` getter methods.
- Renamed `SerializablePusPacket` to `WritablePusPacket`.
- Renamed `UnsignedPfc` to `PfcUnsigned` and `RealPfc` to `PfcReal`.
- Renamed `WritablePduPacket.written_len` and `SerializablePusPacket.len_packed` to `len_written`.
- Introduce custom implementation of `PartialEq` for `CommonPduConfig` which only compares the
  values for the source entity ID, destination entity ID and transaction sequence number field to
  allow those fields to have different widths.
- Removed the `PusError::RawDataTooShort` variant which is already covered by
  `PusError::ByteConversionError` variant.
- Ranamed `TlvLvError::ByteConversionError` to `TlvLvError::ByteConversion`.
- Renamed `PusError::IncorrectCrc` to `PusError::ChecksumFailure`.
- Some more struct variant changes for error enumerations.

## Removed

- `PusError::NoRawData` variant.
- `cfdp::LenInBytes` which was not used.

# [v0.7.0-beta.2] 2023-09-26

## Added

- `PacketId` trait impls: `Ord`, `PartialOrd` and `Hash`
- `SerializablePusPacket` trait: Add `to_vec` method with default implementation.

# [v0.7.0-beta.1] 2023-08-28

- Bump `zerocopy` dependency to v0.7.0

## Changed

- The `Tlv` and `Lv` API return `&[u8]` instead of `Option<&[u8]>`.
- `ByteConversionError` error variants `ToSliceTooSmall` and `FromSliceTooSmall` are struct
  variants now. `SizeMissmatch` was removed appropriately.
- `UnsignedByteFieldError` error variants `ValueTooLargeForWidth` and `InvalidWidth` are struct
  variants now.
- `TimestampError` error variant `InvalidTimeCode` is struct variant now.

## Added

- Added `raw_data` API for `Tlv` and `Lv` to retrieve the whole `Lv`/`Tlv` slice if the object
  was created from a raw bytestream.
- Added `MsgToUserTlv` helper class which wraps a regular `Tlv` and adds some useful functionality.
- `UnsignedByteField` and `GenericUnsignedByteField` `new` methods are `const` now.
- `PduError` variants which contained a tuple variant with multiple fields were converted to a
  struct variant.

# Added

- Added `pdu_datafield_len` getter function for `PduHeader`

## Removed

- `SizeMissmatch` because it is not required for the `ByteConversionError` error enumeration
  anymore.

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

[unreleased]: https://egit.irs.uni-stuttgart.de/rust/spacepackets/compare/v0.15.0...HEAD
[v0.15.0]: https://egit.irs.uni-stuttgart.de/rust/spacepackets/compare/v0.14.0...v0.15.0
[v0.14.0]: https://egit.irs.uni-stuttgart.de/rust/spacepackets/compare/v0.13.1...v0.14.0
[v0.13.1]: https://egit.irs.uni-stuttgart.de/rust/spacepackets/compare/v0.13.0...v0.13.1
[v0.13.0]: https://egit.irs.uni-stuttgart.de/rust/spacepackets/compare/v0.12.0...v0.13.0
[v0.12.0]: https://egit.irs.uni-stuttgart.de/rust/spacepackets/compare/v0.11.2...v0.12.0
