Change Log
=======

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](http://keepachangelog.com/)
and this project adheres to [Semantic Versioning](http://semver.org/).

# [unreleased]

# [v0.2.0] 13.09.2022

## Added

- Basic support for ECSS enumeration types for u8, u16, u32 and u64

## Changed

- Better names for generic error enumerations: `PacketError` renamed to `ByteConversionError`
- `ssc` abbreviations fully replaced by better name `seq_count`
- Time module: `CcsdsTimeProvider::date_time` now has `Option<DateTime<Utc>>` as
  a returnvalue instead of `DateTime<Utc>`

# [v0.1.0] 16.08.2022

Initial release with CCSDS Space Packet Primary Header implementation and basic PUS TC and TM
implementations.
