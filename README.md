[![Crates.io](https://img.shields.io/crates/v/spacepackets)](https://crates.io/crates/spacepackets)
[![docs.rs](https://img.shields.io/docsrs/spacepackets)](https://docs.rs/spacepackets)
[![ci](https://github.com/us-irs/spacepackets-rs/actions/workflows/ci.yml/badge.svg?branch=main)](https://github.com/us-irs/spacepackets-rs/actions/workflows/ci.yml)

ECSS and CCSDS Spacepackets
======

This package contains generic implementations for various CCSDS
(Consultative Committee for Space Data Systems) and ECSS
(European Cooperation for Space Standardization) packet standards.

Currently, this includes the following components:

- Space Packet implementation according to
  [CCSDS Blue Book 133.0-B-2](https://public.ccsds.org/Pubs/133x0b2e1.pdf)
- PUS Telecommand and PUS Telemetry implementation according to the
  [ECSS-E-ST-70-41C standard](https://ecss.nl/standard/ecss-e-st-70-41c-space-engineering-telemetry-and-telecommand-packet-utilization-15-april-2016/).
- CDS Short Time Code implementation according to
  [CCSDS CCSDS 301.0-B-4](https://public.ccsds.org/Pubs/301x0b4e1.pdf)
 
# Features

`spacepackets` supports various runtime environments and is also suitable for `no_std` environments.

It also offers optional support for [`serde`](https://serde.rs/). This allows serializing and
deserializing them with an appropriate `serde` provider like
[`postcard`](https://github.com/jamesmunns/postcard).

Default features:

 - [`std`](https://doc.rust-lang.org/std/): Enables functionality relying on the standard library.
 - [`alloc`](https://doc.rust-lang.org/alloc/): Enables features which operate on containers
   like [`alloc::vec::Vec`](https://doc.rust-lang.org/beta/alloc/vec/struct.Vec.html).
   Enabled by the `std` feature.

# Examples

You can check the [documentation](https://docs.rs/spacepackets) of individual modules for various
usage examples.
