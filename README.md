[![Crates.io](https://img.shields.io/crates/v/spacepackets)](https://crates.io/crates/spacepackets)
[![docs.rs](https://img.shields.io/docsrs/spacepackets)](https://docs.rs/spacepackets)
[![ci](https://github.com/us-irs/spacepackets-rs/actions/workflows/ci.yml/badge.svg?branch=main)](https://github.com/us-irs/spacepackets-rs/actions/workflows/ci.yml)
[![matrix chat](https://img.shields.io/matrix/sat-rs%3Amatrix.org)](https://matrix.to/#/#sat-rs:matrix.org)

ECSS and CCSDS Spacepackets
======

This package contains generic implementations for various CCSDS
(Consultative Committee for Space Data Systems) and ECSS
(European Cooperation for Space Standardization) packet standards.

Currently, this includes the following components:

- Space Packet implementation according to
  [CCSDS Blue Book 133.0-B-2](https://public.ccsds.org/Pubs/133x0b2e1.pdf)
- CCSDS File Delivery Protocol (CFDP) packet implementations according to
  [CCSDS Blue Book 727.0-B-5](https://public.ccsds.org/Pubs/727x0b5.pdf)
- PUS Telecommand and PUS Telemetry implementation according to the
  [ECSS-E-ST-70-41C standard](https://ecss.nl/standard/ecss-e-st-70-41c-space-engineering-telemetry-and-telecommand-packet-utilization-15-april-2016/).
- CUC (CCSDS Unsegmented Time Code) implementation according to
  [CCSDS 301.0-B-4 3.2](https://public.ccsds.org/Pubs/301x0b4e1.pdf)
- CDS (CCSDS Day Segmented Time Code) implementation according to
  [CCSDS 301.0-B-4 3.3](https://public.ccsds.org/Pubs/301x0b4e1.pdf)
- Some helper types to support ASCII timecodes as specified in
  [CCSDS 301.0-B-4 3.5](https://public.ccsds.org/Pubs/301x0b4e1.pdf)

# Features

`spacepackets` supports various runtime environments and is also suitable for `no_std` environments.

## Default features

 - [`std`](https://doc.rust-lang.org/std/): Enables functionality relying on the standard library.
 - [`alloc`](https://doc.rust-lang.org/alloc/): Enables features which operate on containers
   like [`alloc::vec::Vec`](https://doc.rust-lang.org/beta/alloc/vec/struct.Vec.html).
   Enabled by the `std` feature.

## Optional Features

 - [`serde`](https://serde.rs/): Adds `serde` support for most types by adding `Serialize` and `Deserialize` `derive`s
 - [`chrono`](https://crates.io/crates/chrono): Add basic support for the `chrono` time library.
 - [`timelib`](https://crates.io/crates/time): Add basic support for the `time` time library.
 - [`defmt`](https://defmt.ferrous-systems.com/): Add support for the `defmt` by adding the
   [`defmt::Format`](https://defmt.ferrous-systems.com/format) derive on many types.

# Examples

You can check the [documentation](https://docs.rs/spacepackets) of individual modules for various
usage examples.

# Coverage

Coverage was generated using [`grcov`](https://github.com/mozilla/grcov). If you have not done so
already, install the `llvm-tools-preview`:

```sh
rustup component add llvm-tools-preview
cargo install grcov --locked
```

After that, you can simply run `coverage.py` to test the project with coverage. You can optionally
supply the `--open` flag to open the coverage report in your webbrowser.

# Miri

You can run the [`miri`](https://github.com/rust-lang/miri) tool on this library to check for
undefined behaviour (UB). This library does not use use any `unsafe` code blocks, but `miri` could
still catch UB from used libraries.

```sh
cargo +nightly miri nextest run --all-features
```
