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
- CDS Short Time Code implementations according to
  [CCSDS CCSDS 301.0-B-4](https://public.ccsds.org/Pubs/301x0b4e1.pdf)

This package is suitable for `no_std` environments.

It features optional support for the [`alloc`](https://doc.rust-lang.org/alloc/) crate
and also offers support for [`serde`](https://serde.rs/). The Space Paccket, PUS TM and TC implementations
derive the `serde` `Serialize` and `Deserialize` trait. This allows serializing and
deserializing them with an appropriate `serde` provider like
[`postcard`](https://github.com/jamesmunns/postcard).
