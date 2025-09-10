all: check clippy fmt build docs

clippy:
  cargo clippy -- -D warnings

fmt:
  cargo fmt --all -- --check

check:
  cargo check --all-features

build:
  cargo build --all-features

docs:
  export RUSTDOCFLAGS="--cfg docsrs --generate-link-to-definition -Z unstable-options"
  cargo +nightly doc --all-features
