all: check build test clippy fmt docs

clippy:
  cargo clippy -- -D warnings

fmt:
  cargo fmt --all -- --check

check:
  cargo check --all-features

test:
  cargo nextest r --all-features
  cargo test --doc

build:
  cargo build --all-features

docs:
  export RUSTDOCFLAGS="--cfg docsrs --generate-link-to-definition -Z unstable-options"
  cargo +nightly doc --all-features --open
