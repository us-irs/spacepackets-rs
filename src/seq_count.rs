//! # Sequence counter module.
//!
//! CCSDS and ECSS packet standard oftentimes use sequence counters, for example to allow detecting
//! packet gaps. This module provides basic abstractions and helper components to implement
//! sequence counters.
use crate::MAX_SEQ_COUNT;
use arbitrary_int::traits::Integer;
use core::cell::Cell;
use paste::paste;

/// Core trait for objects which can provide a sequence count.
///
/// The core functions are not mutable on purpose to allow easier usage with
/// static structs when using the interior mutability pattern. This can be achieved by using
/// [Cell], [core::cell::RefCell] or atomic types.
pub trait SequenceCounter {
    /// Raw type of the counter.
    type Raw: Into<u64>;

    /// Bit width of the counter.
    fn max_bit_width(&self) -> usize;

    /// Get the current sequence count value.
    fn get(&self) -> Self::Raw;

    /// Increment the sequence count by one.
    fn increment(&self);

    /// Get the current sequence count value and increment the counter by one.
    fn get_and_increment(&self) -> Self::Raw {
        let val = self.get();
        self.increment();
        val
    }

    /// Set the sequence counter.
    ///
    /// This should not be required by default but can be used to reset the counter
    /// or initialize it with a custom value.
    fn set(&self, value: Self::Raw);
}

/// Simple sequence counter which wraps at ´T::MAX´.
#[derive(Clone)]
pub struct SequenceCounterSimple<T: Copy> {
    seq_count: Cell<T>,
    // The maximum value
    max_val: T,
}

macro_rules! impl_for_primitives {
    ($($ty: ident,)+) => {
        $(
            paste! {
                impl SequenceCounterSimple<$ty> {
                    /// Constructor with a custom maximum value.
                    pub const fn [<new_custom_max_val_ $ty>](max_val: $ty) -> Self {
                        Self {
                            seq_count: Cell::new(0),
                            max_val,
                        }
                    }

                    /// Generic constructor.
                    pub const fn [<new_ $ty>]() -> Self {
                        Self {
                            seq_count: Cell::new(0),
                            max_val: $ty::MAX
                        }
                    }
                }

                impl Default for SequenceCounterSimple<$ty> {
                    fn default() -> Self {
                        Self::[<new_ $ty>]()
                    }
                }

                impl SequenceCounter for SequenceCounterSimple<$ty> {
                    type Raw = $ty;

                    #[inline]
                    fn max_bit_width(&self) -> usize {
                        core::mem::size_of::<Self::Raw>() * 8
                    }

                    #[inline]
                    fn get(&self) -> Self::Raw {
                        self.seq_count.get()
                    }

                    #[inline]
                    fn increment(&self) {
                        self.get_and_increment();
                    }

                    #[inline]
                    fn get_and_increment(&self) -> Self::Raw {
                        let curr_count = self.seq_count.get();

                        if curr_count == self.max_val {
                            self.seq_count.set(0);
                        } else {
                            self.seq_count.set(curr_count + 1);
                        }
                        curr_count
                    }

                    #[inline]
                    fn set(&self, value: Self::Raw) {
                        self.seq_count.set(value);
                    }
                }
            }
        )+
    }
}

impl_for_primitives!(u8, u16, u32, u64,);

/// This is a sequence count provider which wraps around at [MAX_SEQ_COUNT].
#[derive(Clone)]
pub struct SequenceCounterCcsdsSimple {
    provider: SequenceCounterSimple<u16>,
}

impl Default for SequenceCounterCcsdsSimple {
    #[inline]
    fn default() -> Self {
        Self {
            provider: SequenceCounterSimple::new_custom_max_val_u16(MAX_SEQ_COUNT.as_u16()),
        }
    }
}

impl SequenceCounter for SequenceCounterCcsdsSimple {
    type Raw = u16;
    delegate::delegate! {
        to self.provider {
            fn get(&self) -> u16;
            fn increment(&self);
            fn get_and_increment(&self) -> u16;
        }
    }

    #[inline]
    fn set(&self, value: u16) {
        if value > MAX_SEQ_COUNT.as_u16() {
            return;
        }
        self.provider.set(value);
    }

    #[inline]
    fn max_bit_width(&self) -> usize {
        Self::MAX_BIT_WIDTH
    }
}

impl SequenceCounterCcsdsSimple {
    /// Maximum bit width for CCSDS packet sequence counter is 14 bits.
    pub const MAX_BIT_WIDTH: usize = 14;

    /// Create a new sequence counter specifically for the sequence count of CCSDS packets.
    ///
    /// It has a [Self::MAX_BIT_WIDTH] of 14.
    pub const fn new() -> Self {
        Self {
            provider: SequenceCounterSimple::new_custom_max_val_u16(MAX_SEQ_COUNT.value()),
        }
    }
}

#[cfg(target_has_atomic = "8")]
impl SequenceCounter for core::sync::atomic::AtomicU8 {
    type Raw = u8;

    #[inline]
    fn max_bit_width(&self) -> usize {
        8
    }

    #[inline]
    fn get(&self) -> Self::Raw {
        self.load(core::sync::atomic::Ordering::Relaxed)
    }

    #[inline]
    fn increment(&self) {
        self.fetch_add(1, core::sync::atomic::Ordering::Relaxed);
    }

    #[inline]
    fn set(&self, value: u8) {
        self.store(value, core::sync::atomic::Ordering::Relaxed);
    }
}

#[cfg(target_has_atomic = "16")]
impl SequenceCounter for core::sync::atomic::AtomicU16 {
    type Raw = u16;

    #[inline]
    fn max_bit_width(&self) -> usize {
        16
    }

    #[inline]
    fn get(&self) -> Self::Raw {
        self.load(core::sync::atomic::Ordering::Relaxed)
    }

    #[inline]
    fn increment(&self) {
        self.fetch_add(1, core::sync::atomic::Ordering::Relaxed);
    }

    #[inline]
    fn set(&self, value: u16) {
        self.store(value, core::sync::atomic::Ordering::Relaxed);
    }
}

#[cfg(target_has_atomic = "32")]
impl SequenceCounter for core::sync::atomic::AtomicU32 {
    type Raw = u32;

    #[inline]
    fn max_bit_width(&self) -> usize {
        32
    }

    #[inline]
    fn get(&self) -> Self::Raw {
        self.load(core::sync::atomic::Ordering::Relaxed)
    }

    #[inline]
    fn increment(&self) {
        self.fetch_add(1, core::sync::atomic::Ordering::Relaxed);
    }

    #[inline]
    fn set(&self, value: u32) {
        self.store(value, core::sync::atomic::Ordering::Relaxed);
    }
}

#[cfg(target_has_atomic = "64")]
impl SequenceCounter for core::sync::atomic::AtomicU64 {
    type Raw = u64;

    #[inline]
    fn max_bit_width(&self) -> usize {
        64
    }

    #[inline]
    fn get(&self) -> Self::Raw {
        self.load(core::sync::atomic::Ordering::Relaxed)
    }

    #[inline]
    fn increment(&self) {
        self.fetch_add(1, core::sync::atomic::Ordering::Relaxed);
    }

    #[inline]
    fn set(&self, value: u64) {
        self.store(value, core::sync::atomic::Ordering::Relaxed);
    }
}

#[cfg(feature = "portable-atomic")]
impl SequenceCounter for portable_atomic::AtomicU8 {
    type Raw = u8;

    #[inline]
    fn max_bit_width(&self) -> usize {
        8
    }

    fn get(&self) -> Self::Raw {
        self.load(portable_atomic::Ordering::Relaxed)
    }

    fn increment(&self) {
        self.fetch_add(1, portable_atomic::Ordering::Relaxed);
    }

    fn set(&self, value: Self::Raw) {
        self.store(value, portable_atomic::Ordering::Relaxed);
    }
}

#[cfg(feature = "portable-atomic")]
impl SequenceCounter for portable_atomic::AtomicU16 {
    type Raw = u16;

    #[inline]
    fn max_bit_width(&self) -> usize {
        16
    }

    fn get(&self) -> Self::Raw {
        self.load(portable_atomic::Ordering::Relaxed)
    }

    fn increment(&self) {
        self.fetch_add(1, portable_atomic::Ordering::Relaxed);
    }

    fn set(&self, value: Self::Raw) {
        self.store(value, portable_atomic::Ordering::Relaxed);
    }
}

#[cfg(feature = "portable-atomic")]
impl SequenceCounter for portable_atomic::AtomicU32 {
    type Raw = u32;

    #[inline]
    fn max_bit_width(&self) -> usize {
        32
    }

    fn get(&self) -> Self::Raw {
        self.load(portable_atomic::Ordering::Relaxed)
    }

    fn increment(&self) {
        self.fetch_add(1, portable_atomic::Ordering::Relaxed);
    }

    fn set(&self, value: Self::Raw) {
        self.store(value, portable_atomic::Ordering::Relaxed);
    }
}

#[cfg(feature = "portable-atomic")]
impl SequenceCounter for portable_atomic::AtomicU64 {
    type Raw = u64;

    #[inline]
    fn max_bit_width(&self) -> usize {
        64
    }

    fn get(&self) -> Self::Raw {
        self.load(portable_atomic::Ordering::Relaxed)
    }

    fn increment(&self) {
        self.fetch_add(1, portable_atomic::Ordering::Relaxed);
    }

    fn set(&self, value: Self::Raw) {
        self.store(value, portable_atomic::Ordering::Relaxed);
    }
}

impl<T: SequenceCounter + ?Sized> SequenceCounter for &T {
    type Raw = T::Raw;

    #[inline]
    fn max_bit_width(&self) -> usize {
        (**self).max_bit_width()
    }

    #[inline]
    fn get(&self) -> Self::Raw {
        (**self).get()
    }

    #[inline]
    fn increment(&self) {
        (**self).increment()
    }

    fn set(&self, value: Self::Raw) {
        (**self).set(value);
    }
}

#[cfg(any(
    target_has_atomic = "8",
    target_has_atomic = "16",
    target_has_atomic = "32",
    target_has_atomic = "64"
))]
macro_rules! sync_clonable_seq_counter_impl {
    ($ty: ident) => {
        paste::paste! {
            /// This can be used if a custom wrap value is required when using a thread-safe
            /// atomic based sequence counter.
            #[derive(Debug)]
            pub struct [<SequenceCounterSyncCustomWrap $ty:upper>] {
                seq_count: core::sync::atomic::[<Atomic $ty:upper>],
                max_val: $ty,
            }

            impl [<SequenceCounterSyncCustomWrap $ty:upper>] {
                /// Generic constructor.
                pub fn new(max_val: $ty) -> Self {
                    Self {
                        seq_count: core::sync::atomic::[<Atomic $ty:upper>]::new(0),
                        max_val,
                    }
                }
            }

            impl SequenceCounter for [<SequenceCounterSyncCustomWrap $ty:upper>] {
                type Raw = $ty;

                fn max_bit_width(&self) -> usize {
                    core::mem::size_of::<Self::Raw>() * 8
                }

                fn get(&self) -> $ty {
                    self.seq_count.load(core::sync::atomic::Ordering::Relaxed)
                }

                fn increment(&self) {
                    self.get_and_increment();
                }

                fn get_and_increment(&self) -> $ty {
                    self.seq_count.fetch_update(
                        core::sync::atomic::Ordering::Relaxed,
                        core::sync::atomic::Ordering::Relaxed,
                        |cur| {
                            // compute the next value, wrapping at MAX_VAL
                            let next = if cur == self.max_val { 0 } else { cur + 1 };
                            Some(next)
                        },
                    ).unwrap()
                }

                fn set(&self, value: $ty) {
                    self.seq_count.store(value, core::sync::atomic::Ordering::Relaxed);
                }
            }
        }
    };
}

#[cfg(target_has_atomic = "8")]
sync_clonable_seq_counter_impl!(u8);
#[cfg(target_has_atomic = "16")]
sync_clonable_seq_counter_impl!(u16);
#[cfg(target_has_atomic = "32")]
sync_clonable_seq_counter_impl!(u32);
#[cfg(target_has_atomic = "64")]
sync_clonable_seq_counter_impl!(u64);

/// Modules relying on [std] support.
#[cfg(feature = "std")]
pub mod std_mod {
    use super::*;

    use core::str::FromStr;
    use std::path::{Path, PathBuf};
    use std::string::ToString as _;
    use std::{fs, io};

    /// A persistent file-backed sequence counter that can wrap any other [SequenceCounter]
    /// implementation which is non-persistent.
    ///
    /// In the default configuration, the underlying [SequenceCounter] is initialized from the file
    /// content, and the file content will only be updated on a manual [Self::save] or on drop.
    #[derive(Debug, PartialEq, Eq)]
    pub struct SequenceCounterOnFile<
        Inner: SequenceCounter<Raw = RawTy>,
        RawTy: core::fmt::Debug
            + Copy
            + Clone
            + Into<u64>
            + TryFrom<u64>
            + FromStr
            + Default
            + PartialEq
            + Eq,
    > {
        path: PathBuf,
        inner: Inner,
        /// Configures whether the counter value is saved to disk when the object is dropped.
        ///
        /// If this is set to [true] which is the default, the sequence counter will only be stored
        /// to disk if the [Self::save] method is used or the object is dropped. Otherwise, the
        /// counter will be saved to disk on every [Self::increment] or [Self::set].
        pub save_on_drop: bool,
    }

    impl<
            Inner: SequenceCounter<Raw = RawTy>,
            RawTy: core::fmt::Debug
                + Copy
                + Clone
                + Into<u64>
                + TryFrom<u64>
                + FromStr
                + Default
                + PartialEq
                + Eq,
        > SequenceCounterOnFile<Inner, RawTy>
    {
        /// Initialize a new persistent sequence counter using a file at the given path and
        /// any non persistent inner [SequenceCounter] implementation.
        pub fn new<P: AsRef<Path>>(path: P, inner: Inner) -> io::Result<Self> {
            let path = path.as_ref().to_path_buf();
            let value = Self::load_from_path(&path);
            inner.set(value);
            Ok(Self {
                path,
                inner,
                save_on_drop: true,
            })
        }

        fn load_from_path(path: &Path) -> RawTy {
            let bytes = match fs::read(path) {
                Ok(b) => b,
                Err(_) => return Default::default(),
            };

            // Trim optional single trailing newline (Unix/Windows)
            let trimmed = match bytes.last() {
                Some(&b'\n') => &bytes[..bytes.len() - 1],
                _ => &bytes,
            };

            // Reject non-ASCII
            if !trimmed.is_ascii() {
                return Default::default();
            }

            // Parse
            std::str::from_utf8(trimmed)
                .ok()
                .and_then(|s| s.parse().ok())
                .unwrap_or_default()
        }

        /// Persist the current value to disk (best-effort).
        pub fn save(&self) -> io::Result<()> {
            let value = self.inner.get();
            std::fs::write(&self.path, value.into().to_string())
        }
    }

    impl<
            Inner: SequenceCounter<Raw = RawTy>,
            RawTy: core::fmt::Debug
                + Copy
                + Clone
                + Into<u64>
                + TryFrom<u64, Error: core::fmt::Debug>
                + FromStr
                + Default
                + PartialEq
                + Eq,
        > SequenceCounter for SequenceCounterOnFile<Inner, RawTy>
    {
        type Raw = RawTy;

        fn max_bit_width(&self) -> usize {
            self.inner.max_bit_width()
        }

        fn get(&self) -> RawTy {
            self.inner.get()
        }

        fn increment(&self) {
            self.inner.increment();

            if !self.save_on_drop {
                // persist (ignore I/O errors here; caller can call `save` explicitly)
                let _ = self.save();
            }
        }

        fn set(&self, value: RawTy) {
            self.inner.set(value);
            if !self.save_on_drop {
                // persist (ignore I/O errors here; caller can call `save` explicitly)
                let _ = self.save();
            }
        }
    }

    impl<
            Inner: SequenceCounter<Raw = RawTy>,
            RawTy: core::fmt::Debug
                + Copy
                + Clone
                + Into<u64>
                + TryFrom<u64>
                + FromStr
                + Default
                + PartialEq
                + Eq,
        > Drop for SequenceCounterOnFile<Inner, RawTy>
    {
        fn drop(&mut self) {
            if self.save_on_drop {
                let _ = self.save();
            }
        }
    }

    /// Type alisas for a CCSDS sequence counter stored on file.
    pub type SequenceCounterCcsdsOnFile = SequenceCounterOnFile<SequenceCounterCcsdsSimple, u16>;

    impl SequenceCounterCcsdsOnFile {
        /// Open or create the counter file at `path`.
        pub fn new_ccsds_counter<P: AsRef<Path>>(path: P) -> io::Result<Self> {
            SequenceCounterOnFile::new(path, SequenceCounterCcsdsSimple::default())
        }
    }

    /// Type alisas for a [u16] sequence counter stored on file.
    pub type SequenceCounterU16OnFile = SequenceCounterOnFile<SequenceCounterSimple<u16>, u16>;

    impl SequenceCounterU16OnFile {
        /// Open or create the counter file at `path`.
        pub fn new_u16_counter<P: AsRef<Path>>(path: P) -> io::Result<Self> {
            SequenceCounterOnFile::new(path, SequenceCounterSimple::<u16>::default())
        }
    }
}

#[cfg(test)]
mod tests {
    use core::sync::atomic::{AtomicU16, AtomicU32, AtomicU64, AtomicU8};
    use std::boxed::Box;

    use crate::seq_count::{
        SequenceCounter, SequenceCounterCcsdsSimple, SequenceCounterSimple,
        SequenceCounterSyncCustomWrapU8,
    };
    use crate::MAX_SEQ_COUNT;

    #[test]
    fn test_u8_counter() {
        let u8_counter = SequenceCounterSimple::<u8>::default();
        assert_eq!(u8_counter.get(), 0);
        assert_eq!(u8_counter.max_bit_width(), 8);
        assert_eq!(u8_counter.get_and_increment(), 0);
        assert_eq!(u8_counter.get_and_increment(), 1);
        assert_eq!(u8_counter.get(), 2);
    }

    #[test]
    fn test_u8_counter_overflow() {
        let u8_counter = SequenceCounterSimple::new_u8();
        for _ in 0..256 {
            u8_counter.increment();
        }
        assert_eq!(u8_counter.get(), 0);
    }

    #[test]
    fn test_ccsds_counter() {
        let ccsds_counter = SequenceCounterCcsdsSimple::default();
        assert_eq!(ccsds_counter.get(), 0);
        assert_eq!(ccsds_counter.get_and_increment(), 0);
        assert_eq!(ccsds_counter.get_and_increment(), 1);
        assert_eq!(ccsds_counter.get(), 2);
    }

    #[test]
    fn test_ccsds_counter_overflow() {
        let ccsds_counter = SequenceCounterCcsdsSimple::default();
        for _ in 0..MAX_SEQ_COUNT.value() + 1 {
            ccsds_counter.increment();
        }
        assert_eq!(ccsds_counter.get(), 0);
    }

    fn common_counter_test(seq_counter: &mut impl SequenceCounter) {
        assert_eq!(seq_counter.get().into(), 0);
        assert_eq!(seq_counter.get_and_increment().into(), 0);
        assert_eq!(seq_counter.get_and_increment().into(), 1);
        assert_eq!(seq_counter.get().into(), 2);
        seq_counter.increment();
        assert_eq!(seq_counter.get().into(), 3);
        assert_eq!(seq_counter.get_and_increment().into(), 3);
        assert_eq!(seq_counter.get().into(), 4);
    }

    #[test]
    fn test_atomic_counter_u8() {
        let mut sync_u8_counter = AtomicU8::new(0);
        assert_eq!(sync_u8_counter.max_bit_width(), 8);
        common_counter_test(&mut sync_u8_counter);
    }

    #[test]
    fn test_atomic_counter_u16() {
        let mut sync_u16_counter = AtomicU16::new(0);
        assert_eq!(sync_u16_counter.max_bit_width(), 16);
        common_counter_test(&mut sync_u16_counter);
    }

    #[test]
    fn test_atomic_counter_u32() {
        let mut sync_u32_counter = AtomicU32::new(0);
        assert_eq!(sync_u32_counter.max_bit_width(), 32);
        common_counter_test(&mut sync_u32_counter);
    }

    #[test]
    fn test_atomic_counter_u64() {
        let mut sync_u64_counter = AtomicU64::new(0);
        assert_eq!(sync_u64_counter.max_bit_width(), 64);
        common_counter_test(&mut sync_u64_counter);
    }

    #[test]
    #[cfg(feature = "portable-atomic")]
    fn test_portable_atomic_counter_u8() {
        let mut sync_u8_counter = portable_atomic::AtomicU8::new(0);
        common_counter_test(&mut sync_u8_counter);
    }

    #[test]
    #[cfg(feature = "portable-atomic")]
    fn test_portable_atomic_counter_u16() {
        let mut sync_u16_counter = portable_atomic::AtomicU16::new(0);
        common_counter_test(&mut sync_u16_counter);
    }

    #[test]
    #[cfg(feature = "portable-atomic")]
    fn test_portable_atomic_counter_u32() {
        let mut sync_u32_counter = portable_atomic::AtomicU32::new(0);
        common_counter_test(&mut sync_u32_counter);
    }

    #[test]
    #[cfg(feature = "portable-atomic")]
    fn test_portable_atomic_counter_u64() {
        let mut sync_u64_counter = portable_atomic::AtomicU64::new(0);
        common_counter_test(&mut sync_u64_counter);
    }

    fn common_overflow_test_u8(seq_counter: &impl SequenceCounter) {
        for _ in 0..u8::MAX as u16 + 1 {
            seq_counter.increment();
        }
        assert_eq!(seq_counter.get().into(), 0);
    }

    #[test]
    fn test_atomic_u8_counter_overflow() {
        let sync_u8_counter = AtomicU8::new(0);
        common_overflow_test_u8(&sync_u8_counter);
    }

    #[test]
    #[cfg(feature = "portable-atomic")]
    fn test_portable_atomic_u8_counter_overflow() {
        let sync_u8_counter = portable_atomic::AtomicU8::new(0);
        common_overflow_test_u8(&sync_u8_counter);
    }

    #[test]
    fn test_atomic_ref_counters_overflow_custom_max_val() {
        let sync_u8_counter = SequenceCounterSyncCustomWrapU8::new(128);
        for _ in 0..129 {
            sync_u8_counter.increment();
        }
        assert_eq!(sync_u8_counter.get(), 0);
    }

    #[test]
    fn test_dyn_compatible() {
        let counter: Box<dyn SequenceCounter<Raw = u16>> =
            Box::new(SequenceCounterCcsdsSimple::default());
        assert_eq!(counter.get(), 0);
        assert_eq!(counter.max_bit_width(), 14);
        counter.increment();
        assert_eq!(counter.get(), 1);
        assert_eq!(counter.get_and_increment(), 1);
        assert_eq!(counter.get(), 2);
    }

    #[test]
    fn test_persistent_counter() {
        let tempdir = tempfile::tempdir().expect("failed to create temp dir");
        let path = tempdir.path().join("seq_count.txt");
        let mut persistent_counter =
            crate::seq_count::std_mod::SequenceCounterCcsdsOnFile::new_ccsds_counter(&path)
                .unwrap();
        assert_eq!(persistent_counter.get(), 0);
        assert_eq!(persistent_counter.get_and_increment(), 0);
        drop(persistent_counter);
        assert!(path.exists());

        persistent_counter =
            crate::seq_count::std_mod::SequenceCounterCcsdsOnFile::new_ccsds_counter(
                tempdir.path().join("seq_count.txt"),
            )
            .unwrap();
        assert_eq!(persistent_counter.get(), 1);
    }

    #[test]
    fn test_persistent_couter_manual_save() {
        let tempdir = tempfile::tempdir().expect("failed to create temp dir");
        let path = tempdir.path().join("seq_count.txt");
        let mut persistent_counter =
            crate::seq_count::std_mod::SequenceCounterCcsdsOnFile::new_ccsds_counter(&path)
                .unwrap();
        assert_eq!(persistent_counter.get(), 0);
        assert_eq!(persistent_counter.get_and_increment(), 0);
        persistent_counter.save().unwrap();
        assert!(path.exists());
        std::mem::forget(persistent_counter);
        persistent_counter =
            crate::seq_count::std_mod::SequenceCounterCcsdsOnFile::new_ccsds_counter(
                tempdir.path().join("seq_count.txt"),
            )
            .unwrap();
        assert_eq!(persistent_counter.get(), 1);
    }
}
