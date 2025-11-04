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
    const MAX_BIT_WIDTH: usize;

    /// Get the current sequence count value.
    fn get(&self) -> Self::Raw;

    /// Increment the sequence count by one.
    fn increment(&self);

    /// Increment the sequence count by one, mutable API.
    fn increment_mut(&mut self) {
        self.increment();
    }

    /// Get the current sequence count value and increment the counter by one.
    fn get_and_increment(&self) -> Self::Raw {
        let val = self.get();
        self.increment();
        val
    }

    /// Get the current sequence count value and increment the counter by one, mutable API.
    fn get_and_increment_mut(&mut self) -> Self::Raw {
        self.get_and_increment()
    }
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
                    pub fn [<new_custom_max_val_ $ty>](max_val: $ty) -> Self {
                        Self {
                            seq_count: Cell::new(0),
                            max_val,
                        }
                    }

                    /// Generic constructor.
                    pub fn [<new_ $ty>]() -> Self {
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
                    const MAX_BIT_WIDTH: usize = core::mem::size_of::<Self::Raw>() * 8;

                    fn get(&self) -> Self::Raw {
                        self.seq_count.get()
                    }

                    fn increment(&self) {
                        self.get_and_increment();
                    }

                    fn get_and_increment(&self) -> Self::Raw {
                        let curr_count = self.seq_count.get();

                        if curr_count == self.max_val {
                            self.seq_count.set(0);
                        } else {
                            self.seq_count.set(curr_count + 1);
                        }
                        curr_count
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
    fn default() -> Self {
        Self {
            provider: SequenceCounterSimple::new_custom_max_val_u16(MAX_SEQ_COUNT.as_u16()),
        }
    }
}

impl SequenceCounter for SequenceCounterCcsdsSimple {
    type Raw = u16;
    const MAX_BIT_WIDTH: usize = core::mem::size_of::<Self::Raw>() * 8;
    delegate::delegate! {
        to self.provider {
            fn get(&self) -> u16;
            fn increment(&self);
            fn get_and_increment(&self) -> u16;
        }
    }
}

#[cfg(target_has_atomic = "8")]
impl SequenceCounter for core::sync::atomic::AtomicU8 {
    type Raw = u8;

    const MAX_BIT_WIDTH: usize = 8;

    fn get(&self) -> Self::Raw {
        self.load(core::sync::atomic::Ordering::Relaxed)
    }

    fn increment(&self) {
        self.fetch_add(1, core::sync::atomic::Ordering::Relaxed);
    }
}

#[cfg(target_has_atomic = "16")]
impl SequenceCounter for core::sync::atomic::AtomicU16 {
    type Raw = u16;

    const MAX_BIT_WIDTH: usize = 16;

    fn get(&self) -> Self::Raw {
        self.load(core::sync::atomic::Ordering::Relaxed)
    }

    fn increment(&self) {
        self.fetch_add(1, core::sync::atomic::Ordering::Relaxed);
    }
}

#[cfg(target_has_atomic = "32")]
impl SequenceCounter for core::sync::atomic::AtomicU32 {
    type Raw = u32;

    const MAX_BIT_WIDTH: usize = 32;

    fn get(&self) -> Self::Raw {
        self.load(core::sync::atomic::Ordering::Relaxed)
    }

    fn increment(&self) {
        self.fetch_add(1, core::sync::atomic::Ordering::Relaxed);
    }
}

#[cfg(target_has_atomic = "64")]
impl SequenceCounter for core::sync::atomic::AtomicU64 {
    type Raw = u64;

    const MAX_BIT_WIDTH: usize = 64;

    fn get(&self) -> Self::Raw {
        self.load(core::sync::atomic::Ordering::Relaxed)
    }

    fn increment(&self) {
        self.fetch_add(1, core::sync::atomic::Ordering::Relaxed);
    }
}

#[cfg(feature = "portable-atomic")]
impl SequenceCounter for portable_atomic::AtomicU8 {
    type Raw = u8;

    const MAX_BIT_WIDTH: usize = 8;

    fn get(&self) -> Self::Raw {
        self.load(portable_atomic::Ordering::Relaxed)
    }

    fn increment(&self) {
        self.fetch_add(1, portable_atomic::Ordering::Relaxed);
    }
}

#[cfg(feature = "portable-atomic")]
impl SequenceCounter for portable_atomic::AtomicU16 {
    type Raw = u16;

    const MAX_BIT_WIDTH: usize = 16;

    fn get(&self) -> Self::Raw {
        self.load(portable_atomic::Ordering::Relaxed)
    }

    fn increment(&self) {
        self.fetch_add(1, portable_atomic::Ordering::Relaxed);
    }
}

#[cfg(feature = "portable-atomic")]
impl SequenceCounter for portable_atomic::AtomicU32 {
    type Raw = u32;

    const MAX_BIT_WIDTH: usize = 32;

    fn get(&self) -> Self::Raw {
        self.load(portable_atomic::Ordering::Relaxed)
    }

    fn increment(&self) {
        self.fetch_add(1, portable_atomic::Ordering::Relaxed);
    }
}

#[cfg(feature = "portable-atomic")]
impl SequenceCounter for portable_atomic::AtomicU64 {
    type Raw = u64;

    const MAX_BIT_WIDTH: usize = 64;

    fn get(&self) -> Self::Raw {
        self.load(portable_atomic::Ordering::Relaxed)
    }

    fn increment(&self) {
        self.fetch_add(1, portable_atomic::Ordering::Relaxed);
    }
}

impl<T: SequenceCounter + ?Sized> SequenceCounter for &T {
    type Raw = T::Raw;
    const MAX_BIT_WIDTH: usize = T::MAX_BIT_WIDTH;

    fn get(&self) -> Self::Raw {
        (**self).get()
    }

    fn increment(&self) {
        (**self).increment()
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
                const MAX_BIT_WIDTH: usize = core::mem::size_of::<Self::Raw>() * 8;

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

#[cfg(test)]
mod tests {
    use core::sync::atomic::{AtomicU16, AtomicU32, AtomicU64, AtomicU8};

    use crate::seq_count::{
        SequenceCounter, SequenceCounterCcsdsSimple, SequenceCounterSimple,
        SequenceCounterSyncCustomWrapU8,
    };
    use crate::MAX_SEQ_COUNT;

    #[test]
    fn test_u8_counter() {
        let u8_counter = SequenceCounterSimple::<u8>::default();
        assert_eq!(u8_counter.get(), 0);
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
        seq_counter.increment_mut();
        assert_eq!(seq_counter.get().into(), 3);
        assert_eq!(seq_counter.get_and_increment_mut().into(), 3);
        assert_eq!(seq_counter.get().into(), 4);
    }

    #[test]
    fn test_atomic_counter_u8() {
        let mut sync_u8_counter = AtomicU8::new(0);
        common_counter_test(&mut sync_u8_counter);
    }

    #[test]
    fn test_atomic_counter_u16() {
        let mut sync_u16_counter = AtomicU16::new(0);
        common_counter_test(&mut sync_u16_counter);
    }

    #[test]
    fn test_atomic_counter_u32() {
        let mut sync_u32_counter = AtomicU32::new(0);
        common_counter_test(&mut sync_u32_counter);
    }

    #[test]
    fn test_atomic_counter_u64() {
        let mut sync_u64_counter = AtomicU64::new(0);
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
}
