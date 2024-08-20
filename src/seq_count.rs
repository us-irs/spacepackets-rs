use crate::MAX_SEQ_COUNT;
use core::cell::Cell;
use paste::paste;
#[cfg(feature = "std")]
pub use stdmod::*;

/// Core trait for objects which can provide a sequence count.
///
/// The core functions are not mutable on purpose to allow easier usage with
/// static structs when using the interior mutability pattern. This can be achieved by using
/// [Cell], [core::cell::RefCell] or atomic types.
pub trait SequenceCountProvider {
    type Raw: Into<u64>;
    const MAX_BIT_WIDTH: usize;

    fn get(&self) -> Self::Raw;

    fn increment(&self);

    fn get_and_increment(&self) -> Self::Raw {
        let val = self.get();
        self.increment();
        val
    }
}

#[derive(Clone)]
pub struct SeqCountProviderSimple<T: Copy> {
    seq_count: Cell<T>,
    max_val: T,
}

macro_rules! impl_for_primitives {
    ($($ty: ident,)+) => {
        $(
            paste! {
                impl SeqCountProviderSimple<$ty> {
                    pub fn [<new_custom_max_val_ $ty>](max_val: $ty) -> Self {
                        Self {
                            seq_count: Cell::new(0),
                            max_val,
                        }
                    }
                    pub fn [<new_ $ty>]() -> Self {
                        Self {
                            seq_count: Cell::new(0),
                            max_val: $ty::MAX
                        }
                    }
                }

                impl Default for SeqCountProviderSimple<$ty> {
                    fn default() -> Self {
                        Self::[<new_ $ty>]()
                    }
                }

                impl SequenceCountProvider for SeqCountProviderSimple<$ty> {
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
pub struct CcsdsSimpleSeqCountProvider {
    provider: SeqCountProviderSimple<u16>,
}

impl Default for CcsdsSimpleSeqCountProvider {
    fn default() -> Self {
        Self {
            provider: SeqCountProviderSimple::new_custom_max_val_u16(MAX_SEQ_COUNT),
        }
    }
}

impl SequenceCountProvider for CcsdsSimpleSeqCountProvider {
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

#[cfg(feature = "std")]
pub mod stdmod {
    use super::*;
    use std::sync::{Arc, Mutex};

    macro_rules! sync_clonable_seq_counter_impl {
         ($($ty: ident,)+) => {
             $(paste! {
                 /// These sequence counters can be shared between threads and can also be
                 /// configured to wrap around at specified maximum values. Please note that
                 /// that the API provided by this class will not panic und [Mutex] lock errors,
                 /// but it will yield 0 for the getter functions.
                 #[derive(Clone, Default)]
                 pub struct [<SeqCountProviderSync $ty:upper>] {
                     seq_count: Arc<Mutex<$ty>>,
                     max_val: $ty
                 }

                 impl [<SeqCountProviderSync $ty:upper>] {
                     pub fn new() -> Self {
                        Self::new_with_max_val($ty::MAX)
                     }

                     pub fn new_with_max_val(max_val: $ty) -> Self {
                         Self {
                             seq_count: Arc::default(),
                             max_val
                         }
                     }
                 }
                 impl SequenceCountProvider for [<SeqCountProviderSync $ty:upper>] {
                    type Raw = $ty;
                    const MAX_BIT_WIDTH: usize = core::mem::size_of::<Self::Raw>() * 8;

                    fn get(&self) -> $ty {
                        match self.seq_count.lock() {
                            Ok(counter) => *counter,
                            Err(_) => 0
                        }
                    }

                    fn increment(&self) {
                        self.get_and_increment();
                    }

                    fn get_and_increment(&self) -> $ty {
                        match self.seq_count.lock() {
                            Ok(mut counter) => {
                                let val = *counter;
                                if val == self.max_val {
                                    *counter = 0;
                                } else {
                                    *counter += 1;
                                }
                                val
                            }
                            Err(_) => 0,
                        }
                    }
                 }
             })+
         }
    }
    sync_clonable_seq_counter_impl!(u8, u16, u32, u64,);
}

#[cfg(test)]
mod tests {
    use crate::seq_count::{
        CcsdsSimpleSeqCountProvider, SeqCountProviderSimple, SeqCountProviderSyncU8,
        SequenceCountProvider,
    };
    use crate::MAX_SEQ_COUNT;

    #[test]
    fn test_u8_counter() {
        let u8_counter = SeqCountProviderSimple::<u8>::default();
        assert_eq!(u8_counter.get(), 0);
        assert_eq!(u8_counter.get_and_increment(), 0);
        assert_eq!(u8_counter.get_and_increment(), 1);
        assert_eq!(u8_counter.get(), 2);
    }

    #[test]
    fn test_u8_counter_overflow() {
        let u8_counter = SeqCountProviderSimple::new_u8();
        for _ in 0..256 {
            u8_counter.increment();
        }
        assert_eq!(u8_counter.get(), 0);
    }

    #[test]
    fn test_ccsds_counter() {
        let ccsds_counter = CcsdsSimpleSeqCountProvider::default();
        assert_eq!(ccsds_counter.get(), 0);
        assert_eq!(ccsds_counter.get_and_increment(), 0);
        assert_eq!(ccsds_counter.get_and_increment(), 1);
        assert_eq!(ccsds_counter.get(), 2);
    }

    #[test]
    fn test_ccsds_counter_overflow() {
        let ccsds_counter = CcsdsSimpleSeqCountProvider::default();
        for _ in 0..MAX_SEQ_COUNT + 1 {
            ccsds_counter.increment();
        }
        assert_eq!(ccsds_counter.get(), 0);
    }

    #[test]
    fn test_atomic_ref_counters() {
        let sync_u8_counter = SeqCountProviderSyncU8::new();
        assert_eq!(sync_u8_counter.get(), 0);
        assert_eq!(sync_u8_counter.get_and_increment(), 0);
        assert_eq!(sync_u8_counter.get_and_increment(), 1);
        assert_eq!(sync_u8_counter.get(), 2);
    }

    #[test]
    fn test_atomic_ref_counters_overflow() {
        let sync_u8_counter = SeqCountProviderSyncU8::new();
        for _ in 0..u8::MAX as u16 + 1 {
            sync_u8_counter.increment();
        }
        assert_eq!(sync_u8_counter.get(), 0);
    }

    #[test]
    fn test_atomic_ref_counters_overflow_custom_max_val() {
        let sync_u8_counter = SeqCountProviderSyncU8::new_with_max_val(128);
        for _ in 0..129 {
            sync_u8_counter.increment();
        }
        assert_eq!(sync_u8_counter.get(), 0);
    }
}
