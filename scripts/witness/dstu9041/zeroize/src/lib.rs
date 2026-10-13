//! What uacrypt uses of zeroize, without the clearing.
#![no_std]

pub use zeroize_derive::{Zeroize, ZeroizeOnDrop};

/// The trait, for every type, clearing nothing.
pub trait Zeroize {
    fn zeroize(&mut self) {}
}
impl<T: ?Sized> Zeroize for T {}

/// A marker under the name the derive shares.
pub trait ZeroizeOnDrop {}

/// The wrapper, holding its value.
pub struct Zeroizing<T>(T);

impl<T> Zeroizing<T> {
    pub fn new(value: T) -> Self {
        Zeroizing(value)
    }
}

impl<T> core::ops::Deref for Zeroizing<T> {
    type Target = T;
    fn deref(&self) -> &T {
        &self.0
    }
}

impl<T> core::ops::DerefMut for Zeroizing<T> {
    fn deref_mut(&mut self) -> &mut T {
        &mut self.0
    }
}
