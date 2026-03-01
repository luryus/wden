use std::pin::Pin;

use zeroize::{ZeroizeOnDrop};

const BUFFER_CAPACITY: usize = 256;

#[derive(Clone, ZeroizeOnDrop)]
pub struct SecureBuffer<const SIZE: usize> 
{
    buffer: Pin<Box<[u8; SIZE]>>,
}

impl<const SIZE: usize> SecureBuffer<SIZE> {
    pub fn new() -> Self {
        const { assert!(SIZE <= BUFFER_CAPACITY, "SecureBuffer size must be less than or equal to BUFFER_CAPACITY"); }
        Self {
            buffer: Box::pin([0u8; SIZE]),
        }
    }

    pub fn as_slice(&self) -> &[u8] {
        self.buffer.as_slice()
    }

    pub fn as_mut_slice(&mut self) -> &mut [u8] {
        self.buffer.as_mut_slice()
    }
}
