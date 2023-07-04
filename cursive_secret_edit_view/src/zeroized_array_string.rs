use std::{
    ops::{Deref, DerefMut},
    pin::Pin,
};

use arrayvec::ArrayString;
use zeroize::Zeroize;

pub struct ZeroizedArrayString<const N: usize>(pub Pin<Box<ArrayString<N>>>);
impl<const N: usize> Zeroize for ZeroizedArrayString<N> {
    fn zeroize(&mut self) {
        unsafe {
            self.0.set_len(N);
            self.0.as_bytes_mut()
        }
        .zeroize()
    }
}

impl<const N: usize> ZeroizedArrayString<N> {
    pub fn new() -> Self {
        Self(Box::pin(ArrayString::new_const()))
    }

    /// Insert a character in a byte position. Panics if the character won't fit.
    pub fn insert(&mut self, i: usize, c: char) {
        let mut temp = Self::new();
        // Copy the end
        temp.0.push_str(self.0.split_at(i).1);
        self.0.truncate(i);
        self.0.push(c);
        self.0.push_str(&temp.0);
    }
}

impl<const N: usize> Default for ZeroizedArrayString<N> {
    fn default() -> Self {
        Self::new()
    }
}

impl<const N: usize> Deref for ZeroizedArrayString<N> {
    type Target = ArrayString<N>;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl<const N: usize> DerefMut for ZeroizedArrayString<N> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

#[cfg(test)]
mod test {
    use zeroize::Zeroize;

    use super::ZeroizedArrayString;

    #[test]
    fn test_content_zeroized() {
        let mut str: ZeroizedArrayString<128> = Default::default();
        for _ in 0..128 {
            str.push('F');
        }
        str.clear();
        str.push_str("foobar");

        let slice = unsafe { str.get_unchecked(0..128) };
        assert!(slice.bytes().all(|b| b != 0));

        str.zeroize();

        let slice = unsafe { str.get_unchecked(0..128) };
        assert!(slice.bytes().all(|b| b == 0));
    }
}
