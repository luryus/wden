use arrayvec::ArrayString;
use zeroize::Zeroize;

pub struct ZeroizedArrayString<const N: usize>(pub ArrayString<N>);
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
    pub const fn new() -> Self {
        Self(ArrayString::new_const())
    }

    /// Insert a character in a byte position. Panics if the character won't fit.
    pub fn insert(&mut self, i: usize, c: char) {
        let mut temp = Self(ArrayString::new());
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

#[cfg(test)]
mod test {
    use zeroize::Zeroize;

    use super::ZeroizedArrayString;


    #[test]
    fn test_content_zeroized() {
        let mut str: ZeroizedArrayString<128> = Default::default();
        for _ in 0..128 {
            str.0.push('F');
        }
        str.0.clear();
        str.0.push_str("foobar");

        let slice = unsafe { str.0.get_unchecked(0..128) };
        assert!(slice.bytes().all(|b| b != 0));

        str.zeroize();

        let slice = unsafe { str.0.get_unchecked(0..128) };
        assert!(slice.bytes().all(|b| b == 0));
    }
}