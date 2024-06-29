use arrayvec::{ArrayString, CapacityError};

pub(crate) trait ArrayStringExt {
    /// Insert a character in a byte position. Panics if i > length or if i is not on a character
    /// boundary
    fn try_insert(&mut self, i: usize, c: char) -> Result<(), CapacityError<char>>;
}

impl<const N: usize> ArrayStringExt for ArrayString<N> {
    fn try_insert(&mut self, i: usize, c: char) -> Result<(), CapacityError<char>> {
        let c_len = c.len_utf8();
        if self.remaining_capacity() < c_len {
            return Err(CapacityError::new(c));
        }

        if i > self.len() {
            panic!("Tried to insert character beyond the end of the string");
        }

        if !self.is_char_boundary(i) {
            panic!("Tried to insert character in a position that is not a char boundary");
        }

        unsafe {
            // Safety: length expansion is safe as the capacity check is done
            // above. This leaves some uninitialized elements in the underlying
            // buffer, but we immediately initialize them using copy_within
            // (copying the tail of the buffer forward to make space for the new character)
            let prev_len = self.len();
            self.set_len(prev_len + c_len);

            let buf = self.as_bytes_mut();
            // Move each byte in the tail forward so that there's space for c
            buf.copy_within(i..prev_len, i + c_len);

            // Write the new character in the created space
            c.encode_utf8(&mut buf[i..i + c_len]);
        }

        Ok(())
    }
}

#[cfg(test)]
mod test {

    use super::ArrayStringExt;
    use arrayvec::{ArrayString, CapacityError};

    #[test]
    #[should_panic]
    fn test_insert_between_char_bytes_panics() {
        let mut s: ArrayString<128> = Default::default();
        s.push('😂');
        let _ = s.try_insert(1, 'a');
    }

    #[test]
    #[should_panic]
    fn test_insert_after_end_panics() {
        let mut s: ArrayString<128> = Default::default();
        let _ = s.try_insert(100, 'a');
    }

    #[test]
    fn test_insert_in_full_errors() {
        let mut s: ArrayString<128> = ArrayString::zero_filled();
        let res = s.try_insert(0, 'a');
        assert_eq!(Err(CapacityError::new('a')), res);
    }

    #[test]
    fn test_insert_multibyte_no_space_errors() {
        let mut s: ArrayString<128> = ArrayString::zero_filled();
        s.truncate(127);
        let res = s.try_insert(1, '😂');
        assert_eq!(Err(CapacityError::new('😂')), res);
    }

    #[test]
    fn test_insert_success() {
        let mut s: ArrayString<128> = Default::default();
        s.push_str("abcde");
        s.try_insert(2, '!').unwrap();
        assert_eq!("ab!cde", &s);
    }

    #[test]
    fn test_insert_multibyte_success() {
        let mut s: ArrayString<128> = Default::default();
        s.push_str("abcde");
        s.try_insert(2, '😂').unwrap();
        assert_eq!("ab😂cde", &s);
    }

    #[test]
    fn test_insert_end() {
        let mut s: ArrayString<6> = Default::default();
        s.push_str("abcde");
        s.try_insert(5, '!').unwrap();
        assert_eq!("abcde!", &s);

        // Multibyte
        s.truncate(4);
        // ö takes 2 bytes in UTF-8
        s.try_insert(4, 'ö').unwrap();
        assert_eq!("abcdö", &s);
    }
}
