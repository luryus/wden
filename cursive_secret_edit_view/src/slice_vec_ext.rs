use tinyvec::SliceVec;

pub(crate) trait SliceVecExt {
    /// Insert a slice of bytes at position `i`. Panics if `i > len`.
    fn try_insert(&mut self, i: usize, bytes: &[u8]) -> Result<(), ()>;
}

impl SliceVecExt for SliceVec<'_, u8> {
    fn try_insert(&mut self, i: usize, bytes: &[u8]) -> Result<(), ()> {
        if i > self.len() {
            panic!("Tried to insert bytes beyond the end of the buffer");
        }

        let remaining_capacity = self.capacity() - self.len();
        if remaining_capacity < bytes.len() {
            return Err(());
        }

        let prev_len = self.len();
        // Extend length by bytes.len() to make room
        for _ in 0..bytes.len() {
            self.push(0);
        }
        // Shift existing tail forward
        self.copy_within(i..prev_len, i + bytes.len());
        // Write the new bytes
        self[i..i + bytes.len()].copy_from_slice(bytes);

        Ok(())
    }
}

#[cfg(test)]
mod test {
    use super::SliceVecExt;
    use tinyvec::SliceVec;

    fn make_vec<'a>(backing: &'a mut [u8], data: &[u8]) -> SliceVec<'a, u8> {
        let mut v = SliceVec::from_slice_len(backing, 0);
        for &b in data {
            v.push(b);
        }
        v
    }

    #[test]
    #[should_panic]
    fn test_insert_after_end_panics() {
        let mut backing = [0u8; 128];
        let mut v = make_vec(&mut backing, b"abcde");
        let _ = v.try_insert(100, b"!");
    }

    #[test]
    fn test_insert_in_full_errors() {
        let mut backing = [0u8; 5];
        let mut v = make_vec(&mut backing, b"abcde");
        assert!(v.try_insert(0, b"!").is_err());
    }

    #[test]
    fn test_insert_success() {
        let mut backing = [0u8; 128];
        let mut v = make_vec(&mut backing, b"abcde");
        v.try_insert(2, b"!").unwrap();
        assert_eq!(&v[..], b"ab!cde");
    }

    #[test]
    fn test_insert_multibyte_success() {
        let mut backing = [0u8; 128];
        let mut v = make_vec(&mut backing, b"abcde");
        v.try_insert(2, "😂".as_bytes()).unwrap();
        assert_eq!(&v[..], "ab😂cde".as_bytes());
    }

    #[test]
    fn test_insert_end() {
        let mut backing = [0u8; 128];
        let mut v = make_vec(&mut backing, b"abcde");
        v.try_insert(5, b"!").unwrap();
        assert_eq!(&v[..], b"abcde!");
    }

    #[test]
    fn test_insert_start() {
        let mut backing = [0u8; 128];
        let mut v = make_vec(&mut backing, b"abcde");
        v.try_insert(0, b"!").unwrap();
        assert_eq!(&v[..], b"!abcde");
    }

    #[test]
    fn test_insert_no_space_for_slice_errors() {
        let mut backing = [0u8; 6];
        let mut v = make_vec(&mut backing, b"abcde");
        assert!(v.try_insert(2, b"!!").is_err());
    }
}
