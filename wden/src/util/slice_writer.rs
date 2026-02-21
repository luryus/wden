
pub struct SliceWriter<'a> {
    buf: &'a mut [u8],
    pos: usize
}

impl<'a> SliceWriter<'a> {
    pub fn new(buf: &'a mut [u8]) -> Self {
        Self {
            buf, pos: 0
        }
    }

    pub fn written_len(&self) -> usize {
        self.pos
    }
}

impl<'a> std::io::Write for SliceWriter<'a> {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        let remaining = self.buf.len().saturating_sub(self.pos);
        let len = remaining.min(buf.len());
        let copy_buf = &buf[..len];
        self.buf[self.pos..self.pos+len].copy_from_slice(copy_buf);

        self.pos += len;
        assert!(self.pos <= self.buf.len());
        
        Ok(len)
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}
