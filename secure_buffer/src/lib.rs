use std::sync::{Mutex, OnceLock};

use region::Protection;
use zeroize::Zeroize;

const BUFFER_CAPACITY: usize = 256;
static POOL: OnceLock<Mutex<SecureBufferPool>> = OnceLock::new();

struct SecureBufferPool {
    allocation: region::Allocation,
    _lock_guard: region::LockGuard,

    free_slots: Vec<bool>,
}

unsafe impl Send for SecureBufferPool {}

impl SecureBufferPool {
    fn new() -> Self {
        let size = region::page::size();

        let mut allocation = region::alloc(region::page::size(), Protection::READ_WRITE)
            .expect("Couldn't allocate a page for SecureBufferPool");
        let lock_guard = region::lock::<u8>(allocation.as_ptr(), allocation.len())
            .expect("Couldn't lock secure memory page");
        mark_memory_dontdump(&mut allocation);

        let num_slots = size / BUFFER_CAPACITY;
        let free_slots = vec![true; num_slots];

        Self {
            allocation,
            _lock_guard: lock_guard,
            free_slots,
        }
    }

    fn allocate<const SIZE: usize>(&mut self) -> Option<SecureBuffer<'_, SIZE>> {
        const {
            assert!(
                SIZE <= BUFFER_CAPACITY,
                "Requested buffer size must be less than or equal to BUFFER_CAPACITY"
            );
        }

        if let Some(index) = self.free_slots.iter().position(|&slot| slot) {
            self.free_slots[index] = false;

            let offset = index * BUFFER_CAPACITY;
            // SAFETY: The offset is calculated based on the known structure of the allocation and the buffer size,
            // ensuring it points to a valid memory region within the allocated page.
            let buffer_ptr = unsafe { self.allocation.as_mut_ptr::<u8>().add(offset) };
            // SAFETY: The buffer pointer is valid and properly aligned for the type [u8; SIZE], and the memory is zeroed out.
            let buffer = unsafe { std::slice::from_raw_parts_mut(buffer_ptr, SIZE) };

            Some(SecureBuffer {
                buffer,
                pool_idx: index,
            })
        } else {
            None
        }
    }

    fn deallocate(&mut self, pool_idx: usize) {
        if pool_idx < self.free_slots.len() {
            self.free_slots[pool_idx] = true;
        }
    }
}

pub struct SecureBuffer<'pool, const SIZE: usize> {
    buffer: &'pool mut [u8],
    pool_idx: usize,
}

pub fn get_secure_buffer<const SIZE: usize>() -> SecureBuffer<'static, SIZE> {
    let pool = POOL.get_or_init(|| Mutex::new(SecureBufferPool::new()));
    let mut pool_guard = pool.lock().expect("Failed to lock SecureBufferPool");
    let buf = pool_guard
        .allocate::<SIZE>()
        .expect("No free buffer slots available in SecureBufferPool");
    // SAFETY: The pool allocation lives in a `static`, so the buffer memory is valid for 'static.
    // The pool's free_slots bookkeeping ensures no two live SecureBuffers alias the same slot.
    // The lifetime extension is sound here because we have the context the pool impl lacks.
    unsafe { std::mem::transmute::<SecureBuffer<'_, SIZE>, SecureBuffer<'static, SIZE>>(buf) }
}

impl<'a, const SIZE: usize> SecureBuffer<'a, SIZE> {
    pub fn as_slice(&self) -> &[u8] {
        &self.buffer
    }

    pub fn as_mut_slice(&mut self) -> &mut [u8] {
        self.buffer
    }

    pub fn len(&self) -> usize {
        self.buffer.len()
    }
}

impl<'a, const SIZE: usize> Drop for SecureBuffer<'a, SIZE> {
    fn drop(&mut self) {
        self.buffer.zeroize();
        // SAFETY: The buffer's pool_idx is valid and corresponds to the correct slot in the pool.
        // The pool's free_slots bookkeeping ensures no two live SecureBuffers alias the same slot.
        let pool = POOL.get().expect("SecureBufferPool not initialized");
        let mut pool_guard = pool.lock().expect("Failed to lock SecureBufferPool");
        pool_guard.deallocate(self.pool_idx);
    }
}

fn mark_memory_dontdump(allocation: &mut region::Allocation) {
    #[cfg(target_os = "linux")]
    {
        // SAFETY: The allocation instance is known to be valid and page-aligned.
        unsafe {
            libc::madvise(
                allocation.as_mut_ptr(),
                allocation.len(),
                libc::MADV_DONTDUMP,
            );
        }
    }
}