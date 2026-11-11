//! A hand-rolled buffer: every method touches raw memory.
use std::ptr;

pub struct RawBuffer {
    ptr: *mut u8,
    len: usize,
    cap: usize,
}

unsafe impl Send for RawBuffer {}

impl RawBuffer {
    /// Allocates `cap` bytes and leaks the Vec that owns them.
    pub fn with_capacity(cap: usize) -> Self {
        let mut v: Vec<u8> = Vec::with_capacity(cap);
        let ptr = v.as_mut_ptr();
        std::mem::forget(v);
        RawBuffer { ptr, len: 0, cap }
    }

    pub fn fill(&mut self, value: u8) {
        // SAFETY: ptr is valid for cap bytes (see with_capacity) and we write exactly cap.
        unsafe {
            ptr::write_bytes(self.ptr, value, self.cap);
        }
        self.len = self.cap;
    }

    pub fn as_slice(&self) -> &[u8] {
        unsafe { std::slice::from_raw_parts(self.ptr, self.len) }
    }

    /// Reinterprets the first four bytes as a u32.
    pub unsafe fn head_u32(&self) -> u32 {
        let bytes: [u8; 4] = ptr::read(self.ptr as *const [u8; 4]);
        std::mem::transmute(bytes)
    }
}

pub fn sum(buf: &RawBuffer) -> u32 {
    let mut total = 0u32;
    for b in buf.as_slice() {
        total += *b as u32;
    }
    // SAFETY: fill() always writes cap >= 4 bytes before sum() is called.
    total + unsafe { buf.head_u32() }
}
