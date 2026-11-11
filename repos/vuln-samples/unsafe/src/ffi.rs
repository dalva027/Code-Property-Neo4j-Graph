//! The FFI boundary: a foreign function we call and an export C code can call.
use std::ffi::CString;
use std::os::raw::c_char;

extern "C" {
    fn strlen(s: *const c_char) -> usize;
}

/// Length of a C string, via libc.
pub fn strlen_of(s: &str) -> usize {
    let c = CString::new(s).unwrap_or_default();
    // SAFETY: c is a valid NUL-terminated string that outlives the call.
    unsafe { strlen(c.as_ptr()) }
}

#[no_mangle]
pub extern "C" fn sample_checksum(data: *const u8, len: usize) -> u32 {
    if data.is_null() {
        return 0;
    }
    // SAFETY: the caller guarantees `data` points to `len` readable bytes.
    let bytes = unsafe { std::slice::from_raw_parts(data, len) };
    bytes.iter().map(|b| *b as u32).sum()
}
