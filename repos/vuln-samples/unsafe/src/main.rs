//! Class U sample: unsafe code reachable from main, documented and undocumented unsafe,
//! dangerous operations, an `unsafe impl Send`, and an FFI surface.
mod buffer;
mod ffi;

use buffer::RawBuffer;

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let mut buf = RawBuffer::with_capacity(16);
    buf.fill(args.len() as u8);
    let total = buffer::sum(&buf);
    println!("{} {}", total, ffi::strlen_of("abc"));
    println!("{}", helper::never_unsafe());
}

mod helper {
    /// Plain safe code: nothing here is reported.
    pub fn never_unsafe() -> u32 {
        1
    }
}
