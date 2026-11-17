//! A toy HTTP responder that writes its headers by hand, the way small servers and proxies do.
use std::io::{Read, Write};
use std::net::TcpStream;

/// The source: whatever the client sent.
fn request_line(stream: &mut TcpStream) -> String {
    let mut buffer = [0u8; 512];
    let read = stream.read(&mut buffer).unwrap_or(0);
    String::from_utf8_lossy(&buffer[..read]).trim().to_string()
}

// -- T6 open redirect --------------------------------------------------------------------------
pub fn redirect(stream: &mut TcpStream) -> bool {
    let target = request_line(stream);
    write!(stream, "HTTP/1.1 302 Found\r\nLocation: {}\r\n\r\n", target).is_ok() // EXPECT open-redirect
}

/// Safe: only site-relative targets are followed.
pub fn redirect_local(stream: &mut TcpStream) -> bool {
    let target = request_line(stream);
    if !target.starts_with('/') {
        return false;
    }
    write!(stream, "HTTP/1.1 302 Found\r\nLocation: {}\r\n\r\n", target).is_ok()
}

// -- T7 header injection -------------------------------------------------------------------------
pub fn echo_id(stream: &mut TcpStream) -> bool {
    let id = request_line(stream);
    write!(stream, "HTTP/1.1 200 OK\r\nX-Request-Id: {}\r\n\r\n", id).is_ok() // EXPECT header-injection
}

/// Safe: a value with CR or LF is rejected.
pub fn echo_id_checked(stream: &mut TcpStream) -> bool {
    let id = request_line(stream);
    if id.contains('\r') || id.contains('\n') {
        return false;
    }
    write!(stream, "HTTP/1.1 200 OK\r\nX-Request-Id: {}\r\n\r\n", id).is_ok()
}
