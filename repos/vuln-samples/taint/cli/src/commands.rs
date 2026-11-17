use std::io::{self, BufRead};
use std::net::TcpStream;
use std::process::Command;

use rusqlite::Connection;

/// The source every function here reads from: an argument of the command line.
pub(crate) fn argument(index: usize) -> String {
    std::env::args().nth(index).unwrap_or_default()
}

// -- T1 command injection ------------------------------------------------------------------
pub fn run_tool() -> bool {
    let tool = argument(1);
    Command::new(&tool).status().is_ok() // EXPECT command-injection
}

/// Safe: only two known programs can be run.
pub fn run_known_tool() -> bool {
    let tool = argument(1);
    match tool.as_str() {
        "ls" | "date" => Command::new(&tool).status().is_ok(),
        _ => false,
    }
}

/// The input reaches the sink through a helper: the finding is in `shell`.
pub fn run_script() -> bool {
    let script = argument(2);
    shell(&script)
}

fn shell(script: &str) -> bool {
    Command::new("sh").arg("-c").arg(script).status().is_ok() // EXPECT command-injection
}

// -- T2 SQL injection ------------------------------------------------------------------------
pub fn delete_user(db: &Connection) -> bool {
    let name = argument(1);
    let sql = format!("DELETE FROM users WHERE name = '{}'", name);
    db.execute(&sql, []).is_ok() // EXPECT sql-injection
}

/// Safe: the value is a bind parameter.
pub fn delete_user_bound(db: &Connection) -> bool {
    let name = argument(1);
    db.execute("DELETE FROM users WHERE name = ?1", [&name]).is_ok()
}

// -- T3 path traversal -----------------------------------------------------------------------
pub fn show_file() -> String {
    let mut line = String::new();
    let _ = io::stdin().lock().read_line(&mut line);
    let path = line.trim();
    std::fs::read_to_string(path).unwrap_or_default() // EXPECT path-traversal
}

/// Safe: only the file name is kept, so the path cannot leave the data directory.
pub fn show_data_file() -> String {
    let mut line = String::new();
    let _ = io::stdin().lock().read_line(&mut line);
    let Some(name) = std::path::Path::new(line.trim()).file_name() else {
        return String::new();
    };
    std::fs::read_to_string(std::path::Path::new("/var/data").join(name)).unwrap_or_default()
}

// -- T4 server-side request forgery -----------------------------------------------------------
pub fn probe() -> bool {
    let target = argument(1);
    TcpStream::connect(&target).is_ok() // EXPECT ssrf
}

/// Safe: only the port comes from input, and it is a number.
pub fn probe_local() -> bool {
    let port: u16 = argument(1).parse().unwrap_or(80);
    TcpStream::connect(("127.0.0.1", port)).is_ok()
}

// -- T5 length from input reaching unsafe memory APIs -------------------------------------------
pub fn grow() -> usize {
    let wanted: usize = argument(1).parse().unwrap_or(0);
    let mut buffer: Vec<u8> = Vec::with_capacity(64);
    unsafe { buffer.set_len(wanted) }; // EXPECT unsafe-length-from-input
    buffer.len()
}

/// Safe: the length is checked against the capacity first.
pub fn grow_checked() -> usize {
    let wanted: usize = argument(1).parse().unwrap_or(0);
    let mut buffer: Vec<u8> = Vec::with_capacity(64);
    if wanted <= buffer.capacity() {
        unsafe { buffer.set_len(wanted) };
    }
    buffer.len()
}
