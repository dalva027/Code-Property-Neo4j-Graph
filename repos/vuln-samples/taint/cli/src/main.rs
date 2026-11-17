//! A command-line tool and a toy HTTP responder: for each rule that follows data flow, one function
//! that lets input reach a dangerous call and one that does the same thing safely. Input comes
//! from the command line, stdin and a TCP stream. See ../expected.json.
mod commands;
mod net;
mod numbers;
mod secrets;

use std::net::TcpListener;

fn main() {
    let db = rusqlite::Connection::open_in_memory().expect("in-memory database");
    let results = [
        commands::run_tool(),
        commands::run_known_tool(),
        commands::run_script(),
        commands::delete_user(&db),
        commands::delete_user_bound(&db),
        commands::probe(),
        commands::probe_local(),
    ];
    println!("{results:?} {} {}", commands::show_file(), commands::show_data_file());
    println!("{} {}", commands::grow(), commands::grow_checked());
    println!("{} {}", numbers::table(), numbers::table_capped());
    println!("{} {}", numbers::frame_size(), numbers::frame_size_checked());
    println!("{:?} {:?}", secrets::store_password("hunter2"), secrets::legacy_password_hash("hunter2"));
    println!("{:?} {}", secrets::checksum(b"data"), secrets::session_token());
    println!("{:?}", secrets::seal(&[0u8; 32], b"message"));
    println!("{:?}", secrets::seal_fresh(&[0u8; 32], b"message", &[1u8; 12]));

    if let Ok(listener) = TcpListener::bind("127.0.0.1:8080") {
        for stream in listener.incoming().flatten() {
            let mut stream = stream;
            let _ = net::redirect(&mut stream)
                || net::redirect_local(&mut stream)
                || net::echo_id(&mut stream)
                || net::echo_id_checked(&mut stream);
        }
    }
}
