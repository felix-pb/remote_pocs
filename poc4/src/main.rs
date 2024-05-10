mod nfsd;
mod portmap;

use std::io::{Read, Write};
use std::net::{Ipv4Addr, SocketAddr, TcpListener};
use std::thread::JoinHandle;

const SERVER_IP_ADDRESS: &str = "10.0.0.176";

fn main() {
    // Start the 2 services.
    let nfsd_service = start_service("nfsd", 2049, nfsd::handler);
    let portmap_service = start_service("portmap", 111, portmap::handler);

    // Wait for the 2 services to exit.
    nfsd_service.join().unwrap();
    portmap_service.join().unwrap();
}

type Request<'a> = &'a [u8];
type Response = Vec<u8>;
type Handler = fn(Request) -> Option<Response>;

/// Start a service on a dedicated thread listening for incoming TCP connections on a specific port.
fn start_service(name: &'static str, port: u16, handler: Handler) -> JoinHandle<()> {
    std::thread::spawn(move || {
        let ip = SERVER_IP_ADDRESS.parse::<Ipv4Addr>().unwrap();
        let addr = SocketAddr::from((ip, port));
        let listener = TcpListener::bind(addr).unwrap();
        println!("[{name}]: {listener:?}");
        while let Ok((mut stream, _)) = listener.accept() {
            // Handle each accepted TCP connection in a dedicated thread.
            std::thread::spawn(move || {
                println!("[{name}]: {stream:?} --> connected");
                let mut marker_buf = [0; 4];
                let mut record_buf = vec![0; 1024 * 1024];
                loop {
                    // Read the four-byte marker.
                    if let Err(e) = stream.read_exact(&mut marker_buf) {
                        break println!("[{name}]: {stream:?} --> error: {e}");
                    }

                    // Assert that the "last fragment" bit is set, then clear it.
                    assert!(marker_buf[0] == 0x80);
                    marker_buf[0] = 0x00;

                    // Assert that the record size doesn't exceed the buffer size.
                    let record_size = u32::from_be_bytes(marker_buf) as usize;
                    assert!(record_size <= record_buf.len());

                    // Read the entire record.
                    if let Err(e) = stream.read_exact(&mut record_buf[..record_size]) {
                        break println!("[{name}]: {stream:?} --> error: {e}");
                    }
                    let request = &record_buf[..record_size];
                    println!("[{name}]: {stream:?} --> received request ({record_size} bytes)");

                    // Call the request handler and send back the response.
                    match handler(request) {
                        Some(response) => stream.write_all(&response).unwrap(),
                        None => println!("[{name}]: {stream:?} --> ignored request"),
                    };
                }
                println!("[{name}]: {stream:?} --> disconnected");
            });
        }
    })
}

// Build an NFS response with an RPC header.
fn build_response(xid: &[u8], payload: &[u8]) -> Response {
    let mut response = Response::new();
    // Fragment header, Last fragment
    let size = (24u32 + payload.len() as u32) | 0x8000_0000;
    response.extend_from_slice(&size.to_be_bytes());
    // XID: same as request
    response.extend_from_slice(xid);
    // Message Type: Reply (1)
    response.extend_from_slice(&1_u32.to_be_bytes());
    // Reply State: accepted (0)
    response.extend_from_slice(&0_u32.to_be_bytes());
    // Verifier: Flavor: AUTH_NULL (0)
    response.extend_from_slice(&0_u32.to_be_bytes());
    // Verifier: Length: 0
    response.extend_from_slice(&0_u32.to_be_bytes());
    // Accept State: RPC executed successfully (0)
    response.extend_from_slice(&0_u32.to_be_bytes());
    // Payload
    response.extend_from_slice(payload);
    response
}
