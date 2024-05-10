# poc1 (SMB)

This report presents a vulnerability in [SMBClient-231.120.2][1]. This
vulnerability could allow a malicious SMB server to achieve remote kernel memory
corruption on macOS with minimum user interaction. This report also presents a
simple proof-of-concept to trigger the vulnerability. The PoC has been tested
successfully on both M1 and Intel MacBook devices running macOS Monterey 12.2.

## Description of the vulnerability

The vulnerability is located in the function [`smb_iod_recvall`][2] which is
responsible to process incoming packets from the SMB server:

```c
// Location: kernel/netsmb/smb_iod.c
// The snippet shows L1806-L1867 with comments omitted.
if ((SMBV_SMB3_OR_LATER(sessionp))
    (nt_status == STATUS_SUCCESS)
    (flags & SMB2_FLAGS_SIGNED)) {
    if (iod->iod_sess_setup_reply != NULL) {
        SMB_FREE(iod->iod_sess_setup_reply, M_SMBTEMP);
        iod->iod_sess_setup_reply = NULL;
    }

    mbuf_chain_len = mbuf_get_chain_len(m);

    if (mbuf_chain_len > (64 * 1024)) { // (1)
        SMBERROR("Session Setup reply too big <%zu>??? \n", mbuf_chain_len);
        mbuf_chain_len = 64 * 1024;
    }

    SMB_MALLOC(iod->iod_sess_setup_reply, uint8_t *,
                mbuf_chain_len, M_SMBTEMP, M_WAITOK); // (2)
    if (iod->iod_sess_setup_reply == NULL) {
        SMBERROR("Out of memory for saving final Session Setup reply. id: %d \n",
                    iod->iod_id);
    }
    else {
        iod->iod_sess_setup_reply_len = mbuf_chain_len;
        tmp_m = m;
        offset = 0;

        while (tmp_m) {
            len = mbuf_len(tmp_m);
            memcpy(iod->iod_sess_setup_reply + offset,
                    (uint8_t *) mbuf_data(tmp_m), len); // (3)

            offset += len;
            tmp_m = mbuf_next(tmp_m);
        }
    }
}
```

The variable `m` is a pointer to the mbuf containing the response sent by the
SMB server. The code incorrectly sets `mbuf_chain_len` to a max of 64 KiB (1),
which results in a 64 KiB buffer being mallocated (2). However, the code then
blindly performs a memcpy of the entire attacker-controlled mbuf into this newly
mallocated buffer (3). Note that this branch is easy to trigger because both
`nt_status` and `flags` are attacker-controlled values retrieved from the mbuf
a bit earlier (L1638-L1639) and the SMBClient negotiates SMB v3.0.2 by default.

The true maximum size of the mbuf is determined by the function
[`nbssn_recvhdr`][3] which is responsible for reading the 4-byte NetBIOS header:

```c
// Location: kernel/netsmb/smb_trantcp.c
// The snippet shows L469-L482 with comments omitted.
len = ntohl(len);
*rpcodep = (len >> 24) & 0xFF;
if (nbp->nbp_flags & NBF_NETBIOS) {
    if ((len >> 16) & 0xFE) {
        SMBERROR("bad nb header received 0x%x (MBZ flag set)\n", len);
        return (EPIPE);
    }
    len &= SMB_MAXPKTLEN;
}
else {
    len &= SMB_LARGE_MAXPKTLEN;
}
```

The variable `len` is masked with `SMB_LARGE_MAXPKTLEN` (0x00FFFFFF), which is
then used to read that amount of bytes from the server into the mbuf pointed to
by `m` in the previous snippet. Thus, we can overflow the vulnerable mallocated
buffer with up to 0x00FFFFFF - (64 * 1024) = 16,711,679 bytes.

## Description of the PoC

The vulnerability is easy to trigger because it happens during the SESSION_SETUP
phase of the SMB protocol, which is right after the NEGOTIATE phase. To create
the PoC, it suffices to replicate the behavior of the real `smbd` server
installed on macOS up to the SESSION_SETUP response and simply modify the values
of `nt_status` and `flags` in the SMB response header to trigger the branch as
mentioned earlier. A large malicious payload can then be appended to that
response to cause the kernel heap buffer overflow.

## How to build and run the Poc?

The PoC is written in Rust, which can be installed from [here][4].

Once you've installed the Rust toolchain, you can build the PoC with:

```sh
cargo build --release
```

This will build the PoC as an executable in `target/release/smbclient_poc`.
Then, you can run the malicious SMB server with the `macos` argument:

```sh
sudo ./target/release/smbclient_poc macos
```

This will start the TCP server on port 445 (which is why we need `sudo`). Then,
from the victim's macOS device (which must be a different device), perform the
following steps:

1. In the top menu bar of Finder, click on "Go" > "Connect to Server...".
2. In the Server Address, enter the address (`smb://x.x.x.x`), then click "Connect".
3. In the popup that appears, click "Connect".
4. If another popup appears, select "Connect As: Guest", then click "Continue".
5. At this point, you should get a kernel panic!

Note that the vulnerability is triggered before any authentication happens.

[1]: https://github.com/apple-oss-distributions/SMBClient/tree/SMBClient-231.120.2
[2]: https://github.com/apple-oss-distributions/SMBClient/blob/SMBClient-231.120.2/kernel/netsmb/smb_iod.c#L1806-L1867
[3]: https://github.com/apple-oss-distributions/SMBClient/blob/SMBClient-231.120.2/kernel/netsmb/smb_trantcp.c#L469-L482
[4]: https://www.rust-lang.org/tools/install
