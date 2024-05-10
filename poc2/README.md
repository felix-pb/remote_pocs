# poc2 (SMB)

This report presents a vulnerability in [SMBClient-286.40.9][1]. This
vulnerability could allow a malicious SMB server to achieve remote kernel memory
corruption on macOS with minimum user interaction. This report also presents a
simple proof-of-concept to trigger the vulnerability. The PoC has been tested
successfully on both M1 and Intel MacBook devices running macOS Monterey 12.3.

## Description of the vulnerability

The vulnerability is located in the function [`smb3_msg_decrypt`][2] which is
responsible to decrypt incoming packets from the SMB server if they have a
transform header:
```c
// Location: kernel/netsmb/smb_crypt.c
// The snippet shows the entire function with irrelevant parts omitted.
int smb3_msg_decrypt(struct smb_session *sessionp, mbuf_t *mb)
{
    SMB3_AES_TF_HEADER      *tf_hdr;
    mbuf_t                  mb_hdr, mb_tmp, mbuf_payload;
    uint16_t                i16;
    uint64_t                i64;
    uint32_t                msglen = 0;
    int                     error;
    unsigned char           *msgp;
    unsigned char           sig[SMB3_AES_TF_SIG_LEN];
    const struct ccmode_ccm *ccmode = ccaes_ccm_decrypt_mode();
    const struct ccmode_gcm *gcmode = ccaes_gcm_decrypt_mode();
    size_t                  nbytes;
    uint32_t                mbuf_cnt = 0;
    char                    *cptr = NULL;

    // ...

    mbuf_payload = NULL;
    mb_hdr = NULL;
    error = 0;

    // ...

    if (!sessionp->session_smb3_decrypt_key_len) { // (9)
        error = EAUTH;
        goto out;
    }

    mb_hdr = *mb;

    if (mbuf_split(mb_hdr, SMB3_AES_TF_HDR_LEN, MBUF_WAITOK, &mbuf_payload)) { // (1)
        mb_hdr = NULL;
        error = EBADRPC;
        goto out;
    }

    if (mbuf_pullup(&mb_hdr, SMB3_AES_TF_HDR_LEN)) {
        error = EBADRPC;
        goto out;
    }

    msgp = mbuf_data(mb_hdr);
    tf_hdr = (SMB3_AES_TF_HEADER *)msgp;

    if (bcmp(msgp, SMB3_AES_TF_PROTO_STR, SMB3_AES_TF_PROTO_LEN) != 0) { // (2)
        error = EBADRPC;
        goto out;
    }

    i16 = letohs(tf_hdr->encrypt_algorithm);
    if (i16 != SMB2_ENCRYPTION_AES128_CCM) { // (3)
        error = EAUTH;
        goto out;
    }

    i64 = letohq(tf_hdr->sess_id);
    if (i64 != sessionp->session_session_id) { // (4)
        error = EAUTH;
        goto out;
    }

    msglen = letohl(tf_hdr->orig_msg_size); // (5)

    // ...

    if (msglen > (64 * 1024)) { // (6)
        if ((sessionp->decrypt_bufferp != NULL) && (msglen > sessionp->decrypt_buf_len)) {
            SMB_FREE(sessionp->decrypt_bufferp, M_TEMP);
            sessionp->decrypt_bufferp = NULL;
            sessionp->decrypt_buf_len = 0;
        }

        if (sessionp->decrypt_bufferp == NULL) {
            SMB_MALLOC(sessionp->decrypt_bufferp, char *, msglen, M_TEMP, M_WAITOK); // (7)
            if (sessionp->decrypt_bufferp == NULL) {
                error = EAUTH;
                goto out;
            }
           sessionp->decrypt_buf_len = msglen;
        }

        cptr = sessionp->decrypt_bufferp;
        for (mb_tmp = mbuf_payload; mb_tmp != NULL; mb_tmp = mbuf_next(mb_tmp)) { // (8)
            nbytes = mbuf_len(mb_tmp);
            if (nbytes) {
                bcopy(mbuf_data(mb_tmp), cptr, nbytes);
                cptr += nbytes;
            }
        }
        // ...
    }
    // ...
}
```

The function parameter `mb` is a pointer to the mbuf containing the incoming
SMB response and therefore is attacker-controlled. First, the function splits
the transform header (i.e. the first 52 bytes) and the rest of the response with
`mbuf_split` (1). Then, there's a few checks performed on the header: the
transform header signature `"\xFDSMB"` (2), the encryption algorithm (3), and
the session ID (4). Since the SMB server controls all these values, these checks
are passed trivially. After that, `msglen` is retrieved from the header's
`orig_msg_size` field (5). Crucially, no check is performed to see if the value
of `msglen` actually matches the length of `mbuf_payload`. Therefore, an
attacker can easily set `msglen` to (64 * 1024 + 1) in order to enter the
branch at (6), but still send a payload that is much larger than 64 KiB + 1.
This results in a buffer of size `msglen` being mallocated (7). However, the
code then blindly performs a bcopy of the entire attacker-controlled
`mbuf_payload` into this newly mallocated buffer (8). As explained with more
details in my previous report, the maximum size of this mbuf is determined by
the constant `SMB_LARGE_MAXPKTLEN` which is 0x00FFFFFF. Thus, we can overflow
the vulnerable mallocated buffer with up to 0x00FFFFFF - (64 * 1024 + 1) =
16,711,678 bytes.

However, there's one check I didn't mention which is that the session must
contain a decryption key (9). This is the only check that cannot be passed
trivially with the content of the current SMB response, and requires some
prior setup. However, it's not hard to meet this condition as the session's
decryption key can be set during the SESSION SETUP phase of the SMB2 protocol
for dialects 3.0, 3.0.2, or 3.1.1. In particular, the only function where the
session's decryption key is set is `smb3_derive_keys` (also in `smb_crypt.c`),
which is called after the SPNEGO authentication. Overall, it's pretty easy
for a malicious server to finish the SESSION SETUP such that the client has
a decryption key, and then simply send a malicious packet to remotely trigger
a kernel heap buffer overflow with attacker-controlled data.

Note that this attack can be repeated many times to generate an arbitrary number
of kernel heap overflows of arbitrary size (up to 16,711,678 bytes each). Once
the session setup is done, the SMB server can send any number of fake encrypted
messages. Each of them can be constructed to achieve its goal (e.g. corrupt
kernel heap memory with attacker-controlled data) and then simply be discarded
by the client.

## Description of the PoC

Since the SMB server needs to perform SPNEGO authentication and I didn't want to
implement that myself, I ended up using an existing open-source project to build
my PoC: [impacket][3]. In particular, this project contains a built-in SMB
server implementation. In order to make the PoC, I had to make a handful of
patches. All patches have a comment prefixed with `felix-pb` so you can search
for that if you'd like to know exactly what I changed. Nonetheless, here's a
quick summary of the changes:

1. The `smb2Negotiate` response is modified so that the preferred dialect is
3.1.1 instead of 2.002, and a negotiate context is appended as required for the
3.1.1 dialect.
2. The `smb2SessionSetup` response is modified to use a fixed session ID instead
of a random one. This is just to make it easier to pass the check (4) in the
vulnerable `smb3_msg_decrypt` function. More importantly, the `SessionFlags` is
set to 0 instead of 1, because the decryption key won't be generated by the
client otherwise and check (9) would not pass.
3. Finally, after four responses (2 NEGOTIATE + 2 SESSION SETUP), the SMB server
is patched to send a malicious packet, which is just 128 KiB of A's although the
`msglen` is only set to 64 KiB + 1.

## How to build and run the Poc?

The PoC only requires Docker, which can be installed from [here][4].

First, build the PoC as a docker image.
```
docker build -t smbclient_poc .
```

Then, run the PoC as a docker container. This starts a TCP server on port 445.
```
docker run -it --rm -p 445:445 smbclient_poc
```

Finally, from the victim's macOS device (which must be a different device),
perform the following steps:

1. In the top menu bar of Finder, click on "Go" > "Connect to Server...".
2. Enter the "Server Address" field (`smb://x.x.x.x`), then click "Connect".
3. Select "Connect As: Guest", then click "Connect".
4. At this point, you should get a kernel panic!

[1]: https://github.com/apple-oss-distributions/SMBClient/tree/SMBClient-286.40.9
[2]: https://github.com/apple-oss-distributions/SMBClient/blob/SMBClient-286.40.9/kernel/netsmb/smb_crypt.c#L1923-L2228
[3]: https://github.com/SecureAuthCorp/impacket/
[4]: https://docs.docker.com/get-docker/
