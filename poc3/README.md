# poc3 (SMB)

This report presents a vulnerability in [SMBClient-287.101.2][1]. This
vulnerability could allow a malicious SMB server to achieve remote kernel memory
corruption on macOS with minimum user interaction. This report also presents a
simple proof-of-concept to trigger the vulnerability. The PoC has been tested
successfully on both M1 and Intel MacBook devices running macOS Monterey 12.3.1.

## Description of the vulnerability

The vulnerability is located in the function [`smb2_smb_parse_ioctl`][2] which
is responsible to parse the response of an SMB2 IOCTL request.

```c
// Location: kernel/netsmb/smb_smb_2.c
// This snippet shows the entire function with irrelevant parts omitted.
int smb2_smb_parse_ioctl(struct mdchain *mdp, struct smb2_ioctl_rq *ioctlp)
{
    int error;
    uint16_t length;
    uint16_t reserved_uint16;
    uint32_t ret_ctlcode;
    SMB2FID ret_fid;
    uint32_t ret_input_offset;
    uint32_t ret_output_offset;
    uint32_t ret_flags;
    uint32_t reserved_uint32;
    struct smb2_secure_neg_info *neg_reply = NULL;

    // ...

    error = md_get_uint32le(mdp, &ret_ctlcode); // (1)
    if (error) {
        goto bad;
    }

    // ...

    error = md_get_uint32le(mdp, &ioctlp->ret_output_len); // (2)
    if (error) {
        goto bad;
    }

    // ...

    switch (ret_ctlcode) { // (3)
        // ...
        case FSCTL_QUERY_NETWORK_INTERFACE_INFO:
            error = md_get_mem(mdp, (caddr_t) ioctlp->rcv_output_buffer, ioctlp->ret_output_len, MB_MSYSTEM); // (4)
            if (error) {
                SMBERROR("FSCTL_QUERY_NETWORK_INTERFACE_INFO error pulling data\n");
                goto bad;
            }
            break;
        default:
            // ...
    }

bad:
    return error;
}
```

The function parameter `mdp` is a pointer to the mbuf chain containing the full
SMB response from the server and therefore is attacker-controlled. First, the
function copies some values from the response into local stack variables or the
`struct smb2_ioctl_rq` pointed to by the function parameter `ioctlp`. In
particular, `ret_ctlcode` (1) and `ioctlp->ret_output_len` (2) are set with
attacker-controlled values. The former allows the attacker to enter the switch
case of their choice (3), and the latter allows the attacker to trigger the
buffer overflow (4). The function `md_get_mem` bcopies `ioctlp->ret_output_len`
bytes from the mbuf chain into the buffer pointed to by
`ioctlp->rcv_output_buffer`. Note that `md_get_mem` has no way to know the size
of the destination buffer and therefore doesn't perform bounds-checking, i.e. it
is the responsibility of the caller.

So what's the size of the `ioctlp->rcv_output_buffer` destination buffer?
Alarmingly, this pointer is not touched at all when parsing the SMB2 IOCTL
response, which means that this buffer was allocated before we knew how many
bytes we are going to copy into it. There are many code paths that lead to the
vulnerable function `smb2_smb_parse_ioctl`, but only two of them can take
advantage of this bug. For all the other code paths, `ioctlp->rcv_output_buffer`
will be NULL, which won't cause memory corruption with `md_get_mem`.

## Description of the first variant

The first bad call site is in the function
[`smb2fs_smb_query_network_interface_info`][3]:

```c
// Location: kernel/smbfs/smbfs_smb_2.c
// This snippet shows the entire function with irrelevant parts omitted.
int smb2fs_smb_query_network_interface_info(struct smb_share *share, vfs_context_t context)
{
    struct smb_session *sessionp = SS_TO_SESSION(share);
    int error = 0;
    struct smb2_ioctl_rq *ioctlp = NULL;
    struct smb2_network_info_reply reply;

    // ...

    SMB_MALLOC(reply.buff, void *, QUERY_NETWORK_INTERFACE_MAX_REPLY, M_SMBTEMP, M_WAITOK | M_ZERO); // (1)

    // ...

    ioctlp->share = share;
    ioctlp->ctl_code = FSCTL_QUERY_NETWORK_INTERFACE_INFO;
    ioctlp->fid = 0;
    ioctlp->mc_flags = 0;
    ioctlp->snd_output_len = 0;
    ioctlp->rcv_input_len = 0;
    ioctlp->snd_input_len = 0;
    ioctlp->rcv_output_len = reply.buff_size;
    ioctlp->rcv_output_buffer = (uint8_t *) reply.buff; // (2)

    error = smb2_smb_ioctl(share, NULL, ioctlp, NULL, context); // (3)

    // ...
}
```

The function heap-allocates a buffer of size equal to 64 KiB (i.e.
`QUERY_NETWORK_INTERFACE_MAX_REPLY`) with SMB_MALLOC (1). Later, it sets
`ioctlp->rcv_output_buffer` with the pointer returned by SMB_MALLOC (2).
Finally, it calls `smb2_smb_ioctl` (3), which will build and send the request,
wait for the reply and parse it with the vulnerable function
`smb2_smb_parse_ioctl`. In short, this variant allows a remote attacker to
trigger a *heap* buffer overflow in the kernel, because the heap allocation is
fixed at 64 KiB but the copy amount is determined by an attacker-controlled
32-bit unsigned integer. However, fixing this bug by simply limiting the copy
amount to 64 KiB would be **wrong** as demonstrated by the second variant.

Note: the PoC described below triggers this variant.

## Description of the second variant

The second bad call site is in the function
[`smb2fs_smb_validate_neg_info`][4]:

```c
// Location: kernel/smbfs/smbfs_smb_2.c
// This snippet shows the entire function with irrelevant parts omitted.
int smb2fs_smb_validate_neg_info(struct smb_share *share, vfs_context_t context)
{
    struct smb_session *sessionp = SS_TO_SESSION(share);
    int error = 0;
    struct smb2_ioctl_rq *ioctlp = NULL;
    struct smb2_secure_neg_info req;
    struct smb2_secure_neg_info reply; // (1)
    struct smb_sopt *sp = NULL;
    int i, try_count = 0;
    struct smbiod *iod = NULL;

    // ...

    ioctlp->share = share;
    ioctlp->ctl_code = FSCTL_VALIDATE_NEGOTIATE_INFO;
    ioctlp->fid = 0;
    ioctlp->mc_flags = 0;
    ioctlp->snd_output_len = 0;
    ioctlp->rcv_input_len = 0;
    ioctlp->snd_input_len = 24;
    ioctlp->snd_input_len += 2 * req.dialect_count;
    ioctlp->snd_input_buffer = (uint8_t *) &req;
    ioctlp->rcv_output_len = sizeof(reply);
    ioctlp->rcv_output_buffer = (uint8_t *) &reply; // (2)

    error = smb2_smb_ioctl(share, iod, ioctlp, NULL, context); // (3)

    // ...
}
```

The function stack-allocates a `struct smb2_secure_neg_info` named `reply` (1).
Later, it sets `ioctlp->rcv_output_buffer` with the address of this struct (2).
Finally, it calls `smb2_smb_ioctl` (3). Unlike the first variant, this variant
allows a remote attacker to trigger a *stack* buffer overflow in the kernel. You
might have noticed that the `ioctlp->ctl_code` is set to
`FSCTL_VALIDATE_NEGOTIATE_INFO` instead of `FSCTL_QUERY_NETWORK_INTERFACE_INFO`.
However, there is no check to make sure that the reply's `ctl_code` matches the
request's `ctl_code`. Therefore, a malicious SMB server can enter the `ctl_code`
switch-branch of their choice, no matter the type of the IOCTL request sent by
the client.

Note: the PoC described below triggers the first variant, not this variant.

## Description of the PoC

For the PoC, I used the open-source project [impacket][5] to avoid
reimplementing parts of the SMB protocol. In particular, it contains a built-in
SMB server implementation. In order to make the PoC work, I had to make a
handful of patches. All patches have a comment prefixed with `felix-pb` so you
can search for that if you'd like to know exactly what I changed. Nonetheless,
here's a quick summary of the changes:

1. The `smb2Negotiate` response is modified so that the preferred dialect is
3.1.1 instead of 2.002, and a negotiate context is appended as required for the
3.1.1 dialect. In addition, the capacilities are modified from `0x0` to `0x8` to
enable multi-channel on the client.
2. The `smb2Ioctl` response is modified so that if the CtlCode is equal to
`FSCTL_QUERY_NETWORK_INTERFACE_INFO`, we send a large 1 MiB payload of
`'A'`/`0x41` bytes in order to trigger the buffer overflow.

## How to build and run the PoC?

The PoC only requires Docker, which can be installed from [here][6].

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
4. A share named "MYSHARE" should become visible, select it and click "OK".
5. At this point, you should get a kernel panic!

## Bonus: Memory Leaks

While investigating this vulnerability, I also came across two memory leaks.
Here's the first one:

```c
// Location: kernel/netsmb/smb_smb_2.c
// This snippet shows the entire function.
static int smb2_smb_parse_get_resume_key(struct mdchain *mdp, struct smb2_ioctl_rq *ioctlp)
{
    int error = 0;
    char *resume_key = NULL;

    SMB_MALLOC(resume_key, char *, (size_t) ioctlp->ret_output_len, M_TEMP, M_WAITOK | M_ZERO); // (1)
    if (resume_key == NULL) {
        error = ENOMEM;
        goto bad;
    }

    error = md_get_mem(mdp, (void *) resume_key, (size_t) ioctlp->ret_output_len, MB_MSYSTEM); // (2)
    if (!error) {
        ioctlp->rcv_output_buffer = (uint8_t *) resume_key; // (3)
        ioctlp->rcv_output_len = (uint32_t) ioctlp->ret_output_len;
    }

bad:
    return (error);
}
```

This function allocates a buffer of size equal to `ioctlp->ret_output_len` (1),
which is the same attacker-controlled value as explained previously. Then, it
attempts to copy that amount of bytes from the mbuf chain into this newly
mallocated buffer (2). If `md_get_mem` succeeds, `ioctlp->rcv_output_buffer` is
set with the pointer returned by SMB_MALLOC (3). This field will be used to free
the buffer later. However, if `md_get_mem` fails (e.g. because the mbuf chain is
too small to fill the buffer, which the attacker can control trivially), then
the newly mallocated buffer should be freed immediately since the pointer to it
(i.e. `resume_key`) will be lost forever after the function returns. Note that
although `ioctlp->ret_output_len` is a 32-bit unsigned integer, the maximum size
of an SMB response is 0x00FFFFFF (i.e. `SMB_LARGE_MAXPKTLEN`). Therefore, this
bug allows a remote attacker to leak roughly 16 MiB of fully attacker-controlled
data at a time.

Finally, the function `smb2_smb_parse_copychunk_response` is redundant with the
function above, i.e. it is completely identical except that the local variable
`resume_key` is named `copychunk_resp` instead. Thus, it also suffers from a
memory leak.

[1]: https://github.com/apple-oss-distributions/SMBClient/tree/SMBClient-287.101.2
[2]: https://github.com/apple-oss-distributions/SMBClient/blob/SMBClient-287.101.2/kernel/netsmb/smb_smb_2.c#L5833-L6083
[3]: https://github.com/apple-oss-distributions/SMBClient/blob/SMBClient-287.101.2/kernel/smbfs/smbfs_smb_2.c#L9202-L9286
[4]: https://github.com/apple-oss-distributions/SMBClient/blob/SMBClient-287.101.2/kernel/smbfs/smbfs_smb_2.c#L8959-L9200
[5]: https://github.com/SecureAuthCorp/impacket/
[6]: https://docs.docker.com/get-docker/
