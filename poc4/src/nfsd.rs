use crate::{build_response, Request, Response, SERVER_IP_ADDRESS};
use std::sync::atomic::{AtomicUsize, Ordering};

static NFS_REQUEST_COUNT: AtomicUsize = AtomicUsize::new(0);

pub fn handler(request: Request) -> Option<Response> {
    let xid = request.get(..4)?;
    let count = NFS_REQUEST_COUNT.fetch_add(1, Ordering::SeqCst);

    match count {
        0 => Some(build_response(xid, &[])),
        1 => Some(build_response(xid, &nfs4_setclientid_payload_1())),
        2 => Some(build_response(xid, &nfs4_setclientid_payload_2())),
        3 => Some(build_response(xid, &nfs4_mount_payload_1())),
        4 => Some(build_response(xid, &nfs4_get_fs_locations_payload_1())),
        5 => Some(build_response(xid, &[])),
        _ => None,
    }
}

fn nfs4_setclientid_payload_1() -> Vec<u8> {
    let mut payload = Vec::new();
    // Status: NFS4_OK (0)
    payload.extend_from_slice(&0_u32.to_be_bytes());
    // nfsm_chain_skip_tag(error, &nmrep);
    payload.extend_from_slice(&0_u32.to_be_bytes());
    // nfsm_chain_get_32(error, &nmrep, numops);
    payload.extend_from_slice(&1_u32.to_be_bytes());
    // nfsm_chain_op_check(error, &nmrep, NFS_OP_SETCLIENTID);
    payload.extend_from_slice(&35_u32.to_be_bytes());
    payload.extend_from_slice(&0_u32.to_be_bytes());
    // nfsm_chain_get_64(error, &nmrep, nmp->nm_clientid);
    payload.extend_from_slice(&0xABCDEF_u64.to_be_bytes());
    // nfsm_chain_get_64(error, &nmrep, verifier);
    payload.extend_from_slice(&0_u64.to_be_bytes());
    payload
}

fn nfs4_setclientid_payload_2() -> Vec<u8> {
    let mut payload = Vec::new();
    // Status: NFS4_OK (0)
    payload.extend_from_slice(&0_u32.to_be_bytes());
    // nfsm_chain_skip_tag(error, &nmrep);
    payload.extend_from_slice(&0_u32.to_be_bytes());
    // nfsm_chain_get_32(error, &nmrep, numops);
    payload.extend_from_slice(&1_u32.to_be_bytes());
    // nfsm_chain_op_check(error, &nmrep, NFS_OP_SETCLIENTID_CONFIRM);
    payload.extend_from_slice(&36_u32.to_be_bytes());
    payload.extend_from_slice(&0_u32.to_be_bytes());
    payload
}

fn nfs4_mount_payload_1() -> Vec<u8> {
    let mut payload = Vec::new();
    // Status: NFS4_OK (0)
    payload.extend_from_slice(&0_u32.to_be_bytes());
    // nfsm_chain_skip_tag(error, &nmrep);
    payload.extend_from_slice(&0_u32.to_be_bytes());
    // nfsm_chain_get_32(error, &nmrep, numops);
    payload.extend_from_slice(&4_u32.to_be_bytes());
    // nfsm_chain_op_check(error, &nmrep, dirfh.fh_len ? NFS_OP_PUTFH : NFS_OP_PUTROOTFH);
    payload.extend_from_slice(&24_u32.to_be_bytes());
    payload.extend_from_slice(&0_u32.to_be_bytes());
    // nfsm_chain_op_check(error, &nmrep, isdotdot ? NFS_OP_LOOKUPP : NFS_OP_LOOKUP);
    payload.extend_from_slice(&15_u32.to_be_bytes());
    payload.extend_from_slice(&0_u32.to_be_bytes());
    // nfsm_chain_op_check(error, &nmrep, NFS_OP_GETFH);
    payload.extend_from_slice(&10_u32.to_be_bytes());
    payload.extend_from_slice(&0_u32.to_be_bytes());
    // nfsm_chain_get_32(error, &nmrep, fh.fh_len);
    // nfsm_chain_get_opaque(error, &nmrep, fh.fh_len, fh.fh_data);
    payload.extend_from_slice(&32_u32.to_be_bytes());
    payload.extend_from_slice(&[b'A'; 32]);
    // nfsm_chain_op_check(error, &nmrep, NFS_OP_GETATTR);
    // NOTE: The status is 1 instead of 0 in order to set the error,
    // in order to avoid the call to `nfs4_parsefattr` inside the if-branch.
    payload.extend_from_slice(&9_u32.to_be_bytes());
    payload.extend_from_slice(&1_u32.to_be_bytes());
    payload
}

fn nfs4_get_fs_locations_payload_1() -> Vec<u8> {
    let mut payload = Vec::new();
    // Status: NFS4_OK (0)
    payload.extend_from_slice(&0_u32.to_be_bytes());
    // nfsm_chain_skip_tag(error, &nmrep);
    payload.extend_from_slice(&0_u32.to_be_bytes());
    // nfsm_chain_get_32(error, &nmrep, numops);
    payload.extend_from_slice(&3_u32.to_be_bytes());
    // nfsm_chain_op_check(error, &nmrep, NFS_OP_PUTFH);
    payload.extend_from_slice(&22_u32.to_be_bytes());
    payload.extend_from_slice(&0_u32.to_be_bytes());
    // nfsm_chain_op_check(error, &nmrep, NFS_OP_LOOKUP);
    payload.extend_from_slice(&15_u32.to_be_bytes());
    payload.extend_from_slice(&0_u32.to_be_bytes());
    // nfsm_chain_op_check(error, &nmrep, NFS_OP_GETATTR);
    payload.extend_from_slice(&9_u32.to_be_bytes());
    payload.extend_from_slice(&0_u32.to_be_bytes());
    // nfsm_chain_get_bitmap(error, nmc, bitmap, len);
    payload.extend_from_slice(&2_u32.to_be_bytes());
    payload.extend_from_slice(&0x01000000_u32.to_be_bytes()); // NFS_FATTR_FS_LOCATIONS bit
    payload.extend_from_slice(&0x00000000_u32.to_be_bytes());
    // nfsm_chain_get_32(error, nmc, attrbytes);
    let len = SERVER_IP_ADDRESS.len() as u32;
    let pad_len = if len % 4 == 0 { 0 } else { 4 - (len % 4) };
    payload.extend_from_slice(&(68_u32 + len + pad_len).to_be_bytes());

    // ====== if (NFS_BITMAP_ISSET(bitmap, NFS_FATTR_FS_LOCATIONS)) {...} ======

    // nfsm_chain_get_32(error, nmc, fsp->np_compcount);
    // for (comp = 0; comp < fsp->np_compcount; comp++) {
    //     nfsm_chain_get_32(error, nmc, val);
    //     ...
    //     nfsm_chain_get_opaque(error, nmc, val, fsp->np_components[comp]);
    // }
    payload.extend_from_slice(&3_u32.to_be_bytes()); // fsp->np_compcount = 3
    payload.extend_from_slice(&4_u32.to_be_bytes()); // val (comp = 0)
    payload.extend_from_slice(&[b'd'; 4]); // fsp->np_components[0] = "dddd"
    payload.extend_from_slice(&4_u32.to_be_bytes()); // val (comp = 1)
    payload.extend_from_slice(&[b'e'; 4]); // fsp->np_components[1] = "eeee"
    payload.extend_from_slice(&4_u32.to_be_bytes()); // val (comp = 2)
    payload.extend_from_slice(&[b'f'; 4]); // fsp->np_components[2] = "ffff"

    // nfsm_chain_get_32(error, nmc, nfslsp->nl_numlocs);
    // for (loc = 0; loc < nfslsp->nl_numlocs; loc++) {
    //    nfsm_chain_get_32(error, nmc, fsl->nl_servcount);
    //    ...
    //    for (serv = 0; serv < fsl->nl_servcount; serv++) {
    //        nfsm_chain_get_32(error, nmc, val);
    //        ...
    //        nfsm_chain_get_opaque(error, nmc, val, fss->ns_name);
    //    }
    //    ...
    //    nfsm_chain_get_32(error, nmc, fsp->np_compcount);
    //    ...
    //    for (comp = 0; comp < fsp->np_compcount; comp++) {
    //        nfsm_chain_get_32(error, nmc, val);
    //        ...
    //        nfsm_chain_get_opaque(error, nmc, val, fsp->np_components[comp]);
    //    }
    // }
    payload.extend_from_slice(&1_u32.to_be_bytes()); // nfslsp->nl_numlocs = 1
    payload.extend_from_slice(&1_u32.to_be_bytes()); // fsl->nl_servcount = 1
    payload.extend_from_slice(&len.to_be_bytes()); // val = len
    payload.extend_from_slice(SERVER_IP_ADDRESS.as_bytes()); // fss->ns_name = SERVER_IP_ADDRESS
    payload.extend_from_slice(&vec![0; pad_len as usize]); // 4-byte alignment padding
    payload.extend_from_slice(&3_u32.to_be_bytes()); // fsp->np_compcount = 3
    payload.extend_from_slice(&4_u32.to_be_bytes()); // val (comp = 0)
    payload.extend_from_slice(&[b'd'; 4]); // fsp->np_components[0] = "dddd"
    payload.extend_from_slice(&4_u32.to_be_bytes()); // val (comp = 1)
    payload.extend_from_slice(&[b'e'; 4]); // fsp->np_components[1] = "eeee"
    payload.extend_from_slice(&4_u32.to_be_bytes()); // val (comp = 2)
    payload.extend_from_slice(&[b'f'; 4]); // fsp->np_components[2] = "ffff"

    // =========================================================================
    payload
}
