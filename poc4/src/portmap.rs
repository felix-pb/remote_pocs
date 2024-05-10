use crate::{build_response, Request, Response};

const PROCEDURE_NULL: &[u8] = &0_u32.to_be_bytes();
const PROCEDURE_GETPORT: &[u8] = &3_u32.to_be_bytes();

const PROGRAM_NFS: &[u8] = &100003_u32.to_be_bytes();
const PROGRAM_MOUNT: &[u8] = &100005_u32.to_be_bytes();
const PROGRAM_STAT: &[u8] = &100024_u32.to_be_bytes();

pub fn handler(request: Request) -> Option<Response> {
    let xid = request.get(..4)?;
    let procedure = request.get(20..24)?;

    match procedure {
        PROCEDURE_NULL => Some(build_response(xid, &[])),
        PROCEDURE_GETPORT => {
            let program = request.get(64..68)?;
            match program {
                PROGRAM_NFS => Some(build_response(xid, &2049_u32.to_be_bytes())),
                PROGRAM_MOUNT => Some(build_response(xid, &855_u32.to_be_bytes())),
                PROGRAM_STAT => Some(build_response(xid, &928_u32.to_be_bytes())),
                _ => None,
            }
        }
        _ => None,
    }
}
