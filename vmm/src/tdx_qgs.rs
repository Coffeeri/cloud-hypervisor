// Copyright © 2024 Intel Corporation
//
// SPDX-License-Identifier: Apache-2.0 AND BSD-3-Clause
//
// TDX Quote Generation Service (QGS) client.
//
// Handles asynchronous communication with the host QGS daemon to retrieve a
// TDX quote for a guest.
//
// The VMM process itself runs on the host, alongside the QGS daemon (qgsd),
// so this talks to QGS over the local Unix domain socket that qgsd listens
// on by default (see /etc/qgs.conf: vsock is only used when qgsd is
// explicitly configured with a `port`). Connecting over AF_VSOCK to
// VMADDR_CID_HOST from a process that is *already* on the host does not
// reach a real vsock listener and results in ECONNRESET.
//
// Protocol framing: 4-byte big-endian length prefix then the QGS message body.
//
// TDX shared-memory quote header layout (24 bytes):
//   offset  0..8   structure_version  (u64 LE, must be 1, set by guest)
//   offset  8..16  error_code         (u64 LE, set by VMM on completion)
//   offset 16..20  in_len             (u32 LE, set by guest, size of QGS request)
//   offset 20..24  out_len            (u32 LE, set by VMM on completion)
//
// The guest kernel driver (drivers/virt/coco/tdx-guest/tdx-guest.c) does NOT
// place a fully-formed qgs_msg request in the shared buffer: it sets
// `in_len = TDX_REPORT_LEN` and copies the *raw* TDREPORT bytes into `data`.
// It is the VMM's job to wrap that raw TDREPORT into a proper
// qgs_msg_get_quote_req_t (see Intel SGX DCAP `qgs_msg_lib.h`) before sending
// it to qgsd; sending the raw TDREPORT bytes directly makes qgsd read garbage
// as the qgs_msg_header_t and log "invalid request, close connection".

use std::io::{Read, Write};
use std::os::unix::net::UnixStream;
use std::sync::Arc;
use std::time::Duration;

use hypervisor::VmOps;
use libc::{AF_VSOCK, SOCK_STREAM, VMADDR_CID_HOST};
use log::warn;
use vm_device::interrupt::InterruptSourceGroup;

/// Default Unix domain socket path used by the Intel `qgsd` daemon when it is
/// configured for its default (non-vsock) transport.
const QGS_UNIX_SOCKET_PATH: &str = "/var/run/tdx-qgs/qgs.socket";
const QGS_MSG_FRAMING_HEADER_SIZE: usize = 4; // big-endian u32 length prefix
const QGS_IO_TIMEOUT_SECS: u64 = 30;

// Quote header error codes
pub const TDX_VP_GET_QUOTE_SUCCESS: u64 = 0;
pub const TDX_VP_GET_QUOTE_IN_FLIGHT: u64 = u64::MAX; // -1 in two's complement
pub const TDX_VP_GET_QUOTE_QGS_UNAVAILABLE: u64 = 0x8000_0000_0000_0001;
pub const TDX_VP_GET_QUOTE_ERROR: u64 = 0x8000_0000_0000_0000;

// Quote header field offsets
const HDR_STRUCTURE_VERSION_OFFSET: usize = 0;
const HDR_ERROR_CODE_OFFSET: usize = 8;
const HDR_IN_LEN_OFFSET: usize = 16;
const HDR_OUT_LEN_OFFSET: usize = 20;
const TDX_GET_QUOTE_HDR_SIZE: usize = 24;

// qgs_msg_header_t / qgs_msg_get_quote_req_t constants (Intel SGX DCAP
// qgs_msg_lib.h). All fields are host-native (little-endian on x86_64); only
// the outer 4-byte socket framing length prefix is big-endian.
const QGS_MSG_LIB_MAJOR_VER: u16 = 1;
const QGS_MSG_LIB_MINOR_VER: u16 = 1;
const QGS_MSG_TYPE_GET_QUOTE_REQ: u32 = 0;
const QGS_MSG_HEADER_SIZE: usize = 16; // major(2)+minor(2)+type(4)+size(4)+error_code(4)

/// Wrap a raw TDREPORT (as handed to us by the guest via the shared GPA
/// buffer) into a qgs_msg_get_quote_req_t body, ready to be sent to qgsd
/// (after adding the 4-byte big-endian length prefix).
fn build_get_quote_req(report: &[u8]) -> Vec<u8> {
    let report_size = report.len() as u32;
    let id_list_size: u32 = 0;
    let total_size = (QGS_MSG_HEADER_SIZE + 4 + 4 + report.len()) as u32;

    let mut req = Vec::with_capacity(total_size as usize);
    req.extend_from_slice(&QGS_MSG_LIB_MAJOR_VER.to_le_bytes());
    req.extend_from_slice(&QGS_MSG_LIB_MINOR_VER.to_le_bytes());
    req.extend_from_slice(&QGS_MSG_TYPE_GET_QUOTE_REQ.to_le_bytes());
    req.extend_from_slice(&total_size.to_le_bytes());
    req.extend_from_slice(&0u32.to_le_bytes()); // error_code, unused in requests
    req.extend_from_slice(&report_size.to_le_bytes());
    req.extend_from_slice(&id_list_size.to_le_bytes());
    req.extend_from_slice(report);
    req
}

/// Connect to the QGS daemon's Unix domain socket, with read/write timeouts
/// applied so a stuck or unresponsive QGS cannot hang the worker thread
/// forever.
fn connect_to_qgs() -> std::io::Result<UnixStream> {
    let stream = UnixStream::connect(QGS_UNIX_SOCKET_PATH)?;
    let timeout = Duration::from_secs(QGS_IO_TIMEOUT_SECS);
    stream.set_read_timeout(Some(timeout))?;
    stream.set_write_timeout(Some(timeout))?;
    Ok(stream)
}

/// Read exactly `n` bytes from a Read source.
fn read_exact_bytes(stream: &mut impl Read, n: usize) -> std::io::Result<Vec<u8>> {
    let mut buf = vec![0u8; n];
    let mut pos = 0;
    while pos < n {
        let got = stream.read(&mut buf[pos..])?;
        if got == 0 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::UnexpectedEof,
                "QGS connection closed",
            ));
        }
        pos += got;
    }
    Ok(buf)
}

/// Send a length-prefixed message to QGS and receive the response.
///
/// Returns the raw QGS response body bytes on success.
fn qgs_send_receive(msg: &[u8]) -> std::io::Result<Vec<u8>> {
    let mut stream = connect_to_qgs()?;

    // Write 4-byte big-endian length prefix + message
    let len_prefix = (msg.len() as u32).to_be_bytes();
    stream.write_all(&len_prefix)?;
    stream.write_all(msg)?;

    // Read 4-byte big-endian length prefix
    let prefix = read_exact_bytes(&mut stream, QGS_MSG_FRAMING_HEADER_SIZE)?;
    let resp_len = u32::from_be_bytes([prefix[0], prefix[1], prefix[2], prefix[3]]) as usize;

    if resp_len == 0 || resp_len > 256 * 1024 {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("QGS response size {resp_len} out of range"),
        ));
    }

    read_exact_bytes(&mut stream, resp_len)
}

/// Parse the QGS GET_QUOTE_RESP body and extract the raw quote bytes.
///
/// QGS response layout:
///   qgs_msg_header_t (16 bytes):
///     major_version(u16) minor_version(u16) type(u32) size(u32) error_code(u32)
///   selected_id_size (u32)
///   quote_size (u32)
///   [id bytes][quote bytes]
fn extract_quote_from_qgs_response(resp: &[u8]) -> Option<&[u8]> {
    const QGS_HDR_SIZE: usize = 16;
    const GET_QUOTE_RESP: u32 = 1;

    if resp.len() < QGS_HDR_SIZE + 8 {
        return None;
    }

    let resp_type = u32::from_le_bytes(resp[4..8].try_into().ok()?);
    let error_code = u32::from_le_bytes(resp[12..16].try_into().ok()?);

    if resp_type != GET_QUOTE_RESP || error_code != 0 {
        warn!("QGS GET_QUOTE_RESP error: type={resp_type} code={error_code:#x}");
        return None;
    }

    let selected_id_size =
        u32::from_le_bytes(resp[QGS_HDR_SIZE..QGS_HDR_SIZE + 4].try_into().ok()?) as usize;
    let quote_size =
        u32::from_le_bytes(resp[QGS_HDR_SIZE + 4..QGS_HDR_SIZE + 8].try_into().ok()?) as usize;
    let payload_start = QGS_HDR_SIZE + 8 + selected_id_size;
    let payload_end = payload_start + quote_size;

    if payload_end > resp.len() {
        return None;
    }

    Some(&resp[payload_start..payload_end])
}

/// Async quote worker: connects to QGS, fetches quote, writes result back to
/// guest shared memory, then fires the completion MSI.
pub fn spawn_get_quote_worker(
    vm_ops: Arc<dyn VmOps>,
    event_notify_group: Option<Arc<dyn InterruptSourceGroup>>,
    gpa: u64,
    buf_size: u64,
    in_message: Vec<u8>,
) {
    // std::thread::Builder::new()
    //     .name("tdx-quote".to_string())
    //     .spawn(move || {
    //         let (error_code, quote_bytes) = match qgs_send_receive(&in_message) {
    //             Err(e) => {
    //                 warn!("TDX GetQuote: QGS connection failed: {e}");
    //                 (TDX_VP_GET_QUOTE_QGS_UNAVAILABLE, None)
    //             }
    //             Ok(resp) => match extract_quote_from_qgs_response(&resp) {
    //                 Some(quote) => (TDX_VP_GET_QUOTE_SUCCESS, Some(quote.to_vec())),
    //                 None => {
    //                     warn!("TDX GetQuote: failed to parse QGS response");
    //                     (TDX_VP_GET_QUOTE_ERROR, None)
    //                 }
    //             },
    //         };

    //         // Write result back into guest GPA buffer
    //         let out_len = write_quote_result(vm_ops.as_ref(), gpa, buf_size, error_code, quote_bytes.as_deref());

    //         // Log outcome
    //         if error_code == TDX_VP_GET_QUOTE_SUCCESS {
    //             log::info!("TDX GetQuote: success, quote_size={out_len}");
    //         }

    //         // Fire completion MSI if registered
    //         if let Some(group) = event_notify_group {
    //             if let Err(e) = group.trigger(0) {
    //                 warn!("TDX GetQuote: failed to trigger completion interrupt: {e}");
    //             }
    //         }
    //     })
    //     .unwrap_or_else(|e| panic!("TDX GetQuote: failed to spawn worker thread: {e}"));
    let qgs_req = build_get_quote_req(&in_message);
    let (error_code, quote_bytes) = match qgs_send_receive(&qgs_req) {
        Err(e) => {
            warn!("TDX GetQuote: QGS connection failed: {e}");
            (TDX_VP_GET_QUOTE_QGS_UNAVAILABLE, None)
        }
        Ok(resp) => match extract_quote_from_qgs_response(&resp) {
            Some(quote) => (TDX_VP_GET_QUOTE_SUCCESS, Some(quote.to_vec())),
            None => {
                warn!("TDX GetQuote: failed to parse QGS response");
                (TDX_VP_GET_QUOTE_ERROR, None)
            }
        },
    };

    // Write result back into guest GPA buffer
    let out_len = write_quote_result(
        vm_ops.as_ref(),
        gpa,
        buf_size,
        error_code,
        quote_bytes.as_deref(),
    );

    // Log outcome
    if error_code == TDX_VP_GET_QUOTE_SUCCESS {
        log::info!("TDX GetQuote: success, quote_size={out_len}");
    }

    // Fire completion MSI if registered
    if let Some(group) = event_notify_group {
        if let Err(e) = group.trigger(0) {
            warn!("TDX GetQuote: failed to trigger completion interrupt: {e}");
        }
    }
}

/// Write the quote header + optional quote data back to the guest GPA buffer.
/// Returns the number of bytes written as out_len.
fn write_quote_result(
    vm_ops: &dyn VmOps,
    gpa: u64,
    buf_size: u64,
    error_code: u64,
    quote: Option<&[u8]>,
) -> u32 {
    let out_len = quote.map(|q| q.len() as u32).unwrap_or(0);

    // Update only the header fields VMM owns (error_code and out_len).
    // structure_version and in_len are left as the guest set them.
    let mut hdr = [0u8; TDX_GET_QUOTE_HDR_SIZE];
    // Read current header first (to preserve structure_version and in_len)
    if vm_ops.guest_mem_read(gpa, &mut hdr).is_err() {
        return 0;
    }
    hdr[HDR_ERROR_CODE_OFFSET..HDR_ERROR_CODE_OFFSET + 8]
        .copy_from_slice(&error_code.to_le_bytes());
    hdr[HDR_OUT_LEN_OFFSET..HDR_OUT_LEN_OFFSET + 4].copy_from_slice(&out_len.to_le_bytes());

    if vm_ops.guest_mem_write(gpa, &hdr).is_err() {
        return 0;
    }

    // Write the quote body after the header if we have one
    if let Some(q) = quote {
        let payload_gpa = gpa + TDX_GET_QUOTE_HDR_SIZE as u64;
        let available = buf_size.saturating_sub(TDX_GET_QUOTE_HDR_SIZE as u64) as usize;
        let write_len = q.len().min(available);
        if write_len < q.len() {
            warn!(
                "TDX GetQuote: quote ({} bytes) truncated to fit buffer ({available} bytes)",
                q.len()
            );
        }
        if vm_ops
            .guest_mem_write(payload_gpa, &q[..write_len])
            .is_err()
        {
            return 0;
        }
        write_len as u32
    } else {
        0
    }
}

/// Read the in-message from guest buffer, mark the buffer as IN_FLIGHT,
/// and return the in-message bytes.
///
/// Returns `None` if the buffer is too small, the header is invalid, or
/// the read fails.
pub fn take_in_message(vm_ops: &dyn VmOps, gpa: u64, buf_size: u64) -> Option<Vec<u8>> {
    if buf_size < TDX_GET_QUOTE_HDR_SIZE as u64 {
        return None;
    }

    let mut hdr = [0u8; TDX_GET_QUOTE_HDR_SIZE];
    vm_ops.guest_mem_read(gpa, &mut hdr).ok()?;

    let structure_version = u64::from_le_bytes(
        hdr[HDR_STRUCTURE_VERSION_OFFSET..HDR_STRUCTURE_VERSION_OFFSET + 8]
            .try_into()
            .ok()?,
    );
    if structure_version != 1 {
        warn!("TDX GetQuote: unexpected structure_version={structure_version}");
        return None;
    }

    let in_len = u32::from_le_bytes(
        hdr[HDR_IN_LEN_OFFSET..HDR_IN_LEN_OFFSET + 4]
            .try_into()
            .ok()?,
    ) as u64;
    if in_len == 0 || in_len > buf_size - TDX_GET_QUOTE_HDR_SIZE as u64 {
        warn!("TDX GetQuote: invalid in_len={in_len}, buf_size={buf_size}");
        return None;
    }

    // Read the in-message (QGS request from guest)
    let payload_gpa = gpa + TDX_GET_QUOTE_HDR_SIZE as u64;
    let mut in_msg = vec![0u8; in_len as usize];
    vm_ops.guest_mem_read(payload_gpa, &mut in_msg).ok()?;

    // Mark buffer as in-flight
    hdr[HDR_ERROR_CODE_OFFSET..HDR_ERROR_CODE_OFFSET + 8]
        .copy_from_slice(&TDX_VP_GET_QUOTE_IN_FLIGHT.to_le_bytes());
    vm_ops.guest_mem_write(gpa, &hdr).ok()?;

    Some(in_msg)
}
