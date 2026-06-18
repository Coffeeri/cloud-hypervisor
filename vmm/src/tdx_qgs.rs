// Copyright © 2024 Intel Corporation
//
// SPDX-License-Identifier: Apache-2.0 AND BSD-3-Clause
//
// TDX Quote Generation Service (QGS) client.
//
// Handles asynchronous communication with the host QGS daemon via vsock
// (CID=VMADDR_CID_HOST, port=4050) to retrieve a TDX quote for a guest.
//
// Protocol framing: 4-byte big-endian length prefix then the QGS message body.
//
// TDX shared-memory quote header layout (24 bytes):
//   offset  0..8   structure_version  (u64 LE, must be 1, set by guest)
//   offset  8..16  error_code         (u64 LE, set by VMM on completion)
//   offset 16..20  in_len             (u32 LE, set by guest, size of QGS request)
//   offset 20..24  out_len            (u32 LE, set by VMM on completion)

use std::io::{Read, Write};
use std::sync::Arc;

use hypervisor::VmOps;
use libc::{AF_VSOCK, SOCK_STREAM, VMADDR_CID_HOST};
use log::warn;
use vm_device::interrupt::InterruptSourceGroup;

const QGS_VSOCK_PORT: u32 = 4050;
const QGS_MSG_FRAMING_HEADER_SIZE: usize = 4; // big-endian u32 length prefix
const QGS_CONNECT_TIMEOUT_SECS: u64 = 5;
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

/// A vsock stream connected to the host QGS daemon.
struct VsockStream {
    fd: i32,
}

impl VsockStream {
    fn connect(cid: u32, port: u32) -> std::io::Result<Self> {
        // SAFETY: socket() syscall with valid parameters
        let fd = unsafe { libc::socket(AF_VSOCK, SOCK_STREAM, 0) };
        if fd < 0 {
            return Err(std::io::Error::last_os_error());
        }

        // Set send/receive timeouts
        let tv = libc::timeval {
            tv_sec: QGS_IO_TIMEOUT_SECS as libc::time_t,
            tv_usec: 0,
        };
        // SAFETY: setsockopt with valid fd and parameters
        unsafe {
            libc::setsockopt(
                fd,
                libc::SOL_SOCKET,
                libc::SO_RCVTIMEO,
                &tv as *const libc::timeval as *const libc::c_void,
                std::mem::size_of::<libc::timeval>() as libc::socklen_t,
            );
            libc::setsockopt(
                fd,
                libc::SOL_SOCKET,
                libc::SO_SNDTIMEO,
                &tv as *const libc::timeval as *const libc::c_void,
                std::mem::size_of::<libc::timeval>() as libc::socklen_t,
            );
        }

        #[repr(C)]
        struct SockaddrVm {
            svm_family: libc::sa_family_t,
            svm_reserved1: u16,
            svm_port: u32,
            svm_cid: u32,
            svm_zero: [u8; 4],
        }

        let addr = SockaddrVm {
            svm_family: AF_VSOCK as libc::sa_family_t,
            svm_reserved1: 0,
            svm_port: port,
            svm_cid: cid,
            svm_zero: [0; 4],
        };

        // SAFETY: connect() with valid fd and populated sockaddr
        let ret = unsafe {
            libc::connect(
                fd,
                &addr as *const SockaddrVm as *const libc::sockaddr,
                std::mem::size_of::<SockaddrVm>() as libc::socklen_t,
            )
        };

        if ret != 0 {
            let err = std::io::Error::last_os_error();
            // SAFETY: close valid fd
            unsafe { libc::close(fd) };
            return Err(err);
        }

        Ok(VsockStream { fd })
    }
}

impl Read for VsockStream {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        // SAFETY: recv with valid fd and buffer
        let n = unsafe { libc::recv(self.fd, buf.as_mut_ptr() as *mut libc::c_void, buf.len(), 0) };
        if n < 0 {
            Err(std::io::Error::last_os_error())
        } else {
            Ok(n as usize)
        }
    }
}

impl Write for VsockStream {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        // SAFETY: send with valid fd and buffer
        let n = unsafe { libc::send(self.fd, buf.as_ptr() as *const libc::c_void, buf.len(), 0) };
        if n < 0 {
            Err(std::io::Error::last_os_error())
        } else {
            Ok(n as usize)
        }
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

impl Drop for VsockStream {
    fn drop(&mut self) {
        // SAFETY: close valid fd
        unsafe { libc::close(self.fd) };
    }
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
    let mut stream = VsockStream::connect(VMADDR_CID_HOST as u32, QGS_VSOCK_PORT)?;

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
    std::thread::Builder::new()
        .name("tdx-quote".to_string())
        .spawn(move || {
            let (error_code, quote_bytes) = match qgs_send_receive(&in_message) {
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
        })
        .unwrap_or_else(|e| panic!("TDX GetQuote: failed to spawn worker thread: {e}"));
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
