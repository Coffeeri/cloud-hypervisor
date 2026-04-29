// Copyright © 2026 Cyberus Technology GmbH
//
// SPDX-License-Identifier: Apache-2.0

//! Blockdev-mirroring for virtio-blk devices.
//!
//! Mirrors guest writes to a destination disk while a background
//! worker copies existing data from source to destination. Once
//! both sides are in sync the device manager can complete the mirror,
//! switching the device to serve I/O from the destination.

use std::collections::{BTreeMap, VecDeque};
use std::os::fd::{AsRawFd, RawFd};
use std::sync::atomic::AtomicU64;
use std::sync::{Arc, Condvar, Mutex};
use std::thread::JoinHandle;
use std::{io, thread};

use libc::{iovec, off_t};
use log::warn;
use vmm_sys_util::epoll;
use vmm_sys_util::eventfd::EventFd;

use crate::BatchRequest;
use crate::async_io::{AsyncIo, AsyncIoError, AsyncIoResult};
use crate::disk_file::AsyncFullDiskFile;
use crate::error::BlockResult;

/// Block size for the copy worker, in which it copies data from
/// source to destination and holds the range lock.
pub const MIRROR_BLOCK_SIZE: usize = 512 * 1024; // 512 KiB

/// Serializes overlapping byte ranges between the copy worker and the
/// per-queue mirror writes.
///
/// Each party calls [`Self::lock_range`] before submitting I/O and
/// holds the returned [`RangeGuard`] until completion. A conflicting
/// request blocks on a `Condvar` until the held guard is dropped.
/// Lookups are O(log n) on the number of held ranges.
struct RangeLockManager {
    /// Held ranges as `start -> end_exclusive`. The mutex makes the
    /// overlap check and insert in [`Self::lock_range`] atomic with
    /// respect to releases in [`RangeGuard::drop`].
    ranges: Mutex<BTreeMap<u64, u64>>,
    /// Notified on guard drop. Waiters re-check their range.
    cv: Condvar,
}

impl RangeLockManager {
    pub fn new() -> Arc<Self> {
        Arc::new(Self {
            ranges: Mutex::new(BTreeMap::new()),
            cv: Condvar::new(),
        })
    }

    /// Returns true if `[start, end)` overlaps any range in `ranges`. Where `end` is exclusive.
    fn overlaps_any(ranges: &BTreeMap<u64, u64>, start: u64, end: u64) -> bool {
        ranges
            .range(..end)
            .next_back()
            .is_some_and(|(_, &e)| e > start)
    }

    /// Acquires an exclusive lock on `[offset, offset + length)`.
    /// Blocks while any held range overlaps.
    fn lock_range(self: &Arc<Self>, offset: u64, length: u64) -> io::Result<RangeGuard> {
        if length == 0 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "Range length is zero",
            ));
        }

        let end = offset
            .checked_add(length)
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "Range overflow"))?;
        let mut ranges = self.ranges.lock().unwrap();

        while RangeLockManager::overlaps_any(&ranges, offset, end) {
            // wait until any range is unlocked
            ranges = self.cv.wait(ranges).unwrap();
        }
        ranges.insert(offset, end);

        Ok(RangeGuard {
            mgr: Arc::clone(self),
            start: offset,
        })
    }

    /// Acquires a [`RangeGuard`] covering the contiguous bytes from
    /// `offset` through the end of `iovecs`.
    fn lock_iovecs(self: &Arc<Self>, offset: off_t, iovecs: &[iovec]) -> io::Result<RangeGuard> {
        let total_len = iovecs
            .iter()
            .try_fold(0u64, |acc, v| acc.checked_add(v.iov_len as u64))
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "iovec length overflow"))?;

        self.lock_range(offset as u64, total_len)
    }
}

/// RAII handle for a range held in a [`RangeLockManager`]. Drop
/// releases the range and wakes all waiters.
struct RangeGuard {
    mgr: Arc<RangeLockManager>,
    start: u64,
}
impl Drop for RangeGuard {
    fn drop(&mut self) {
        let mut ranges = self.mgr.ranges.lock().unwrap();
        ranges.remove(&self.start);
        self.mgr.cv.notify_all();
    }
}

/// Phase of a mirror.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MirrorPhase {
    /// Background copy is in progress.
    Running,
    /// All blocks copied. Source and destination are in sync.
    Ready,
    /// Switch-over to the destination is in progress.
    Completing,
    /// All virtqueues switched to the destination.
    Completed,
    /// Mirror cancellation is in progress.
    Cancelling,
    /// The mirror has failed.
    Failed(String),
}

/// State shared by the copy worker and the per-queue mirroring
/// `AsyncIo` handles.
///
/// Held in an `Arc` so all threads see the same phase and progress
/// counters.
pub struct MirrorState {
    /// Current phase of the migration.
    phase: Mutex<MirrorPhase>,
    range_locks: Arc<RangeLockManager>,
    copied_bytes: AtomicU64,
    total_bytes: u64,
}

impl MirrorState {
    pub fn new(logical_disk_size: u64) -> Arc<Self> {
        Arc::new(Self {
            phase: Mutex::new(MirrorPhase::Running),
            range_locks: RangeLockManager::new(),
            copied_bytes: AtomicU64::new(0),
            total_bytes: logical_disk_size,
        })
    }

    /// Returns a snapshot of the current phase.
    pub fn phase(&self) -> MirrorPhase {
        self.phase.lock().unwrap().clone()
    }

    /// Attempts a phase transition. Only the documented transitions are
    /// applied. Any other attempt is ignored and logged.
    ///
    /// Allowed transitions:
    /// ```text
    /// Running    -> Ready | Cancelling | Failed(_)
    /// Ready      -> Completing | Cancelling | Failed(_)
    /// Completing -> Completed
    /// Failed(_)  -> Cancelling
    /// ```
    /// Plus idempotent self-transitions. `Completed` and `Cancelling` are
    /// terminal: the mirror handle is dropped out of them, after which
    /// `Block::mirror_status` reports no active mirror.
    pub fn transition_to_phase(&self, target: MirrorPhase) {
        use MirrorPhase::*;
        let mut current = self.phase.lock().unwrap();

        // Ignore idempotent transitions to the current state
        if std::mem::discriminant(&*current) == std::mem::discriminant(&target) {
            return;
        }

        let transition_allowed = matches!(
            (&*current, &target),
            (Running, Ready)
                | (Running, Cancelling)
                | (Running, Failed(_))
                | (Ready, Completing)
                | (Ready, Cancelling)
                | (Ready, Failed(_))
                | (Completing, Completed)
                | (Failed(_), Cancelling)
        );

        if !transition_allowed {
            warn!(
                "Invalid migration phase transition attempted: {:?} -> {:?}",
                *current, target
            );
            return;
        }

        *current = target;
    }
}

/// Per-queue `AsyncIo` handle for a mirror.
pub struct MirroringAsyncIo {
    source: Box<dyn AsyncIo>,
    destination: Box<dyn AsyncIo>,
    state: Arc<MirrorState>,
    /// Completions of inflight requests to be popped by `next_completed_request`.
    inflight_completions: VecDeque<(u64, i32)>,
    /// Reusable waiters parked on the source and destination notifier eventfds
    /// while a mirrored write awaits its completions. Built once so each write
    /// does not pay the epoll setup cost.
    source_waiter: EpollWaiter,
    dest_waiter: EpollWaiter,
}
impl MirroringAsyncIo {
    /// Fail virtqueue worker and go into passthrough.
    /// While this keeps the VM and source block-dev state valid, the operator
    /// needs to cancel to cleanup resources.
    fn fail(&mut self, reason: String) {
        self.state.transition_to_phase(MirrorPhase::Failed(reason));
    }

    /// Helper that submits an `AsyncIo` request to both source and destination.
    ///
    /// Source error bubbles to the guest. Destination error fails and cancels
    /// the migration but is hidden from the guest, since `source` is the disk
    /// the guest sees.
    fn mirror_request<S, D>(
        &mut self,
        request_label: &str,
        submit_source: S,
        submit_destination: D,
    ) -> AsyncIoResult<()>
    where
        S: FnOnce(&mut Box<dyn AsyncIo>) -> AsyncIoResult<()>,
        D: FnOnce(&mut Box<dyn AsyncIo>) -> AsyncIoResult<()>,
    {
        submit_source(&mut self.source)?;
        if let Err(e) = submit_destination(&mut self.destination) {
            self.fail(format!("destination {request_label} submit failed: {e:?}"));
        }
        Ok(())
    }

    /// Block until `user_data`'s source and destination completion arrive, then
    /// queue the single guest-visible `(user_data, src_result)`. Other
    /// completions seen while waiting (e.g. an async read finishing) are stashed
    /// for later delivery.
    fn wait_for_completions(&mut self, user_data: u64) -> io::Result<()> {
        let src_result = Self::await_completion(
            &mut self.source,
            &self.source_waiter,
            &mut self.inflight_completions,
            user_data,
        )?;

        let dest_result = Self::await_completion(
            &mut self.destination,
            &self.dest_waiter,
            &mut self.inflight_completions,
            user_data,
        )?;
        if dest_result < 0 {
            self.fail(format!(
                "destination completion failed: user_data={user_data}"
            ));
        }

        self.inflight_completions.push_back((user_data, src_result));
        let _ = self.source.notifier().write(1); // re-arm; the waits drained the eventfd
        Ok(())
    }

    /// Drain `io` until `user_data`'s own completion appears (returning its
    /// result); stash anything else into `stash`.
    fn await_completion(
        io: &mut Box<dyn AsyncIo>,
        waiter: &EpollWaiter,
        stash: &mut VecDeque<(u64, i32)>,
        user_data: u64,
    ) -> io::Result<i32> {
        loop {
            while let Some((id, res)) = io.next_completed_request() {
                if id == user_data {
                    return Ok(res);
                }
                stash.push_back((id, res));
            }
            waiter.wait()?;
            let _ = io.notifier().read()?;
        }
    }
}
impl AsyncIo for MirroringAsyncIo {
    fn notifier(&self) -> &EventFd {
        self.source.notifier()
    }

    fn read_vectored(
        &mut self,
        offset: off_t,
        iovecs: &[iovec],
        user_data: u64,
    ) -> AsyncIoResult<()> {
        self.source.read_vectored(offset, iovecs, user_data)
    }

    fn write_vectored(
        &mut self,
        offset: off_t,
        iovecs: &[iovec],
        user_data: u64,
    ) -> AsyncIoResult<()> {
        let _guard = self
            .state
            .range_locks
            .lock_iovecs(offset, iovecs)
            .map_err(AsyncIoError::WriteVectored)?;

        self.mirror_request(
            "write_vectored",
            |src| src.write_vectored(offset, iovecs, user_data),
            |dst| dst.write_vectored(offset, iovecs, user_data),
        )?;

        self.wait_for_completions(user_data)
            .map_err(AsyncIoError::WriteVectored)?;
        Ok(())
    }

    fn fsync(&mut self, user_data: Option<u64>) -> AsyncIoResult<()> {
        self.mirror_request(
            "fsync",
            |src| src.fsync(user_data),
            |dst| dst.fsync(user_data),
        )?;

        // Only a tracked fsync (Some user_data) owes the guest a completion; a
        // barrier fsync (None) wants no notification, so we must not wait.
        if let Some(user_data) = user_data {
            self.wait_for_completions(user_data)
                .map_err(AsyncIoError::Fsync)?;
        }
        Ok(())
    }

    fn punch_hole(&mut self, offset: u64, length: u64, user_data: u64) -> AsyncIoResult<()> {
        let _guard = self
            .state
            .range_locks
            .lock_range(offset, length)
            .map_err(AsyncIoError::PunchHole)?;
        self.mirror_request(
            "punch_hole",
            |src| src.punch_hole(offset, length, user_data),
            |dst| dst.punch_hole(offset, length, user_data),
        )?;

        self.wait_for_completions(user_data)
            .map_err(AsyncIoError::PunchHole)?;
        Ok(())
    }

    fn write_zeroes(&mut self, offset: u64, length: u64, user_data: u64) -> AsyncIoResult<()> {
        let _guard = self
            .state
            .range_locks
            .lock_range(offset, length)
            .map_err(AsyncIoError::WriteZeroes)?;
        self.mirror_request(
            "write_zeroes",
            |src| src.write_zeroes(offset, length, user_data),
            |dst| dst.write_zeroes(offset, length, user_data),
        )?;

        self.wait_for_completions(user_data)
            .map_err(AsyncIoError::WriteZeroes)?;
        Ok(())
    }

    fn next_completed_request(&mut self) -> Option<(u64, i32)> {
        // Mirrored writes are awaited synchronously; only async source reads
        // surface here.
        while let Some((id, res)) = self.source.next_completed_request() {
            self.inflight_completions.push_back((id, res));
        }
        self.inflight_completions.pop_front()
    }

    fn batch_requests_enabled(&self) -> bool {
        false
    }

    fn submit_batch_requests(&mut self, _batch_request: &[BatchRequest]) -> AsyncIoResult<()> {
        unimplemented!("Batch requests are not supported in MirroringAsyncIo")
    }

    fn alignment(&self) -> u64 {
        // Stricter alignment wins. Same iovec goes to both backends.
        self.source.alignment().max(self.destination.alignment())
    }
}

/// Owns the copy worker thread's [`JoinHandle`]. The thread is joined
/// when the handle is dropped, or via [`Self::join`].
pub struct CopyWorkerHandle {
    join: Option<JoinHandle<()>>,
}

impl CopyWorkerHandle {
    /// Waits for the copy worker thread to finish. Idempotent:
    /// subsequent calls return `Ok(())` without blocking.
    pub fn join(&mut self) -> thread::Result<()> {
        if let Some(t) = self.join.take() {
            return t.join();
        }

        Ok(())
    }
}

impl Drop for CopyWorkerHandle {
    fn drop(&mut self) {
        self.join().ok();
    }
}

/// Background thread that copies existing source bytes to destination
/// in fixed-size blocks. Holds a [`RangeGuard`] across each block so
/// the virtqueue mirror writes cannot race the copy.
pub struct CopyWorker {
    source_io: Box<dyn AsyncIo>,
    dest_io: Box<dyn AsyncIo>,
    state: Arc<MirrorState>,
    /// Once allocated, the buffer is reused for all blocks to avoid repeated allocations.
    buf: Vec<u8>,
    /// Tracks the next user_data for request and completion notifications.
    next_user_data: u64,
    source_waiter: EpollWaiter,
    dest_waiter: EpollWaiter,
}
impl CopyWorker {
    /// Builds a worker on top of two async I/O handles. Queue depth 1
    /// is enough, as the worker is sequential. The caller must initialize the
    /// destination disk.
    ///
    /// Start the worker thread with [`Self::spawn`].
    pub fn new(
        source_disk: &dyn AsyncFullDiskFile,
        destination_disk: &dyn AsyncFullDiskFile,
        state: Arc<MirrorState>,
        block_size_bytes: usize,
    ) -> BlockResult<Self> {
        let source_io = source_disk.create_async_io(1)?;
        let dest_io = destination_disk.create_async_io(1)?;
        let source_waiter = EpollWaiter::new(source_io.notifier().as_raw_fd())?;
        let dest_waiter = EpollWaiter::new(dest_io.notifier().as_raw_fd())?;

        Ok(Self {
            source_io,
            dest_io,
            state,
            buf: vec![0; block_size_bytes],
            next_user_data: 0,
            source_waiter,
            dest_waiter,
        })
    }

    /// Spawns the worker on a named thread and returns its handle.
    /// On error inside the thread, the migration phase transitions
    /// to [`MirrorPhase::Failed`].
    pub fn spawn(self) -> io::Result<CopyWorkerHandle> {
        let state = self.state.clone();
        let join = thread::Builder::new()
            .name("blockdev-mirror-copy-worker".into())
            .spawn(move || {
                let mut worker = self;
                if let Err(e) = worker.run() {
                    state.transition_to_phase(MirrorPhase::Failed(format!(
                        "Copy worker failed: {e:?}"
                    )));
                }
            })?;

        Ok(CopyWorkerHandle { join: Some(join) })
    }

    /// Drives the block-by-block copy for predefined [`MirrorState::total_bytes`],
    /// then transitions the migration phase to [`MirrorPhase::Ready`].
    fn run(&mut self) -> io::Result<()> {
        let total_size = self.state.total_bytes;
        let max_length = self.buf.len() as u64;
        let mut offset = 0;

        while offset < total_size {
            let length = max_length.min(total_size - offset) as usize;
            self.copy_block(offset, length)?;
            offset += length as u64;
        }

        self.state.transition_to_phase(MirrorPhase::Ready);
        Ok(())
    }

    /// Copies `length` bytes at `offset` from source to destination.
    ///
    /// Holds a range lock for the duration so virtqueue mirror writes cannot race
    /// the copy. Uses `self.buf` for the copy to avoid repeated allocations.
    fn copy_block(&mut self, offset: u64, length: usize) -> io::Result<()> {
        let _guard = self.state.range_locks.lock_range(offset, length as u64)?;

        // Create a single iovec for the requested block.
        let iovecs = [iovec {
            iov_base: self.buf.as_mut_ptr().cast(),
            iov_len: length,
        }];

        // Read from source into buf.
        self.buf[..length].fill(0);
        let read_id = self.generate_user_data();
        self.source_io
            .read_vectored(offset as off_t, &iovecs, read_id)
            .map_err(|e| io::Error::other(format!("async io read_vectored failed: {e}")))?;
        let (user_data, result) =
            Self::wait_for_completion(&mut self.source_io, &self.source_waiter)?;
        if result < 0 {
            return Err(io::Error::from_raw_os_error(-result));
        }
        debug_assert_eq!(user_data, read_id);

        // Write buf to destination.
        let write_id = self.generate_user_data();
        self.dest_io
            .write_vectored(offset as off_t, &iovecs, write_id)
            .map_err(|e| io::Error::other(format!("async io write_vectored failed: {e}")))?;
        let (user_data, result) = Self::wait_for_completion(&mut self.dest_io, &self.dest_waiter)?;
        if result < 0 {
            return Err(io::Error::from_raw_os_error(-result));
        }
        debug_assert_eq!(user_data, write_id);

        self.state
            .copied_bytes
            .fetch_add(length as u64, std::sync::atomic::Ordering::Relaxed);

        Ok(())
    }

    /// Returns the current [`Self::next_user_data`] and increments it, wrapping on overflow.
    fn generate_user_data(&mut self) -> u64 {
        let user_data = self.next_user_data;
        self.next_user_data = self.next_user_data.wrapping_add(1);

        user_data
    }

    /// Blocks until one completion is available on `io`, then returns it.
    fn wait_for_completion(
        io: &mut Box<dyn AsyncIo>,
        waiter: &EpollWaiter,
    ) -> io::Result<(u64, i32)> {
        loop {
            if let Some(completion) = io.next_completed_request() {
                return Ok(completion);
            }

            // We need to poll the eventfd to detect when the next request completes.
            waiter.wait()?;

            // Drain the evenfd counter so next epoll_wait will not fire immediately on stale signal.
            let _ = io.notifier().read()?;
        }
    }
}

/// Handle returned by `Block::start_mirror`. The owner (typically the
/// device manager) keeps it alive for the duration of the mirror to
/// observe `MirrorState` and to retain the [`CopyWorker`] thread.
#[allow(dead_code)]
pub struct BlockMirrorHandle {
    pub state: Arc<MirrorState>,
    pub copy_worker: CopyWorkerHandle,
}

/// Single-fd `epoll` wrapper. Built once per eventfd and reused for
/// every `wait()` call so the copy worker doesn't pay setup cost per
/// block.
///
/// `wait()` blocks until the eventfd becomes readable.
struct EpollWaiter {
    epoll: epoll::Epoll,
}

impl EpollWaiter {
    /// Creates a reusable `EpollWaiter` for the given eventfd.
    fn new(event_fd: RawFd) -> io::Result<Self> {
        let epoll = epoll::Epoll::new()?;
        epoll.ctl(
            epoll::ControlOperation::Add,
            event_fd,
            epoll::EpollEvent::new(epoll::EventSet::IN, 0), // We care about `event fd has data to read` only.
        )?;
        Ok(Self { epoll })
    }

    /// Blocks until the event fd becomes readable. Retries on EINTR.
    fn wait(&self) -> io::Result<()> {
        let mut events = [epoll::EpollEvent::default(); 1];
        loop {
            match self.epoll.wait(-1, &mut events) {
                Ok(_) => return Ok(()),
                Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
                Err(e) => return Err(e),
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn overlaps_detects_range_starting_inside_query() {
        let mut locked = BTreeMap::new();
        locked.insert(10u64, 20u64);
        locked.insert(25u64, 30u64);
        assert!(RangeLockManager::overlaps_any(&locked, 21, 26));
    }

    #[test]
    fn overlaps_detects_preceding_overlap() {
        let mut locked = BTreeMap::new();
        locked.insert(10u64, 25u64);
        assert!(RangeLockManager::overlaps_any(&locked, 20, 30));
    }

    #[test]
    fn overlaps_disjoint_returns_false() {
        let mut locked = BTreeMap::new();
        locked.insert(10u64, 20u64);
        locked.insert(30u64, 40u64);
        assert!(!RangeLockManager::overlaps_any(&locked, 22, 28));
    }

    #[test]
    fn overlaps_touching_boundary_is_not_overlap() {
        let mut locked = BTreeMap::new();
        locked.insert(10u64, 20u64);
        assert!(!RangeLockManager::overlaps_any(&locked, 20, 30));
    }
}
