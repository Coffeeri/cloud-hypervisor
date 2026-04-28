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
use std::io;
use std::os::fd::RawFd;
use std::sync::{Arc, Condvar, Mutex};

use libc::{iovec, off_t};
use log::warn;
use vmm_sys_util::epoll;
use vmm_sys_util::eventfd::EventFd;

use crate::BatchRequest;
use crate::async_io::{AsyncIo, AsyncIoError, AsyncIoResult};

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
}

impl MirrorState {
    pub fn new() -> Arc<Self> {
        Arc::new(Self {
            phase: Mutex::new(MirrorPhase::Running),
            range_locks: RangeLockManager::new(),
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

/// Single-fd `epoll` wrapper. Built once per eventfd and reused for
/// every `wait()` call so the copy worker doesn't pay setup cost per
/// block.
///
/// `wait()` blocks until the eventfd becomes readable.
#[allow(dead_code)]
struct EpollWaiter {
    epoll: epoll::Epoll,
}

#[allow(dead_code)]
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
