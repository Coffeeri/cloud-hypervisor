// Copyright 2026 The Cloud Hypervisor Authors. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Live storage migration for virtio-blk devices.
//!
//! Mirrors guest writes to a destination disk while a background
//! worker copies existing data from source to destination. Once
//! both sides are in sync the device manager can pivot the device
//! to serve I/O from the destination.

use std::collections::{BTreeMap, HashMap};
use std::io;
use std::os::fd::RawFd;
use std::sync::{Arc, Condvar, Mutex};

use libc::{iovec, off_t};
use log::error;
use log::warn;
use vmm_sys_util::epoll;
use vmm_sys_util::eventfd::EventFd;

use crate::BatchRequest;
use crate::async_io::{AsyncIo, AsyncIoError, AsyncIoResult};
use crate::disk_file::AsyncFullDiskFile;

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

/// Phase of a live storage migration.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MirrorPhase {
    /// Background copy is in progress.
    Copying,
    /// All blocks copied. Source and destination are in sync.
    Synced,
    /// Storage migration was canceled before pivoting.
    Aborted,
    /// Storage migration has failed.
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
            phase: Mutex::new(MirrorPhase::Copying),
            range_locks: RangeLockManager::new(),
        })
    }

    /// Returns a snapshot of the current phase.
    pub fn phase(&self) -> MirrorPhase {
        self.phase.lock().unwrap().clone()
    }

    /// Attempts a phase transition. Only the documented transitions are
    /// applied; any other attempt is ignored and logged.
    ///
    /// Allowed transitions:
    /// ```text
    /// Copying -> Synced | Failed(_) | Aborted
    /// Synced  -> Failed(_) | Aborted
    /// Aborted -> Failed(_)
    /// And idempotent transitions:
    /// Copying -> Copying | Synced -> Synced | Aborted -> Aborted | Failed(_) -> Failed(_)
    /// ```
    ///
    /// Failed and Aborted are terminal.
    pub fn transition_to_phase(&self, target: MirrorPhase) {
        use MirrorPhase::*;
        let mut current = self.phase.lock().unwrap();

        // Ignore idempotent transitions to the current state
        if std::mem::discriminant(&*current) == std::mem::discriminant(&target) {
            return;
        }

        let transition_allowed = matches!(
            (&*current, &target),
            (Copying, Synced)
                | (Copying, Failed(_))
                | (Copying, Aborted)
                | (Synced, Failed(_))
                | (Synced, Aborted)
                | (Aborted, Failed(_))
        );

        if !transition_allowed {
            error!("Invalid phase transition from {current:?} to {target:?}");
            // TODO cancel storage migration and rollback to plain disk
            return;
        }

        *current = target;
    }
}

/// Pairs a source and destination `AsyncFullDiskFile` while a
/// mirror is active.
///
/// The virtio block device holds this in place of the original
/// disk file. Each per-queue `AsyncIo` built from it sends writes
/// to both backends and serves reads from `source`.
#[allow(dead_code)]
pub struct MirroringDiskFile {
    /// Disk that backed the device before the mirror started.
    /// Reads continue to come from here.
    source: Box<dyn AsyncFullDiskFile>,
    /// Destination disk. Receives both mirrored guest writes and
    /// the bulk copy from source.
    destination: Box<dyn AsyncFullDiskFile>,
    /// Shared with the copy worker and the per-queue I/O wrappers.
    state: Arc<MirrorState>,
}

/// State for a single inflight mirrored request awaiting source and
/// destination completions. Drop releases the optional range guard so the
/// copy worker can touch the range again.
///
/// Only mutating requests are tracked, reads are applied to the
/// `source` disk.
struct InflightMutatingRequest {
    src_completion: Option<i32>,
    dest_completion: Option<i32>,
    _guard: Option<RangeGuard>,
}
impl InflightMutatingRequest {
    fn new(guard: Option<RangeGuard>) -> Self {
        Self {
            src_completion: None,
            dest_completion: None,
            _guard: guard,
        }
    }
}

/// Per-queue `AsyncIo` handle for a mirror.
pub struct MirroringAsyncIo {
    source: Box<dyn AsyncIo>,
    destination: Box<dyn AsyncIo>,
    state: Arc<MirrorState>,
    /// Inflight mirrored requests, keyed by the request's `user_data`.
    /// The optional guard inside each entry blocks the copy worker from touching
    /// the same range until both completions arrive.
    inflight_requests: HashMap<u64, InflightMutatingRequest>,
}
impl MirroringAsyncIo {
    fn cancel_storage_migration(&self) {
        self.state.transition_to_phase(MirrorPhase::Aborted);

        // TODO: Implement storage migration cancellation:
        // TODO: roll back to plain disk, stop copy worker, etc.
    }

    fn fail_storage_migration(&self, reason: String) {
        self.state.transition_to_phase(MirrorPhase::Failed(reason));
        self.cancel_storage_migration();
    }

    /// Helper that applies an `AsyncIo` request to both source and destination,
    /// tracking it in `inflight_requests` until both complete.
    ///
    /// Source error bubbles to the guest. Destination error fails and cancels
    /// the migration but is hidden from the guest, since `source` is the disk
    /// the guest sees.
    /// Tracking is skipped when `user_data` is `None` (fsync barriers that don't
    /// want a completion notification).
    fn mirror_request<S, D>(
        &mut self,
        request_label: &str,
        guard: Option<RangeGuard>,
        user_data: Option<u64>,
        submit_source: S,
        submit_destination: D,
    ) -> AsyncIoResult<()>
    where
        S: FnOnce(&mut Box<dyn AsyncIo>) -> AsyncIoResult<()>,
        D: FnOnce(&mut Box<dyn AsyncIo>) -> AsyncIoResult<()>,
    {
        // Source error bubbles to the guest. Drop optional guard via scope exit.
        submit_source(&mut self.source)?;

        // Destination error fails migration silently.
        if let Err(e) = submit_destination(&mut self.destination) {
            self.fail_storage_migration(format!(
                "destination {request_label} submit failed for user_data {user_data:?}: {e:?}"
            ));

            return Ok(());
        }

        // Only track requests where completion is wanted: user_data is set.
        // E.g. for `fsync()` we not always want to track this.
        if let Some(user_data) = user_data {
            self.inflight_requests
                .insert(user_data, InflightMutatingRequest::new(guard));
        }

        Ok(())
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
        let guard = self
            .state
            .range_locks
            .lock_iovecs(offset, iovecs)
            .map_err(AsyncIoError::WriteVectored)?;
        self.mirror_request(
            "write_vectored",
            Some(guard),
            Some(user_data),
            |src| src.write_vectored(offset, iovecs, user_data),
            |dst| dst.write_vectored(offset, iovecs, user_data),
        )
    }

    fn fsync(&mut self, user_data: Option<u64>) -> AsyncIoResult<()> {
        self.mirror_request(
            "fsync",
            None, // We dont need a guard here, `fsync()` is not ranged.
            user_data,
            |src| src.fsync(user_data),
            |dst| dst.fsync(user_data),
        )
    }

    fn punch_hole(&mut self, offset: u64, length: u64, user_data: u64) -> AsyncIoResult<()> {
        let guard = self
            .state
            .range_locks
            .lock_range(offset, length)
            .map_err(AsyncIoError::PunchHole)?;
        self.mirror_request(
            "punch_hole",
            Some(guard),
            Some(user_data),
            |src| src.punch_hole(offset, length, user_data),
            |dst| dst.punch_hole(offset, length, user_data),
        )
    }

    fn write_zeroes(&mut self, offset: u64, length: u64, user_data: u64) -> AsyncIoResult<()> {
        let guard = self
            .state
            .range_locks
            .lock_range(offset, length)
            .map_err(AsyncIoError::WriteZeroes)?;
        self.mirror_request(
            "write_zeroes",
            Some(guard),
            Some(user_data),
            |src| src.write_zeroes(offset, length, user_data),
            |dst| dst.write_zeroes(offset, length, user_data),
        )
    }

    fn next_completed_request(&mut self) -> Option<(u64, i32)> {
        // Drain source completions.
        while let Some((completion_id, result)) = self.source.next_completed_request() {
            match self.inflight_requests.get_mut(&completion_id) {
                Some(inflight_req) => inflight_req.src_completion = Some(result),
                None => return Some((completion_id, result)), // passthrough read or non-mirrored write completion
            }
        }

        // Drain destination completions.
        while let Some((completion_id, result)) = self.destination.next_completed_request() {
            if let Some(inflight_req) = self.inflight_requests.get_mut(&completion_id) {
                inflight_req.dest_completion = Some(result);
            } else {
                warn!("Unexpected destination completion for request {completion_id}");
            }
        }

        // Respond with the next mirrored completion on source and destination, if any.
        let (user_data, completed_req) = self
            .inflight_requests
            .extract_if(|_, w| w.src_completion.is_some() && w.dest_completion.is_some())
            .next()?;

        if completed_req.dest_completion.unwrap() < 0 {
            self.fail_storage_migration(format!(
                "destination completion with user_data={user_data} failed"
            ));
        }

        Some((user_data, completed_req.src_completion.unwrap()))
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
