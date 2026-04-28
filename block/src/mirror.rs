// Copyright 2026 The Cloud Hypervisor Authors. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Live storage migration for virtio-blk devices.
//!
//! Mirrors guest writes to a destination disk while a background
//! worker copies existing data from source to destination. Once
//! both sides are in sync the device manager can pivot the device
//! to serve I/O from the destination.

use std::collections::BTreeMap;
use std::io;
use std::sync::{Arc, Condvar, Mutex};

use libc::{iovec, off_t};
use log::error;
use vmm_sys_util::eventfd::EventFd;

use crate::BatchRequest;
use crate::async_io::{AsyncIo, AsyncIoResult};
use crate::disk_file::AsyncFullDiskFile;

/// Serializes overlapping byte ranges between the copy worker and the
/// per-queue mirror writes.
///
/// Each party calls [`Self::lock_range`] before submitting I/O and
/// holds the returned [`RangeGuard`] until completion. A conflicting
/// request blocks on a `Condvar` until the held guard is dropped.
/// Lookups are O(log n) on the number of held ranges.
#[allow(dead_code)]
struct RangeLockManager {
    /// Held ranges as `start -> end_exclusive`. The mutex makes the
    /// overlap check and insert in [`Self::lock_range`] atomic with
    /// respect to releases in [`RangeGuard::drop`].
    ranges: Mutex<BTreeMap<u64, u64>>,
    /// Notified on guard drop. Waiters re-check their range.
    cv: Condvar,
}

#[allow(dead_code)]
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
#[allow(dead_code)]
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
    #[allow(dead_code)]
    phase: Mutex<MirrorPhase>,
}

#[allow(dead_code)]
impl MirrorState {
    pub fn new() -> Arc<Self> {
        Arc::new(Self {
            phase: Mutex::new(MirrorPhase::Copying),
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

/// Per-queue `AsyncIo` handle for a mirror.
#[allow(dead_code)]
pub struct MirroringAsyncIo {
    source: Box<dyn AsyncIo>,
    destination: Box<dyn AsyncIo>,
    state: Arc<MirrorState>,
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
        self.source.write_vectored(offset, iovecs, user_data)
    }

    fn fsync(&mut self, user_data: Option<u64>) -> AsyncIoResult<()> {
        self.source.fsync(user_data)
    }

    fn punch_hole(&mut self, offset: u64, length: u64, user_data: u64) -> AsyncIoResult<()> {
        self.source.punch_hole(offset, length, user_data)
    }

    fn write_zeroes(&mut self, offset: u64, length: u64, user_data: u64) -> AsyncIoResult<()> {
        self.source.write_zeroes(offset, length, user_data)
    }

    fn next_completed_request(&mut self) -> Option<(u64, i32)> {
        self.source.next_completed_request()
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
