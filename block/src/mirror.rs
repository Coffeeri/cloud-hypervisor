// Copyright 2026 The Cloud Hypervisor Authors. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Live storage migration for virtio-blk devices.
//!
//! Mirrors guest writes to a destination disk while a background
//! worker copies existing data from source to destination. Once
//! both sides are in sync the device manager can pivot the device
//! to serve I/O from the destination.

use std::sync::{Arc, Mutex};

use log::error;

use crate::disk_file::AsyncFullDiskFile;

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
