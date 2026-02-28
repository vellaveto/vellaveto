// Copyright 2026 Paolo Vella
// SPDX-License-Identifier: BUSL-1.1
//
// Use of this software is governed by the Business Source License
// included in the LICENSE-BSL-1.1 file at the root of this repository.
//
// Change Date: Three years from the date of publication of this version.
// Change License: MPL-2.0

//! Local (in-process) cluster backend.
//!
//! Delegates all operations to the existing `ApprovalStore` and in-process
//! rate limiters. This is the default backend when clustering is disabled,
//! preserving single-instance behavior exactly.

use async_trait::async_trait;
use std::sync::Arc;
use vellaveto_approval::ApprovalStore;

use crate::{ClusterBackend, ClusterError};

/// Local backend that delegates to in-process state.
///
/// This wraps the existing `ApprovalStore` (unchanged) and provides a no-op
/// rate limiter (rate limiting remains process-local via the existing governor
/// rate limiters in `vellaveto-server`).
pub struct LocalBackend {
    approvals: Arc<ApprovalStore>,
}

impl LocalBackend {
    /// Create a new local backend wrapping an existing `ApprovalStore`.
    pub fn new(approvals: Arc<ApprovalStore>) -> Self {
        Self { approvals }
    }
}

#[async_trait]
impl ClusterBackend for LocalBackend {
    async fn approval_create(
        &self,
        action: vellaveto_types::Action,
        reason: String,
        requested_by: Option<String>,
    ) -> Result<String, ClusterError> {
        Ok(self.approvals.create(action, reason, requested_by).await?)
    }

    async fn approval_get(
        &self,
        id: &str,
    ) -> Result<vellaveto_approval::PendingApproval, ClusterError> {
        Ok(self.approvals.get(id).await?)
    }

    async fn approval_approve(
        &self,
        id: &str,
        by: &str,
    ) -> Result<vellaveto_approval::PendingApproval, ClusterError> {
        Ok(self.approvals.approve(id, by).await?)
    }

    async fn approval_deny(
        &self,
        id: &str,
        by: &str,
    ) -> Result<vellaveto_approval::PendingApproval, ClusterError> {
        Ok(self.approvals.deny(id, by).await?)
    }

    async fn approval_list_pending(
        &self,
    ) -> Result<Vec<vellaveto_approval::PendingApproval>, ClusterError> {
        Ok(self.approvals.list_pending().await)
    }

    async fn approval_pending_count(&self) -> Result<usize, ClusterError> {
        Ok(self.approvals.pending_count().await)
    }

    async fn approval_expire_stale(&self) -> Result<usize, ClusterError> {
        Ok(self.approvals.expire_stale().await)
    }

    async fn rate_limit_check(
        &self,
        _category: &str,
        _key: &str,
        _rps: u32,
        _burst: u32,
    ) -> Result<bool, ClusterError> {
        // Rate limiting is handled process-locally by the existing governor
        // rate limiters in vellaveto-server. The local backend always returns
        // "allowed" and defers to the caller's own rate limiter.
        Ok(true)
    }

    async fn health_check(&self) -> Result<(), ClusterError> {
        // Local backend is always healthy — it's in-process memory.
        Ok(())
    }
}
