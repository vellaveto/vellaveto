// Copyright 2026 Paolo Vella
// SPDX-License-Identifier: BUSL-1.1
//
// Use of this software is governed by the Business Source License
// included in the LICENSE-BSL-1.1 file at the root of this repository.
//
// Change Date: Three years from the date of publication of this version.
// Change License: MPL-2.0

//! ETDI: Enhanced Tool Definition Interface (arxiv:2506.01333)
//!
//! Cryptographic verification of MCP tool definitions to prevent:
//! - Tool rug-pulls (definition changes post-install)
//! - Tool squatting (malicious tools impersonating legitimate ones)
//! - Supply chain attacks on MCP tool servers
//!
//! # Architecture
//!
//! - [`signature`]: Core signature creation and verification (Ed25519/ECDSA P-256)
//! - [`attestation`]: Attestation chain management for provenance tracking
//! - [`version_pin`]: Version pinning and drift detection
//! - [`store`]: Persistent storage for ETDI state
//!
//! # Security Properties
//!
//! - Fail-closed: Missing or invalid signatures result in Deny when `require_signatures` is true
//! - Tamper-evident: Attestation chains detect unauthorized modifications
//! - Observable: All verification results are logged for audit

pub mod attestation;
pub mod signature;
pub mod store;
pub mod version_pin;

pub use attestation::AttestationChain;
pub use signature::{EtdiError, ToolSignatureVerifier, ToolSigner};
pub use store::EtdiStore;
pub use version_pin::VersionPinManager;
