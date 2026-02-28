// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
//
// Copyright 2026 Paolo Vella

//! Evidence Pack configuration for DORA and NIS2 compliance.

use serde::{Deserialize, Serialize};

/// Maximum length for evidence pack config string fields.
const MAX_EVIDENCE_PACK_STRING_LEN: usize = 512;

/// DORA compliance evidence pack configuration.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct DoraConfig {
    /// Enable DORA evidence pack generation.
    #[serde(default)]
    pub enabled: bool,
    /// Organization name for the DORA report.
    #[serde(default)]
    pub organization_name: String,
    /// Unique identifier for the ICT system.
    #[serde(default)]
    pub system_id: String,
}

impl DoraConfig {
    /// Validate DORA configuration bounds.
    pub fn validate(&self) -> Result<(), String> {
        validate_pack_string("dora.organization_name", &self.organization_name)?;
        validate_pack_string("dora.system_id", &self.system_id)?;
        Ok(())
    }
}

/// NIS2 compliance evidence pack configuration.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct Nis2Config {
    /// Enable NIS2 evidence pack generation.
    #[serde(default)]
    pub enabled: bool,
    /// Organization name for the NIS2 report.
    #[serde(default)]
    pub organization_name: String,
    /// Unique identifier for the network/information system.
    #[serde(default)]
    pub system_id: String,
}

impl Nis2Config {
    /// Validate NIS2 configuration bounds.
    pub fn validate(&self) -> Result<(), String> {
        validate_pack_string("nis2.organization_name", &self.organization_name)?;
        validate_pack_string("nis2.system_id", &self.system_id)?;
        Ok(())
    }
}

fn validate_pack_string(field_name: &str, value: &str) -> Result<(), String> {
    if value.len() > MAX_EVIDENCE_PACK_STRING_LEN {
        return Err(format!(
            "{} length {} exceeds max {}",
            field_name,
            value.len(),
            MAX_EVIDENCE_PACK_STRING_LEN,
        ));
    }
    if vellaveto_types::has_dangerous_chars(value) {
        return Err(format!(
            "{} contains control or format characters",
            field_name,
        ));
    }
    Ok(())
}
