use crate::default_true;
use serde::{Deserialize, Serialize};
use vellaveto_types::has_dangerous_chars;

const MAX_OIDC_URL_LEN: usize = 512;
const MAX_OIDC_CLIENT_ID_LEN: usize = 128;
const MAX_OIDC_SECRET_LEN: usize = 512;
const MAX_OIDC_SCOPE_LEN: usize = 64;
const MAX_OIDC_SCOPES: usize = 16;

const MAX_SAML_URL_LEN: usize = 512;
const MAX_SAML_FIELD_LEN: usize = 256;

const MAX_COOKIE_NAME_LEN: usize = 64;
const MIN_SESSION_TIMEOUT_SECS: u64 = 60;
const MAX_SESSION_TIMEOUT_SECS: u64 = 86_400;
const MAX_SESSIONS_PER_PRINCIPAL: u32 = 100;

const MIN_SCIM_SYNC_SECS: u64 = 60;
const MAX_SCIM_SYNC_SECS: u64 = 86_400;

fn default_oidc_role_claim() -> String {
    "vellaveto_role".to_string()
}

fn default_oidc_scopes() -> Vec<String> {
    vec![
        "openid".to_string(),
        "profile".to_string(),
        "email".to_string(),
    ]
}

fn default_jwks_cache_secs() -> u64 {
    300
}

fn default_session_cookie_name() -> String {
    "vellaveto_session".to_string()
}

fn default_session_idle_timeout() -> u64 {
    3_600
}

fn default_session_max_age() -> u64 {
    3_600
}

fn default_max_sessions_per_principal() -> u32 {
    10
}

fn default_scim_sync_interval() -> u64 {
    3_600
}

fn ensure_safe_str(field: &str, value: &str, max_len: usize) -> Result<(), String> {
    if value.is_empty() {
        return Err(format!("{} must not be empty", field));
    }
    if value.len() > max_len {
        return Err(format!(
            "{} length {} exceeds max {}",
            field,
            value.len(),
            max_len
        ));
    }
    if has_dangerous_chars(value) {
        return Err(format!(
            "{} contains control or Unicode format characters",
            field
        ));
    }
    Ok(())
}

fn ensure_env_var(field: &str, value: &str) -> Result<(), String> {
    if value.is_empty() {
        return Err(format!("{} must not be empty", field));
    }
    if has_dangerous_chars(value) {
        return Err(format!(
            "{} contains control or Unicode format characters",
            field
        ));
    }
    Ok(())
}

/// Enterprise IAM configuration covering OIDC, SAML, session, and SCIM plumbing.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct IamConfig {
    /// Globally enable IAM integration.
    #[serde(default)]
    pub enabled: bool,

    /// OpenID Connect provider configuration.
    #[serde(default)]
    pub oidc: OidcConfig,

    /// SAML 2.0 service provider configuration.
    #[serde(default)]
    pub saml: SamlConfig,

    /// Session management controls (secure cookies, timeouts, session caps).
    #[serde(default)]
    pub session: SessionConfig,

    /// SCIM provisioning integration configuration.
    #[serde(default)]
    pub scim: ScimConfig,
}

impl Default for IamConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            oidc: OidcConfig::default(),
            saml: SamlConfig::default(),
            session: SessionConfig::default(),
            scim: ScimConfig::default(),
        }
    }
}

impl IamConfig {
    /// Validate IAM configuration bounds.
    pub fn validate(&self) -> Result<(), String> {
        self.oidc.validate()?;
        self.saml.validate()?;
        self.session.validate()?;
        self.scim.validate()?;

        if self.enabled && !self.oidc.enabled && !self.saml.enabled {
            return Err(
                "iam.enabled is true but neither oidc.enabled nor saml.enabled is configured"
                    .to_string(),
            );
        }
        Ok(())
    }
}

/// OpenID Connect provider configuration.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct OidcConfig {
    #[serde(default)]
    pub enabled: bool,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub issuer_url: Option<String>,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub client_id: Option<String>,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub client_secret: Option<String>,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub redirect_uri: Option<String>,

    #[serde(default = "default_oidc_scopes")]
    pub scopes: Vec<String>,

    #[serde(default = "default_oidc_role_claim")]
    pub role_claim: String,

    #[serde(default)]
    pub allow_insecure_issuer: bool,

    #[serde(default)]
    pub pkce: bool,

    #[serde(default = "default_jwks_cache_secs")]
    pub jwks_cache_secs: u64,
}

impl Default for OidcConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            issuer_url: None,
            client_id: None,
            client_secret: None,
            redirect_uri: None,
            scopes: default_oidc_scopes(),
            role_claim: default_oidc_role_claim(),
            allow_insecure_issuer: false,
            pkce: true,
            jwks_cache_secs: default_jwks_cache_secs(),
        }
    }
}

impl OidcConfig {
    fn validate(&self) -> Result<(), String> {
        if !self.enabled {
            return Ok(());
        }

        let issuer = self.issuer_url.as_ref().ok_or_else(|| {
            "iam.oidc.issuer_url is required when oidc.enabled is true".to_string()
        })?;
        ensure_safe_str("iam.oidc.issuer_url", issuer, MAX_OIDC_URL_LEN)?;

        let client_id = self.client_id.as_ref().ok_or_else(|| {
            "iam.oidc.client_id is required when oidc.enabled is true".to_string()
        })?;
        ensure_safe_str("iam.oidc.client_id", client_id, MAX_OIDC_CLIENT_ID_LEN)?;

        if let Some(client_secret) = &self.client_secret {
            ensure_safe_str("iam.oidc.client_secret", client_secret, MAX_OIDC_SECRET_LEN)?;
        } else if !self.pkce {
            return Err("iam.oidc.client_secret is required when PKCE is disabled".to_string());
        }

        let redirect = self.redirect_uri.as_ref().ok_or_else(|| {
            "iam.oidc.redirect_uri is required when oidc.enabled is true".to_string()
        })?;
        ensure_safe_str("iam.oidc.redirect_uri", redirect, MAX_OIDC_URL_LEN)?;

        if self.scopes.is_empty() {
            return Err("iam.oidc.scopes must contain at least one scope".to_string());
        }
        if self.scopes.len() > MAX_OIDC_SCOPES {
            return Err(format!(
                "iam.oidc.scopes length {} exceeds max {}",
                self.scopes.len(),
                MAX_OIDC_SCOPES
            ));
        }
        for (i, scope) in self.scopes.iter().enumerate() {
            if scope.len() > MAX_OIDC_SCOPE_LEN {
                return Err(format!(
                    "iam.oidc.scopes[{}] length {} exceeds max {}",
                    i,
                    scope.len(),
                    MAX_OIDC_SCOPE_LEN
                ));
            }
            ensure_safe_str(
                &format!("iam.oidc.scopes[{}]", i),
                scope,
                MAX_OIDC_SCOPE_LEN,
            )?;
        }

        ensure_safe_str("iam.oidc.role_claim", &self.role_claim, MAX_SAML_FIELD_LEN)?;

        if self.jwks_cache_secs == 0 {
            return Err("iam.oidc.jwks_cache_secs must be greater than 0".to_string());
        }

        Ok(())
    }
}

/// SAML 2.0 service provider configuration.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct SamlConfig {
    #[serde(default)]
    pub enabled: bool,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub entity_id: Option<String>,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub acs_url: Option<String>,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub idp_metadata_url: Option<String>,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub role_attribute: Option<String>,
}

impl Default for SamlConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            entity_id: None,
            acs_url: None,
            idp_metadata_url: None,
            role_attribute: Some("Role".to_string()),
        }
    }
}

impl SamlConfig {
    fn validate(&self) -> Result<(), String> {
        if !self.enabled {
            return Ok(());
        }

        let entity_id = self.entity_id.as_ref().ok_or_else(|| {
            "iam.saml.entity_id is required when saml.enabled is true".to_string()
        })?;
        ensure_safe_str("iam.saml.entity_id", entity_id, MAX_SAML_FIELD_LEN)?;

        let acs = self
            .acs_url
            .as_ref()
            .ok_or_else(|| "iam.saml.acs_url is required when saml.enabled is true".to_string())?;
        ensure_safe_str("iam.saml.acs_url", acs, MAX_SAML_URL_LEN)?;

        let metadata = self.idp_metadata_url.as_ref().ok_or_else(|| {
            "iam.saml.idp_metadata_url is required when saml.enabled is true".to_string()
        })?;
        ensure_safe_str("iam.saml.idp_metadata_url", metadata, MAX_SAML_URL_LEN)?;

        if let Some(role_attr) = &self.role_attribute {
            ensure_safe_str("iam.saml.role_attribute", role_attr, MAX_SAML_FIELD_LEN)?;
        }

        Ok(())
    }
}

/// Session configuration for IAM sessions.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct SessionConfig {
    #[serde(default = "default_session_cookie_name")]
    pub cookie_name: String,

    #[serde(default = "default_true")]
    pub secure_cookie: bool,

    #[serde(default = "default_true")]
    pub http_only: bool,

    #[serde(default = "default_session_idle_timeout")]
    pub idle_timeout_secs: u64,

    #[serde(default = "default_session_max_age")]
    pub max_age_secs: u64,

    #[serde(default = "default_max_sessions_per_principal")]
    pub max_sessions_per_principal: u32,
}

impl Default for SessionConfig {
    fn default() -> Self {
        Self {
            cookie_name: default_session_cookie_name(),
            secure_cookie: true,
            http_only: true,
            idle_timeout_secs: default_session_idle_timeout(),
            max_age_secs: default_session_max_age(),
            max_sessions_per_principal: default_max_sessions_per_principal(),
        }
    }
}

impl SessionConfig {
    fn validate(&self) -> Result<(), String> {
        ensure_safe_str(
            "iam.session.cookie_name",
            &self.cookie_name,
            MAX_COOKIE_NAME_LEN,
        )?;

        if self.idle_timeout_secs < MIN_SESSION_TIMEOUT_SECS
            || self.idle_timeout_secs > MAX_SESSION_TIMEOUT_SECS
        {
            return Err(format!(
                "iam.session.idle_timeout_secs must be between {} and {}",
                MIN_SESSION_TIMEOUT_SECS, MAX_SESSION_TIMEOUT_SECS
            ));
        }
        if self.max_age_secs < MIN_SESSION_TIMEOUT_SECS
            || self.max_age_secs > MAX_SESSION_TIMEOUT_SECS
        {
            return Err(format!(
                "iam.session.max_age_secs must be between {} and {}",
                MIN_SESSION_TIMEOUT_SECS, MAX_SESSION_TIMEOUT_SECS
            ));
        }
        if self.max_sessions_per_principal == 0
            || self.max_sessions_per_principal > MAX_SESSIONS_PER_PRINCIPAL
        {
            return Err(format!(
                "iam.session.max_sessions_per_principal must be between 1 and {}",
                MAX_SESSIONS_PER_PRINCIPAL
            ));
        }
        Ok(())
    }
}

/// SCIM provisioning configuration.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct ScimConfig {
    #[serde(default)]
    pub enabled: bool,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub endpoint: Option<String>,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub bearer_token: Option<String>,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub bearer_token_env: Option<String>,

    #[serde(default = "default_scim_sync_interval")]
    pub sync_interval_secs: u64,
}

impl Default for ScimConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            endpoint: None,
            bearer_token: None,
            bearer_token_env: None,
            sync_interval_secs: default_scim_sync_interval(),
        }
    }
}

impl ScimConfig {
    fn validate(&self) -> Result<(), String> {
        if !self.enabled {
            return Ok(());
        }

        let endpoint = self
            .endpoint
            .as_ref()
            .ok_or_else(|| "iam.scim.endpoint is required when scim.enabled is true".to_string())?;
        ensure_safe_str("iam.scim.endpoint", endpoint, MAX_OIDC_URL_LEN)?;

        if self.bearer_token.is_none() && self.bearer_token_env.is_none() {
            return Err(
                "iam.scim.bearer_token or iam.scim.bearer_token_env is required when scim.enabled is true".to_string(),
            );
        }
        if let Some(token) = &self.bearer_token {
            ensure_safe_str("iam.scim.bearer_token", token, MAX_OIDC_SECRET_LEN)?;
        }
        if let Some(env) = &self.bearer_token_env {
            ensure_env_var("iam.scim.bearer_token_env", env)?;
        }

        if self.sync_interval_secs < MIN_SCIM_SYNC_SECS
            || self.sync_interval_secs > MAX_SCIM_SYNC_SECS
        {
            return Err(format!(
                "iam.scim.sync_interval_secs must be between {} and {}",
                MIN_SCIM_SYNC_SECS, MAX_SCIM_SYNC_SECS
            ));
        }

        Ok(())
    }
}
