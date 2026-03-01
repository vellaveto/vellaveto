// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
//
// Copyright 2026 Paolo Vella
// SPDX-License-Identifier: MPL-2.0

// ═══════════════════════════════════════════════════════════════════════════════
// BILLING — Payment provider configuration (Paddle + Stripe)
// ═══════════════════════════════════════════════════════════════════════════════

use serde::{Deserialize, Serialize};

const MAX_ENV_VAR_NAME_LEN: usize = 128;

/// Top-level billing configuration.
#[derive(Debug, Default, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BillingConfig {
    /// Whether billing webhooks are enabled.
    #[serde(default)]
    pub enabled: bool,

    /// Paddle payment provider configuration (international self-serve).
    #[serde(default)]
    pub paddle: PaddleConfig,

    /// Stripe payment provider configuration (Italian enterprise).
    #[serde(default)]
    pub stripe: StripeConfig,
}

/// Paddle webhook configuration.
///
/// Webhook secret is read from an environment variable at runtime —
/// NEVER stored in config files.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PaddleConfig {
    /// Name of the environment variable holding the Paddle webhook secret.
    /// Default: `VELLAVETO_PADDLE_WEBHOOK_SECRET`
    #[serde(default = "PaddleConfig::default_secret_env")]
    pub webhook_secret_env: String,
}

impl Default for PaddleConfig {
    fn default() -> Self {
        Self {
            webhook_secret_env: Self::default_secret_env(),
        }
    }
}

impl PaddleConfig {
    fn default_secret_env() -> String {
        "VELLAVETO_PADDLE_WEBHOOK_SECRET".to_string()
    }

    /// Read the webhook secret from the configured environment variable.
    /// Returns None if the env var is not set or is empty.
    pub fn webhook_secret(&self) -> Option<String> {
        std::env::var(&self.webhook_secret_env)
            .ok()
            .filter(|s| !s.is_empty())
    }
}

/// Stripe webhook configuration.
///
/// Webhook secret is read from an environment variable at runtime —
/// NEVER stored in config files.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StripeConfig {
    /// Name of the environment variable holding the Stripe webhook secret.
    /// Default: `VELLAVETO_STRIPE_WEBHOOK_SECRET`
    #[serde(default = "StripeConfig::default_secret_env")]
    pub webhook_secret_env: String,
}

impl Default for StripeConfig {
    fn default() -> Self {
        Self {
            webhook_secret_env: Self::default_secret_env(),
        }
    }
}

impl StripeConfig {
    fn default_secret_env() -> String {
        "VELLAVETO_STRIPE_WEBHOOK_SECRET".to_string()
    }

    /// Read the webhook secret from the configured environment variable.
    /// Returns None if the env var is not set or is empty.
    pub fn webhook_secret(&self) -> Option<String> {
        std::env::var(&self.webhook_secret_env)
            .ok()
            .filter(|s| !s.is_empty())
    }
}

impl BillingConfig {
    /// Validate the billing configuration.
    pub fn validate(&self) -> Result<(), String> {
        // SECURITY (P2-2): Reject empty env var names — std::env::var("")
        // fails silently on most platforms, causing the webhook handler to
        // accept all unsigned traffic.
        if self.paddle.webhook_secret_env.is_empty() {
            return Err("paddle.webhook_secret_env must not be empty".to_string());
        }
        if self.stripe.webhook_secret_env.is_empty() {
            return Err("stripe.webhook_secret_env must not be empty".to_string());
        }
        if self.paddle.webhook_secret_env.len() > MAX_ENV_VAR_NAME_LEN {
            return Err("paddle.webhook_secret_env exceeds maximum length".to_string());
        }
        if self.stripe.webhook_secret_env.len() > MAX_ENV_VAR_NAME_LEN {
            return Err("stripe.webhook_secret_env exceeds maximum length".to_string());
        }
        // Env var names should be alphanumeric + underscore only
        if !self
            .paddle
            .webhook_secret_env
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '_')
        {
            return Err("paddle.webhook_secret_env contains invalid characters".to_string());
        }
        if !self
            .stripe
            .webhook_secret_env
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '_')
        {
            return Err("stripe.webhook_secret_env contains invalid characters".to_string());
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_billing_config_defaults() {
        let config = BillingConfig::default();
        assert!(!config.enabled);
        assert_eq!(
            config.paddle.webhook_secret_env,
            "VELLAVETO_PADDLE_WEBHOOK_SECRET"
        );
        assert_eq!(
            config.stripe.webhook_secret_env,
            "VELLAVETO_STRIPE_WEBHOOK_SECRET"
        );
    }

    #[test]
    fn test_billing_config_validate_ok() {
        let config = BillingConfig::default();
        assert!(config.validate().is_ok());
    }

    #[test]
    fn test_billing_config_validate_empty_env_name_paddle() {
        let config = BillingConfig {
            enabled: true,
            paddle: PaddleConfig {
                webhook_secret_env: String::new(),
            },
            stripe: StripeConfig::default(),
        };
        let err = config.validate().unwrap_err();
        assert!(err.contains("must not be empty"));
    }

    #[test]
    fn test_billing_config_validate_empty_env_name_stripe() {
        let config = BillingConfig {
            enabled: true,
            paddle: PaddleConfig::default(),
            stripe: StripeConfig {
                webhook_secret_env: String::new(),
            },
        };
        let err = config.validate().unwrap_err();
        assert!(err.contains("must not be empty"));
    }

    #[test]
    fn test_billing_config_validate_bad_env_name() {
        let config = BillingConfig {
            enabled: true,
            paddle: PaddleConfig {
                webhook_secret_env: "INVALID-NAME".to_string(),
            },
            stripe: StripeConfig::default(),
        };
        assert!(config.validate().is_err());
    }

    #[test]
    fn test_billing_config_validate_too_long_env_name() {
        let config = BillingConfig {
            enabled: true,
            paddle: PaddleConfig {
                webhook_secret_env: "A".repeat(MAX_ENV_VAR_NAME_LEN + 1),
            },
            stripe: StripeConfig::default(),
        };
        assert!(config.validate().is_err());
    }

    #[test]
    fn test_billing_config_serde_roundtrip() {
        let config = BillingConfig {
            enabled: true,
            paddle: PaddleConfig {
                webhook_secret_env: "MY_PADDLE_SECRET".to_string(),
            },
            stripe: StripeConfig {
                webhook_secret_env: "MY_STRIPE_SECRET".to_string(),
            },
        };
        let json = serde_json::to_string(&config).expect("serialize");
        let parsed: BillingConfig = serde_json::from_str(&json).expect("deserialize");
        assert!(parsed.enabled);
        assert_eq!(parsed.paddle.webhook_secret_env, "MY_PADDLE_SECRET");
        assert_eq!(parsed.stripe.webhook_secret_env, "MY_STRIPE_SECRET");
    }

    #[test]
    fn test_paddle_webhook_secret_from_env() {
        // When env var is not set, returns None
        let config = PaddleConfig {
            webhook_secret_env: "VELLAVETO_TEST_PADDLE_SECRET_NONEXISTENT".to_string(),
        };
        assert!(config.webhook_secret().is_none());
    }

    #[test]
    fn test_stripe_webhook_secret_from_env() {
        // When env var is not set, returns None
        let config = StripeConfig {
            webhook_secret_env: "VELLAVETO_TEST_STRIPE_SECRET_NONEXISTENT".to_string(),
        };
        assert!(config.webhook_secret().is_none());
    }
}
