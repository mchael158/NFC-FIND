//! Authorization gate for the NFC relay prototype.
//!
//! A relay tool is dual-use. This module enforces that the operator has
//! declared an authorized scope before any NFC/relay path is enabled.

use std::env;

#[derive(Debug, Clone)]
pub struct Scope {
    pub engagement: String,
    pub target_environment: String, // "lab" | "authorized-pentest" | "research"
    pub authorized: bool,
}

impl Scope {
    pub fn from_env() -> Self {
        let engagement = env::var("NFC_RELAY_ENGAGEMENT").unwrap_or_default();
        let target_environment = env::var("NFC_RELAY_ENV").unwrap_or_else(|_| "lab".into());
        let authorized = env::var("NFC_RELAY_AUTHORIZED")
            .map(|v| v == "1" || v.eq_ignore_ascii_case("true") || v.eq_ignore_ascii_case("yes"))
            .unwrap_or(false);

        Self {
            engagement,
            target_environment,
            authorized,
        }
    }

    pub fn require_authorized(&self) -> anyhow::Result<()> {
        if !self.authorized {
            anyhow::bail!(
                "relay disabled: set NFC_RELAY_AUTHORIZED=1 and NFC_RELAY_ENGAGEMENT=<name> \
                 (target env: {})",
                self.target_environment
            );
        }
        if self.engagement.trim().is_empty() {
            anyhow::bail!("relay disabled: NFC_RELAY_ENGAGEMENT must be set");
        }
        Ok(())
    }
}
