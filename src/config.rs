//! Operator-supplied configuration schema for `dev.mcpg.identity.basic`.

use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use thiserror::Error;
use time::OffsetDateTime;

/// Deserialize-only RFC3339 option helper. Avoids enabling
/// `time`'s `formatting` feature on the cdylib (we never serialize
/// the parsed timestamp).
mod rfc3339_opt {
    use serde::{Deserialize, Deserializer};
    use time::OffsetDateTime;
    use time::format_description::well_known::Rfc3339;

    pub fn deserialize<'de, D: Deserializer<'de>>(
        d: D,
    ) -> Result<Option<OffsetDateTime>, D::Error> {
        let opt: Option<String> = Option::deserialize(d)?;
        opt.map(|s| OffsetDateTime::parse(&s, &Rfc3339).map_err(serde::de::Error::custom))
            .transpose()
    }
}

/// Top-level plugin config.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BasicConfig {
    pub users: Vec<UserEntry>,
    #[serde(default)]
    pub username_case: UsernameCase,
    #[serde(default)]
    pub resolution: ResolutionConfig,
}

#[derive(Debug, Clone, Copy, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum UsernameCase {
    #[default]
    Insensitive,
    Sensitive,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UserEntry {
    pub username: String,
    /// PHC-string format. Operators generate via `argon2 ... -e` or
    /// `htpasswd -B -n`. Resolved via the gateway's secret-resolver
    /// (`${env.VAR}` / `vault://...`) so the hash is never in
    /// plaintext config.
    pub password_hash: String,
    #[serde(default = "default_true")]
    pub enabled: bool,
    #[serde(default, deserialize_with = "rfc3339_opt::deserialize")]
    pub expires_at: Option<OffsetDateTime>,
    #[serde(default)]
    pub roles: Vec<String>,
    #[serde(default)]
    pub groups: Vec<String>,
    #[serde(default)]
    pub scopes: Vec<String>,
    #[serde(default)]
    pub attributes: BTreeMap<String, String>,
}

fn default_true() -> bool {
    true
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ResolutionConfig {
    /// Trust-level the gateway should associate with successfully
    /// authenticated callers. Hash verification is cryptographic
    /// proof of password possession, so `"verified"` is the
    /// natural default; operators with weaker guarantees (e.g.
    /// header-asserted-only deploys) downgrade.
    #[serde(default = "default_trust_level")]
    pub trust_level: String,

    /// `auth_provider` field on the resolved `PluginIdentity`.
    /// Operators MAY override (e.g. `"basic-partner"` for
    /// per-tenant accounting).
    #[serde(default = "default_auth_provider_label")]
    pub auth_provider_label: String,
}

impl Default for ResolutionConfig {
    fn default() -> Self {
        Self {
            trust_level: default_trust_level(),
            auth_provider_label: default_auth_provider_label(),
        }
    }
}

fn default_trust_level() -> String {
    "verified".into()
}

fn default_auth_provider_label() -> String {
    "basic".into()
}

#[derive(Debug, Error)]
pub enum ConfigError {
    #[error("invalid identity.basic config JSON: {0}")]
    InvalidJson(#[from] serde_json::Error),
    #[error("identity.basic: `users` must be non-empty")]
    EmptyUsers,
    #[error("identity.basic: user[{index}]: username is empty")]
    EmptyUsername { index: usize },
    #[error("identity.basic: user[{index}]: password_hash is empty")]
    EmptyPasswordHash { index: usize },
    #[error(
        "identity.basic: user[{index}] (`{username}`): password_hash does not look \
         like a supported PHC string (must start with $argon2id$, $argon2i$, \
         $argon2d$, $2a$, $2b$, or $2y$). Re-hash via `argon2 -e` or `htpasswd -B`."
    )]
    UnsupportedHashAlgorithm { index: usize, username: String },
    #[error(
        "identity.basic: duplicate username `{username}` (case-folded under \
         `username_case: insensitive`); set `username_case: sensitive` if Alice \
         and alice are genuinely different users."
    )]
    DuplicateUsername { username: String },
    #[error(
        "identity.basic: invalid trust_level `{value}` (allowed: \
         verified | header_asserted)"
    )]
    InvalidTrustLevel { value: String },
}

impl BasicConfig {
    /// Parse + validate from JSON.
    pub fn parse(s: &str) -> Result<Self, ConfigError> {
        let cfg: Self = serde_json::from_str(s)?;
        cfg.validate()?;
        Ok(cfg)
    }

    fn validate(&self) -> Result<(), ConfigError> {
        if self.users.is_empty() {
            return Err(ConfigError::EmptyUsers);
        }
        match self.resolution.trust_level.as_str() {
            "verified" | "header_asserted" => {}
            other => {
                return Err(ConfigError::InvalidTrustLevel {
                    value: other.into(),
                });
            }
        }
        let mut seen: BTreeSet<String> = BTreeSet::new();
        for (index, user) in self.users.iter().enumerate() {
            if user.username.trim().is_empty() {
                return Err(ConfigError::EmptyUsername { index });
            }
            if user.password_hash.trim().is_empty() {
                return Err(ConfigError::EmptyPasswordHash { index });
            }
            let prefix = user
                .password_hash
                .split('$')
                .nth(1)
                .map(|s| format!("${s}$"))
                .unwrap_or_default();
            let supported = matches!(
                prefix.as_str(),
                "$argon2id$" | "$argon2i$" | "$argon2d$" | "$2a$" | "$2b$" | "$2y$"
            );
            if !supported {
                return Err(ConfigError::UnsupportedHashAlgorithm {
                    index,
                    username: user.username.clone(),
                });
            }
            let canonical = match self.username_case {
                UsernameCase::Insensitive => user.username.to_lowercase(),
                UsernameCase::Sensitive => user.username.clone(),
            };
            if !seen.insert(canonical) {
                return Err(ConfigError::DuplicateUsername {
                    username: user.username.clone(),
                });
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn argon2_alice_hash() -> &'static str {
        // Pre-computed argon2id hash of password "hunter2" with a
        // fixed salt for test determinism (cost params low to keep
        // tests fast — DO NOT use these params in production).
        "$argon2id$v=19$m=16,t=1,p=1$dGVzdHNhbHQ$Y/p1AcN05PI3DMWP00wbAA"
    }

    #[test]
    fn parses_minimal_config() {
        let cfg = json!({
            "users": [{
                "username": "alice",
                "password_hash": argon2_alice_hash(),
            }]
        })
        .to_string();
        let parsed = BasicConfig::parse(&cfg).unwrap();
        assert_eq!(parsed.users.len(), 1);
        assert_eq!(parsed.users[0].username, "alice");
        assert!(parsed.users[0].enabled);
    }

    #[test]
    fn rejects_empty_users() {
        let cfg = json!({ "users": [] }).to_string();
        let err = BasicConfig::parse(&cfg).unwrap_err();
        matches!(err, ConfigError::EmptyUsers);
    }

    #[test]
    fn rejects_md5_hash() {
        let cfg = json!({
            "users": [{
                "username": "alice",
                "password_hash": "$1$abc$xxx", // md5
            }]
        })
        .to_string();
        let err = BasicConfig::parse(&cfg).unwrap_err();
        match err {
            ConfigError::UnsupportedHashAlgorithm { username, .. } => {
                assert_eq!(username, "alice");
            }
            other => panic!("unexpected: {other:?}"),
        }
    }

    #[test]
    fn rejects_duplicate_username_case_folded() {
        let cfg = json!({
            "users": [
                { "username": "Alice", "password_hash": argon2_alice_hash() },
                { "username": "alice", "password_hash": argon2_alice_hash() }
            ]
        })
        .to_string();
        let err = BasicConfig::parse(&cfg).unwrap_err();
        matches!(err, ConfigError::DuplicateUsername { .. });
    }

    #[test]
    fn allows_distinct_case_when_sensitive() {
        let cfg = json!({
            "users": [
                { "username": "Alice", "password_hash": argon2_alice_hash() },
                { "username": "alice", "password_hash": argon2_alice_hash() }
            ],
            "username_case": "sensitive"
        })
        .to_string();
        BasicConfig::parse(&cfg).unwrap();
    }

    #[test]
    fn rejects_invalid_trust_level() {
        let cfg = json!({
            "users": [{ "username": "alice", "password_hash": argon2_alice_hash() }],
            "resolution": { "trust_level": "alien" }
        })
        .to_string();
        let err = BasicConfig::parse(&cfg).unwrap_err();
        match err {
            ConfigError::InvalidTrustLevel { value } => assert_eq!(value, "alien"),
            other => panic!("unexpected: {other:?}"),
        }
    }
}
