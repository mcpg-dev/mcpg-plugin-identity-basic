//! `dev.mcpg.identity.basic` — HTTP Basic auth identity plugin.
//!
//! This crate is the implementation; the operator-
//! facing summary lives in `README.md`.
//!
//! # Trust model
//!
//! `resolution.trust_level: "verified"` (default) gives a
//! successfully authenticated caller the same trust bucket as an
//! OIDC-verified JWT — argon2 / bcrypt verify cryptographically
//! establishes the caller controls the password. Operators on
//! weaker contracts downgrade to `"header_asserted"`.

pub mod config;

use std::collections::BTreeMap;
use std::sync::Arc;

use argon2::Argon2;
use async_trait::async_trait;
use base64::Engine;
use base64::engine::general_purpose::STANDARD as BASE64_STANDARD;
use mcpg_plugin_protocol::{
    IdentityProviderPlugin, IdentityResolution, PluginClass, PluginIdentity, PluginManifest,
};
use mcpg_plugin_sdk::declare_plugin;
use mcpg_plugin_sdk::ffi::SyncIdentityResolver;
use password_hash::PasswordHash;
use serde_json::Value;
use time::OffsetDateTime;
use tracing::{debug, info_span, warn};

pub use config::{BasicConfig, ConfigError, ResolutionConfig, UserEntry, UsernameCase};

const PLUGIN_ID: &str = "dev.mcpg.identity.basic";

fn record_resolve_outcome(result: &IdentityResolution, elapsed: std::time::Duration) {
    let outcome = match result {
        IdentityResolution::Resolved { .. } => "resolved",
        IdentityResolution::None => "none",
        IdentityResolution::Invalid { .. } => "invalid",
    };
    metrics::counter!(
        "mcpg_identity_basic_resolutions_total",
        "outcome" => outcome,
    )
    .increment(1);
    metrics::histogram!("mcpg_identity_basic_resolve_ms").record(elapsed.as_millis() as f64);
    match result {
        IdentityResolution::Resolved { identity } => debug!(
            subject = identity.subject_id.as_deref().unwrap_or(""),
            elapsed_ms = %elapsed.as_millis(),
            "basic identity resolved"
        ),
        IdentityResolution::None => debug!(
            elapsed_ms = %elapsed.as_millis(),
            "basic identity: no credential — fall through"
        ),
        IdentityResolution::Invalid { reason } => warn!(
            reason = %reason,
            elapsed_ms = %elapsed.as_millis(),
            "basic identity: invalid credential"
        ),
    }
}

/// Compiled user entry — owns the parsed metadata and a pre-
/// classified hash kind so per-request verify only branches once.
struct CompiledUser {
    canonical_username: String,
    raw_username: String,
    password_hash: String,
    hash_kind: HashKind,
    enabled: bool,
    expires_at: Option<OffsetDateTime>,
    roles: Vec<String>,
    groups: Vec<String>,
    scopes: Vec<String>,
    attributes: BTreeMap<String, String>,
}

#[derive(Debug, Clone, Copy)]
enum HashKind {
    Argon2,
    Bcrypt,
}

impl HashKind {
    fn detect(hash: &str) -> Option<Self> {
        if hash.starts_with("$argon2id$")
            || hash.starts_with("$argon2i$")
            || hash.starts_with("$argon2d$")
        {
            Some(Self::Argon2)
        } else if hash.starts_with("$2a$") || hash.starts_with("$2b$") || hash.starts_with("$2y$") {
            Some(Self::Bcrypt)
        } else {
            None
        }
    }
}

pub struct BasicIdentityPlugin {
    inner: Arc<Inner>,
}

struct Inner {
    manifest: PluginManifest,
    users: Vec<CompiledUser>,
    username_case: UsernameCase,
    resolution: ResolutionConfig,
}

impl BasicIdentityPlugin {
    /// Factory used by `declare_plugin!`. Panics on bad config —
    /// same security stance as the OIDC + api-key siblings.
    pub fn from_config_json(config_json: &str) -> Self {
        let cfg = BasicConfig::parse(config_json).unwrap_or_else(|err| {
            tracing::error!(
                plugin_id = PLUGIN_ID,
                error = %err,
                "basic identity: config parse failed; refusing to register"
            );
            panic!(
                "basic identity config parse failed: {err}. A misconfigured \
                 identity resolver is a security hole; refusing to load."
            )
        });
        Self::from_validated_config(cfg)
    }

    fn from_validated_config(cfg: BasicConfig) -> Self {
        let username_case = cfg.username_case;
        let users: Vec<CompiledUser> = cfg
            .users
            .into_iter()
            .map(|u| {
                let canonical = match username_case {
                    UsernameCase::Insensitive => u.username.to_lowercase(),
                    UsernameCase::Sensitive => u.username.clone(),
                };
                let hash_kind = HashKind::detect(&u.password_hash)
                    .expect("validator already accepted the hash prefix");
                CompiledUser {
                    canonical_username: canonical,
                    raw_username: u.username,
                    password_hash: u.password_hash,
                    hash_kind,
                    enabled: u.enabled,
                    expires_at: u.expires_at,
                    roles: u.roles,
                    groups: u.groups,
                    scopes: u.scopes,
                    attributes: u.attributes,
                }
            })
            .collect();
        tracing::info!(
            plugin_id = PLUGIN_ID,
            users_loaded = users.len(),
            "basic identity: registry compiled"
        );
        Self {
            inner: Arc::new(Inner {
                manifest: PluginManifest {
                    id: PLUGIN_ID.into(),
                    version: env!("CARGO_PKG_VERSION").into(),
                    name: "HTTP Basic Identity Resolver".into(),
                    plugin_class: PluginClass::IdentityProvider,
                    protocol_version: "1.0".into(),
                    license: None,
                    required_capabilities: Vec::new(),
                    tags: Vec::new(),
                    provides: Vec::new(),
                    provides_schemes: Vec::new(),
                    module_path_prefix: ::std::module_path!()
                        .split("::")
                        .next()
                        .unwrap_or("")
                        .to_owned(),
                    backend_profile: None,
                },
                users,
                username_case,
                resolution: cfg.resolution,
            }),
        }
    }
}

fn lookup_header<'a>(headers: &'a [(String, String)], target: &str) -> Option<&'a str> {
    headers.iter().find_map(|(name, value)| {
        if name.eq_ignore_ascii_case(target) {
            Some(value.as_str())
        } else {
            None
        }
    })
}

fn strip_basic_prefix(value: &str) -> Option<&str> {
    // Case-insensitive scheme match per RFC 7235.
    let mut chars = value.chars();
    let scheme: String = chars.by_ref().take(5).collect();
    if scheme.len() != 5 || !scheme.eq_ignore_ascii_case("Basic") {
        return None;
    }
    let rest = &value[5..];
    rest.strip_prefix(' ')
}

fn verify_password(hash: &str, kind: HashKind, password: &str) -> bool {
    match kind {
        HashKind::Argon2 => {
            let parsed = match PasswordHash::new(hash) {
                Ok(p) => p,
                Err(_) => return false,
            };
            // password_hash::PasswordVerifier expects password as bytes.
            use password_hash::PasswordVerifier;
            Argon2::default()
                .verify_password(password.as_bytes(), &parsed)
                .is_ok()
        }
        HashKind::Bcrypt => bcrypt::verify(password, hash).unwrap_or(false),
    }
}

fn resolve_with_now(
    inner: &Inner,
    headers: &[(String, String)],
    now: OffsetDateTime,
) -> IdentityResolution {
    let Some(auth_value) = lookup_header(headers, "authorization") else {
        return IdentityResolution::None;
    };
    let Some(credential) = strip_basic_prefix(auth_value) else {
        return IdentityResolution::None;
    };
    if credential.is_empty() {
        return IdentityResolution::None;
    }
    let decoded = match BASE64_STANDARD.decode(credential.as_bytes()) {
        Ok(bytes) => bytes,
        Err(_) => {
            return IdentityResolution::Invalid {
                reason: "malformed Basic credential (base64)".into(),
            };
        }
    };
    let decoded_str = match std::str::from_utf8(&decoded) {
        Ok(s) => s,
        Err(_) => {
            return IdentityResolution::Invalid {
                reason: "malformed Basic credential (non-utf8)".into(),
            };
        }
    };
    let Some(colon_idx) = decoded_str.find(':') else {
        return IdentityResolution::Invalid {
            reason: "malformed Basic credential (no colon)".into(),
        };
    };
    let username = &decoded_str[..colon_idx];
    let password = &decoded_str[colon_idx + 1..];
    if username.is_empty() {
        return IdentityResolution::Invalid {
            reason: "empty username".into(),
        };
    }
    if password.is_empty() {
        return IdentityResolution::Invalid {
            reason: "empty password".into(),
        };
    }
    let lookup_key = match inner.username_case {
        UsernameCase::Insensitive => username.to_lowercase(),
        UsernameCase::Sensitive => username.to_owned(),
    };
    let Some(user) = inner
        .users
        .iter()
        .find(|u| u.canonical_username == lookup_key)
    else {
        return IdentityResolution::Invalid {
            reason: "unknown user".into(),
        };
    };

    if !verify_password(&user.password_hash, user.hash_kind, password) {
        return IdentityResolution::Invalid {
            reason: "password mismatch".into(),
        };
    }
    if !user.enabled {
        return IdentityResolution::Invalid {
            reason: "user disabled".into(),
        };
    }
    if let Some(expires_at) = user.expires_at
        && expires_at <= now
    {
        return IdentityResolution::Invalid {
            reason: "user expired".into(),
        };
    }

    let subject_id = match inner.username_case {
        UsernameCase::Insensitive => user.canonical_username.clone(),
        UsernameCase::Sensitive => user.raw_username.clone(),
    };

    IdentityResolution::Resolved {
        identity: PluginIdentity {
            kind: inner.resolution.trust_level.clone(),
            trust_level: inner.resolution.trust_level.clone(),
            subject_id: Some(subject_id),
            auth_provider: Some(inner.resolution.auth_provider_label.clone()),
            issuer: None,
            roles: user.roles.clone(),
            groups: user.groups.clone(),
            scopes: user.scopes.clone(),
            attributes: user.attributes.clone(),
        },
    }
}

#[async_trait]
impl IdentityProviderPlugin for BasicIdentityPlugin {
    fn manifest(&self) -> &PluginManifest {
        &self.inner.manifest
    }

    async fn resolve_identity(
        &self,
        headers: &[(String, String)],
        _metadata: &mcpg_plugin_protocol::types::RequestMetadata,
        _config: &Value,
    ) -> IdentityResolution {
        // Plugin-scoped span so traces from basic identity attribute
        // back to dev.mcpg.identity.basic for per-plugin override.
        let _span = info_span!("identity_basic_resolve", plugin_id = PLUGIN_ID).entered();
        let started = std::time::Instant::now();
        let result = resolve_with_now(&self.inner, headers, OffsetDateTime::now_utc());
        record_resolve_outcome(&result, started.elapsed());
        result
    }
}

impl SyncIdentityResolver for BasicIdentityPlugin {
    fn manifest(&self) -> &PluginManifest {
        &self.inner.manifest
    }

    fn resolve_identity(
        &self,
        headers: &[(String, String)],
        _metadata: &mcpg_plugin_protocol::types::RequestMetadata,
        _config: &Value,
    ) -> IdentityResolution {
        let _span = info_span!("identity_basic_resolve", plugin_id = PLUGIN_ID).entered();
        let started = std::time::Instant::now();
        let result = resolve_with_now(&self.inner, headers, OffsetDateTime::now_utc());
        record_resolve_outcome(&result, started.elapsed());
        result
    }
}

declare_plugin! {

    plugin_id: "dev.mcpg.identity.basic",
    plugin_version: env!("CARGO_PKG_VERSION"),
    descriptor_yaml: include_str!("../plugin.yaml"),
    capabilities: &[],
    entities: [
        identity as id {
            inner_name: "",
            plugin_type: BasicIdentityPlugin,
            // basic identity has no cluster-coordinated state — operator
            // config is the sole source of truth, evaluated locally.
            factory: |cfg: &str, _host: ::mcpg_plugin_sdk::HostHandle| -> BasicIdentityPlugin {
                BasicIdentityPlugin::from_config_json(cfg)
            },
        }
    ],
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use time::macros::datetime;

    /// argon2id hash of password "hunter2" with a fixed salt for
    /// test determinism. NOT for production use.
    fn alice_hash_argon2() -> String {
        use argon2::password_hash::SaltString;
        use password_hash::PasswordHasher;
        let salt = SaltString::from_b64("dGVzdHNhbHQwMDAwMDAw").unwrap();
        let argon = Argon2::default();
        argon.hash_password(b"hunter2", &salt).unwrap().to_string()
    }

    fn alice_hash_bcrypt() -> String {
        bcrypt::hash("hunter2", 4).unwrap()
    }

    fn build(cfg: serde_json::Value) -> BasicIdentityPlugin {
        BasicIdentityPlugin::from_config_json(&cfg.to_string())
    }

    fn auth_header(creds: &str) -> Vec<(String, String)> {
        let encoded = BASE64_STANDARD.encode(creds.as_bytes());
        vec![("Authorization".into(), format!("Basic {encoded}"))]
    }

    fn now() -> OffsetDateTime {
        datetime!(2026-04-26 00:00 UTC)
    }

    #[test]
    fn resolves_argon2_happy_path() {
        let plugin = build(json!({
            "users": [{
                "username": "alice",
                "password_hash": alice_hash_argon2(),
                "roles": ["operator"],
            }]
        }));
        let r = resolve_with_now(&plugin.inner, &auth_header("alice:hunter2"), now());
        match r {
            IdentityResolution::Resolved { identity } => {
                assert_eq!(identity.subject_id.as_deref(), Some("alice"));
                assert_eq!(identity.trust_level, "verified");
                assert_eq!(identity.roles, vec!["operator".to_owned()]);
            }
            other => panic!("unexpected: {other:?}"),
        }
    }

    #[test]
    fn resolves_bcrypt_happy_path() {
        let plugin = build(json!({
            "users": [{
                "username": "alice",
                "password_hash": alice_hash_bcrypt(),
            }]
        }));
        let r = resolve_with_now(&plugin.inner, &auth_header("alice:hunter2"), now());
        assert!(matches!(r, IdentityResolution::Resolved { .. }));
    }

    #[test]
    fn no_authorization_header_returns_none() {
        let plugin = build(json!({
            "users": [{ "username": "alice", "password_hash": alice_hash_argon2() }]
        }));
        let r = resolve_with_now(&plugin.inner, &[], now());
        assert!(matches!(r, IdentityResolution::None));
    }

    #[test]
    fn bearer_scheme_returns_none() {
        let plugin = build(json!({
            "users": [{ "username": "alice", "password_hash": alice_hash_argon2() }]
        }));
        let r = resolve_with_now(
            &plugin.inner,
            &[("Authorization".into(), "Bearer xyz".into())],
            now(),
        );
        assert!(matches!(r, IdentityResolution::None));
    }

    #[test]
    fn malformed_base64_returns_invalid() {
        let plugin = build(json!({
            "users": [{ "username": "alice", "password_hash": alice_hash_argon2() }]
        }));
        let r = resolve_with_now(
            &plugin.inner,
            &[("Authorization".into(), "Basic !!not-base64!!".into())],
            now(),
        );
        match r {
            IdentityResolution::Invalid { reason } => assert!(reason.contains("base64")),
            other => panic!("unexpected: {other:?}"),
        }
    }

    #[test]
    fn no_colon_returns_invalid() {
        let plugin = build(json!({
            "users": [{ "username": "alice", "password_hash": alice_hash_argon2() }]
        }));
        let r = resolve_with_now(&plugin.inner, &auth_header("alicepasswordnocolon"), now());
        match r {
            IdentityResolution::Invalid { reason } => assert!(reason.contains("no colon")),
            other => panic!("unexpected: {other:?}"),
        }
    }

    #[test]
    fn unknown_user_returns_invalid() {
        let plugin = build(json!({
            "users": [{ "username": "alice", "password_hash": alice_hash_argon2() }]
        }));
        let r = resolve_with_now(&plugin.inner, &auth_header("bob:hunter2"), now());
        match r {
            IdentityResolution::Invalid { reason } => assert_eq!(reason, "unknown user"),
            other => panic!("unexpected: {other:?}"),
        }
    }

    #[test]
    fn wrong_password_returns_invalid() {
        let plugin = build(json!({
            "users": [{ "username": "alice", "password_hash": alice_hash_argon2() }]
        }));
        let r = resolve_with_now(&plugin.inner, &auth_header("alice:wrongpass"), now());
        match r {
            IdentityResolution::Invalid { reason } => assert_eq!(reason, "password mismatch"),
            other => panic!("unexpected: {other:?}"),
        }
    }

    #[test]
    fn case_insensitive_username_matches() {
        let plugin = build(json!({
            "users": [{ "username": "Alice", "password_hash": alice_hash_argon2() }]
        }));
        let r = resolve_with_now(&plugin.inner, &auth_header("ALICE:hunter2"), now());
        assert!(matches!(r, IdentityResolution::Resolved { .. }));
    }

    #[test]
    fn case_sensitive_username_rejects_wrong_case() {
        let plugin = build(json!({
            "users": [{ "username": "Alice", "password_hash": alice_hash_argon2() }],
            "username_case": "sensitive"
        }));
        let r = resolve_with_now(&plugin.inner, &auth_header("alice:hunter2"), now());
        match r {
            IdentityResolution::Invalid { reason } => assert_eq!(reason, "unknown user"),
            other => panic!("unexpected: {other:?}"),
        }
    }

    #[test]
    fn disabled_user_rejected() {
        let plugin = build(json!({
            "users": [{
                "username": "alice",
                "password_hash": alice_hash_argon2(),
                "enabled": false,
            }]
        }));
        let r = resolve_with_now(&plugin.inner, &auth_header("alice:hunter2"), now());
        match r {
            IdentityResolution::Invalid { reason } => assert_eq!(reason, "user disabled"),
            other => panic!("unexpected: {other:?}"),
        }
    }

    #[test]
    fn expired_user_rejected() {
        let plugin = build(json!({
            "users": [{
                "username": "alice",
                "password_hash": alice_hash_argon2(),
                "expires_at": "2026-01-01T00:00:00Z",
            }]
        }));
        let r = resolve_with_now(&plugin.inner, &auth_header("alice:hunter2"), now());
        match r {
            IdentityResolution::Invalid { reason } => assert_eq!(reason, "user expired"),
            other => panic!("unexpected: {other:?}"),
        }
    }
}
