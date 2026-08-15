# HTTP Basic Identity Resolver — `dev.mcpg.identity.basic`

> class `identity_provider` · `native` · package `mcpg-plugin-identity-basic` · artifact `libmcpg_plugin_identity_basic.so` · Apache-2.0

Resolves the caller's identity from an `Authorization: Basic` header against a
user registry you declare in config. Each entry maps a username to an argon2 or
bcrypt password hash, plus the roles, groups, scopes, and attributes the gateway
should stamp on the resolved identity — so downstream authorization rules can key
off a real principal rather than an anonymous request. Plaintext passwords never
appear in the config: you store hashes produced out of band, and the plugin
verifies the supplied password against them. It performs no outbound network
calls at all. Reach for it when you need authenticated callers on a small or
self-contained deployment and running an external identity provider is not worth
it.

## What it does
- Parses the `Authorization: Basic` header (scheme match is case-insensitive per
  RFC 7235), base64-decodes it, and splits username from password at the first
  colon.
- Looks the username up in the registry, folding case unless `username_case` is
  `sensitive`, then verifies the password against the stored hash.
- Accepts argon2 (`$argon2id$`, `$argon2i$`, `$argon2d$`) and bcrypt (`$2a$`,
  `$2b$`, `$2y$`) PHC strings; anything else is rejected at config load, so an
  MD5 htpasswd file cannot be loaded by accident.
- Rejects duplicate usernames at config load, evaluated under the configured
  case-folding so `Alice` and `alice` cannot silently shadow each other.
- Honours per-user `enabled` and `expires_at`, so an account can be turned off or
  time-boxed without deleting its entry.
- Declares no required capabilities: it never opens a socket or reads a file.

## Configuration
Loaded from the flat top-level `plugins:` list; every `identity_provider` entry
joins the gateway's identity chain in declaration order.

```yaml
plugins:
  - id: dev.mcpg.identity.basic
    class: identity_provider
    source: { path: ./plugins/libmcpg_plugin_identity_basic.so }
    config:
      username_case: insensitive
      users:
        - username: alice
          password_hash: ${env.ALICE_PASSWORD_HASH}   # argon2 or bcrypt PHC string
          roles: ["operator"]
          groups: ["sre"]
          scopes: ["admin.read"]
          attributes: { tenant: acme }
          enabled: true
          expires_at: "2027-01-01T00:00:00Z"
      resolution:
        trust_level: verified
        auth_provider_label: basic
```

| Field | Type | Default | Description |
|---|---|---|---|
| `users` | user[] | — (required) | The user registry; must be non-empty. |
| `username_case` | `insensitive` \| `sensitive` | `insensitive` | Whether lookups and duplicate detection fold case. |
| `resolution.trust_level` | `verified` \| `header_asserted` | `verified` | Trust level stamped on a resolved identity. |
| `resolution.auth_provider_label` | string | `basic` | `auth_provider` value on the resolved identity; change it to distinguish several Basic registries. |

Each entry under `users`:

| Field | Type | Default | Description |
|---|---|---|---|
| `username` | string | — (required) | Login name; must be non-empty. |
| `password_hash` | string | — (required) | argon2 or bcrypt PHC string, generated out of band. |
| `enabled` | bool | `true` | `false` soft-disables the account. |
| `expires_at` | string? | `null` | RFC 3339 timestamp; a past value rejects the credential. |
| `roles` | string[] | `[]` | Roles stamped on the resolved identity. |
| `groups` | string[] | `[]` | Groups stamped on the resolved identity. |
| `scopes` | string[] | `[]` | Scopes stamped on the resolved identity. |
| `attributes` | map<string,string> | `{}` | Attributes stamped on the resolved identity. |

Unknown fields are rejected. A configuration that fails validation aborts the
plugin's registration rather than loading an identity resolver with holes in it.

Generate hashes with a standard tool — `argon2 <salt> -e` or `htpasswd -B -n
<user>` — and reference them through the gateway's secret resolver (`${env.VAR}`,
`vault://…`, `file:///…`) so the hash itself stays out of the config artifact.

## Security
The resolver returns one of three outcomes, and the difference matters for how
the identity chain proceeds:

- **Resolved** — password verified. The chain stops and the identity is used.
- **None** — no `Authorization: Basic` header, or an empty credential. The chain
  falls through to the next identity provider.
- **Invalid** — a Basic credential was presented and rejected: malformed base64,
  no colon, empty username or password, unknown user, password mismatch,
  disabled account, or expired account. **The chain stops here** and the request
  is refused. A credential one provider has explicitly rejected is never
  re-adjudicated by a laxer one further down the chain.

`resolution.trust_level` defaults to `verified` because a successful hash
verification is cryptographic proof that the caller holds the password — the same
standing as a verified JWT. Lower it to `header_asserted` only if your deployment
gives Basic auth weaker guarantees than that.

Order matters when several identity providers are configured: put the provider
that should adjudicate a given credential shape ahead of the ones that should not
see it.

## Observability
- `mcpg_identity_basic_resolutions_total{outcome}` — counted per resolution, with
  `outcome` one of `resolved`, `none`, or `invalid`.
- `mcpg_identity_basic_resolve_ms` — resolution latency, dominated by the
  password-hash verification.

## Build
`cdylib-export` is enabled by default, so the plain build already produces the
loadable artifact. Disable the default features when linking this crate as an
rlib path dependency alongside other plugins, so the build does not emit two
`mcpg_plugin_register` exports.

```bash
cargo build -p mcpg-plugin-identity-basic --features cdylib-export --release   # → target/release/libmcpg_plugin_identity_basic.so
```

## Sign & load (production)
Sign the artifact, pin/verify via the entry's `signature:` block, and honour
revocations. See <https://mcpg.dev/docs/security/plugin-security>.

## See also
- Identity and authorization in the gateway: <https://mcpg.dev/docs/security/identity-and-authorization>
- Plugin classes and the ABI: <https://mcpg.dev/docs/plugins/plugins-and-protocol>
- Sibling resolvers: `libs/plugins/identity/oidc`, `libs/plugins/identity/api-key`,
  `libs/plugins/identity/mtls`
