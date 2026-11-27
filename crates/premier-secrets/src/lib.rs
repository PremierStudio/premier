//! `premier-secrets` — `.env.schema` typed contract, hierarchical secret resolution,
//! sovereign `age`/AEAD vault, streaming secret redactor, and local secret runner.

pub mod backend;
pub mod external;
pub mod key_transparency;
pub mod kms;
pub mod oidc;
pub mod placeholder;
pub mod redactor;
pub mod rotation;
pub mod runner;
pub mod schema;

use thiserror::Error;

pub use backend::{
    AgeSovereignBackend, KeychainBackend, MemoryBackend, ResolveContext, ResolvedEnv,
    SecretBackend, SecretCoord, SecretLayer, SecretResolver, ValueProvenance,
};
pub use backend::{create_state_dir, write_private};
pub use external::{
    CompositeSecretBackend, OnePasswordConnectConfig, OnePasswordConnectConnector, VaultKvConfig,
    VaultKvConnector,
};
pub use key_transparency::{
    KeyTransparencyEntry, KeyTransparencyLog, KtVerificationReport, recipients_fingerprint,
};
pub use kms::{
    AgeKeyWrapper, ENVELOPE_VAULT_VERSION, EnvKekWrapper, EnvelopeVaultBackend, EnvelopeVaultFile,
    KeyWrapper, KmsStatus, PREMIER_KMS_KEY_ENV, PREMIER_KMS_URI_ENV, VaultTransitConfig,
    VaultTransitWrapper, migrate_from_age_vault, parse_pem_certificates,
};
pub use oidc::{
    ActorClaim, DEFAULT_TOKEN_TTL_SECS, IssuedWorkloadToken, MAX_TOKEN_TTL_SECS, OidcTokenIssuer,
    WorkloadClaims, WorkloadTokenRequest,
};
pub use placeholder::{BoundCapability, PLACEHOLDER_PREFIX, PlaceholderRegistry};
pub use redactor::{SecretRedactor, StreamingRedactor, percent_encode_component};
pub use rotation::{
    RotationDispatcher, RotationPhase, RotationReceipt, RotationStatus, sign_webhook_payload,
    verify_webhook_signature,
};
pub use runner::{
    RunOutput, check_fifo_mount_supported, mount_fifo, render_dotenv, run_with_secrets,
};
pub use schema::{
    ApprovalMode, AutoAllowRule, EgressSpec, EnvSchema, InjectSpec, RotationSpec, RotatorSpec,
    Sensitivity, ValidationIssue, ValidationReport, VarSpec, VarType, path_matches_prefix,
};

#[derive(Debug, Error)]
pub enum SecretError {
    #[error("failed to parse .env.schema: {0}")]
    TomlParse(#[from] toml::de::Error),

    #[error("invalid .env.schema variable '{var_name}': {reason}")]
    InvalidSchema { var_name: String, reason: String },

    #[error("secret backend error: {0}")]
    Backend(String),

    #[error("cryptographic error: {0}")]
    Crypto(String),

    #[error("I/O error: {0}")]
    Io(String),

    #[error(
        "POSIX FIFO virtual .env mount is available on Linux/macOS/WSL2; on native Windows use `premier run -- <cmd>` (or enable ProjFS in M3)"
    )]
    FifoUnsupportedOnPlatform,
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use std::collections::BTreeMap;

    use premier_core::{Capability, DelegatedIdentity, Environment, Principal};
    use premier_policy::{CompiledPolicy, parse_policy_toml};
    use zeroize::Zeroizing;

    use super::*;

    const SAMPLE_SCHEMA: &str = r#"
version = 1
repo_id = "acme/platform"

[vars.APP_PORT]
type = "int"
sensitivity = "public"
default = "8080"
required_in = ["dev", "prod"]

[vars.STRIPE_API_KEY]
type = "secret"
sensitivity = "restricted"
required_in = ["staging", "prod"]
zone = "billing"

[vars.STRIPE_API_KEY.egress]
hosts = ["api.stripe.com"]
methods = ["GET", "POST"]
path_prefixes = ["/v1/"]
inject = { kind = "bearer_header", header = "Authorization" }
rate_limit_per_min = 30
approval = "auto"
"#;

    #[test]
    fn schema_rejects_wildcard_hosts_and_hardcoded_secret_defaults() {
        let bad_wildcard = r#"
version = 1
[vars.TOKEN]
type = "secret"
sensitivity = "restricted"
[vars.TOKEN.egress]
hosts = ["*.stripe.com"]
"#;
        assert!(EnvSchema::parse_toml(bad_wildcard).is_err());

        let bad_default = r#"
version = 1
[vars.TOKEN]
type = "secret"
sensitivity = "secret"
default = "sk_live_oops"
"#;
        assert!(EnvSchema::parse_toml(bad_default).is_err());
    }

    #[test]
    fn schema_validates_types_and_required_vars() {
        let schema = EnvSchema::parse_toml(SAMPLE_SCHEMA).unwrap();
        let mut vals = BTreeMap::new();
        vals.insert("APP_PORT".to_owned(), "not-a-number".to_owned());

        let report = schema.validate_values(&Environment::Prod, &vals);
        assert!(!report.is_ok());
        assert_eq!(report.issues.len(), 2); // bad APP_PORT int + missing STRIPE_API_KEY
    }

    #[test]
    fn sovereign_age_aead_roundtrip_and_key_swap_tamper_detection() {
        let dir = tempfile::tempdir().unwrap();
        let vault_path = dir.path().join("vault.premier.toml");
        let identity = age::x25519::Identity::generate();

        let backend = AgeSovereignBackend::new(
            &vault_path,
            "acme/platform",
            "secrets/prod.toml",
            identity,
            vec![],
        );
        let coord = SecretCoord {
            repo_id: "acme/platform".to_owned(),
            layer: SecretLayer::Env,
            scope: "prod".to_owned(),
            var_name: "STRIPE_API_KEY".to_owned(),
        };

        backend.set(&coord, "sk_live_super_secret_999").unwrap();
        let loaded = backend.get(&coord).unwrap().unwrap();
        assert_eq!(loaded.as_str(), "sk_live_super_secret_999");

        // Tamper test: transplant ciphertext from STRIPE_API_KEY under a different key name -> AAD fails!
        let mut raw_text = std::fs::read_to_string(&vault_path).unwrap();
        raw_text = raw_text.replace("STRIPE_API_KEY", "OTHER_KEY");
        std::fs::write(&vault_path, raw_text).unwrap();

        let tampered_coord = SecretCoord {
            var_name: "OTHER_KEY".to_owned(),
            ..coord
        };
        let err = backend.get(&tampered_coord).unwrap_err();
        assert!(matches!(err, SecretError::Crypto(_)));
    }

    #[test]
    fn streaming_redactor_scrubs_raw_base64_and_cross_chunk_secrets() {
        let secret = "sk_live_AbCdEf123456!";
        let redactor = SecretRedactor::build([("STRIPE_API_KEY", secret)]);

        // Direct raw + base64 test
        use base64::Engine;
        let b64 = base64::engine::general_purpose::STANDARD.encode(secret.as_bytes());
        let input = format!("raw={secret} b64={b64}");
        let (clean, count) = redactor.redact_str(&input);
        assert!(!clean.contains(secret));
        assert!(!clean.contains(&b64));
        assert!(clean.contains("[REDACTED:STRIPE_API_KEY]"));
        assert!(count >= secret.len() + b64.len());

        // Split secret across two 5-byte chunks!
        let mut stream = redactor.streaming();
        let full = format!("prefix-{secret}-suffix");
        let mut emitted = Vec::new();
        for chunk in full.as_bytes().chunks(5) {
            emitted.extend(stream.push(chunk));
        }
        emitted.extend(stream.finish());
        let emitted_str = String::from_utf8(emitted).unwrap();
        assert_eq!(emitted_str, "prefix-[REDACTED:STRIPE_API_KEY]-suffix");
    }

    fn egress_with_prefixes(prefixes: &[&str]) -> EgressSpec {
        EgressSpec {
            hosts: vec!["api.stripe.com".to_owned()],
            methods: vec![],
            path_prefixes: prefixes.iter().map(|p| (*p).to_owned()).collect(),
            upstream_base_url: None,
            inject: InjectSpec::PlaceholderReplace,
            rate_limit_per_min: None,
            approval: ApprovalMode::Auto,
            jit_ttl_secs: 60,
            auto_allow: vec![],
        }
    }

    fn auto_allow_schema(rule: &str) -> Result<EnvSchema, SecretError> {
        EnvSchema::parse_toml(&format!(
            "version = 1\n[vars.TOKEN]\ntype = \"secret\"\n[vars.TOKEN.egress]\n\
             hosts = [\"api.stripe.com\"]\nmethods = [\"GET\", \"POST\"]\n\
             path_prefixes = [\"/v1/\"]\napproval = \"jit\"\n\
             [[vars.TOKEN.egress.auto_allow]]\n{rule}\n"
        ))
    }

    #[test]
    fn auto_allow_rules_may_only_narrow_the_egress_envelope() {
        let ok = auto_allow_schema(
            "agent_profile = \"claude\"\nhost = \"API.stripe.com\"\n\
             methods = [\"get\"]\npath_prefixes = [\"/v1/charges\"]",
        )
        .unwrap();
        assert_eq!(
            ok.vars["TOKEN"].egress.as_ref().unwrap().auto_allow.len(),
            1
        );
        // A profile-less rule is valid (it only matches agent-less requests).
        assert!(
            auto_allow_schema(
                "host = \"api.stripe.com\"\nmethods = [\"GET\"]\npath_prefixes = [\"/v1/\"]"
            )
            .is_ok()
        );
        let tail = "methods = [\"GET\"]\npath_prefixes = [\"/v1/\"]";
        for bad in [
            // wildcard / empty profile
            format!("agent_profile = \"*\"\nhost = \"api.stripe.com\"\n{tail}"),
            format!("agent_profile = \" \"\nhost = \"api.stripe.com\"\n{tail}"),
            // host widening / shape
            format!("host = \"*.stripe.com\"\n{tail}"),
            format!("host = \"*\"\n{tail}"),
            format!("host = \"\"\n{tail}"),
            format!("host = \"https://api.stripe.com\"\n{tail}"),
            format!("host = \"api.stripe.com/v1\"\n{tail}"),
            format!("host = \"evil.example\"\n{tail}"),
            // method widening
            "host = \"api.stripe.com\"\npath_prefixes = [\"/v1/\"]".to_owned(),
            "host = \"api.stripe.com\"\nmethods = [\"\"]\npath_prefixes = [\"/v1/\"]".to_owned(),
            "host = \"api.stripe.com\"\nmethods = [\"*\"]\npath_prefixes = [\"/v1/\"]".to_owned(),
            "host = \"api.stripe.com\"\nmethods = [\"DELETE\"]\npath_prefixes = [\"/v1/\"]"
                .to_owned(),
            // path widening
            "host = \"api.stripe.com\"\nmethods = [\"GET\"]".to_owned(),
            "host = \"api.stripe.com\"\nmethods = [\"GET\"]\npath_prefixes = [\"/\"]".to_owned(),
            "host = \"api.stripe.com\"\nmethods = [\"GET\"]\npath_prefixes = [\"/v2/\"]".to_owned(),
            "host = \"api.stripe.com\"\nmethods = [\"GET\"]\npath_prefixes = [\"/v1/../v2\"]"
                .to_owned(),
            "host = \"api.stripe.com\"\nmethods = [\"GET\"]\npath_prefixes = [\"v1/\"]".to_owned(),
        ] {
            assert!(auto_allow_schema(&bad).is_err(), "{bad} must be rejected");
        }
    }

    #[test]
    fn matches_auto_allow_is_exact_on_profile_host_method_and_path() {
        let mut spec = egress_with_prefixes(&["/v1/"]);
        spec.auto_allow = vec![AutoAllowRule {
            agent_profile: Some("claude".to_owned()),
            host: "api.stripe.com".to_owned(),
            methods: vec!["GET".to_owned()],
            path_prefixes: vec!["/v1/charges".to_owned()],
        }];
        let m = |p: Option<&str>, h: &str, verb: &str, path: &str| {
            spec.matches_auto_allow(p, h, verb, path)
        };
        assert!(m(Some("claude"), "api.stripe.com", "GET", "/v1/charges"));
        assert!(m(
            Some("claude"),
            "API.STRIPE.COM",
            "get",
            "/v1/charges/ch_1"
        ));
        assert!(!m(Some("claude"), "api.stripe.com", "POST", "/v1/charges"));
        assert!(!m(Some("codex"), "api.stripe.com", "GET", "/v1/charges"));
        assert!(!m(None, "api.stripe.com", "GET", "/v1/charges"));
        assert!(!m(
            Some("claude"),
            "api.stripe.com",
            "GET",
            "/v1/chargesevil"
        ));
        assert!(!m(Some("claude"), "api.stripe.com", "GET", "/v1/customers"));
        assert!(!m(
            Some("claude"),
            "api.stripe.com",
            "GET",
            "/v1/charges/../refunds"
        ));
        assert!(!m(Some("claude"), "evil.example", "GET", "/v1/charges"));

        // A profile-less rule never matches a request made under an agent profile.
        spec.auto_allow[0].agent_profile = None;
        assert!(spec.matches_auto_allow(None, "api.stripe.com", "GET", "/v1/charges"));
        assert!(!spec.matches_auto_allow(Some("claude"), "api.stripe.com", "GET", "/v1/charges"));

        // A hand-built rule outside the envelope (bypassing validation) still never matches.
        let mut narrow = egress_with_prefixes(&["/v2/"]);
        narrow.auto_allow = spec.auto_allow.clone();
        assert!(!narrow.matches_auto_allow(None, "api.stripe.com", "GET", "/v1/charges"));
    }

    #[test]
    fn path_matches_prefix_respects_segment_boundaries() {
        assert!(path_matches_prefix("/v1/x", "/v1"));
        assert!(path_matches_prefix("/v1", "/v1"));
        assert!(path_matches_prefix("/anything", "/"));
        assert!(!path_matches_prefix("/v1evil", "/v1"));
        assert!(!path_matches_prefix("/v1/../v2", "/v1"));
        assert!(!path_matches_prefix("/a/../b", "/"));
    }

    #[test]
    fn register_defaults_to_secret_sensitivity() {
        let mut reg = PlaceholderRegistry::new();
        let a = reg.register(
            "A",
            Zeroizing::new("x".to_owned()),
            egress_with_prefixes(&[]),
            None,
        );
        let b = reg.register_with_sensitivity(
            "B",
            Zeroizing::new("y".to_owned()),
            egress_with_prefixes(&[]),
            None,
            Sensitivity::Restricted,
        );
        assert_eq!(
            reg.get_by_placeholder(&a).unwrap().sensitivity,
            Sensitivity::Secret
        );
        assert_eq!(
            reg.get_by_placeholder(&b).unwrap().sensitivity,
            Sensitivity::Restricted
        );
    }

    #[test]
    fn path_prefix_rejects_traversal_and_encoded_segments() {
        let slash = egress_with_prefixes(&["/v1/"]);
        for ok in ["/v1/charges", "/v1/a%20b/c", "/v1/"] {
            assert!(slash.matches_path(ok), "{ok} should be allowed");
        }
        for bad in [
            "/v1/../v2/admin",
            "/v1/..",
            "/v1/./x",
            "/v1/%2e%2e/v2/admin",
            "/v1/%2E%2e/v2/admin",
            "/v1/.%2e/v2/admin",
            "/v1/a%2fb",
            "/v1/a%2Fb",
            "/v1/a%5cb",
            "/v1/a\\..\\b",
            "/v1/%252e%252e/v2/admin",
            "/v1/%zz",
            "/v1/trailing%2",
            "/v2/admin",
            "v1/charges",
        ] {
            assert!(!slash.matches_path(bad), "{bad} must be refused");
        }

        // A prefix without a trailing slash only matches on a segment boundary.
        let bare = egress_with_prefixes(&["/v1"]);
        assert!(bare.matches_path("/v1"));
        assert!(bare.matches_path("/v1/charges"));
        assert!(!bare.matches_path("/v1evil"));
        assert!(!bare.matches_path("/v1/../v2"));

        // Dot-segments are refused even when no prefix restriction is declared.
        assert!(egress_with_prefixes(&[]).matches_path("/anything"));
        assert!(!egress_with_prefixes(&[]).matches_path("/a/../b"));
    }

    #[test]
    fn schema_rejects_upstream_override_to_foreign_host_or_cleartext() {
        let schema = |url: &str| {
            EnvSchema::parse_toml(&format!(
                "version = 1\n[vars.TOKEN]\ntype = \"secret\"\n[vars.TOKEN.egress]\n\
                 hosts = [\"api.stripe.com\"]\nupstream_base_url = \"{url}\"\n"
            ))
        };
        for bad in [
            "https://evil.example",
            "http://api.stripe.com",
            "http://127.0.0.1:8080",
            "https://api.stripe.com.evil.example",
            "https://user:pw@api.stripe.com",
            "https://api.stripe.com/other/base",
            "not a url",
        ] {
            assert!(schema(bad).is_err(), "{bad} must be rejected");
        }
        assert!(schema("https://api.stripe.com").is_ok());
        assert!(schema("https://API.stripe.com:8443/").is_ok());
        let pinned = schema("https://api.stripe.com:8443").unwrap();
        assert_eq!(
            pinned.vars["TOKEN"].egress.as_ref().unwrap().tls_port(),
            8443
        );
        assert_eq!(egress_with_prefixes(&[]).tls_port(), 443);
    }

    /// A secret exercising every escaping rule: JSON, percent, base64 `+`/`/` and padding.
    const NASTY_SECRET: &str = "sk_live/Ab+Cd \"Ef\"\\12<3>~456!?";

    /// Every encoded form of `secret` an upstream could reflect, as `(label, document, needle)`:
    /// `needle` is the part of `document` that is determined by the secret alone.
    fn encoded_forms(secret: &str) -> Vec<(String, String, String)> {
        use base64::Engine;
        use base64::engine::general_purpose::{
            STANDARD, STANDARD_NO_PAD, URL_SAFE, URL_SAFE_NO_PAD,
        };
        let b = secret.as_bytes();
        let pct = |all: bool, upper: bool| -> String {
            b.iter()
                .map(|&c| {
                    if !all && (c.is_ascii_alphanumeric() || b"-_.~".contains(&c)) {
                        (c as char).to_string()
                    } else if upper {
                        format!("%{c:02X}")
                    } else {
                        format!("%{c:02x}")
                    }
                })
                .collect()
        };
        let mut forms: Vec<(String, String)> = vec![
            ("raw".to_owned(), secret.to_owned()),
            ("pct-upper".to_owned(), pct(false, true)),
            ("pct-lower".to_owned(), pct(false, false)),
            ("pct-all-upper".to_owned(), pct(true, true)),
            ("pct-all-lower".to_owned(), pct(true, false)),
            ("form".to_owned(), pct(false, true).replace("%20", "+")),
            ("hex-lower".to_owned(), hex::encode(b)),
            ("hex-upper".to_owned(), hex::encode_upper(b)),
            ("json".to_owned(), {
                let j = serde_json::to_string(secret).unwrap();
                j[1..j.len() - 1].to_owned()
            }),
        ];
        let mut out: Vec<(String, String, String)> = Vec::new();
        for (name, engine) in [
            ("b64", &STANDARD),
            ("b64-nopad", &STANDARD_NO_PAD),
            ("b64url", &URL_SAFE),
            ("b64url-nopad", &URL_SAFE_NO_PAD),
        ] {
            forms.push((format!("{name}-standalone"), engine.encode(b)));
            // All three alignments, with every amount of trailing data.
            for lead in ["", "x", "xy"] {
                for trail in ["", "z", "zz", "zzz"] {
                    let doc = engine.encode(format!("{lead}{secret}{trail}"));
                    let first = (8 * lead.len()).div_ceil(6);
                    let last = 8 * (lead.len() + b.len()) / 6;
                    out.push((
                        format!("{name}-embedded-{}-{}", lead.len(), trail.len()),
                        doc.clone(),
                        doc[first..last].to_owned(),
                    ));
                }
            }
        }
        out.extend(forms.into_iter().map(|(n, f)| (n, f.clone(), f)));
        out
    }

    #[test]
    fn redactor_covers_every_encoded_form() {
        let fake_stripe = ["sk", "live", "AbCdEfGhIjKlMnOpQrStUvWx"].join("_");
        for secret in [NASTY_SECRET, fake_stripe.as_str(), "s3cr"] {
            let redactor = SecretRedactor::build([("KEY", secret)]);
            for (label, doc, needle) in encoded_forms(secret) {
                let input = format!("{{\"echo\":\"{doc}\"}}");
                let (clean, count) = redactor.redact_str(&input);
                assert!(count > 0, "{label}: nothing scrubbed from {input}");
                assert!(
                    !clean.contains(&needle),
                    "{label}: {needle} survived in {clean}"
                );
            }
        }
    }

    #[test]
    fn streaming_redactor_is_exact_at_every_chunk_boundary() {
        let redactor = SecretRedactor::build([("KEY", NASTY_SECRET), ("OTHER", "tok_other_9876")]);
        for (label, doc, needle) in encoded_forms(NASTY_SECRET) {
            let input = format!("pre-{doc}-mid-tok_other_9876-{doc}-post");
            let bytes = input.as_bytes();
            let (expected, _) = redactor.redact_bytes(bytes);
            assert!(
                !String::from_utf8_lossy(&expected).contains(&needle),
                "{label}"
            );

            // Two chunks, split at every offset.
            for split in 0..=bytes.len() {
                let mut stream = redactor.streaming();
                let mut got = stream.push(&bytes[..split]);
                got.extend(stream.push(&bytes[split..]));
                got.extend(stream.finish());
                assert_eq!(got, expected, "{label}: split at {split}");
                assert!(stream.total_scrubbed() > 0);
            }
            // Every fixed chunk size, including byte-at-a-time.
            for size in 1..=7 {
                let mut stream = redactor.streaming();
                let mut got = Vec::new();
                for chunk in bytes.chunks(size) {
                    got.extend(stream.push(chunk));
                }
                got.extend(stream.finish());
                assert_eq!(got, expected, "{label}: chunk size {size}");
            }
        }
    }

    #[test]
    fn hierarchical_resolution_enforces_policy_and_layer_precedence() {
        let schema = EnvSchema::parse_toml(SAMPLE_SCHEMA).unwrap();
        let policy = CompiledPolicy::compile(
            None,
            &parse_policy_toml(
                r#"
version = 1
[[rules]]
id = "allow-billing-use"
effect = "allow"
principals = ["group:billing"]
paths = ["secrets/billing/**"]
capabilities = ["use"]
"#,
            )
            .unwrap(),
        )
        .unwrap();

        let backend = MemoryBackend::new();
        backend
            .set(
                &SecretCoord {
                    repo_id: "acme/platform".to_owned(),
                    layer: SecretLayer::Env,
                    scope: "dev".to_owned(),
                    var_name: "STRIPE_API_KEY".to_owned(),
                },
                "sk_env_val",
            )
            .unwrap();
        backend
            .set(
                &SecretCoord {
                    repo_id: "acme/platform".to_owned(),
                    layer: SecretLayer::Personal,
                    scope: "@alice".to_owned(),
                    var_name: "STRIPE_API_KEY".to_owned(),
                },
                "sk_personal_override",
            )
            .unwrap();

        let resolver = SecretResolver::new(&schema, Some(&policy), &backend);

        // Alice in group:billing resolving for USE gets personal override.
        let ctx = ResolveContext {
            repo_id: "acme/platform".to_owned(),
            org: "acme".to_owned(),
            env: Environment::Dev,
            branch: "main".to_owned(),
            identity: DelegatedIdentity::human_only(
                Principal::User("alice".to_owned()),
                vec!["billing".to_owned()],
            ),
        };
        let resolved = resolver.resolve(&ctx, Capability::USE).unwrap();
        assert_eq!(
            resolved.values.get("STRIPE_API_KEY").unwrap().as_str(),
            "sk_personal_override"
        );
        assert_eq!(
            resolved.provenance.get("STRIPE_API_KEY").unwrap().layer,
            SecretLayer::Personal
        );

        // External anonymous caller cannot resolve STRIPE_API_KEY even for USE.
        let ext_ctx = ResolveContext {
            identity: DelegatedIdentity::human_only(Principal::Anonymous, vec![]),
            ..ctx
        };
        let ext_resolved = resolver.resolve(&ext_ctx, Capability::USE).unwrap();
        assert!(!ext_resolved.values.contains_key("STRIPE_API_KEY"));
        // Public default APP_PORT still resolves.
        assert_eq!(
            ext_resolved.values.get("APP_PORT").unwrap().as_str(),
            "8080"
        );
    }

    #[test]
    fn placeholder_registry_detects_leaked_tokens() {
        let schema = EnvSchema::parse_toml(SAMPLE_SCHEMA).unwrap();
        let egress = schema.vars["STRIPE_API_KEY"].egress.clone().unwrap();
        let mut reg = PlaceholderRegistry::new();
        let ph = reg.register(
            "STRIPE_API_KEY",
            Zeroizing::new("sk_live_secret".to_owned()),
            egress,
            Some("billing".to_owned()),
        );
        assert!(ph.starts_with(PLACEHOLDER_PREFIX));
        let found = reg.find_in_bytes(format!("Authorization: Bearer {ph}").as_bytes());
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].var_name, "STRIPE_API_KEY");

        // Re-registering the same var_name removes the stale placeholder.
        let ph2 = reg.register(
            "STRIPE_API_KEY",
            Zeroizing::new("sk_live_secret_v2".to_owned()),
            schema.vars["STRIPE_API_KEY"].egress.clone().unwrap(),
            Some("billing".to_owned()),
        );
        assert_ne!(ph, ph2);
        assert!(reg.get_by_placeholder(&ph).is_none());
        assert!(reg.find_in_bytes(ph.as_bytes()).is_empty());
        assert_eq!(reg.find_in_bytes(ph2.as_bytes()).len(), 1);
    }

    #[test]
    fn schema_rejects_ip_literals_localhost_traversal_and_path_semicolons() {
        for bad_host in [
            "127.0.0.1",
            "169.254.169.254",
            "::1",
            "[::1]",
            "localhost",
            "LOCALHOST.",
            "api.localhost",
            "api.stripe.com:443",
        ] {
            let toml = format!(
                "version = 1\n[vars.TOKEN]\ntype = \"secret\"\n[vars.TOKEN.egress]\nhosts = [\"{bad_host}\"]\n"
            );
            assert!(
                EnvSchema::parse_toml(&toml).is_err(),
                "host {bad_host} must be rejected"
            );
        }

        for bad_var in ["../EVIL", "A/B", "A\\B", "A:B", "BAD.", "BAD "] {
            let toml = format!("version = 1\n[vars.\"{bad_var}\"]\ntype = \"string\"\n");
            assert!(
                EnvSchema::parse_toml(&toml).is_err(),
                "var_name {bad_var:?} must be rejected"
            );
        }
        for bad_zone in ["../billing", "a/b", "a:b", "zone.", "zone "] {
            let toml =
                format!("version = 1\n[vars.KEY]\ntype = \"secret\"\nzone = \"{bad_zone}\"\n");
            assert!(
                EnvSchema::parse_toml(&toml).is_err(),
                "zone {bad_zone:?} must be rejected"
            );
        }

        let slash = egress_with_prefixes(&["/v1/"]);
        for bad_path in [
            "/v1/..;/v2/admin",
            "/v1/foo;bar",
            "/v1//charges",
            "//evil.com/v1/charges",
            "/v1/%3b/admin",
        ] {
            assert!(
                !slash.matches_path(bad_path),
                "ambiguous path {bad_path} must be refused"
            );
        }
    }

    #[test]
    fn sovereign_vault_rejects_repo_id_mismatch() {
        let dir = tempfile::tempdir().unwrap();
        let vault_path = dir.path().join("vault.premier.toml");
        let identity = age::x25519::Identity::generate();

        let backend_a = AgeSovereignBackend::new(
            &vault_path,
            "acme/repo-a",
            "secrets/prod.toml",
            identity.clone(),
            vec![],
        );
        let coord = SecretCoord {
            repo_id: "acme/repo-a".to_owned(),
            layer: SecretLayer::Env,
            scope: "prod".to_owned(),
            var_name: "KEY".to_owned(),
        };
        backend_a.set(&coord, "val-a").unwrap();

        let backend_b = AgeSovereignBackend::new(
            &vault_path,
            "acme/repo-b",
            "secrets/prod.toml",
            identity,
            vec![],
        );
        let err = backend_b.get(&coord).unwrap_err();
        assert!(matches!(err, SecretError::Crypto(_)));
    }

    #[test]
    fn render_dotenv_escapes_newlines_carriage_returns_dollar_and_backticks() {
        let mut vars = BTreeMap::new();
        vars.insert("PLAIN".to_owned(), Zeroizing::new("simple_123".to_owned()));
        vars.insert(
            "TRICKY".to_owned(),
            Zeroizing::new("a\nb\rc$HOME`id`\"\\".to_owned()),
        );
        let rendered = render_dotenv(&vars);
        assert_eq!(
            rendered.as_str(),
            "PLAIN=simple_123\nTRICKY=\"a\\nb\\rc\\$HOME\\`id\\`\\\"\\\\\"\n"
        );
    }

    #[test]
    fn export_all_zeroizing_missing_vault_returns_empty_without_creating_file() {
        let dir = tempfile::tempdir().unwrap();
        let state_dir = dir.path().join(".premier");
        let vault_path = state_dir.join("vault.premier.toml");
        let identity = age::x25519::Identity::generate();

        let backend = AgeSovereignBackend::new(
            &vault_path,
            "acme/platform",
            "secrets/prod.toml",
            identity,
            vec![],
        );

        let exported = backend.export_all_zeroizing().unwrap();
        assert!(exported.is_empty());
        assert!(!vault_path.exists());
        assert!(!state_dir.exists());
    }

    #[test]
    fn export_all_zeroizing_decrypts_entries_across_layers_and_scopes() {
        let dir = tempfile::tempdir().unwrap();
        let vault_path = dir.path().join("vault.premier.toml");
        let identity = age::x25519::Identity::generate();

        let backend = AgeSovereignBackend::new(
            &vault_path,
            "acme/platform",
            "secrets/vault.toml",
            identity,
            vec![],
        );

        let fixtures = [
            (SecretLayer::Org, "acme", "ORG_SIGNING_KEY", "org_sec_001"),
            (
                SecretLayer::Zone,
                "billing",
                "STRIPE_API_KEY",
                "sk_live_billing_002",
            ),
            (
                SecretLayer::Env,
                "prod",
                "DATABASE_URL",
                "postgres://svc:pw@db.internal:5432/app",
            ),
            (
                SecretLayer::Branch,
                "feat/declassify",
                "WEBHOOK_SECRET",
                "whsec_branch_003",
            ),
            (
                SecretLayer::Personal,
                "user:alice",
                "STRIPE_API_KEY",
                "sk_test_alice_004",
            ),
        ];

        for (layer, scope, var_name, secret) in fixtures {
            let coord = SecretCoord {
                repo_id: "acme/platform".to_owned(),
                layer,
                scope: scope.to_owned(),
                var_name: var_name.to_owned(),
            };
            backend.set(&coord, secret).unwrap();
        }

        let exported = backend.export_all_zeroizing().unwrap();
        assert_eq!(exported.len(), fixtures.len());

        let mut got: Vec<(String, String)> = exported
            .iter()
            .map(|(k, v)| (k.clone(), v.as_str().to_owned()))
            .collect();
        got.sort();

        let mut expected: Vec<(String, String)> = fixtures
            .iter()
            .map(|(_, _, var_name, secret)| ((*var_name).to_owned(), (*secret).to_owned()))
            .collect();
        expected.sort();

        assert_eq!(got, expected);
    }

    #[test]
    fn export_all_zeroizing_fails_closed_on_tampered_key_or_ciphertext() {
        let dir = tempfile::tempdir().unwrap();
        let vault_path = dir.path().join("vault.premier.toml");
        let identity = age::x25519::Identity::generate();

        let backend = AgeSovereignBackend::new(
            &vault_path,
            "acme/platform",
            "secrets/prod.toml",
            identity,
            vec![],
        );

        backend
            .set(
                &SecretCoord {
                    repo_id: "acme/platform".to_owned(),
                    layer: SecretLayer::Env,
                    scope: "prod".to_owned(),
                    var_name: "STRIPE_API_KEY".to_owned(),
                },
                "sk_live_secret_alpha",
            )
            .unwrap();
        backend
            .set(
                &SecretCoord {
                    repo_id: "acme/platform".to_owned(),
                    layer: SecretLayer::Zone,
                    scope: "billing".to_owned(),
                    var_name: "WEBHOOK_SECRET".to_owned(),
                },
                "whsec_secret_beta",
            )
            .unwrap();

        let original_raw = std::fs::read_to_string(&vault_path).unwrap();

        // 1. Tamper with an entry key -> AAD mismatch fails closed.
        let key_tampered = original_raw.replace("STRIPE_API_KEY", "TAMPERED_KEY");
        assert_ne!(key_tampered, original_raw);
        std::fs::write(&vault_path, &key_tampered).unwrap();
        let err = backend.export_all_zeroizing().unwrap_err();
        assert!(matches!(err, SecretError::Crypto(_)));

        // 2. Tamper with an entry ciphertext -> AEAD tag check fails closed.
        let mut parsed: toml::Value = toml::from_str(&original_raw).unwrap();
        let entries = parsed.get_mut("entries").unwrap().as_table_mut().unwrap();
        let first_key = entries.keys().next().unwrap().clone();
        let orig_enc = entries
            .get(&first_key)
            .unwrap()
            .as_str()
            .unwrap()
            .to_owned();
        let (nonce_b64, ct_b64) = orig_enc.split_once(':').unwrap();
        let mut ct_bytes = {
            use base64::Engine;
            base64::engine::general_purpose::STANDARD
                .decode(ct_b64)
                .unwrap()
        };
        ct_bytes[0] ^= 0x01;
        let flipped_enc = {
            use base64::Engine;
            format!(
                "{nonce_b64}:{}",
                base64::engine::general_purpose::STANDARD.encode(&ct_bytes)
            )
        };
        entries.insert(first_key, toml::Value::String(flipped_enc));
        std::fs::write(&vault_path, toml::to_string_pretty(&parsed).unwrap()).unwrap();

        let err = backend.export_all_zeroizing().unwrap_err();
        assert!(matches!(err, SecretError::Crypto(_)));
    }
}

/// Enterprise secret lifecycle: Envelope KMS, external connectors, Key Transparency, workload
/// OIDC and signed dual-phase rotation.
#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod lifecycle_tests {
    use std::collections::HashMap;
    use std::io::{Read, Write};
    use std::net::TcpListener;
    use std::sync::{Arc, Mutex};

    use base64::Engine;
    use base64::engine::general_purpose::{STANDARD as B64, URL_SAFE_NO_PAD as B64URL};
    use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
    use serde_json::{Value, json};

    use super::*;

    // ----- loopback mock server (plain HTTP or TLS with a throwaway CA) -----

    #[derive(Debug, Clone)]
    struct Recorded {
        method: String,
        path: String,
        headers: HashMap<String, String>,
        body: Vec<u8>,
    }

    type Handler = Arc<dyn Fn(&Recorded) -> (u16, String) + Send + Sync>;

    struct MockServer {
        base: String,
        requests: Arc<Mutex<Vec<Recorded>>>,
        root_pem: Option<String>,
    }

    impl MockServer {
        fn http(handler: impl Fn(&Recorded) -> (u16, String) + Send + Sync + 'static) -> Self {
            Self::start(Arc::new(handler), false)
        }

        fn https(handler: impl Fn(&Recorded) -> (u16, String) + Send + Sync + 'static) -> Self {
            Self::start(Arc::new(handler), true)
        }

        fn start(handler: Handler, tls: bool) -> Self {
            let listener = TcpListener::bind("127.0.0.1:0").unwrap();
            let port = listener.local_addr().unwrap().port();
            let (tls_cfg, root_pem) = if tls {
                let ck = rcgen::generate_simple_self_signed(vec![
                    "127.0.0.1".to_owned(),
                    "localhost".to_owned(),
                ])
                .unwrap();
                let key =
                    PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(ck.key_pair.serialize_der()));
                let cfg = rustls::ServerConfig::builder_with_provider(Arc::new(
                    rustls::crypto::ring::default_provider(),
                ))
                .with_safe_default_protocol_versions()
                .unwrap()
                .with_no_client_auth()
                .with_single_cert(vec![ck.cert.der().clone()], key)
                .unwrap();
                (Some(Arc::new(cfg)), Some(ck.cert.pem()))
            } else {
                (None, None)
            };
            let requests = Arc::new(Mutex::new(Vec::new()));
            let reqs = requests.clone();
            std::thread::spawn(move || {
                for stream in listener.incoming() {
                    let Ok(tcp) = stream else { continue };
                    let (reqs, handler, tls_cfg) = (reqs.clone(), handler.clone(), tls_cfg.clone());
                    std::thread::spawn(move || match tls_cfg {
                        Some(cfg) => {
                            let conn = rustls::ServerConnection::new(cfg).unwrap();
                            let mut s = rustls::StreamOwned::new(conn, tcp);
                            serve_one(&mut s, &handler, &reqs);
                            s.conn.send_close_notify();
                            let _ = s.flush();
                        }
                        None => {
                            let mut s = tcp;
                            serve_one(&mut s, &handler, &reqs);
                        }
                    });
                }
            });
            let scheme = if tls { "https" } else { "http" };
            Self {
                base: format!("{scheme}://127.0.0.1:{port}"),
                requests,
                root_pem,
            }
        }

        fn roots(&self) -> Vec<CertificateDer<'static>> {
            parse_pem_certificates(self.root_pem.as_ref().unwrap().as_bytes()).unwrap()
        }

        fn recorded(&self) -> Vec<Recorded> {
            self.requests.lock().unwrap().clone()
        }
    }

    fn serve_one<S: Read + Write>(s: &mut S, handler: &Handler, reqs: &Mutex<Vec<Recorded>>) {
        let mut buf = Vec::new();
        let mut chunk = [0u8; 4096];
        let header_end = loop {
            if let Some(i) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
                break i + 4;
            }
            match s.read(&mut chunk) {
                Ok(0) | Err(_) => return,
                Ok(n) => buf.extend_from_slice(&chunk[..n]),
            }
        };
        let head = String::from_utf8_lossy(&buf[..header_end]).to_string();
        let mut lines = head.split("\r\n");
        let mut first = lines.next().unwrap().split(' ');
        let method = first.next().unwrap().to_owned();
        let path = first.next().unwrap().to_owned();
        let headers: HashMap<String, String> = lines
            .filter_map(|l| l.split_once(':'))
            .map(|(k, v)| (k.trim().to_ascii_lowercase(), v.trim().to_owned()))
            .collect();
        let len: usize = headers
            .get("content-length")
            .map_or(0, |v| v.parse().unwrap());
        while buf.len() < header_end + len {
            match s.read(&mut chunk) {
                Ok(0) | Err(_) => return,
                Ok(n) => buf.extend_from_slice(&chunk[..n]),
            }
        }
        let rec = Recorded {
            method,
            path,
            headers,
            body: buf[header_end..header_end + len].to_vec(),
        };
        let (status, body) = handler(&rec);
        reqs.lock().unwrap().push(rec);
        let resp = format!(
            "HTTP/1.1 {status} Mock\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
            body.len()
        );
        let _ = s.write_all(resp.as_bytes());
        let _ = s.flush();
    }

    fn coord(layer: SecretLayer, scope: &str, var: &str) -> SecretCoord {
        SecretCoord {
            repo_id: "acme/platform".to_owned(),
            layer,
            scope: scope.to_owned(),
            var_name: var.to_owned(),
        }
    }

    fn prod(var: &str) -> SecretCoord {
        coord(SecretLayer::Env, "prod", var)
    }

    // ----- Envelope KMS -----

    #[test]
    fn envelope_kek_separation_dek_rotation_rewrap_and_age_migration() {
        let dir = tempfile::tempdir().unwrap();
        let state = dir.path().join(".premier");
        std::fs::create_dir_all(&state).unwrap();
        let kt_path = state.join("kt.jsonl");

        // A KEK file inside the vault state dir is refused (before it is even read).
        let inside = state.join("kek.key");
        std::fs::write(&inside, hex::encode([7u8; 32])).unwrap();
        let inside_uri = url::Url::from_file_path(&inside).unwrap().to_string();
        assert!(matches!(
            EnvKekWrapper::from_uri(&inside_uri, Some(&state)),
            Err(SecretError::Crypto(_))
        ));
        let unchecked = EnvKekWrapper::from_uri(&inside_uri, None).unwrap();
        assert!(unchecked.reject_if_in_dir(&state).is_err());

        // Same KEK as base64, outside the state dir: accepted, same key id.
        let outside = dir.path().join("keys").join("kek.key");
        std::fs::create_dir_all(outside.parent().unwrap()).unwrap();
        std::fs::write(&outside, B64.encode([7u8; 32])).unwrap();
        let outside_uri = url::Url::from_file_path(&outside).unwrap().to_string();
        let wrapper = EnvKekWrapper::from_uri(&outside_uri, Some(&state)).unwrap();
        assert_eq!(wrapper.key_id(), unchecked.key_id());
        assert!(!format!("{wrapper:?}").contains(&hex::encode([7u8; 32])));
        assert!(EnvKekWrapper::from_uri("env://PREMIER_TEST_SURELY_UNSET_KEK", None).is_err());
        assert!(EnvKekWrapper::from_uri("s3://bucket/kek", None).is_err());

        let vault_path = state.join("vault.envelope.toml");
        let env = EnvelopeVaultBackend::new(&vault_path, "acme/platform", Arc::new(wrapper))
            .with_kek_separated(true)
            .with_key_transparency(&kt_path);
        env.set(&prod("STRIPE_API_KEY"), "sk_live_envelope_1")
            .unwrap();
        env.set(&prod("DB_PASSWORD"), "pg_pw_2").unwrap();
        assert_eq!(
            env.get(&prod("STRIPE_API_KEY")).unwrap().unwrap().as_str(),
            "sk_live_envelope_1"
        );
        let raw = std::fs::read_to_string(&vault_path).unwrap();
        assert!(!raw.contains("sk_live_envelope_1") && !raw.contains("pg_pw_2"));

        // DEK rotation re-encrypts everything under a new DEK version.
        let before: EnvelopeVaultFile = toml::from_str(&raw).unwrap();
        assert_eq!(env.rotate_dek().unwrap(), 2);
        let after: EnvelopeVaultFile =
            toml::from_str(&std::fs::read_to_string(&vault_path).unwrap()).unwrap();
        assert_ne!(before.wrapped_dek, after.wrapped_dek);
        assert_ne!(before.entries, after.entries);
        assert_eq!(
            env.get(&prod("DB_PASSWORD")).unwrap().unwrap().as_str(),
            "pg_pw_2"
        );

        let st = env.status().unwrap();
        assert_eq!(
            (st.mode.as_str(), st.provider.as_str(), st.envelope_version),
            ("envelope", "env-kek", 2)
        );
        assert_eq!((st.dek_version, st.entry_count), (2, 2));
        assert!(st.kek_separated && st.kt_enabled && st.kt_valid);
        assert_eq!((st.kt_entries, st.kt_error), (1, None));

        // A different KEK presenting the same key id cannot unwrap the DEK.
        let wrong = EnvelopeVaultBackend::new(
            &vault_path,
            "acme/platform",
            Arc::new(EnvKekWrapper::from_key_bytes(st.key_id.clone(), [9u8; 32])),
        );
        assert!(matches!(
            wrong.get(&prod("DB_PASSWORD")),
            Err(SecretError::Crypto(_))
        ));

        // Re-wrap the DEK to an age recipient; only a backend on the new key can read it.
        let identity = age::x25519::Identity::generate();
        let age_wrapper = AgeKeyWrapper::new(identity.clone(), vec![]);
        env.rewrap_dek(&age_wrapper).unwrap();
        assert!(matches!(
            env.get(&prod("DB_PASSWORD")),
            Err(SecretError::Crypto(_))
        ));
        let env_age =
            EnvelopeVaultBackend::new(&vault_path, "acme/platform", Arc::new(age_wrapper))
                .with_key_transparency(&kt_path);
        assert_eq!(env_age.list_entries().unwrap().len(), 2);
        assert_eq!(env_age.status().unwrap().kt_entries, 2);

        // Ciphertext transplanted under another key name fails AEAD.
        let raw = std::fs::read_to_string(&vault_path).unwrap();
        std::fs::write(&vault_path, raw.replace("STRIPE_API_KEY", "OTHER_KEY")).unwrap();
        assert!(matches!(
            env_age.get(&prod("OTHER_KEY")),
            Err(SecretError::Crypto(_))
        ));

        // Migrate a sovereign age vault into a fresh envelope vault.
        let age_vault = AgeSovereignBackend::new(
            state.join("vault.toml"),
            "acme/platform",
            "secrets/prod.toml",
            age::x25519::Identity::generate(),
            vec![],
        );
        age_vault.set(&prod("A"), "alpha").unwrap();
        age_vault.set(&prod("B"), "beta").unwrap();
        let target = EnvelopeVaultBackend::new(
            state.join("vault.v2.toml"),
            "acme/platform",
            Arc::new(EnvKekWrapper::from_key_bytes("test-kek", [1u8; 32])),
        );
        assert_eq!(migrate_from_age_vault(&age_vault, &target).unwrap(), 2);
        let migrated = target.list_entries().unwrap();
        let expected = age_vault.list_entries().unwrap();
        assert_eq!(migrated.len(), 2);
        for (k, v) in expected {
            assert_eq!(migrated[&k].as_str(), v.as_str());
        }
        assert_eq!(target.get(&prod("B")).unwrap().unwrap().as_str(), "beta");
    }

    fn transit_mock() -> MockServer {
        MockServer::https(|r| {
            if r.headers.get("x-vault-token").map(String::as_str) != Some("s.test-token") {
                return (403, r#"{"errors":["permission denied"]}"#.to_owned());
            }
            let body: Value = serde_json::from_slice(&r.body).unwrap();
            match r.path.as_str() {
                "/v1/transit/encrypt/premier-kek" => {
                    let blob = B64.encode(
                        json!({"pt": body["plaintext"], "ad": body["associated_data"]}).to_string(),
                    );
                    (
                        200,
                        json!({"data": {"ciphertext": format!("vault:v1:{blob}")}}).to_string(),
                    )
                }
                "/v1/transit/decrypt/premier-kek" => {
                    let ct = body["ciphertext"].as_str().unwrap();
                    let inner: Value = serde_json::from_slice(
                        &B64.decode(ct.strip_prefix("vault:v1:").unwrap()).unwrap(),
                    )
                    .unwrap();
                    if inner["ad"] != body["associated_data"] {
                        return (
                            400,
                            r#"{"errors":["cipher: message authentication failed"]}"#.to_owned(),
                        );
                    }
                    (200, json!({"data": {"plaintext": inner["pt"]}}).to_string())
                }
                _ => (404, "{}".to_owned()),
            }
        })
    }

    fn transit_config(address: &str, roots: Vec<CertificateDer<'static>>) -> VaultTransitConfig {
        VaultTransitConfig {
            address: address.to_owned(),
            mount: "transit".to_owned(),
            key_name: "premier-kek".to_owned(),
            token: zeroize::Zeroizing::new("s.test-token".to_owned()),
            namespace: None,
            allow_insecure_loopback: false,
            extra_root_certs: roots,
        }
    }

    #[test]
    fn vault_transit_wraps_over_verified_tls_with_bound_context() {
        let server = transit_mock();
        let wrapper =
            VaultTransitWrapper::new(transit_config(&server.base, server.roots())).unwrap();
        assert!(!format!("{wrapper:?}").contains("s.test-token"));
        assert_eq!(wrapper.key_id(), "vault-transit:transit/premier-kek");

        let dek = [3u8; 32];
        let wrapped = wrapper.wrap_dek(&dek, "acme/platform:dek-v1").unwrap();
        assert!(wrapped.starts_with("vault-transit-v1:vault:v1:"));
        assert_eq!(
            *wrapper
                .unwrap_dek(&wrapped, "acme/platform:dek-v1")
                .unwrap(),
            dek
        );
        assert!(
            wrapper
                .unwrap_dek(&wrapped, "acme/platform:dek-v2")
                .is_err()
        );

        let dir = tempfile::tempdir().unwrap();
        let env = EnvelopeVaultBackend::new(
            dir.path().join("vault.toml"),
            "acme/platform",
            Arc::new(wrapper),
        )
        .with_kek_separated(true);
        env.set(&prod("STRIPE_API_KEY"), "sk_transit").unwrap();
        assert_eq!(
            env.get(&prod("STRIPE_API_KEY")).unwrap().unwrap().as_str(),
            "sk_transit"
        );
        assert_eq!(env.status().unwrap().provider, "vault-transit");
        assert!(server.recorded().iter().all(|r| r.method == "POST"));

        // The mock's self-signed cert is not trusted without the extra root.
        let untrusted = VaultTransitWrapper::new(transit_config(&server.base, vec![])).unwrap();
        assert!(untrusted.wrap_dek(&dek, "ctx").is_err());

        // Endpoint and path hygiene.
        for (address, allow) in [
            ("http://127.0.0.1:8200", false),
            ("http://10.0.0.5:8200", true),
            ("ftp://vault.example", false),
            ("https://user:pw@vault.example", false),
            ("https://vault.example/?x=1", false),
        ] {
            let mut cfg = transit_config(address, vec![]);
            cfg.allow_insecure_loopback = allow;
            assert!(VaultTransitWrapper::new(cfg).is_err(), "{address}");
        }
        let mut loopback = transit_config("http://localhost:8200", vec![]);
        loopback.allow_insecure_loopback = true;
        assert!(VaultTransitWrapper::new(loopback).is_ok());
        for (mount, key) in [
            ("../sys", "k"),
            ("transit", "a?b"),
            ("transit", "x/y"),
            ("a#b", "k"),
        ] {
            let mut cfg = transit_config("https://vault.example", vec![]);
            cfg.mount = mount.to_owned();
            cfg.key_name = key.to_owned();
            assert!(VaultTransitWrapper::new(cfg).is_err(), "{mount}/{key}");
        }
    }

    // ----- External connectors (called from inside a tokio runtime) -----

    #[tokio::test]
    async fn vault_kv_onepassword_and_composite_work_inside_async_runtime() {
        let store: Arc<Mutex<HashMap<String, String>>> = Arc::default();
        let kv_store = store.clone();
        let kv_server = MockServer::http(move |r| {
            if r.headers.get("x-vault-token").map(String::as_str) != Some("s.kv-token") {
                return (403, "{}".to_owned());
            }
            let mut store = kv_store.lock().unwrap();
            match r.method.as_str() {
                "GET" => match store.get(&r.path) {
                    Some(v) => (200, json!({"data": {"data": {"value": v}}}).to_string()),
                    None => (404, r#"{"errors":[]}"#.to_owned()),
                },
                "POST" => {
                    let body: Value = serde_json::from_slice(&r.body).unwrap();
                    let value = body["data"]["value"].as_str().unwrap().to_owned();
                    store.insert(r.path.clone(), value);
                    (200, r#"{"data":{"version":1}}"#.to_owned())
                }
                "DELETE" => {
                    store.remove(&r.path);
                    (204, String::new())
                }
                _ => (405, "{}".to_owned()),
            }
        });
        let kv_config = |address: &str| VaultKvConfig {
            address: address.to_owned(),
            mount: "secret".to_owned(),
            prefix: "premier/acme".to_owned(),
            token: zeroize::Zeroizing::new("s.kv-token".to_owned()),
            namespace: None,
            allow_insecure_loopback: true,
            extra_root_certs: vec![],
        };
        let kv = Arc::new(VaultKvConnector::new(kv_config(&kv_server.base)).unwrap());

        kv.set(&prod("STRIPE_API_KEY"), "sk_kv \"quoted\"").unwrap();
        assert_eq!(
            kv.get(&prod("STRIPE_API_KEY")).unwrap().unwrap().as_str(),
            "sk_kv \"quoted\""
        );
        assert!(
            store.lock().unwrap().contains_key(
                "/v1/secret/data/premier/acme/acme%2Fplatform/env/prod/STRIPE_API_KEY"
            )
        );
        let branch = coord(SecretLayer::Branch, "feature/x", "TOKEN");
        kv.set(&branch, "t").unwrap();
        assert!(
            store.lock().unwrap().contains_key(
                "/v1/secret/data/premier/acme/acme%2Fplatform/branch/feature%2Fx/TOKEN"
            )
        );
        // Same var_name across different repos stays strictly namespaced in Vault KV.
        let other_repo = SecretCoord {
            repo_id: "other/repo".to_owned(),
            ..prod("STRIPE_API_KEY")
        };
        assert!(kv.get(&other_repo).unwrap().is_none());
        assert!(kv.get(&coord(SecretLayer::Env, "..", "X")).is_err());
        assert!(kv.get(&prod("MISSING")).unwrap().is_none());
        kv.delete(&branch).unwrap();
        assert!(kv.get(&branch).unwrap().is_none());
        assert!(VaultKvConnector::new(kv_config("http://10.1.2.3:8200")).is_err());

        // Composite: primary first, read-through to KV, writes stay on primary.
        let primary = Arc::new(MemoryBackend::new());
        let composite = CompositeSecretBackend::new(primary.clone(), kv.clone());
        assert_eq!(
            composite
                .get(&prod("STRIPE_API_KEY"))
                .unwrap()
                .unwrap()
                .as_str(),
            "sk_kv \"quoted\""
        );
        composite.set(&prod("STRIPE_API_KEY"), "sk_local").unwrap();
        assert_eq!(
            composite
                .get(&prod("STRIPE_API_KEY"))
                .unwrap()
                .unwrap()
                .as_str(),
            "sk_local"
        );
        assert_eq!(
            kv.get(&prod("STRIPE_API_KEY")).unwrap().unwrap().as_str(),
            "sk_kv \"quoted\""
        );
        assert_eq!(composite.name(), "composite(memory+vault-kv-v2)");

        // 1Password Connect: exact repo/layer/scope/var title + field by label or PASSWORD purpose.
        let op_server = MockServer::http(|r| {
            if r.headers.get("authorization").map(String::as_str) != Some("Bearer op-token") {
                return (401, "{}".to_owned());
            }
            match r.path.as_str() {
                "/v1/vaults/vlt123/items" => (
                    200,
                    r#"[{"id":"item1","title":"acme/platform/env/prod/STRIPE_API_KEY"},{"id":"item2","title":"OTHER"}]"#
                        .to_owned(),
                ),
                "/v1/vaults/vlt123/items/item1" => (
                    200,
                    r#"{"id":"item1","fields":[{"label":"username","value":"bob"},{"label":"credential","purpose":"PASSWORD","value":"sk_1p"}]}"#
                        .to_owned(),
                ),
                _ => (404, "{}".to_owned()),
            }
        });
        let op_config = |vault_id: &str| OnePasswordConnectConfig {
            host: op_server.base.clone(),
            vault_id: vault_id.to_owned(),
            token: zeroize::Zeroizing::new("op-token".to_owned()),
            allow_insecure_loopback: true,
            extra_root_certs: vec![],
        };
        let op = OnePasswordConnectConnector::new(op_config("vlt123")).unwrap();
        assert!(!format!("{op:?}").contains("op-token"));
        assert_eq!(
            op.get(&prod("STRIPE_API_KEY")).unwrap().unwrap().as_str(),
            "sk_1p"
        );
        assert!(
            op.get(&coord(SecretLayer::Env, "staging", "STRIPE_API_KEY"))
                .unwrap()
                .is_none()
        );
        assert!(op.get(&other_repo).unwrap().is_none());
        assert!(op.get(&prod("NOPE")).unwrap().is_none());
        assert!(op.set(&prod("STRIPE_API_KEY"), "x").is_err());
        assert!(OnePasswordConnectConnector::new(op_config("../x")).is_err());
    }

    // ----- Key Transparency -----

    #[test]
    fn key_transparency_chain_fails_closed_on_any_tamper() {
        let dir = tempfile::tempdir().unwrap();
        let log = KeyTransparencyLog::open(dir.path().join("kt.jsonl"));
        assert_eq!(log.verify_chain().unwrap().entry_count, 0);
        for i in 0..3 {
            let e = log
                .append_binding(
                    "acme/platform",
                    "secrets/prod.toml",
                    &[format!("age1key{i}")],
                    "alice",
                    "genesis",
                )
                .unwrap();
            assert_eq!(e.seq, i + 1);
        }
        let report = log.verify_chain().unwrap();
        assert!(report.valid);
        assert_eq!(report.entry_count, 3);
        assert_eq!(report.latest_recipients, vec!["age1key2".to_owned()]);
        assert!(
            log.verify_vault_recipients("acme/platform", &[" AGE1KEY2 ".to_owned()])
                .is_ok()
        );
        assert!(matches!(
            log.verify_vault_recipients("acme/platform", &["age1evil".to_owned()]),
            Err(SecretError::Crypto(_))
        ));
        let other = log
            .verify_vault_recipients("other/repo", &["anything".to_owned()])
            .unwrap();
        assert!(other.latest_hash.is_none());

        let original = std::fs::read_to_string(log.path()).unwrap();
        let lines: Vec<&str> = original.lines().collect();
        let tampers = [
            // field edit without rehash
            [
                lines[0],
                lines[1].replace("\"alice\"", "\"mallory\"").as_str(),
                lines[2],
            ]
            .join("\n"),
            // deleted entry
            [lines[0], lines[2]].join("\n"),
            // recipients swapped, fingerprint kept
            [
                lines[0],
                lines[1],
                lines[2].replace("age1key2", "age1evil").as_str(),
            ]
            .join("\n"),
            // entry_hash rewritten
            [
                lines[0],
                lines[1],
                lines[2]
                    .replace("\"entry_hash\":\"", "\"entry_hash\":\"00")
                    .as_str(),
            ]
            .join("\n"),
        ];
        for tampered in tampers {
            std::fs::write(log.path(), tampered + "\n").unwrap();
            assert!(matches!(log.verify_chain(), Err(SecretError::Crypto(_))));
            assert!(
                log.append_binding("acme/platform", "p", &[], "a", "e")
                    .is_err()
            );
        }
        std::fs::write(log.path(), &original).unwrap();
        assert!(log.verify_chain().is_ok());
    }

    #[test]
    fn age_vault_key_transparency_detects_silent_public_key_swap() {
        let dir = tempfile::tempdir().unwrap();
        let vault_path = dir.path().join(".premier").join("vault.toml");
        let kt_path = dir.path().join(".premier").join("kt.jsonl");
        let identity = age::x25519::Identity::generate();
        let make = |extra: Vec<age::x25519::Recipient>| {
            AgeSovereignBackend::new(
                &vault_path,
                "acme/platform",
                "secrets/prod.toml",
                identity.clone(),
                extra,
            )
            .with_key_transparency(&kt_path)
        };

        let backend = make(vec![]);
        backend.set(&prod("STRIPE_API_KEY"), "sk_age_1").unwrap();
        let kt = KeyTransparencyLog::open(&kt_path);
        let entries = kt.entries().unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].event, "genesis");
        assert_eq!(entries[0].recipients, backend.recipient_public_keys());
        let raw = std::fs::read_to_string(&vault_path).unwrap();
        let ours = backend.recipient_public_keys()[0].clone();
        assert!(raw.contains(&ours));
        assert_eq!(
            backend
                .get(&prod("STRIPE_API_KEY"))
                .unwrap()
                .unwrap()
                .as_str(),
            "sk_age_1"
        );
        assert_eq!(backend.list_entries().unwrap().len(), 1);

        // An extra (attacker) recipient slipped into the config fails closed.
        let attacker = age::x25519::Identity::generate().to_public().to_string();
        let swapped = make(vec![attacker.parse().unwrap()]);
        assert!(matches!(
            swapped.get(&prod("STRIPE_API_KEY")),
            Err(SecretError::Crypto(_))
        ));
        assert!(swapped.set(&prod("X"), "y").is_err());

        // Editing the vault's recorded recipients fails closed.
        std::fs::write(&vault_path, raw.replace(&ours, &attacker)).unwrap();
        assert!(matches!(
            backend.get(&prod("STRIPE_API_KEY")),
            Err(SecretError::Crypto(_))
        ));
        std::fs::write(&vault_path, &raw).unwrap();
        assert!(backend.get(&prod("STRIPE_API_KEY")).is_ok());

        // Editing the KT log fails closed.
        let kt_raw = std::fs::read_to_string(&kt_path).unwrap();
        std::fs::write(
            &kt_path,
            kt_raw.replace("\"event\":\"genesis\"", "\"event\":\"rotate\""),
        )
        .unwrap();
        assert!(matches!(
            backend.get(&prod("STRIPE_API_KEY")),
            Err(SecretError::Crypto(_))
        ));
        std::fs::write(&kt_path, &kt_raw).unwrap();

        // Recreating the vault under different keys is refused against the existing binding.
        std::fs::remove_file(&vault_path).unwrap();
        assert!(matches!(
            swapped.set(&prod("STRIPE_API_KEY"), "sk_evil"),
            Err(SecretError::Crypto(_))
        ));
    }

    // ----- Workload OIDC -----

    #[test]
    fn oidc_issue_verify_expiry_and_revocation() {
        let issuer = OidcTokenIssuer::new("https://premier.example", [5u8; 32]);
        let request = WorkloadTokenRequest {
            sub: "user:alice".to_owned(),
            act: Some(ActorClaim {
                sub: "agent:claude".to_owned(),
                profile: "coder".to_owned(),
                task_id: "task-1".to_owned(),
            }),
            aud: vec!["premier-proxy".to_owned()],
            repo: "acme/platform".to_owned(),
            branch: "main".to_owned(),
            scope: vec!["secrets:use".to_owned()],
            groups: vec!["billing".to_owned()],
            ttl_secs: None,
        };
        let issued = issuer.issue(request.clone()).unwrap();
        assert_eq!(issued.alg, "EdDSA");
        assert_eq!(issued.kid, issuer.kid());
        assert_eq!(issued.claims.exp - issued.claims.iat, 300);
        assert!(!format!("{issued:?}").contains(&issued.token));
        let claims = issuer.verify(&issued.token, "premier-proxy").unwrap();
        assert_eq!(claims, issued.claims);

        assert!(issuer.verify(&issued.token, "other-aud").is_err());
        let foreign = OidcTokenIssuer::new("https://premier.example", [6u8; 32]);
        assert!(foreign.verify(&issued.token, "premier-proxy").is_err());

        // Forged claims and alg=none are refused.
        let parts: Vec<&str> = issued.token.split('.').collect();
        let mut forged = issued.claims.clone();
        forged.sub = "user:root".to_owned();
        let forged_claims = B64URL.encode(serde_json::to_vec(&forged).unwrap());
        let forged_token = format!("{}.{forged_claims}.{}", parts[0], parts[2]);
        assert!(issuer.verify(&forged_token, "premier-proxy").is_err());
        let none_header = B64URL.encode(br#"{"alg":"none","typ":"JWT"}"#);
        assert!(
            issuer
                .verify(&format!("{none_header}.{}.", parts[1]), "premier-proxy")
                .is_err()
        );

        // Expiry is exact.
        let exp = issued.claims.exp;
        assert!(
            issuer
                .verify_at(&issued.token, "premier-proxy", exp - 1)
                .is_ok()
        );
        assert!(
            issuer
                .verify_at(&issued.token, "premier-proxy", exp)
                .is_err()
        );

        // TTL is clamped to 1..=3600.
        for (ttl, expected) in [(100_000, 3600), (0, 1), (60, 60)] {
            let t = issuer
                .issue(WorkloadTokenRequest {
                    ttl_secs: Some(ttl),
                    ..request.clone()
                })
                .unwrap();
            assert_eq!(t.claims.exp - t.claims.iat, expected);
        }

        // Revocation by jti and by principal (including the acting agent).
        issuer.revoke_jti(&issued.claims.jti);
        assert!(issuer.verify(&issued.token, "premier-proxy").is_err());
        let second = issuer.issue(request.clone()).unwrap();
        assert!(issuer.verify(&second.token, "premier-proxy").is_ok());
        issuer.revoke_principal("agent:claude");
        assert!(issuer.verify(&second.token, "premier-proxy").is_err());
        // Tokens minted before/at revocation stay invalid, while fresh tokens after revocation succeed.
        issuer.revoke_principal_at("user:dave", second.claims.iat + 10);
        let dave_req = WorkloadTokenRequest {
            sub: "user:dave".to_owned(),
            act: None,
            ..request.clone()
        };
        let dave_token = issuer.issue(dave_req).unwrap();
        let at_revoked = dave_token.claims.iat;
        assert!(
            issuer
                .verify_at(&dave_token.token, "premier-proxy", at_revoked)
                .is_err()
        );
        issuer.revoke_principal_at("user:carol", second.claims.iat - 1);
        let carol_token = issuer
            .issue(WorkloadTokenRequest {
                sub: "user:carol".to_owned(),
                act: None,
                ..request.clone()
            })
            .unwrap();
        assert!(issuer.verify(&carol_token.token, "premier-proxy").is_ok());
        let human_only = issuer
            .issue(WorkloadTokenRequest {
                sub: "user:bob".to_owned(),
                act: None,
                ..request.clone()
            })
            .unwrap();
        assert!(issuer.verify(&human_only.token, "premier-proxy").is_ok());

        let doc = issuer.discovery_document();
        assert_eq!(doc["issuer"], "https://premier.example");
        assert_eq!(
            doc["token_endpoint"],
            "https://premier.example/v1/oidc/token"
        );
        assert_eq!(doc["id_token_signing_alg_values_supported"][0], "EdDSA");
        assert!(!doc.to_string().contains(&hex::encode([5u8; 32])));
        assert!(
            issuer
                .issue(WorkloadTokenRequest {
                    aud: vec![],
                    ..request
                })
                .is_err()
        );
    }

    // ----- Signed dual-phase rotation -----

    const SIGNING: &[u8] = b"whsec_test_signing_key";

    #[test]
    fn webhook_signatures_are_hmac_bound_to_timestamp_and_body() {
        let sig = sign_webhook_payload(SIGNING, 1_700_000_000, b"{\"a\":1}").unwrap();
        assert!(sig.starts_with("sha256=") && sig.len() == 7 + 64);
        assert!(verify_webhook_signature(
            SIGNING,
            1_700_000_000,
            b"{\"a\":1}",
            &sig
        ));
        assert!(!verify_webhook_signature(
            SIGNING,
            1_700_000_001,
            b"{\"a\":1}",
            &sig
        ));
        assert!(!verify_webhook_signature(
            SIGNING,
            1_700_000_000,
            b"{\"a\":2}",
            &sig
        ));
        assert!(!verify_webhook_signature(
            b"other",
            1_700_000_000,
            b"{\"a\":1}",
            &sig
        ));
        assert!(sign_webhook_payload(b"", 1, b"").is_err());
    }

    fn rotation_server(prepare_body: &'static str, commit_status: u16) -> MockServer {
        MockServer::http(move |r| {
            let ts: i64 = r.headers["x-premier-timestamp"].parse().unwrap();
            if !verify_webhook_signature(
                SIGNING,
                ts,
                &r.body,
                &r.headers["x-premier-signature-256"],
            ) {
                return (401, "{}".to_owned());
            }
            let body: Value = serde_json::from_slice(&r.body).unwrap();
            match body["phase"].as_str().unwrap() {
                "prepare" => (200, prepare_body.to_owned()),
                "commit" => (commit_status, "{}".to_owned()),
                "rollback" => (200, "{}".to_owned()),
                _ => (400, "{}".to_owned()),
            }
        })
    }

    fn rotation_spec(url: String) -> RotationSpec {
        RotationSpec {
            provider: Some("stripe".to_owned()),
            webhook_url: url,
            signing_secret_ref: "vault://premier/whsec".to_owned(),
            max_age_days: Some(90),
            schedule: None,
            revoke_on_offboard: true,
        }
    }

    fn phases(server: &MockServer) -> Vec<String> {
        server
            .recorded()
            .iter()
            .map(|r| {
                let v: Value = serde_json::from_slice(&r.body).unwrap();
                v["phase"].as_str().unwrap().to_owned()
            })
            .collect()
    }

    #[test]
    fn dual_phase_rotation_commits_and_rolls_back_without_leaking_secrets() {
        let dispatcher = RotationDispatcher {
            allow_insecure_loopback: true,
            allow_private_webhooks: true,
            allowed_hosts: vec![],
            extra_root_certs: vec![],
        };
        let c = prod("STRIPE_API_KEY");

        // Happy path: provider mints the new value in `prepare`.
        let server = rotation_server(r#"{"new_value":"sk_live_rotated_2"}"#, 200);
        let backend = MemoryBackend::new();
        backend.set(&c, "sk_live_original_1").unwrap();
        let spec = rotation_spec(format!("{}/rotate", server.base));
        let receipt = dispatcher.execute_dual_phase(
            &spec,
            SIGNING,
            &backend,
            &c,
            "user:alice",
            "scheduled",
            false,
            None,
        );
        assert_eq!(receipt.status, RotationStatus::Committed, "{receipt:?}");
        assert_eq!(receipt.phase_reached, RotationPhase::Commit);
        assert_eq!(
            (receipt.http_status, receipt.rollback_sent),
            (Some(200), false)
        );
        assert_eq!(
            (receipt.provider.as_str(), receipt.env.as_str()),
            ("stripe", "prod")
        );
        assert_eq!(
            backend.get(&c).unwrap().unwrap().as_str(),
            "sk_live_rotated_2"
        );
        assert_eq!(phases(&server), ["prepare", "commit"]);
        let receipt_json = serde_json::to_string(&receipt).unwrap();
        for leaked in ["sk_live_rotated_2", "sk_live_original_1", "whsec"] {
            assert!(!receipt_json.contains(leaked));
            assert!(
                server
                    .recorded()
                    .iter()
                    .all(|r| !String::from_utf8_lossy(&r.body).contains(leaked))
            );
        }

        // Commit fails: previous value restored and a signed rollback sent.
        let server = rotation_server(r#"{"new_value":"sk_live_rotated_3"}"#, 500);
        let backend = MemoryBackend::new();
        backend.set(&c, "sk_live_original_1").unwrap();
        let spec = rotation_spec(format!("{}/rotate", server.base));
        let receipt = dispatcher.execute_dual_phase(
            &spec, SIGNING, &backend, &c, "user:bob", "offboard", true, None,
        );
        assert_eq!(receipt.status, RotationStatus::RolledBack, "{receipt:?}");
        assert_eq!(receipt.phase_reached, RotationPhase::Rollback);
        assert!(receipt.rollback_sent && receipt.triggered_by_offboard);
        assert_eq!(receipt.http_status, Some(500));
        assert_eq!(
            backend.get(&c).unwrap().unwrap().as_str(),
            "sk_live_original_1"
        );
        assert_eq!(phases(&server), ["prepare", "commit", "rollback"]);
        assert!(!serde_json::to_string(&receipt).unwrap().contains("sk_live"));

        // Supplied value when the provider returns none; manual when neither exists.
        let server = rotation_server("{}", 200);
        let spec = rotation_spec(format!("{}/rotate", server.base));
        let backend = MemoryBackend::new();
        let receipt = dispatcher.execute_dual_phase(
            &spec,
            SIGNING,
            &backend,
            &c,
            "user:alice",
            "manual",
            false,
            Some("sk_supplied"),
        );
        assert_eq!(receipt.status, RotationStatus::Committed);
        assert_eq!(backend.get(&c).unwrap().unwrap().as_str(), "sk_supplied");
        let receipt = dispatcher.execute_dual_phase(
            &spec,
            SIGNING,
            &backend,
            &c,
            "user:alice",
            "manual",
            false,
            None,
        );
        assert_eq!(receipt.status, RotationStatus::ManualRequired);
        assert!(receipt.rollback_sent);
        assert_eq!(backend.get(&c).unwrap().unwrap().as_str(), "sk_supplied");

        // Wrong signing key: the receiver refuses prepare; nothing changes.
        let receipt = dispatcher.execute_dual_phase(
            &spec,
            b"wrong-key",
            &backend,
            &c,
            "user:alice",
            "manual",
            false,
            Some("sk_x"),
        );
        assert_eq!(receipt.status, RotationStatus::Failed);
        assert_eq!(receipt.http_status, Some(401));
        assert!(!receipt.rollback_sent);
        assert_eq!(backend.get(&c).unwrap().unwrap().as_str(), "sk_supplied");

        // Cleartext to a non-loopback host is refused before any byte is sent.
        let spec = rotation_spec("http://rotation.example.com/hook".to_owned());
        let receipt = dispatcher.execute_dual_phase(
            &spec,
            SIGNING,
            &backend,
            &c,
            "user:alice",
            "manual",
            false,
            Some("sk_x"),
        );
        assert_eq!(receipt.status, RotationStatus::Failed);
        assert!(receipt.error.unwrap().contains("cleartext"));
        assert_eq!(backend.get(&c).unwrap().unwrap().as_str(), "sk_supplied");
    }

    #[test]
    fn schema_validates_rotation_webhooks() {
        let schema = |url: &str, secret_ref: &str| {
            EnvSchema::parse_toml(&format!(
                "version = 1\n[vars.STRIPE_API_KEY]\ntype = \"secret\"\n\
                 [vars.STRIPE_API_KEY.rotation]\nprovider = \"stripe\"\n\
                 webhook_url = \"{url}\"\nsigning_secret_ref = \"{secret_ref}\"\nmax_age_days = 90\n"
            ))
        };
        let ok = schema("https://hooks.example.com/rotate", "vault://premier/whsec").unwrap();
        let rotation = ok.vars["STRIPE_API_KEY"].rotation.as_ref().unwrap();
        assert!(rotation.revoke_on_offboard);
        assert_eq!(rotation.max_age_days, Some(90));
        for (url, secret_ref) in [
            ("http://hooks.example.com/rotate", "ref"),
            ("https://user:pw@hooks.example.com/rotate", "ref"),
            ("not a url", "ref"),
            ("https://hooks.example.com/rotate", "   "),
        ] {
            assert!(schema(url, secret_ref).is_err(), "{url} / {secret_ref:?}");
        }
    }

    #[test]
    fn deleting_or_emptying_kt_log_fails_closed_for_bound_vaults() {
        let dir = tempfile::tempdir().unwrap();
        let state = dir.path().join(".premier");
        std::fs::create_dir_all(&state).unwrap();

        // 1. Bound AgeSovereignBackend fails closed if KT is emptied or deleted.
        let kt_age = state.join("kt-age.jsonl");
        let age_vault = state.join("vault.toml");
        let age_backend = AgeSovereignBackend::new(
            &age_vault,
            "acme/platform",
            "secrets/prod.toml",
            age::x25519::Identity::generate(),
            vec![],
        )
        .with_key_transparency(&kt_age);
        age_backend.set(&prod("K"), "v1").unwrap();
        std::fs::write(&kt_age, "").unwrap();
        assert!(matches!(
            age_backend.get(&prod("K")),
            Err(SecretError::Crypto(_))
        ));
        std::fs::remove_file(&kt_age).unwrap();
        assert!(matches!(
            age_backend.get(&prod("K")),
            Err(SecretError::Crypto(_))
        ));

        // 2. Bound EnvelopeVaultBackend fails closed if KT is emptied or deleted.
        let kt_env = state.join("kt-env.jsonl");
        let env_vault = state.join("vault.envelope.toml");
        let env_backend = EnvelopeVaultBackend::new(
            &env_vault,
            "acme/platform",
            Arc::new(EnvKekWrapper::from_key_bytes("kek-1", [3u8; 32])),
        )
        .with_key_transparency(&kt_env);
        env_backend.set(&prod("K"), "v2").unwrap();
        std::fs::write(&kt_env, "").unwrap();
        assert!(matches!(
            env_backend.get(&prod("K")),
            Err(SecretError::Crypto(_))
        ));
        assert!(!env_backend.status().unwrap().kt_valid);
        std::fs::remove_file(&kt_env).unwrap();
        assert!(matches!(
            env_backend.get(&prod("K")),
            Err(SecretError::Crypto(_))
        ));
        assert!(!env_backend.status().unwrap().kt_valid);
    }

    #[test]
    fn rotation_dispatcher_blocks_private_ips_and_enforces_allowed_hosts() {
        let backend = MemoryBackend::new();
        let c = prod("STRIPE_API_KEY");

        let default_disp = RotationDispatcher::default();
        for url in [
            "https://127.0.0.1:9999/hook",
            "https://169.254.169.254/latest/meta-data",
            "https://10.0.0.5/hook",
            "https://[::1]:9999/hook",
        ] {
            let receipt = default_disp.execute_dual_phase(
                &rotation_spec(url.to_owned()),
                SIGNING,
                &backend,
                &c,
                "user:alice",
                "ssrf",
                false,
                Some("x"),
            );
            assert_eq!(receipt.status, RotationStatus::Failed, "{url}");
            assert!(
                receipt.error.as_deref().unwrap_or("").contains("refusing"),
                "{url}: {:?}",
                receipt.error
            );
        }

        let strict_hosts = RotationDispatcher {
            allowed_hosts: vec!["hooks.allowed.example".to_owned()],
            ..Default::default()
        };
        let receipt = strict_hosts.execute_dual_phase(
            &rotation_spec("https://hooks.other.example/rotate".to_owned()),
            SIGNING,
            &backend,
            &c,
            "user:alice",
            "host",
            false,
            Some("x"),
        );
        assert_eq!(receipt.status, RotationStatus::Failed);
        assert!(
            receipt
                .error
                .as_deref()
                .unwrap_or("")
                .contains("allowed_hosts"),
            "{:?}",
            receipt.error
        );
    }

    #[test]
    fn kt_log_concurrent_appends_preserve_valid_hash_chain() {
        let dir = tempfile::tempdir().unwrap();
        let log_path = dir.path().join("kt.jsonl");
        std::thread::scope(|s| {
            for t in 0..8 {
                let p = log_path.clone();
                s.spawn(move || {
                    let log = KeyTransparencyLog::open(&p);
                    for i in 0..5 {
                        log.append_binding(
                            "acme/platform",
                            "vault.toml",
                            &[format!("age1worker{t}item{i}")],
                            "worker",
                            "test",
                        )
                        .unwrap();
                    }
                });
            }
        });
        let report = KeyTransparencyLog::open(&log_path).verify_chain().unwrap();
        assert!(report.valid);
        assert_eq!(report.entry_count, 40);
    }

    #[test]
    fn wave_a_ipv6_ssrf_ranges_and_envelope_aad_binding() {
        let backend = MemoryBackend::new();
        let c = prod("STRIPE_API_KEY");
        let disp = RotationDispatcher::default();
        for url in [
            "https://[64:ff9b::127.0.0.1]/hook",
            "https://[64:ff9b:1::1]/hook",
            "https://[2002:7f00:1::1]/hook",
            "https://[100::1]/hook",
        ] {
            let receipt = disp.execute_dual_phase(
                &rotation_spec(url.to_owned()),
                SIGNING,
                &backend,
                &c,
                "user:alice",
                "ssrf-v6",
                false,
                Some("x"),
            );
            assert_eq!(receipt.status, RotationStatus::Failed, "{url}");
            assert!(
                receipt.error.as_deref().unwrap_or("").contains("refusing"),
                "{url}: {:?}",
                receipt.error
            );
        }

        // Tampering `kt_bound = true -> false` or `provider` in the vault file fails AEAD unwrap.
        let dir = tempfile::tempdir().unwrap();
        let state = dir.path().join(".premier");
        let kt_path = state.join("kt.jsonl");
        let vault_path = state.join("vault.envelope.toml");
        let wrapper = Arc::new(EnvKekWrapper::from_key_bytes("kek-aad", [5u8; 32]));
        let env = EnvelopeVaultBackend::new(&vault_path, "acme/platform", wrapper.clone())
            .with_key_transparency(&kt_path);
        env.set(&prod("TOKEN"), "super-secret").unwrap();

        let original = std::fs::read_to_string(&vault_path).unwrap();
        // Flip `kt_bound = true` -> `false` and delete KT log: must fail AEAD, never re-bootstrap!
        std::fs::remove_file(&kt_path).unwrap();
        std::fs::write(
            &vault_path,
            original.replace("kt_bound = true", "kt_bound = false"),
        )
        .unwrap();
        assert!(matches!(
            env.get(&prod("TOKEN")),
            Err(SecretError::Crypto(_))
        ));
        assert!(!kt_path.exists(), "tampered vault must not bootstrap KT");

        // Restore original + tampered provider -> fails AEAD.
        std::fs::write(
            &vault_path,
            original.replace("provider = \"env-kek\"", "provider = \"other-kms\""),
        )
        .unwrap();
        let env_no_kt = EnvelopeVaultBackend::new(&vault_path, "acme/platform", wrapper.clone());
        assert!(matches!(
            env_no_kt.get(&prod("TOKEN")),
            Err(SecretError::Crypto(_))
        ));

        // Legitimate pre-KT vault (`kt_bound = false` from creation) still bootstraps cleanly.
        let legacy_path = state.join("legacy.envelope.toml");
        let legacy_kt = state.join("legacy-kt.jsonl");
        let legacy_no_kt =
            EnvelopeVaultBackend::new(&legacy_path, "acme/platform", wrapper.clone());
        legacy_no_kt.set(&prod("TOKEN"), "legacy-val").unwrap();
        let legacy_with_kt = EnvelopeVaultBackend::new(&legacy_path, "acme/platform", wrapper)
            .with_key_transparency(&legacy_kt);
        assert_eq!(
            legacy_with_kt
                .get(&prod("TOKEN"))
                .unwrap()
                .unwrap()
                .as_str(),
            "legacy-val"
        );
        assert!(legacy_kt.exists());
    }

    #[tokio::test]
    async fn wave_a_fifo_mount_platform_and_non_fifo_protection() {
        let dir = tempfile::tempdir().unwrap();
        let existing = dir.path().join(".env");
        std::fs::write(&existing, "KEEP=me\n").unwrap();
        let vars = std::collections::BTreeMap::new();

        #[cfg(not(unix))]
        {
            assert!(matches!(
                check_fifo_mount_supported(),
                Err(SecretError::FifoUnsupportedOnPlatform)
            ));
            assert!(matches!(
                mount_fifo(&existing, &vars).await,
                Err(SecretError::FifoUnsupportedOnPlatform)
            ));
        }

        #[cfg(unix)]
        {
            assert!(check_fifo_mount_supported().is_ok());
            assert!(mount_fifo(&existing, &vars).await.is_err());
        }
        // Existing regular `.env` file must never be deleted.
        assert_eq!(std::fs::read_to_string(&existing).unwrap(), "KEEP=me\n");
    }
}
