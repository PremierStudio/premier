//! Short-lived workload identity tokens (EdDSA/Ed25519 compact JWS, verifiable offline via the
//! public JWKS) for agents and CI, carrying the
//! delegating human (`sub`) and the acting agent (`act`) so authority stays
//! `permissions(human) ∩ permissions(agent_task)`.

use std::collections::{BTreeMap, HashMap};
use std::sync::{PoisonError, RwLock};

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64URL;
use chrono::Utc;
use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use rand::RngCore;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use crate::SecretError;

/// Default token lifetime.
pub const DEFAULT_TOKEN_TTL_SECS: u64 = 300;
/// Hard ceiling on any token lifetime.
pub const MAX_TOKEN_TTL_SECS: u64 = 3600;
/// Tolerated clock skew for `iat` in the future.
const CLOCK_SKEW_SECS: i64 = 60;

const ALG: &str = "EdDSA";

/// RFC 8693 `act` claim: the agent acting on behalf of `sub`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ActorClaim {
    pub sub: String,
    pub profile: String,
    pub task_id: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WorkloadClaims {
    pub iss: String,
    pub sub: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub act: Option<ActorClaim>,
    pub aud: Vec<String>,
    pub repo: String,
    pub branch: String,
    #[serde(default)]
    pub scope: Vec<String>,
    #[serde(default)]
    pub groups: Vec<String>,
    pub iat: i64,
    pub exp: i64,
    pub jti: String,
}

#[derive(Clone)]
pub struct IssuedWorkloadToken {
    pub token: String,
    pub claims: WorkloadClaims,
    pub kid: String,
    pub alg: String,
}

impl std::fmt::Debug for IssuedWorkloadToken {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("IssuedWorkloadToken")
            .field("token", &"[redacted]")
            .field("claims", &self.claims)
            .field("kid", &self.kid)
            .field("alg", &self.alg)
            .finish()
    }
}

/// What to put in a token; `ttl_secs` defaults to the issuer's TTL and is clamped `1..=3600`.
#[derive(Debug, Clone, Default)]
pub struct WorkloadTokenRequest {
    pub sub: String,
    pub act: Option<ActorClaim>,
    pub aud: Vec<String>,
    pub repo: String,
    pub branch: String,
    pub scope: Vec<String>,
    pub groups: Vec<String>,
    pub ttl_secs: Option<u64>,
}

#[derive(Serialize, Deserialize)]
struct JwsHeader {
    alg: String,
    #[serde(default)]
    typ: Option<String>,
    #[serde(default)]
    kid: Option<String>,
}

/// EdDSA (Ed25519) workload token issuer/verifier with in-memory revocation.
pub struct OidcTokenIssuer {
    issuer: String,
    kid: String,
    // `SigningKey` zeroizes its secret scalar on drop (ed25519-dalek `zeroize` feature).
    signing_key: SigningKey,
    verifying_key: VerifyingKey,
    default_ttl_secs: u64,
    /// principal -> revoked-at (unix secs).
    revoked_principals: RwLock<HashMap<String, i64>>,
    /// jti -> expiry (unix secs); entries past expiry are pruned.
    revoked_jtis: RwLock<HashMap<String, i64>>,
}

fn b64_json<T: Serialize>(value: &T) -> Result<String, SecretError> {
    serde_json::to_vec(value)
        .map(|v| B64URL.encode(v))
        .map_err(|e| SecretError::Backend(format!("encode token failed: {e}")))
}

fn invalid(reason: &str) -> SecretError {
    SecretError::Crypto(format!("workload token rejected: {reason}"))
}

impl OidcTokenIssuer {
    /// `key` is the 32-byte Ed25519 seed; a legacy HS256 `oidc.key` is simply reused as a seed.
    pub fn new(issuer: impl Into<String>, key: [u8; 32]) -> Self {
        let key = Zeroizing::new(key);
        let signing_key = SigningKey::from_bytes(&key);
        let verifying_key = signing_key.verifying_key();
        let digest = hex::encode(Sha256::digest(verifying_key.as_bytes()));
        Self {
            issuer: issuer.into(),
            kid: format!("ed25519-{}", &digest[..16]),
            signing_key,
            verifying_key,
            default_ttl_secs: DEFAULT_TOKEN_TTL_SECS,
            revoked_principals: RwLock::default(),
            revoked_jtis: RwLock::default(),
        }
    }

    /// Issuer with a fresh random signing key.
    pub fn generate(issuer: impl Into<String>) -> Self {
        let mut key = Zeroizing::new([0u8; 32]);
        rand::thread_rng().fill_bytes(&mut *key);
        Self::new(issuer, *key)
    }

    pub fn with_default_ttl_secs(mut self, ttl_secs: u64) -> Self {
        self.default_ttl_secs = ttl_secs.clamp(1, MAX_TOKEN_TTL_SECS);
        self
    }

    pub fn issuer(&self) -> &str {
        &self.issuer
    }

    pub fn kid(&self) -> &str {
        &self.kid
    }

    /// The 32-byte Ed25519 public key (the JWK `x`).
    pub fn public_key_bytes(&self) -> [u8; 32] {
        self.verifying_key.to_bytes()
    }

    /// Public JWK Set (RFC 7517/8037) for offline verification; no secret material.
    pub fn jwks(&self) -> serde_json::Value {
        serde_json::json!({
            "keys": [{
                "kty": "OKP",
                "crv": "Ed25519",
                "alg": ALG,
                "use": "sig",
                "kid": self.kid,
                "x": B64URL.encode(self.public_key_bytes()),
            }]
        })
    }

    pub fn issue(&self, req: WorkloadTokenRequest) -> Result<IssuedWorkloadToken, SecretError> {
        if req.sub.trim().is_empty() {
            return Err(SecretError::Backend(
                "workload token subject must not be empty".to_owned(),
            ));
        }
        if req.aud.is_empty() {
            return Err(SecretError::Backend(
                "workload token needs at least one audience".to_owned(),
            ));
        }
        let ttl = req
            .ttl_secs
            .unwrap_or(self.default_ttl_secs)
            .clamp(1, MAX_TOKEN_TTL_SECS);
        let now = Utc::now().timestamp();
        let mut jti = [0u8; 16];
        rand::thread_rng().fill_bytes(&mut jti);
        let claims = WorkloadClaims {
            iss: self.issuer.clone(),
            sub: req.sub,
            act: req.act,
            aud: req.aud,
            repo: req.repo,
            branch: req.branch,
            scope: req.scope,
            groups: req.groups,
            iat: now,
            // ttl <= 3600, so the cast cannot truncate.
            exp: now + ttl as i64,
            jti: hex::encode(jti),
        };
        let header = JwsHeader {
            alg: ALG.to_owned(),
            typ: Some("JWT".to_owned()),
            kid: Some(self.kid.clone()),
        };
        let signing_input = format!("{}.{}", b64_json(&header)?, b64_json(&claims)?);
        let sig = B64URL.encode(self.signing_key.sign(signing_input.as_bytes()).to_bytes());
        Ok(IssuedWorkloadToken {
            token: format!("{signing_input}.{sig}"),
            claims,
            kid: self.kid.clone(),
            alg: ALG.to_owned(),
        })
    }

    pub fn verify(
        &self,
        token: &str,
        expected_audience: &str,
    ) -> Result<WorkloadClaims, SecretError> {
        self.verify_at(token, expected_audience, Utc::now().timestamp())
    }

    /// [`Self::verify`] against an explicit clock (unix seconds).
    pub fn verify_at(
        &self,
        token: &str,
        expected_audience: &str,
        now: i64,
    ) -> Result<WorkloadClaims, SecretError> {
        let mut parts = token.trim().split('.');
        let (Some(h64), Some(c64), Some(s64), None) =
            (parts.next(), parts.next(), parts.next(), parts.next())
        else {
            return Err(invalid("not a compact JWS"));
        };
        let header: JwsHeader = B64URL
            .decode(h64)
            .ok()
            .and_then(|b| serde_json::from_slice(&b).ok())
            .ok_or_else(|| invalid("malformed header"))?;
        if header.alg != ALG {
            return Err(invalid("unsupported alg"));
        }
        if header.kid.as_deref().is_some_and(|k| k != self.kid) {
            return Err(invalid("unknown kid"));
        }
        let sig = B64URL
            .decode(s64)
            .map_err(|_| invalid("malformed signature"))?;
        let sig = Signature::from_slice(&sig).map_err(|_| invalid("malformed signature"))?;
        self.verifying_key
            .verify_strict(format!("{h64}.{c64}").as_bytes(), &sig)
            .map_err(|_| invalid("bad signature"))?;
        let claims: WorkloadClaims = B64URL
            .decode(c64)
            .ok()
            .and_then(|b| serde_json::from_slice(&b).ok())
            .ok_or_else(|| invalid("malformed claims"))?;
        if claims.iss != self.issuer {
            return Err(invalid("wrong issuer"));
        }
        if now >= claims.exp {
            return Err(invalid("expired"));
        }
        if claims.iat > now + CLOCK_SKEW_SECS || claims.exp - claims.iat > MAX_TOKEN_TTL_SECS as i64
        {
            return Err(invalid("implausible lifetime"));
        }
        if !claims.aud.iter().any(|a| a == expected_audience) {
            return Err(invalid("wrong audience"));
        }
        if self
            .revoked_jtis
            .read()
            .unwrap_or_else(PoisonError::into_inner)
            .get(&claims.jti)
            .is_some_and(|&exp| exp > now)
        {
            return Err(invalid("revoked"));
        }
        let principals = self
            .revoked_principals
            .read()
            .unwrap_or_else(PoisonError::into_inner);
        let is_revoked = |p: &str| principals.get(p).is_some_and(|&at| claims.iat <= at);
        if is_revoked(&claims.sub) || claims.act.as_ref().is_some_and(|a| is_revoked(&a.sub)) {
            return Err(invalid("principal revoked"));
        }
        drop(principals);
        Ok(claims)
    }

    /// Reject every token whose `sub` or `act.sub` is `principal` issued at or before `Utc::now()`
    /// (e.g. on offboarding), while allowing fresh tokens minted after re-enablement.
    pub fn revoke_principal(&self, principal: &str) {
        self.revoke_principal_at(principal, Utc::now().timestamp());
    }

    /// Reject tokens for `principal` whose `iat <= revoked_at`.
    pub fn revoke_principal_at(&self, principal: &str, revoked_at: i64) {
        let mut guard = self
            .revoked_principals
            .write()
            .unwrap_or_else(PoisonError::into_inner);
        guard
            .entry(principal.to_owned())
            .and_modify(|prev| *prev = (*prev).max(revoked_at))
            .or_insert(revoked_at);
    }

    /// Revoke `jti` for the longest any token can live.
    pub fn revoke_jti(&self, jti: &str) {
        let now = Utc::now().timestamp();
        self.revoke_jti_until(jti, now + MAX_TOKEN_TTL_SECS as i64);
    }

    /// Revoke `jti` until `expires_at` (unix secs, normally the token's `exp`). Expired entries
    /// are pruned on insert so the set stays bounded.
    pub fn revoke_jti_until(&self, jti: &str, expires_at: i64) {
        let mut guard = self
            .revoked_jtis
            .write()
            .unwrap_or_else(PoisonError::into_inner);
        let now = Utc::now().timestamp();
        guard.retain(|_, exp| *exp > now);
        guard
            .entry(jti.to_owned())
            .and_modify(|prev| *prev = (*prev).max(expires_at))
            .or_insert(expires_at);
    }

    /// Drop JTI revocations with `exp <= now` and principal revocations older than any live token.
    pub fn prune_revoked(&self, now: i64) {
        self.revoked_jtis
            .write()
            .unwrap_or_else(PoisonError::into_inner)
            .retain(|_, exp| *exp > now);
        self.revoked_principals
            .write()
            .unwrap_or_else(PoisonError::into_inner)
            .retain(|_, at| now - *at <= MAX_TOKEN_TTL_SECS as i64);
    }

    /// Non-expired JTI revocations (`jti -> expires_at`), for persistence.
    pub fn revoked_jtis_snapshot(&self, now: i64) -> BTreeMap<String, i64> {
        self.revoked_jtis
            .read()
            .unwrap_or_else(PoisonError::into_inner)
            .iter()
            .filter(|(_, exp)| **exp > now)
            .map(|(j, exp)| (j.clone(), *exp))
            .collect()
    }

    /// OpenID-style discovery metadata (no secret key material; keys are at `jwks_uri`).
    pub fn discovery_document(&self) -> serde_json::Value {
        let iss = self.issuer.trim_end_matches('/');
        serde_json::json!({
            "issuer": self.issuer,
            "token_endpoint": format!("{iss}/v1/oidc/token"),
            "response_types_supported": ["id_token"],
            "subject_types_supported": ["public"],
            "jwks_uri": format!("{iss}/.well-known/jwks.json"),
            "id_token_signing_alg_values_supported": [ALG],
            "token_ttl_default_secs": self.default_ttl_secs,
            "token_ttl_max_secs": MAX_TOKEN_TTL_SECS,
            "kid": self.kid,
            "claims_supported": [
                "iss", "sub", "act", "aud", "repo", "branch", "scope", "groups", "iat", "exp", "jti"
            ],
        })
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    fn req() -> WorkloadTokenRequest {
        WorkloadTokenRequest {
            sub: "user:alice".to_owned(),
            aud: vec!["premier".to_owned()],
            repo: "acme/x".to_owned(),
            branch: "main".to_owned(),
            ..WorkloadTokenRequest::default()
        }
    }

    fn issuer() -> OidcTokenIssuer {
        OidcTokenIssuer::new("https://premier.example/", [7u8; 32])
    }

    /// Re-sign `h.c` with an arbitrary header to test header validation.
    fn resign(iss: &OidcTokenIssuer, header: &str, token: &str) -> String {
        let c64 = token.split('.').nth(1).unwrap();
        let h64 = B64URL.encode(header);
        let input = format!("{h64}.{c64}");
        let sig = B64URL.encode(iss.signing_key.sign(input.as_bytes()).to_bytes());
        format!("{input}.{sig}")
    }

    #[test]
    fn eddsa_sign_verify_and_external_jwks_verification() {
        let iss = issuer();
        let t = iss.issue(req()).unwrap();
        assert_eq!(t.alg, "EdDSA");
        assert!(t.kid.starts_with("ed25519-"));
        assert_eq!(t.kid.len(), "ed25519-".len() + 16);
        assert_eq!(iss.verify(&t.token, "premier").unwrap(), t.claims);

        let jwks = iss.jwks();
        let jwk = &jwks["keys"][0];
        assert_eq!(jwks["keys"].as_array().unwrap().len(), 1);
        for (k, v) in [
            ("kty", "OKP"),
            ("crv", "Ed25519"),
            ("alg", "EdDSA"),
            ("use", "sig"),
        ] {
            assert_eq!(jwk[k], v);
        }
        assert_eq!(jwk["kid"], iss.kid());
        assert!(jwk.get("d").is_none());
        // An independent verifier using only the published `x` accepts the signature.
        let x: [u8; 32] = B64URL
            .decode(jwk["x"].as_str().unwrap())
            .unwrap()
            .try_into()
            .unwrap();
        assert_eq!(x, iss.public_key_bytes());
        let vk = VerifyingKey::from_bytes(&x).unwrap();
        let (input, sig) = t.token.rsplit_once('.').unwrap();
        let sig = Signature::from_slice(&B64URL.decode(sig).unwrap()).unwrap();
        vk.verify_strict(input.as_bytes(), &sig).unwrap();
        // Header advertises EdDSA + kid.
        let header: serde_json::Value =
            serde_json::from_slice(&B64URL.decode(input.split('.').next().unwrap()).unwrap())
                .unwrap();
        assert_eq!(header["alg"], "EdDSA");
        assert_eq!(header["kid"], iss.kid());
    }

    #[test]
    fn discovery_advertises_eddsa_and_jwks_uri() {
        let doc = issuer().discovery_document();
        assert_eq!(
            doc["id_token_signing_alg_values_supported"],
            serde_json::json!(["EdDSA"])
        );
        assert_eq!(
            doc["jwks_uri"],
            "https://premier.example/.well-known/jwks.json"
        );
    }

    #[test]
    fn kid_mismatch_alg_and_foreign_key_are_rejected() {
        let iss = issuer();
        let t = iss.issue(req()).unwrap();
        let bad_kid = resign(
            &iss,
            r#"{"alg":"EdDSA","typ":"JWT","kid":"nope"}"#,
            &t.token,
        );
        assert!(iss.verify(&bad_kid, "premier").is_err());
        // No kid is tolerated; correct kid is accepted.
        let no_kid = resign(&iss, r#"{"alg":"EdDSA","typ":"JWT"}"#, &t.token);
        assert!(iss.verify(&no_kid, "premier").is_ok());
        for alg in ["HS256", "none", "RS256", "ES256"] {
            let h = format!(r#"{{"alg":"{alg}","typ":"JWT","kid":"{}"}}"#, iss.kid());
            assert!(
                iss.verify(&resign(&iss, &h, &t.token), "premier").is_err(),
                "{alg}"
            );
        }
        let other = OidcTokenIssuer::new("https://premier.example/", [8u8; 32]);
        assert!(other.verify(&t.token, "premier").is_err());
        // Truncated / wrong-length signature.
        let (input, _) = t.token.rsplit_once('.').unwrap();
        assert!(
            iss.verify(&format!("{input}.{}", B64URL.encode([0u8; 10])), "premier")
                .is_err()
        );
        assert!(
            iss.verify(&format!("{input}.{}", B64URL.encode([0u8; 64])), "premier")
                .is_err()
        );
    }

    #[test]
    fn legacy_32_byte_key_upgrades_deterministically() {
        let (a, b) = (issuer(), issuer());
        assert_eq!(a.kid(), b.kid());
        assert_eq!(a.public_key_bytes(), b.public_key_bytes());
        assert_eq!(
            a.public_key_bytes(),
            SigningKey::from_bytes(&[7u8; 32])
                .verifying_key()
                .to_bytes()
        );
        let t = a.issue(req()).unwrap();
        assert!(b.verify(&t.token, "premier").is_ok());
    }

    #[test]
    fn jti_revocation_expires_and_prunes() {
        let iss = issuer();
        let now = Utc::now().timestamp();
        let t = iss.issue(req()).unwrap();
        iss.revoke_jti_until(&t.claims.jti, t.claims.exp);
        assert!(iss.verify(&t.token, "premier").is_err());
        assert_eq!(
            iss.revoked_jtis_snapshot(now).get(&t.claims.jti),
            Some(&t.claims.exp)
        );

        // Default expiry covers the max token lifetime.
        iss.revoke_jti("default");
        assert!(iss.revoked_jtis_snapshot(now)["default"] >= now + MAX_TOKEN_TTL_SECS as i64);

        // Already-expired entries are never reported and are pruned on the next insert.
        iss.revoke_jti_until("stale", now - 10);
        assert!(!iss.revoked_jtis_snapshot(now).contains_key("stale"));
        assert_eq!(iss.revoked_jtis.read().unwrap().len(), 3);
        iss.revoke_jti_until("fresh", now + 100);
        assert!(!iss.revoked_jtis.read().unwrap().contains_key("stale"));

        // prune_revoked drops expired JTIs and aged-out principal revocations.
        iss.revoke_principal_at("old", now - MAX_TOKEN_TTL_SECS as i64 - 5);
        iss.revoke_principal_at("recent", now);
        iss.prune_revoked(now + 200);
        let snap = iss.revoked_jtis_snapshot(now);
        assert!(!snap.contains_key("fresh") && snap.contains_key("default"));
        let principals = iss.revoked_principals.read().unwrap();
        assert!(!principals.contains_key("old") && principals.contains_key("recent"));
    }
}
