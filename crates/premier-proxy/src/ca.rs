//! Per-session ephemeral ECDSA P-256 CA and dynamic leaf certificate generator (`rcgen` + `rustls`/`ring`).
//!
//! Never modifies the OS system trust store; scoped strictly to the launched agent process tree.

use std::collections::HashMap;
use std::sync::{Arc, RwLock};

use rcgen::{BasicConstraints, Certificate, CertificateParams, DnType, IsCa, KeyPair, SanType};
use rustls::ServerConfig;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};

use crate::ProxyError;

/// In-memory ephemeral CA used for `CONNECT` MITM on schema-declared secret hosts only.
pub struct EphemeralCa {
    ca_cert: Certificate,
    ca_key: KeyPair,
    ca_pem: String,
    leaf_cache: RwLock<HashMap<String, Arc<ServerConfig>>>,
}

fn apply_validity_window(params: &mut CertificateParams) {
    let now = std::time::SystemTime::now();
    let not_before = now
        .checked_sub(std::time::Duration::from_secs(5 * 60))
        .unwrap_or(now);
    let not_after = now + std::time::Duration::from_secs(24 * 60 * 60);
    params.not_before = not_before.into();
    params.not_after = not_after.into();
}

impl EphemeralCa {
    /// Generate a fresh in-memory ECDSA P-256 CA for this proxy session.
    pub fn generate() -> Result<Self, ProxyError> {
        let _ = rustls::crypto::ring::default_provider().install_default();

        let ca_key = KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256)
            .map_err(|e| ProxyError::Tls(format!("generate CA keypair failed: {e}")))?;

        let mut params = CertificateParams::default();
        params.is_ca = IsCa::Ca(BasicConstraints::Constrained(0));
        apply_validity_window(&mut params);
        params
            .distinguished_name
            .push(DnType::CommonName, "Premier Ephemeral Session CA");
        params
            .distinguished_name
            .push(DnType::OrganizationName, "Premier Local Proxy");

        let ca_cert = params
            .self_signed(&ca_key)
            .map_err(|e| ProxyError::Tls(format!("self-sign CA failed: {e}")))?;
        let ca_pem = ca_cert.pem();

        Ok(Self {
            ca_cert,
            ca_key,
            ca_pem,
            leaf_cache: RwLock::new(HashMap::new()),
        })
    }

    /// Public CA certificate in PEM format (safe to write to a scoped temp file for child env vars).
    pub fn ca_cert_pem(&self) -> &str {
        &self.ca_pem
    }

    /// Public CA certificate DER bytes.
    pub fn ca_cert_der(&self) -> CertificateDer<'static> {
        self.ca_cert.der().clone()
    }

    /// Return a cached `rustls::ServerConfig` signed for `host` (DNS name or IP).
    pub fn server_config_for_host(&self, host: &str) -> Result<Arc<ServerConfig>, ProxyError> {
        let normalized = host.trim().to_ascii_lowercase();
        if let Ok(guard) = self.leaf_cache.read()
            && let Some(cfg) = guard.get(&normalized)
        {
            return Ok(Arc::clone(cfg));
        }

        let leaf_key = KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256)
            .map_err(|e| ProxyError::Tls(format!("generate leaf keypair failed: {e}")))?;

        let mut params = CertificateParams::default();
        apply_validity_window(&mut params);
        params
            .distinguished_name
            .push(DnType::CommonName, normalized.clone());

        if let Ok(ip) = normalized.parse::<std::net::IpAddr>() {
            params.subject_alt_names = vec![SanType::IpAddress(ip)];
        } else {
            let ia5 = rcgen::Ia5String::try_from(normalized.clone())
                .map_err(|e| ProxyError::Tls(format!("invalid DNS SAN '{normalized}': {e}")))?;
            params.subject_alt_names = vec![SanType::DnsName(ia5)];
        }

        let leaf_cert = params
            .signed_by(&leaf_key, &self.ca_cert, &self.ca_key)
            .map_err(|e| ProxyError::Tls(format!("sign leaf cert for '{normalized}': {e}")))?;

        let cert_chain = vec![leaf_cert.der().clone(), self.ca_cert.der().clone()];
        let priv_key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(leaf_key.serialize_der()));

        let server_cfg =
            ServerConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
                .with_safe_default_protocol_versions()
                .map_err(|e| ProxyError::Tls(format!("rustls protocol versions failed: {e}")))?
                .with_no_client_auth()
                .with_single_cert(cert_chain, priv_key)
                .map_err(|e| ProxyError::Tls(format!("rustls server config failed: {e}")))?;

        let arc_cfg = Arc::new(server_cfg);
        if let Ok(mut guard) = self.leaf_cache.write() {
            guard.insert(normalized, Arc::clone(&arc_cfg));
        }
        Ok(arc_cfg)
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn ephemeral_ca_constrained_pathlen_and_bounded_leaf_succeed() {
        let ca = EphemeralCa::generate().unwrap();
        assert!(ca.ca_cert_pem().contains("BEGIN CERTIFICATE"));
        assert!(!ca.ca_cert_der().is_empty());
        let cfg = ca.server_config_for_host("api.stripe.com").unwrap();
        let cached = ca.server_config_for_host("API.STRIPE.COM").unwrap();
        assert!(Arc::ptr_eq(&cfg, &cached));
    }
}
