//! External secret-manager connectors (HashiCorp Vault KV v2, 1Password Connect) and a
//! primary + read-through fallback composite. All calls go over verified TLS.

use std::sync::Arc;

use http::Method;
use rustls::pki_types::CertificateDer;
use serde::Deserialize;
use url::Url;
use zeroize::Zeroizing;

use crate::SecretError;
use crate::backend::{SecretBackend, SecretCoord, SecretLayer};
use crate::kms::{
    HttpRequest, HttpResponse, http_json_request, join_url, validate_base_url,
    validate_path_segments,
};
use crate::redactor::percent_encode_component;

fn layer_slug(layer: SecretLayer) -> &'static str {
    match layer {
        SecretLayer::Org => "org",
        SecretLayer::Repo => "repo",
        SecretLayer::Zone => "zone",
        SecretLayer::Env => "env",
        SecretLayer::Branch => "branch",
        SecretLayer::Personal => "personal",
    }
}

/// One percent-encoded path segment; `.`/`..`/empty are refused (they survive encoding).
fn encoded_segment(what: &str, value: &str) -> Result<String, SecretError> {
    if value.is_empty() || value == "." || value == ".." {
        return Err(SecretError::Backend(format!(
            "{what} is not a valid path segment"
        )));
    }
    Ok(percent_encode_component(value))
}

/// HashiCorp Vault KV v2 settings. `token` is never logged or serialized.
#[derive(Clone)]
pub struct VaultKvConfig {
    pub address: String,
    pub mount: String,
    /// Path under the mount, e.g. `premier/acme-platform` (may be empty).
    pub prefix: String,
    pub token: Zeroizing<String>,
    pub namespace: Option<String>,
    pub allow_insecure_loopback: bool,
    pub extra_root_certs: Vec<CertificateDer<'static>>,
}

impl std::fmt::Debug for VaultKvConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("VaultKvConfig")
            .field("address", &self.address)
            .field("mount", &self.mount)
            .field("prefix", &self.prefix)
            .field("token", &"[redacted]")
            .field("namespace", &self.namespace)
            .field("allow_insecure_loopback", &self.allow_insecure_loopback)
            .finish()
    }
}

/// Vault KV v2 backend at `/v1/{mount}/data/{prefix}/{layer}/{scope}/{var_name}`, field `value`.
#[derive(Debug)]
pub struct VaultKvConnector {
    base: Url,
    config: VaultKvConfig,
}

#[derive(Deserialize)]
struct KvReadResponse {
    data: KvReadData,
}

#[derive(Deserialize)]
struct KvReadData {
    data: Option<KvValue>,
}

#[derive(Deserialize)]
struct KvValue {
    value: Option<String>,
}

impl VaultKvConnector {
    pub fn new(config: VaultKvConfig) -> Result<Self, SecretError> {
        validate_path_segments("vault kv mount", &config.mount, true)?;
        if !config.prefix.is_empty() {
            validate_path_segments("vault kv prefix", &config.prefix, true)?;
        }
        if let Some(ns) = &config.namespace {
            validate_path_segments("vault namespace", ns, true)?;
        }
        if config.token.trim().is_empty() {
            return Err(SecretError::Backend(
                "vault kv token must not be empty".to_owned(),
            ));
        }
        let base = validate_base_url(&config.address, config.allow_insecure_loopback)?;
        Ok(Self { base, config })
    }

    fn data_url(&self, coord: &SecretCoord) -> Result<String, SecretError> {
        let prefix = if self.config.prefix.is_empty() {
            String::new()
        } else {
            format!("{}/", self.config.prefix)
        };
        Ok(join_url(
            &self.base,
            &format!(
                "/v1/{}/data/{prefix}{}/{}/{}/{}",
                self.config.mount,
                encoded_segment("repo_id", &coord.repo_id)?,
                layer_slug(coord.layer),
                encoded_segment("scope", &coord.scope)?,
                encoded_segment("var_name", &coord.var_name)?,
            ),
        ))
    }

    fn send(
        &self,
        method: Method,
        coord: &SecretCoord,
        body: Option<Zeroizing<Vec<u8>>>,
    ) -> Result<HttpResponse, SecretError> {
        let mut headers = vec![("X-Vault-Token", self.config.token.clone())];
        if let Some(ns) = &self.config.namespace {
            headers.push(("X-Vault-Namespace", Zeroizing::new(ns.clone())));
        }
        http_json_request(HttpRequest {
            method,
            url: self.data_url(coord)?,
            headers,
            body,
            allow_insecure_loopback: self.config.allow_insecure_loopback,
            block_private_ips: false,
            extra_root_certs: self.config.extra_root_certs.clone(),
        })
    }
}

impl SecretBackend for VaultKvConnector {
    fn name(&self) -> &str {
        "vault-kv-v2"
    }

    fn get(&self, coord: &SecretCoord) -> Result<Option<Zeroizing<String>>, SecretError> {
        let resp = self.send(Method::GET, coord, None)?;
        if resp.status == 404 {
            return Ok(None);
        }
        if !resp.is_success() {
            return Err(SecretError::Backend(format!(
                "Vault KV read failed with HTTP {}",
                resp.status
            )));
        }
        let parsed: KvReadResponse = resp.json("Vault KV")?;
        Ok(parsed.data.data.and_then(|d| d.value).map(Zeroizing::new))
    }

    fn set(&self, coord: &SecretCoord, value: &str) -> Result<(), SecretError> {
        let value_json = Zeroizing::new(
            serde_json::to_string(value)
                .map_err(|e| SecretError::Backend(format!("encode KV value failed: {e}")))?,
        );
        let body = Zeroizing::new(
            format!(r#"{{"data":{{"value":{}}}}}"#, value_json.as_str()).into_bytes(),
        );
        let resp = self.send(Method::POST, coord, Some(body))?;
        if !resp.is_success() {
            return Err(SecretError::Backend(format!(
                "Vault KV write failed with HTTP {}",
                resp.status
            )));
        }
        Ok(())
    }

    /// Soft-deletes the latest version (recoverable in Vault; reads then return `None`).
    fn delete(&self, coord: &SecretCoord) -> Result<(), SecretError> {
        let resp = self.send(Method::DELETE, coord, None)?;
        if !resp.is_success() && resp.status != 404 {
            return Err(SecretError::Backend(format!(
                "Vault KV delete failed with HTTP {}",
                resp.status
            )));
        }
        Ok(())
    }
}

/// 1Password Connect settings. `token` is never logged or serialized.
#[derive(Clone)]
pub struct OnePasswordConnectConfig {
    pub host: String,
    pub vault_id: String,
    pub token: Zeroizing<String>,
    pub allow_insecure_loopback: bool,
    pub extra_root_certs: Vec<CertificateDer<'static>>,
}

impl std::fmt::Debug for OnePasswordConnectConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("OnePasswordConnectConfig")
            .field("host", &self.host)
            .field("vault_id", &self.vault_id)
            .field("token", &"[redacted]")
            .field("allow_insecure_loopback", &self.allow_insecure_loopback)
            .finish()
    }
}

/// Read-through 1Password Connect backend: item titled `var_name`, field labelled `var_name`
/// (else the item's password field).
// shortcut: matches on var_name only, ignoring layer/scope; use it as a CompositeSecretBackend
// fallback, and add per-layer vaults if 1Password ever becomes a primary store.
#[derive(Debug)]
pub struct OnePasswordConnectConnector {
    base: Url,
    config: OnePasswordConnectConfig,
}

#[derive(Deserialize)]
struct OpItemSummary {
    id: String,
    #[serde(default)]
    title: String,
}

#[derive(Deserialize)]
struct OpItem {
    #[serde(default)]
    fields: Vec<OpField>,
}

#[derive(Deserialize)]
struct OpField {
    #[serde(default)]
    label: Option<String>,
    #[serde(default)]
    purpose: Option<String>,
    #[serde(default)]
    value: Option<String>,
}

fn is_op_id(s: &str) -> bool {
    !s.is_empty() && s.len() <= 64 && s.bytes().all(|b| b.is_ascii_alphanumeric())
}

impl OnePasswordConnectConnector {
    pub fn new(config: OnePasswordConnectConfig) -> Result<Self, SecretError> {
        if !is_op_id(&config.vault_id) {
            return Err(SecretError::Backend(
                "1Password vault_id must be alphanumeric".to_owned(),
            ));
        }
        if config.token.trim().is_empty() {
            return Err(SecretError::Backend(
                "1Password Connect token must not be empty".to_owned(),
            ));
        }
        let base = validate_base_url(&config.host, config.allow_insecure_loopback)?;
        Ok(Self { base, config })
    }

    fn fetch(&self, path: &str) -> Result<HttpResponse, SecretError> {
        let resp = http_json_request(HttpRequest {
            method: Method::GET,
            url: join_url(&self.base, path),
            headers: vec![(
                "Authorization",
                Zeroizing::new(format!("Bearer {}", self.config.token.as_str())),
            )],
            body: None,
            allow_insecure_loopback: self.config.allow_insecure_loopback,
            block_private_ips: false,
            extra_root_certs: self.config.extra_root_certs.clone(),
        })?;
        if !resp.is_success() {
            return Err(SecretError::Backend(format!(
                "1Password Connect request failed with HTTP {}",
                resp.status
            )));
        }
        Ok(resp)
    }
}

impl SecretBackend for OnePasswordConnectConnector {
    fn name(&self) -> &str {
        "1password-connect"
    }

    fn get(&self, coord: &SecretCoord) -> Result<Option<Zeroizing<String>>, SecretError> {
        let vault = &self.config.vault_id;
        let expected_title = format!(
            "{}/{}/{}/{}",
            coord.repo_id,
            layer_slug(coord.layer),
            coord.scope,
            coord.var_name
        );
        let items: Vec<OpItemSummary> = self
            .fetch(&format!("/v1/vaults/{vault}/items"))?
            .json("1Password Connect")?;
        let Some(item) = items.iter().find(|i| i.title == expected_title) else {
            return Ok(None);
        };
        // The id comes from the server: never splice an unchecked value into the next URL.
        if !is_op_id(&item.id) {
            return Err(SecretError::Backend(
                "1Password Connect returned a malformed item id".to_owned(),
            ));
        }
        // shortcut: non-matching field values are dropped un-zeroized; parse field-by-field if
        // items ever hold many unrelated secrets.
        let detail: OpItem = self
            .fetch(&format!("/v1/vaults/{vault}/items/{}", item.id))?
            .json("1Password Connect")?;
        let by_label = detail
            .fields
            .iter()
            .position(|f| f.label.as_deref() == Some(coord.var_name.as_str()));
        let by_purpose = || {
            detail
                .fields
                .iter()
                .position(|f| f.purpose.as_deref() == Some("PASSWORD"))
        };
        let Some(idx) = by_label.or_else(by_purpose) else {
            return Ok(None);
        };
        Ok(detail
            .fields
            .into_iter()
            .nth(idx)
            .and_then(|f| f.value)
            .map(Zeroizing::new))
    }

    fn set(&self, _coord: &SecretCoord, _value: &str) -> Result<(), SecretError> {
        Err(SecretError::Backend(
            "1Password Connect connector is read-through only".to_owned(),
        ))
    }

    fn delete(&self, _coord: &SecretCoord) -> Result<(), SecretError> {
        Err(SecretError::Backend(
            "1Password Connect connector is read-through only".to_owned(),
        ))
    }
}

/// Reads `primary`, falling back to `fallback` on a miss; writes and deletes hit `primary` only.
pub struct CompositeSecretBackend {
    primary: Arc<dyn SecretBackend>,
    fallback: Arc<dyn SecretBackend>,
    name: String,
}

impl CompositeSecretBackend {
    pub fn new(primary: Arc<dyn SecretBackend>, fallback: Arc<dyn SecretBackend>) -> Self {
        let name = format!("composite({}+{})", primary.name(), fallback.name());
        Self {
            primary,
            fallback,
            name,
        }
    }
}

impl SecretBackend for CompositeSecretBackend {
    fn name(&self) -> &str {
        &self.name
    }

    fn get(&self, coord: &SecretCoord) -> Result<Option<Zeroizing<String>>, SecretError> {
        match self.primary.get(coord)? {
            Some(v) => Ok(Some(v)),
            None => self.fallback.get(coord),
        }
    }

    fn set(&self, coord: &SecretCoord, value: &str) -> Result<(), SecretError> {
        self.primary.set(coord, value)
    }

    fn delete(&self, coord: &SecretCoord) -> Result<(), SecretError> {
        self.primary.delete(coord)
    }
}
