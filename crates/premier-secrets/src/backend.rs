//! Pluggable secret storage backends, sovereign `age`/AEAD vault, and hierarchical resolver.

use std::collections::{BTreeMap, HashMap};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{PoisonError, RwLock};

use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::{Aes256Gcm, Nonce};
use base64::Engine;
use base64::engine::general_purpose::STANDARD as B64;
use premier_core::{Capability, DelegatedIdentity, Environment};
use premier_policy::CompiledPolicy;
use rand::RngCore;
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use crate::SecretError;
use crate::key_transparency::{KeyTransparencyLog, acquire_path_lock, normalize_recipients};
use crate::schema::{EnvSchema, Sensitivity};

/// `age`-encrypt `plaintext` to every recipient.
pub(crate) fn age_wrap(
    recipients: &[age::x25519::Recipient],
    plaintext: &[u8],
) -> Result<Vec<u8>, SecretError> {
    let encryptor =
        age::Encryptor::with_recipients(recipients.iter().map(|r| r as &dyn age::Recipient))
            .map_err(|e| SecretError::Crypto(format!("age encryptor init failed: {e}")))?;
    let mut wrapped = Vec::new();
    let mut writer = encryptor
        .wrap_output(&mut wrapped)
        .map_err(|e| SecretError::Crypto(format!("age wrap failed: {e}")))?;
    writer
        .write_all(plaintext)
        .map_err(|e| SecretError::Crypto(format!("age write failed: {e}")))?;
    writer
        .finish()
        .map_err(|e| SecretError::Crypto(format!("age finish failed: {e}")))?;
    Ok(wrapped)
}

/// Decrypt an `age` payload with `identity`.
pub(crate) fn age_unwrap(
    identity: &age::x25519::Identity,
    wrapped: &[u8],
) -> Result<Zeroizing<Vec<u8>>, SecretError> {
    let decryptor = age::Decryptor::new(wrapped)
        .map_err(|e| SecretError::Crypto(format!("age decryptor init failed: {e}")))?;
    let mut reader = decryptor
        .decrypt(std::iter::once(identity as &dyn age::Identity))
        .map_err(|e| SecretError::Crypto(format!("age DEK unwrap failed: {e}")))?;
    let mut out = Zeroizing::new(Vec::new());
    reader
        .read_to_end(&mut out)
        .map_err(|e| SecretError::Crypto(format!("age DEK read failed: {e}")))?;
    Ok(out)
}

/// `create_dir_all`, and for Premier's own state directories (`.premier`, `.premier-local`) a
/// `.gitignore` of `*` inside, so `git add -A` in the hosted repository never stages the auth
/// store, vault key or audit log. Idempotent; an existing `.gitignore` is left alone.
pub fn create_state_dir(dir: &Path) -> std::io::Result<()> {
    std::fs::create_dir_all(dir)?;
    let ignore = dir.join(".gitignore");
    let ours = dir
        .file_name()
        .is_some_and(|n| n == ".premier" || n == ".premier-local");
    if ours && !ignore.exists() {
        std::fs::write(
            ignore, "*
",
        )?;
    }
    Ok(())
}

/// Write a file that holds server secrets (keys, vault, account and state stores), owner-only
/// (0600) on unix.
// shortcut: on Windows the file only inherits its directory's ACL, tighten it explicitly if the
// workspace ever lives somewhere other users can read.
pub fn write_private(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    let mut opts = std::fs::OpenOptions::new();
    opts.write(true).create(true).truncate(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }
    let mut file = opts.open(path)?;
    // `mode` only applies on creation: tighten a file that predates this.
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        file.set_permissions(std::fs::Permissions::from_mode(0o600))?;
    }
    file.write_all(bytes)?;
    file.sync_all()
}

/// Hierarchical inheritance layer (lowest to highest precedence).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SecretLayer {
    Org,
    Repo,
    Zone,
    Env,
    Branch,
    Personal,
}

/// Scoped key identifying a secret in a backend.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct SecretCoord {
    pub repo_id: String,
    pub layer: SecretLayer,
    pub scope: String,
    pub var_name: String,
}

impl SecretCoord {
    pub fn storage_key(&self) -> String {
        format!(
            "{}:{:?}:{}:{}",
            self.repo_id, self.layer, self.scope, self.var_name
        )
    }
}

/// Non-secret provenance metadata describing where a resolved value came from.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ValueProvenance {
    pub var_name: String,
    pub layer: SecretLayer,
    pub backend: String,
    pub sensitivity: Sensitivity,
}

/// Pluggable secret backend trait (OS Keychain, KMS/OIDC, Sovereign `age` AEAD, or Memory).
pub trait SecretBackend: Send + Sync {
    fn name(&self) -> &str;
    fn get(&self, coord: &SecretCoord) -> Result<Option<Zeroizing<String>>, SecretError>;
    fn set(&self, coord: &SecretCoord, value: &str) -> Result<(), SecretError>;
    fn delete(&self, coord: &SecretCoord) -> Result<(), SecretError>;
}

/// In-memory zeroizing backend (tests and ephemeral sessions).
#[derive(Debug, Default)]
pub struct MemoryBackend {
    values: RwLock<HashMap<String, Zeroizing<String>>>,
}

impl MemoryBackend {
    pub fn new() -> Self {
        Self::default()
    }
}

impl SecretBackend for MemoryBackend {
    fn name(&self) -> &str {
        "memory"
    }

    fn get(&self, coord: &SecretCoord) -> Result<Option<Zeroizing<String>>, SecretError> {
        let guard = self
            .values
            .read()
            .map_err(|_| SecretError::Backend("memory backend lock poisoned".to_owned()))?;
        Ok(guard.get(&coord.storage_key()).cloned())
    }

    fn set(&self, coord: &SecretCoord, value: &str) -> Result<(), SecretError> {
        let mut guard = self
            .values
            .write()
            .map_err(|_| SecretError::Backend("memory backend lock poisoned".to_owned()))?;
        guard.insert(coord.storage_key(), Zeroizing::new(value.to_owned()));
        Ok(())
    }

    fn delete(&self, coord: &SecretCoord) -> Result<(), SecretError> {
        let mut guard = self
            .values
            .write()
            .map_err(|_| SecretError::Backend("memory backend lock poisoned".to_owned()))?;
        guard.remove(&coord.storage_key());
        Ok(())
    }
}

/// Native OS Keychain backend (Windows Credential Manager / macOS Keychain / Linux keyutils).
#[derive(Debug, Clone)]
pub struct KeychainBackend {
    service_prefix: String,
}

impl KeychainBackend {
    pub fn new(service_prefix: impl Into<String>) -> Self {
        Self {
            service_prefix: service_prefix.into(),
        }
    }

    fn entry_for(&self, coord: &SecretCoord) -> Result<keyring::Entry, SecretError> {
        let service = format!("{}:{}", self.service_prefix, coord.repo_id);
        let account = format!("{:?}:{}:{}", coord.layer, coord.scope, coord.var_name);
        keyring::Entry::new(&service, &account)
            .map_err(|e| SecretError::Backend(format!("keychain entry error: {e}")))
    }
}

impl SecretBackend for KeychainBackend {
    fn name(&self) -> &str {
        "os-keychain"
    }

    fn get(&self, coord: &SecretCoord) -> Result<Option<Zeroizing<String>>, SecretError> {
        let entry = self.entry_for(coord)?;
        match entry.get_password() {
            Ok(v) => Ok(Some(Zeroizing::new(v))),
            Err(keyring::Error::NoEntry) => Ok(None),
            Err(e) => Err(SecretError::Backend(format!("keychain get failed: {e}"))),
        }
    }

    fn set(&self, coord: &SecretCoord, value: &str) -> Result<(), SecretError> {
        let entry = self.entry_for(coord)?;
        entry
            .set_password(value)
            .map_err(|e| SecretError::Backend(format!("keychain set failed: {e}")))
    }

    fn delete(&self, coord: &SecretCoord) -> Result<(), SecretError> {
        let entry = self.entry_for(coord)?;
        match entry.delete_credential() {
            Ok(()) | Err(keyring::Error::NoEntry) => Ok(()),
            Err(e) => Err(SecretError::Backend(format!("keychain delete failed: {e}"))),
        }
    }
}

/// Sovereign / Air-Gapped Format-Preserving AEAD Vault (`age` + AES-256-GCM with path+key AAD).
///
/// Keys remain readable in TOML/JSON for PR diffability while every value is independently
/// authenticated with `AAD = "premier-aead-v1:{repo_id}:{vault_path}:{key}"`, preventing
/// cross-key or cross-file ciphertext transplantation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgeSovereignVaultFile {
    pub version: u32,
    pub repo_id: String,
    /// `age`-armored DEK wrapped to one or more X25519 recipients.
    pub wrapped_dek_age_b64: String,
    /// Plaintext variable names mapped to `nonce_b64:ciphertext_b64`.
    pub entries: BTreeMap<String, String>,
    /// Sorted `age` public keys the DEK is wrapped to (checked against Key Transparency).
    #[serde(default)]
    pub recipients: Vec<String>,
}

static TMP_SEQ: AtomicU64 = AtomicU64::new(0);

/// Sovereign `age` + AES-256-GCM backend operating on a local vault file.
pub struct AgeSovereignBackend {
    vault_path: PathBuf,
    repo_id: String,
    logical_path: String,
    identity: age::x25519::Identity,
    recipients: Vec<age::x25519::Recipient>,
    kt_log_path: Option<PathBuf>,
}

impl AgeSovereignBackend {
    pub fn new(
        vault_path: impl AsRef<Path>,
        repo_id: impl Into<String>,
        logical_path: impl Into<String>,
        identity: age::x25519::Identity,
        extra_recipients: Vec<age::x25519::Recipient>,
    ) -> Self {
        let mut recipients = vec![identity.to_public()];
        recipients.extend(extra_recipients);
        Self {
            vault_path: vault_path.as_ref().to_path_buf(),
            repo_id: repo_id.into(),
            logical_path: logical_path.into(),
            identity,
            recipients,
            kt_log_path: None,
        }
    }

    /// Bind this vault's recipients into an append-only Key Transparency log and fail closed
    /// whenever an existing vault's recipients drift from the latest binding.
    pub fn with_key_transparency(mut self, kt_log_path: impl Into<PathBuf>) -> Self {
        self.kt_log_path = Some(kt_log_path.into());
        self
    }

    /// Sorted, deduplicated `age` public keys the DEK is wrapped to.
    pub fn recipient_public_keys(&self) -> Vec<String> {
        normalize_recipients(
            &self
                .recipients
                .iter()
                .map(ToString::to_string)
                .collect::<Vec<_>>(),
        )
    }

    /// Decrypt every entry (storage key -> value), e.g. to migrate to an Envelope KMS vault.
    pub fn list_entries(&self) -> Result<BTreeMap<String, Zeroizing<String>>, SecretError> {
        let lock = acquire_path_lock(&self.vault_path);
        let _guard = lock.lock().unwrap_or_else(PoisonError::into_inner);
        if !self.vault_path.exists() {
            return Ok(BTreeMap::new());
        }
        let (vault, dek) = self.load_or_init()?;
        vault
            .entries
            .iter()
            .map(|(k, enc)| Ok((k.clone(), self.decrypt_value(&dek, k, enc)?)))
            .collect()
    }

    fn verify_key_transparency(&self, vault: &AgeSovereignVaultFile) -> Result<(), SecretError> {
        let Some(kt_path) = &self.kt_log_path else {
            return Ok(());
        };
        let ours = self.recipient_public_keys();
        if !vault.recipients.is_empty() && normalize_recipients(&vault.recipients) != ours {
            return Err(SecretError::Crypto(
                "vault recipients differ from the configured recipients; possible silent public-key swap"
                    .to_owned(),
            ));
        }
        let kt = KeyTransparencyLog::open(kt_path);
        let report = kt.verify_vault_recipients(&self.repo_id, &ours)?;
        if report.latest_hash.is_none() {
            if !vault.recipients.is_empty() {
                return Err(SecretError::Crypto(
                    "key transparency binding missing for recipient-bound vault; possible KT log deletion or replay"
                        .to_owned(),
                ));
            }
            // Legacy pre-KT vault (no recorded recipients): trust on first use so later swaps are caught.
            kt.append_binding(
                &self.repo_id,
                &self.logical_path,
                &ours,
                "premier-secrets",
                "bootstrap",
            )?;
        }
        Ok(())
    }

    fn aad_for(&self, key: &str) -> String {
        /// Legacy v1 format tag of the vault's AEAD associated data (kept for decrypt compatibility).
        const AAD_TAG: &str = "premier-aead-v1";
        format!("{AAD_TAG}:{}:{}:{}", self.repo_id, self.logical_path, key)
    }

    fn aad_v2(&self, key: &str) -> String {
        /// Length-prefixed v2 format tag preventing delimiter collisions across components.
        const AAD_TAG_V2: &str = "premier-aead-v2";
        format!(
            "{AAD_TAG_V2}:{}:{}:{}:{}:{}:{}",
            self.repo_id.len(),
            self.repo_id,
            self.logical_path.len(),
            self.logical_path,
            key.len(),
            key
        )
    }

    fn load_or_init(&self) -> Result<(AgeSovereignVaultFile, Zeroizing<[u8; 32]>), SecretError> {
        if self.vault_path.exists() {
            let text = std::fs::read_to_string(&self.vault_path)
                .map_err(|e| SecretError::Backend(format!("read sovereign vault failed: {e}")))?;
            let vault: AgeSovereignVaultFile = toml::from_str(&text)
                .map_err(|e| SecretError::Backend(format!("parse sovereign vault failed: {e}")))?;
            if vault.repo_id != self.repo_id {
                return Err(SecretError::Crypto(format!(
                    "sovereign vault repo_id mismatch: vault belongs to '{}', expected '{}'",
                    vault.repo_id, self.repo_id
                )));
            }
            self.verify_key_transparency(&vault)?;
            let wrapped = B64
                .decode(&vault.wrapped_dek_age_b64)
                .map_err(|e| SecretError::Crypto(format!("invalid base64 DEK: {e}")))?;
            let dek_vec = age_unwrap(&self.identity, &wrapped)?;
            if dek_vec.len() != 32 {
                return Err(SecretError::Crypto(
                    "unwrapped DEK has wrong length".to_owned(),
                ));
            }
            let mut dek = Zeroizing::new([0u8; 32]);
            dek.copy_from_slice(&dek_vec);
            return Ok((vault, dek));
        }

        let mut dek = Zeroizing::new([0u8; 32]);
        rand::thread_rng().fill_bytes(&mut *dek);

        let wrapped = age_wrap(&self.recipients, &*dek)?;
        let vault = AgeSovereignVaultFile {
            version: 1,
            repo_id: self.repo_id.clone(),
            wrapped_dek_age_b64: B64.encode(&wrapped),
            entries: BTreeMap::new(),
            recipients: self.recipient_public_keys(),
        };
        Ok((vault, dek))
    }

    fn save_vault(&self, vault: &AgeSovereignVaultFile) -> Result<(), SecretError> {
        if let Some(parent) = self.vault_path.parent() {
            create_state_dir(parent)
                .map_err(|e| SecretError::Backend(format!("create vault dir failed: {e}")))?;
        }
        let text = toml::to_string_pretty(vault)
            .map_err(|e| SecretError::Backend(format!("serialize sovereign vault failed: {e}")))?;
        let seq = TMP_SEQ.fetch_add(1, Ordering::Relaxed);
        let file_name = self
            .vault_path
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("vault");
        let tmp_path = self
            .vault_path
            .with_file_name(format!(".{file_name}.tmp.{}.{seq}", std::process::id()));
        write_private(&tmp_path, text.as_bytes())
            .map_err(|e| SecretError::Backend(format!("write sovereign vault failed: {e}")))?;
        if let Err(e) = std::fs::rename(&tmp_path, &self.vault_path) {
            let _ = std::fs::remove_file(&tmp_path);
            return Err(SecretError::Backend(format!(
                "atomic rename of sovereign vault failed: {e}"
            )));
        }
        Ok(())
    }

    pub fn encrypt_value(
        &self,
        dek: &[u8; 32],
        key: &str,
        plaintext: &str,
    ) -> Result<String, SecretError> {
        let cipher = Aes256Gcm::new_from_slice(dek)
            .map_err(|e| SecretError::Crypto(format!("aes-gcm init failed: {e}")))?;
        let mut nonce_bytes = [0u8; 12];
        rand::thread_rng().fill_bytes(&mut nonce_bytes);
        let nonce = Nonce::from_slice(&nonce_bytes);
        let aad = self.aad_v2(key);
        let ct = cipher
            .encrypt(
                nonce,
                Payload {
                    msg: plaintext.as_bytes(),
                    aad: aad.as_bytes(),
                },
            )
            .map_err(|e| SecretError::Crypto(format!("aes-gcm encrypt failed: {e}")))?;
        Ok(format!("{}:{}", B64.encode(nonce_bytes), B64.encode(ct)))
    }

    pub fn decrypt_value(
        &self,
        dek: &[u8; 32],
        key: &str,
        encoded: &str,
    ) -> Result<Zeroizing<String>, SecretError> {
        let (nonce_b64, ct_b64) = encoded
            .split_once(':')
            .ok_or_else(|| SecretError::Crypto("malformed ciphertext format".to_owned()))?;
        let nonce_bytes = B64
            .decode(nonce_b64)
            .map_err(|e| SecretError::Crypto(format!("invalid nonce b64: {e}")))?;
        if nonce_bytes.len() != 12 {
            return Err(SecretError::Crypto("invalid nonce length".to_owned()));
        }
        let ct = B64
            .decode(ct_b64)
            .map_err(|e| SecretError::Crypto(format!("invalid ciphertext b64: {e}")))?;
        let cipher = Aes256Gcm::new_from_slice(dek)
            .map_err(|e| SecretError::Crypto(format!("aes-gcm init failed: {e}")))?;
        let nonce = Nonce::from_slice(&nonce_bytes);
        let aad_v2 = self.aad_v2(key);
        let pt = cipher
            .decrypt(
                nonce,
                Payload {
                    msg: ct.as_slice(),
                    aad: aad_v2.as_bytes(),
                },
            )
            .or_else(|_| {
                let aad_v1 = self.aad_for(key);
                cipher.decrypt(
                    nonce,
                    Payload {
                        msg: ct.as_slice(),
                        aad: aad_v1.as_bytes(),
                    },
                )
            })
            .map_err(|_| {
                SecretError::Crypto(format!(
                    "AEAD authentication failed for key '{key}' (possible tampering or key-swap)"
                ))
            })?;
        let s = String::from_utf8(pt)
            .map_err(|e| SecretError::Crypto(format!("decrypted secret not UTF-8: {e}")))?;
        Ok(Zeroizing::new(s))
    }

    /// Decrypt and return every `(var_name, plaintext)` entry currently stored in the vault.
    ///
    /// Returns an empty vector without creating any file if the vault does not exist on disk.
    /// Callers must never expose these returned `Zeroizing<String>` values directly; feed them
    /// into a hashed/constant-time matcher (`VaultSecretIndex`) or `SecretRedactor` and drop them.
    pub fn export_all_zeroizing(&self) -> Result<Vec<(String, Zeroizing<String>)>, SecretError> {
        if !self.vault_path.exists() {
            return Ok(Vec::new());
        }
        let (vault, dek) = self.load_or_init()?;
        let mut out = Vec::with_capacity(vault.entries.len());
        for (map_key, enc) in &vault.entries {
            let val = self.decrypt_value(&dek, map_key, enc)?;
            let var_name = map_key.rsplit(':').next().unwrap_or(map_key).to_owned();
            out.push((var_name, val));
        }
        Ok(out)
    }
}

impl SecretBackend for AgeSovereignBackend {
    fn name(&self) -> &str {
        "age-sovereign-aead"
    }

    fn get(&self, coord: &SecretCoord) -> Result<Option<Zeroizing<String>>, SecretError> {
        let lock = acquire_path_lock(&self.vault_path);
        let _guard = lock.lock().unwrap_or_else(PoisonError::into_inner);
        if !self.vault_path.exists() {
            return Ok(None);
        }
        let (vault, dek) = self.load_or_init()?;
        let map_key = coord.storage_key();
        match vault.entries.get(&map_key) {
            Some(enc) => Ok(Some(self.decrypt_value(&dek, &map_key, enc)?)),
            None => Ok(None),
        }
    }

    fn set(&self, coord: &SecretCoord, value: &str) -> Result<(), SecretError> {
        let lock = acquire_path_lock(&self.vault_path);
        let _guard = lock.lock().unwrap_or_else(PoisonError::into_inner);
        let creating = !self.vault_path.exists();
        let kt = self.kt_log_path.as_ref().map(KeyTransparencyLog::open);
        if creating && let Some(kt) = &kt {
            // A recreated vault must still match the repo's last binding.
            kt.verify_vault_recipients(&self.repo_id, &self.recipient_public_keys())?;
        }
        let (mut vault, dek) = self.load_or_init()?;
        let map_key = coord.storage_key();
        let enc = self.encrypt_value(&dek, &map_key, value)?;
        vault.entries.insert(map_key, enc);
        self.save_vault(&vault)?;
        if creating
            && let Some(kt) = &kt
            && let Err(e) = kt.append_binding(
                &self.repo_id,
                &self.logical_path,
                &vault.recipients,
                "premier-secrets",
                "genesis",
            )
        {
            let _ = std::fs::remove_file(&self.vault_path);
            return Err(e);
        }
        Ok(())
    }

    fn delete(&self, coord: &SecretCoord) -> Result<(), SecretError> {
        let lock = acquire_path_lock(&self.vault_path);
        let _guard = lock.lock().unwrap_or_else(PoisonError::into_inner);
        if !self.vault_path.exists() {
            return Ok(());
        }
        let (mut vault, _) = self.load_or_init()?;
        vault.entries.remove(&coord.storage_key());
        self.save_vault(&vault)
    }
}

/// Resolution context specifying the active inheritance chain.
#[derive(Debug, Clone)]
pub struct ResolveContext {
    pub repo_id: String,
    pub org: String,
    pub env: Environment,
    pub branch: String,
    pub identity: DelegatedIdentity,
}

/// Resolved environment values + provenance (values held in `Zeroizing<String>`).
#[derive(Debug)]
pub struct ResolvedEnv {
    pub values: BTreeMap<String, Zeroizing<String>>,
    pub provenance: BTreeMap<String, ValueProvenance>,
}

/// Hierarchical resolver enforcing `org -> repo -> zone -> env -> branch -> personal`
/// precedence and `premier-policy` ACL checks.
pub struct SecretResolver<'a> {
    schema: &'a EnvSchema,
    policy: Option<&'a CompiledPolicy>,
    backend: &'a dyn SecretBackend,
}

impl<'a> SecretResolver<'a> {
    pub fn new(
        schema: &'a EnvSchema,
        policy: Option<&'a CompiledPolicy>,
        backend: &'a dyn SecretBackend,
    ) -> Self {
        Self {
            schema,
            policy,
            backend,
        }
    }

    /// Resolve all schema variables permitted for `ctx` under `required_cap`
    /// (`Capability::READ` for direct `premier run`, `Capability::USE` for proxy placeholders).
    pub fn resolve(
        &self,
        ctx: &ResolveContext,
        required_cap: Capability,
    ) -> Result<ResolvedEnv, SecretError> {
        let mut values = BTreeMap::new();
        let mut provenance = BTreeMap::new();

        for (var_name, spec) in &self.schema.vars {
            if let Some(policy) = self.policy
                && matches!(
                    spec.sensitivity,
                    Sensitivity::Secret | Sensitivity::Restricted
                )
            {
                let decision = policy.can_use_secret(
                    &ctx.identity,
                    var_name,
                    spec.zone.as_deref(),
                    &ctx.branch,
                );
                let permitted = if required_cap == Capability::USE {
                    decision.allows(Capability::USE) || decision.allows(Capability::READ)
                } else {
                    decision.allows(required_cap)
                };
                if !permitted {
                    continue;
                }
            }

            let mut layers: Vec<(SecretLayer, String)> = vec![
                (SecretLayer::Org, ctx.org.clone()),
                (SecretLayer::Repo, ctx.repo_id.clone()),
            ];
            if let Some(z) = &spec.zone {
                layers.push((SecretLayer::Zone, z.clone()));
            }
            layers.push((SecretLayer::Env, ctx.env.as_str().to_owned()));
            layers.push((SecretLayer::Branch, ctx.branch.clone()));
            layers.push((SecretLayer::Personal, ctx.identity.principal.canonical_id()));

            // Evaluate from highest precedence to lowest (first hit wins).
            let mut found = None;
            for (layer, scope) in layers.into_iter().rev() {
                let coord = SecretCoord {
                    repo_id: ctx.repo_id.clone(),
                    layer,
                    scope,
                    var_name: var_name.clone(),
                };
                if let Some(val) = self.backend.get(&coord)? {
                    found = Some((val, layer, self.backend.name().to_owned()));
                    break;
                }
            }

            if let Some((val, layer, backend_name)) = found {
                values.insert(var_name.clone(), val);
                provenance.insert(
                    var_name.clone(),
                    ValueProvenance {
                        var_name: var_name.clone(),
                        layer,
                        backend: backend_name,
                        sensitivity: spec.sensitivity,
                    },
                );
            } else if let Some(default_val) = &spec.default {
                values.insert(var_name.clone(), Zeroizing::new(default_val.clone()));
                provenance.insert(
                    var_name.clone(),
                    ValueProvenance {
                        var_name: var_name.clone(),
                        layer: SecretLayer::Repo,
                        backend: "schema-default".to_owned(),
                        sensitivity: spec.sensitivity,
                    },
                );
            }
        }

        Ok(ResolvedEnv { values, provenance })
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::create_state_dir;

    #[test]
    fn state_dirs_ignore_themselves_and_only_them() {
        let tmp = tempfile::tempdir().unwrap();
        for name in [".premier", ".premier-local"] {
            let dir = tmp.path().join(name);
            create_state_dir(&dir).unwrap();
            assert_eq!(
                std::fs::read_to_string(dir.join(".gitignore")).unwrap(),
                "*\n"
            );
        }
        // Idempotent, and an edited file is left alone.
        let ignore = tmp.path().join(".premier/.gitignore");
        std::fs::write(&ignore, "custom\n").unwrap();
        create_state_dir(&tmp.path().join(".premier")).unwrap();
        assert_eq!(std::fs::read_to_string(&ignore).unwrap(), "custom\n");
        create_state_dir(&tmp.path().join("logs")).unwrap();
        assert!(!tmp.path().join("logs/.gitignore").exists());
    }
}
