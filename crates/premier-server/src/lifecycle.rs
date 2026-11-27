//! Platform 5 lifecycle: live autonomy budget approval, workspace Envelope KMS + Key
//! Transparency, signed dual-phase secret rotation, keyless OIDC workload identity, and the
//! one-click offboarding kill switch.
//!
//! Nothing here returns, logs or audits a raw secret value or a raw workload token, except the
//! token minted for its own caller by `POST /v1/oidc/token`.

use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;
use std::sync::{Arc, Mutex, PoisonError};

use axum::extract::{Path as AxumPath, State};
use axum::http::{StatusCode, header};
use axum::response::IntoResponse;
use axum::{Extension, Json};
use base64::Engine;
use chrono::{DateTime, Utc};
use premier_core::{AuditDecision, AuditEvent, Capability, DelegatedIdentity, Principal};
use premier_policy::{AutonomyBudget, CompiledPolicy};
use premier_secrets::{
    ActorClaim, AgeSovereignBackend, EnvSchema, EnvelopeVaultBackend, KeyTransparencyEntry,
    KeyTransparencyLog, KmsStatus, OidcTokenIssuer, RotationDispatcher, RotationPhase,
    RotationReceipt, RotationSpec, RotationStatus, SecretBackend, SecretCoord, SecretLayer,
    Sensitivity, WorkloadTokenRequest, migrate_from_age_vault, recipients_fingerprint,
};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use zeroize::Zeroizing;

use crate::auth::AuthUser;
use crate::runner::AgentSessionRecord;
use crate::store::{
    WorkspaceVault, account_dir, age_vault_path, env_kms_configured, envelope_vault_path, kt_path,
    load_json, load_json_in, open_workspace_age_vault, open_workspace_vault,
    open_workspace_vault_backend, save_json, save_json_in, save_state, workspace_key_wrapper,
};
use crate::{ApiError, ServerState, err_resp};

type ApiErr = (StatusCode, Json<ApiError>);
type Fail = (StatusCode, String);

const ROTATIONS_FILE: &str = "rotations.json";
const OFFBOARDS_FILE: &str = "offboards.json";
const MAX_RECEIPTS: usize = 200;
const KT_RECENT: usize = 20;
const OIDC_KEY_FILE: &str = "oidc.key";
const OIDC_REVOKED_FILE: &str = "oidc_revoked.json";

/// Serializes read-modify-write of the receipt files.
static RECEIPTS: Mutex<()> = Mutex::new(());
/// Serializes Sovereign -> Envelope KMS migration.
static MIGRATE_LOCK: Mutex<()> = Mutex::new(());

fn api((status, msg): Fail) -> ApiErr {
    err_resp(status, msg)
}

fn ise(e: impl ToString) -> ApiErr {
    err_resp(StatusCode::INTERNAL_SERVER_ERROR, e.to_string())
}

fn default_true() -> bool {
    true
}

fn default_dev() -> String {
    "dev".to_owned()
}

fn default_prod() -> String {
    "prod".to_owned()
}

fn non_empty(s: Option<String>) -> Option<String> {
    s.map(|s| s.trim().to_owned()).filter(|s| !s.is_empty())
}

fn random_id() -> String {
    crate::auth::random_bytes(16)
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

fn repo_id(state: &ServerState) -> String {
    state
        .current_env_schema()
        .and_then(|s| s.repo_id.clone())
        .unwrap_or_else(|| "local/repo".to_owned())
}

/// The authenticated caller as an audit identity (`anonymous` outside a request).
fn actor_identity(actor: &str) -> DelegatedIdentity {
    DelegatedIdentity::human_only(
        Principal::parse(actor).unwrap_or(Principal::Anonymous),
        vec![],
    )
}

fn audit(
    state: &ServerState,
    actor: &str,
    action: &str,
    decision: AuditDecision,
    target: Option<String>,
    reason: String,
) {
    let mut ev = AuditEvent::now(
        &actor_identity(actor),
        "premier-lifecycle",
        action,
        decision,
        reason,
    );
    ev.target = target;
    crate::auth::audit(&state.audit_sink, ev);
}

/// Prepend `new` (newest first) to the receipt list in state file `file` inside `dir`, capped.
fn record_in<T: Serialize + serde::de::DeserializeOwned + Clone>(
    dir: &Path,
    file: &str,
    new: &[T],
) -> Result<(), String> {
    let _guard = RECEIPTS.lock().unwrap_or_else(PoisonError::into_inner);
    let mut all: Vec<T> = load_json_in(dir, file);
    for r in new {
        all.insert(0, r.clone());
    }
    all.truncate(MAX_RECEIPTS);
    save_json_in(dir, file, &all)
}

/// Prepend `new` (newest first) to the receipt list in state file `file`, capped.
fn record<T: Serialize + serde::de::DeserializeOwned + Clone>(
    workspace_root: &Path,
    file: &str,
    new: &[T],
) -> Result<(), String> {
    record_in(&crate::store::state_dir(workspace_root), file, new)
}

// ---------------------------------------------------------------------------
// Live autonomy budgets
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize)]
pub struct RaiseBudgetRequest {
    pub limits: AutonomyBudget,
    #[serde(default = "default_true")]
    pub resume: bool,
}

/// `POST /v1/agents/sessions/{id}/budget`: a human budget approval (owner only).
pub async fn raise_budget_handler(
    State(state): State<ServerState>,
    AxumPath(id): AxumPath<String>,
    Json(req): Json<RaiseBudgetRequest>,
) -> Result<Json<AgentSessionRecord>, ApiErr> {
    let rec = state
        .session_manager
        .raise_session_budget(&id, req.limits, req.resume)
        .map_err(api)?;
    let actor = crate::auth::actor_principal();
    audit(
        &state,
        &actor,
        "budget_raised",
        AuditDecision::Allowed,
        Some(id.clone()),
        format!(
            "Raised the autonomy budget of session {id}{}",
            if req.resume { " and resumed it" } else { "" }
        ),
    );
    Ok(Json(rec))
}

// ---------------------------------------------------------------------------
// Envelope KMS + Key Transparency
// ---------------------------------------------------------------------------

/// `GET /v1/secrets/kms/status`: the vault's KMS mode and Key Transparency health.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KmsStatusResponse {
    #[serde(flatten)]
    pub status: KmsStatus,
    /// The last (up to 20) entries of the Key Transparency log.
    pub kt_recent_entries: Vec<KeyTransparencyEntry>,
}

/// Sovereign `age` vault health, in the envelope status' shape.
fn sovereign_status(workspace_root: &Path, repo_id: &str, age: &AgeSovereignBackend) -> KmsStatus {
    let keys = age.recipient_public_keys();
    let fingerprint = recipients_fingerprint(&keys);
    let vault_path = age_vault_path(workspace_root);
    // Decrypting first also binds a pre-KT vault (trust on first use) before it is checked.
    let entries = age.list_entries();
    let kt = KeyTransparencyLog::open(kt_path(workspace_root));
    let check = if vault_path.exists() {
        kt.verify_vault_recipients(repo_id, &keys)
    } else {
        kt.verify_chain()
    };
    let (kt_valid, kt_entries, kt_error) = match check {
        Ok(r) => (true, r.entry_count, None),
        Err(e) => (
            false,
            kt.entries().map_or(0, |e| e.len()),
            Some(e.to_string()),
        ),
    };
    let (entry_count, kt_valid, kt_error) = match entries {
        Ok(m) => (m.len(), kt_valid, kt_error),
        Err(e) => (0, false, kt_error.or_else(|| Some(e.to_string()))),
    };
    KmsStatus {
        mode: "sovereign_age".to_owned(),
        provider: "age".to_owned(),
        key_id: format!("age-{}", fingerprint.get(..16).unwrap_or(&fingerprint)),
        envelope_version: 1,
        dek_version: 1,
        kek_separated: false,
        vault_path: vault_path.display().to_string(),
        entry_count,
        kt_enabled: true,
        kt_entries,
        kt_valid,
        kt_error,
    }
}

pub fn kms_status(workspace_root: &Path, repo_id: &str) -> Result<KmsStatusResponse, String> {
    let status = if !envelope_vault_path(workspace_root).exists()
        && age_vault_path(workspace_root).exists()
        && env_kms_configured()
    {
        sovereign_status(
            workspace_root,
            repo_id,
            &open_workspace_vault(workspace_root, repo_id)?,
        )
    } else {
        match open_workspace_vault_backend(workspace_root, repo_id)? {
            WorkspaceVault::Envelope(e) => e.status().map_err(|e| e.to_string())?,
            WorkspaceVault::Age(age) => sovereign_status(workspace_root, repo_id, &age),
        }
    };
    let mut recent = KeyTransparencyLog::open(kt_path(workspace_root))
        .entries()
        .unwrap_or_default();
    let skip = recent.len().saturating_sub(KT_RECENT);
    recent.drain(..skip);
    Ok(KmsStatusResponse {
        status,
        kt_recent_entries: recent,
    })
}

/// Move the Sovereign `age` vault into an Envelope KMS vault. Returns `(entries migrated,
/// already migrated)`. The `age` vault is verified against Key Transparency and fully decrypted
/// before anything changes; a failed import or post-migration check is rolled back cleanly. On
/// success, the retired `vault.toml` (and `age.key` when an external KEK is used) is deleted and
/// `migrate_retire_age` is appended to Key Transparency.
pub fn migrate_to_envelope(
    workspace_root: &Path,
    repo_id: &str,
    actor: &str,
) -> Result<(usize, bool), Fail> {
    let fail = |e: String| (StatusCode::INTERNAL_SERVER_ERROR, e);
    let (wrapper, separated) = workspace_key_wrapper(workspace_root).map_err(fail)?;
    migrate_to_envelope_with_wrapper(workspace_root, repo_id, actor, wrapper, separated)
}

pub(crate) fn migrate_to_envelope_with_wrapper(
    workspace_root: &Path,
    repo_id: &str,
    actor: &str,
    wrapper: Arc<dyn premier_secrets::KeyWrapper>,
    separated: bool,
) -> Result<(usize, bool), Fail> {
    let _guard = MIGRATE_LOCK.lock().unwrap_or_else(PoisonError::into_inner);
    let fail = |e: String| (StatusCode::INTERNAL_SERVER_ERROR, e);
    let envelope_path = envelope_vault_path(workspace_root);
    if envelope_path.exists() {
        return Ok((0, true));
    }
    let age_path = age_vault_path(workspace_root);
    let age = open_workspace_vault(workspace_root, repo_id).map_err(fail)?;
    let source_entries = age.list_entries().map_err(|e| {
        (
            StatusCode::CONFLICT,
            format!("the age vault failed verification; nothing was migrated: {e}"),
        )
    })?;
    let target_binding = vec![format!("{}:{}", wrapper.provider_name(), wrapper.key_id())];
    // Both vaults share one KT log per repo: bind the envelope key first, so the envelope
    // vault's creation check matches the latest binding instead of the age recipients.
    let kt = KeyTransparencyLog::open(kt_path(workspace_root));
    kt.append_binding(
        repo_id,
        &envelope_path.display().to_string(),
        &target_binding,
        actor,
        "migrate_to_envelope",
    )
    .map_err(|e| fail(format!("key transparency: {e}")))?;
    let envelope = EnvelopeVaultBackend::new(&envelope_path, repo_id, Arc::clone(&wrapper))
        .with_kek_separated(separated)
        .with_key_transparency(kt_path(workspace_root));
    // KT was verified above; the latest binding is now the envelope key.
    let plain_age = open_workspace_age_vault(workspace_root, repo_id).map_err(fail)?;
    let rollback = |msg: String| {
        let _ = std::fs::remove_file(&envelope_path);
        let _ = kt.append_binding(
            repo_id,
            &age_path.display().to_string(),
            &age.recipient_public_keys(),
            actor,
            "migrate_rollback",
        );
        fail(msg)
    };
    match migrate_from_age_vault(&plain_age, &envelope) {
        Ok(n) => {
            let verified = match envelope.list_entries() {
                Ok(migrated) => {
                    migrated.len() == source_entries.len()
                        && source_entries.iter().all(|(k, v)| {
                            migrated.get(k).is_some_and(|mv| mv.as_str() == v.as_str())
                        })
                }
                Err(e) => {
                    return Err(rollback(format!(
                        "post-migration verification failed and was rolled back: {e}"
                    )));
                }
            };
            if !verified {
                return Err(rollback(
                    "post-migration verification detected an entry mismatch; migration was rolled back"
                        .to_owned(),
                ));
            }
            match std::fs::remove_file(&age_path) {
                Ok(()) => {}
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
                Err(e) => {
                    return Err(fail(format!(
                        "migration succeeded but removing retired age vault failed: {e}"
                    )));
                }
            }
            // If a dedicated GitHub companion age vault exists, migrate it into Envelope KMS
            // before retiring `age.key`, so migrating the workspace vault never bricks GitHub auth.
            let gh_age_path = crate::store::github_age_vault_path(workspace_root);
            let gh_env_path = crate::store::github_envelope_vault_path(workspace_root);
            if gh_age_path.exists() && !gh_env_path.exists() {
                let gh_repo = crate::store::GITHUB_VAULT_REPO_ID;
                let gh_age = crate::store::open_github_age_vault(workspace_root, gh_repo)
                    .map_err(fail)?
                    .with_key_transparency(kt_path(workspace_root));
                let gh_entries = gh_age
                    .list_entries()
                    .map_err(|e| rollback(format!("github age vault verification failed: {e}")))?;
                let gh_plain_age =
                    crate::store::open_github_age_vault(workspace_root, gh_repo).map_err(fail)?;
                kt.append_binding(
                    gh_repo,
                    &gh_env_path.display().to_string(),
                    &target_binding,
                    actor,
                    "migrate_to_envelope",
                )
                .map_err(|e| rollback(format!("github key transparency: {e}")))?;
                let gh_env = EnvelopeVaultBackend::new(&gh_env_path, gh_repo, Arc::clone(&wrapper))
                    .with_kek_separated(separated)
                    .with_key_transparency(kt_path(workspace_root));
                if let Err(e) = migrate_from_age_vault(&gh_plain_age, &gh_env) {
                    let _ = std::fs::remove_file(&gh_env_path);
                    let _ = kt.append_binding(
                        gh_repo,
                        &gh_age_path.display().to_string(),
                        &gh_age.recipient_public_keys(),
                        actor,
                        "migrate_rollback",
                    );
                    return Err(rollback(format!(
                        "github vault migration failed and was rolled back: {e}"
                    )));
                }
                let gh_ok = gh_env.list_entries().is_ok_and(|migrated| {
                    migrated.len() == gh_entries.len()
                        && gh_entries.iter().all(|(k, v)| {
                            migrated.get(k).is_some_and(|mv| mv.as_str() == v.as_str())
                        })
                });
                if !gh_ok {
                    let _ = std::fs::remove_file(&gh_env_path);
                    let _ = kt.append_binding(
                        gh_repo,
                        &gh_age_path.display().to_string(),
                        &gh_age.recipient_public_keys(),
                        actor,
                        "migrate_rollback",
                    );
                    return Err(rollback(
                        "github vault post-migration verification failed; rolled back".to_owned(),
                    ));
                }
                let _ = std::fs::remove_file(&gh_age_path);
            }
            if separated {
                let key_path = crate::store::age_key_path(workspace_root);
                match std::fs::remove_file(&key_path) {
                    Ok(()) => {}
                    Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
                    Err(e) => {
                        return Err(fail(format!(
                            "migration succeeded but removing retired age.key failed: {e}"
                        )));
                    }
                }
            }
            kt.append_binding(
                repo_id,
                &envelope_path.display().to_string(),
                &target_binding,
                actor,
                "migrate_retire_age",
            )
            .map_err(|e| fail(format!("key transparency retire-age binding failed: {e}")))?;
            Ok((n, false))
        }
        Err(e) => Err(rollback(format!(
            "migration failed and was rolled back: {e}"
        ))),
    }
}

/// Re-encrypt every envelope entry under a fresh DEK; 409 outside envelope mode.
pub fn rotate_workspace_dek(workspace_root: &Path, repo_id: &str) -> Result<u32, Fail> {
    let not_envelope = || {
        (
            StatusCode::CONFLICT,
            "the workspace vault is not in envelope mode; migrate it first (POST /v1/secrets/kms/migrate)"
                .to_owned(),
        )
    };
    if !envelope_vault_path(workspace_root).exists() {
        return Err(not_envelope());
    }
    match open_workspace_vault_backend(workspace_root, repo_id)
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e))?
    {
        WorkspaceVault::Envelope(e) => {
            let ver = e
                .rotate_dek()
                .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
            let gh_env_path = crate::store::github_envelope_vault_path(workspace_root);
            if gh_env_path.exists() {
                let (wrapper, separated) = workspace_key_wrapper(workspace_root)
                    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e))?;
                let gh_env = EnvelopeVaultBackend::new(
                    &gh_env_path,
                    crate::store::GITHUB_VAULT_REPO_ID,
                    wrapper,
                )
                .with_kek_separated(separated)
                .with_key_transparency(kt_path(workspace_root));
                gh_env
                    .rotate_dek()
                    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
            }
            Ok(ver)
        }
        WorkspaceVault::Age(_) => Err(not_envelope()),
    }
}

/// What `secret_meta` records for entries in the vault in use.
fn vault_label(workspace_root: &Path) -> &'static str {
    if env_kms_configured() || envelope_vault_path(workspace_root).exists() {
        "envelope-kms"
    } else {
        "age-aead"
    }
}

async fn status_of(state: &ServerState) -> Result<KmsStatusResponse, ApiErr> {
    let (root, repo) = (state.workspace_root.clone(), repo_id(state));
    tokio::task::spawn_blocking(move || kms_status(&root, &repo))
        .await
        .map_err(ise)?
        .map_err(ise)
}

pub async fn kms_status_handler(
    State(state): State<ServerState>,
) -> Result<Json<KmsStatusResponse>, ApiErr> {
    status_of(&state).await.map(Json)
}

pub async fn migrate_kms_handler(State(state): State<ServerState>) -> Result<Json<Value>, ApiErr> {
    let actor = crate::auth::actor_principal();
    let (root, repo, who) = (state.workspace_root.clone(), repo_id(&state), actor.clone());
    let (migrated, already) =
        tokio::task::spawn_blocking(move || migrate_to_envelope(&root, &repo, &who))
            .await
            .map_err(ise)?
            .map_err(api)?;
    if !already {
        {
            let mut st = state.persisted.lock().map_err(ise)?;
            for meta in st.secret_meta.values_mut() {
                "envelope-kms".clone_into(&mut meta.backend);
            }
            save_state(&state.workspace_root, &st).map_err(ise)?;
        }
        audit(
            &state,
            &actor,
            "kms_migrated",
            AuditDecision::Allowed,
            None,
            format!("Migrated {migrated} vault entries from Sovereign age to Envelope KMS"),
        );
    }
    let status = status_of(&state).await?;
    Ok(Json(json!({
        "ok": true,
        "migrated_entries": migrated,
        "already_migrated": already,
        "status": status,
    })))
}

pub async fn rotate_dek_handler(State(state): State<ServerState>) -> Result<Json<Value>, ApiErr> {
    let actor = crate::auth::actor_principal();
    let (root, repo) = (state.workspace_root.clone(), repo_id(&state));
    let dek_version = tokio::task::spawn_blocking(move || rotate_workspace_dek(&root, &repo))
        .await
        .map_err(ise)?
        .map_err(api)?;
    audit(
        &state,
        &actor,
        "kms_dek_rotated",
        AuditDecision::Allowed,
        None,
        format!("Re-encrypted the workspace vault under DEK v{dek_version}"),
    );
    let status = status_of(&state).await?;
    Ok(Json(
        json!({ "ok": true, "dek_version": dek_version, "status": status }),
    ))
}

// ---------------------------------------------------------------------------
// Signed dual-phase rotation
// ---------------------------------------------------------------------------

/// A receipt for a rotation that never reached the provider (no webhook, no signing key...).
#[allow(clippy::too_many_arguments)]
fn unsent_receipt(
    var: &str,
    env: &str,
    spec: Option<&RotationSpec>,
    status: RotationStatus,
    actor: &str,
    reason: &str,
    offboard: bool,
    error: String,
) -> RotationReceipt {
    RotationReceipt {
        id: random_id(),
        var_name: var.to_owned(),
        env: env.to_owned(),
        provider: spec
            .and_then(|s| s.provider.clone())
            .unwrap_or_else(|| "manual".to_owned()),
        webhook_url: spec.map(|s| s.webhook_url.clone()),
        status,
        phase_reached: RotationPhase::Prepare,
        triggered_by_offboard: offboard,
        actor: actor.to_owned(),
        reason: reason.to_owned(),
        timestamp: Utc::now(),
        http_status: None,
        rollback_sent: false,
        error: Some(error),
    }
}

/// The webhook HMAC key `reference` names: the workspace vault (env, then org layer), or a
/// `PREMIER_ROTATION_*` server environment variable (never arbitrary host env vars).
fn signing_secret(
    vault: &dyn SecretBackend,
    repo_id: &str,
    env: &str,
    reference: &str,
) -> Option<Zeroizing<String>> {
    signing_secret_with(vault, repo_id, env, reference, |k| std::env::var(k).ok())
}

pub(crate) fn signing_secret_with(
    vault: &dyn SecretBackend,
    repo_id: &str,
    env: &str,
    reference: &str,
    lookup_env: impl Fn(&str) -> Option<String>,
) -> Option<Zeroizing<String>> {
    for (layer, scope) in [(SecretLayer::Env, env), (SecretLayer::Org, "local")] {
        let coord = SecretCoord {
            repo_id: repo_id.to_owned(),
            layer,
            scope: scope.to_owned(),
            var_name: reference.to_owned(),
        };
        if let Ok(Some(v)) = vault.get(&coord)
            && !v.is_empty()
        {
            return Some(v);
        }
    }
    reference
        .starts_with("PREMIER_ROTATION_")
        .then(|| lookup_env(reference))
        .flatten()
        .filter(|v| !v.is_empty())
        .map(Zeroizing::new)
}

/// One signed `prepare` -> store -> `commit` rotation of `var` in the workspace vault (blocking).
#[allow(clippy::too_many_arguments)]
pub fn rotate_var_blocking(
    workspace_root: &Path,
    repo_id: &str,
    dispatcher: &RotationDispatcher,
    var: &str,
    spec: &RotationSpec,
    env: &str,
    actor: &str,
    reason: &str,
    offboard: bool,
    new_value: Option<&str>,
) -> RotationReceipt {
    let unsent = |status, error| {
        unsent_receipt(var, env, Some(spec), status, actor, reason, offboard, error)
    };
    let vault = match open_workspace_vault_backend(workspace_root, repo_id) {
        Ok(v) => v,
        Err(e) => {
            return unsent(
                RotationStatus::Failed,
                format!("opening the vault failed: {e}"),
            );
        }
    };
    let Some(signing) = signing_secret(&vault, repo_id, env, &spec.signing_secret_ref) else {
        return unsent(
            RotationStatus::ManualRequired,
            format!(
                "rotation signing secret '{}' is not configured in the vault (or PREMIER_ROTATION_* env); rotate manually",
                spec.signing_secret_ref
            ),
        );
    };
    let coord = SecretCoord {
        repo_id: repo_id.to_owned(),
        layer: SecretLayer::Env,
        scope: env.to_owned(),
        var_name: var.to_owned(),
    };
    dispatcher.execute_dual_phase(
        spec,
        signing.as_bytes(),
        &vault,
        &coord,
        actor,
        reason,
        offboard,
        new_value,
    )
}

/// Record a committed rotation of `var` in `secret_meta` and save the state.
pub fn note_rotated_in(
    st: &mut crate::store::PersistedState,
    workspace_root: &Path,
    var: &str,
    env: &str,
) -> Result<(), String> {
    let rotated_count =
        crate::store::get_secret_meta(&st.secret_meta, env, var).map_or(0, |m| m.rotated_count) + 1;
    // A legacy bare-key entry is superseded by the `env:var` one.
    if st.secret_meta.get(var).is_some_and(|m| m.env == env) {
        st.secret_meta.remove(var);
    }
    st.secret_meta.insert(
        crate::store::secret_meta_key(env, var),
        crate::store::SecretMetaEntry {
            env: env.to_owned(),
            backend: vault_label(workspace_root).to_owned(),
            updated_at: Utc::now().to_rfc3339(),
            rotated_count,
        },
    );
    save_state(workspace_root, st)
}

fn note_rotated(state: &ServerState, var: &str, env: &str) -> Result<(), String> {
    let mut st = state.persisted.lock().map_err(|e| e.to_string())?;
    note_rotated_in(&mut st, &state.workspace_root, var, env)
}

/// Persist rotation receipts in `rotations.json` (newest first, at most 200 kept).
pub fn record_rotations(workspace_root: &Path, receipts: &[RotationReceipt]) -> Result<(), String> {
    record(workspace_root, ROTATIONS_FILE, receipts)
}

/// Rotate `var` through its webhook off the async runtime, and note a committed rotation.
#[allow(clippy::too_many_arguments)]
async fn rotate_var(
    state: &ServerState,
    var: &str,
    spec: RotationSpec,
    env: &str,
    actor: &str,
    reason: &str,
    offboard: bool,
    new_value: Option<Zeroizing<String>>,
) -> RotationReceipt {
    let (root, repo, dispatcher) = (
        state.workspace_root.clone(),
        repo_id(state),
        std::sync::Arc::clone(&state.rotation_dispatcher),
    );
    let (v, e, a, r) = (
        var.to_owned(),
        env.to_owned(),
        actor.to_owned(),
        reason.to_owned(),
    );
    let spec_bg = spec.clone();
    let receipt = tokio::task::spawn_blocking(move || {
        rotate_var_blocking(
            &root,
            &repo,
            &dispatcher,
            &v,
            &spec_bg,
            &e,
            &a,
            &r,
            offboard,
            new_value.as_deref().map(String::as_str),
        )
    })
    .await
    .unwrap_or_else(|e| {
        unsent_receipt(
            var,
            env,
            Some(&spec),
            RotationStatus::Failed,
            actor,
            reason,
            offboard,
            format!("rotation task failed: {e}"),
        )
    });
    if receipt.status == RotationStatus::Committed
        && let Err(e) = note_rotated(state, var, env)
    {
        tracing::warn!(error = %e, "failed to record a committed rotation");
    }
    receipt
}

fn deserialize_opt_zeroizing<'de, D>(deserializer: D) -> Result<Option<Zeroizing<String>>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    Option::<String>::deserialize(deserializer).map(|opt| opt.map(Zeroizing::new))
}

#[derive(Deserialize)]
pub struct RotateSecretRequest {
    #[serde(default = "default_dev")]
    pub env: String,
    #[serde(default)]
    pub reason: Option<String>,
    #[serde(default, deserialize_with = "deserialize_opt_zeroizing")]
    pub new_value: Option<Zeroizing<String>>,
}

impl std::fmt::Debug for RotateSecretRequest {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RotateSecretRequest")
            .field("env", &self.env)
            .field("reason", &self.reason)
            .field("new_value", &self.new_value.as_ref().map(|_| "[REDACTED]"))
            .finish()
    }
}

impl Default for RotateSecretRequest {
    fn default() -> Self {
        Self {
            env: default_dev(),
            reason: None,
            new_value: None,
        }
    }
}

/// `POST /v1/secrets/{key}/rotate`: signed dual-phase rotation through the variable's webhook.
pub async fn rotate_secret_handler(
    State(state): State<ServerState>,
    AxumPath(key): AxumPath<String>,
    body: Option<Json<RotateSecretRequest>>,
) -> Result<Json<RotationReceipt>, ApiErr> {
    let req = body.map(|Json(b)| b).unwrap_or_default();
    let spec = state
        .current_env_schema()
        .and_then(|s| s.vars.get(&key).cloned())
        .ok_or_else(|| {
            err_resp(
                StatusCode::NOT_FOUND,
                format!("'{key}' is not declared in .env.schema"),
            )
        })?;
    let rotation = spec.rotation.ok_or_else(|| {
        err_resp(
            StatusCode::BAD_REQUEST,
            format!(
                "'{key}' has no rotation webhook configured ([vars.{key}.rotation]); set a new value with POST /v1/secrets/set instead"
            ),
        )
    })?;
    let env = if req.env.trim().is_empty() {
        default_dev()
    } else {
        req.env.trim().to_owned()
    };
    let actor = crate::auth::actor_principal();
    let reason = non_empty(req.reason).unwrap_or_else(|| "manual rotation".to_owned());
    let receipt = rotate_var(
        &state,
        &key,
        rotation,
        &env,
        &actor,
        &reason,
        false,
        req.new_value,
    )
    .await;
    record(
        &state.workspace_root,
        ROTATIONS_FILE,
        std::slice::from_ref(&receipt),
    )
    .map_err(ise)?;
    audit(
        &state,
        &actor,
        "secret_rotation",
        if receipt.status == RotationStatus::Committed {
            AuditDecision::Allowed
        } else {
            AuditDecision::Denied
        },
        Some(key.clone()),
        format!(
            "Dual-phase rotation of '{key}' (env={env}): {:?}",
            receipt.status
        ),
    );
    Ok(Json(receipt))
}

pub async fn list_rotations_handler(
    State(state): State<ServerState>,
) -> Json<Vec<RotationReceipt>> {
    Json(load_json(&state.workspace_root, ROTATIONS_FILE))
}

// ---------------------------------------------------------------------------
// Keyless OIDC workload identity
// ---------------------------------------------------------------------------

fn decode_key(raw: &str) -> Option<Zeroizing<[u8; 32]>> {
    let raw = raw.trim();
    let bytes = Zeroizing::new(
        if raw.len() == 64 && raw.bytes().all(|b| b.is_ascii_hexdigit()) {
            (0..32)
                .map(|i| u8::from_str_radix(raw.get(i * 2..i * 2 + 2)?, 16).ok())
                .collect::<Option<Vec<u8>>>()?
        } else {
            base64::engine::general_purpose::STANDARD
                .decode(raw)
                .or_else(|_| base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(raw))
                .ok()?
        },
    );
    let mut key = Zeroizing::new([0u8; 32]);
    (bytes.len() == 32).then(|| {
        key.copy_from_slice(&bytes);
        key
    })
}

/// The workload token issuer: `PREMIER_OIDC_ISSUER` (default `https://premier.local`), signed
/// with `PREMIER_OIDC_SIGNING_KEY` (64 hex chars or base64 of 32 bytes), else the account's
/// `oidc.key` (a legacy 32-byte HS256 key is reused as the Ed25519 seed), else a fresh key, written to `oidc.key` when `persist` and the account directory
/// is writable. Unexpired principal and `jti` revocations are re-applied; stale ones are pruned.
pub fn load_oidc_issuer(account_root: &Path, persist: bool) -> OidcTokenIssuer {
    let issuer = std::env::var("PREMIER_OIDC_ISSUER")
        .ok()
        .filter(|s| !s.trim().is_empty())
        .unwrap_or_else(|| "https://premier.local".to_owned());
    let dir = crate::store::account_dir(account_root);
    let key_path = dir.join(OIDC_KEY_FILE);
    let key = std::env::var("PREMIER_OIDC_SIGNING_KEY")
        .ok()
        .and_then(|raw| decode_key(&raw))
        .or_else(|| {
            let raw = Zeroizing::new(std::fs::read_to_string(&key_path).ok()?);
            decode_key(&raw)
        });
    let key = key.unwrap_or_else(|| {
        let mut key = Zeroizing::new([0u8; 32]);
        key.copy_from_slice(&crate::auth::random_bytes(32));
        // Never creates the account directory as a side effect of building a state.
        if persist && premier_secrets::create_state_dir(&dir).is_ok() {
            let hex = Zeroizing::new(key.iter().map(|b| format!("{b:02x}")).collect::<String>());
            if let Err(e) = premier_secrets::write_private(&key_path, hex.as_bytes()) {
                tracing::warn!(error = %e, "OIDC signing key kept in memory only");
            }
        }
        key
    });
    let iss = OidcTokenIssuer::new(issuer, *key);
    let now = Utc::now();
    let _guard = RECEIPTS.lock().unwrap_or_else(PoisonError::into_inner);
    let mut revoked = load_oidc_revocations(&dir);
    let pruned = revoked.prune(now);
    for (principal, at) in &revoked.principals {
        iss.revoke_principal_at(principal, at.timestamp());
    }
    for (jti, exp) in &revoked.jtis {
        iss.revoke_jti_until(jti, *exp);
    }
    // Only rewrites an existing file; never creates the account directory as a side effect.
    if persist
        && pruned
        && dir.join(OIDC_REVOKED_FILE).exists()
        && let Err(e) = save_json_in(&dir, OIDC_REVOKED_FILE, &revoked)
    {
        tracing::warn!(error = %e, "failed to persist pruned OIDC revocations");
    }
    iss
}

/// On-disk `oidc_revoked.json`: principal revocation times plus revoked `jti -> exp` (unix secs).
#[derive(Debug, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct OidcRevocations {
    #[serde(default)]
    principals: BTreeMap<String, DateTime<Utc>>,
    #[serde(default)]
    jtis: BTreeMap<String, i64>,
}

/// Current format, or the legacy bare `principal -> revoked_at` map.
#[derive(Deserialize)]
#[serde(untagged)]
enum OidcRevokedFile {
    Current(OidcRevocations),
    Legacy(BTreeMap<String, DateTime<Utc>>),
}

impl Default for OidcRevokedFile {
    fn default() -> Self {
        Self::Current(OidcRevocations::default())
    }
}

impl OidcRevocations {
    /// Drop entries that can no longer cover a live token; true if anything was removed.
    fn prune(&mut self, now: DateTime<Utc>) -> bool {
        let before = self.principals.len() + self.jtis.len();
        self.principals.retain(|_, at| {
            (now - *at).num_seconds() <= premier_secrets::MAX_TOKEN_TTL_SECS as i64
        });
        self.jtis.retain(|_, exp| *exp > now.timestamp());
        self.principals.len() + self.jtis.len() != before
    }
}

fn load_oidc_revocations(dir: &Path) -> OidcRevocations {
    match load_json_in::<OidcRevokedFile>(dir, OIDC_REVOKED_FILE) {
        OidcRevokedFile::Current(c) => c,
        OidcRevokedFile::Legacy(principals) => OidcRevocations {
            principals,
            jtis: BTreeMap::new(),
        },
    }
}

/// Reject `principal`'s workload tokens issued at or before `now` and persist across restarts.
fn revoke_oidc_principal(state: &ServerState, principal: &str) -> Result<(), String> {
    let now = Utc::now();
    state
        .oidc_issuer
        .revoke_principal_at(principal, now.timestamp());
    state.oidc_issuer.prune_revoked(now.timestamp());
    let dir = crate::store::account_dir(state.account_root());
    let _guard = RECEIPTS.lock().unwrap_or_else(PoisonError::into_inner);
    let mut revoked = load_oidc_revocations(&dir);
    revoked.prune(now);
    revoked.principals.insert(principal.to_owned(), now);
    save_json_in(&dir, OIDC_REVOKED_FILE, &revoked)
}

/// Reject the workload token `jti` until `expires_at` (normally its `exp`) and persist it across
/// restarts. Expired entries are pruned from memory and disk.
pub fn revoke_oidc_jti(
    state: &ServerState,
    jti: &str,
    expires_at: DateTime<Utc>,
) -> Result<(), String> {
    let now = Utc::now();
    state
        .oidc_issuer
        .revoke_jti_until(jti, expires_at.timestamp());
    state.oidc_issuer.prune_revoked(now.timestamp());
    let dir = crate::store::account_dir(state.account_root());
    let _guard = RECEIPTS.lock().unwrap_or_else(PoisonError::into_inner);
    let mut revoked = load_oidc_revocations(&dir);
    revoked
        .jtis
        .entry(jti.to_owned())
        .and_modify(|prev| *prev = (*prev).max(expires_at.timestamp()))
        .or_insert(expires_at.timestamp());
    revoked.prune(now);
    save_json_in(&dir, OIDC_REVOKED_FILE, &revoked)
}

/// The workload token scope of `identity` (already `human ∩ agent`): the schema variables it
/// may `use` / `read` on `branch`, and their zones. No policy or schema: nothing.
pub fn workload_scope(
    policy: Option<&CompiledPolicy>,
    schema: Option<&EnvSchema>,
    identity: &DelegatedIdentity,
    branch: &str,
) -> Vec<String> {
    let (Some(policy), Some(schema)) = (policy, schema) else {
        return Vec::new();
    };
    let mut scope = BTreeSet::new();
    for (name, spec) in &schema.vars {
        let dec = policy.can_use_secret(identity, name, spec.zone.as_deref(), branch);
        let (read, used) = (dec.allows(Capability::READ), dec.allows(Capability::USE));
        if read {
            scope.insert(format!("secrets:read:{name}"));
        }
        if used {
            scope.insert(format!("secrets:use:{name}"));
        }
        if (read || used)
            && let Some(zone) = &spec.zone
        {
            scope.insert(format!("zone:{zone}"));
        }
    }
    scope.into_iter().collect()
}

pub async fn oidc_discovery_handler(State(state): State<ServerState>) -> Json<Value> {
    Json(state.oidc_issuer.discovery_document())
}

pub use self::oidc_discovery_handler as openid_configuration_handler;

/// `GET /.well-known/jwks.json`: the public Ed25519 verification key set (no secret material).
pub async fn jwks_handler(State(state): State<ServerState>) -> impl IntoResponse {
    (
        [
            (header::CACHE_CONTROL, "public, max-age=300"),
            (header::CONTENT_TYPE, "application/json"),
        ],
        Json(state.oidc_issuer.jwks()),
    )
}

#[derive(Debug, Default, Deserialize)]
pub struct OidcTokenRequest {
    #[serde(default)]
    pub principal: Option<String>,
    #[serde(default)]
    pub agent_profile: Option<String>,
    #[serde(default)]
    pub task_id: Option<String>,
    #[serde(alias = "aud", default)]
    pub audience: Vec<String>,
    #[serde(default)]
    pub branch: Option<String>,
    #[serde(default)]
    pub ttl_secs: Option<u64>,
}

/// `POST /v1/oidc/token`: mint a short-lived workload token. A caller mints for themself; only
/// an owner signed in with a browser may mint for another principal.
pub async fn oidc_token_handler(
    State(state): State<ServerState>,
    Extension(user): Extension<AuthUser>,
    Json(req): Json<OidcTokenRequest>,
) -> Result<Json<Value>, ApiErr> {
    let caller = format!("@{}", user.username);
    let principal = match non_empty(req.principal) {
        None => Principal::parse(&caller),
        Some(raw) => Principal::parse(&raw),
    }
    .map_err(|e| err_resp(StatusCode::BAD_REQUEST, e.to_string()))?;
    let sub = principal.canonical_id();
    if sub != caller && crate::auth::owner_only().is_err() {
        return Err(err_resp(
            StatusCode::FORBIDDEN,
            "only an owner signed in with a browser may mint a workload token for another principal",
        ));
    }
    let policy = state.current_policy();
    let requested_profile = non_empty(req.agent_profile);
    let profile = match &user.agent_profile {
        Some(bound) => {
            if requested_profile.as_deref().is_some_and(|p| p != bound) {
                return Err(err_resp(
                    StatusCode::FORBIDDEN,
                    "access token is bound to a different agent_profile",
                ));
            }
            Some(bound.clone())
        }
        None => requested_profile,
    };
    if let (Some(name), Some(p)) = (&profile, &policy)
        && !p.has_agent_profile(name)
    {
        return Err(err_resp(
            StatusCode::BAD_REQUEST,
            format!("agent profile '{name}' is not defined in this repository's policy"),
        ));
    }
    let groups = crate::directory::groups_for(&state, &principal).map_err(ise)?;
    let task_id = non_empty(req.task_id)
        .unwrap_or_else(|| format!("oidc-{}", random_id().get(..12).unwrap_or_default()));
    let identity = match &profile {
        Some(p) => DelegatedIdentity::delegated(
            principal.clone(),
            groups.clone(),
            p.clone(),
            task_id.clone(),
        ),
        None => DelegatedIdentity::human_only(principal.clone(), groups.clone()),
    };
    let branch = req.branch.unwrap_or_else(|| {
        let (short, tip) = crate::checked_out(&state.workspace_root);
        tip.filter(|tip| tip.starts_with("refs/")).unwrap_or(short)
    });
    let full_ref = crate::visible_branch(&state, &identity, &branch)?;
    let branch = crate::ref_short(&full_ref).unwrap_or(&full_ref).to_owned();
    let scope = workload_scope(
        policy.as_deref(),
        state.current_env_schema().as_deref(),
        &identity,
        &branch,
    );
    let aud: Vec<String> = req
        .audience
        .into_iter()
        .map(|a| a.trim().to_owned())
        .filter(|a| !a.is_empty())
        .collect();
    let aud = if aud.is_empty() {
        vec!["premier".to_owned()]
    } else {
        aud
    };
    if crate::auth::owner_only().is_err() {
        // The server process may explicitly opt delegated callers into more audiences.
        let allowed = std::env::var("PREMIER_OIDC_ALLOWED_AUDIENCES").unwrap_or_default();
        if aud.iter().any(|audience| {
            audience != "premier" && !allowed.split(',').any(|item| item.trim() == audience)
        }) {
            return Err(err_resp(
                StatusCode::FORBIDDEN,
                "workload token audience is not allowed",
            ));
        }
    }
    let issued = state
        .oidc_issuer
        .issue(WorkloadTokenRequest {
            sub: sub.clone(),
            act: profile.map(|p| ActorClaim {
                sub: format!("agent:{p}"),
                profile: p,
                task_id,
            }),
            aud,
            repo: repo_id(&state),
            branch,
            scope,
            groups,
            ttl_secs: req.ttl_secs,
        })
        .map_err(|e| err_resp(StatusCode::BAD_REQUEST, e.to_string()))?;
    audit(
        &state,
        &caller,
        "oidc_token_issued",
        AuditDecision::Allowed,
        Some(sub),
        format!(
            "Issued workload token jti={} (aud={}, exp={})",
            issued.claims.jti,
            issued.claims.aud.join(","),
            issued.claims.exp
        ),
    );
    Ok(Json(json!({
        "token": issued.token,
        "claims": issued.claims,
        "kid": issued.kid,
        "alg": issued.alg,
    })))
}

#[derive(Debug, Deserialize)]
pub struct OidcVerifyRequest {
    #[serde(default)]
    pub token: String,
    #[serde(alias = "aud", default)]
    pub audience: String,
}

/// `POST /v1/oidc/verify`: `{ valid, claims }` or `{ valid: false, error }`.
pub async fn oidc_verify_handler(
    State(state): State<ServerState>,
    Json(req): Json<OidcVerifyRequest>,
) -> Result<Json<Value>, ApiErr> {
    let (token, audience) = (req.token.trim(), req.audience.trim());
    if token.is_empty() || audience.is_empty() {
        return Err(err_resp(
            StatusCode::BAD_REQUEST,
            "token and audience must be non-empty",
        ));
    }
    Ok(Json(match state.oidc_issuer.verify(token, audience) {
        Ok(claims) => json!({ "valid": true, "claims": claims }),
        Err(e) => json!({ "valid": false, "error": e.to_string() }),
    }))
}

// ---------------------------------------------------------------------------
// One-click offboarding kill switch
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Deserialize)]
pub struct OffboardRequest {
    pub principal: String,
    #[serde(default)]
    pub reason: Option<String>,
    #[serde(default = "default_prod")]
    pub env: String,
    #[serde(default = "default_true")]
    pub rotate_secrets: bool,
    #[serde(default)]
    pub delete_account: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OffboardReceipt {
    pub id: String,
    pub principal: String,
    pub actor: String,
    pub reason: String,
    pub timestamp: DateTime<Utc>,
    pub account_disabled: bool,
    pub account_deleted: bool,
    pub sessions_revoked: usize,
    pub tokens_revoked: usize,
    pub ssh_keys_revoked: usize,
    pub approvals_revoked: usize,
    pub agent_sessions_terminated: usize,
    pub oidc_revoked: bool,
    pub rotations: Vec<RotationReceipt>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub persist_errors: Vec<String>,
}

fn strip_branch_prefix(r: &str) -> &str {
    r.strip_prefix("refs/heads/")
        .or_else(|| r.strip_prefix("refs/premier-private/"))
        .unwrap_or(r)
}

fn all_short_branches(state: &ServerState) -> BTreeSet<String> {
    let mut branches = BTreeSet::new();
    let checked_out = crate::checked_out(&state.workspace_root).0;
    if !checked_out.trim().is_empty() {
        branches.insert(checked_out);
    }
    if let Ok(refs) = premier_git_bridge::CanonicalGitRepo::open(&state.workspace_root).list_refs()
    {
        for (full, _) in refs {
            if full.starts_with("refs/heads/") || full.starts_with("refs/premier-private/") {
                branches.insert(strip_branch_prefix(&full).to_owned());
            }
        }
    }
    for full in state.branch_visibility_map().keys() {
        if full.starts_with("refs/heads/") || full.starts_with("refs/premier-private/") {
            branches.insert(strip_branch_prefix(full).to_owned());
        }
    }
    branches
}

/// The secret variables `identity` may `use` or `read` on any branch/ref in this repo.
fn exposed_secrets(
    state: &ServerState,
    identity: &DelegatedIdentity,
) -> Vec<(String, premier_secrets::VarSpec)> {
    let Some(schema) = state.current_env_schema() else {
        return Vec::new();
    };
    let policy = state.current_policy();
    let branches = all_short_branches(state);
    schema
        .vars
        .iter()
        .filter(|(_, spec)| {
            matches!(
                spec.sensitivity,
                Sensitivity::Secret | Sensitivity::Restricted
            )
        })
        .filter(|(name, spec)| {
            policy.as_ref().is_none_or(|p| {
                branches.iter().any(|branch| {
                    let dec = p.can_use_secret(identity, name, spec.zone.as_deref(), branch);
                    dec.allows(Capability::USE) || dec.allows(Capability::READ)
                })
            })
        })
        .map(|(name, spec)| (name.clone(), spec.clone()))
        .collect()
}

/// Revoke everything `req.principal` holds across all loaded repositories: account (disabled or
/// deleted), browser sessions, access tokens, SSH keys, JIT approvals, live agent sessions and
/// workload tokens; then rotate (or flag for manual revocation) every secret the principal could
/// use on any branch. Refuses to offboard the caller or the last enabled owner (409) first.
pub async fn offboard(
    state: &ServerState,
    req: OffboardRequest,
    actor: &str,
    caller_username: Option<&str>,
) -> Result<OffboardReceipt, Fail> {
    let username = req
        .principal
        .trim()
        .trim_start_matches('@')
        .to_ascii_lowercase();
    let principal = Principal::parse(&format!("@{username}"))
        .ok()
        .filter(|p| matches!(p, Principal::User(_)))
        .ok_or_else(|| {
            (
                StatusCode::BAD_REQUEST,
                format!("'{}' is not a user principal", req.principal),
            )
        })?;
    let canonical = principal.canonical_id();
    if caller_username.is_some_and(|me| me.eq_ignore_ascii_case(&username)) {
        return Err((
            StatusCode::CONFLICT,
            "you cannot offboard yourself".to_owned(),
        ));
    }
    let reason = non_empty(req.reason).unwrap_or_else(|| "offboarded".to_owned());
    let env = if req.env.trim().is_empty() {
        default_prod()
    } else {
        req.env.trim().to_owned()
    };

    let repos = state.all_repo_states();

    // 1. What the principal could reach across all repos & branches, with its groups, before revocation.
    let groups = crate::directory::groups_for(state, &principal)
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e))?;
    let identity = DelegatedIdentity::human_only(principal, groups);
    let repo_exposed: Vec<(ServerState, Vec<(String, premier_secrets::VarSpec)>)> = repos
        .iter()
        .map(|repo| (repo.clone(), exposed_secrets(repo, &identity)))
        .collect();

    // 2. Login account, sessions, tokens, SSH keys (refuses the last enabled owner).
    let auth = state
        .auth
        .revoke_user_access(&username, actor, &reason, req.delete_account)?;

    let mut persist_errors = Vec::new();
    let mut critical_persist_failed = false;

    // 3. JIT approvals + 4. Live agent sessions across every loaded repository.
    let mut approvals_revoked = 0usize;
    let mut agent_sessions_terminated = 0usize;
    for repo in &repos {
        approvals_revoked += repo.approval_hub.revoke_principal(&canonical);
        if let Err(e) = save_json(
            &repo.workspace_root,
            "approvals.json",
            &repo.approval_hub.snapshot(),
        ) {
            tracing::warn!(error = %e, repo = %repo.workspace_root.display(), "failed to persist approvals after offboarding");
            persist_errors.push(format!("approvals({}): {e}", repo.workspace_root.display()));
            critical_persist_failed = true;
        }
        agent_sessions_terminated += repo
            .session_manager
            .stop_for_principal(&canonical, &format!("principal offboarded: {reason}"))
            .await;
    }

    // 5. Workload tokens.
    let oidc_revoked = match revoke_oidc_principal(state, &canonical) {
        Ok(()) => true,
        Err(e) => {
            tracing::warn!(error = %e, "failed to persist OIDC revocation after offboarding");
            persist_errors.push(format!("oidc_revoked: {e}"));
            critical_persist_failed = true;
            false
        }
    };

    // 6. Iron Law of Revocation: what was exposed in any repo is rotated at the provider, or flagged.
    let mut rotations = Vec::new();
    if req.rotate_secrets {
        for (repo, exposed) in repo_exposed {
            if exposed.is_empty() {
                continue;
            }
            let mut repo_rotations = Vec::with_capacity(exposed.len());
            for (var, spec) in exposed {
                let receipt = match spec.rotation {
                    Some(rotation) if rotation.revoke_on_offboard => {
                        rotate_var(&repo, &var, rotation, &env, actor, &reason, true, None).await
                    }
                    other => unsent_receipt(
                        &var,
                        &env,
                        other.as_ref(),
                        RotationStatus::ManualRequired,
                        actor,
                        &reason,
                        true,
                        format!(
                            "'{var}' was usable by {canonical} and has no offboarding rotation webhook; revoke it at its provider manually"
                        ),
                    ),
                };
                repo_rotations.push(receipt);
            }
            if let Err(e) = record(&repo.workspace_root, ROTATIONS_FILE, &repo_rotations) {
                tracing::warn!(error = %e, repo = %repo.workspace_root.display(), "failed to persist rotation receipts after offboarding");
                persist_errors.push(format!("rotations({}): {e}", repo.workspace_root.display()));
            }
            rotations.extend(repo_rotations);
        }
    }

    // 7. Group assignments go with a deleted account.
    if req.delete_account
        && let Err(e) = crate::directory::forget(state, &canonical)
    {
        tracing::warn!(error = %e, "failed to drop the directory entry of an offboarded account");
        persist_errors.push(format!("directory: {e}"));
    }

    // 8. The receipt (record best-effort before auditing so audit never gets skipped).
    let mut receipt = OffboardReceipt {
        id: random_id(),
        principal: canonical.clone(),
        actor: actor.to_owned(),
        reason: reason.clone(),
        timestamp: Utc::now(),
        account_disabled: auth.account_disabled,
        account_deleted: auth.account_deleted,
        sessions_revoked: auth.sessions_revoked,
        tokens_revoked: auth.tokens_revoked,
        ssh_keys_revoked: auth.ssh_keys_revoked,
        approvals_revoked,
        agent_sessions_terminated,
        oidc_revoked,
        rotations,
        persist_errors,
    };
    if let Err(e) = record_in(
        &account_dir(state.account_root()),
        OFFBOARDS_FILE,
        std::slice::from_ref(&receipt),
    ) {
        tracing::warn!(error = %e, "failed to persist offboard receipt");
        receipt.persist_errors.push(format!("offboards: {e}"));
    }

    // 9. Always emit the audit event before returning.
    let committed = receipt
        .rotations
        .iter()
        .filter(|r| r.status == RotationStatus::Committed)
        .count();
    let persist_note = if receipt.persist_errors.is_empty() {
        String::new()
    } else {
        format!(
            "; persistence errors: {}",
            receipt.persist_errors.join("; ")
        )
    };
    audit(
        state,
        actor,
        "principal_offboarded",
        AuditDecision::Allowed,
        Some(canonical),
        format!(
            "Offboarded ({reason}): account {}, {} sessions, {} tokens, {} SSH keys, {} approvals, {} agent sessions revoked; {}; {committed}/{} secret rotations committed{persist_note}",
            if receipt.account_deleted {
                "deleted"
            } else if receipt.account_disabled {
                "disabled"
            } else {
                "none"
            },
            receipt.sessions_revoked,
            receipt.tokens_revoked,
            receipt.ssh_keys_revoked,
            receipt.approvals_revoked,
            receipt.agent_sessions_terminated,
            if receipt.oidc_revoked {
                "workload tokens revoked"
            } else {
                "workload token revocation not persisted"
            },
            receipt.rotations.len(),
        ),
    );
    if critical_persist_failed {
        return Err((
            StatusCode::INTERNAL_SERVER_ERROR,
            format!(
                "offboarding applied in memory and audited, but critical revocation persistence failed: {}",
                receipt.persist_errors.join("; ")
            ),
        ));
    }
    Ok(receipt)
}

/// `POST /v1/security/offboard` (and `/v1/auth/offboard`).
pub async fn offboard_handler(
    State(state): State<ServerState>,
    Extension(user): Extension<AuthUser>,
    Json(req): Json<OffboardRequest>,
) -> Result<Json<OffboardReceipt>, ApiErr> {
    let actor = format!("@{}", user.username);
    offboard(&state, req, &actor, Some(&user.username))
        .await
        .map(Json)
        .map_err(api)
}

pub async fn list_offboard_receipts_handler(
    State(state): State<ServerState>,
) -> Json<Vec<OffboardReceipt>> {
    Json(load_json_in(
        &account_dir(state.account_root()),
        OFFBOARDS_FILE,
    ))
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests;

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod oidc_eddsa_tests {
    use super::*;
    use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64URL;

    fn token_req() -> WorkloadTokenRequest {
        WorkloadTokenRequest {
            sub: "@a".to_owned(),
            aud: vec!["x".to_owned()],
            repo: "r".to_owned(),
            branch: "main".to_owned(),
            ..WorkloadTokenRequest::default()
        }
    }

    fn state_in(root: &Path) -> ServerState {
        let (mut state, ..) = crate::tests::member_state(root);
        state.oidc_issuer = Arc::new(load_oidc_issuer(state.account_root(), true));
        state
    }

    #[tokio::test]
    async fn jwks_handler_serves_cacheable_key_that_verifies_minted_tokens() {
        let tmp = tempfile::tempdir().unwrap();
        let state = state_in(tmp.path());
        let minted = state.oidc_issuer.issue(token_req()).unwrap();
        let resp = jwks_handler(State(state.clone())).await.into_response();
        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(
            resp.headers()
                .get_all(header::CACHE_CONTROL)
                .iter()
                .collect::<Vec<_>>(),
            ["public, max-age=300"]
        );
        assert_eq!(
            resp.headers()
                .get_all(header::CONTENT_TYPE)
                .iter()
                .collect::<Vec<_>>(),
            ["application/json"]
        );
        let body = axum::body::to_bytes(resp.into_body(), 1 << 20)
            .await
            .unwrap();
        let jwks: Value = serde_json::from_slice(&body).unwrap();
        let jwk = &jwks["keys"][0];
        assert_eq!(jwk["kty"], "OKP");
        assert_eq!(jwk["crv"], "Ed25519");
        assert_eq!(jwk["alg"], "EdDSA");
        assert_eq!(jwk["kid"], minted.kid);
        let x: [u8; 32] = B64URL
            .decode(jwk["x"].as_str().unwrap())
            .unwrap()
            .try_into()
            .unwrap();
        // Signature math is covered in premier-secrets; here the JWK must be exactly the key that
        // signed the minted token (its header names the same `kid`, and `x` is the public key).
        assert_eq!(x, state.oidc_issuer.public_key_bytes());
        let header: Value = serde_json::from_slice(
            &B64URL
                .decode(minted.token.split('.').next().unwrap())
                .unwrap(),
        )
        .unwrap();
        assert_eq!(header["alg"], "EdDSA");
        assert_eq!(header["kid"], jwk["kid"]);
        assert!(state.oidc_issuer.verify(&minted.token, "x").is_ok());
    }

    #[tokio::test]
    async fn discovery_advertises_eddsa_and_jwks_uri_under_both_names() {
        let tmp = tempfile::tempdir().unwrap();
        let state = state_in(tmp.path());
        for Json(doc) in [
            oidc_discovery_handler(State(state.clone())).await,
            openid_configuration_handler(State(state.clone())).await,
        ] {
            assert_eq!(
                doc["id_token_signing_alg_values_supported"],
                json!(["EdDSA"])
            );
            let iss = state.oidc_issuer.issuer().trim_end_matches('/').to_owned();
            assert_eq!(doc["jwks_uri"], format!("{iss}/.well-known/jwks.json"));
        }
    }

    #[test]
    fn legacy_32_byte_key_files_upgrade_to_ed25519() {
        for (name, contents) in [
            ("hex", "ab".repeat(32)),
            (
                "b64",
                base64::engine::general_purpose::STANDARD.encode([0xabu8; 32]),
            ),
        ] {
            let tmp = tempfile::tempdir().unwrap();
            let dir = account_dir(tmp.path());
            std::fs::create_dir_all(&dir).unwrap();
            std::fs::write(dir.join(OIDC_KEY_FILE), &contents).unwrap();
            let iss = load_oidc_issuer(tmp.path(), true);
            let expected = OidcTokenIssuer::new(iss.issuer(), [0xab; 32]);
            assert_eq!(iss.kid(), expected.kid(), "{name}");
            assert!(iss.kid().starts_with("ed25519-"), "{name}");
            let t = iss.issue(token_req()).unwrap();
            assert_eq!(t.alg, "EdDSA");
            assert!(expected.verify(&t.token, "x").is_ok(), "{name}");
            // The key file is left untouched.
            assert_eq!(
                std::fs::read_to_string(dir.join(OIDC_KEY_FILE)).unwrap(),
                contents
            );
        }
    }

    #[test]
    fn jti_revocation_persists_across_restarts_and_expired_entries_are_pruned() {
        let tmp = tempfile::tempdir().unwrap();
        let state = state_in(tmp.path());
        let live = state.oidc_issuer.issue(token_req()).unwrap();
        let other = state.oidc_issuer.issue(token_req()).unwrap();
        let exp = DateTime::from_timestamp(live.claims.exp, 0).unwrap();
        revoke_oidc_jti(&state, &live.claims.jti, exp).unwrap();
        assert!(state.oidc_issuer.verify(&live.token, "x").is_err());

        // Restart: the revoked jti is still rejected, other tokens still verify.
        let restarted = load_oidc_issuer(state.account_root(), true);
        assert!(restarted.verify(&live.token, "x").is_err());
        assert!(restarted.verify(&other.token, "x").is_ok());

        // An already-expired revocation is never persisted, and a stale one on disk is pruned at load.
        let dir = account_dir(state.account_root());
        let past = Utc::now() - chrono::Duration::seconds(10);
        revoke_oidc_jti(&state, "stale-jti", past).unwrap();
        let on_disk = load_oidc_revocations(&dir);
        assert!(!on_disk.jtis.contains_key("stale-jti"));
        let mut seeded = load_oidc_revocations(&dir);
        seeded.jtis.insert("stale-jti".to_owned(), past.timestamp());
        seeded
            .principals
            .insert("@old".to_owned(), Utc::now() - chrono::Duration::hours(3));
        save_json_in(&dir, OIDC_REVOKED_FILE, &seeded).unwrap();
        let _ = load_oidc_issuer(state.account_root(), true);
        let pruned = load_oidc_revocations(&dir);
        assert!(!pruned.jtis.contains_key("stale-jti"));
        assert!(!pruned.principals.contains_key("@old"));
        assert!(pruned.jtis.contains_key(&live.claims.jti));
    }

    #[test]
    fn legacy_principal_only_file_loads_and_is_kept_on_next_save() {
        let tmp = tempfile::tempdir().unwrap();
        let state = state_in(tmp.path());
        let dir = account_dir(state.account_root());
        let at = Utc::now();
        std::fs::write(
            dir.join(OIDC_REVOKED_FILE),
            serde_json::to_string(&BTreeMap::from([("@a".to_owned(), at)])).unwrap(),
        )
        .unwrap();
        let iss = load_oidc_issuer(state.account_root(), true);
        let tok = state.oidc_issuer.issue(token_req()).unwrap();
        // Same persisted key: the restarted issuer honours the legacy principal revocation.
        assert!(iss.verify_at(&tok.token, "x", at.timestamp()).is_err());

        revoke_oidc_jti(&state, "j1", Utc::now() + chrono::Duration::seconds(60)).unwrap();
        let saved = load_oidc_revocations(&dir);
        assert!(saved.principals.contains_key("@a"));
        assert!(saved.jtis.contains_key("j1"));
        // New format round-trips.
        let raw: Value =
            serde_json::from_str(&std::fs::read_to_string(dir.join(OIDC_REVOKED_FILE)).unwrap())
                .unwrap();
        assert!(raw["principals"].is_object() && raw["jtis"].is_object());
    }
}
