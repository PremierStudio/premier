//! Principal directory: the principals and groups that `.access.toml` rules refer to, persisted in
//! `.premier/directory.json`. It is the only source of group membership: every identity the
//! server evaluates policy for gets its groups here, never from the request.
//!
//! Accounts are synthesised from `auth.json` (never duplicated here); every owner carries the
//! implicit [`OWNERS_GROUP`]. A member's request is always evaluated as that member: see
//! [`identity`].

use std::collections::{BTreeMap, BTreeSet};
use std::path::PathBuf;
use std::sync::{Mutex, PoisonError};

use axum::extract::{Path as AxumPath, State};
use axum::http::StatusCode;
use axum::{Extension, Json};
use premier_core::{AuditDecision, AuditEvent, DelegatedIdentity, Principal};
use serde::{Deserialize, Serialize};

use crate::auth::AuthUser;
use crate::{ApiError, ServerState, err_resp};

/// Group every owner account is implicitly in; reserved, it cannot be assigned to anyone else.
pub const OWNERS_GROUP: &str = "owners";

/// Policy served (in memory) when the workspace has no `.access.toml`: private by default. The
/// comment is saved into the real file with the rest, so it must read true there as well.
pub const DEFAULT_POLICY_TOML: &str = r#"# Premier starter policy: only owners have access. Add rules below.
# Everyone else, including anonymous Git clones, gets nothing until a rule grants it.
version = 1

[defaults]
public = []
authenticated = []

[[rules]]
id = "owners-full-access"
effect = "allow"
principals = ["group:owners"]
paths = ["**"]
refs = ["*"]
capabilities = ["traverse", "list", "read", "write", "use"]
reason = "Workspace owners have full access; nobody else has any until rules grant it"
"#;

const MAX_GROUPS: usize = 32;

type ApiErr = (StatusCode, Json<ApiError>);

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
struct Entry {
    #[serde(default)]
    display_name: String,
    #[serde(default)]
    groups: Vec<String>,
}

/// On-disk shape, keyed by canonical principal id (`@name`, `bot:x`, ...).
#[derive(Debug, Default, Serialize, Deserialize)]
struct DirectoryFile {
    #[serde(default)]
    principals: BTreeMap<String, Entry>,
}

#[derive(Debug, Serialize)]
pub struct DirectoryPrincipal {
    pub principal: String,
    pub display_name: String,
    pub groups: Vec<String>,
    pub is_owner: bool,
    pub has_account: bool,
}

#[derive(Debug, Serialize)]
pub struct Directory {
    pub principals: Vec<DirectoryPrincipal>,
    pub groups: Vec<String>,
}

// Serialises read-modify-write of directory.json within this process.
static WRITE_LOCK: Mutex<()> = Mutex::new(());

fn file_path(state: &ServerState) -> PathBuf {
    crate::store::account_dir(state.account_root()).join("directory.json")
}

/// A missing file is an empty directory; a corrupt one is an error, never "nobody has groups
/// except by accident".
fn load(state: &ServerState) -> Result<DirectoryFile, String> {
    match std::fs::read_to_string(file_path(state)) {
        Ok(raw) => {
            serde_json::from_str(&raw).map_err(|e| format!("directory.json is corrupt: {e}"))
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(DirectoryFile::default()),
        Err(e) => Err(format!("read directory.json failed: {e}")),
    }
}

fn save(state: &ServerState, file: &DirectoryFile) -> Result<(), String> {
    let path = file_path(state);
    let dir = path.parent().ok_or("directory.json has no parent dir")?;
    premier_secrets::create_state_dir(dir).map_err(|e| format!("create state dir failed: {e}"))?;
    let tmp = dir.join(format!("directory.json.tmp.{}", std::process::id()));
    let json = serde_json::to_vec_pretty(file).map_err(|e| format!("serialize directory: {e}"))?;
    premier_secrets::write_private(&tmp, &json)
        .map_err(|e| format!("write directory tmp failed: {e}"))?;
    std::fs::rename(&tmp, &path).map_err(|e| format!("atomic rename directory failed: {e}"))
}

fn owner_groups(assigned: Option<&Entry>) -> Vec<String> {
    let mut groups = vec![OWNERS_GROUP.to_owned()];
    groups.extend(assigned.into_iter().flat_map(|e| e.groups.iter().cloned()));
    groups
}

/// Server-side group membership of `principal`.
pub(crate) fn groups_for(
    state: &ServerState,
    principal: &Principal,
) -> Result<Vec<String>, String> {
    if !principal.is_authenticated() {
        return Ok(vec![]);
    }
    let id = principal.canonical_id();
    let file = load(state)?;
    let entry = file.principals.get(&id);
    let is_owner = state
        .auth
        .accounts()?
        .iter()
        .any(|(account, _, owner)| *owner && *account == id);
    Ok(if is_owner {
        owner_groups(entry)
    } else {
        entry.map(|e| e.groups.clone()).unwrap_or_default()
    })
}

/// The one way a claimed principal string becomes an identity: the claim only stands for an
/// owner (a member is themself), and groups come from the directory. If the caller authenticated
/// with an agent-scoped access token, its bound `agent_profile` is always enforced
/// (`permissions(human) ∩ permissions(agent_profile)`), and passing a mismatched profile is
/// rejected with `403 Forbidden`.
pub(crate) fn identity(
    state: &ServerState,
    principal_raw: &str,
    agent_profile: Option<String>,
    task_tag: &str,
) -> Result<DelegatedIdentity, ApiErr> {
    let principal = Principal::parse(&crate::auth::effective_principal(principal_raw))
        .map_err(|e| err_resp(StatusCode::BAD_REQUEST, e.to_string()))?;
    let groups = groups_for(state, &principal).map_err(ise)?;
    let requested = agent_profile
        .map(|s| s.trim().to_owned())
        .filter(|s| !s.is_empty());
    let effective_profile = match crate::auth::bound_agent_profile() {
        Some(bound) => {
            if requested.as_deref().is_some_and(|req| req != bound) {
                return Err(err_resp(
                    StatusCode::FORBIDDEN,
                    "access token is bound to a different agent_profile",
                ));
            }
            Some(bound)
        }
        None => requested,
    };
    Ok(match effective_profile {
        Some(prof) => DelegatedIdentity::delegated(principal, groups, prof, task_tag),
        None => DelegatedIdentity::human_only(principal, groups),
    })
}

/// Human-only identities of every directory principal plus anonymous (access-diff default set).
pub(crate) fn all_identities(state: &ServerState) -> Result<Vec<DelegatedIdentity>, ApiErr> {
    let mut out = vec![DelegatedIdentity::human_only(Principal::Anonymous, vec![])];
    for p in snapshot(state).map_err(ise)?.principals {
        if let Ok(principal) = Principal::parse(&p.principal) {
            out.push(DelegatedIdentity::human_only(principal, p.groups));
        }
    }
    Ok(out)
}

fn snapshot(state: &ServerState) -> Result<Directory, String> {
    let mut file = load(state)?;
    let mut principals = Vec::new();
    for (id, display_name, is_owner) in state.auth.accounts()? {
        let assigned = file.principals.remove(&id);
        principals.push(DirectoryPrincipal {
            groups: if is_owner {
                owner_groups(assigned.as_ref())
            } else {
                assigned.map(|e| e.groups).unwrap_or_default()
            },
            principal: id,
            display_name,
            is_owner,
            has_account: true,
        });
    }
    principals.extend(
        file.principals
            .into_iter()
            .map(|(principal, e)| DirectoryPrincipal {
                principal,
                display_name: e.display_name,
                groups: e.groups,
                is_owner: false,
                has_account: false,
            }),
    );
    let groups: BTreeSet<String> = principals
        .iter()
        .flat_map(|p| p.groups.iter().cloned())
        .collect();
    Ok(Directory {
        principals,
        groups: groups.into_iter().collect(),
    })
}

fn ise(msg: String) -> ApiErr {
    err_resp(StatusCode::INTERNAL_SERVER_ERROR, msg)
}

/// Same rule as account management: an access token cannot rewrite who is in which group.
fn require_session(user: &AuthUser) -> Result<(), ApiErr> {
    if user.session_id.is_none() {
        return Err(err_resp(
            StatusCode::FORBIDDEN,
            "directory changes require a browser session",
        ));
    }
    Ok(())
}

/// Canonical id of a path-parameter principal, or 400.
fn principal_id(raw: &str) -> Result<String, ApiErr> {
    let bad = |msg: &str| err_resp(StatusCode::BAD_REQUEST, msg);
    let principal = Principal::parse(raw).map_err(|e| bad(&e.to_string()))?;
    if !principal.is_authenticated() {
        return Err(bad("the anonymous principal cannot be in the directory"));
    }
    let id = principal.canonical_id();
    if id.len() > 64 || !id.chars().all(|c| c.is_ascii_graphic()) {
        return Err(bad(
            "principal must be at most 64 printable ASCII characters",
        ));
    }
    Ok(id)
}

fn valid_groups(raw: Vec<String>, is_owner: bool) -> Result<Vec<String>, ApiErr> {
    let bad = |msg: String| err_resp(StatusCode::BAD_REQUEST, msg);
    let mut groups = BTreeSet::new();
    for g in raw {
        let ok = (1..=32).contains(&g.len())
            && g.bytes()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_' || b == b'-');
        if !ok {
            return Err(bad(format!(
                "group name '{g}' must be 1-32 characters of a-z, 0-9, '_' or '-'"
            )));
        }
        if g == OWNERS_GROUP {
            if is_owner {
                continue; // implicit, never stored
            }
            return Err(bad(format!(
                "the '{OWNERS_GROUP}' group is reserved for owner accounts"
            )));
        }
        groups.insert(g);
    }
    if groups.len() > MAX_GROUPS {
        return Err(bad(format!(
            "a principal can be in at most {MAX_GROUPS} groups"
        )));
    }
    Ok(groups.into_iter().collect())
}

/// Drop the stored groups of a deleted account.
pub(crate) fn forget(state: &ServerState, id: &str) -> Result<(), String> {
    let _guard = WRITE_LOCK.lock().unwrap_or_else(PoisonError::into_inner);
    let mut file = load(state)?;
    if file.principals.remove(id).is_some() {
        save(state, &file)?;
    }
    Ok(())
}

fn audit_change(state: &ServerState, user: &AuthUser, action: &str, reason: String, target: &str) {
    let actor = identity(state, &format!("@{}", user.username), None, "directory")
        .unwrap_or_else(|_| DelegatedIdentity::human_only(Principal::Anonymous, vec![]));
    let mut ev = AuditEvent::now(
        &actor,
        "premier-server",
        action,
        AuditDecision::Allowed,
        reason,
    );
    ev.target = Some(target.to_owned());
    crate::auth::audit(&state.audit_sink, ev);
}

pub async fn get_handler(State(state): State<ServerState>) -> Result<Json<Directory>, ApiErr> {
    let mut dir = snapshot(&state).map_err(ise)?;
    if crate::auth::owner_only().is_err() {
        let me = crate::auth::actor_principal();
        dir.principals.retain(|p| p.principal == me);
        let groups: BTreeSet<String> = dir
            .principals
            .iter()
            .flat_map(|p| p.groups.iter().cloned())
            .collect();
        dir.groups = groups.into_iter().collect();
    }
    Ok(Json(dir))
}

#[derive(Debug, Deserialize)]
pub struct UpsertPrincipalRequest {
    #[serde(default)]
    pub display_name: String,
    #[serde(default)]
    pub groups: Vec<String>,
}

pub async fn put_principal_handler(
    State(state): State<ServerState>,
    Extension(user): Extension<AuthUser>,
    AxumPath(principal): AxumPath<String>,
    Json(req): Json<UpsertPrincipalRequest>,
) -> Result<Json<Directory>, ApiErr> {
    require_session(&user)?;
    let id = principal_id(&principal)?;
    let accounts = state.auth.accounts().map_err(ise)?;
    let account = accounts.iter().find(|(account, ..)| *account == id);
    let groups = valid_groups(req.groups, account.is_some_and(|a| a.2))?;
    // An account's display name lives in auth.json (`PATCH /v1/auth/profile`), not here.
    let display_name = if account.is_some() {
        String::new()
    } else if req.display_name.trim().is_empty() {
        id.trim_start_matches('@').to_owned()
    } else {
        crate::auth::valid_display_name(&req.display_name)?
    };

    {
        let _guard = WRITE_LOCK.lock().unwrap_or_else(PoisonError::into_inner);
        let mut file = load(&state).map_err(ise)?;
        file.principals.insert(
            id.clone(),
            Entry {
                display_name,
                groups: groups.clone(),
            },
        );
        save(&state, &file).map_err(ise)?;
    }
    audit_change(
        &state,
        &user,
        "directory_principal_upserted",
        format!("Set groups of {id} to [{}]", groups.join(", ")),
        &id,
    );
    snapshot(&state).map(Json).map_err(ise)
}

pub async fn delete_principal_handler(
    State(state): State<ServerState>,
    Extension(user): Extension<AuthUser>,
    AxumPath(principal): AxumPath<String>,
) -> Result<Json<Directory>, ApiErr> {
    require_session(&user)?;
    let id = principal_id(&principal)?;
    let accounts = state.auth.accounts().map_err(ise)?;
    if accounts.iter().any(|(account, ..)| *account == id) {
        return Err(err_resp(
            StatusCode::CONFLICT,
            format!("'{id}' has an account; delete the user instead"),
        ));
    }
    {
        let _guard = WRITE_LOCK.lock().unwrap_or_else(PoisonError::into_inner);
        let mut file = load(&state).map_err(ise)?;
        if file.principals.remove(&id).is_none() {
            return Err(err_resp(
                StatusCode::NOT_FOUND,
                format!("principal '{id}' is not in the directory"),
            ));
        }
        save(&state, &file).map_err(ise)?;
    }
    audit_change(
        &state,
        &user,
        "directory_principal_removed",
        format!("Removed {id} from the directory"),
        &id,
    );
    snapshot(&state).map(Json).map_err(ise)
}
