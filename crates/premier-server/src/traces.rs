//! HTTP handlers for `premier-trace` (`agent-trace`):
//! ACL-scoped trace listing, prompt blame search, hook ingestion, sample seeding, and deletion.

use axum::extract::{Path as AxumPath, Query, State};
use axum::http::StatusCode;
use axum::{Extension, Json};
use premier_core::{DelegatedIdentity, Principal};
use premier_secrets::SecretRedactor;
use premier_trace::{
    DeliverySummary, SessionStatus, TraceSession, TraceSpan, ingest_agent_hook_json,
};
use serde::{Deserialize, Serialize};
use zeroize::Zeroize;

use crate::{ApiError, ServerState, auth, directory, err_resp};

const MAX_INGEST_BYTES: usize = 256 * 1024;

#[derive(Debug, Deserialize)]
pub struct TracesQuery {
    #[serde(default = "default_principal")]
    pub principal: String,
    #[serde(default)]
    pub agent_profile: Option<String>,
    #[serde(default = "default_ref_name")]
    pub ref_name: String,
}

#[derive(Debug, Deserialize)]
pub struct TracesBlameQuery {
    pub q: String,
    #[serde(default = "default_principal")]
    pub principal: String,
    #[serde(default)]
    pub agent_profile: Option<String>,
    #[serde(default = "default_ref_name")]
    pub ref_name: String,
}

#[derive(Debug, Serialize)]
pub struct TraceIngestResponse {
    pub ok: bool,
    pub session_id: String,
    pub span: TraceSpan,
    pub bytes_scrubbed: usize,
}

#[derive(Debug, Serialize)]
pub struct TraceDeleteResponse {
    pub ok: bool,
    pub deleted: bool,
    pub session_id: String,
}

fn default_principal() -> String {
    auth::actor_principal()
}

fn default_ref_name() -> String {
    "main".to_owned()
}

pub(crate) fn vault_redactor(root: &std::path::Path, repo_id: &str) -> SecretRedactor {
    let secrets = crate::store::load_vault_secrets_zeroizing(root, repo_id);
    SecretRedactor::build(
        secrets
            .iter()
            .map(|(name, value)| (name.as_str(), value.as_str())),
    )
}

pub(crate) async fn repository_redactor(
    state: &ServerState,
) -> Result<SecretRedactor, (StatusCode, Json<ApiError>)> {
    let repo_id = state
        .current_env_schema()
        .and_then(|schema| schema.repo_id.clone())
        .unwrap_or_else(|| "local/repo".to_owned());
    let root = state.workspace_root.clone();
    tokio::task::spawn_blocking(move || vault_redactor(&root, &repo_id))
        .await
        .map_err(|err| err_resp(StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))
}

pub(crate) fn scrub_text(text: &mut String, redactor: &SecretRedactor) -> usize {
    let (clean, count) = redactor.redact_str(text);
    if count != 0 {
        text.zeroize();
        *text = clean;
    }
    count
}

fn scrub_json_keys(value: &mut serde_json::Value, redactor: &SecretRedactor) -> usize {
    match value {
        serde_json::Value::Object(fields) => std::mem::take(fields)
            .into_iter()
            .map(|(mut key, mut value)| {
                let count = scrub_text(&mut key, redactor) + scrub_json_keys(&mut value, redactor);
                fields.insert(key, value);
                count
            })
            .sum(),
        serde_json::Value::Array(items) => items
            .iter_mut()
            .map(|value| scrub_json_keys(value, redactor))
            .sum(),
        _ => 0,
    }
}

pub(crate) fn scrub_span(span: &mut TraceSpan, redactor: &SecretRedactor) {
    if !redactor.is_empty() {
        let label_bytes: usize = [
            &mut span.zone,
            &mut span.tool_name,
            &mut span.actor_id,
            &mut span.actor_type,
            &mut span.parent_span_id,
            &mut span.correlation_id,
            &mut span.status,
            &mut span.language,
            &mut span.source,
        ]
        .into_iter()
        .filter_map(Option::as_mut)
        .chain(&mut span.links)
        .chain([&mut span.span_id])
        .map(|label| scrub_text(label, redactor))
        .sum();
        let key_bytes: usize = [&mut span.input, &mut span.output, &mut span.authority]
            .into_iter()
            .filter_map(Option::as_mut)
            .map(|value| scrub_json_keys(value, redactor))
            .sum();
        span.bytes_scrubbed = span
            .bytes_scrubbed
            .saturating_add(label_bytes)
            .saturating_add(key_bytes);
        premier_trace::scrub_span(span, redactor);
    }
}

fn visible_sessions(
    state: &ServerState,
    viewer: &DelegatedIdentity,
    mut sessions: Vec<TraceSession>,
) -> Vec<TraceSession> {
    let declared = state.branch_visibility_map();
    let refs = crate::branch_ref_names(state, None);
    let may_see = |full: &str| {
        declared.get(full).map_or_else(
            || premier_git_bridge::can_see_ref(viewer, &crate::default_ref_visibility(full)),
            |visibility| premier_git_bridge::can_see_ref(viewer, visibility),
        )
    };
    sessions.retain(|session| {
        if session.model == "mcp-gateway" && !session.session_id.starts_with("tr_mcp_branch_") {
            // Legacy gateway sessions could mix calls spanning multiple visibility scopes.
            return viewer.matches_selector("group:owners");
        }
        if session.branch.contains("[REDACTED:") {
            return viewer.matches_selector("group:owners");
        }
        if session.branch.starts_with("refs/") {
            return crate::ref_short(&session.branch).is_some() && may_see(&session.branch);
        }
        let public = format!("refs/heads/{}", session.branch);
        let private = format!("{}{}", crate::PRIVATE_REF_PREFIX, session.branch);
        if refs.is_none() && state.workspace_root.join(".git").exists() {
            return viewer.matches_selector("group:owners");
        }
        // Older sessions recorded short names. Both namespaces must be visible when both
        // could describe the trace, including refs that were later deleted.
        let private_candidate = declared.contains_key(&private)
            || refs.as_ref().is_some_and(|refs| refs.contains(&private));
        may_see(&public) && (!private_candidate || may_see(&private))
    });
    sessions
}

/// `GET /v1/traces` — list ACL-filtered agent trace sessions newest first.
///
/// Owners may simulate any principal via `?principal=&agent_profile=`; members are always
/// pinned to their authenticated identity by [`directory::identity`].
pub async fn list_traces_handler(
    State(state): State<ServerState>,
    Query(q): Query<TracesQuery>,
) -> Result<Json<Vec<TraceSession>>, (StatusCode, Json<ApiError>)> {
    let identity = directory::identity(&state, &q.principal, q.agent_profile, "studio-traces")?;
    let policy = state.current_policy();
    let sessions =
        state
            .trace_store
            .list_sessions_for_viewer(&identity, policy.as_deref(), &q.ref_name);
    Ok(Json(visible_sessions(&state, &identity, sessions)))
}

/// `GET /v1/traces/blame?q=...` — search ACL-filtered sessions by Change-Id, commit, branch,
/// session ID, or authorized file path.
pub async fn blame_traces_handler(
    State(state): State<ServerState>,
    Query(q): Query<TracesBlameQuery>,
) -> Result<Json<Vec<TraceSession>>, (StatusCode, Json<ApiError>)> {
    let identity =
        directory::identity(&state, &q.principal, q.agent_profile, "studio-trace-blame")?;
    let policy = state.current_policy();
    let sessions = state.trace_store.blame_by_change_or_commit(
        &q.q,
        &identity,
        policy.as_deref(),
        &q.ref_name,
    );
    Ok(Json(visible_sessions(&state, &identity, sessions)))
}

/// `POST /v1/traces/ingest` — ingest a JSON hook payload from Claude Code, Codex, Cursor,
/// Gemini CLI, or generic `ai-tools` hooks with mandatory pre-write secret scrubbing.
pub async fn ingest_trace_handler(
    State(state): State<ServerState>,
    Extension(user): Extension<auth::AuthUser>,
    body: String,
) -> Result<Json<TraceIngestResponse>, (StatusCode, Json<ApiError>)> {
    if body.len() > MAX_INGEST_BYTES {
        return Err(err_resp(
            StatusCode::PAYLOAD_TOO_LARGE,
            format!("trace hook payload exceeds {MAX_INGEST_BYTES} byte limit"),
        ));
    }

    let mut ingested = ingest_agent_hook_json(&body)
        .map_err(|_| err_resp(StatusCode::BAD_REQUEST, "invalid trace hook payload"))?;

    // Only a browser-authenticated owner can attribute imported hooks to another principal.
    let caller_principal = format!("@{}", user.username);
    let mut session_principal = ingested
        .principal
        .take()
        .filter(|principal| !principal.trim().is_empty())
        .unwrap_or_else(|| caller_principal.clone());
    let owner = auth::owner_only().is_ok();
    if session_principal != caller_principal && !owner {
        return Err(err_resp(
            StatusCode::FORBIDDEN,
            "only an owner browser session may attribute a trace to another principal",
        ));
    }

    let redactor = repository_redactor(&state).await?;
    let supplied_branch = ingested.branch.is_some();
    let mut branch = ingested.branch.take().unwrap_or_else(|| "main".to_owned());
    branch = crate::branch_full_ref(&state.workspace_root, &branch).unwrap_or(branch);
    let metadata_bytes: usize = [
        &mut ingested.session_id,
        &mut ingested.tool_source,
        &mut session_principal,
        &mut branch,
    ]
    .into_iter()
    .chain(ingested.model.iter_mut())
    .chain(ingested.change_id.iter_mut())
    .map(|label| scrub_text(label, &redactor))
    .sum();
    ingested.span.bytes_scrubbed = ingested.span.bytes_scrubbed.saturating_add(metadata_bytes);
    scrub_span(&mut ingested.span, &redactor);

    let system_viewer = DelegatedIdentity::human_only(Principal::User("system".to_owned()), vec![]);
    let existing = state.trace_store.get_session_for_viewer(
        &ingested.session_id,
        &system_viewer,
        None,
        "main",
    );

    if let Some(ref existing_session) = existing {
        if !owner && existing_session.principal != caller_principal {
            return Err(err_resp(
                StatusCode::FORBIDDEN,
                "cannot append spans to a trace session owned by another principal",
            ));
        }
        let existing_branch =
            crate::branch_full_ref(&state.workspace_root, &existing_session.branch)
                .unwrap_or_else(|| existing_session.branch.clone());
        if supplied_branch && branch != existing_branch {
            return Err(err_resp(
                StatusCode::CONFLICT,
                "trace session already belongs to a different branch",
            ));
        }
    } else {
        let shell = TraceSession {
            session_id: ingested.session_id.clone(),
            started_at: ingested.span.timestamp,
            updated_at: ingested.span.timestamp,
            principal: session_principal,
            agent_profile: None,
            model: ingested
                .model
                .clone()
                .unwrap_or_else(|| "unknown".to_owned()),
            tool_name: ingested.tool_source.clone(),
            branch,
            change_id: ingested.change_id.clone(),
            commit_oid: None,
            status: SessionStatus::Active,
            spans: Vec::new(),
            delivery: DeliverySummary::default(),
        };
        state
            .trace_store
            .record_session(shell)
            .map_err(|e| err_resp(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    }

    // The store also runs its heuristic scrubber and seals the span into the hash chain.
    let recorded = state
        .trace_store
        .record_span(&ingested.session_id, ingested.span)
        .map_err(|e| err_resp(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    let bytes_scrubbed = recorded.bytes_scrubbed;
    Ok(Json(TraceIngestResponse {
        ok: true,
        session_id: ingested.session_id,
        span: recorded,
        bytes_scrubbed,
    }))
}

/// `POST /v1/traces/sample` (owner-only) — seed sample flight-recorder sessions when empty,
/// returning the ACL-filtered session list for immediate inspection.
pub async fn seed_sample_traces_handler(
    State(state): State<ServerState>,
    Query(q): Query<TracesQuery>,
) -> Result<Json<Vec<TraceSession>>, (StatusCode, Json<ApiError>)> {
    state.trace_store.seed_demo_sessions();
    let identity = directory::identity(&state, &q.principal, q.agent_profile, "studio-traces")?;
    let policy = state.current_policy();
    let sessions =
        state
            .trace_store
            .list_sessions_for_viewer(&identity, policy.as_deref(), &q.ref_name);
    Ok(Json(visible_sessions(&state, &identity, sessions)))
}

/// `DELETE /v1/traces/{session_id}` (owner-only) — remove a recorded trace session.
pub async fn delete_trace_handler(
    State(state): State<ServerState>,
    AxumPath(session_id): AxumPath<String>,
) -> Result<Json<TraceDeleteResponse>, (StatusCode, Json<ApiError>)> {
    let deleted = state
        .trace_store
        .delete_session(&session_id)
        .map_err(|e| err_resp(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    Ok(Json(TraceDeleteResponse {
        ok: true,
        deleted,
        session_id,
    }))
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use std::sync::Arc;

    use axum::body::Body;
    use axum::http::{Method, Request, StatusCode};
    use http_body_util::BodyExt;
    use premier_trace::{REDACTED_ZONE_PATH, REDACTED_ZONE_SUMMARY};
    use serde_json::Value;
    use tower_service::Service;

    use crate::build_router;
    use crate::tests::{member_state, use_member_policy};

    async fn setup_authed_router() -> (axum::Router, String, String) {
        let dir = tempfile::tempdir().unwrap();
        let (mut state, owner_cookie, mia_cookie, _mia_token) = member_state(dir.path());
        use_member_policy(&state);
        state.trace_store = Arc::new(premier_trace::TraceStore::in_memory(
            premier_secrets::SecretRedactor::build(std::iter::empty::<(&str, &str)>()),
        ));
        let _keep = dir.keep();
        let router = build_router(state);
        (router, owner_cookie, mia_cookie)
    }

    async fn read_json(resp: axum::response::Response) -> Value {
        let bytes = resp.into_body().collect().await.unwrap().to_bytes();
        serde_json::from_slice(&bytes).unwrap()
    }

    #[tokio::test]
    async fn traces_scrub_vault_values_and_hide_restricted_branches() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        let (mut state, owner_cookie, member_cookie, _) = member_state(root);
        use_member_policy(&state);
        crate::tests::commit_all(root);
        let branch = "refs/premier-private/trace-embargo";
        assert!(
            premier_git_bridge::git_command(root)
                .args(["update-ref", branch, "HEAD"])
                .status()
                .unwrap()
                .success()
        );
        let raw = "outbound-credential-only-from-vault";
        crate::store::set_workspace_secret(
            root,
            "local/repo",
            "dev",
            "TRACE_CREDENTIAL",
            raw,
            &mut state.persisted.lock().unwrap(),
        )
        .unwrap();
        let log = crate::store::traces_path(root);
        state.trace_store = Arc::new(premier_trace::TraceStore::new(
            Some(log.clone()),
            premier_secrets::SecretRedactor::build(std::iter::empty::<(&str, &str)>()),
        ));
        let (_, owner_token) = state.auth.seed("another-owner", "correct horse battery");
        let mut router = build_router(state);
        let payload = serde_json::json!({
            "hook_event_name": "PostToolUse",
            "session_id": "restricted-trace",
            "principal": "@mia",
            "branch": branch,
            "model": raw,
            "tool_name": raw,
            "summary": format!("external output: {raw}"),
            "tool_input": { "param": raw, (raw): "key" },
        })
        .to_string();
        let request = |name, value: &str| {
            Request::post("/v1/traces/ingest")
                .header(name, value)
                .header("content-type", "application/json")
                .body(Body::from(payload.clone()))
                .unwrap()
        };
        let result = router
            .call(request("authorization", &format!("Bearer {owner_token}")))
            .await
            .unwrap();
        assert_eq!(result.status(), StatusCode::FORBIDDEN);
        let result = router.call(request("cookie", &owner_cookie)).await.unwrap();
        assert_eq!(result.status(), StatusCode::OK);
        let result = read_json(result).await;
        assert!(result["bytes_scrubbed"].as_u64().unwrap() > 0);
        assert!(!result.to_string().contains(raw));
        let written = std::fs::read_to_string(log).unwrap();
        assert!(written.contains("[REDACTED:TRACE_CREDENTIAL]"));
        assert!(!written.contains(raw));

        for uri in ["/v1/traces", "/v1/traces/blame?q=restricted-trace"] {
            for (cookie, count) in [(&owner_cookie, 1), (&member_cookie, 0)] {
                let req = Request::get(uri)
                    .header("cookie", cookie.as_str())
                    .body(Body::empty())
                    .unwrap();
                let result = router.call(req).await.unwrap();
                assert_eq!(result.status(), StatusCode::OK);
                assert_eq!(read_json(result).await.as_array().unwrap().len(), count);
            }
        }
    }

    #[tokio::test]
    async fn ingest_scrubs_secrets_and_enforces_zone_acl_on_read() {
        let (mut router, owner_cookie, member_cookie) = setup_authed_router().await;

        let fake_stripe = ["sk", "live", "TracesScrubKey_01234567"].join("_");
        let payload = serde_json::json!({
            "hook_event_name": "PostToolUse",
            "session_id": "sess_test_1",
            "tool_name": "Edit",
            "file_path": "billing/ledger/tx.rs",
            "summary": format!("Updated ledger with key {fake_stripe}"),
            "command": format!("curl -H 'Authorization: Bearer {fake_stripe}' https://api.stripe.com/v1/charges"),
            "duration_ms": 210
        })
        .to_string();

        let ingest_req = Request::builder()
            .method(Method::POST)
            .uri("/v1/traces/ingest")
            .header("cookie", owner_cookie.as_str())
            .header("content-type", "application/json")
            .body(Body::from(payload))
            .unwrap();
        let resp = router.call(ingest_req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let body = read_json(resp).await;
        assert_eq!(body["ok"], true);
        assert!(body["bytes_scrubbed"].as_u64().unwrap() > 0);
        let span_summary = body["span"]["summary"].as_str().unwrap();
        assert!(!span_summary.contains(&fake_stripe));
        assert!(span_summary.contains("[REDACTED:STRIPE_KEY]"));

        // Owner sees the billing path
        let owner_req = Request::builder()
            .method(Method::GET)
            .uri("/v1/traces")
            .header("cookie", owner_cookie.as_str())
            .body(Body::empty())
            .unwrap();
        let owner_resp = router.call(owner_req).await.unwrap();
        assert_eq!(owner_resp.status(), StatusCode::OK);
        let owner_sessions = read_json(owner_resp).await;
        assert_eq!(
            owner_sessions[0]["spans"][0]["path"].as_str().unwrap(),
            "billing/ledger/tx.rs"
        );

        // Member (even trying to spoof ?principal=@owner) gets Zone-ACL redacted output
        let member_req = Request::builder()
            .method(Method::GET)
            .uri("/v1/traces?principal=@owner")
            .header("cookie", member_cookie.as_str())
            .body(Body::empty())
            .unwrap();
        let member_resp = router.call(member_req).await.unwrap();
        assert_eq!(member_resp.status(), StatusCode::OK);
        let member_sessions = read_json(member_resp).await;
        assert_eq!(
            member_sessions[0]["spans"][0]["path"].as_str().unwrap(),
            REDACTED_ZONE_PATH
        );
        assert_eq!(
            member_sessions[0]["spans"][0]["summary"].as_str().unwrap(),
            REDACTED_ZONE_SUMMARY
        );
        assert_eq!(member_sessions[0]["spans"][0]["redacted_for_viewer"], true);
        assert!(
            member_sessions[0]["delivery"]["files_touched"]
                .as_array()
                .unwrap()
                .is_empty()
        );
    }

    #[tokio::test]
    async fn sample_seed_and_delete_are_owner_only() {
        let (mut router, owner_cookie, member_cookie) = setup_authed_router().await;

        let denied = Request::builder()
            .method(Method::POST)
            .uri("/v1/traces/sample")
            .header("cookie", member_cookie.as_str())
            .body(Body::empty())
            .unwrap();
        assert_eq!(
            router.call(denied).await.unwrap().status(),
            StatusCode::FORBIDDEN
        );

        let seeded = Request::builder()
            .method(Method::POST)
            .uri("/v1/traces/sample")
            .header("cookie", owner_cookie.as_str())
            .body(Body::empty())
            .unwrap();
        let seeded_resp = router.call(seeded).await.unwrap();
        assert_eq!(seeded_resp.status(), StatusCode::OK);
        let sessions = read_json(seeded_resp).await;
        assert_eq!(sessions.as_array().unwrap().len(), 2);

        let sid = sessions[0]["session_id"].as_str().unwrap().to_owned();
        let del = Request::builder()
            .method(Method::DELETE)
            .uri(format!("/v1/traces/{sid}"))
            .header("cookie", owner_cookie.as_str())
            .body(Body::empty())
            .unwrap();
        let del_resp = router.call(del).await.unwrap();
        assert_eq!(del_resp.status(), StatusCode::OK);
        let del_body = read_json(del_resp).await;
        assert_eq!(del_body["deleted"], true);
    }
}
