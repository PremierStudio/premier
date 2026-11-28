//! `GET /v1/worktable`: one round trip for the Studio worktable. Branches, reviews, quarantine
//! items, agent profiles and telemetry, each filtered exactly like its own route
//! (`/v1/branches`, `/v1/reviews`, `/v1/agents/sessions`, `/v1/approvals`, `/v1/audit`).

use std::collections::{BTreeMap, BTreeSet};

use axum::Json;
use axum::extract::{Query, State};
use axum::http::StatusCode;
use premier_core::{AuditDecision, Capability, DelegatedIdentity, Readiness, RepoPath, Visibility};
use premier_git_bridge::OWNERS_SELECTOR;
use premier_policy::CompiledPolicy;
use premier_proxy::ApprovalStatus;
use premier_secrets::ApprovalMode;
use serde::{Deserialize, Serialize};

use crate::{
    ApiError, BranchRow, GitIds, PRIVATE_REF_PREFIX, ServerState, accessible_in, auth,
    branch_changed_paths, branch_ref_names, branch_rows, commit_infos, default_branch,
    default_principal, default_ref_visibility, directory, handlers_v1, lists_some_path, path_caps,
    served_map, shown_ahead, visible_commits, warm_tree_paths, who_lists,
};

#[derive(Debug, Deserialize)]
pub struct WorktableQuery {
    #[serde(default = "default_principal")]
    pub principal: String,
    #[serde(default)]
    pub agent_profile: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct WorktableProfileSecret {
    pub name: String,
    /// `auto`, `jit`, or `unconfigured` (the schema declares no egress for it).
    pub approval: &'static str,
    pub hosts: Vec<String>,
}

#[derive(Debug, Serialize)]
pub struct WorktableAgentProfile {
    pub name: String,
    pub allow_paths: Vec<String>,
    pub deny_paths: Vec<String>,
    pub capabilities: Vec<String>,
    pub allow_secret_use: Vec<WorktableProfileSecret>,
    pub allow_egress_hosts: Vec<String>,
}

#[derive(Debug, Serialize)]
pub struct WorktableBranch {
    pub name: String,
    pub head_oid: String,
    pub subject: String,
    pub author: String,
    pub updated_at: String,
    pub relative_time: String,
    pub visibility: Visibility,
    pub readiness: Readiness,
    pub is_current: bool,
    pub ahead_commits: usize,
    pub private_paths_touched: Vec<String>,
    pub quarantine_paths: Vec<String>,
    pub publish_candidate: bool,
}

#[derive(Debug, Serialize)]
pub struct WorktableReviewSummary {
    pub change_id: String,
    pub title: String,
    pub branch: String,
    pub base_ref: String,
    pub author: String,
    pub delegated_agent: Option<String>,
    pub visibility: Visibility,
    pub readiness: Readiness,
    pub quarantine_flagged: bool,
    pub quarantine_paths: Vec<String>,
    pub round_count: usize,
    pub comment_count: usize,
    pub verdicts: BTreeMap<String, String>,
    pub created_at: String,
    pub latest_commit_oid: Option<String>,
    pub session_id: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct WorktableQuarantineItem {
    pub id: String,
    pub path: String,
    pub branch: String,
    pub change_id: Option<String>,
    pub author: String,
    pub title: String,
    /// `high` or `medium`.
    pub severity: &'static str,
    pub reason: String,
}

#[derive(Debug, Serialize)]
pub struct WorktableTelemetry {
    pub active_sessions: usize,
    pub pending_approvals: usize,
    pub uncommitted_sessions: usize,
    pub quarantined_count: usize,
    pub ready_to_publish_count: usize,
    /// Owner only: the audit log is.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub bytes_scrubbed_total: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub blocked_count: Option<usize>,
}

#[derive(Debug, Serialize)]
pub struct WorktableResponse {
    pub principal: String,
    pub agent_profile: Option<String>,
    pub default_branch: String,
    pub is_owner: bool,
    pub branches: Vec<WorktableBranch>,
    pub reviews: Vec<WorktableReviewSummary>,
    pub quarantine_items: Vec<WorktableQuarantineItem>,
    pub agent_profiles: Vec<WorktableAgentProfile>,
    pub telemetry: WorktableTelemetry,
}

/// Who a request is evaluated as, and how much of the canonical view the caller is entitled to.
struct Lens<'a> {
    state: &'a ServerState,
    identity: DelegatedIdentity,
    ids: GitIds,
    policy: Option<std::sync::Arc<CompiledPolicy>>,
    default: String,
    caller_is_owner: bool,
    /// An owner looking as themself: nothing is filtered.
    unrestricted_owner: bool,
}

pub async fn worktable_handler(
    State(state): State<ServerState>,
    Query(q): Query<WorktableQuery>,
) -> Result<Json<WorktableResponse>, (StatusCode, Json<ApiError>)> {
    let caller_is_owner = auth::caller_is_owner();
    // A member is always themself: `directory::identity` ignores the principal they name.
    let identity = directory::identity(&state, &q.principal, q.agent_profile, "studio-worktable")?;
    let agent_profile = identity.agent_task.as_ref().map(|t| t.profile.clone());
    let unrestricted_owner =
        caller_is_owner && identity.matches_selector(OWNERS_SELECTOR) && agent_profile.is_none();
    // A member's commit ids are always those of her clone, never canonical ones.
    let ids = if caller_is_owner {
        GitIds(None)
    } else {
        GitIds::of(&state, &identity)?
    };
    let lens = Lens {
        state: &state,
        policy: state.current_policy(),
        default: default_branch(&state.workspace_root),
        identity,
        ids,
        caller_is_owner,
        unrestricted_owner,
    };

    let branches = lens.branches();
    let reviews = lens.reviews();
    let quarantine_items = quarantine_items(&reviews, &branches);
    let agent_profiles = if caller_is_owner {
        agent_profiles(&state)
    } else {
        vec![]
    };
    let telemetry = lens.telemetry(&branches, quarantine_items.len());

    Ok(Json(WorktableResponse {
        principal: lens.identity.principal.canonical_id(),
        agent_profile,
        default_branch: lens.default.clone(),
        is_owner: caller_is_owner,
        branches,
        reviews,
        quarantine_items,
        agent_profiles,
        telemetry,
    }))
}

impl Lens<'_> {
    fn git(&self) -> std::process::Command {
        premier_git_bridge::git_command(&self.state.workspace_root)
    }

    /// `list_branches_handler`'s rules, for the lens identity.
    fn branches(&self) -> Vec<WorktableBranch> {
        let state = self.state;
        let identity = &self.identity;
        let overrides = state.branch_metadata();
        // Everyone a branch can be labelled as visible to besides the owners: the roster is the
        // unrestricted owner's to see only.
        let others: Vec<DelegatedIdentity> = if self.unrestricted_owner {
            directory::all_identities(state)
                .unwrap_or_default()
                .into_iter()
                .filter(|id| {
                    id.principal.is_authenticated() && !id.matches_selector(OWNERS_SELECTOR)
                })
                .collect()
        } else {
            vec![]
        };
        let measured = self.unrestricted_owner || self.ids.tip(&self.default, "").is_some();
        // One `for-each-ref` carries every per-branch fact git has (tip, subject, author, dates,
        // ahead count); it used to be that plus a `rev-parse`, a `rev-list` and more per branch.
        let Some(rows) = branch_rows(&state.workspace_root) else {
            return vec![];
        };
        let stored_visibility = |row: &BranchRow| {
            overrides
                .get(&row.full_ref)
                .cloned()
                .unwrap_or_else(|| (default_ref_visibility(&row.full_ref), Readiness::Ready))
        };
        // The rest of what the loop needs of git is fetched side by side up front.
        let seeable: Vec<&BranchRow> = rows
            .iter()
            .filter(|row| {
                self.unrestricted_owner
                    || premier_git_bridge::can_see_ref(identity, &stored_visibility(row).0)
            })
            .collect();
        let public: Vec<&BranchRow> = seeable
            .iter()
            .copied()
            .filter(|row| stored_visibility(row).0 == Visibility::Public)
            .collect();
        // Fails closed: no policy, or a tip that cannot be read, serves nobody.
        let served_to_anonymous = served_map(state, self.policy.as_deref(), &public);
        let tips_to_list: Vec<&str> = seeable
            .iter()
            .filter(|row| {
                !self.unrestricted_owner
                    || (!others.is_empty()
                        && served_to_anonymous.get(&row.full_ref) == Some(&false))
            })
            .map(|row| row.tip.as_str())
            .collect();
        warm_tree_paths(&state.workspace_root, &tips_to_list);

        let mut branches = Vec::new();
        let mut seen = BTreeSet::new();
        // `(index into branches, full ref, name)` of those whose changed paths are still to be read.
        let mut touched_pending: Vec<(usize, String, String)> = Vec::new();
        for row in &rows {
            let full_ref = row.full_ref.as_str();
            let name = full_ref
                .strip_prefix("refs/heads/")
                .or_else(|| full_ref.strip_prefix(PRIVATE_REF_PREFIX))
                .unwrap_or(full_ref)
                .to_owned();
            if !seen.insert(name.clone()) {
                continue;
            }
            let (mut visibility, readiness) = stored_visibility(row);
            if !self.unrestricted_owner
                && (!premier_git_bridge::can_see_ref(identity, &visibility)
                    || !lists_some_path(state, identity, full_ref, &name, &row.tip))
            {
                continue;
            }
            // Anyone but the unrestricted owner is told about the newest commit they are shown,
            // never the raw tip (it may be a commit they cannot see).
            let (subject, author, updated_at, relative_time) = if self.unrestricted_owner {
                (
                    row.subject.clone(),
                    row.author.clone(),
                    row.date.clone(),
                    row.relative.clone(),
                )
            } else {
                visible_commits(
                    state,
                    identity,
                    &self.ids,
                    full_ref,
                    std::slice::from_ref(&name),
                    0,
                    1,
                )
                .pop()
                .map(|c| (c.subject, c.author, c.committed_at, c.relative_time))
                .unwrap_or_default()
            };
            // The label rule of `list_branches_handler`: public only while an anonymous clone is
            // served the branch; otherwise who lists a path on it (named for the unrestricted
            // owner only, everyone else learns just that they are one of them).
            if visibility == Visibility::Public
                && !served_to_anonymous.get(full_ref).copied().unwrap_or(false)
            {
                visibility = Visibility::Restricted(if self.unrestricted_owner {
                    let lists = who_lists(state, &others, full_ref, &name, &row.tip);
                    std::iter::once(OWNERS_SELECTOR.to_owned())
                        .chain(
                            others
                                .iter()
                                .zip(&lists)
                                .filter(|(_, lists)| **lists)
                                .map(|(id, _)| id.principal.canonical_id()),
                        )
                        .collect()
                } else {
                    vec![identity.principal.canonical_id()]
                });
            }

            // A branch whose tip the default branch already contains is 0 ahead and changed
            // nothing of its own: nothing to count and nothing to diff, so no `git` for either.
            let level = row.ahead == Some(0);
            let ahead_commits = if name == self.default || !measured || level {
                0
            } else if self.unrestricted_owner {
                if let Some(ahead) = row.ahead {
                    ahead
                } else {
                    self.git()
                        .args(["rev-list", "--count", &format!("HEAD..{full_ref}")])
                        .output()
                        .ok()
                        .filter(|o| o.status.success())
                        .and_then(|o| String::from_utf8_lossy(&o.stdout).trim().parse().ok())
                        .unwrap_or(0)
                }
            } else {
                shown_ahead(
                    state,
                    identity,
                    &self.ids,
                    &format!("HEAD..{full_ref}"),
                    &name,
                )
            };
            // What the branch itself changed (its merge base with the default branch to its tip).
            if !(name == self.default || !measured || level) {
                touched_pending.push((branches.len(), full_ref.to_owned(), name.clone()));
            }

            let is_current = row.head;
            branches.push(WorktableBranch {
                head_oid: match &self.ids.0 {
                    None => row.short_oid.clone(),
                    // Her tip, or nothing where her clone has no such branch.
                    Some(_) => self
                        .ids
                        .tip(&name, "")
                        .map(|tip| tip[..7].to_owned())
                        .unwrap_or_default(),
                },
                publish_candidate: !is_current
                    && ahead_commits > 0
                    && readiness == Readiness::Ready
                    && !matches!(visibility, Visibility::Public),
                name,
                subject,
                author,
                updated_at,
                relative_time,
                visibility,
                readiness,
                is_current,
                ahead_commits,
                private_paths_touched: vec![],
                quarantine_paths: vec![],
            });
        }

        // One `git diff` per branch that has something of its own, run side by side.
        let refs: Vec<&str> = touched_pending.iter().map(|(_, r, _)| r.as_str()).collect();
        let changed = branch_changed_paths(&state.workspace_root, &refs);
        for ((index, _, name), paths) in touched_pending.iter().zip(changed) {
            let paths: Vec<String> = paths
                .into_iter()
                .filter(|p| {
                    self.unrestricted_owner
                        || path_caps(self.policy.as_deref(), identity, p, name)
                            .contains(Capability::LIST)
                })
                .collect();
            branches[*index].quarantine_paths = paths
                .iter()
                .filter(|p| self.is_instruction_file(p))
                .cloned()
                .collect();
            branches[*index].private_paths_touched = paths;
        }
        branches
    }

    fn is_instruction_file(&self, path: &str) -> bool {
        self.policy
            .as_ref()
            .is_some_and(|pol| RepoPath::new(path).is_ok_and(|rp| pol.is_instruction_file(&rp)))
    }

    /// `list_reviews_handler`'s rules, summarised.
    fn reviews(&self) -> Vec<WorktableReviewSummary> {
        let state = self.state;
        let identity = &self.identity;
        let stored = state
            .persisted
            .lock()
            .map(|s| s.reviews.clone())
            .unwrap_or_default();
        let sessions = if self.unrestricted_owner {
            Vec::new()
        } else {
            state.session_manager.list()
        };
        let me = identity.principal.canonical_id();
        // Fails closed: no policy, or a path that does not parse, decides nothing.
        let decide = |path: &str, branch: &str| {
            let pol = self.policy.as_ref()?;
            let rp = RepoPath::new(path).ok()?;
            Some((
                pol.explain(identity, &rp, branch),
                pol.is_instruction_file(&rp),
            ))
        };
        // A review of a branch the identity cannot see, or has no access to, does not exist for
        // it (invariant 3). One listing of the refs answers for every review's branch.
        let all_refs = branch_ref_names(state, None);
        let mut accessible_branches: BTreeMap<String, bool> = BTreeMap::new();
        let stored: Vec<_> = stored
            .into_iter()
            .filter(|rev| {
                *accessible_branches
                    .entry(rev.branch.clone())
                    .or_insert_with(|| {
                        all_refs
                            .as_deref()
                            .is_some_and(|all| accessible_in(state, identity, &rev.branch, all))
                    })
            })
            .collect();
        // Every round's changed paths: one `git log` for all of them.
        let all_round_oids: Vec<&str> = stored
            .iter()
            .flat_map(|rev| rev.round_oids.iter().map(String::as_str))
            .collect();
        let infos = commit_infos(&state.workspace_root, &all_round_oids, "");
        let mut out = Vec::new();
        for rev in stored {
            let mut quarantine_paths: Vec<String> = Vec::new();
            let mut round_count = 0;
            let mut latest_commit_oid = None;
            for oid in &rev.round_oids {
                let touched: &[String] = infos
                    .get(oid.as_str())
                    .map(|i| i.paths.as_slice())
                    .unwrap_or(&[]);
                let mut visible = 0usize;
                for path in touched {
                    let Some((_, instruction)) =
                        decide(path, &rev.branch).filter(|(dec, _)| dec.allows(Capability::LIST))
                    else {
                        continue;
                    };
                    visible += 1;
                    if instruction && !quarantine_paths.contains(path) {
                        quarantine_paths.push(path.clone());
                    }
                }
                // A round whose changes the identity can list none of is not theirs to know of.
                if visible == 0 && !touched.is_empty() {
                    continue;
                }
                round_count += 1;
                let shown: String = self.ids.shown(oid).chars().take(7).collect();
                latest_commit_oid = Some(shown).filter(|s| !s.is_empty());
            }
            let comment_count = rev
                .comments
                .iter()
                .filter(|c| {
                    decide(&c.path, &rev.branch)
                        .is_some_and(|(dec, _)| dec.allows(Capability::READ))
                })
                .count();
            out.push(WorktableReviewSummary {
                quarantine_flagged: !quarantine_paths.is_empty(),
                quarantine_paths,
                round_count,
                comment_count,
                latest_commit_oid,
                session_id: rev
                    .provenance
                    .as_ref()
                    .filter(|p| {
                        identity.principal.is_authenticated()
                            && (self.unrestricted_owner
                                || sessions.iter().any(|s| {
                                    s.id == p.session_id
                                        && handlers_v1::may_see_session(s)
                                        && s.principal == me
                                }))
                    })
                    .map(|p| p.session_id.clone()),
                change_id: rev.change_id,
                title: rev.title,
                branch: rev.branch,
                base_ref: rev.base_ref,
                author: rev.author,
                delegated_agent: rev.delegated_agent,
                visibility: rev.visibility,
                readiness: rev.readiness,
                verdicts: rev.verdicts,
                created_at: rev.created_at,
            });
        }
        out
    }

    /// Sessions and approvals as `/v1/agents/sessions` and `/v1/approvals` give them, narrowed
    /// to the lens identity; audit totals for owners only.
    fn telemetry(&self, branches: &[WorktableBranch], quarantined: usize) -> WorktableTelemetry {
        let me = self.identity.principal.canonical_id();
        let profile = self
            .identity
            .agent_task
            .as_ref()
            .map(|t| t.profile.as_str());
        let in_lens = |principal: &str, agent_profile: Option<&str>| {
            self.unrestricted_owner
                || (self.identity.principal.is_authenticated()
                    && principal == me
                    && profile.is_none_or(|p| agent_profile == Some(p)))
        };
        let sessions: Vec<_> = self
            .state
            .session_manager
            .list()
            .into_iter()
            .filter(|s| {
                handlers_v1::may_see_session(s) && in_lens(&s.principal, Some(&s.agent_profile))
            })
            .collect();
        let actor = auth::actor_principal();
        let pending_approvals = self
            .state
            .approval_hub
            .list()
            .iter()
            .filter(|a| self.caller_is_owner || a.principal == actor)
            .filter(|a| in_lens(&a.principal, a.agent_profile.as_deref()))
            .filter(|a| a.status == ApprovalStatus::Pending)
            .count();
        let audit = self
            .caller_is_owner
            .then(|| self.state.audit_sink.snapshot());
        WorktableTelemetry {
            active_sessions: sessions.iter().filter(|s| s.status == "running").count(),
            pending_approvals,
            uncommitted_sessions: sessions
                .iter()
                .filter(|s| {
                    s.status != "running"
                        && !s.changes.is_empty()
                        && s.commit.is_none()
                        && !s.discarded
                })
                .count(),
            quarantined_count: quarantined,
            ready_to_publish_count: branches.iter().filter(|b| b.publish_candidate).count(),
            bytes_scrubbed_total: audit
                .as_ref()
                .map(|ev| ev.iter().map(|e| e.bytes_scrubbed).sum()),
            blocked_count: audit.as_ref().map(|ev| {
                ev.iter()
                    .filter(|e| {
                        matches!(
                            e.decision,
                            AuditDecision::ExfiltrationBlocked
                                | AuditDecision::Denied
                                | AuditDecision::RateLimited
                        )
                    })
                    .count()
            }),
        }
    }
}

/// One item per instruction file touched: from reviews first, then from branches no review on
/// that `(branch, path)` already covers.
fn quarantine_items(
    reviews: &[WorktableReviewSummary],
    branches: &[WorktableBranch],
) -> Vec<WorktableQuarantineItem> {
    let mut covered = BTreeSet::new();
    let mut items = Vec::new();
    for rev in reviews.iter().filter(|r| r.quarantine_flagged) {
        for path in &rev.quarantine_paths {
            if covered.insert((rev.branch.clone(), path.clone())) {
                items.push(WorktableQuarantineItem {
                    id: format!("rev:{}:{path}", rev.change_id),
                    path: path.clone(),
                    branch: rev.branch.clone(),
                    change_id: Some(rev.change_id.clone()),
                    author: rev.author.clone(),
                    title: rev.title.clone(),
                    severity: "high",
                    reason: "Instruction file modified in review — verify before agent delegation"
                        .to_owned(),
                });
            }
        }
    }
    // The default branch has no `quarantine_paths` (nothing is measured against itself).
    for branch in branches {
        for path in &branch.quarantine_paths {
            if covered.insert((branch.name.clone(), path.clone())) {
                items.push(WorktableQuarantineItem {
                    id: format!("br:{}:{path}", branch.name),
                    path: path.clone(),
                    branch: branch.name.clone(),
                    change_id: None,
                    author: branch.author.clone(),
                    title: branch.subject.clone(),
                    severity: "high",
                    reason: "Instruction file modified on branch — verify before agent delegation"
                        .to_owned(),
                });
            }
        }
    }
    items
}

/// The repository policy's agent profiles, each secret enriched from the env schema. Owner only.
fn agent_profiles(state: &ServerState) -> Vec<WorktableAgentProfile> {
    let Some(file) = state.current_repo_policy_file() else {
        return vec![];
    };
    let schema = state.current_env_schema();
    file.agent_profiles
        .iter()
        .map(|p| WorktableAgentProfile {
            name: p.name.clone(),
            allow_paths: p.allow_paths.clone(),
            deny_paths: p.deny_paths.clone(),
            capabilities: p.capabilities.clone(),
            allow_secret_use: p
                .allow_secret_use
                .iter()
                .map(|name| {
                    let egress = schema
                        .as_ref()
                        .and_then(|s| s.vars.get(name))
                        .and_then(|v| v.egress.as_ref());
                    WorktableProfileSecret {
                        name: name.clone(),
                        approval: match egress.map(|e| e.approval) {
                            Some(ApprovalMode::Jit) => "jit",
                            Some(ApprovalMode::Auto) => "auto",
                            None => "unconfigured",
                        },
                        hosts: egress.map(|e| e.hosts.clone()).unwrap_or_default(),
                    }
                })
                .collect(),
            allow_egress_hosts: p.allow_egress_hosts.clone(),
        })
        .collect()
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use std::path::Path;
    use std::sync::Arc;

    use axum::http::Method;
    use premier_core::{AuditEvent, Principal};
    use premier_policy::parse_policy_toml;
    use premier_proxy::ApprovalRequest;
    use premier_secrets::EnvSchema;
    use serde_json::{Value, json};

    use super::*;
    use crate::runner::{AgentSessionRecord, SessionChange, SessionManager};
    use crate::store::{CapturedProvenance, ReviewComment, StoredReview};
    use crate::tests::{call, member_state};
    use crate::{build_router, store};

    /// `MEMBER_POLICY` plus a public README, instruction-file quarantine and one agent profile.
    const POLICY: &str = r#"
version = 1
[defaults]
public = []
authenticated = ["traverse", "list", "read"]
[quarantine]
instruction_files = ["AGENTS.md", "**/AGENTS.md"]
[[rules]]
id = "owners-full-access"
effect = "allow"
principals = ["group:owners"]
paths = ["**"]
refs = ["*"]
capabilities = ["traverse", "list", "read", "write", "use"]
[[rules]]
id = "public-readme"
effect = "allow"
principals = ["*"]
paths = ["README.md"]
refs = ["*"]
capabilities = ["traverse", "list", "read"]
[[rules]]
id = "mia-no-billing"
effect = "deny"
principals = ["@mia"]
paths = ["billing/**"]
refs = ["*"]
capabilities = ["traverse", "list", "read", "write", "use"]
[[agent_profiles]]
name = "ui-agent"
allow_paths = ["apps/**"]
deny_paths = ["billing/**"]
capabilities = ["traverse", "list", "read", "write"]
allow_secret_use = ["STRIPE_API_KEY", "GITHUB_TOKEN", "PLAIN_VAR"]
allow_egress_hosts = ["registry.npmjs.org"]
"#;

    fn git(root: &Path, args: &[&str]) -> String {
        let out = std::process::Command::new("git")
            .current_dir(root)
            .args(["-c", "user.name=T", "-c", "user.email=t@example.test"])
            .args(["-c", "core.autocrlf=false"])
            .args(args)
            .output()
            .unwrap();
        assert!(out.status.success(), "git {args:?}: {out:?}");
        String::from_utf8_lossy(&out.stdout).trim().to_owned()
    }

    fn review(change_id: &str, branch: &str, oid: String) -> StoredReview {
        let comment = |id: &str, path: &str| ReviewComment {
            id: id.to_owned(),
            author: "@owner".to_owned(),
            path: path.to_owned(),
            line: None,
            side: None,
            body: "look".to_owned(),
            created_at: String::new(),
            round: None,
            addressed_in_round: None,
            kind: crate::store::CommentKind::default(),
            target_agent: None,
            steer_session_id: None,
        };
        StoredReview {
            change_id: change_id.to_owned(),
            title: format!("{branch} review"),
            branch: branch.to_owned(),
            base_ref: "main".to_owned(),
            author: "@owner".to_owned(),
            delegated_agent: Some("ui-agent".to_owned()),
            visibility: Visibility::Public,
            readiness: Readiness::Ready,
            round_oids: vec![oid],
            comments: vec![
                comment("c1", "README.md"),
                comment("c2", "billing/AGENTS.md"),
            ],
            verdicts: BTreeMap::new(),
            provenance: Some(CapturedProvenance {
                session_id: "cage-0009".to_owned(),
                principal: Some("@owner".to_owned()),
                agent_profile: "ui-agent".to_owned(),
                command: "true".to_owned(),
                prompt_summary: String::new(),
                tool_calls: vec![],
                created_at: String::new(),
                steps: vec![],
                ..Default::default()
            }),
            created_at: "2026-11-22T00:00:00Z".to_owned(),
            lane_id: None,
            rounds_meta: Vec::new(),
            github_pr_url: None,
            github_pr_number: None,
        }
    }

    /// `main` (checked out): README.md, billing/ledger.rs. `feature`: README.md, AGENTS.md and
    /// billing/AGENTS.md changed, with a review. `agents`: AGENTS.md only, no review.
    /// `refs/premier-private/hush`: one commit, owners only, with a review.
    fn repo(root: &Path) -> (ServerState, String, String) {
        let (mut state, owner, mia, _) = member_state(root);
        let file = parse_policy_toml(POLICY).unwrap();
        *state.policy.write().unwrap() =
            Some(Arc::new(CompiledPolicy::compile(None, &file).unwrap()));
        state.set_repo_policy_metadata(Some(POLICY.to_owned()), Some(Arc::new(file)));
        let schema: EnvSchema = serde_json::from_value(json!({ "vars": {
            "STRIPE_API_KEY": { "egress": { "hosts": ["api.stripe.com"], "approval": "jit" } },
            "GITHUB_TOKEN": { "egress": { "hosts": ["api.github.com"] } },
            "PLAIN_VAR": {}
        }}))
        .unwrap();
        state.env_schema = Arc::new(std::sync::RwLock::new(Some(Arc::new(schema))));

        std::fs::create_dir_all(root.join("billing")).unwrap();
        std::fs::write(root.join("billing/ledger.rs"), "// v1\n").unwrap();
        git(root, &["init", "-q", "-b", "main"]);
        git(root, &["add", "README.md", "billing"]);
        git(root, &["commit", "-q", "-m", "initial | with a pipe"]);
        git(root, &["checkout", "-q", "-b", "feature"]);
        std::fs::write(root.join("README.md"), "# Feature\n").unwrap();
        std::fs::write(root.join("AGENTS.md"), "be nice\n").unwrap();
        std::fs::write(root.join("billing/AGENTS.md"), "be rich\n").unwrap();
        git(root, &["add", "README.md", "AGENTS.md", "billing"]);
        git(root, &["commit", "-q", "-m", "feature work"]);
        let feature_tip = git(root, &["rev-parse", "HEAD"]);
        git(root, &["checkout", "-q", "main"]);
        git(root, &["checkout", "-q", "-b", "agents"]);
        std::fs::write(root.join("AGENTS.md"), "agents only\n").unwrap();
        git(root, &["add", "AGENTS.md"]);
        git(root, &["commit", "-q", "-m", "agents work"]);
        git(root, &["checkout", "-q", "--detach", "main"]);
        std::fs::write(root.join("README.md"), "# Hush\n").unwrap();
        git(root, &["commit", "-q", "-am", "hush work"]);
        let hush_tip = git(root, &["rev-parse", "HEAD"]);
        git(root, &["update-ref", "refs/premier-private/hush", "HEAD"]);
        git(root, &["checkout", "-q", "main"]);

        {
            let mut st = state.persisted.lock().unwrap();
            st.reviews.push(review("I-feature", "feature", feature_tip));
            st.reviews.push(review("I-hush", "hush", hush_tip));
        }

        // Sessions come back from disk ended (a running one is marked interrupted), so
        // `active_sessions` stays 0 here: one of the owner's committed, one each not.
        let session = |id: &str, principal: &str, commit: Option<&str>| AgentSessionRecord {
            id: id.to_owned(),
            principal: principal.to_owned(),
            agent_profile: "ui-agent".to_owned(),
            status: "completed".to_owned(),
            changes: vec![SessionChange {
                path: "README.md".to_owned(),
                kind: "modified".to_owned(),
                size: 1,
                mode: "100644".to_owned(),
            }],
            commit: commit.map(str::to_owned),
            ..Default::default()
        };
        let sessions = vec![
            session("cage-0001", "@owner", Some("abc")),
            session("cage-0002", "@mia", None),
            session("cage-0003", "@owner", None),
        ];
        store::save_json(root, "sessions.json", &sessions).unwrap();
        state.session_manager = Arc::new(SessionManager::open(root));

        let approval = |principal: &str| ApprovalRequest {
            principal: principal.to_owned(),
            agent_profile: None,
            var_name: "STRIPE_API_KEY".to_owned(),
            host: "api.stripe.com".to_owned(),
            method: "POST".to_owned(),
            path: "/".to_owned(),
            ttl_secs: 60,
            ..Default::default()
        };
        // The receivers are dropped: the requests stay pending in the hub's list.
        let _ = state.approval_hub.enqueue(approval("@owner"));
        let _ = state.approval_hub.enqueue(approval("@mia"));

        let me = DelegatedIdentity::human_only(Principal::User("owner".to_owned()), vec![]);
        let event = |decision, bytes| {
            let mut ev = AuditEvent::now(&me, "proxy", "egress", decision, "test");
            ev.bytes_scrubbed = bytes;
            ev
        };
        state
            .audit_sink
            .record(event(AuditDecision::ExfiltrationBlocked, 40));
        state.audit_sink.record(event(AuditDecision::Redacted, 2));
        (state, owner, mia)
    }

    async fn get(state: &ServerState, uri: &str, cookie: &str) -> (StatusCode, Value) {
        let router = build_router(state.clone());
        let (status, _, body) = call(&router, Method::GET, uri, &[("cookie", cookie)], None).await;
        (status, body)
    }

    fn named<'a>(rows: &'a Value, key: &str, name: &str) -> Option<&'a Value> {
        rows.as_array().unwrap().iter().find(|r| r[key] == name)
    }

    fn names(rows: &Value) -> Vec<&str> {
        rows.as_array()
            .unwrap()
            .iter()
            .map(|r| r["name"].as_str().unwrap())
            .collect()
    }

    #[tokio::test]
    async fn worktable_owner_gets_the_full_picture() {
        let tmp = tempfile::tempdir().unwrap();
        let (state, owner, _) = repo(tmp.path());
        let (status, body) = get(&state, "/v1/worktable", &owner).await;
        assert_eq!(status, StatusCode::OK, "{body}");
        assert_eq!(body["principal"], "@owner");
        assert_eq!(body["is_owner"], true);
        assert_eq!(body["default_branch"], "main");
        assert_eq!(body["agent_profile"], Value::Null);

        let branches = &body["branches"];
        let main = named(branches, "name", "main").unwrap();
        assert_eq!(main["is_current"], true);
        assert_eq!(main["subject"], "initial | with a pipe");
        assert_eq!(main["author"], "T");
        assert!(!main["updated_at"].as_str().unwrap().is_empty());
        assert_eq!(main["publish_candidate"], false);

        let hush = named(branches, "name", "hush").unwrap();
        assert_eq!(
            hush["visibility"],
            json!({ "scope": "restricted", "allow": ["group:owners"] })
        );
        assert_eq!(hush["ahead_commits"], 1);
        assert_eq!(hush["publish_candidate"], true);

        let feature = named(branches, "name", "feature").unwrap();
        assert_eq!(feature["visibility"], json!({ "scope": "public" }));
        assert_eq!(feature["publish_candidate"], false);
        assert_eq!(
            feature["private_paths_touched"],
            json!(["AGENTS.md", "README.md", "billing/AGENTS.md"])
        );
        assert_eq!(
            feature["quarantine_paths"],
            json!(["AGENTS.md", "billing/AGENTS.md"])
        );

        let reviews = &body["reviews"];
        let rev = named(reviews, "change_id", "I-feature").unwrap();
        assert_eq!(rev["quarantine_flagged"], true);
        assert_eq!(
            rev["quarantine_paths"],
            json!(["AGENTS.md", "billing/AGENTS.md"])
        );
        assert_eq!(rev["round_count"], 1);
        assert_eq!(rev["comment_count"], 2);
        assert_eq!(rev["session_id"], "cage-0009");
        let tip = git(tmp.path(), &["rev-parse", "feature"]);
        assert_eq!(rev["latest_commit_oid"], tip[..7]);
        assert!(named(reviews, "change_id", "I-hush").is_some());

        let items = &body["quarantine_items"];
        let ids: Vec<&str> = items
            .as_array()
            .unwrap()
            .iter()
            .map(|i| i["id"].as_str().unwrap())
            .collect();
        assert_eq!(
            ids,
            [
                "rev:I-feature:AGENTS.md",
                "rev:I-feature:billing/AGENTS.md",
                "br:agents:AGENTS.md"
            ]
        );
        let br = named(items, "id", "br:agents:AGENTS.md").unwrap();
        assert_eq!(br["change_id"], Value::Null);
        assert_eq!(br["title"], "agents work");
        assert_eq!(br["severity"], "high");

        assert_eq!(
            body["agent_profiles"],
            json!([{
                "name": "ui-agent",
                "allow_paths": ["apps/**"],
                "deny_paths": ["billing/**"],
                "capabilities": ["traverse", "list", "read", "write"],
                "allow_secret_use": [
                    { "name": "STRIPE_API_KEY", "approval": "jit", "hosts": ["api.stripe.com"] },
                    { "name": "GITHUB_TOKEN", "approval": "auto", "hosts": ["api.github.com"] },
                    { "name": "PLAIN_VAR", "approval": "unconfigured", "hosts": [] }
                ],
                "allow_egress_hosts": ["registry.npmjs.org"]
            }])
        );

        let t = &body["telemetry"];
        assert_eq!(t["active_sessions"], 0);
        assert_eq!(t["pending_approvals"], 2);
        assert_eq!(t["uncommitted_sessions"], 2);
        assert_eq!(t["quarantined_count"], 3);
        let ready: Vec<&str> = branches
            .as_array()
            .unwrap()
            .iter()
            .filter(|b| b["publish_candidate"] == true)
            .map(|b| b["name"].as_str().unwrap())
            .collect();
        assert_eq!(t["ready_to_publish_count"], ready.len(), "{ready:?}");
        assert!(ready.contains(&"hush"));
        assert_eq!(t["bytes_scrubbed_total"], 42);
        assert_eq!(t["blocked_count"], 1);
    }

    #[tokio::test]
    async fn worktable_member_sees_only_her_own_slice() {
        let tmp = tempfile::tempdir().unwrap();
        let (state, owner, mia) = repo(tmp.path());
        let (_, owner_body) = get(&state, "/v1/worktable", &owner).await;
        let canonical = git(tmp.path(), &["rev-parse", "--short=7", "feature"]);
        let owner_feature = named(&owner_body["branches"], "name", "feature").unwrap();
        assert_eq!(owner_feature["head_oid"].as_str().unwrap(), canonical);

        // Naming the owner changes nothing: a member is always herself.
        for uri in ["/v1/worktable", "/v1/worktable?principal=@owner"] {
            let (status, body) = get(&state, uri, &mia).await;
            assert_eq!(status, StatusCode::OK, "{body}");
            assert_eq!(body["principal"], "@mia");
            assert_eq!(body["is_owner"], false);
            let text = body.to_string();
            assert!(!text.contains("hush"), "{body}");
            assert!(!text.contains("billing"), "{body}");
            assert!(!text.contains("group:owners"), "{body}");

            let feature = named(&body["branches"], "name", "feature").unwrap();
            assert_eq!(
                feature["private_paths_touched"],
                json!(["AGENTS.md", "README.md"])
            );
            assert_eq!(feature["quarantine_paths"], json!(["AGENTS.md"]));
            // Her clone's ids, never the canonical ones.
            let projected = feature["head_oid"].as_str().unwrap();
            assert_eq!(projected.len(), 7, "{body}");
            assert_ne!(projected, canonical, "{body}");

            let rev = named(&body["reviews"], "change_id", "I-feature").unwrap();
            assert_eq!(rev["quarantine_paths"], json!(["AGENTS.md"]));
            assert_eq!(rev["comment_count"], 1);
            // Session cage-0009 is not @mia's session, so it is omitted for her.
            assert_eq!(rev["session_id"], Value::Null);
            assert_eq!(rev["latest_commit_oid"].as_str().unwrap(), projected);

            assert_eq!(body["agent_profiles"], json!([]));
            let t = &body["telemetry"];
            assert!(t.get("bytes_scrubbed_total").is_none(), "{t}");
            assert!(t.get("blocked_count").is_none(), "{t}");
            assert_eq!(t["pending_approvals"], 1);
            assert_eq!(t["uncommitted_sessions"], 1);
            assert_eq!(t["quarantined_count"], 2);
        }
    }

    #[tokio::test]
    async fn worktable_owner_view_as_lens_hides_what_the_lens_cannot_see() {
        let tmp = tempfile::tempdir().unwrap();
        let (state, owner, _) = repo(tmp.path());

        let (status, body) = get(&state, "/v1/worktable?principal=@mia", &owner).await;
        assert_eq!(status, StatusCode::OK, "{body}");
        assert_eq!(body["principal"], "@mia");
        assert_eq!(body["is_owner"], true);
        assert!(!names(&body["branches"]).contains(&"hush"), "{body}");
        assert!(named(&body["reviews"], "change_id", "I-hush").is_none());
        let feature = named(&body["branches"], "name", "feature").unwrap();
        assert_eq!(
            feature["private_paths_touched"],
            json!(["AGENTS.md", "README.md"])
        );
        let t = &body["telemetry"];
        assert_eq!(t["pending_approvals"], 1);
        assert_eq!(t["uncommitted_sessions"], 1);
        assert_eq!(t["bytes_scrubbed_total"], 42);

        let (status, body) = get(&state, "/v1/worktable?principal=anonymous", &owner).await;
        assert_eq!(status, StatusCode::OK, "{body}");
        assert_eq!(body["principal"], "anonymous");
        let shown = names(&body["branches"]);
        assert!(!shown.contains(&"hush"), "{body}");
        assert!(shown.contains(&"feature"), "{body}");
        for branch in body["branches"].as_array().unwrap() {
            assert_eq!(branch["visibility"], json!({ "scope": "public" }), "{body}");
        }
        let rev = named(&body["reviews"], "change_id", "I-feature").unwrap();
        assert_eq!(rev["session_id"], Value::Null);
        assert_eq!(rev["comment_count"], 1);
        assert!(named(&body["reviews"], "change_id", "I-hush").is_none());
        let t = &body["telemetry"];
        assert_eq!(t["pending_approvals"], 0);
        assert_eq!(t["uncommitted_sessions"], 0);
        assert_eq!(t["active_sessions"], 0);
    }

    #[tokio::test]
    async fn worktable_personal_branch_traverse_isolation_and_owned_session_id() {
        let tmp = tempfile::tempdir().unwrap();
        let (state, owner, mia) = repo(tmp.path());

        let policy_with_traverse = format!(
            "{POLICY}\n[[rules]]\nid = \"mia-embargo-traverse-only\"\neffect = \"deny\"\nprincipals = [\"@mia\"]\npaths = [\"embargo/**\"]\nrefs = [\"*\"]\ncapabilities = [\"list\", \"read\", \"write\", \"use\"]\n"
        );
        let file = parse_policy_toml(&policy_with_traverse).unwrap();
        *state.policy.write().unwrap() =
            Some(Arc::new(CompiledPolicy::compile(None, &file).unwrap()));
        state.set_repo_policy_metadata(Some(policy_with_traverse), Some(Arc::new(file)));

        git(tmp.path(), &["checkout", "-q", "-b", "mia-personal"]);
        std::fs::create_dir_all(tmp.path().join("embargo")).unwrap();
        std::fs::write(tmp.path().join("README.md"), "# Personal\n").unwrap();
        std::fs::write(tmp.path().join("embargo/AGENTS.md"), "secret\n").unwrap();
        git(tmp.path(), &["add", "README.md", "embargo"]);
        git(tmp.path(), &["commit", "-q", "-m", "personal work"]);
        let personal_tip = git(tmp.path(), &["rev-parse", "HEAD"]);
        git(tmp.path(), &["checkout", "-q", "main"]);

        {
            let mut st = state.persisted.lock().unwrap();
            st.branch_metadata.insert(
                "refs/heads/mia-personal".to_owned(),
                (Visibility::Personal("@mia".to_owned()), Readiness::Wip),
            );
            let mut own_rev = review("I-personal", "mia-personal", personal_tip);
            own_rev.visibility = Visibility::Personal("@mia".to_owned());
            own_rev.provenance = Some(CapturedProvenance {
                session_id: "cage-0002".to_owned(),
                principal: Some("@mia".to_owned()),
                agent_profile: "ui-agent".to_owned(),
                command: "true".to_owned(),
                prompt_summary: String::new(),
                tool_calls: vec![],
                created_at: String::new(),
                steps: vec![],
                ..Default::default()
            });
            st.reviews.push(own_rev);
        }

        // @mia sees her personal branch (with array wire format) and her own session_id,
        // while traverse-only embargo/AGENTS.md never leaks into quarantine_paths or items.
        let (status, body) = get(&state, "/v1/worktable", &mia).await;
        assert_eq!(status, StatusCode::OK, "{body}");
        let personal = named(&body["branches"], "name", "mia-personal").unwrap();
        assert_eq!(
            personal["visibility"],
            json!({ "scope": "personal", "allow": ["@mia"] })
        );
        assert_eq!(personal["quarantine_paths"], json!([]));
        let rev = named(&body["reviews"], "change_id", "I-personal").unwrap();
        assert_eq!(rev["session_id"], "cage-0002");
        assert_eq!(rev["quarantine_paths"], json!([]));
        assert_eq!(rev["quarantine_flagged"], false);
        assert!(!body.to_string().contains("embargo/AGENTS.md"), "{body}");

        // Owner still sees embargo/AGENTS.md quarantine surface and personal branch.
        let (status, owner_body) = get(&state, "/v1/worktable", &owner).await;
        assert_eq!(status, StatusCode::OK, "{owner_body}");
        let owner_rev = named(&owner_body["reviews"], "change_id", "I-personal").unwrap();
        assert_eq!(owner_rev["quarantine_paths"], json!(["embargo/AGENTS.md"]));
        assert!(
            named(
                &owner_body["quarantine_items"],
                "id",
                "rev:I-personal:embargo/AGENTS.md"
            )
            .is_some()
        );

        // Anonymous cannot see personal branches or reviews.
        let (_, anon_body) = get(&state, "/v1/worktable?principal=anonymous", &owner).await;
        assert!(!names(&anon_body["branches"]).contains(&"mia-personal"));
        assert!(named(&anon_body["reviews"], "change_id", "I-personal").is_none());
    }

    #[tokio::test]
    async fn worktable_on_an_empty_repository_is_empty_not_an_error() {
        let tmp = tempfile::tempdir().unwrap();
        let (state, owner, mia, _) = member_state(tmp.path());
        git(tmp.path(), &["init", "-q", "-b", "main"]);
        for cookie in [&owner, &mia] {
            let (status, body) = get(&state, "/v1/worktable", cookie).await;
            assert_eq!(status, StatusCode::OK, "{body}");
            assert_eq!(body["branches"], json!([]));
            assert_eq!(body["reviews"], json!([]));
            assert_eq!(body["quarantine_items"], json!([]));
            assert_eq!(body["agent_profiles"], json!([]));
            assert_eq!(body["telemetry"]["ready_to_publish_count"], 0);
        }
    }
}
