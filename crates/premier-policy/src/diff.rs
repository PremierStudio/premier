//! Access Impact Diff and Untrusted Instruction-File Quarantine checks.

use std::collections::BTreeSet;

use premier_core::{Capability, DelegatedIdentity, RepoPath};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::firewall::FirewallSeverity;
use crate::quarantine::scan_instruction_file;
use crate::schema::{McpApprovalMode, McpTransportKind, PolicyLayer};
use crate::trie::CompiledPolicy;

/// Single capability delta for one `(principal, path)` pair between base and head policies.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AccessDelta {
    pub principal: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub agent_profile: Option<String>,
    pub path: String,
    pub before: Vec<String>,
    pub after: Vec<String>,
    pub granted: Vec<String>,
    pub revoked: Vec<String>,
}

/// MCP tool access change for one `(principal, tool)` pair between base and head policies.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct McpAccessDelta {
    pub principal: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub agent_profile: Option<String>,
    /// `"<server>:<tool>"`.
    pub tool: String,
    pub before_allowed: bool,
    pub after_allowed: bool,
    pub before_approval: McpApprovalMode,
    pub after_approval: McpApprovalMode,
    /// Newly allowed, or still allowed with a looser approval requirement.
    pub escalated: bool,
}

/// Quarantine alert when an untrusted instruction file (`AGENTS.md`, `CLAUDE.md`, etc.)
/// is added, modified, or fails SHA-256 pin verification.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct QuarantineAlert {
    pub path: String,
    pub severity: String,
    pub message: String,
}

/// Complete PR Access Impact Diff output.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AccessImpactDiff {
    pub ref_name: String,
    pub deltas: Vec<AccessDelta>,
    pub quarantine_alerts: Vec<QuarantineAlert>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub mcp_deltas: Vec<McpAccessDelta>,
}

impl AccessImpactDiff {
    pub fn has_escalations(&self) -> bool {
        self.deltas.iter().any(|d| !d.granted.is_empty())
            || self.mcp_deltas.iter().any(|d| d.escalated)
            || self
                .quarantine_alerts
                .iter()
                .any(|a| a.path == ".access.toml")
    }
}

/// Compute an Access Impact Diff across `(identities × paths)` between `base` and `head`.
pub fn compute_access_diff(
    base: &CompiledPolicy,
    head: &CompiledPolicy,
    identities: &[DelegatedIdentity],
    paths: &[RepoPath],
    changed_files: &[(RepoPath, Option<Vec<u8>>)],
    ref_name: &str,
) -> AccessImpactDiff {
    let mut deltas = Vec::new();

    for identity in identities {
        for path in paths {
            let before_mask = base.explain(identity, path, ref_name).effective;
            let after_mask = head.explain(identity, path, ref_name).effective;
            if before_mask != after_mask {
                let granted = after_mask & !before_mask;
                let revoked = before_mask & !after_mask;
                deltas.push(AccessDelta {
                    principal: identity.principal.canonical_id(),
                    agent_profile: identity.agent_task.as_ref().map(|a| a.profile.clone()),
                    path: path.to_string(),
                    before: cap_names(before_mask),
                    after: cap_names(after_mask),
                    granted: cap_names(granted),
                    revoked: cap_names(revoked),
                });
            }
        }
    }

    let mut mcp_deltas = Vec::new();
    let samples: BTreeSet<(String, String)> = base
        .mcp_rule_tool_samples()
        .into_iter()
        .chain(head.mcp_rule_tool_samples())
        .collect();
    for identity in identities {
        for (server, tool) in &samples {
            let before = base.evaluate_mcp_tool(identity, server, tool, ref_name);
            let after = head.evaluate_mcp_tool(identity, server, tool, ref_name);
            let changed = before.allowed != after.allowed
                || (after.allowed
                    && (before.approval != after.approval
                        || before.jit_ttl_secs != after.jit_ttl_secs
                        || before.arg_constraints != after.arg_constraints
                        || before.risk != after.risk));
            if !changed {
                continue;
            }
            let ttl_lengthened = before.allowed
                && after.approval == before.approval
                && after.jit_ttl_secs > before.jit_ttl_secs;
            let constraint_weakened = before.allowed
                && before
                    .arg_constraints
                    .iter()
                    .any(|c| !after.arg_constraints.contains(c));
            let risk_downgraded = before.allowed && after.risk < before.risk;
            mcp_deltas.push(McpAccessDelta {
                principal: after.principal,
                agent_profile: after.agent_profile,
                tool: after.full_name,
                before_allowed: before.allowed,
                after_allowed: after.allowed,
                before_approval: before.approval,
                after_approval: after.approval,
                escalated: after.allowed
                    && (!before.allowed
                        || after.approval < before.approval
                        || ttl_lengthened
                        || constraint_weakened
                        || risk_downgraded),
            });
        }
    }

    let mut quarantine_alerts = Vec::new();

    // Detect removal or modification of any base-pinned instruction file hash, even if the
    // instruction file itself was not listed in `changed_files`.
    for (pinned_path, base_hash) in base.pinned_instruction_hashes() {
        match head.pinned_instruction_hashes().get(pinned_path) {
            None => {
                quarantine_alerts.push(QuarantineAlert {
                    path: pinned_path.clone(),
                    severity: "critical".to_owned(),
                    message: "Pinned instruction file hash removed in PR; owner re-pin required"
                        .to_owned(),
                });
            }
            Some(head_hash) if !head_hash.eq_ignore_ascii_case(base_hash) => {
                quarantine_alerts.push(QuarantineAlert {
                    path: pinned_path.clone(),
                    severity: "critical".to_owned(),
                    message: format!(
                        "Pinned instruction file hash modified in PR (base {base_hash}, head {head_hash}); owner re-pin required"
                    ),
                });
            }
            Some(_) => {}
        }
    }

    for (name, after_srv) in head.mcp_servers() {
        match base.mcp_server(name) {
            None => {
                let severity = if after_srv.config.transport == McpTransportKind::Stdio
                    && after_srv.layer == PolicyLayer::Repo
                {
                    "critical"
                } else {
                    "high"
                };
                quarantine_alerts.push(QuarantineAlert {
                    path: ".access.toml".to_owned(),
                    severity: severity.to_owned(),
                    message: format!(
                        "MCP server '{name}' ({:?}, {:?} layer) added in .access.toml; review command/URL, credentials, and tool pins before approval",
                        after_srv.config.transport, after_srv.layer
                    ),
                });
            }
            Some(before_srv) => {
                let b = &before_srv.config;
                let a = &after_srv.config;
                let mut changed_fields: Vec<&str> = Vec::new();
                if b.transport != a.transport {
                    changed_fields.push("transport");
                }
                if b.command != a.command {
                    changed_fields.push("command");
                }
                if b.args != a.args {
                    changed_fields.push("args");
                }
                if b.url != a.url {
                    changed_fields.push("url");
                }
                if b.headers != a.headers {
                    changed_fields.push("headers");
                }
                if b.credentials != a.credentials {
                    changed_fields.push("credentials");
                }
                if b.env != a.env {
                    changed_fields.push("env");
                }
                if b.pinned_tool_hashes != a.pinned_tool_hashes {
                    changed_fields.push("pinned_tool_hashes");
                }
                if b.default_approval != a.default_approval {
                    changed_fields.push("default_approval");
                }
                if b.jit_ttl_secs != a.jit_ttl_secs {
                    changed_fields.push("jit_ttl_secs");
                }
                if !changed_fields.is_empty() {
                    quarantine_alerts.push(QuarantineAlert {
                        path: ".access.toml".to_owned(),
                        severity: "high".to_owned(),
                        message: format!(
                            "MCP server '{name}' definition modified ({}); manual security review required",
                            changed_fields.join(", ")
                        ),
                    });
                }
            }
        }
    }
    for (changed_path, maybe_bytes) in changed_files {
        if base.is_instruction_file(changed_path) || head.is_instruction_file(changed_path) {
            if let Some(bytes) = maybe_bytes {
                let hosts = head.all_allowed_egress_hosts();
                // Pass no pin: the mismatch alert below already covers it.
                let report = scan_instruction_file(changed_path.as_str(), bytes, &hosts, None);
                for f in report.findings {
                    quarantine_alerts.push(QuarantineAlert {
                        path: changed_path.to_string(),
                        severity: match f.severity {
                            FirewallSeverity::Critical => "critical",
                            FirewallSeverity::High => "high",
                            FirewallSeverity::Warning => "warning",
                            FirewallSeverity::Info => "info",
                        }
                        .to_owned(),
                        message: format!("[{}] {}", f.rule_id, f.summary),
                    });
                }
            }
            let expected_hash = base
                .pinned_instruction_hash(changed_path)
                .or_else(|| head.pinned_instruction_hash(changed_path));
            if let Some(expected_hash) = expected_hash {
                match maybe_bytes {
                    Some(bytes) => {
                        let actual = sha256_hex(bytes);
                        if !actual.eq_ignore_ascii_case(expected_hash) {
                            quarantine_alerts.push(QuarantineAlert {
                                path: changed_path.to_string(),
                                severity: "critical".to_owned(),
                                message: format!(
                                    "Pinned instruction file hash mismatch (expected {expected_hash}, got {actual}); owner re-pin required"
                                ),
                            });
                        }
                    }
                    None => {
                        quarantine_alerts.push(QuarantineAlert {
                            path: changed_path.to_string(),
                            severity: "high".to_owned(),
                            message: "Instruction file modified in PR; manual security review required before agent execution".to_owned(),
                        });
                    }
                }
            } else {
                quarantine_alerts.push(QuarantineAlert {
                    path: changed_path.to_string(),
                    severity: "high".to_owned(),
                    message: "Unpinned untrusted instruction file touched in PR; agents must not inherit escalated tools or egress".to_owned(),
                });
            }
        }
    }

    AccessImpactDiff {
        ref_name: ref_name.to_owned(),
        deltas,
        quarantine_alerts,
        mcp_deltas,
    }
}

/// Secret `USE` deltas across `(identities × secrets)`, each secret a `(var_name, zone)` pair.
pub fn compute_secret_use_deltas(
    base: &CompiledPolicy,
    head: &CompiledPolicy,
    identities: &[DelegatedIdentity],
    secrets: &[(String, Option<String>)],
    ref_name: &str,
) -> Vec<AccessDelta> {
    let mut deltas = Vec::new();
    for identity in identities {
        for (var_name, zone) in secrets {
            let before_mask = base
                .can_use_secret(identity, var_name, zone.as_deref(), ref_name)
                .effective;
            let after_mask = head
                .can_use_secret(identity, var_name, zone.as_deref(), ref_name)
                .effective;
            if before_mask == after_mask {
                continue;
            }
            deltas.push(AccessDelta {
                principal: identity.principal.canonical_id(),
                agent_profile: identity.agent_task.as_ref().map(|a| a.profile.clone()),
                path: match zone {
                    Some(z) => format!("secret:{var_name} (@{z})"),
                    None => format!("secret:{var_name}"),
                },
                before: cap_names(before_mask),
                after: cap_names(after_mask),
                granted: cap_names(after_mask & !before_mask),
                revoked: cap_names(before_mask & !after_mask),
            });
        }
    }
    deltas
}

pub fn sha256_hex(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    hex::encode(hasher.finalize())
}

fn cap_names(mask: Capability) -> Vec<String> {
    mask.to_names().into_iter().map(str::to_owned).collect()
}
