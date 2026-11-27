//! Git-over-SSH backend bridging `premier-ssh` onto `premier-server`'s repository registry,
//! dynamic zone/ref projection, reversible push engine, and account SSH key store.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use premier_core::{
    AuditDecision, AuditEvent, DelegatedIdentity, Principal, Readiness, Visibility,
};
use premier_git_bridge::http_v2::{PktToken, encode_pkt_line, parse_pkt_lines};
use premier_git_bridge::objects::parse_tag_object;
use premier_git_bridge::{
    CanonicalGitRepo, GitBridgeError, GitObjectKind, ProjectedView, ProtectedFiles,
    collect_reachable_objects, encode_packfile, handle_receive_pack_with_firewall,
    handle_upload_pack_v2, project_repository, render_info_refs_v2, render_receive_pack_refs,
};
use premier_overlay::OverlayGuard;
use premier_ssh::{GitService, PushSlot, SshAuthenticatedUser, SshGitBackend, async_trait};

use crate::repos::Registry;
use crate::store::save_state;
use crate::{ServerState, auth, canon, directory, handlers_v1};

const PKT_FLUSH: &[u8] = b"0000";
const ZERO_OID: &str = "0000000000000000000000000000000000000000";
const PUSH_QUEUE_WAIT: Duration = Duration::from_secs(30);

/// `premier-ssh` backend backed by a live [`Registry`] of Premier repositories.
#[derive(Clone)]
pub struct ServerSshBackend {
    registry: Registry,
}

impl ServerSshBackend {
    pub fn new(registry: Registry) -> Self {
        Self { registry }
    }

    /// Re-verifies account enabled status and live role on every SSH Git RPC so disabled or
    /// demoted accounts cannot continue using a persistent SSH connection.
    fn resolve_repo_and_identity(
        &self,
        user: &SshAuthenticatedUser,
        repo: &str,
    ) -> Result<(ServerState, DelegatedIdentity, bool), String> {
        let default_state = self.registry.default_state();
        let live_user = default_state
            .auth
            .user_state(&user.username)
            .ok_or_else(|| "authentication failed: account disabled or removed".to_owned())?;
        let is_owner = live_user.role == auth::Role::Owner;
        let not_found = || "repository not found".to_owned();
        let state = self.registry.state_for_repo(repo).ok_or_else(not_found)?;
        let principal =
            Principal::parse(&format!("@{}", live_user.username)).map_err(|_| not_found())?;
        let groups = directory::groups_for(&state, &principal)
            .map_err(|e| format!("failed to load principal directory: {e}"))?;
        let identity = DelegatedIdentity::human_only(principal, groups);
        let live_ssh_user = SshAuthenticatedUser {
            username: live_user.username,
            is_owner,
        };
        if !self
            .registry
            .is_visible_to(&state, &live_ssh_user, &identity)
        {
            return Err(not_found());
        }
        Ok((state, identity, is_owner))
    }
}

fn default_advertised_ref(workspace_root: &std::path::Path) -> Option<String> {
    canon::default_ref(workspace_root)
        .as_deref()
        .and_then(crate::ref_short)
        .map(|short| format!("refs/heads/{short}"))
}

/// Render a Git wire protocol v0/v1 `git-upload-pack` ref advertisement strictly scoped to `view`.
///
/// Explicitly omits `allow-tip-sha1-in-want` and `allow-reachable-sha1-in-want` (AGENTS.md
/// invariant 3). Emits `<peeled_oid> refs/tags/<name>^{}` for annotated tags.
fn render_upload_pack_refs_v0(view: &ProjectedView, default_ref: Option<&str>) -> Vec<u8> {
    let head = default_ref
        .and_then(|d| view.refs.get_key_value(d))
        .or_else(|| view.refs.iter().find(|(r, _)| r.starts_with("refs/heads/")));

    let mut caps = String::from("side-band-64k side-band agent=premier/0.1");
    if let Some((head_target, _)) = head {
        caps.push_str(&format!(" symref=HEAD:{head_target}"));
    }

    let mut out = Vec::new();
    if view.refs.is_empty() {
        let line = format!("{ZERO_OID} capabilities^{{}}\0{caps}\n");
        out.extend_from_slice(&encode_pkt_line(line.as_bytes()));
    } else {
        let mut advertised: Vec<(String, String)> = Vec::with_capacity(view.refs.len() + 1);
        if let Some((_, head_oid)) = head {
            advertised.push(("HEAD".to_owned(), head_oid.clone()));
        }
        for (ref_name, oid) in &view.refs {
            advertised.push((ref_name.clone(), oid.clone()));
            if ref_name.starts_with("refs/tags/")
                && let Some(obj) = view.odb.get(oid)
                && obj.kind == GitObjectKind::Tag
                && let Ok(peeled) = parse_tag_object(&obj.data)
            {
                advertised.push((format!("{ref_name}^{{}}"), peeled));
            }
        }
        for (idx, (ref_name, oid)) in advertised.into_iter().enumerate() {
            let line = if idx == 0 {
                format!("{oid} {ref_name}\0{caps}\n")
            } else {
                format!("{oid} {ref_name}\n")
            };
            out.extend_from_slice(&encode_pkt_line(line.as_bytes()));
        }
    }
    out.extend_from_slice(PKT_FLUSH);
    out
}

/// Handle a Git wire protocol v0/v1 `git-upload-pack` negotiation payload (`want` / `have` /
/// `done`) strictly within `view`'s anti-CFOR reachability scope.
fn handle_upload_pack_v0(view: &ProjectedView, stdin: &[u8]) -> Result<Vec<u8>, GitBridgeError> {
    let tokens = parse_pkt_lines(stdin)?;
    let mut wants = Vec::new();
    let mut haves = Vec::new();
    let mut sideband_64k = false;
    let mut sideband = false;
    let mut saw_done = false;

    for tok in tokens {
        let PktToken::Data(bytes) = tok else {
            continue;
        };
        let line = String::from_utf8_lossy(&bytes);
        let line = line.trim_end_matches(['\r', '\n']);
        if let Some(rest) = line.strip_prefix("want ") {
            let mut parts = rest.split_whitespace();
            if let Some(oid) = parts.next() {
                wants.push(oid.to_owned());
                for cap in parts {
                    if cap == "side-band-64k" {
                        sideband_64k = true;
                    } else if cap == "side-band" {
                        sideband = true;
                    }
                }
            }
        } else if let Some(rest) = line.strip_prefix("have ") {
            let oid = rest.trim();
            if !oid.is_empty() {
                haves.push(oid.to_owned());
            }
        } else if line == "done" {
            saw_done = true;
            break;
        }
    }

    if wants.is_empty() {
        return Ok(Vec::new());
    }

    for want in &wants {
        view.ledger.require_oid_in_scope(&view.scope, want)?;
    }

    // Multi-round v0/v1 negotiation: client sent `have` lines without `done`, so answer `NAK`
    // and await the next negotiation round (never leaking `have` existence via `ACK`).
    if !haves.is_empty() && !saw_done {
        return Ok(encode_pkt_line(b"NAK\n"));
    }

    let objects = collect_reachable_objects(view, &wants, &haves)?;
    let pack = encode_packfile(&objects)?;

    let mut out = Vec::new();
    out.extend_from_slice(&encode_pkt_line(b"NAK\n"));
    if sideband_64k || sideband {
        let chunk_size = if sideband_64k { 65_000 } else { 999 };
        for chunk in pack.chunks(chunk_size) {
            let mut frame = Vec::with_capacity(chunk.len() + 1);
            frame.push(1u8);
            frame.extend_from_slice(chunk);
            out.extend_from_slice(&encode_pkt_line(&frame));
        }
        out.extend_from_slice(PKT_FLUSH);
    } else {
        out.extend_from_slice(&pack);
    }
    Ok(out)
}

#[async_trait]
impl SshGitBackend for ServerSshBackend {
    async fn authenticate_pubkey(
        &self,
        username: &str,
        key_openssh: &str,
    ) -> Option<SshAuthenticatedUser> {
        let default_state = self.registry.default_state();
        let auth_store = Arc::clone(&default_state.auth);
        let uname = username.to_owned();
        let key = key_openssh.to_owned();
        let authed =
            tokio::task::spawn_blocking(move || auth_store.authenticate_ssh_key(&uname, &key))
                .await
                .ok()
                .flatten();
        match authed {
            Some(user) => Some(SshAuthenticatedUser {
                username: user.username,
                is_owner: user.role == auth::Role::Owner,
            }),
            None => {
                let anon = DelegatedIdentity::human_only(Principal::Anonymous, vec![]);
                let who: String = username.chars().take(64).collect();
                let mut ev = AuditEvent::now(
                    &anon,
                    "premier-ssh",
                    "ssh_auth_failed",
                    AuditDecision::Denied,
                    format!("Rejected SSH public key authentication for '{who}'"),
                );
                ev.target = Some(format!("ssh-user:{who}"));
                default_state.audit_sink.record(ev);
                None
            }
        }
    }

    async fn advertise_refs(
        &self,
        user: &SshAuthenticatedUser,
        repo: &str,
        service: GitService,
        protocol_v2: bool,
    ) -> Result<Vec<u8>, String> {
        let (state, identity, _) = self.resolve_repo_and_identity(user, repo)?;
        let Some(policy) = state.current_policy() else {
            return Err("no compiled policy loaded".to_owned());
        };
        let root = state.workspace_root.clone();
        let fp_short = state.policy_fingerprint();
        let vis_map = state.branch_visibility_map();

        tokio::task::spawn_blocking(move || {
            let canonical = CanonicalGitRepo::open(&root);
            let view = project_repository(&canonical, &policy, &fp_short, &identity, &vis_map)
                .map_err(|e| e.to_string())?;
            let bytes = match service {
                GitService::UploadPack if protocol_v2 => render_info_refs_v2(),
                GitService::UploadPack => {
                    let default_ref = default_advertised_ref(&root);
                    render_upload_pack_refs_v0(&view, default_ref.as_deref())
                }
                GitService::ReceivePack => render_receive_pack_refs(&view),
            };
            Ok(bytes)
        })
        .await
        .map_err(|e| e.to_string())?
    }

    async fn handle_upload_pack(
        &self,
        user: &SshAuthenticatedUser,
        repo: &str,
        protocol_v2: bool,
        stdin: &[u8],
    ) -> Result<Vec<u8>, String> {
        let (state, identity, _) = self.resolve_repo_and_identity(user, repo)?;
        let Some(policy) = state.current_policy() else {
            return Err("no compiled policy loaded".to_owned());
        };
        let root = state.workspace_root.clone();
        let fp_short = state.policy_fingerprint();
        let vis_map = state.branch_visibility_map();
        let identity_bg = identity.clone();
        let stdin_bg = stdin.to_vec();

        let res = tokio::task::spawn_blocking(move || {
            let canonical = CanonicalGitRepo::open(&root);
            let view = project_repository(&canonical, &policy, &fp_short, &identity_bg, &vis_map)?;
            let resp_bytes = if protocol_v2 {
                let default_ref = default_advertised_ref(&root);
                handle_upload_pack_v2(&view, default_ref.as_deref(), &stdin_bg)?
            } else {
                handle_upload_pack_v0(&view, &stdin_bg)?
            };
            Ok::<_, GitBridgeError>((resp_bytes, view.refs.len(), view.odb.len()))
        })
        .await
        .map_err(|e| e.to_string())?;

        match res {
            Ok((resp_bytes, ref_count, obj_count)) => {
                let mut ev = AuditEvent::now(
                    &identity,
                    "premier-git-bridge",
                    "git_upload_pack_ssh",
                    AuditDecision::Allowed,
                    format!(
                        "Projected Git SSH response for {} ({}, {obj_count} isolated objects)",
                        identity.principal,
                        premier_git_bridge::plural(ref_count, "authorized ref")
                    ),
                );
                ev.target = Some(format!("ssh:{repo}"));
                auth::audit(&state.audit_sink, ev);
                Ok(resp_bytes)
            }
            Err(GitBridgeError::ObjectNotVisible) => {
                let mut ev = AuditEvent::now(
                    &identity,
                    "premier-git-bridge",
                    "git_upload_pack_ssh",
                    AuditDecision::Denied,
                    "Anti-CFOR rejected unauthorized OID want over SSH (zero oracle)",
                );
                ev.target = Some(format!("ssh:{repo}"));
                auth::audit(&state.audit_sink, ev);
                Err(GitBridgeError::ObjectNotVisible.to_string())
            }
            Err(e) => Err(e.to_string()),
        }
    }

    /// The same process-wide slots HTTP pushes take, so SSH and HTTP share one budget.
    async fn reserve_push_slot(&self) -> Result<PushSlot, String> {
        match tokio::time::timeout(PUSH_QUEUE_WAIT, handlers_v1::PUSH_SLOTS.acquire()).await {
            Ok(Ok(slot)) => Ok(Box::new(slot)),
            _ => Err("server busy: retry the push in a moment".to_owned()),
        }
    }

    async fn handle_receive_pack(
        &self,
        user: &SshAuthenticatedUser,
        repo: &str,
        stdin: Vec<u8>,
    ) -> Result<Vec<u8>, String> {
        let (state, identity, is_owner) = self.resolve_repo_and_identity(user, repo)?;
        let Some(policy) = state.current_policy() else {
            return Err("no compiled policy loaded".to_owned());
        };

        let root = state.workspace_root.clone();
        let fp_short = state.policy_fingerprint();
        let vis_map: HashMap<String, Visibility> = state.branch_visibility_map();
        let overlay_manifest = state
            .persisted
            .lock()
            .map(|g| g.overlays.clone())
            .unwrap_or_default();
        let overlay_guard =
            OverlayGuard::from_manifest(&overlay_manifest).map_err(|e| e.to_string())?;
        let identity_bg = identity.clone();
        let stdin_bg = stdin;
        let state_bg = state.clone();
        let vault = crate::firewall::build_vault_secret_index(&state);
        let approved = crate::firewall::approved_instruction_map(&state);
        let audit_bg = state.audit_sink.clone();

        let res = tokio::task::spawn_blocking(move || {
            let canonical = CanonicalGitRepo::open(&root);
            // Detached `HEAD` fails closed to the built-in owner-only policy, matching HTTP push.
            let policy = if canon::default_ref(&root).is_some() {
                policy
            } else {
                state_bg.builtin_policy().map_err(GitBridgeError::Io)?
            };
            let view = project_repository(&canonical, &policy, &fp_short, &identity_bg, &vis_map)?;
            let before = canon::DefaultTip::capture(&root);
            let default_ref = canon::default_ref(&root).unwrap_or_default();
            let check = |name: &str, content: Option<&[u8]>| {
                state_bg.check_config_change(is_owner, name, content)
            };
            let protected = ProtectedFiles {
                full_ref: &default_ref,
                names: &canon::CONFIG_FILES,
                check: &check,
            };
            let on_blocked = |ref_name: &str, report: &premier_policy::DeclassificationReport| {
                crate::firewall::record_firewall_audit(
                    &audit_bg,
                    &identity_bg,
                    "git_push_ssh",
                    ref_name,
                    report,
                );
            };
            let firewall = premier_git_bridge::ReceivePackFirewall {
                vault: vault.as_ref(),
                approved_instructions: &approved,
                on_blocked: Some(&on_blocked),
            };
            let res = handle_receive_pack_with_firewall(
                &canonical,
                &view,
                &policy,
                &overlay_guard,
                &identity_bg,
                is_owner,
                Some(&protected),
                Some(&firewall),
                &stdin_bg,
            );
            state_bg.default_branch_moved(before);
            res
        })
        .await
        .map_err(|e| e.to_string())?;

        match res {
            Ok(pack_res) => {
                if let Ok(mut st) = state.persisted.lock() {
                    let mut changed = false;
                    for update in &pack_res.accepted {
                        if update.canonical_new == ZERO_OID {
                            if st.branch_metadata.remove(&update.canonical_ref).is_some() {
                                changed = true;
                            }
                            if let Some(short) = crate::ref_short(&update.canonical_ref)
                                && st.branch_metadata.remove(short).is_some()
                            {
                                changed = true;
                            }
                        } else if let Some(visibility) = &update.created_visibility {
                            st.branch_metadata.insert(
                                update.canonical_ref.clone(),
                                (visibility.clone(), Readiness::Ready),
                            );
                            changed = true;
                        }
                    }
                    if changed {
                        let _ = save_state(&state.workspace_root, &st);
                    }
                }
                for update in &pack_res.accepted {
                    let mut ev = AuditEvent::now(
                        &identity,
                        "premier-git-bridge",
                        "git_ref_update",
                        AuditDecision::Allowed,
                        format!(
                            "pushed via SSH by {}: {} {}..{} ({})",
                            update.pusher,
                            update.canonical_ref,
                            update.canonical_old,
                            update.canonical_new,
                            premier_git_bridge::plural(update.commits, "commit")
                        ),
                    );
                    ev.target = Some(update.canonical_ref.clone());
                    auth::audit(&state.audit_sink, ev);
                }
                let decision = if pack_res.rejected_refs.is_empty() {
                    AuditDecision::Allowed
                } else {
                    AuditDecision::Denied
                };
                let mut ev = AuditEvent::now(
                    &identity,
                    "premier-git-bridge",
                    "git_receive_pack_ssh",
                    decision,
                    format!(
                        "Reversible SSH git push by {}: {} updated, {} rejected",
                        identity.principal,
                        pack_res.updated_refs.len(),
                        pack_res.rejected_refs.len()
                    ),
                );
                ev.target = Some(format!("ssh:{repo}"));
                auth::audit(&state.audit_sink, ev);

                Ok(pack_res.response_bytes)
            }
            Err(e) => Err(e.to_string()),
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use std::path::Path;
    use std::sync::{Arc, Mutex};

    use axum::http::{Method, StatusCode};
    use base64::Engine;
    use base64::engine::general_purpose::{STANDARD, STANDARD_NO_PAD};
    use premier_git_bridge::{CommitObj, GitObject, GitObjectKind, TreeEntry, encode_tree};
    use premier_policy::{CompiledPolicy, parse_policy_toml, sha256_hex};
    use premier_proxy::AuditSink;
    use serde_json::json;

    use super::*;
    use crate::auth::{Role, normalize_ssh_public_key};
    use crate::store::PersistedState;
    use crate::tests::{call, member_state, use_member_policy};
    use crate::{PRIVATE_REF_PREFIX, build_router};

    fn fake_ed25519_key(seed: u8, comment: &str) -> String {
        let mut blob = Vec::new();
        let tag = b"ssh-ed25519";
        blob.extend_from_slice(&(tag.len() as u32).to_be_bytes());
        blob.extend_from_slice(tag);
        blob.extend_from_slice(&32u32.to_be_bytes());
        blob.extend_from_slice(&[seed; 32]);
        let b64 = STANDARD.encode(&blob);
        if comment.is_empty() {
            format!("ssh-ed25519 {b64}")
        } else {
            format!("ssh-ed25519 {b64} {comment}")
        }
    }

    fn run_git(dir: &Path, args: &[&str]) -> String {
        let out = std::process::Command::new("git")
            .current_dir(dir)
            .args(["-c", "user.name=Test", "-c", "user.email=test@example.test"])
            .args(args)
            .output()
            .unwrap();
        assert!(
            out.status.success(),
            "git {:?} failed: {}",
            args,
            String::from_utf8_lossy(&out.stderr)
        );
        String::from_utf8_lossy(&out.stdout).trim().to_owned()
    }

    #[test]
    fn ssh_key_normalization_validates_types_size_and_fingerprint() {
        let raw = fake_ed25519_key(0x42, "alice@laptop extra words");
        let (key_type, normalized, fp) = normalize_ssh_public_key(&raw).unwrap();
        assert_eq!(key_type, "ssh-ed25519");
        assert_eq!(normalized.split_whitespace().count(), 2);
        assert!(!normalized.contains("alice@laptop"));
        assert!(fp.starts_with("SHA256:"));
        assert!(!fp.ends_with('='));

        // Same key without comment normalizes identically.
        let (_, normalized_plain, fp_plain) =
            normalize_ssh_public_key(&fake_ed25519_key(0x42, "")).unwrap();
        assert_eq!(normalized, normalized_plain);
        assert_eq!(fp, fp_plain);

        // Other allowed key types succeed when properly RFC 4253 wire-encoded.
        let ssh_str = |buf: &mut Vec<u8>, bytes: &[u8]| {
            buf.extend_from_slice(&(bytes.len() as u32).to_be_bytes());
            buf.extend_from_slice(bytes);
        };
        let valid_blobs: Vec<(&str, Vec<u8>)> = vec![
            ("ecdsa-sha2-nistp256", {
                let mut b = Vec::new();
                ssh_str(&mut b, b"ecdsa-sha2-nistp256");
                ssh_str(&mut b, b"nistp256");
                ssh_str(&mut b, &[0x04; 65]);
                b
            }),
            ("ecdsa-sha2-nistp384", {
                let mut b = Vec::new();
                ssh_str(&mut b, b"ecdsa-sha2-nistp384");
                ssh_str(&mut b, b"nistp384");
                ssh_str(&mut b, &[0x04; 97]);
                b
            }),
            ("ecdsa-sha2-nistp521", {
                let mut b = Vec::new();
                ssh_str(&mut b, b"ecdsa-sha2-nistp521");
                ssh_str(&mut b, b"nistp521");
                ssh_str(&mut b, &[0x04; 133]);
                b
            }),
            ("ssh-rsa", {
                let mut b = Vec::new();
                ssh_str(&mut b, b"ssh-rsa");
                ssh_str(&mut b, &[0x01, 0x00, 0x01]); // e = 65537
                let mut n = vec![0x00, 0x80];
                n.extend_from_slice(&[0xab; 255]); // 2048-bit modulus
                ssh_str(&mut b, &n);
                b
            }),
            ("sk-ssh-ed25519@openssh.com", {
                let mut b = Vec::new();
                ssh_str(&mut b, b"sk-ssh-ed25519@openssh.com");
                ssh_str(&mut b, &[0x22; 32]);
                ssh_str(&mut b, b"ssh:");
                b
            }),
            ("sk-ecdsa-sha2-nistp256@openssh.com", {
                let mut b = Vec::new();
                ssh_str(&mut b, b"sk-ecdsa-sha2-nistp256@openssh.com");
                ssh_str(&mut b, b"nistp256");
                ssh_str(&mut b, &[0x04; 65]);
                ssh_str(&mut b, b"ssh:");
                b
            }),
        ];
        for (kt, blob) in valid_blobs {
            let line = format!("{kt} {}", STANDARD.encode(&blob));
            assert_eq!(normalize_ssh_public_key(&line).unwrap().0, kt);
        }

        // Wire-format rejection: mismatched alg, wrong Ed25519 length, short RSA, even e, trailing bytes.
        let mut bad_alg = Vec::new();
        ssh_str(&mut bad_alg, b"ssh-rsa");
        ssh_str(&mut bad_alg, &[0x42; 32]);
        assert!(
            normalize_ssh_public_key(&format!("ssh-ed25519 {}", STANDARD.encode(&bad_alg)))
                .is_err()
        );

        let mut bad_ed_len = Vec::new();
        ssh_str(&mut bad_ed_len, b"ssh-ed25519");
        ssh_str(&mut bad_ed_len, &[0x42; 31]);
        assert!(
            normalize_ssh_public_key(&format!("ssh-ed25519 {}", STANDARD.encode(&bad_ed_len)))
                .is_err()
        );

        let mut trailing = Vec::new();
        ssh_str(&mut trailing, b"ssh-ed25519");
        ssh_str(&mut trailing, &[0x42; 32]);
        trailing.push(0x00);
        assert!(
            normalize_ssh_public_key(&format!("ssh-ed25519 {}", STANDARD.encode(&trailing)))
                .is_err()
        );

        let mut short_rsa = Vec::new();
        ssh_str(&mut short_rsa, b"ssh-rsa");
        ssh_str(&mut short_rsa, &[0x01, 0x00, 0x01]);
        let mut n1024 = vec![0x00, 0x80];
        n1024.extend_from_slice(&[0xcd; 127]);
        ssh_str(&mut short_rsa, &n1024);
        assert!(
            normalize_ssh_public_key(&format!("ssh-rsa {}", STANDARD.encode(&short_rsa))).is_err()
        );

        let mut even_e_rsa = Vec::new();
        ssh_str(&mut even_e_rsa, b"ssh-rsa");
        ssh_str(&mut even_e_rsa, &[0x04]);
        let mut n2048 = vec![0x00, 0x80];
        n2048.extend_from_slice(&[0xcd; 255]);
        ssh_str(&mut even_e_rsa, &n2048);
        assert!(
            normalize_ssh_public_key(&format!("ssh-rsa {}", STANDARD.encode(&even_e_rsa))).is_err()
        );

        // Rejected inputs.
        assert!(normalize_ssh_public_key("").is_err());
        assert!(normalize_ssh_public_key("ssh-dss AAAA").is_err());
        assert!(normalize_ssh_public_key("ssh-ed25519 !!!not-base64!!!").is_err());
        assert!(normalize_ssh_public_key("ssh-ed25519 ").is_err());
        assert!(normalize_ssh_public_key(&format!("{raw}\nextra")).is_err());
        let oversized = format!("ssh-ed25519 {}", STANDARD.encode(vec![7u8; 16 * 1024 + 1]));
        assert!(normalize_ssh_public_key(&oversized).is_err());

        // Sanity-check fingerprint matches SHA-256 of decoded bytes.
        let payload = STANDARD
            .decode(normalized.split_whitespace().nth(1).unwrap())
            .unwrap();
        let expected_hex = sha256_hex(&payload);
        let expected_bytes: Vec<u8> = (0..32)
            .map(|i| u8::from_str_radix(&expected_hex[i * 2..i * 2 + 2], 16).unwrap())
            .collect();
        assert_eq!(
            fp,
            format!("SHA256:{}", STANDARD_NO_PAD.encode(expected_bytes))
        );
    }

    #[tokio::test]
    async fn ssh_keys_http_crud_duplicate_rejection_and_auth_lookup() {
        let tmp = tempfile::tempdir().unwrap();
        let (state, owner_cookie, mia_cookie, mia_token) = member_state(tmp.path());
        let router = build_router(state.clone());

        let alice_key = fake_ed25519_key(0x11, "mia@workstation");

        // 1. Access token MUST be refused (403 browser session required) for all SSH key routes.
        let bearer = format!("Bearer {mia_token}");
        let (status, _, _) = call(
            &router,
            Method::GET,
            "/v1/auth/ssh-keys",
            &[("authorization", &bearer)],
            None,
        )
        .await;
        assert_eq!(status, StatusCode::FORBIDDEN);

        let (status, _, _) = call(
            &router,
            Method::POST,
            "/v1/auth/ssh-keys",
            &[("authorization", &bearer)],
            Some(json!({ "name": "laptop", "key": alice_key })),
        )
        .await;
        assert_eq!(status, StatusCode::FORBIDDEN);

        // 2. Browser session lists empty keys, then adds one.
        let (status, _, body) = call(
            &router,
            Method::GET,
            "/v1/auth/ssh-keys",
            &[("cookie", &mia_cookie)],
            None,
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body.as_array().unwrap().len(), 0);

        let (status, _, created) = call(
            &router,
            Method::POST,
            "/v1/auth/ssh-keys",
            &[("cookie", &mia_cookie)],
            Some(json!({ "name": "workstation", "key": alice_key })),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{created}");
        let key_id = created["id"].as_str().unwrap().to_owned();
        assert_eq!(created["name"], "workstation");
        assert_eq!(created["key_type"], "ssh-ed25519");
        assert!(
            created["fingerprint"]
                .as_str()
                .unwrap()
                .starts_with("SHA256:")
        );

        // 3. Duplicate key (even with a different comment or another user) returns 409 Conflict.
        let same_key_diff_comment = fake_ed25519_key(0x11, "owner@other");
        let (status, _, _) = call(
            &router,
            Method::POST,
            "/v1/auth/ssh-keys",
            &[("cookie", &owner_cookie)],
            Some(json!({ "name": "stolen", "key": same_key_diff_comment })),
        )
        .await;
        assert_eq!(status, StatusCode::CONFLICT);

        // 4. `authenticate_ssh_key` works for explicit username AND `"git"`, rejects wrong user.
        let plain_key = fake_ed25519_key(0x11, "");
        let authed_explicit = state.auth.authenticate_ssh_key("mia", &plain_key).unwrap();
        assert_eq!(authed_explicit.username, "mia");
        assert_eq!(authed_explicit.role, Role::Member);

        let authed_git = state.auth.authenticate_ssh_key("git", &plain_key).unwrap();
        assert_eq!(authed_git.username, "mia");
        assert_eq!(authed_git.role, Role::Member);

        assert!(
            state
                .auth
                .authenticate_ssh_key("owner", &plain_key)
                .is_none()
        );

        // 5. Another user cannot revoke mia's key.
        let (status, _, _) = call(
            &router,
            Method::DELETE,
            &format!("/v1/auth/ssh-keys/{key_id}"),
            &[("cookie", &owner_cookie)],
            None,
        )
        .await;
        assert_eq!(status, StatusCode::NOT_FOUND);

        // 6. Disabling the user blocks SSH authentication immediately.
        let (status, _, _) = call(
            &router,
            Method::PATCH,
            "/v1/users/mia",
            &[("cookie", &owner_cookie)],
            Some(json!({ "disabled": true })),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert!(state.auth.authenticate_ssh_key("git", &plain_key).is_none());
        assert!(state.auth.authenticate_ssh_key("mia", &plain_key).is_none());

        // Re-enable mia and revoke the key via DELETE.
        let (status, _, _) = call(
            &router,
            Method::PATCH,
            "/v1/users/mia",
            &[("cookie", &owner_cookie)],
            Some(json!({ "disabled": false })),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        // Re-login isn't needed for direct `AuthStore::revoke_ssh_key`, verify via AuthStore too.
        assert_eq!(state.auth.list_ssh_keys("mia").len(), 1);
        state.auth.revoke_ssh_key("mia", &key_id).unwrap();
        assert!(state.auth.list_ssh_keys("mia").is_empty());
        assert!(state.auth.authenticate_ssh_key("git", &plain_key).is_none());
    }

    #[tokio::test]
    async fn ssh_backend_projected_fetch_push_and_hidden_repo_anti_oracle() {
        let tmp = tempfile::tempdir().unwrap();
        let main_repo = tmp.path().join("main-repo");
        let repos_dir = tmp.path().join("extra-repos");
        let hidden_repo = repos_dir.join("secret-repo");
        std::fs::create_dir_all(main_repo.join("billing")).unwrap();
        std::fs::create_dir_all(&hidden_repo).unwrap();

        // Set up default repo with public README.md, restricted billing/ledger.rs, and private branch.
        run_git(&main_repo, &["init", "-q", "-b", "main"]);
        std::fs::write(main_repo.join("README.md"), "# Public v1\n").unwrap();
        std::fs::write(
            main_repo.join("billing/ledger.rs"),
            "const SECRET: u32 = 42;\n",
        )
        .unwrap();
        run_git(&main_repo, &["add", "."]);
        run_git(&main_repo, &["commit", "-q", "-m", "initial"]);

        // Add an embargoed private branch that only owners can see.
        run_git(&main_repo, &["checkout", "-q", "--detach", "main"]);
        std::fs::write(main_repo.join("README.md"), "# Embargo\n").unwrap();
        run_git(&main_repo, &["commit", "-q", "-am", "embargo commit"]);
        run_git(
            &main_repo,
            &[
                "update-ref",
                &format!("{PRIVATE_REF_PREFIX}embargo"),
                "HEAD",
            ],
        );
        run_git(&main_repo, &["checkout", "-q", "main"]);

        // Set up second repo ("secret-repo") with owner-only default policy (no .access.toml).
        run_git(&hidden_repo, &["init", "-q", "-b", "main"]);
        std::fs::write(hidden_repo.join("TOP_SECRET.txt"), "eyes only\n").unwrap();
        run_git(&hidden_repo, &["add", "."]);
        run_git(&hidden_repo, &["commit", "-q", "-m", "secret init"]);

        let (mut state, _, _, _) = member_state(&main_repo);
        use_member_policy(&state);
        // Allow authenticated members to write README.md (and deny billing/**).
        let ssh_policy_toml = r#"
version = 1
[defaults]
public = ["traverse", "list", "read"]
authenticated = ["traverse", "list", "read", "write"]
[[rules]]
id = "owners-all"
effect = "allow"
principals = ["group:owners"]
paths = ["**"]
capabilities = ["traverse", "list", "read", "write", "use"]
[[rules]]
id = "deny-billing"
effect = "deny"
principals = ["*"]
paths = ["billing/**"]
capabilities = ["traverse", "list", "read", "write", "use"]
"#;
        let pf = parse_policy_toml(ssh_policy_toml).unwrap();
        let compiled = CompiledPolicy::compile(None, &pf).unwrap();
        state.replace_repo_policy(Arc::new(compiled), Arc::new(pf), ssh_policy_toml.to_owned());
        state.persisted = Arc::new(Mutex::new(PersistedState::default()));
        state.audit_sink = Arc::new(AuditSink::default());

        let owner_key = fake_ed25519_key(0xAA, "owner@dev");
        let mia_key = fake_ed25519_key(0xBB, "mia@dev");
        state
            .auth
            .add_ssh_key("owner", "owner-key", &owner_key)
            .unwrap();
        state.auth.add_ssh_key("mia", "mia-key", &mia_key).unwrap();

        let registry = Registry::open(state.clone(), Some("main-repo".to_owned()), Some(repos_dir));
        let backend = ServerSshBackend::new(registry);

        // 1. Pubkey authentication (via `"git"` and explicit usernames).
        let mia_user = backend.authenticate_pubkey("git", &mia_key).await.unwrap();
        assert_eq!(mia_user.username, "mia");
        assert!(!mia_user.is_owner);

        let owner_user = backend
            .authenticate_pubkey("git", &owner_key)
            .await
            .unwrap();
        assert_eq!(owner_user.username, "owner");
        assert!(owner_user.is_owner);

        assert!(
            backend
                .authenticate_pubkey("owner", &mia_key)
                .await
                .is_none()
        );

        // 2. Anti-oracle hidden-repo refusal: mia gets identical error for hidden & missing repos.
        let hidden_err = backend
            .advertise_refs(&mia_user, "secret-repo", GitService::UploadPack, true)
            .await
            .unwrap_err();
        let missing_err = backend
            .advertise_refs(&mia_user, "does-not-exist", GitService::UploadPack, true)
            .await
            .unwrap_err();
        assert_eq!(hidden_err, "repository not found");
        assert_eq!(hidden_err, missing_err);

        // Owner CAN access `secret-repo`.
        let owner_secret_adv = backend
            .advertise_refs(&owner_user, "secret-repo", GitService::UploadPack, true)
            .await
            .unwrap();
        assert!(String::from_utf8_lossy(&owner_secret_adv).contains("version 2"));

        // 3. Protocol v2 `advertise_refs` + `ls-refs` + `fetch` for mia vs owner.
        let v2_adv = backend
            .advertise_refs(&mia_user, "repo", GitService::UploadPack, true)
            .await
            .unwrap();
        let v2_adv_str = String::from_utf8_lossy(&v2_adv);
        assert!(v2_adv_str.contains("version 2"));
        assert!(v2_adv_str.contains("ls-refs"));

        let mut ls_refs_req = Vec::new();
        ls_refs_req.extend_from_slice(&encode_pkt_line(b"command=ls-refs\n"));
        ls_refs_req.extend_from_slice(b"0001");
        ls_refs_req.extend_from_slice(&encode_pkt_line(b"symrefs\n"));
        ls_refs_req.extend_from_slice(b"0000");

        let mia_ls = backend
            .handle_upload_pack(&mia_user, "repo", true, &ls_refs_req)
            .await
            .unwrap();
        let mia_ls_str = String::from_utf8_lossy(&mia_ls);
        assert!(mia_ls_str.contains("refs/heads/main"));
        assert!(
            !mia_ls_str.contains("embargo"),
            "private branch leaked: {mia_ls_str}"
        );

        let owner_ls = backend
            .handle_upload_pack(&owner_user, "repo", true, &ls_refs_req)
            .await
            .unwrap();
        let owner_ls_str = String::from_utf8_lossy(&owner_ls);
        assert!(owner_ls_str.contains("refs/heads/embargo"));

        // Extract mia's projected main OID and owner's embargo OID.
        let extract_oid = |ls_bytes: &[u8], target_ref: &str| -> String {
            for tok in parse_pkt_lines(ls_bytes).unwrap() {
                if let PktToken::Data(line) = tok {
                    let s = String::from_utf8_lossy(&line);
                    let parts: Vec<&str> = s.split_whitespace().collect();
                    if parts.len() >= 2 && parts[1] == target_ref {
                        return parts[0].to_owned();
                    }
                }
            }
            panic!("ref {target_ref} not found in ls-refs output");
        };
        let mia_main_oid = extract_oid(&mia_ls, "refs/heads/main");
        let owner_embargo_oid = extract_oid(&owner_ls, "refs/heads/embargo");

        // Mia fetches her own projected main OID -> succeeds (protocol v2).
        let mut mia_fetch = Vec::new();
        mia_fetch.extend_from_slice(&encode_pkt_line(b"command=fetch\n"));
        mia_fetch.extend_from_slice(b"0001");
        mia_fetch.extend_from_slice(&encode_pkt_line(
            format!("want {mia_main_oid}\n").as_bytes(),
        ));
        mia_fetch.extend_from_slice(&encode_pkt_line(b"done\n"));
        mia_fetch.extend_from_slice(b"0000");
        let fetch_resp = backend
            .handle_upload_pack(&mia_user, "repo", true, &mia_fetch)
            .await
            .unwrap();
        assert!(fetch_resp.windows(4).any(|w| w == b"PACK"));

        // Protocol v0 multi-round negotiation: `have` without `done` returns `0008NAK\n` (no pack).
        let mut v0_round1 = Vec::new();
        v0_round1.extend_from_slice(&encode_pkt_line(
            format!("want {mia_main_oid}\n").as_bytes(),
        ));
        v0_round1.extend_from_slice(PKT_FLUSH);
        v0_round1.extend_from_slice(&encode_pkt_line(
            format!("have {mia_main_oid}\n").as_bytes(),
        ));
        v0_round1.extend_from_slice(PKT_FLUSH);
        let v0_resp = backend
            .handle_upload_pack(&mia_user, "repo", false, &v0_round1)
            .await
            .unwrap();
        assert_eq!(v0_resp, b"0008NAK\n");

        // Failed SSH auth is recorded in the audit sink.
        let before_audit = state.audit_sink.snapshot().len();
        assert!(
            backend
                .authenticate_pubkey("mia", &owner_key)
                .await
                .is_none()
        );
        let after_audit = state.audit_sink.snapshot();
        assert!(after_audit.len() > before_audit);
        assert!(after_audit.iter().any(|ev| ev.action == "ssh_auth_failed"));

        // Disabling Mia invalidates her already-authenticated `SshAuthenticatedUser` immediately.
        let router = build_router(state.clone());
        let (owner_cookie, _) = state.auth.seed("owner2", crate::tests::PW);
        let (status, _, _) = call(
            &router,
            Method::PATCH,
            "/v1/users/mia",
            &[("cookie", &owner_cookie)],
            Some(json!({ "disabled": true })),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert!(
            backend
                .advertise_refs(&mia_user, "repo", GitService::UploadPack, true)
                .await
                .is_err(),
            "disabled user must be rejected on existing SSH session"
        );
        // Re-enable Mia for the rest of the test.
        let (status, _, _) = call(
            &router,
            Method::PATCH,
            "/v1/users/mia",
            &[("cookie", &owner_cookie)],
            Some(json!({ "disabled": false })),
        )
        .await;
        assert_eq!(status, StatusCode::OK);

        // Anti-CFOR: mia requesting owner's embargo OID fails identically to nonexistent OID.
        let mut bad_fetch = Vec::new();
        bad_fetch.extend_from_slice(&encode_pkt_line(b"command=fetch\n"));
        bad_fetch.extend_from_slice(b"0001");
        bad_fetch.extend_from_slice(&encode_pkt_line(
            format!("want {owner_embargo_oid}\n").as_bytes(),
        ));
        bad_fetch.extend_from_slice(&encode_pkt_line(b"done\n"));
        bad_fetch.extend_from_slice(b"0000");
        let err_embargo = backend
            .handle_upload_pack(&mia_user, "repo", true, &bad_fetch)
            .await
            .unwrap_err();
        assert_eq!(err_embargo, "object not found in authorized scope");

        // 4. Protocol v0/v1 advertise + fetch for mia.
        let v0_adv = backend
            .advertise_refs(&mia_user, "repo", GitService::UploadPack, false)
            .await
            .unwrap();
        let v0_adv_str = String::from_utf8_lossy(&v0_adv);
        assert!(v0_adv_str.contains(&format!("{mia_main_oid} refs/heads/main")));
        assert!(!v0_adv_str.contains("embargo"));
        assert!(!v0_adv_str.contains("allow-tip-sha1-in-want"));

        let mut v0_req = Vec::new();
        v0_req.extend_from_slice(&encode_pkt_line(
            format!("want {mia_main_oid} side-band-64k\n").as_bytes(),
        ));
        v0_req.extend_from_slice(b"0000");
        v0_req.extend_from_slice(&encode_pkt_line(b"done\n"));
        let v0_resp = backend
            .handle_upload_pack(&mia_user, "repo", false, &v0_req)
            .await
            .unwrap();
        assert!(v0_resp.starts_with(b"0008NAK\n"));
        assert!(v0_resp.windows(4).any(|w| w == b"PACK"));

        // 5. Reversible `handle_receive_pack`: mia pushes an update to README.md on `main`;
        //    canonical repo updates README.md while preserving hidden `billing/ledger.rs`!
        let rcv_adv = backend
            .advertise_refs(&mia_user, "repo", GitService::ReceivePack, false)
            .await
            .unwrap();
        assert!(String::from_utf8_lossy(&rcv_adv).contains(&mia_main_oid));

        let blob_obj = GitObject::new(GitObjectKind::Blob, b"# Public v2 via SSH\n".to_vec());
        let tree_data = encode_tree(vec![TreeEntry {
            mode: "100644".to_owned(),
            name: "README.md".to_owned(),
            oid_hex: blob_obj.oid.clone(),
        }])
        .unwrap();
        let tree_obj = GitObject::new(GitObjectKind::Tree, tree_data);
        let commit_obj = CommitObj {
            tree: tree_obj.oid.clone(),
            parents: vec![mia_main_oid.clone()],
            author: "Mia <mia@example.test> 1732200100 +0000".to_owned(),
            committer: "Mia <mia@example.test> 1732200100 +0000".to_owned(),
            message: "docs: update README over SSH\n".to_owned(),
        };
        let commit_git_obj = GitObject::new(GitObjectKind::Commit, commit_obj.encode());
        let commit_oid = commit_git_obj.oid.clone();
        let pack = encode_packfile(&[&commit_git_obj, &tree_obj, &blob_obj]).unwrap();

        let mut push_payload = Vec::new();
        let cmd_line = format!(
            "{mia_main_oid} {commit_oid} refs/heads/main\0report-status side-band-64k atomic\n"
        );
        push_payload.extend_from_slice(&encode_pkt_line(cmd_line.as_bytes()));
        push_payload.extend_from_slice(b"0000");
        push_payload.extend_from_slice(&pack);

        let push_resp = backend
            .handle_receive_pack(&mia_user, "repo", push_payload)
            .await
            .unwrap();
        let push_resp_str = String::from_utf8_lossy(&push_resp);
        assert!(
            push_resp_str.contains("ok refs/heads/main"),
            "unexpected push response: {push_resp_str}"
        );

        // Verify canonical repo updated README.md and kept billing/ledger.rs intact!
        run_git(&main_repo, &["fsck", "--strict", "--full"]);
        assert_eq!(
            run_git(&main_repo, &["show", "main:README.md"]),
            "# Public v2 via SSH"
        );
        assert_eq!(
            run_git(&main_repo, &["show", "main:billing/ledger.rs"]),
            "const SECRET: u32 = 42;"
        );

        // 6. A delete-only push (`git push --delete`) carries no pack: the transport dispatches
        //    it at its flush, and the backend deletes the ref.
        run_git(&main_repo, &["branch", "gone", "main"]);
        let adv = backend
            .advertise_refs(&owner_user, "repo", GitService::ReceivePack, false)
            .await
            .unwrap();
        let gone_oid = parse_pkt_lines(&adv)
            .unwrap()
            .into_iter()
            .find_map(|tok| match tok {
                PktToken::Data(line) => {
                    let line = String::from_utf8_lossy(&line).into_owned();
                    let (oid, rest) = line.split_once(' ')?;
                    rest.starts_with("refs/heads/gone").then(|| oid.to_owned())
                }
                _ => None,
            })
            .unwrap();
        let mut delete_payload = encode_pkt_line(
            format!("{gone_oid} {ZERO_OID} refs/heads/gone\0report-status atomic\n").as_bytes(),
        );
        delete_payload.extend_from_slice(b"0000");
        assert!(premier_ssh::is_complete_delete_only_push(&delete_payload));
        let resp = backend
            .handle_receive_pack(&owner_user, "repo", delete_payload)
            .await
            .unwrap();
        let resp = String::from_utf8_lossy(&resp);
        assert!(resp.contains("ok refs/heads/gone"), "{resp}");
        assert!(
            std::process::Command::new("git")
                .current_dir(&main_repo)
                .args(["rev-parse", "--verify", "-q", "refs/heads/gone"])
                .output()
                .unwrap()
                .stdout
                .is_empty()
        );

        // Verify audit events were recorded for SSH upload-pack and receive-pack.
        let events = state.audit_sink.snapshot();
        assert!(events.iter().any(|e| e.action == "git_upload_pack_ssh"));
        assert!(events.iter().any(|e| e.action == "git_receive_pack_ssh"));
        assert!(events.iter().any(|e| e.action == "git_ref_update"));
    }
}
