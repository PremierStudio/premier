//! Pure-Rust Git Smart HTTP v2 wire protocol (`ls-refs` & `fetch` with side-band-64k).
//!
//! Completely replaces stock `git-upload-pack` + `uploadpack.hideRefs`:
//! - Never advertises private refs to unauthorized callers.
//! - Rejects unauthorized `want` OIDs with an indistinguishable error (zero existence oracle).
//! - Silently ignores unauthorized `have` OIDs (zero `have`/ACK oracle).

use crate::GitBridgeError;
use crate::objects::{GitObjectKind, encode_packfile, parse_tag_object};
use crate::projector::{ProjectedView, collect_reachable_objects};

const PKT_FLUSH: &[u8] = b"0000";
const PKT_DELIM: &[u8] = b"0001";
const MAX_TAG_PEEL_DEPTH: usize = 8;

/// Encode a single Git pkt-line frame (`4-hex-len + payload`).
pub fn encode_pkt_line(payload: &[u8]) -> Vec<u8> {
    let total = payload.len() + 4;
    let mut out = Vec::with_capacity(total);
    out.extend_from_slice(format!("{total:04x}").as_bytes());
    out.extend_from_slice(payload);
    out
}

/// Parsed pkt-line token from a Git v2 request body.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PktToken {
    Data(Vec<u8>),
    Flush,
    Delim,
}

/// Parse a Git pkt-line byte stream into tokens.
pub fn parse_pkt_lines(input: &[u8]) -> Result<Vec<PktToken>, GitBridgeError> {
    let mut tokens = Vec::new();
    let mut i = 0usize;
    while i + 4 <= input.len() {
        let len_bytes = &input[i..i + 4];
        if !len_bytes.iter().all(u8::is_ascii_hexdigit) {
            return Err(GitBridgeError::Protocol(format!(
                "invalid pkt-line hex '{}'",
                String::from_utf8_lossy(len_bytes)
            )));
        }
        let len_str = std::str::from_utf8(len_bytes)
            .map_err(|_| GitBridgeError::Protocol("non-ASCII pkt-line length".to_owned()))?;
        let len = usize::from_str_radix(len_str, 16)
            .map_err(|_| GitBridgeError::Protocol(format!("invalid pkt-line hex '{len_str}'")))?;
        i += 4;
        if len == 0 {
            tokens.push(PktToken::Flush);
            continue;
        }
        if len == 1 {
            tokens.push(PktToken::Delim);
            continue;
        }
        if len == 2 {
            // response-end-pkt
            continue;
        }
        if len < 4 || i + (len - 4) > input.len() {
            return Err(GitBridgeError::Protocol(
                "truncated pkt-line payload".to_owned(),
            ));
        }
        let payload_len = len - 4;
        tokens.push(PktToken::Data(input[i..i + payload_len].to_vec()));
        i += payload_len;
    }
    Ok(tokens)
}

/// Build the `GET /info/refs?service=git-upload-pack` Smart HTTP v2 capability advertisement.
///
/// Explicitly omits `allow-tip-sha1-in-want` and `allow-reachable-sha1-in-want`.
pub fn render_info_refs_v2() -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(&encode_pkt_line(b"# service=git-upload-pack\n"));
    out.extend_from_slice(PKT_FLUSH);
    out.extend_from_slice(&encode_pkt_line(b"version 2\n"));
    out.extend_from_slice(&encode_pkt_line(b"agent=premier/0.1\n"));
    out.extend_from_slice(&encode_pkt_line(b"ls-refs\n"));
    out.extend_from_slice(&encode_pkt_line(b"fetch=wait-for-done\n"));
    out.extend_from_slice(&encode_pkt_line(b"object-format=sha1\n"));
    out.extend_from_slice(PKT_FLUSH);
    out
}

/// Handle a `POST /git-upload-pack` Smart HTTP v2 command (`ls-refs` or `fetch`)
/// strictly within the caller's isolated `ProjectedView`. `default_ref` is the repository's default
/// branch as advertised (`refs/heads/<name>`), `None` when it has none.
pub fn handle_upload_pack_v2(
    view: &ProjectedView,
    default_ref: Option<&str>,
    request_body: &[u8],
) -> Result<Vec<u8>, GitBridgeError> {
    let tokens = parse_pkt_lines(request_body)?;
    let mut command = String::new();
    let mut args = Vec::new();
    let mut in_args = false;

    for tok in tokens {
        match tok {
            PktToken::Delim => in_args = true,
            PktToken::Flush => break,
            PktToken::Data(bytes) => {
                let line = String::from_utf8_lossy(&bytes)
                    .trim_end_matches(['\r', '\n'])
                    .to_owned();
                if !in_args {
                    if let Some(cmd) = line.strip_prefix("command=") {
                        command = cmd.to_owned();
                    }
                } else {
                    args.push(line);
                }
            }
        }
    }

    match command.as_str() {
        "ls-refs" => handle_ls_refs(view, default_ref, &args),
        "fetch" => handle_fetch(view, &args),
        other => Err(GitBridgeError::Protocol(format!(
            "unsupported git v2 command '{other}'"
        ))),
    }
}

fn handle_ls_refs(
    view: &ProjectedView,
    default_ref: Option<&str>,
    args: &[String],
) -> Result<Vec<u8>, GitBridgeError> {
    let want_symrefs = args.iter().any(|a| a == "symrefs");
    let want_peel = args.iter().any(|a| a == "peel");
    let prefixes: Vec<&str> = args
        .iter()
        .filter_map(|a| a.strip_prefix("ref-prefix "))
        .collect();

    let matches_prefix = |name: &str| -> bool {
        if prefixes.is_empty() {
            return true;
        }
        prefixes.iter().any(|p| name.starts_with(p))
    };

    let mut out = Vec::new();

    // HEAD is the repository's default branch when the caller sees it (what a clone checks out);
    // otherwise their first visible branch by name, never a ref outside the view.
    if let Some((head_target, head_oid)) = default_ref
        .and_then(|d| view.refs.get_key_value(d))
        .or_else(|| view.refs.iter().find(|(r, _)| r.starts_with("refs/heads/")))
        && matches_prefix("HEAD")
    {
        let line = if want_symrefs {
            format!("{head_oid} HEAD symref-target:{head_target}\n")
        } else {
            format!("{head_oid} HEAD\n")
        };
        out.extend_from_slice(&encode_pkt_line(line.as_bytes()));
    }

    for (ref_name, oid) in &view.refs {
        if matches_prefix(ref_name) {
            let line = if want_peel && let Some(peeled) = peel_tag_oid(view, oid) {
                format!("{oid} {ref_name} peeled:{peeled}\n")
            } else {
                format!("{oid} {ref_name}\n")
            };
            out.extend_from_slice(&encode_pkt_line(line.as_bytes()));
        }
    }

    out.extend_from_slice(PKT_FLUSH);
    Ok(out)
}

/// Peel annotated tags (including nested tag -> tag -> commit chains) up to `MAX_TAG_PEEL_DEPTH`.
/// Returns `None` for non-tag objects, cycles, or chains exceeding the depth bound.
fn peel_tag_oid(view: &ProjectedView, start_oid: &str) -> Option<String> {
    let mut current = start_oid.to_owned();
    for depth in 0..MAX_TAG_PEEL_DEPTH {
        let obj = view.odb.get(&current)?;
        if obj.kind != GitObjectKind::Tag {
            return (depth > 0).then_some(current);
        }
        current = parse_tag_object(&obj.data).ok()?;
    }
    let obj = view.odb.get(&current)?;
    (obj.kind != GitObjectKind::Tag).then_some(current)
}

fn handle_fetch(view: &ProjectedView, args: &[String]) -> Result<Vec<u8>, GitBridgeError> {
    let mut wants = Vec::new();
    let mut haves = Vec::new();
    let mut done = false;
    let mut wait_for_done = false;

    for arg in args {
        if let Some(oid) = arg.strip_prefix("want ") {
            wants.push(oid.trim().to_owned());
        } else if let Some(oid) = arg.strip_prefix("have ") {
            haves.push(oid.trim().to_owned());
        } else if arg == "done" {
            done = true;
        } else if arg == "wait-for-done" {
            wait_for_done = true;
        }
    }

    // Anti-oracle: validate all `wants` immediately against the caller's authorized scope!
    for w in &wants {
        view.ledger.require_oid_in_scope(&view.scope, w)?;
    }

    let mut out = Vec::new();

    if !done {
        // Neutral `acknowledgments`: only ACK OIDs strictly inside the caller's scope.
        let acks = view.ledger.filter_negotiated_haves(&view.scope, &haves);
        out.extend_from_slice(&encode_pkt_line(b"acknowledgments\n"));
        if acks.is_empty() || wait_for_done {
            if acks.is_empty() {
                out.extend_from_slice(&encode_pkt_line(b"NAK\n"));
            } else {
                for ack in &acks {
                    out.extend_from_slice(&encode_pkt_line(format!("ACK {ack}\n").as_bytes()));
                }
            }
            out.extend_from_slice(PKT_FLUSH);
            return Ok(out);
        }
        for ack in &acks {
            out.extend_from_slice(&encode_pkt_line(format!("ACK {ack}\n").as_bytes()));
        }
        out.extend_from_slice(&encode_pkt_line(b"ready\n"));
        out.extend_from_slice(PKT_DELIM);
    }

    let objects = collect_reachable_objects(view, &wants, &haves)?;
    let pack = encode_packfile(&objects)?;

    out.extend_from_slice(&encode_pkt_line(b"packfile\n"));
    // Side-band-64k framing (channel 1 = packfile bytes, max payload 65515 per pkt-line).
    for chunk in pack.chunks(65_000) {
        let mut frame = Vec::with_capacity(chunk.len() + 1);
        frame.push(1u8);
        frame.extend_from_slice(chunk);
        out.extend_from_slice(&encode_pkt_line(&frame));
    }
    out.extend_from_slice(PKT_FLUSH);
    Ok(out)
}
