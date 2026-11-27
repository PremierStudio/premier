use super::*;

const KEY: [u8; 32] = [7u8; 32];

fn personal(owner: &str, path: &str, payload: Option<&str>) -> MountOverlayInput {
    MountOverlayInput {
        kind: OverlayKind::Personal,
        path: path.to_owned(),
        owner_principal: Some(owner.to_owned()),
        team_group: None,
        encrypted: true,
        payload: payload.map(|p| p.as_bytes().to_vec()),
    }
}

fn team(name: &str, path: &str, payload: Option<&str>) -> MountOverlayInput {
    MountOverlayInput {
        kind: OverlayKind::Team(name.to_owned()),
        path: path.to_owned(),
        owner_principal: None,
        team_group: None,
        encrypted: true,
        payload: payload.map(|p| p.as_bytes().to_vec()),
    }
}

fn store(dir: &Path) -> OverlayStore {
    OverlayStore::open_with_key(dir, "repo-a", KEY).unwrap()
}

fn blob(dir: &Path, id: &str) -> PathBuf {
    dir.join("overlays/blobs").join(format!("{id}.bin"))
}

#[test]
fn personal_overlays_are_isolated_even_at_the_same_path() {
    let tmp = tempfile::tempdir().unwrap();
    let s = store(tmp.path());
    s.mount(personal("@alice", "AGENTS.local.md", Some("alice notes")))
        .unwrap();
    s.mount(personal("bob", "AGENTS.local.md", Some("bob notes")))
        .unwrap();

    let alice = s.list_for_principal("alice", &[]).unwrap();
    assert_eq!(alice.len(), 1);
    assert_eq!(alice[0].owner_principal.as_deref(), Some("@alice"));
    assert!(alice[0].has_payload && alice[0].encrypted);
    assert_eq!(s.list_for_owner("@bob").unwrap().len(), 1);
    assert!(s.list_for_principal("@carol", &[]).unwrap().is_empty());

    let read = |who: &str| s.read_payload_for_principal("AGENTS.local.md", who, &[]);
    assert_eq!(read("@alice").unwrap().unwrap(), b"alice notes");
    assert_eq!(read("user:BOB").unwrap().unwrap(), b"bob notes");
    assert!(matches!(
        read("@carol"),
        Err(OverlayError::AccessDenied { .. })
    ));

    // Bob re-mounting only touches his own record.
    s.mount(personal("@bob", "AGENTS.local.md", Some("bob v2")))
        .unwrap();
    assert_eq!(read("@alice").unwrap().unwrap(), b"alice notes");

    // Carol can unmount neither.
    assert!(matches!(
        s.unmount("AGENTS.local.md", "@carol"),
        Err(OverlayError::AccessDenied { .. })
    ));
    assert!(s.unmount("AGENTS.local.md", "@bob").unwrap());
    assert_eq!(read("@alice").unwrap().unwrap(), b"alice notes");
    // Only Alice's overlay is left at that path: Bob is refused, not handed hers.
    assert!(matches!(
        read("@bob"),
        Err(OverlayError::AccessDenied { .. })
    ));
    assert!(s.unmount("AGENTS.local.md", "@alice").unwrap());
    assert_eq!(read("@bob").unwrap(), None);
}

#[test]
fn personal_overlays_need_a_real_owner() {
    let tmp = tempfile::tempdir().unwrap();
    let s = store(tmp.path());
    for owner in ["", "anonymous", "@", "group:core"] {
        assert!(
            matches!(
                s.mount(personal(owner, "a.md", None)),
                Err(OverlayError::InvalidInput(_))
            ),
            "{owner}"
        );
    }
}

#[test]
fn team_overlays_follow_group_membership() {
    let tmp = tempfile::tempdir().unwrap();
    let s = store(tmp.path());
    let r = s
        .mount(team("Core", ".run/dev.run.xml", Some("<run/>")))
        .unwrap();
    assert_eq!(r.team_group.as_deref(), Some("core"));
    assert_eq!(r.kind, OverlayKind::Team("core".to_owned()));

    let core = vec!["group:core".to_owned()];
    assert_eq!(s.list_for_principal("@mia", &core).unwrap().len(), 1);
    assert_eq!(
        s.list_for_principal("@mia", &["team:CORE".to_owned()])
            .unwrap()
            .len(),
        1
    );
    assert!(
        s.list_for_principal("@mia", &["billing".to_owned()])
            .unwrap()
            .is_empty()
    );
    assert_eq!(
        s.read_payload_for_principal(".run/dev.run.xml", "@mia", &core)
            .unwrap()
            .unwrap(),
        b"<run/>"
    );
    assert!(matches!(
        s.read_payload_for_principal(".run/dev.run.xml", "@eve", &[]),
        Err(OverlayError::AccessDenied { .. })
    ));
    assert_eq!(s.list_for_owner("@owner").unwrap().len(), 1);
}

#[test]
fn encrypted_payloads_never_hit_disk_in_plaintext_and_tampering_fails() {
    let tmp = tempfile::tempdir().unwrap();
    let s = store(tmp.path());
    let secret = "TOP-SECRET-OVERLAY-CONTENT-123";
    let r = s
        .mount(personal("@alice", "notes.local.md", Some(secret)))
        .unwrap();
    let path = blob(tmp.path(), &r.id);
    let raw = std::fs::read(&path).unwrap();
    for file in walk(tmp.path()) {
        let bytes = std::fs::read(&file).unwrap();
        assert!(
            !String::from_utf8_lossy(&bytes).contains(secret),
            "{}",
            file.display()
        );
    }

    // Wrong key.
    let other = OverlayStore::open_with_key(tmp.path(), "repo-a", [9u8; 32]).unwrap();
    assert!(matches!(
        other.read_payload_for_principal("notes.local.md", "@alice", &[]),
        Err(OverlayError::Crypto { .. })
    ));

    // One flipped ciphertext bit.
    let mut env: serde_json::Value = serde_json::from_slice(&raw).unwrap();
    let mut ct = B64.decode(env["ct"].as_str().unwrap()).unwrap();
    ct[0] ^= 1;
    env["ct"] = B64.encode(ct).into();
    std::fs::write(&path, serde_json::to_vec(&env).unwrap()).unwrap();
    assert!(matches!(
        s.read_payload_for_principal("notes.local.md", "@alice", &[]),
        Err(OverlayError::Crypto { .. })
    ));

    // A valid blob moved under another record (different AAD) does not decrypt.
    std::fs::write(&path, &raw).unwrap();
    let bob = s.mount(personal("@bob", "notes.local.md", None)).unwrap();
    let mut index = s.load_index().unwrap();
    if let Some(rec) = index.records.iter_mut().find(|x| x.id == bob.id) {
        rec.has_payload = true;
    }
    s.save_index(index).unwrap();
    std::fs::copy(&path, blob(tmp.path(), &bob.id)).unwrap();
    assert!(matches!(
        s.read_payload_for_principal("notes.local.md", "@bob", &[]),
        Err(OverlayError::Crypto { .. })
    ));
    assert_eq!(
        s.read_payload_for_principal("notes.local.md", "@alice", &[])
            .unwrap()
            .unwrap(),
        secret.as_bytes()
    );
}

#[test]
fn generated_key_persists_and_plain_payloads_are_stored_as_is() {
    let tmp = tempfile::tempdir().unwrap();
    let s = OverlayStore::open(tmp.path(), "repo-a").unwrap();
    assert!(!tmp.path().join("overlays").exists(), "open writes nothing");
    s.mount(personal("@alice", "a.md", Some("enc"))).unwrap();
    let key = std::fs::read(tmp.path().join("overlays/.key")).unwrap();
    assert_eq!(key.len(), 32);
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        let mode = std::fs::metadata(tmp.path().join("overlays/.key"))
            .unwrap()
            .permissions()
            .mode();
        assert_eq!(mode & 0o777, 0o600);
    }
    // Reopened under a new name: the pinned repo id and the key still decrypt.
    let again = OverlayStore::open(tmp.path(), "renamed").unwrap();
    assert_eq!(again.repo_id(), "repo-a");
    assert_eq!(
        again
            .read_payload_for_principal("a.md", "@alice", &[])
            .unwrap()
            .unwrap(),
        b"enc"
    );

    let mut plain = personal("@alice", "b.md", Some("plain text"));
    plain.encrypted = false;
    let r = s.mount(plain).unwrap();
    assert_eq!(
        std::fs::read(blob(tmp.path(), &r.id)).unwrap(),
        b"plain text"
    );

    // Re-mounting as encrypted without new content re-encodes the stored payload.
    s.mount(personal("@alice", "b.md", None)).unwrap();
    let raw = std::fs::read(blob(tmp.path(), &r.id)).unwrap();
    assert!(!String::from_utf8_lossy(&raw).contains("plain text"));
    assert_eq!(
        s.read_payload_for_principal("b.md", "@alice", &[])
            .unwrap()
            .unwrap(),
        b"plain text"
    );
}

#[test]
fn unmount_deletes_the_blob() {
    let tmp = tempfile::tempdir().unwrap();
    let s = store(tmp.path());
    let r = s
        .mount(personal("@alice", "x.local.md", Some("x")))
        .unwrap();
    let path = blob(tmp.path(), &r.id);
    assert!(path.exists());
    assert!(s.unmount("x.local.md", "@alice").unwrap());
    assert!(!path.exists());
    assert!(!s.unmount("x.local.md", "@alice").unwrap());
    assert!(s.to_manifest().unwrap().entries.is_empty());
}

#[test]
fn invalid_and_reserved_paths_are_refused() {
    let tmp = tempfile::tempdir().unwrap();
    let s = store(tmp.path());
    for bad in [
        "",
        "../x",
        "/etc/passwd",
        "C:/x",
        ".git/config",
        "a/.GIT/hooks/pre-commit",
        ".premier/state.json",
        "x/.premier-local/a",
        "notes/[unclosed",
    ] {
        assert!(s.mount(personal("@alice", bad, None)).is_err(), "{bad}");
    }
    assert!(matches!(
        s.mount(personal("@alice", "notes/*.md", Some("x"))),
        Err(OverlayError::InvalidInput(_))
    ));
    assert!(s.mount(personal("@alice", "notes/*.md", None)).is_ok());
}

#[test]
fn manifest_merges_everyone_and_guards_pushes() {
    let tmp = tempfile::tempdir().unwrap();
    let s = store(tmp.path());
    s.mount(personal("@alice", "AGENTS.local.md", None))
        .unwrap();
    s.mount(personal("@bob", "AGENTS.local.md", None)).unwrap();
    s.mount(personal("@bob", "bob/*.env", None)).unwrap();
    s.mount(team("core", ".run/**", None)).unwrap();
    let manifest = s.to_manifest().unwrap();
    assert_eq!(manifest.entries.len(), 3, "{manifest:?}");
    let guard = OverlayGuard::from_manifest(&manifest).unwrap();
    for blocked in ["bob/prod.env", ".run/x.xml", "AGENTS.local.md"] {
        assert!(
            guard.is_overlay_path(&RepoPath::new(blocked).unwrap()),
            "{blocked}"
        );
    }
    assert!(!guard.is_overlay_path(&RepoPath::new("src/main.rs").unwrap()));
    assert!(
        guard
            .validate_public_paths(&[RepoPath::new("bob/x.env").unwrap()])
            .is_err()
    );
}

#[test]
fn materialize_writes_only_authorized_payloads() {
    let tmp = tempfile::tempdir().unwrap();
    let target = tempfile::tempdir().unwrap();
    let s = store(tmp.path());
    s.mount(personal("@alice", "AGENTS.local.md", Some("alice")))
        .unwrap();
    s.mount(personal("@bob", "AGENTS.local.md", Some("bob")))
        .unwrap();
    s.mount(personal("@bob", "bob-only.md", Some("bob")))
        .unwrap();
    s.mount(team("core", ".run/dev.xml", Some("core"))).unwrap();
    s.mount(team("core", "AGENTS.local.md", Some("team copy")))
        .unwrap();
    s.mount(team("billing", "billing.env", Some("billing")))
        .unwrap();
    s.mount(personal("@alice", "glob/*.md", None)).unwrap();
    s.mount(personal("@alice", "meta-only.md", None)).unwrap();

    let mut written = s
        .materialize_into_dir(target.path(), "@alice", &["core".to_owned()])
        .unwrap();
    written.sort();
    assert_eq!(written, vec![".run/dev.xml", "AGENTS.local.md"]);
    let read = |p: &str| std::fs::read_to_string(target.path().join(p)).unwrap();
    assert_eq!(read("AGENTS.local.md"), "alice", "personal wins over team");
    assert_eq!(read(".run/dev.xml"), "core");
    for absent in ["bob-only.md", "billing.env", "meta-only.md"] {
        assert!(!target.path().join(absent).exists(), "{absent}");
    }
}

#[test]
fn materialize_refuses_symlink_escapes() {
    let tmp = tempfile::tempdir().unwrap();
    let target = tempfile::tempdir().unwrap();
    let outside = tempfile::tempdir().unwrap();
    let s = store(tmp.path());
    s.mount(personal("@alice", "linked/pwn.md", Some("x")))
        .unwrap();
    #[cfg(unix)]
    let linked = std::os::unix::fs::symlink(outside.path(), target.path().join("linked")).is_ok();
    #[cfg(windows)]
    let linked =
        std::os::windows::fs::symlink_dir(outside.path(), target.path().join("linked")).is_ok();
    if !linked {
        eprintln!("symlinks not permitted on this host: test skipped");
        return;
    }
    assert!(matches!(
        s.materialize_into_dir(target.path(), "@alice", &[]),
        Err(OverlayError::InvalidPath { .. })
    ));
    assert!(!outside.path().join("pwn.md").exists());
}

#[test]
fn materialize_refuses_a_tampered_index_path() {
    let tmp = tempfile::tempdir().unwrap();
    let target = tempfile::tempdir().unwrap();
    let s = store(tmp.path());
    s.mount(personal("@alice", "ok.md", Some("x"))).unwrap();
    for bad in ["../escape.md", ".git/hooks/pre-commit"] {
        let mut index = s.load_index().unwrap();
        index.records[0].path = bad.to_owned();
        s.save_index(index).unwrap();
        assert!(
            matches!(
                s.materialize_into_dir(target.path(), "@alice", &[]),
                Err(OverlayError::InvalidPath { .. })
            ),
            "{bad}"
        );
    }
    assert!(!target.path().join(".git").exists());
    assert!(!target.path().join("ok.md").exists());
}

fn walk(dir: &Path) -> Vec<PathBuf> {
    let mut out = Vec::new();
    for e in std::fs::read_dir(dir).unwrap().flatten() {
        let p = e.path();
        if p.is_dir() {
            out.extend(walk(&p));
        } else {
            out.push(p);
        }
    }
    out
}
