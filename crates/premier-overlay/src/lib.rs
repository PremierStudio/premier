//! `premier-overlay` — Typed Team & Personal E2EE Overlays with structural push exclusion.
//!
//! Ensures files mounted via `overlay:team-*` or `overlay:me` (such as `AGENTS.local.md`
//! or `.run` launch configs) can never be committed or pushed to public Git history.

use globset::{GlobBuilder, GlobSet, GlobSetBuilder};
use premier_core::{OverlayKind, RepoPath};
use serde::{Deserialize, Serialize};
use thiserror::Error;

mod store;
pub use store::{
    MountOverlayInput, OverlayListResponse, OverlayRecord, OverlayStore, OverlaySummary,
    normalize_group, normalize_principal,
};

#[derive(Debug, Error)]
pub enum OverlayError {
    #[error("invalid overlay glob '{pattern}': {source}")]
    InvalidGlob {
        pattern: String,
        #[source]
        source: globset::Error,
    },

    #[error("refusing to include overlay file(s) in public commit/push: {paths:?}")]
    LeakBlocked { paths: Vec<String> },

    #[error("invalid overlay path '{path}': {reason}")]
    InvalidPath { path: String, reason: String },

    #[error("invalid overlay: {0}")]
    InvalidInput(String),

    /// The overlay at `path` belongs to another principal (or a team the caller is not in).
    #[error("overlay '{path}' belongs to another principal")]
    AccessDenied { path: String },

    /// Decryption failed: the payload, its nonce or its bound metadata was altered.
    #[error("overlay '{path}' failed authenticated decryption")]
    Crypto { path: String },

    #[error("corrupt overlay store: {0}")]
    Corrupt(String),

    #[error("{context}: {source}")]
    Io {
        context: String,
        #[source]
        source: std::io::Error,
    },
}

/// One declared overlay entry tracked in `.premier-local/overlay-manifest.json`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OverlayEntry {
    pub kind: OverlayKind,
    pub path: String,
    #[serde(default)]
    pub encrypted: bool,
}

/// Local workspace overlay manifest (never tracked in public Git trees).
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct OverlayManifest {
    #[serde(default = "default_version")]
    pub version: u32,
    #[serde(default)]
    pub entries: Vec<OverlayEntry>,
}

fn default_version() -> u32 {
    1
}

/// Compiled guard checking candidate commit/push paths against active overlays.
#[derive(Debug, Clone)]
pub struct OverlayGuard {
    matcher: GlobSet,
}

impl OverlayGuard {
    pub fn from_manifest(manifest: &OverlayManifest) -> Result<Self, OverlayError> {
        let build_glob = |pattern: &str| {
            GlobBuilder::new(pattern)
                .case_insensitive(true)
                .literal_separator(true)
                .build()
                .map_err(|source| OverlayError::InvalidGlob {
                    pattern: pattern.to_owned(),
                    source,
                })
        };
        let mut builder = GlobSetBuilder::new();
        // Always guard conventional local-only agent/overlay files.
        for default_pat in [
            "AGENTS.local.md",
            "**/AGENTS.local.md",
            ".premier-local/**",
            "**/.premier-local/**",
        ] {
            builder.add(build_glob(default_pat)?);
        }
        for entry in &manifest.entries {
            builder.add(build_glob(&entry.path)?);
        }
        let matcher = builder
            .build()
            .map_err(|source| OverlayError::InvalidGlob {
                pattern: "<overlay-set>".to_owned(),
                source,
            })?;
        Ok(Self { matcher })
    }

    pub fn is_overlay_path(&self, path: &RepoPath) -> bool {
        self.matcher.is_match(path.as_str())
    }

    /// Reject any candidate public commit/push touching an overlay path.
    pub fn validate_public_paths(&self, paths: &[RepoPath]) -> Result<(), OverlayError> {
        let leaked: Vec<String> = paths
            .iter()
            .filter(|p| self.is_overlay_path(p))
            .map(ToString::to_string)
            .collect();
        if leaked.is_empty() {
            Ok(())
        } else {
            Err(OverlayError::LeakBlocked { paths: leaked })
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn blocks_overlay_files_from_public_push() {
        let manifest = OverlayManifest {
            version: 1,
            entries: vec![OverlayEntry {
                kind: OverlayKind::Team("core".to_owned()),
                path: ".run/**".to_owned(),
                encrypted: false,
            }],
        };
        let guard = OverlayGuard::from_manifest(&manifest).unwrap();

        assert!(guard.is_overlay_path(&RepoPath::new("AGENTS.local.md").unwrap()));
        assert!(guard.is_overlay_path(&RepoPath::new(".run/debug.run.xml").unwrap()));
        assert!(!guard.is_overlay_path(&RepoPath::new("src/main.rs").unwrap()));

        let err = guard
            .validate_public_paths(&[
                RepoPath::new("src/main.rs").unwrap(),
                RepoPath::new("AGENTS.local.md").unwrap(),
            ])
            .unwrap_err();
        assert!(matches!(err, OverlayError::LeakBlocked { .. }));
    }

    #[test]
    fn overlay_guard_is_case_insensitive_and_guards_nested_premier_local() {
        let manifest = OverlayManifest {
            version: 1,
            entries: vec![OverlayEntry {
                kind: OverlayKind::Personal,
                path: "*.secret.toml".to_owned(),
                encrypted: true,
            }],
        };
        let guard = OverlayGuard::from_manifest(&manifest).unwrap();

        for blocked in [
            "agents.local.md",
            "AGENTS.LOCAL.MD",
            "apps/web/Agents.Local.md",
            ".PREMIER-LOCAL/overlay-manifest.json",
            "packages/a/.premier-local/state.json",
            "packages/a/.PREMIER-LOCAL/state.json",
            "LOCAL.SECRET.TOML",
        ] {
            assert!(
                guard.is_overlay_path(&RepoPath::new(blocked).unwrap()),
                "{blocked} must be caught as an overlay path"
            );
        }
        // `literal_separator(true)` ensures `*.secret.toml` does not cross `/` unintentionally.
        assert!(!guard.is_overlay_path(&RepoPath::new("nested/local.secret.toml").unwrap()));
    }
}
