//! Integrity assessment for traces shown by the viewer and CLI.

use crate::{read_manifest, verify};
use serde::{Deserialize, Serialize};
use std::path::Path;

/// Viewer-facing integrity state for a single trace artifact.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum IntegrityStatus {
    /// Recording is still open (no finalized journal).
    Live,
    /// Finalized journal matches the manifest digest and structural checks.
    Verified,
    /// Finalized or readable trace failed verification.
    Invalid,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct IntegrityReport {
    pub status: IntegrityStatus,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub detail: Option<String>,
}

/// Assess integrity of the trace at `root` without panicking on bad input.
pub fn assess_integrity(root: impl AsRef<Path>) -> IntegrityReport {
    let root = root.as_ref();
    let manifest = match read_manifest(root) {
        Ok(manifest) => manifest,
        Err(error) => {
            return IntegrityReport {
                status: IntegrityStatus::Invalid,
                detail: Some(error.to_string()),
            };
        }
    };
    if manifest.journal.is_none() {
        return IntegrityReport {
            status: IntegrityStatus::Live,
            detail: None,
        };
    }
    match verify(root) {
        Ok(_) => IntegrityReport {
            status: IntegrityStatus::Verified,
            detail: None,
        },
        Err(error) => IntegrityReport {
            status: IntegrityStatus::Invalid,
            detail: Some(error.to_string()),
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{EventInput, TraceWriter};
    use std::fs::OpenOptions;
    use std::io::Write;

    #[test]
    fn live_traces_are_not_verified() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().join("live.atrace");
        let _writer = TraceWriter::create(&root, vec!["true".into()]).unwrap();
        let report = assess_integrity(&root);
        assert_eq!(report.status, IntegrityStatus::Live);
        assert!(report.detail.is_none());
    }

    #[test]
    fn finalized_traces_verify() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().join("ok.atrace");
        let mut writer = TraceWriter::create(&root, vec!["true".into()]).unwrap();
        writer
            .append_input(EventInput {
                kind: "session.start".into(),
                ..EventInput::default()
            })
            .unwrap();
        writer.finish(0).unwrap();
        let report = assess_integrity(&root);
        assert_eq!(report.status, IntegrityStatus::Verified);
    }

    #[test]
    fn tampered_journals_are_invalid() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().join("bad.atrace");
        let writer = TraceWriter::create(&root, vec!["true".into()]).unwrap();
        writer.finish(0).unwrap();
        OpenOptions::new()
            .append(true)
            .open(root.join("events").join("000001.events.pb.zst"))
            .unwrap()
            .write_all(b"tampered")
            .unwrap();
        let report = assess_integrity(&root);
        assert_eq!(report.status, IntegrityStatus::Invalid);
        assert!(
            report
                .detail
                .as_deref()
                .is_some_and(|detail| detail.contains("digest")),
            "{:?}",
            report.detail
        );
    }

    #[test]
    fn missing_manifest_is_invalid() {
        let temp = tempfile::tempdir().unwrap();
        let report = assess_integrity(temp.path());
        assert_eq!(report.status, IntegrityStatus::Invalid);
        assert!(report.detail.is_some());
    }
}
