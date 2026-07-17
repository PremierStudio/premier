//! Safe preparation of `.atrace` output directories.

use anyhow::{Result, bail};
use std::fs;
use std::path::Path;

/// Prepare `output` as a destination for a new Premier trace.
///
/// - Creates parent directories as needed.
/// - If `output` does not exist, succeeds.
/// - If `output` is an existing Premier trace directory (has `manifest.json`), replaces it.
/// - Otherwise refuses to delete or overwrite (prevents `demo --output /important` disasters).
pub fn prepare_trace_output(output: &Path) -> Result<()> {
    if let Some(parent) = output.parent()
        && !parent.as_os_str().is_empty()
    {
        fs::create_dir_all(parent)?;
    }
    if !output.exists() {
        return Ok(());
    }
    if output.is_dir() && output.join("manifest.json").is_file() {
        fs::remove_dir_all(output)?;
        return Ok(());
    }
    bail!(
        "refusing to overwrite non-trace path: {} (only an existing Premier .atrace with manifest.json may be replaced)",
        output.display()
    );
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs::File;
    use std::io::Write;

    #[test]
    fn creates_parent_when_missing() {
        let temp = tempfile::tempdir().unwrap();
        let output = temp.path().join("nested").join("run.atrace");
        prepare_trace_output(&output).unwrap();
        assert!(output.parent().unwrap().is_dir());
        assert!(!output.exists());
    }

    #[test]
    fn replaces_existing_trace_directory() {
        let temp = tempfile::tempdir().unwrap();
        let output = temp.path().join("old.atrace");
        fs::create_dir_all(output.join("events")).unwrap();
        File::create(output.join("manifest.json"))
            .unwrap()
            .write_all(br#"{"format_version":1}"#)
            .unwrap();
        File::create(output.join("events").join("keep-me")).unwrap();
        prepare_trace_output(&output).unwrap();
        assert!(!output.exists());
    }

    #[test]
    fn refuses_to_delete_arbitrary_directory() {
        let temp = tempfile::tempdir().unwrap();
        let precious = temp.path().join("user-data");
        fs::create_dir_all(&precious).unwrap();
        File::create(precious.join("important.txt"))
            .unwrap()
            .write_all(b"keep me")
            .unwrap();
        let error = prepare_trace_output(&precious).unwrap_err().to_string();
        assert!(error.contains("refusing to overwrite"), "{error}");
        assert!(precious.join("important.txt").exists());
    }

    #[test]
    fn refuses_to_overwrite_a_plain_file() {
        let temp = tempfile::tempdir().unwrap();
        let file = temp.path().join("notes.txt");
        fs::write(&file, "notes").unwrap();
        let error = prepare_trace_output(&file).unwrap_err().to_string();
        assert!(error.contains("refusing to overwrite"), "{error}");
        assert_eq!(fs::read_to_string(&file).unwrap(), "notes");
    }

    #[test]
    fn accepts_a_relative_filename_with_an_empty_parent() {
        let temp = tempfile::tempdir().unwrap();
        let previous = std::env::current_dir().unwrap();
        std::env::set_current_dir(temp.path()).unwrap();
        let result = prepare_trace_output(Path::new("local.atrace"));
        std::env::set_current_dir(previous).unwrap();
        result.unwrap();
        assert!(!temp.path().join("local.atrace").exists());
    }

    #[test]
    fn refuses_directory_without_manifest() {
        let temp = tempfile::tempdir().unwrap();
        let dir = temp.path().join("almost-trace");
        fs::create_dir_all(dir.join("events")).unwrap();
        let error = prepare_trace_output(&dir).unwrap_err().to_string();
        assert!(error.contains("refusing to overwrite"), "{error}");
        assert!(dir.join("events").exists());
    }
}
