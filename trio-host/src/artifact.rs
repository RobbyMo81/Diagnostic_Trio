//! Artifact write-back behaviour for Diagnostic Trio.
//!
//! Trio maintains one durable JSONL artifact file per tool so that
//! investigations remain reviewable after a run ends.  Artifact files live
//! inside the `artifacts/` sub-directory of the shared workspace.
//!
//! # Artifact set
//!
//! | Tool      | File                        |
//! |-----------|-----------------------------|
//! | Discover  | `discover-findings.jsonl`   |
//! | Searcher  | `searcher-findings.jsonl`   |
//! | Trace     | `trace-findings.jsonl`      |
//!
//! Each file is append-only JSONL: one [`crate::evidence::EvidenceRecord`]
//! per line.  Existing lines are never modified or removed.
//!
//! # Provenance
//!
//! Every line serialises the complete [`crate::evidence::EvidenceRecord`],
//! including `source_tool`, `timestamp`, `target`, `probe_family`, `layer`,
//! `status`, `kind`, `confidence`, `raw_refs`, `interpretation`, and
//! `metadata`.  This means each artifact line is self-describing and can be
//! attributed to its originating tool and run without consulting any external
//! index.
//!
//! # Relationship to the journal and workspace
//!
//! 1. **Workspace**: call [`crate::workspace::WorkspaceLayout::artifact_path`]
//!    with [`ArtifactKind::filename`] to obtain the correct path before
//!    calling [`append_record`].
//!
//! 2. **Journal**: after writing an artifact record, emit a
//!    [`crate::journal::JournalEventKind::FindingRecorded`] or
//!    [`crate::journal::JournalEventKind::WorkspaceUpdated`] entry to keep
//!    the audit trail continuous.  Use the record's `source_tool` +
//!    `timestamp` + `target` combination as a natural key when constructing
//!    the `evidence_ref` in the journal entry.
//!
//! # Example flow
//!
//! ```text
//! 1. Tool produces EvidenceRecord
//! 2. append_record(layout.artifact_path(kind.filename()), &record)
//! 3. journal::append(layout.journal_path("run.jsonl"), &journal_entry)
//! ```

use std::io::{self, Write as _};
use std::path::Path;

use crate::evidence::EvidenceRecord;

// ---------------------------------------------------------------------------
// ArtifactKind
// ---------------------------------------------------------------------------

/// Which Trio tool's artifact file a write targets.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ArtifactKind {
    /// Artifact produced by the Discover capability.
    DiscoverFindings,
    /// Artifact produced by the Searcher capability.
    SearcherFindings,
    /// Artifact produced by the Trace capability.
    TraceFindings,
}

impl ArtifactKind {
    /// Returns the canonical string label for this artifact kind.
    pub fn as_str(&self) -> &'static str {
        match self {
            ArtifactKind::DiscoverFindings => "discover-findings",
            ArtifactKind::SearcherFindings => "searcher-findings",
            ArtifactKind::TraceFindings => "trace-findings",
        }
    }

    /// Returns the filename (including extension) of this artifact file.
    ///
    /// Pass this to [`crate::workspace::WorkspaceLayout::artifact_path`] to
    /// obtain the fully qualified path.
    pub fn filename(&self) -> &'static str {
        match self {
            ArtifactKind::DiscoverFindings => "discover-findings.jsonl",
            ArtifactKind::SearcherFindings => "searcher-findings.jsonl",
            ArtifactKind::TraceFindings => "trace-findings.jsonl",
        }
    }
}

// ---------------------------------------------------------------------------
// Serialisation helpers
// ---------------------------------------------------------------------------

/// Escape a string value for use inside a JSON string literal.
fn json_escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 4);
    for ch in s.chars() {
        match ch {
            '\\' => out.push_str("\\\\"),
            '"' => out.push_str("\\\""),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c => out.push(c),
        }
    }
    out
}

/// Serialise an [`EvidenceRecord`] to a single JSONL line (no trailing
/// newline).
///
/// Every field of the record is included so that the artifact is fully
/// self-describing and provenance is preserved without consulting any external
/// index.
pub fn format_record(record: &EvidenceRecord) -> String {
    // layer: number or null
    let layer_json = match record.layer {
        Some(l) => l.to_string(),
        None => "null".to_string(),
    };

    // raw_refs: JSON array of strings
    let raw_refs_items: Vec<String> = record
        .raw_refs
        .iter()
        .map(|r| format!("\"{}\"", json_escape(r)))
        .collect();
    let raw_refs_json = format!("[{}]", raw_refs_items.join(","));

    // interpretation: string or null
    let interp_json = match &record.interpretation {
        Some(s) => format!("\"{}\"", json_escape(s)),
        None => "null".to_string(),
    };

    // metadata: sorted JSON object
    let metadata_pairs: Vec<String> = {
        let mut pairs: Vec<(&String, &String)> = record.metadata.iter().collect();
        pairs.sort_by_key(|(k, _)| k.as_str());
        pairs
            .iter()
            .map(|(k, v)| format!("\"{}\":\"{}\"", json_escape(k), json_escape(v)))
            .collect()
    };
    let metadata_json = format!("{{{}}}", metadata_pairs.join(","));

    format!(
        "{{\"source_tool\":\"{src}\",\"timestamp\":\"{ts}\",\"target\":\"{tgt}\",\
\"probe_family\":\"{pf}\",\"layer\":{layer},\"status\":\"{status}\",\
\"summary\":\"{summary}\",\"kind\":\"{kind}\",\"raw_refs\":{raw_refs},\
\"confidence\":{conf},\"interpretation\":{interp},\"metadata\":{meta}}}",
        src = json_escape(&record.source_tool),
        ts = json_escape(&record.timestamp),
        tgt = json_escape(&record.target),
        pf = json_escape(&record.probe_family),
        layer = layer_json,
        status = record.status.as_str(),
        summary = json_escape(&record.summary),
        kind = record.kind.as_str(),
        raw_refs = raw_refs_json,
        conf = record.confidence,
        interp = interp_json,
        meta = metadata_json,
    )
}

// ---------------------------------------------------------------------------
// Append-only write
// ---------------------------------------------------------------------------

/// Append `record` to the artifact file at `path` as a single JSONL line.
///
/// The file is opened in append mode and created if it does not exist.  Each
/// call writes exactly one line followed by `\n`.  Existing content is never
/// modified.
///
/// # Errors
///
/// Returns an [`io::Error`] if the file cannot be opened or the write fails.
pub fn append_record(path: impl AsRef<Path>, record: &EvidenceRecord) -> io::Result<()> {
    let mut file = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)?;
    let line = format_record(record);
    writeln!(file, "{}", line)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::evidence::{DiagnosticStatus, EvidenceKind, EvidenceRecord};

    fn record() -> EvidenceRecord {
        EvidenceRecord::new(
            "discover",
            "2026-03-20T00:00:00Z",
            "/etc/hosts",
            "config-parse",
            DiagnosticStatus::Pass,
            "Host file parsed OK.",
            EvidenceKind::Static,
        )
    }

    // --- ArtifactKind ---

    #[test]
    fn artifact_kind_discover_as_str() {
        assert_eq!(ArtifactKind::DiscoverFindings.as_str(), "discover-findings");
    }

    #[test]
    fn artifact_kind_searcher_as_str() {
        assert_eq!(ArtifactKind::SearcherFindings.as_str(), "searcher-findings");
    }

    #[test]
    fn artifact_kind_trace_as_str() {
        assert_eq!(ArtifactKind::TraceFindings.as_str(), "trace-findings");
    }

    #[test]
    fn artifact_kind_discover_filename() {
        assert_eq!(ArtifactKind::DiscoverFindings.filename(), "discover-findings.jsonl");
    }

    #[test]
    fn artifact_kind_searcher_filename() {
        assert_eq!(ArtifactKind::SearcherFindings.filename(), "searcher-findings.jsonl");
    }

    #[test]
    fn artifact_kind_trace_filename() {
        assert_eq!(ArtifactKind::TraceFindings.filename(), "trace-findings.jsonl");
    }

    #[test]
    fn all_kinds_have_jsonl_extension() {
        for kind in &[
            ArtifactKind::DiscoverFindings,
            ArtifactKind::SearcherFindings,
            ArtifactKind::TraceFindings,
        ] {
            assert!(kind.filename().ends_with(".jsonl"));
        }
    }

    // --- format_record ---

    #[test]
    fn format_record_contains_source_tool() {
        let line = format_record(&record());
        assert!(line.contains("\"source_tool\":\"discover\""));
    }

    #[test]
    fn format_record_contains_timestamp() {
        let line = format_record(&record());
        assert!(line.contains("\"timestamp\":\"2026-03-20T00:00:00Z\""));
    }

    #[test]
    fn format_record_contains_target() {
        let line = format_record(&record());
        assert!(line.contains("\"target\":\"/etc/hosts\""));
    }

    #[test]
    fn format_record_contains_probe_family() {
        let line = format_record(&record());
        assert!(line.contains("\"probe_family\":\"config-parse\""));
    }

    #[test]
    fn format_record_null_layer_when_absent() {
        let line = format_record(&record());
        assert!(line.contains("\"layer\":null"));
    }

    #[test]
    fn format_record_layer_when_present() {
        let mut r = record();
        r.layer = Some(7);
        let line = format_record(&r);
        assert!(line.contains("\"layer\":7"));
    }

    #[test]
    fn format_record_contains_status() {
        let line = format_record(&record());
        assert!(line.contains("\"status\":\"pass\""));
    }

    #[test]
    fn format_record_contains_summary() {
        let line = format_record(&record());
        assert!(line.contains("\"summary\":\"Host file parsed OK.\""));
    }

    #[test]
    fn format_record_contains_kind() {
        let line = format_record(&record());
        assert!(line.contains("\"kind\":\"static\""));
    }

    #[test]
    fn format_record_empty_raw_refs() {
        let line = format_record(&record());
        assert!(line.contains("\"raw_refs\":[]"));
    }

    #[test]
    fn format_record_raw_refs_when_present() {
        let mut r = record();
        r.raw_refs = vec!["line 42".to_string()];
        let line = format_record(&r);
        assert!(line.contains("\"raw_refs\":[\"line 42\"]"));
    }

    #[test]
    fn format_record_null_interpretation_when_absent() {
        let line = format_record(&record());
        assert!(line.contains("\"interpretation\":null"));
    }

    #[test]
    fn format_record_interpretation_when_present() {
        let mut r = record();
        r.interpretation = Some("Looks healthy.".to_string());
        let line = format_record(&r);
        assert!(line.contains("\"interpretation\":\"Looks healthy.\""));
    }

    #[test]
    fn format_record_empty_metadata() {
        let line = format_record(&record());
        assert!(line.contains("\"metadata\":{}"));
    }

    #[test]
    fn format_record_metadata_when_present() {
        let mut r = record();
        r.metadata.insert("scope".to_string(), "repository".to_string());
        let line = format_record(&r);
        assert!(line.contains("\"scope\":\"repository\""));
    }

    #[test]
    fn format_record_is_single_line() {
        let line = format_record(&record());
        assert!(!line.contains('\n'));
    }

    #[test]
    fn format_record_starts_and_ends_with_braces() {
        let line = format_record(&record());
        assert!(line.starts_with('{'));
        assert!(line.ends_with('}'));
    }

    #[test]
    fn format_record_all_statuses() {
        for status in &[
            DiagnosticStatus::Blocked,
            DiagnosticStatus::Pass,
            DiagnosticStatus::Fail,
            DiagnosticStatus::Partial,
            DiagnosticStatus::NotTested,
        ] {
            let r = EvidenceRecord::new(
                "trace",
                "2026-03-20T00:00:00Z",
                "eth0",
                "interface-probe",
                status.clone(),
                "test",
                EvidenceKind::Runtime,
            );
            let line = format_record(&r);
            assert!(line.contains(&format!("\"status\":\"{}\"", status.as_str())));
        }
    }

    #[test]
    fn format_record_metadata_isolation() {
        let mut r1 = record();
        let r2 = record();
        r1.metadata.insert("k".to_string(), "v".to_string());
        let line2 = format_record(&r2);
        assert!(line2.contains("\"metadata\":{}"));
    }

    // --- append_record (file I/O) ---

    #[test]
    fn append_record_creates_file() {
        let dir = std::env::temp_dir();
        let path = dir.join("trio_artifact_test_create.jsonl");
        let _ = std::fs::remove_file(&path);

        append_record(&path, &record()).expect("append should succeed");

        assert!(path.exists());
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn append_record_writes_valid_content() {
        let dir = std::env::temp_dir();
        let path = dir.join("trio_artifact_test_content.jsonl");
        let _ = std::fs::remove_file(&path);

        append_record(&path, &record()).expect("append should succeed");

        let content = std::fs::read_to_string(&path).unwrap();
        assert!(content.contains("\"source_tool\":\"discover\""));
        assert!(content.ends_with('\n'));

        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn append_record_adds_to_existing_file() {
        let dir = std::env::temp_dir();
        let path = dir.join("trio_artifact_test_append.jsonl");
        let _ = std::fs::remove_file(&path);

        let mut r1 = record();
        r1.target = "host-a".to_string();
        let mut r2 = record();
        r2.target = "host-b".to_string();

        append_record(&path, &r1).expect("first append");
        append_record(&path, &r2).expect("second append");

        let content = std::fs::read_to_string(&path).unwrap();
        let lines: Vec<&str> = content.lines().collect();
        assert_eq!(lines.len(), 2);
        assert!(lines[0].contains("\"target\":\"host-a\""));
        assert!(lines[1].contains("\"target\":\"host-b\""));

        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn append_record_does_not_overwrite_existing_content() {
        let dir = std::env::temp_dir();
        let path = dir.join("trio_artifact_test_no_overwrite.jsonl");
        let _ = std::fs::remove_file(&path);

        std::fs::write(&path, "prior-line\n").unwrap();

        append_record(&path, &record()).expect("append should succeed");

        let content = std::fs::read_to_string(&path).unwrap();
        let lines: Vec<&str> = content.lines().collect();
        assert_eq!(lines[0], "prior-line");
        assert_eq!(lines.len(), 2);

        let _ = std::fs::remove_file(&path);
    }
}
