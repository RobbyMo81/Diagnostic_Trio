//! Shared journal workflow for Diagnostic Trio.
//!
//! The journal captures materially important work from Discover, Searcher, and
//! Trace in a durable, append-only record.  Every entry is written as a single
//! JSON line (JSONL) so the file can be streamed, tailed, or grep-filtered
//! without parsing the whole document.
//!
//! # Journal format
//!
//! Each line is a self-contained JSON object:
//!
//! ```json
//! {"id":"<uuid>","timestamp":"<rfc3339>","tool":"<name>","event":"<kind>","summary":"<text>","evidence_ref":null,"metadata":{}}
//! ```
//!
//! | Field          | Type              | Description                                        |
//! |----------------|-------------------|----------------------------------------------------|
//! | `id`           | string            | Opaque unique entry identifier                     |
//! | `timestamp`    | RFC 3339 string   | When the event occurred                            |
//! | `tool`         | string            | Which Trio tool emitted this entry                 |
//! | `event`        | string            | Event kind (see [`JournalEventKind`])              |
//! | `summary`      | string            | Short human-readable description                   |
//! | `evidence_ref` | string \| null    | Optional link to a related [`EvidenceRecord`] id   |
//! | `metadata`     | object            | Arbitrary key-value pairs for event-specific data  |
//!
//! # Append-only behaviour
//!
//! [`append`] opens the journal file in append mode and writes exactly one
//! line.  Existing content is never modified.  The function is safe to call
//! from multiple processes writing to the same file on most POSIX systems
//! because `O_APPEND` writes are atomic for lines shorter than `PIPE_BUF`.
//!
//! # Linking to evidence
//!
//! Set [`JournalEntry::evidence_ref`] to the `id` of a related
//! [`EvidenceRecord`] to cross-reference the two.  Consumers can join journal
//! entries to evidence records by matching on this field.

use std::collections::HashMap;
use std::io::{self, Write as _};
use std::path::Path;

// ---------------------------------------------------------------------------
// JournalEventKind
// ---------------------------------------------------------------------------

/// Categories of events that Trio tools write into the journal.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum JournalEventKind {
    /// A Trio tool began executing against a target.
    ToolStarted,
    /// An [`crate::evidence::EvidenceRecord`] was emitted and is ready for review.
    FindingRecorded,
    /// A probe family finished running (pass, fail, or blocked).
    ProbeCompleted,
    /// A safety gate blocked a potentially mutating or sensitive operation.
    SafetyGated,
    /// The shared workspace state was updated by a tool.
    WorkspaceUpdated,
}

impl JournalEventKind {
    /// Returns the canonical lowercase string label for this event kind.
    ///
    /// These labels appear verbatim in the `"event"` field of each JSONL line.
    pub fn as_str(&self) -> &'static str {
        match self {
            JournalEventKind::ToolStarted => "tool-started",
            JournalEventKind::FindingRecorded => "finding-recorded",
            JournalEventKind::ProbeCompleted => "probe-completed",
            JournalEventKind::SafetyGated => "safety-gated",
            JournalEventKind::WorkspaceUpdated => "workspace-updated",
        }
    }
}

// ---------------------------------------------------------------------------
// JournalEntry
// ---------------------------------------------------------------------------

/// A single immutable journal record emitted by a Trio tool.
///
/// Build the entry with all required fields, then pass it to [`format_line`]
/// to serialise it for writing, or to [`append`] to persist it immediately.
#[derive(Debug, Clone)]
pub struct JournalEntry {
    /// Opaque unique identifier for this entry (e.g. a UUID or a counter).
    pub id: String,
    /// RFC 3339 timestamp of when the event occurred.
    pub timestamp: String,
    /// The Trio tool that emitted this entry (`"discover"`, `"searcher"`,
    /// `"trace"`, or a custom tool name).
    pub tool: String,
    /// What kind of event this entry describes.
    pub event_kind: JournalEventKind,
    /// Short human-readable description of the event.
    pub summary: String,
    /// Optional reference to the `id` of a related
    /// [`crate::evidence::EvidenceRecord`].
    pub evidence_ref: Option<String>,
    /// Arbitrary key-value pairs for event-specific data.
    pub metadata: HashMap<String, String>,
}

impl JournalEntry {
    /// Construct a minimal journal entry with no evidence reference or
    /// additional metadata.
    pub fn new(
        id: impl Into<String>,
        timestamp: impl Into<String>,
        tool: impl Into<String>,
        event_kind: JournalEventKind,
        summary: impl Into<String>,
    ) -> Self {
        Self {
            id: id.into(),
            timestamp: timestamp.into(),
            tool: tool.into(),
            event_kind,
            summary: summary.into(),
            evidence_ref: None,
            metadata: HashMap::new(),
        }
    }
}

// ---------------------------------------------------------------------------
// Serialisation helpers
// ---------------------------------------------------------------------------

/// Escape a string value for use inside a JSON string literal.
///
/// Handles backslash, double-quote, and the common ASCII control characters.
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

/// Serialise `entry` to a single JSONL line (no trailing newline).
///
/// The returned string is a valid JSON object suitable for appending to a
/// `.jsonl` journal file.
pub fn format_line(entry: &JournalEntry) -> String {
    let evidence_ref_json = match &entry.evidence_ref {
        Some(r) => format!("\"{}\"", json_escape(r)),
        None => "null".to_string(),
    };

    // Serialise metadata object
    let metadata_pairs: Vec<String> = {
        let mut pairs: Vec<(&String, &String)> = entry.metadata.iter().collect();
        pairs.sort_by_key(|(k, _)| k.as_str());
        pairs
            .iter()
            .map(|(k, v)| format!("\"{}\":\"{}\"", json_escape(k), json_escape(v)))
            .collect()
    };
    let metadata_json = format!("{{{}}}", metadata_pairs.join(","));

    format!(
        "{{\"id\":\"{id}\",\"timestamp\":\"{ts}\",\"tool\":\"{tool}\",\"event\":\"{event}\",\"summary\":\"{summary}\",\"evidence_ref\":{evref},\"metadata\":{meta}}}",
        id = json_escape(&entry.id),
        ts = json_escape(&entry.timestamp),
        tool = json_escape(&entry.tool),
        event = entry.event_kind.as_str(),
        summary = json_escape(&entry.summary),
        evref = evidence_ref_json,
        meta = metadata_json,
    )
}

// ---------------------------------------------------------------------------
// Append-only write
// ---------------------------------------------------------------------------

/// Append `entry` to the journal file at `path` as a single JSONL line.
///
/// The file is opened in append mode and created if it does not exist.  Each
/// call writes exactly one line followed by `\n`.  Existing content is never
/// modified.
///
/// # Errors
///
/// Returns an [`io::Error`] if the file cannot be opened or the write fails.
pub fn append(path: impl AsRef<Path>, entry: &JournalEntry) -> io::Result<()> {
    let mut file = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)?;
    let line = format_line(entry);
    writeln!(file, "{}", line)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn entry(event_kind: JournalEventKind) -> JournalEntry {
        JournalEntry::new(
            "entry-001",
            "2026-03-19T22:00:00Z",
            "discover",
            event_kind,
            "Test event.",
        )
    }

    // --- JournalEventKind ---

    #[test]
    fn event_kind_tool_started() {
        assert_eq!(JournalEventKind::ToolStarted.as_str(), "tool-started");
    }

    #[test]
    fn event_kind_finding_recorded() {
        assert_eq!(
            JournalEventKind::FindingRecorded.as_str(),
            "finding-recorded"
        );
    }

    #[test]
    fn event_kind_probe_completed() {
        assert_eq!(JournalEventKind::ProbeCompleted.as_str(), "probe-completed");
    }

    #[test]
    fn event_kind_safety_gated() {
        assert_eq!(JournalEventKind::SafetyGated.as_str(), "safety-gated");
    }

    #[test]
    fn event_kind_workspace_updated() {
        assert_eq!(
            JournalEventKind::WorkspaceUpdated.as_str(),
            "workspace-updated"
        );
    }

    // --- JournalEntry construction ---

    #[test]
    fn entry_new_sets_required_fields() {
        let e = entry(JournalEventKind::ToolStarted);
        assert_eq!(e.id, "entry-001");
        assert_eq!(e.timestamp, "2026-03-19T22:00:00Z");
        assert_eq!(e.tool, "discover");
        assert_eq!(e.event_kind, JournalEventKind::ToolStarted);
        assert_eq!(e.summary, "Test event.");
    }

    #[test]
    fn entry_new_has_no_evidence_ref() {
        let e = entry(JournalEventKind::FindingRecorded);
        assert!(e.evidence_ref.is_none());
    }

    #[test]
    fn entry_new_has_empty_metadata() {
        let e = entry(JournalEventKind::FindingRecorded);
        assert!(e.metadata.is_empty());
    }

    // --- format_line ---

    #[test]
    fn format_line_contains_id() {
        let line = format_line(&entry(JournalEventKind::ToolStarted));
        assert!(line.contains("\"id\":\"entry-001\""));
    }

    #[test]
    fn format_line_contains_timestamp() {
        let line = format_line(&entry(JournalEventKind::ToolStarted));
        assert!(line.contains("\"timestamp\":\"2026-03-19T22:00:00Z\""));
    }

    #[test]
    fn format_line_contains_tool() {
        let line = format_line(&entry(JournalEventKind::ToolStarted));
        assert!(line.contains("\"tool\":\"discover\""));
    }

    #[test]
    fn format_line_contains_event() {
        let line = format_line(&entry(JournalEventKind::FindingRecorded));
        assert!(line.contains("\"event\":\"finding-recorded\""));
    }

    #[test]
    fn format_line_contains_summary() {
        let line = format_line(&entry(JournalEventKind::ToolStarted));
        assert!(line.contains("\"summary\":\"Test event.\""));
    }

    #[test]
    fn format_line_null_evidence_ref_when_absent() {
        let line = format_line(&entry(JournalEventKind::ToolStarted));
        assert!(line.contains("\"evidence_ref\":null"));
    }

    #[test]
    fn format_line_evidence_ref_when_present() {
        let mut e = entry(JournalEventKind::FindingRecorded);
        e.evidence_ref = Some("rec-42".to_string());
        let line = format_line(&e);
        assert!(line.contains("\"evidence_ref\":\"rec-42\""));
    }

    #[test]
    fn format_line_empty_metadata_object() {
        let line = format_line(&entry(JournalEventKind::ToolStarted));
        assert!(line.contains("\"metadata\":{}"));
    }

    #[test]
    fn format_line_metadata_key_value_present() {
        let mut e = entry(JournalEventKind::ProbeCompleted);
        e.metadata
            .insert("probe".to_string(), "config-parse".to_string());
        let line = format_line(&e);
        assert!(line.contains("\"probe\":\"config-parse\""));
    }

    #[test]
    fn format_line_is_single_line() {
        let line = format_line(&entry(JournalEventKind::ToolStarted));
        assert!(!line.contains('\n'));
    }

    #[test]
    fn format_line_starts_and_ends_with_braces() {
        let line = format_line(&entry(JournalEventKind::ToolStarted));
        assert!(line.starts_with('{'));
        assert!(line.ends_with('}'));
    }

    #[test]
    fn format_line_escapes_double_quotes_in_summary() {
        let mut e = entry(JournalEventKind::FindingRecorded);
        e.summary = r#"Found "key": value"#.to_string();
        let line = format_line(&e);
        assert!(line.contains(r#"\"key\""#));
    }

    #[test]
    fn format_line_escapes_backslash_in_summary() {
        let mut e = entry(JournalEventKind::FindingRecorded);
        e.summary = r"path\to\file".to_string();
        let line = format_line(&e);
        assert!(line.contains(r"path\\to\\file"));
    }

    // --- append (file I/O) ---

    #[test]
    fn append_creates_file_and_writes_line() {
        let dir = std::env::temp_dir();
        let path = dir.join("trio_journal_test_create.jsonl");
        let _ = std::fs::remove_file(&path);

        let e = entry(JournalEventKind::ToolStarted);
        append(&path, &e).expect("append should succeed");

        let content = std::fs::read_to_string(&path).unwrap();
        assert!(content.contains("\"id\":\"entry-001\""));
        assert!(content.ends_with('\n'));

        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn append_adds_to_existing_file() {
        let dir = std::env::temp_dir();
        let path = dir.join("trio_journal_test_append.jsonl");
        let _ = std::fs::remove_file(&path);

        let mut e1 = entry(JournalEventKind::ToolStarted);
        e1.id = "entry-001".to_string();
        let mut e2 = entry(JournalEventKind::FindingRecorded);
        e2.id = "entry-002".to_string();

        append(&path, &e1).expect("first append");
        append(&path, &e2).expect("second append");

        let content = std::fs::read_to_string(&path).unwrap();
        let lines: Vec<&str> = content.lines().collect();
        assert_eq!(lines.len(), 2);
        assert!(lines[0].contains("\"id\":\"entry-001\""));
        assert!(lines[1].contains("\"id\":\"entry-002\""));

        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn append_does_not_overwrite_existing_content() {
        let dir = std::env::temp_dir();
        let path = dir.join("trio_journal_test_no_overwrite.jsonl");
        let _ = std::fs::remove_file(&path);

        // Write a marker line manually
        std::fs::write(&path, "existing-line\n").unwrap();

        let e = entry(JournalEventKind::WorkspaceUpdated);
        append(&path, &e).expect("append should succeed");

        let content = std::fs::read_to_string(&path).unwrap();
        let lines: Vec<&str> = content.lines().collect();
        assert_eq!(lines[0], "existing-line");
        assert_eq!(lines.len(), 2);

        let _ = std::fs::remove_file(&path);
    }

    // --- all tools ---

    #[test]
    fn all_trio_tools_can_emit_entries() {
        for tool in &["discover", "searcher", "trace"] {
            let e = JournalEntry::new(
                "x",
                "2026-03-19T22:00:00Z",
                *tool,
                JournalEventKind::ToolStarted,
                "started",
            );
            let line = format_line(&e);
            assert!(line.contains(&format!("\"tool\":\"{tool}\"")));
        }
    }
}
