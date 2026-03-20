//! Language-layer boundary for Diagnostic Trio.
//!
//! This module documents and enforces the split between Rust (host execution)
//! and Python (reasoning) responsibilities, and defines the IPC message contract
//! used to communicate across the boundary.
//!
//! # Rust responsibilities
//!
//! | Role               | Description                                                  |
//! |--------------------|--------------------------------------------------------------|
//! | `Cli`              | Parse arguments, handle signals, manage exit codes           |
//! | `HostInteraction`  | Execute probes, read files, call system APIs, spawn processes|
//! | `Orchestration`    | Sequence Discover / Searcher / Trace, gate on safety policy  |
//! | `Normalization`    | Emit `EvidenceRecord` values in the shared schema            |
//! | `McpExposure`      | Expose Trio capabilities as MCP tools via stdio transport    |
//!
//! # Python responsibilities
//!
//! | Role                  | Description                                                |
//! |-----------------------|------------------------------------------------------------|
//! | `Reasoning`           | Interpret a set of evidence records holistically           |
//! | `Interpretation`      | Annotate individual records with narrative `interpretation`|
//! | `Synthesis`           | Produce a ranked list of hypotheses or root-cause theories |
//! | `NarrativeGeneration` | Write human-readable diagnostic summaries                  |
//!
//! # Interface
//!
//! Rust and Python exchange [`BridgeMessage`] values serialised as newline-
//! delimited JSON (JSONL) over `stdin` / `stdout`.  Rust writes
//! `EvidenceForReasoning` messages and reads `ReasoningResponse` messages;
//! Python does the reverse.
//!
//! Message flow:
//!
//! ```text
//! Rust                              Python
//!  |                                  |
//!  |  EvidenceForReasoning (JSONL) →  |
//!  |                                  |  (interprets records)
//!  |  ←  ReasoningResponse (JSONL)    |
//!  |                                  |
//!  |  Shutdown (JSONL) →              |
//!  |                                  |
//! ```

use std::collections::HashMap;

// ---------------------------------------------------------------------------
// Role enumerations
// ---------------------------------------------------------------------------

/// Responsibilities that belong to the Rust host-execution layer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RustRole {
    /// Parse CLI arguments, handle OS signals, manage exit codes.
    Cli,
    /// Execute probes against the host: read files, call system APIs, spawn
    /// short-lived processes.
    HostInteraction,
    /// Sequence the Discover, Searcher, and Trace capabilities, applying safety
    /// gating and workspace layout.
    Orchestration,
    /// Convert raw probe outputs into [`EvidenceRecord`](crate::evidence::EvidenceRecord)
    /// values using the shared schema.
    Normalization,
    /// Expose Trio capabilities as MCP tools via the stdio transport protocol.
    McpExposure,
}

impl RustRole {
    /// Returns the canonical label for this role.
    pub fn label(&self) -> &'static str {
        match self {
            RustRole::Cli => "cli",
            RustRole::HostInteraction => "host-interaction",
            RustRole::Orchestration => "orchestration",
            RustRole::Normalization => "normalization",
            RustRole::McpExposure => "mcp-exposure",
        }
    }
}

/// Responsibilities that belong to the Python reasoning layer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PythonRole {
    /// Interpret a set of evidence records as a coherent diagnostic picture.
    Reasoning,
    /// Annotate individual evidence records with a narrative `interpretation`
    /// field.
    Interpretation,
    /// Combine evidence across tools and layers into ranked hypotheses or
    /// root-cause theories.
    Synthesis,
    /// Produce human-readable diagnostic summaries suitable for an operator
    /// report.
    NarrativeGeneration,
}

impl PythonRole {
    /// Returns the canonical label for this role.
    pub fn label(&self) -> &'static str {
        match self {
            PythonRole::Reasoning => "reasoning",
            PythonRole::Interpretation => "interpretation",
            PythonRole::Synthesis => "synthesis",
            PythonRole::NarrativeGeneration => "narrative-generation",
        }
    }
}

// ---------------------------------------------------------------------------
// IPC message types
// ---------------------------------------------------------------------------

/// Discriminant for a [`BridgeMessage`] so the receiver can route it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BridgeMessageKind {
    /// Rust → Python: one or more serialised evidence records for reasoning.
    EvidenceForReasoning,
    /// Python → Rust: interpretation and synthesis results for the submitted
    /// evidence.
    ReasoningResponse,
    /// Rust → Python: signals that no more messages will be sent; Python should
    /// flush its output and terminate cleanly.
    Shutdown,
}

impl BridgeMessageKind {
    /// Returns the canonical string tag used in the JSONL `"kind"` field.
    pub fn as_str(&self) -> &'static str {
        match self {
            BridgeMessageKind::EvidenceForReasoning => "evidence-for-reasoning",
            BridgeMessageKind::ReasoningResponse => "reasoning-response",
            BridgeMessageKind::Shutdown => "shutdown",
        }
    }
}

/// A single IPC message crossing the Rust / Python boundary.
///
/// Messages are serialised to JSONL: one compact JSON object per line, with no
/// embedded newlines in the payload.  The `payload` field carries a JSON-encoded
/// body whose schema depends on `kind`.
#[derive(Debug, Clone)]
pub struct BridgeMessage {
    /// Identifies the message type so the receiver can deserialise `payload`.
    pub kind: BridgeMessageKind,
    /// JSON-encoded message body (compact, no embedded newlines).
    pub payload: String,
    /// Optional key-value metadata (run ID, session ID, …).
    pub metadata: HashMap<String, String>,
}

impl BridgeMessage {
    /// Construct a new message with empty metadata.
    pub fn new(kind: BridgeMessageKind, payload: impl Into<String>) -> Self {
        Self {
            kind,
            payload: payload.into(),
            metadata: HashMap::new(),
        }
    }
}

// ---------------------------------------------------------------------------
// Serialisation helpers
// ---------------------------------------------------------------------------

fn json_escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 2);
    for ch in s.chars() {
        match ch {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c => out.push(c),
        }
    }
    out
}

/// Serialise a [`BridgeMessage`] to a single compact JSONL line (no trailing
/// newline).
pub fn encode_message(msg: &BridgeMessage) -> String {
    let meta_pairs: Vec<String> = msg
        .metadata
        .iter()
        .map(|(k, v)| format!("\"{}\":\"{}\"", json_escape(k), json_escape(v)))
        .collect();
    let meta_str = format!("{{{}}}", meta_pairs.join(","));

    format!(
        "{{\"kind\":\"{}\",\"payload\":\"{}\",\"metadata\":{}}}",
        json_escape(msg.kind.as_str()),
        json_escape(&msg.payload),
        meta_str,
    )
}

/// Minimal JSONL decoder: extract `kind` and `payload` fields from a single
/// JSON line.  Returns `None` when the line cannot be parsed.
///
/// This is intentionally simple (no full JSON parser dependency); callers that
/// need full fidelity should deserialise with a proper JSON library.
pub fn decode_kind(line: &str) -> Option<String> {
    // Extract value of "kind":"..." using a simple scan.
    let key = "\"kind\":\"";
    let start = line.find(key)? + key.len();
    let end = line[start..].find('"')? + start;
    Some(line[start..end].to_owned())
}

/// Extract the `payload` string value from a JSONL bridge message line.
pub fn decode_payload(line: &str) -> Option<String> {
    let key = "\"payload\":\"";
    let start = line.find(key)? + key.len();
    let end = line[start..].find('"')? + start;
    Some(line[start..end].to_owned())
}

// ---------------------------------------------------------------------------
// ALL_RUST_ROLES / ALL_PYTHON_ROLES convenience slices
// ---------------------------------------------------------------------------

/// Every Rust role in definition order.
pub const ALL_RUST_ROLES: &[RustRole] = &[
    RustRole::Cli,
    RustRole::HostInteraction,
    RustRole::Orchestration,
    RustRole::Normalization,
    RustRole::McpExposure,
];

/// Every Python role in definition order.
pub const ALL_PYTHON_ROLES: &[PythonRole] = &[
    PythonRole::Reasoning,
    PythonRole::Interpretation,
    PythonRole::Synthesis,
    PythonRole::NarrativeGeneration,
];

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // --- RustRole ---

    #[test]
    fn rust_role_cli_label() {
        assert_eq!(RustRole::Cli.label(), "cli");
    }

    #[test]
    fn rust_role_host_interaction_label() {
        assert_eq!(RustRole::HostInteraction.label(), "host-interaction");
    }

    #[test]
    fn rust_role_orchestration_label() {
        assert_eq!(RustRole::Orchestration.label(), "orchestration");
    }

    #[test]
    fn rust_role_normalization_label() {
        assert_eq!(RustRole::Normalization.label(), "normalization");
    }

    #[test]
    fn rust_role_mcp_exposure_label() {
        assert_eq!(RustRole::McpExposure.label(), "mcp-exposure");
    }

    #[test]
    fn all_rust_roles_count() {
        assert_eq!(ALL_RUST_ROLES.len(), 5);
    }

    #[test]
    fn all_rust_roles_labels_unique() {
        let labels: Vec<&str> = ALL_RUST_ROLES.iter().map(|r| r.label()).collect();
        let mut dedup = labels.clone();
        dedup.sort_unstable();
        dedup.dedup();
        assert_eq!(labels.len(), dedup.len());
    }

    // --- PythonRole ---

    #[test]
    fn python_role_reasoning_label() {
        assert_eq!(PythonRole::Reasoning.label(), "reasoning");
    }

    #[test]
    fn python_role_interpretation_label() {
        assert_eq!(PythonRole::Interpretation.label(), "interpretation");
    }

    #[test]
    fn python_role_synthesis_label() {
        assert_eq!(PythonRole::Synthesis.label(), "synthesis");
    }

    #[test]
    fn python_role_narrative_generation_label() {
        assert_eq!(
            PythonRole::NarrativeGeneration.label(),
            "narrative-generation"
        );
    }

    #[test]
    fn all_python_roles_count() {
        assert_eq!(ALL_PYTHON_ROLES.len(), 4);
    }

    #[test]
    fn all_python_roles_labels_unique() {
        let labels: Vec<&str> = ALL_PYTHON_ROLES.iter().map(|r| r.label()).collect();
        let mut dedup = labels.clone();
        dedup.sort_unstable();
        dedup.dedup();
        assert_eq!(labels.len(), dedup.len());
    }

    // --- BridgeMessageKind ---

    #[test]
    fn kind_evidence_for_reasoning_str() {
        assert_eq!(
            BridgeMessageKind::EvidenceForReasoning.as_str(),
            "evidence-for-reasoning"
        );
    }

    #[test]
    fn kind_reasoning_response_str() {
        assert_eq!(
            BridgeMessageKind::ReasoningResponse.as_str(),
            "reasoning-response"
        );
    }

    #[test]
    fn kind_shutdown_str() {
        assert_eq!(BridgeMessageKind::Shutdown.as_str(), "shutdown");
    }

    // --- BridgeMessage ---

    #[test]
    fn bridge_message_new_empty_metadata() {
        let msg = BridgeMessage::new(BridgeMessageKind::Shutdown, "{}");
        assert_eq!(msg.kind, BridgeMessageKind::Shutdown);
        assert_eq!(msg.payload, "{}");
        assert!(msg.metadata.is_empty());
    }

    #[test]
    fn bridge_message_with_metadata() {
        let mut msg = BridgeMessage::new(BridgeMessageKind::EvidenceForReasoning, "[]");
        msg.metadata
            .insert("run_id".to_string(), "abc123".to_string());
        assert_eq!(
            msg.metadata.get("run_id").map(|s| s.as_str()),
            Some("abc123")
        );
    }

    // --- encode_message ---

    #[test]
    fn encode_shutdown_message() {
        let msg = BridgeMessage::new(BridgeMessageKind::Shutdown, "{}");
        let line = encode_message(&msg);
        assert!(line.contains("\"kind\":\"shutdown\""));
        assert!(line.contains("\"payload\":\"{}\""));
        assert!(!line.contains('\n'));
    }

    #[test]
    fn encode_escapes_quotes_in_payload() {
        let msg = BridgeMessage::new(BridgeMessageKind::ReasoningResponse, r#"{"ok":true}"#);
        let line = encode_message(&msg);
        // payload value should have inner quotes escaped
        assert!(line.contains("\\\"ok\\\""));
    }

    #[test]
    fn encode_produces_single_line() {
        let msg = BridgeMessage::new(BridgeMessageKind::EvidenceForReasoning, "data");
        let line = encode_message(&msg);
        assert_eq!(line.lines().count(), 1);
    }

    // --- decode_kind / decode_payload ---

    #[test]
    fn decode_kind_shutdown() {
        let line = r#"{"kind":"shutdown","payload":"{}","metadata":{}}"#;
        assert_eq!(decode_kind(line), Some("shutdown".to_string()));
    }

    #[test]
    fn decode_payload_simple() {
        let line = r#"{"kind":"shutdown","payload":"{}","metadata":{}}"#;
        assert_eq!(decode_payload(line), Some("{}".to_string()));
    }

    #[test]
    fn decode_kind_missing_returns_none() {
        assert_eq!(decode_kind("not json"), None);
    }

    #[test]
    fn decode_payload_missing_returns_none() {
        assert_eq!(decode_payload("not json"), None);
    }

    #[test]
    fn round_trip_kind_via_encode_decode() {
        let msg = BridgeMessage::new(BridgeMessageKind::EvidenceForReasoning, "test");
        let line = encode_message(&msg);
        assert_eq!(
            decode_kind(&line),
            Some("evidence-for-reasoning".to_string())
        );
    }
}
