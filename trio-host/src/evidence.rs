//! Shared evidence schema for Diagnostic Trio.
//!
//! All three Trio capabilities — Discover, Searcher, and Trace — emit findings
//! as [`EvidenceRecord`] values so downstream consumers can interpret results
//! uniformly regardless of which tool produced them.
//!
//! # Status values
//!
//! | Variant       | Meaning                                                       |
//! |---------------|---------------------------------------------------------------|
//! | `Blocked`     | The probe could not run (permission denied, tool absent, …)  |
//! | `Pass`        | The probe ran and the finding is healthy / expected           |
//! | `Fail`        | The probe ran and the finding indicates a problem             |
//! | `Partial`     | The probe ran but only part of the target was reachable       |
//! | `NotTested`   | The probe was skipped or not applicable to this target        |
//!
//! # Static vs runtime evidence
//!
//! The [`EvidenceKind`] field distinguishes the two modes:
//!
//! * [`EvidenceKind::Static`] — derived from repository or filesystem
//!   artifacts: source code, config files, manifests, lock files.  No live
//!   process interaction occurs.
//! * [`EvidenceKind::Runtime`] — captured from a running system: process
//!   tables, open ports, kernel routes, active sessions, live logs, or
//!   protocol payloads.  Requires host access and must be gated by safety
//!   checks.

use std::collections::HashMap;

/// Diagnostic status reported by a single probe.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DiagnosticStatus {
    /// The probe could not execute (missing tool, permission denied, …).
    Blocked,
    /// The probe ran and the target is healthy / as expected.
    Pass,
    /// The probe ran and identified a problem.
    Fail,
    /// The probe ran but could only reach part of the target.
    Partial,
    /// The probe was skipped or is not applicable.
    NotTested,
}

impl DiagnosticStatus {
    /// Returns the canonical lowercase string representation.
    pub fn as_str(&self) -> &'static str {
        match self {
            DiagnosticStatus::Blocked => "blocked",
            DiagnosticStatus::Pass => "pass",
            DiagnosticStatus::Fail => "fail",
            DiagnosticStatus::Partial => "partial",
            DiagnosticStatus::NotTested => "not-tested",
        }
    }
}

/// Whether the evidence came from static analysis or live runtime inspection.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EvidenceKind {
    /// Derived from repository or filesystem artifacts; no live processes.
    Static,
    /// Captured from a running system; requires host access and safety gating.
    Runtime,
}

impl EvidenceKind {
    /// Returns the canonical lowercase string representation.
    pub fn as_str(&self) -> &'static str {
        match self {
            EvidenceKind::Static => "static",
            EvidenceKind::Runtime => "runtime",
        }
    }
}

/// A single normalised finding emitted by any Trio capability.
///
/// All fields that may be absent are represented as [`Option`].  Consumers
/// MUST tolerate absent optional fields.
#[derive(Debug, Clone)]
pub struct EvidenceRecord {
    /// The Trio tool that produced this record (`"discover"`, `"searcher"`,
    /// `"trace"`, or a custom probe name).
    pub source_tool: String,

    /// RFC 3339 / ISO 8601 timestamp of when the probe ran, e.g.
    /// `"2026-03-19T22:00:00Z"`.
    pub timestamp: String,

    /// The entity being examined: a hostname, file path, service name,
    /// interface, or other identifier meaningful to the probe.
    pub target: String,

    /// High-level category of probe, e.g. `"port-scan"`, `"config-parse"`,
    /// `"dependency-trace"`.
    pub probe_family: String,

    /// OSI layer (1 = Physical … 7 = Application), or `None` when the finding
    /// is not layer-specific.
    pub layer: Option<u8>,

    /// Outcome of the probe.
    pub status: DiagnosticStatus,

    /// Short human-readable summary of the finding.
    pub summary: String,

    /// Whether the evidence was collected statically or from a live runtime.
    pub kind: EvidenceKind,

    /// Raw excerpts, file references, command output snippets, or other
    /// unprocessed material that supports the summary.
    pub raw_refs: Vec<String>,

    /// Confidence in the finding, in the range `[0.0, 1.0]`.
    pub confidence: f32,

    /// Narrative interpretation produced by the reasoning layer; may be
    /// empty when the record is first emitted by the host.
    pub interpretation: Option<String>,

    /// Arbitrary key-value metadata for probe-specific details.
    pub metadata: HashMap<String, String>,
}

impl EvidenceRecord {
    /// Construct a minimal record with required fields and sensible defaults.
    pub fn new(
        source_tool: impl Into<String>,
        timestamp: impl Into<String>,
        target: impl Into<String>,
        probe_family: impl Into<String>,
        status: DiagnosticStatus,
        summary: impl Into<String>,
        kind: EvidenceKind,
    ) -> Self {
        Self {
            source_tool: source_tool.into(),
            timestamp: timestamp.into(),
            target: target.into(),
            probe_family: probe_family.into(),
            layer: None,
            status,
            summary: summary.into(),
            kind,
            raw_refs: Vec::new(),
            confidence: 1.0,
            interpretation: None,
            metadata: HashMap::new(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn status_as_str_round_trips() {
        assert_eq!(DiagnosticStatus::Blocked.as_str(), "blocked");
        assert_eq!(DiagnosticStatus::Pass.as_str(), "pass");
        assert_eq!(DiagnosticStatus::Fail.as_str(), "fail");
        assert_eq!(DiagnosticStatus::Partial.as_str(), "partial");
        assert_eq!(DiagnosticStatus::NotTested.as_str(), "not-tested");
    }

    #[test]
    fn evidence_kind_as_str() {
        assert_eq!(EvidenceKind::Static.as_str(), "static");
        assert_eq!(EvidenceKind::Runtime.as_str(), "runtime");
    }

    #[test]
    fn evidence_record_new_sets_defaults() {
        let rec = EvidenceRecord::new(
            "discover",
            "2026-03-19T22:00:00Z",
            "/etc/hosts",
            "config-parse",
            DiagnosticStatus::Pass,
            "Host file parsed successfully.",
            EvidenceKind::Static,
        );
        assert_eq!(rec.source_tool, "discover");
        assert_eq!(rec.status, DiagnosticStatus::Pass);
        assert_eq!(rec.kind, EvidenceKind::Static);
        assert!(rec.layer.is_none());
        assert!(rec.raw_refs.is_empty());
        assert!((rec.confidence - 1.0).abs() < f32::EPSILON);
        assert!(rec.interpretation.is_none());
    }

    #[test]
    fn evidence_record_with_layer() {
        let mut rec = EvidenceRecord::new(
            "trace",
            "2026-03-19T22:01:00Z",
            "eth0",
            "interface-probe",
            DiagnosticStatus::Fail,
            "Interface has no carrier.",
            EvidenceKind::Runtime,
        );
        rec.layer = Some(1); // Physical layer
        assert_eq!(rec.layer, Some(1));
    }
}
