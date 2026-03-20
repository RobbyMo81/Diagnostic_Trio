//! Family architecture documentation for Diagnostic Trio.
//!
//! Provides structured constants describing the three operating flows,
//! companion capability roles, and extension points so they are accessible
//! to other Trio components and verifiable by tests.

/// The three operating flows for the Trio tool family.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OperatingFlow {
    InitialSetup,
    LayeredDiagnosis,
    MaintenanceDrift,
}

impl OperatingFlow {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::InitialSetup => "initial-setup",
            Self::LayeredDiagnosis => "layered-diagnosis",
            Self::MaintenanceDrift => "maintenance-drift",
        }
    }

    pub fn label(&self) -> &'static str {
        match self {
            Self::InitialSetup => "Initial Setup",
            Self::LayeredDiagnosis => "Layered Diagnosis",
            Self::MaintenanceDrift => "Maintenance / Drift Detection",
        }
    }

    pub fn steps(&self) -> &'static [&'static str] {
        match self {
            Self::InitialSetup => &[
                "Initialise a fresh workspace (WorkspaceLayout::new).",
                "Populate SharedState with target, search roots, and tool-specific scopes.",
                "Run Discover across repository and host to collect static baseline.",
                "Run Searcher for known entry-point and configuration patterns.",
                "Append significant findings to the shared journal.",
                "Write durable artifacts (discover-findings.jsonl, searcher-findings.jsonl).",
            ],
            Self::LayeredDiagnosis => &[
                "Load existing artifacts and journal from the workspace (if present).",
                "Run Trace to collect live runtime evidence.",
                "Apply the lower-layer blocking rule across all collected findings.",
                "Group evidence by layer and status to identify the lowest failing surface.",
                "Correlate static and runtime findings at the same layer.",
                "Append the diagnosis session to the journal with evidence_ref links.",
            ],
            Self::MaintenanceDrift => &[
                "Load a previous run's artifacts as the baseline.",
                "Run Discover and Searcher against the current state.",
                "Compare current findings against baseline by target, probe family, and layer.",
                "Flag any finding whose status regressed or whose summary changed.",
                "Emit a MaintenanceDrift journal entry for each detected regression.",
                "Write updated artifacts to preserve the new state.",
            ],
        }
    }
}

pub const ALL_FLOWS: &[OperatingFlow] = &[
    OperatingFlow::InitialSetup,
    OperatingFlow::LayeredDiagnosis,
    OperatingFlow::MaintenanceDrift,
];

/// The three companion capabilities of Diagnostic Trio.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CapabilityRole {
    Discover,
    Searcher,
    Trace,
}

impl CapabilityRole {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Discover => "discover",
            Self::Searcher => "searcher",
            Self::Trace => "trace",
        }
    }

    pub fn label(&self) -> &'static str {
        match self {
            Self::Discover => "Discover",
            Self::Searcher => "Searcher",
            Self::Trace => "Trace",
        }
    }

    pub fn source_domain(&self) -> &'static str {
        match self {
            Self::Discover => "Repository and host filesystem",
            Self::Searcher => "File trees, source code, structured text, logs",
            Self::Trace => "Live host runtime",
        }
    }

    pub fn evidence_kind(&self) -> &'static str {
        match self {
            Self::Discover => "Static",
            Self::Searcher => "Static",
            Self::Trace => "Runtime",
        }
    }

    pub fn description(&self) -> &'static str {
        match self {
            Self::Discover => {
                "Classifies configuration, process, network, dependency, log, \
                 and certificate evidence into OSI-layer-tagged findings."
            }
            Self::Searcher => {
                "Searches across 13 configurable backends by intent; normalizes \
                 results into the shared evidence schema."
            }
            Self::Trace => {
                "Interrogates running processes, listeners, routes, sessions, logs, \
                 payload behavior, runtime dependencies, and transport anomalies."
            }
        }
    }
}

pub const ALL_CAPABILITIES: &[CapabilityRole] = &[
    CapabilityRole::Discover,
    CapabilityRole::Searcher,
    CapabilityRole::Trace,
];

/// Documented extension points that do not require changing the core evidence model.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExtensionPoint {
    NewProbeFamily,
    NewSearchBackend,
    NewTraceTarget,
    McpExposure,
}

impl ExtensionPoint {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::NewProbeFamily => "new-probe-family",
            Self::NewSearchBackend => "new-search-backend",
            Self::NewTraceTarget => "new-trace-target",
            Self::McpExposure => "mcp-exposure",
        }
    }

    pub fn label(&self) -> &'static str {
        match self {
            Self::NewProbeFamily => "New Probe Family (Discover)",
            Self::NewSearchBackend => "New Search Backend (Searcher)",
            Self::NewTraceTarget => "New Trace Target (Trace)",
            Self::McpExposure => "MCP Exposure (trio-host)",
        }
    }

    /// Returns true if this extension point requires modifying EvidenceRecord.
    /// All Trio extension points are designed to avoid schema changes.
    pub fn schema_change_required(&self) -> bool {
        false
    }
}

pub const ALL_EXTENSION_POINTS: &[ExtensionPoint] = &[
    ExtensionPoint::NewProbeFamily,
    ExtensionPoint::NewSearchBackend,
    ExtensionPoint::NewTraceTarget,
    ExtensionPoint::McpExposure,
];

/// A named design principle for the Trio family.
pub struct DesignPrinciple {
    pub name: &'static str,
    pub description: &'static str,
}

pub const DESIGN_PRINCIPLES: &[DesignPrinciple] = &[
    DesignPrinciple {
        name: "Schema stability first",
        description: "EvidenceRecord is the stable contract. All extension happens by adding \
                       variants to enums, not by changing the record itself.",
    },
    DesignPrinciple {
        name: "Read-only by default",
        description: "Runtime inspection requires explicit Authorized safety level; \
                       all static inspection is ReadOnly.",
    },
    DesignPrinciple {
        name: "Append-only audit",
        description: "The journal is never rewritten; artifacts accumulate evidence across runs.",
    },
    DesignPrinciple {
        name: "Language boundary is firm",
        description: "Rust handles execution, I/O, and MCP; Python handles reasoning and narrative. \
                       The boundary is the JSONL bridge message stream.",
    },
    DesignPrinciple {
        name: "No Quartet dependency",
        description: "Trio reads from and writes to its own workspace layout without importing \
                       or calling any Quartet component.",
    },
];

#[cfg(test)]
mod tests {
    use super::*;

    // --- OperatingFlow ---

    #[test]
    fn all_flows_count() {
        assert_eq!(ALL_FLOWS.len(), 3);
    }

    #[test]
    fn flow_as_str_unique() {
        let strs: Vec<_> = ALL_FLOWS.iter().map(|f| f.as_str()).collect();
        let mut deduped = strs.clone();
        deduped.sort_unstable();
        deduped.dedup();
        assert_eq!(strs.len(), deduped.len());
    }

    #[test]
    fn initial_setup_as_str() {
        assert_eq!(OperatingFlow::InitialSetup.as_str(), "initial-setup");
    }

    #[test]
    fn layered_diagnosis_as_str() {
        assert_eq!(OperatingFlow::LayeredDiagnosis.as_str(), "layered-diagnosis");
    }

    #[test]
    fn maintenance_drift_as_str() {
        assert_eq!(OperatingFlow::MaintenanceDrift.as_str(), "maintenance-drift");
    }

    #[test]
    fn flow_labels_non_empty() {
        for flow in ALL_FLOWS {
            assert!(!flow.label().is_empty());
        }
    }

    #[test]
    fn initial_setup_has_six_steps() {
        assert_eq!(OperatingFlow::InitialSetup.steps().len(), 6);
    }

    #[test]
    fn layered_diagnosis_has_six_steps() {
        assert_eq!(OperatingFlow::LayeredDiagnosis.steps().len(), 6);
    }

    #[test]
    fn maintenance_drift_has_six_steps() {
        assert_eq!(OperatingFlow::MaintenanceDrift.steps().len(), 6);
    }

    #[test]
    fn all_flow_steps_non_empty() {
        for flow in ALL_FLOWS {
            for step in flow.steps() {
                assert!(!step.is_empty());
            }
        }
    }

    // --- CapabilityRole ---

    #[test]
    fn all_capabilities_count() {
        assert_eq!(ALL_CAPABILITIES.len(), 3);
    }

    #[test]
    fn capability_as_str_unique() {
        let strs: Vec<_> = ALL_CAPABILITIES.iter().map(|c| c.as_str()).collect();
        let mut deduped = strs.clone();
        deduped.sort_unstable();
        deduped.dedup();
        assert_eq!(strs.len(), deduped.len());
    }

    #[test]
    fn discover_as_str() {
        assert_eq!(CapabilityRole::Discover.as_str(), "discover");
    }

    #[test]
    fn searcher_as_str() {
        assert_eq!(CapabilityRole::Searcher.as_str(), "searcher");
    }

    #[test]
    fn trace_as_str() {
        assert_eq!(CapabilityRole::Trace.as_str(), "trace");
    }

    #[test]
    fn discover_and_searcher_emit_static() {
        assert_eq!(CapabilityRole::Discover.evidence_kind(), "Static");
        assert_eq!(CapabilityRole::Searcher.evidence_kind(), "Static");
    }

    #[test]
    fn trace_emits_runtime() {
        assert_eq!(CapabilityRole::Trace.evidence_kind(), "Runtime");
    }

    #[test]
    fn capability_source_domains_non_empty() {
        for cap in ALL_CAPABILITIES {
            assert!(!cap.source_domain().is_empty());
        }
    }

    #[test]
    fn capability_descriptions_non_empty() {
        for cap in ALL_CAPABILITIES {
            assert!(!cap.description().is_empty());
        }
    }

    // --- ExtensionPoint ---

    #[test]
    fn all_extension_points_count() {
        assert_eq!(ALL_EXTENSION_POINTS.len(), 4);
    }

    #[test]
    fn extension_point_as_str_unique() {
        let strs: Vec<_> = ALL_EXTENSION_POINTS.iter().map(|e| e.as_str()).collect();
        let mut deduped = strs.clone();
        deduped.sort_unstable();
        deduped.dedup();
        assert_eq!(strs.len(), deduped.len());
    }

    #[test]
    fn no_extension_point_requires_schema_change() {
        for ep in ALL_EXTENSION_POINTS {
            assert!(!ep.schema_change_required());
        }
    }

    #[test]
    fn new_probe_family_as_str() {
        assert_eq!(ExtensionPoint::NewProbeFamily.as_str(), "new-probe-family");
    }

    #[test]
    fn mcp_exposure_as_str() {
        assert_eq!(ExtensionPoint::McpExposure.as_str(), "mcp-exposure");
    }

    #[test]
    fn extension_point_labels_non_empty() {
        for ep in ALL_EXTENSION_POINTS {
            assert!(!ep.label().is_empty());
        }
    }

    // --- DesignPrinciples ---

    #[test]
    fn design_principles_count() {
        assert_eq!(DESIGN_PRINCIPLES.len(), 5);
    }

    #[test]
    fn design_principles_names_non_empty() {
        for p in DESIGN_PRINCIPLES {
            assert!(!p.name.is_empty());
        }
    }

    #[test]
    fn design_principles_descriptions_non_empty() {
        for p in DESIGN_PRINCIPLES {
            assert!(!p.description.is_empty());
        }
    }
}
