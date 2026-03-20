"""Family architecture documentation for Diagnostic Trio.

Provides structured constants describing the three operating flows,
companion capability roles, and extension points so they are accessible
to other Trio components and verifiable by tests.
"""

from __future__ import annotations

import enum
from dataclasses import dataclass, field


class OperatingFlow(str, enum.Enum):
    """The three operating flows for the Trio tool family."""

    InitialSetup = "initial-setup"
    LayeredDiagnosis = "layered-diagnosis"
    MaintenanceDrift = "maintenance-drift"

    def label(self) -> str:
        labels = {
            OperatingFlow.InitialSetup: "Initial Setup",
            OperatingFlow.LayeredDiagnosis: "Layered Diagnosis",
            OperatingFlow.MaintenanceDrift: "Maintenance / Drift Detection",
        }
        return labels[self]

    def steps(self) -> list[str]:
        """Return the ordered steps for this operating flow."""
        return _FLOW_STEPS[self]


_FLOW_STEPS: dict[OperatingFlow, list[str]] = {
    OperatingFlow.InitialSetup: [
        "Initialise a fresh workspace (WorkspaceLayout.from_root).",
        "Populate SharedState with target, search roots, and tool-specific scopes.",
        "Run Discover across repository and host to collect static baseline.",
        "Run Searcher for known entry-point and configuration patterns.",
        "Append significant findings to the shared journal.",
        "Write durable artifacts (discover-findings.jsonl, searcher-findings.jsonl).",
    ],
    OperatingFlow.LayeredDiagnosis: [
        "Load existing artifacts and journal from the workspace (if present).",
        "Run Trace to collect live runtime evidence.",
        "Apply the lower-layer blocking rule across all collected findings.",
        "Group evidence by layer and status to identify the lowest failing surface.",
        "Correlate static and runtime findings at the same layer.",
        "Append the diagnosis session to the journal with evidence_ref links.",
    ],
    OperatingFlow.MaintenanceDrift: [
        "Load a previous run's artifacts as the baseline.",
        "Run Discover and Searcher against the current state.",
        "Compare current findings against baseline by target, probe family, and layer.",
        "Flag any finding whose status regressed or whose summary changed.",
        "Emit a MaintenanceDrift journal entry for each detected regression.",
        "Write updated artifacts to preserve the new state.",
    ],
}

ALL_FLOWS: list[OperatingFlow] = list(OperatingFlow)


class CapabilityRole(str, enum.Enum):
    """The three companion capabilities of Diagnostic Trio."""

    Discover = "discover"
    Searcher = "searcher"
    Trace = "trace"

    def label(self) -> str:
        labels = {
            CapabilityRole.Discover: "Discover",
            CapabilityRole.Searcher: "Searcher",
            CapabilityRole.Trace: "Trace",
        }
        return labels[self]

    def source_domain(self) -> str:
        domains = {
            CapabilityRole.Discover: "Repository and host filesystem",
            CapabilityRole.Searcher: "File trees, source code, structured text, logs",
            CapabilityRole.Trace: "Live host runtime",
        }
        return domains[self]

    def evidence_kind(self) -> str:
        kinds = {
            CapabilityRole.Discover: "Static",
            CapabilityRole.Searcher: "Static",
            CapabilityRole.Trace: "Runtime",
        }
        return kinds[self]

    def description(self) -> str:
        descriptions = {
            CapabilityRole.Discover: (
                "Classifies configuration, process, network, dependency, log, "
                "and certificate evidence into OSI-layer-tagged findings."
            ),
            CapabilityRole.Searcher: (
                "Searches across 13 configurable backends by intent; normalizes "
                "results into the shared evidence schema."
            ),
            CapabilityRole.Trace: (
                "Interrogates running processes, listeners, routes, sessions, logs, "
                "payload behavior, runtime dependencies, and transport anomalies."
            ),
        }
        return descriptions[self]


ALL_CAPABILITIES: list[CapabilityRole] = list(CapabilityRole)


class ExtensionPoint(str, enum.Enum):
    """Documented extension points that do not require changing the core evidence model."""

    NewProbeFamily = "new-probe-family"
    NewSearchBackend = "new-search-backend"
    NewTraceTarget = "new-trace-target"
    McpExposure = "mcp-exposure"

    def label(self) -> str:
        labels = {
            ExtensionPoint.NewProbeFamily: "New Probe Family (Discover)",
            ExtensionPoint.NewSearchBackend: "New Search Backend (Searcher)",
            ExtensionPoint.NewTraceTarget: "New Trace Target (Trace)",
            ExtensionPoint.McpExposure: "MCP Exposure (trio-host)",
        }
        return labels[self]

    def schema_change_required(self) -> bool:
        """Return True if this extension point requires modifying EvidenceRecord."""
        # All Trio extension points are designed to avoid schema changes.
        return False

    def description(self) -> str:
        descriptions = {
            ExtensionPoint.NewProbeFamily: (
                "Add a DiscoverProbeFamily variant; implement default_layer and as_str. "
                "classify() already produces a generic EvidenceRecord — no schema change needed."
            ),
            ExtensionPoint.NewSearchBackend: (
                "Add a SearchBackend entry to CATALOG. "
                "backends_with_capability and select_backend automatically include it."
            ),
            ExtensionPoint.NewTraceTarget: (
                "Add a TraceTarget variant; implement default_layer and required_safety_level. "
                "capture() already produces a generic EvidenceRecord — no schema change needed."
            ),
            ExtensionPoint.McpExposure: (
                "Add a handler in trio-host that calls classify/normalize/capture "
                "and serialises the EvidenceRecord via format_record. "
                "trio-reason is not involved in MCP serialisation."
            ),
        }
        return descriptions[self]


ALL_EXTENSION_POINTS: list[ExtensionPoint] = list(ExtensionPoint)


@dataclass(frozen=True)
class DesignPrinciple:
    """A named design principle for the Trio family."""

    name: str
    description: str


DESIGN_PRINCIPLES: list[DesignPrinciple] = [
    DesignPrinciple(
        name="Schema stability first",
        description=(
            "EvidenceRecord is the stable contract. All extension happens by adding "
            "variants to enums, not by changing the record itself."
        ),
    ),
    DesignPrinciple(
        name="Read-only by default",
        description=(
            "Runtime inspection requires explicit Authorized safety level; "
            "all static inspection is ReadOnly."
        ),
    ),
    DesignPrinciple(
        name="Append-only audit",
        description=(
            "The journal is never rewritten; artifacts accumulate evidence across runs."
        ),
    ),
    DesignPrinciple(
        name="Language boundary is firm",
        description=(
            "Rust handles execution, I/O, and MCP; Python handles reasoning and narrative. "
            "The boundary is the JSONL bridge message stream."
        ),
    ),
    DesignPrinciple(
        name="No Quartet dependency",
        description=(
            "Trio reads from and writes to its own workspace layout without importing "
            "or calling any Quartet component."
        ),
    ),
]
