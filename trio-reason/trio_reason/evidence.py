"""Shared evidence schema for Diagnostic Trio.

All three Trio capabilities — Discover, Searcher, and Trace — emit findings as
:class:`EvidenceRecord` instances so the reasoning layer can interpret results
uniformly regardless of which tool produced them.

Status values
-------------
``blocked``
    The probe could not run (permission denied, tool absent, …).
``pass``
    The probe ran and the finding is healthy / expected.
``fail``
    The probe ran and the finding indicates a problem.
``partial``
    The probe ran but only part of the target was reachable.
``not-tested``
    The probe was skipped or is not applicable to this target.

Static vs runtime evidence
--------------------------
:attr:`EvidenceKind.STATIC`
    Derived from repository or filesystem artifacts: source code, config
    files, manifests, lock files.  No live process interaction occurs.
:attr:`EvidenceKind.RUNTIME`
    Captured from a running system: process tables, open ports, kernel
    routes, active sessions, live logs, or protocol payloads.  Requires
    host access and must be gated by safety checks before use.
"""

from __future__ import annotations

import enum
from dataclasses import dataclass, field
from typing import Optional


class DiagnosticStatus(str, enum.Enum):
    """Outcome of a single diagnostic probe."""

    BLOCKED = "blocked"
    """The probe could not execute (missing tool, permission denied, …)."""

    PASS = "pass"
    """The probe ran and the target is healthy / as expected."""

    FAIL = "fail"
    """The probe ran and identified a problem."""

    PARTIAL = "partial"
    """The probe ran but could only reach part of the target."""

    NOT_TESTED = "not-tested"
    """The probe was skipped or is not applicable."""


class EvidenceKind(str, enum.Enum):
    """Whether evidence was collected statically or from a live runtime."""

    STATIC = "static"
    """Derived from repository or filesystem artifacts; no live processes."""

    RUNTIME = "runtime"
    """Captured from a running system; requires host access and safety gating."""


@dataclass
class EvidenceRecord:
    """A single normalised finding emitted by any Trio capability.

    All optional fields default to ``None`` or an empty collection.
    Consumers MUST tolerate absent optional fields.

    Parameters
    ----------
    source_tool:
        The Trio tool that produced this record (``"discover"``,
        ``"searcher"``, ``"trace"``, or a custom probe name).
    timestamp:
        RFC 3339 / ISO 8601 timestamp of when the probe ran, e.g.
        ``"2026-03-19T22:00:00Z"``.
    target:
        The entity being examined: a hostname, file path, service name,
        interface, or other identifier meaningful to the probe.
    probe_family:
        High-level category of probe, e.g. ``"port-scan"``,
        ``"config-parse"``, ``"dependency-trace"``.
    status:
        Outcome of the probe.
    summary:
        Short human-readable summary of the finding.
    kind:
        Whether the evidence was collected statically or from a live runtime.
    layer:
        OSI layer (1 = Physical … 7 = Application), or ``None`` when the
        finding is not layer-specific.
    raw_refs:
        Raw excerpts, file references, command output snippets, or other
        unprocessed material that supports the summary.
    confidence:
        Confidence in the finding, in the range ``[0.0, 1.0]``.
    interpretation:
        Narrative interpretation produced by the reasoning layer; may be
        ``None`` when the record is first emitted by the host.
    metadata:
        Arbitrary key-value metadata for probe-specific details.
    """

    # --- required fields ---
    source_tool: str
    timestamp: str
    target: str
    probe_family: str
    status: DiagnosticStatus
    summary: str
    kind: EvidenceKind

    # --- optional fields ---
    layer: Optional[int] = None
    raw_refs: list[str] = field(default_factory=list)
    confidence: float = 1.0
    interpretation: Optional[str] = None
    metadata: dict[str, str] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if self.layer is not None and not (1 <= self.layer <= 7):
            raise ValueError(
                f"layer must be between 1 and 7 inclusive, got {self.layer!r}"
            )
        if not (0.0 <= self.confidence <= 1.0):
            raise ValueError(
                f"confidence must be between 0.0 and 1.0, got {self.confidence!r}"
            )
