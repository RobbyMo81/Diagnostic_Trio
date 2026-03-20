"""Trace runtime evidence capture for Diagnostic Trio.

Trace collects live runtime evidence from a running system, capturing
behaviour that is invisible to static analysis.  All Trace evidence uses
:attr:`~trio_reason.evidence.EvidenceKind.RUNTIME` — it requires host access
and must be gated by safety checks before use.

Interrogation targets and default OSI layers
--------------------------------------------
``processes``
    L7 Application — running processes and their attributes.
``listeners-and-ports``
    L4 Transport — active listeners and open network ports.
``routes-and-interfaces``
    L3 Network — live IP routes and network interface state.
``sessions``
    L5 Session — active sessions (TCP established, SSH, TLS handshake state).
``logs``
    L7 Application — live or recently-rotated log streams.
``payload-or-protocol``
    L6 Presentation — payload or protocol-level behaviour (headers, framing).
``runtime-dependencies``
    L7 Application — runtime dependency availability (DNS, reach, latency).
``bind-or-transport-anomaly``
    L4 Transport — bind failures, port conflicts, transport-level anomalies.

Static vs runtime distinction
------------------------------
Unlike Discover (which reads files and manifests), Trace interrogates the
live system.  Every :func:`capture` call produces an
:class:`~trio_reason.evidence.EvidenceRecord` with
``kind = EvidenceKind.RUNTIME``, and the ``trace_target`` metadata key
records which interrogation target was used.
"""

from __future__ import annotations

import enum

from trio_reason.evidence import DiagnosticStatus, EvidenceKind, EvidenceRecord

# Map from target value to default OSI layer number.
_TARGET_LAYER: dict[str, int] = {
    "routes-and-interfaces": 3,         # Network
    "listeners-and-ports": 4,           # Transport
    "bind-or-transport-anomaly": 4,     # Transport
    "sessions": 5,                      # Session
    "payload-or-protocol": 6,           # Presentation
    "processes": 7,                     # Application
    "logs": 7,                          # Application
    "runtime-dependencies": 7,          # Application
}


class TraceTarget(str, enum.Enum):
    """Runtime interrogation targets supported by Trace."""

    PROCESSES = "processes"
    """Enumerate running processes and their attributes (L7 Application)."""

    LISTENERS_AND_PORTS = "listeners-and-ports"
    """Inspect active listeners and open network ports (L4 Transport)."""

    ROUTES_AND_INTERFACES = "routes-and-interfaces"
    """Inspect live IP routes and network interface state (L3 Network)."""

    SESSIONS = "sessions"
    """Inspect active sessions: TCP established, SSH, TLS handshake (L5 Session)."""

    LOGS = "logs"
    """Read live or recently-rotated log streams (L7 Application)."""

    PAYLOAD_OR_PROTOCOL = "payload-or-protocol"
    """Observe payload or protocol-level behaviour: headers, framing (L6 Presentation)."""

    RUNTIME_DEPENDENCIES = "runtime-dependencies"
    """Probe runtime dependency availability: DNS, reach, latency (L7 Application)."""

    BIND_OR_TRANSPORT_ANOMALY = "bind-or-transport-anomaly"
    """Detect bind failures, port conflicts, transport anomalies (L4 Transport)."""

    def default_layer(self) -> int:
        """Return the default OSI layer number (1–7) for this interrogation target."""
        return _TARGET_LAYER[self.value]


def capture(
    timestamp: str,
    target: str,
    trace_tgt: TraceTarget,
    status: DiagnosticStatus,
    summary: str,
) -> EvidenceRecord:
    """Capture a runtime observation as a layer-tagged Trace evidence record.

    The record is always emitted with ``source_tool="trace"`` and
    ``kind=EvidenceKind.RUNTIME``.  The ``trace_target`` metadata key records
    which interrogation target was used.

    Parameters
    ----------
    timestamp:
        RFC 3339 timestamp of when the probe ran.
    target:
        Process name, interface, port, log path, or other identifier.
    trace_tgt:
        The :class:`TraceTarget` used to interrogate the system.
    status:
        Outcome of the probe.
    summary:
        Short human-readable finding description.

    Returns
    -------
    EvidenceRecord
        A fully populated runtime evidence record with layer and target metadata.
    """
    return EvidenceRecord(
        source_tool="trace",
        timestamp=timestamp,
        target=target,
        probe_family=trace_tgt.value,
        status=status,
        summary=summary,
        kind=EvidenceKind.RUNTIME,
        layer=trace_tgt.default_layer(),
        metadata={"trace_target": trace_tgt.value},
    )
