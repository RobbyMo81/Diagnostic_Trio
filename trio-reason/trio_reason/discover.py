"""Discover evidence classification for Diagnostic Trio.

Discover classifies repository and host evidence into layer-tagged
:class:`~trio_reason.evidence.EvidenceRecord` findings using the shared
evidence schema.  All Discover evidence is *static* — it derives from files
and configuration artifacts without interacting with live processes.

Probe families and their default OSI layers
-------------------------------------------
``config-parse``
    L7 Application — general configuration file parsing.
``dependency-trace``
    L7 Application — package manifests and lock files.
``service-config``
    L7 Application — service definitions and daemon configuration.
``tls-config``
    L6 Presentation — TLS, certificate, and encryption configuration.
``port-config``
    L4 Transport — port and socket configuration.
``routing-config``
    L3 Network — IP routing and addressing configuration.
``host-interface``
    L2 Data Link — network interface configuration (MAC, link state, MTU).

Scopes
------
:attr:`DiscoverScope.REPOSITORY`
    Source code, manifests, lock files, and committed configuration.
:attr:`DiscoverScope.HOST`
    OS-level configuration files on the running host (e.g.
    ``/etc/resolv.conf``, ``/etc/network/interfaces``).
"""

from __future__ import annotations

import enum

from trio_reason.evidence import DiagnosticStatus, EvidenceKind, EvidenceRecord
from trio_reason.safety import SafetyLevel

# Map from probe-family value to default OSI layer number.
_PROBE_FAMILY_LAYER: dict[str, int] = {
    "host-interface": 2,   # Data Link
    "routing-config": 3,   # Network
    "port-config": 4,      # Transport
    "tls-config": 6,       # Presentation
    "config-parse": 7,     # Application
    "dependency-trace": 7, # Application
    "service-config": 7,   # Application
}


class DiscoverProbeFamily(str, enum.Enum):
    """Categories of probes performed by Discover."""

    CONFIG_PARSE = "config-parse"
    """Parse and validate configuration files (L7 Application)."""

    DEPENDENCY_TRACE = "dependency-trace"
    """Trace package manifests and lock files for the dependency surface (L7 Application)."""

    HOST_INTERFACE = "host-interface"
    """Examine network-interface configuration: MAC, link state, MTU (L2 Data Link)."""

    ROUTING_CONFIG = "routing-config"
    """Inspect IP routing table and addressing configuration (L3 Network)."""

    PORT_CONFIG = "port-config"
    """Inspect port or socket configuration at the transport layer (L4 Transport)."""

    TLS_CONFIG = "tls-config"
    """Inspect TLS, certificate, or encryption configuration (L6 Presentation)."""

    SERVICE_CONFIG = "service-config"
    """Inspect application service definitions and daemon configuration (L7 Application)."""

    def default_layer(self) -> int:
        """Return the default OSI layer number (1–7) for this probe family."""
        return _PROBE_FAMILY_LAYER[self.value]


class DiscoverScope(str, enum.Enum):
    """Whether the evidence originates from the repository or the host."""

    REPOSITORY = "repository"
    """Source code, manifests, lock files, and committed configuration."""

    HOST = "host"
    """OS-level configuration files present on the running host."""

    def required_safety_level(self) -> SafetyLevel:
        """Return the minimum :class:`~trio_reason.safety.SafetyLevel` required.

        ``REPOSITORY`` reads version-controlled artifacts — always ``READ_ONLY``.
        ``HOST`` reads OS-level config files outside the repository and therefore
        requires ``AUTHORIZED``.
        """
        if self is DiscoverScope.HOST:
            return SafetyLevel.AUTHORIZED
        return SafetyLevel.READ_ONLY


def classify(
    scope: DiscoverScope,
    timestamp: str,
    target: str,
    probe_family: DiscoverProbeFamily,
    status: DiagnosticStatus,
    summary: str,
) -> EvidenceRecord:
    """Classify a static artifact into a layer-tagged Discover evidence record.

    The record is always emitted with ``source_tool="discover"`` and
    ``kind=EvidenceKind.STATIC``.  The ``discover_scope`` metadata key records
    whether the artifact came from the repository or the host filesystem.

    Parameters
    ----------
    scope:
        :attr:`DiscoverScope.REPOSITORY` or :attr:`DiscoverScope.HOST`.
    timestamp:
        RFC 3339 timestamp of when the probe ran.
    target:
        File path, service name, or other artifact identifier.
    probe_family:
        The :class:`DiscoverProbeFamily` used to examine the target.
    status:
        Outcome of the probe.
    summary:
        Short human-readable finding description.

    Returns
    -------
    EvidenceRecord
        A fully populated static evidence record with layer and scope metadata.
    """
    return EvidenceRecord(
        source_tool="discover",
        timestamp=timestamp,
        target=target,
        probe_family=probe_family.value,
        status=status,
        summary=summary,
        kind=EvidenceKind.STATIC,
        layer=probe_family.default_layer(),
        metadata={"discover_scope": scope.value},
    )
