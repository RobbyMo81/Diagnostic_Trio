"""OSI layer model and status propagation rules for Diagnostic Trio.

Findings from Discover, Searcher, and Trace are tagged with an OSI layer so
failure surfaces can be isolated systematically.  The layer model also enforces
a key invariant: **upper layers cannot be treated as healthy when a lower layer
is failed or untested**.

OSI Layers
----------
.. list-table::
   :header-rows: 1

   * - Number
     - Name
   * - 1
     - Physical
   * - 2
     - Data Link
   * - 3
     - Network
   * - 4
     - Transport
   * - 5
     - Session
   * - 6
     - Presentation
   * - 7
     - Application

Lower-layer dependency rule
---------------------------
Call :func:`effective_status` to apply the rule automatically: if any layer
below the queried layer is :attr:`~.DiagnosticStatus.FAIL` or
:attr:`~.DiagnosticStatus.NOT_TESTED` (or BLOCKED/PARTIAL), the effective
status of the queried layer is demoted to
:attr:`~.DiagnosticStatus.BLOCKED` to prevent a false-healthy reading.
"""

from __future__ import annotations

import enum
from typing import Sequence, Tuple

from .evidence import DiagnosticStatus


class OsiLayer(enum.IntEnum):
    """The seven OSI layers, ordered from physical (lowest) to application.

    :class:`OsiLayer` is an :class:`~enum.IntEnum` so numeric comparisons work
    naturally — ``OsiLayer.PHYSICAL < OsiLayer.APPLICATION`` is ``True``.
    """

    PHYSICAL = 1
    """Layer 1 — cables, signals, hardware."""

    DATA_LINK = 2
    """Layer 2 — MAC addressing, Ethernet frames."""

    NETWORK = 3
    """Layer 3 — IP routing and addressing."""

    TRANSPORT = 4
    """Layer 4 — end-to-end delivery, TCP/UDP."""

    SESSION = 5
    """Layer 5 — session management and control."""

    PRESENTATION = 6
    """Layer 6 — encoding, encryption, compression."""

    APPLICATION = 7
    """Layer 7 — application protocols (HTTP, DNS, TLS handshake, …)."""

    # ------------------------------------------------------------------ #
    # Convenience helpers                                                  #
    # ------------------------------------------------------------------ #

    @property
    def layer_name(self) -> str:
        """Human-readable name of the layer."""
        _NAMES = {
            1: "Physical",
            2: "Data Link",
            3: "Network",
            4: "Transport",
            5: "Session",
            6: "Presentation",
            7: "Application",
        }
        return _NAMES[self.value]

    def is_below(self, other: "OsiLayer") -> bool:
        """Return ``True`` if this layer is strictly below *other*."""
        return self.value < other.value

    def layers_below_inclusive(self) -> list["OsiLayer"]:
        """Return all layers from PHYSICAL up to and including *self*, ordered lowest first."""
        return [l for l in OsiLayer if l.value <= self.value]

    @classmethod
    def from_number(cls, n: int) -> "OsiLayer":
        """Construct an :class:`OsiLayer` from its numeric value (1 – 7).

        Raises :class:`ValueError` if the value is out of range.
        """
        try:
            return cls(n)
        except ValueError:
            raise ValueError(f"OSI layer number must be 1–7, got {n!r}")


#: All OSI layers in ascending order (PHYSICAL first).
ALL_LAYERS: tuple[OsiLayer, ...] = tuple(OsiLayer)


# --------------------------------------------------------------------------- #
# Status propagation                                                           #
# --------------------------------------------------------------------------- #

#: Statuses on a lower layer that block upper layers from being healthy.
_BLOCKING_STATUSES: frozenset[DiagnosticStatus] = frozenset({
    DiagnosticStatus.FAIL,
    DiagnosticStatus.NOT_TESTED,
    DiagnosticStatus.BLOCKED,
    DiagnosticStatus.PARTIAL,
})


def status_blocks_upper(status: DiagnosticStatus) -> bool:
    """Return ``True`` if *status* on a lower layer blocks upper layers.

    :attr:`~DiagnosticStatus.FAIL`, :attr:`~DiagnosticStatus.NOT_TESTED`,
    :attr:`~DiagnosticStatus.BLOCKED`, and :attr:`~DiagnosticStatus.PARTIAL`
    all prevent upper layers from being considered healthy.
    Only :attr:`~DiagnosticStatus.PASS` allows upper layers to be healthy.
    """
    return status in _BLOCKING_STATUSES


def effective_status(
    query_layer: OsiLayer,
    own_status: DiagnosticStatus,
    findings: Sequence[Tuple[OsiLayer, DiagnosticStatus]],
) -> DiagnosticStatus:
    """Compute the effective diagnostic status for *query_layer*.

    If any layer *below* *query_layer* has a status that blocks upper layers
    (see :func:`status_blocks_upper`), the effective status is demoted to
    :attr:`~DiagnosticStatus.BLOCKED` regardless of *own_status*.

    Parameters
    ----------
    query_layer:
        The layer whose effective status is being computed.
    own_status:
        The status that *query_layer*'s own probes reported.
    findings:
        Other ``(layer, status)`` pairs from the current diagnostic session.
        Entries at the same layer as *query_layer* are ignored.

    Returns
    -------
    DiagnosticStatus
        The effective status after applying the lower-layer dependency rule.
    """
    lower_blocked = any(
        l.is_below(query_layer) and status_blocks_upper(s)
        for l, s in findings
    )
    return DiagnosticStatus.BLOCKED if lower_blocked else own_status
