"""Runtime safety gating for Diagnostic Trio.

Trio is **read-only by default**.  All Discover probes and most Trace
interrogations read existing files or observe passively-available state and
never mutate the system.  A small set of interrogation paths is considered
*sensitive* — either because they observe privileged state (active session
data, payload content) or because they touch OS-level configuration outside
of the repository.  These paths require explicit authorization before Trio
will invoke them.

Safety levels
-------------
``READ_ONLY``
    Default.  Reads files and passively available host state.
``AUTHORIZED``
    Explicit opt-in.  Required for sensitive inspection paths.

Gating model
------------
Every potentially sensitive operation declares a ``required``
:class:`SafetyLevel`.  The caller holds a :class:`SafetyPolicy` carrying the
``granted`` level.  :func:`check_gate` raises :class:`SafetyViolation` when
``granted < required``; it returns ``None`` (silently) when the gate passes.

Sensitive paths
---------------
**Trace targets that require** ``AUTHORIZED``:

- ``SESSIONS`` — observes active session credentials and handshake state.
- ``PAYLOAD_OR_PROTOCOL`` — deep packet / payload inspection.

**Discover scopes that require** ``AUTHORIZED``:

- ``DiscoverScope.HOST`` — reads OS-level config files outside the repo.

All other Trace targets and ``DiscoverScope.REPOSITORY`` are ``READ_ONLY``.

Provenance
----------
When Trio emits an :class:`~trio_reason.evidence.EvidenceRecord` for a gated
path the ``metadata`` dict will contain ``"safety_level": "authorized"``.
For read-only paths the key is absent to keep records concise.
"""

from __future__ import annotations

import enum
from dataclasses import dataclass, field


class SafetyLevel(int, enum.Enum):
    """Authorization level required to execute an inspection operation.

    Levels are ordered: ``READ_ONLY < AUTHORIZED``.  A policy grants
    everything at or below its own level.
    """

    READ_ONLY = 0
    """Non-destructive read-only access.  Default for all operations."""

    AUTHORIZED = 1
    """Explicit authorization required for sensitive inspection paths."""

    def label(self) -> str:
        """Canonical string label used in evidence metadata and error messages."""
        return self.name.lower().replace("_", "-")


class SafetyViolation(Exception):
    """Raised when an operation's required safety level exceeds the granted level.

    Attributes
    ----------
    operation:
        Human-readable name of the operation that was blocked.
    required:
        The level the operation needs.
    granted:
        The level that was actually granted.
    """

    def __init__(
        self,
        operation: str,
        required: SafetyLevel,
        granted: SafetyLevel,
    ) -> None:
        self.operation = operation
        self.required = required
        self.granted = granted
        super().__init__(
            f"safety gate blocked {operation!r}: "
            f"requires {required.label()!r} but only {granted.label()!r} granted"
        )


@dataclass
class SafetyPolicy:
    """Caller-held policy object carrying the granted :class:`SafetyLevel`.

    Construct via :meth:`read_only` (default) or :meth:`authorized`
    (explicit opt-in).
    """

    level: SafetyLevel = field(default=SafetyLevel.READ_ONLY)

    @classmethod
    def read_only(cls) -> SafetyPolicy:
        """Return a read-only policy.  This is the safe default."""
        return cls(level=SafetyLevel.READ_ONLY)

    @classmethod
    def authorized(cls) -> SafetyPolicy:
        """Return an authorized policy.

        Pass this only when the caller has explicitly confirmed that sensitive
        inspection is acceptable.
        """
        return cls(level=SafetyLevel.AUTHORIZED)


def check_gate(
    operation: str,
    required: SafetyLevel,
    policy: SafetyPolicy,
) -> None:
    """Gate an operation against the active :class:`SafetyPolicy`.

    Returns ``None`` silently when ``policy.level >= required``.  Raises
    :class:`SafetyViolation` when the operation requires a higher level than
    granted.

    Parameters
    ----------
    operation:
        Human-readable label for the operation being gated.
    required:
        Minimum :class:`SafetyLevel` the operation needs.
    policy:
        The :class:`SafetyPolicy` held by the caller.

    Raises
    ------
    SafetyViolation
        When ``policy.level < required``.
    """
    if policy.level < required:
        raise SafetyViolation(operation=operation, required=required, granted=policy.level)
