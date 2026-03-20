"""Language-layer boundary for Diagnostic Trio.

This module documents and enforces the split between Rust (host execution) and
Python (reasoning) responsibilities, and defines the IPC message contract used
to communicate across the boundary.

Rust responsibilities
---------------------
``cli``
    Parse CLI arguments, handle OS signals, manage exit codes.
``host-interaction``
    Execute probes against the host: read files, call system APIs, spawn
    short-lived processes.
``orchestration``
    Sequence the Discover, Searcher, and Trace capabilities, applying safety
    gating and workspace layout.
``normalization``
    Convert raw probe outputs into :class:`~trio_reason.evidence.EvidenceRecord`
    values using the shared schema.
``mcp-exposure``
    Expose Trio capabilities as MCP tools via the stdio transport protocol.

Python responsibilities
-----------------------
``reasoning``
    Interpret a set of evidence records as a coherent diagnostic picture.
``interpretation``
    Annotate individual evidence records with a narrative ``interpretation``
    field.
``synthesis``
    Combine evidence across tools and layers into ranked hypotheses or
    root-cause theories.
``narrative-generation``
    Produce human-readable diagnostic summaries suitable for an operator report.

Interface
---------
Rust and Python exchange :class:`BridgeMessage` values serialised as newline-
delimited JSON (JSONL) over ``stdin`` / ``stdout``.  Rust writes
``evidence-for-reasoning`` messages and reads ``reasoning-response`` messages;
Python does the reverse.

Message flow::

    Rust                                Python
     |                                    |
     |  evidence-for-reasoning (JSONL) →  |
     |                                    |  (interprets records)
     |  ←  reasoning-response (JSONL)     |
     |                                    |
     |  shutdown (JSONL) →                |
     |                                    |
"""

from __future__ import annotations

import enum
import json
from dataclasses import dataclass, field
from typing import Optional


# ---------------------------------------------------------------------------
# Role enumerations
# ---------------------------------------------------------------------------


class RustRole(str, enum.Enum):
    """Responsibilities that belong to the Rust host-execution layer."""

    CLI = "cli"
    """Parse CLI arguments, handle OS signals, manage exit codes."""

    HOST_INTERACTION = "host-interaction"
    """Execute probes against the host: read files, call system APIs, spawn
    short-lived processes."""

    ORCHESTRATION = "orchestration"
    """Sequence the Discover, Searcher, and Trace capabilities, applying safety
    gating and workspace layout."""

    NORMALIZATION = "normalization"
    """Convert raw probe outputs into EvidenceRecord values using the shared
    schema."""

    MCP_EXPOSURE = "mcp-exposure"
    """Expose Trio capabilities as MCP tools via the stdio transport protocol."""


class PythonRole(str, enum.Enum):
    """Responsibilities that belong to the Python reasoning layer."""

    REASONING = "reasoning"
    """Interpret a set of evidence records as a coherent diagnostic picture."""

    INTERPRETATION = "interpretation"
    """Annotate individual evidence records with a narrative interpretation
    field."""

    SYNTHESIS = "synthesis"
    """Combine evidence across tools and layers into ranked hypotheses or
    root-cause theories."""

    NARRATIVE_GENERATION = "narrative-generation"
    """Produce human-readable diagnostic summaries suitable for an operator
    report."""


# ---------------------------------------------------------------------------
# IPC message types
# ---------------------------------------------------------------------------


class BridgeMessageKind(str, enum.Enum):
    """Discriminant for a :class:`BridgeMessage`."""

    EVIDENCE_FOR_REASONING = "evidence-for-reasoning"
    """Rust → Python: one or more serialised evidence records for reasoning."""

    REASONING_RESPONSE = "reasoning-response"
    """Python → Rust: interpretation and synthesis results for the submitted
    evidence."""

    SHUTDOWN = "shutdown"
    """Rust → Python: signals that no more messages will be sent; Python should
    flush its output and terminate cleanly."""


@dataclass
class BridgeMessage:
    """A single IPC message crossing the Rust / Python boundary.

    Messages are serialised to JSONL: one compact JSON object per line, with no
    embedded newlines in the payload.  The ``payload`` field carries a
    JSON-encoded body whose schema depends on ``kind``.

    Parameters
    ----------
    kind:
        Identifies the message type so the receiver can deserialise ``payload``.
    payload:
        JSON-encoded message body (compact, no embedded newlines).
    metadata:
        Optional key-value metadata (run ID, session ID, …).
    """

    kind: BridgeMessageKind
    payload: str
    metadata: dict[str, str] = field(default_factory=dict)


# ---------------------------------------------------------------------------
# Convenience constants
# ---------------------------------------------------------------------------

ALL_RUST_ROLES: list[RustRole] = list(RustRole)
"""Every Rust role in definition order."""

ALL_PYTHON_ROLES: list[PythonRole] = list(PythonRole)
"""Every Python role in definition order."""


# ---------------------------------------------------------------------------
# Serialisation helpers
# ---------------------------------------------------------------------------


def encode_message(msg: BridgeMessage) -> str:
    """Serialise *msg* to a single compact JSONL line (no trailing newline).

    Parameters
    ----------
    msg:
        The message to encode.

    Returns
    -------
    str
        A single-line JSON string suitable for writing to a JSONL stream.
    """
    return json.dumps(
        {
            "kind": msg.kind.value,
            "payload": msg.payload,
            "metadata": msg.metadata,
        },
        separators=(",", ":"),
    )


def decode_message(line: str) -> Optional[BridgeMessage]:
    """Deserialise a JSONL line into a :class:`BridgeMessage`.

    Returns ``None`` when the line cannot be parsed or is missing required
    fields.

    Parameters
    ----------
    line:
        A single JSON line from a JSONL stream.

    Returns
    -------
    BridgeMessage or None
    """
    try:
        obj = json.loads(line)
        kind = BridgeMessageKind(obj["kind"])
        payload = obj["payload"]
        metadata = obj.get("metadata", {})
        return BridgeMessage(kind=kind, payload=payload, metadata=metadata)
    except (json.JSONDecodeError, KeyError, ValueError):
        return None
