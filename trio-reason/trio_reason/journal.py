"""Shared journal workflow for Diagnostic Trio.

The journal captures materially important work from Discover, Searcher, and
Trace in a durable, append-only record.  Every entry is written as a single
JSON line (JSONL) so the file can be streamed, tailed, or grep-filtered
without parsing the whole document.

Journal format
--------------
Each line is a self-contained JSON object::

    {"id":"<id>","timestamp":"<rfc3339>","tool":"<name>","event":"<kind>",
     "summary":"<text>","evidence_ref":null,"metadata":{}}

.. list-table::
   :header-rows: 1

   * - Field
     - Type
     - Description
   * - ``id``
     - string
     - Opaque unique entry identifier
   * - ``timestamp``
     - RFC 3339 string
     - When the event occurred
   * - ``tool``
     - string
     - Which Trio tool emitted this entry
   * - ``event``
     - string
     - Event kind label (see :class:`JournalEventKind`)
   * - ``summary``
     - string
     - Short human-readable description
   * - ``evidence_ref``
     - string or null
     - Optional link to a related evidence record id
   * - ``metadata``
     - object
     - Arbitrary key-value pairs for event-specific data

Append-only behaviour
---------------------
:func:`append` opens the journal file in append mode (``"a"``) and writes
exactly one line.  Existing content is never modified.  Multiple processes
may safely append to the same file on POSIX systems because line-length
writes via ``O_APPEND`` are atomic for lines shorter than ``PIPE_BUF``.

Linking to evidence
-------------------
Set :attr:`JournalEntry.evidence_ref` to the ``id`` of a related
``EvidenceRecord`` to cross-reference the two.  Consumers can join journal
entries to evidence records by matching on this field.
"""

from __future__ import annotations

import enum
import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional


# ---------------------------------------------------------------------------
# JournalEventKind
# ---------------------------------------------------------------------------


class JournalEventKind(str, enum.Enum):
    """Categories of events that Trio tools write into the journal."""

    TOOL_STARTED = "tool-started"
    """A Trio tool began executing against a target."""

    FINDING_RECORDED = "finding-recorded"
    """An ``EvidenceRecord`` was emitted and is ready for review."""

    PROBE_COMPLETED = "probe-completed"
    """A probe family finished running (pass, fail, or blocked)."""

    SAFETY_GATED = "safety-gated"
    """A safety gate blocked a potentially mutating or sensitive operation."""

    WORKSPACE_UPDATED = "workspace-updated"
    """The shared workspace state was updated by a tool."""


# ---------------------------------------------------------------------------
# JournalEntry
# ---------------------------------------------------------------------------


@dataclass
class JournalEntry:
    """A single immutable journal record emitted by a Trio tool.

    Parameters
    ----------
    id:
        Opaque unique identifier for this entry (e.g. a UUID or counter).
    timestamp:
        RFC 3339 timestamp of when the event occurred.
    tool:
        The Trio tool that emitted this entry (``"discover"``,
        ``"searcher"``, ``"trace"``, or a custom tool name).
    event_kind:
        What kind of event this entry describes.
    summary:
        Short human-readable description of the event.
    evidence_ref:
        Optional reference to the ``id`` of a related ``EvidenceRecord``.
    metadata:
        Arbitrary key-value pairs for event-specific data.
    """

    id: str
    timestamp: str
    tool: str
    event_kind: JournalEventKind
    summary: str
    evidence_ref: Optional[str] = None
    metadata: dict[str, str] = field(default_factory=dict)


# ---------------------------------------------------------------------------
# Serialisation helpers
# ---------------------------------------------------------------------------


def format_line(entry: JournalEntry) -> str:
    """Serialise *entry* to a single JSONL line (no trailing newline).

    The returned string is a valid JSON object suitable for appending to a
    ``.jsonl`` journal file.

    Parameters
    ----------
    entry:
        The :class:`JournalEntry` to serialise.

    Returns
    -------
    str
        A single JSON object line with no embedded newlines.
    """
    obj: dict[str, object] = {
        "id": entry.id,
        "timestamp": entry.timestamp,
        "tool": entry.tool,
        "event": entry.event_kind.value,
        "summary": entry.summary,
        "evidence_ref": entry.evidence_ref,
        "metadata": entry.metadata,
    }
    return json.dumps(obj, ensure_ascii=False, separators=(",", ":"))


# ---------------------------------------------------------------------------
# Append-only write
# ---------------------------------------------------------------------------


def append(path: Path | str, entry: JournalEntry) -> None:
    """Append *entry* to the journal file at *path* as a single JSONL line.

    The file is opened in append mode and created if it does not exist.  Each
    call writes exactly one line followed by ``\\n``.  Existing content is
    never modified.

    Parameters
    ----------
    path:
        Filesystem path to the journal file (created if absent).
    entry:
        The :class:`JournalEntry` to persist.

    Raises
    ------
    OSError
        If the file cannot be opened or the write fails.
    """
    line = format_line(entry)
    with open(path, "a", encoding="utf-8") as fh:
        fh.write(line + "\n")
