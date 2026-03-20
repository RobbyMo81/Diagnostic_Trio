"""Artifact write-back behaviour for Diagnostic Trio.

Trio maintains one durable JSONL artifact file per tool so that
investigations remain reviewable after a run ends.  Artifact files live
inside the ``artifacts/`` sub-directory of the shared workspace.

Artifact set
------------
.. list-table::
   :header-rows: 1

   * - Tool
     - File
   * - Discover
     - ``discover-findings.jsonl``
   * - Searcher
     - ``searcher-findings.jsonl``
   * - Trace
     - ``trace-findings.jsonl``

Each file is append-only JSONL: one :class:`~trio_reason.evidence.EvidenceRecord`
per line.  Existing lines are never modified or removed.

Provenance
----------
Every line serialises the complete ``EvidenceRecord``, including
``source_tool``, ``timestamp``, ``target``, ``probe_family``, ``layer``,
``status``, ``kind``, ``confidence``, ``raw_refs``, ``interpretation``, and
``metadata``.  Each artifact line is therefore self-describing and can be
attributed to its originating tool and run without consulting any external
index.

Relationship to the journal and workspace
-----------------------------------------
1. **Workspace**: call :meth:`~trio_reason.workspace.WorkspaceLayout.artifact_path`
   with :attr:`ArtifactKind.filename` to obtain the correct path before
   calling :func:`append_record`.

2. **Journal**: after writing an artifact record, emit a
   ``JournalEventKind.FINDING_RECORDED`` or
   ``JournalEventKind.WORKSPACE_UPDATED`` entry to keep the audit trail
   continuous.  Use the record's ``source_tool`` + ``timestamp`` + ``target``
   combination as a natural key when constructing the ``evidence_ref`` in the
   journal entry.

Example flow
------------
::

    1. Tool produces EvidenceRecord
    2. append_record(layout.artifact_path(kind.filename), record)
    3. journal.append(layout.journal_path("run.jsonl"), journal_entry)
"""

from __future__ import annotations

import enum
import json
from pathlib import Path


# ---------------------------------------------------------------------------
# ArtifactKind
# ---------------------------------------------------------------------------


class ArtifactKind(str, enum.Enum):
    """Which Trio tool's artifact file a write targets."""

    DISCOVER_FINDINGS = "discover-findings"
    """Artifact produced by the Discover capability."""

    SEARCHER_FINDINGS = "searcher-findings"
    """Artifact produced by the Searcher capability."""

    TRACE_FINDINGS = "trace-findings"
    """Artifact produced by the Trace capability."""

    @property
    def filename(self) -> str:
        """Return the filename (including extension) of this artifact file.

        Pass this to
        :meth:`~trio_reason.workspace.WorkspaceLayout.artifact_path` to
        obtain the fully qualified path.
        """
        return f"{self.value}.jsonl"


# ---------------------------------------------------------------------------
# Serialisation helpers
# ---------------------------------------------------------------------------


def format_record(record: object) -> str:
    """Serialise *record* to a single JSONL line (no trailing newline).

    Every field of the record is included so the artifact is fully
    self-describing and provenance is preserved.

    Parameters
    ----------
    record:
        An :class:`~trio_reason.evidence.EvidenceRecord` instance.

    Returns
    -------
    str
        A single JSON object line with no embedded newlines.
    """
    from trio_reason.evidence import EvidenceRecord  # local import avoids circular refs

    assert isinstance(record, EvidenceRecord)

    obj: dict[str, object] = {
        "source_tool": record.source_tool,
        "timestamp": record.timestamp,
        "target": record.target,
        "probe_family": record.probe_family,
        "layer": record.layer,
        "status": record.status.value,
        "summary": record.summary,
        "kind": record.kind.value,
        "raw_refs": record.raw_refs,
        "confidence": record.confidence,
        "interpretation": record.interpretation,
        "metadata": record.metadata,
    }
    return json.dumps(obj, ensure_ascii=False, separators=(",", ":"))


# ---------------------------------------------------------------------------
# Append-only write
# ---------------------------------------------------------------------------


def append_record(path: Path | str, record: object) -> None:
    """Append *record* to the artifact file at *path* as a single JSONL line.

    The file is opened in append mode and created if it does not exist.  Each
    call writes exactly one line followed by ``\\n``.  Existing content is
    never modified.

    Parameters
    ----------
    path:
        Filesystem path to the artifact file (created if absent).
    record:
        An :class:`~trio_reason.evidence.EvidenceRecord` instance to persist.

    Raises
    ------
    OSError
        If the file cannot be opened or the write fails.
    """
    line = format_record(record)
    with open(path, "a", encoding="utf-8") as fh:
        fh.write(line + "\n")
