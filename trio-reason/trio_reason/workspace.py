"""Shared workspace and state contract for Diagnostic Trio.

Trio tools operate inside a well-known directory tree that provides
isolation from the host filesystem and independence from any Quartet
internals.  All reads and writes go through the paths defined here so
that the layout can be relocated without changing tool behaviour.

Workspace layout
----------------
::

    <workspace_root>/
    ├── artifacts/     — durable output files written by Discover, Searcher, Trace
    ├── cache/         — ephemeral intermediate data that may be evicted freely
    ├── journal/       — append-only journal entries linking runs to findings
    └── state/         — mutable shared state exchanged between Trio tools

Quartet independence
--------------------
Trio never imports or depends on Quartet modules.  It accesses shared
context only through :class:`SharedState` values that callers populate
before invoking any Trio tool.  Trio writes its results back into the
workspace tree; it does not mutate caller-owned data structures.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

# ---------------------------------------------------------------------------
# Canonical sub-directory names
# ---------------------------------------------------------------------------

ARTIFACTS_DIR: str = "artifacts"
CACHE_DIR: str = "cache"
JOURNAL_DIR: str = "journal"
STATE_DIR: str = "state"


@dataclass
class WorkspaceLayout:
    """Resolved paths for every logical section of a Trio workspace.

    Construct via :meth:`WorkspaceLayout.from_root` and pass the result to
    Trio tools so they all agree on where to read and write data.

    Parameters
    ----------
    root:
        Root directory that contains all workspace sub-directories.
    artifacts:
        Where Discover, Searcher, and Trace write durable output files.
    cache:
        Where tools may write intermediate data that is safe to delete.
    journal:
        Where append-only journal entries are stored.
    state:
        Where shared state files are exchanged between Trio tools.
    """

    root: Path
    artifacts: Path
    cache: Path
    journal: Path
    state: Path

    @classmethod
    def from_root(cls, root: Path | str) -> "WorkspaceLayout":
        """Build a :class:`WorkspaceLayout` rooted at *root*.

        The root directory need not exist yet; callers are responsible for
        creating it before the first tool runs.
        """
        root = Path(root)
        return cls(
            root=root,
            artifacts=root / ARTIFACTS_DIR,
            cache=root / CACHE_DIR,
            journal=root / JOURNAL_DIR,
            state=root / STATE_DIR,
        )

    def artifact_path(self, name: str) -> Path:
        """Return the path where a named artifact file should be written.

        Example::

            layout.artifact_path("discover-findings.json")
        """
        return self.artifacts / name

    def cache_path(self, name: str) -> Path:
        """Return the path where a named cache file may be stored."""
        return self.cache / name

    def journal_path(self, name: str) -> Path:
        """Return the path where a named journal file is kept."""
        return self.journal / name

    def state_path(self, name: str) -> Path:
        """Return the path where a named shared-state file lives."""
        return self.state / name


@dataclass
class SharedState:
    """Context provided to every Trio tool before it runs.

    Each tool reads only the fields it needs; unused fields are ignored.  The
    dataclass is intentionally flat — tools must not reach outside it to query
    Quartet or host state.

    Tool-specific inputs
    --------------------
    .. list-table::
       :header-rows: 1

       * - Tool
         - Required fields
       * - Discover
         - ``target``, ``workspace``, ``discover_scope``
       * - Searcher
         - ``target``, ``workspace``, ``search_roots``, ``search_query``
       * - Trace
         - ``target``, ``workspace``, ``trace_scope``

    Parameters
    ----------
    target:
        Primary target being diagnosed: a hostname, IP address, service name,
        or filesystem path, depending on what the invoking tool expects.
    workspace:
        Workspace layout that all tools in this run share.
    discover_scope:
        Which probe families Discover should execute.  An empty list means
        "run all available probes".
    search_roots:
        Filesystem roots Searcher should include in its search.
    search_query:
        Freeform query or keyword that Searcher uses to filter results.
    trace_scope:
        Which runtime interrogation targets to inspect.  An empty list means
        "inspect all safe targets".  Sensitive targets must be explicitly
        named here AND must pass safety gating.
    extra:
        Arbitrary key-value metadata forwarded to all tools.  Use this for
        probe-specific settings that do not belong in the core fields above
        (e.g. port ranges, include/exclude patterns).
    """

    target: str
    workspace: WorkspaceLayout

    # --- optional / per-tool fields ---
    discover_scope: list[str] = field(default_factory=list)
    search_roots: list[Path] = field(default_factory=list)
    search_query: Optional[str] = None
    trace_scope: list[str] = field(default_factory=list)
    extra: dict[str, str] = field(default_factory=dict)
