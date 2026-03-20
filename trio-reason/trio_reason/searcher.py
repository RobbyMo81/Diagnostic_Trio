"""Searcher backend catalog and result normalisation for Diagnostic Trio.

Searcher knows which search tools are available on the host, what each tool can
do, and which are preferred versus optional fallbacks.  This catalog is the
authoritative source of truth for capability selection and graceful-degradation
logic (see US-013 for fallback behaviour).

Result normalisation
--------------------
Raw search hits are normalised into :class:`~trio_reason.evidence.EvidenceRecord`
values via :func:`normalize`.  Each hit carries a :class:`SearchIntent`
describing *why* the search was issued and a :class:`ResultKind` describing the
type of artifact that matched.  The normaliser uses the intent to assign a
default OSI layer and to populate the ``probe_family`` field.

Backend categories
------------------
``high-performance``
    Fast, purpose-built search engines designed for recursive code search.
    Examples: ``rg`` (ripgrep), ``ag`` (The Silver Searcher), ``ugrep``.
``specialized``
    Tools optimised for a specific file type, format, or search style.
    Examples: ``fd`` (file-find), ``jq`` (JSON queries), ``yq`` (YAML queries).
``windows-compatible``
    Search tools that work on Windows without POSIX dependencies.
    Examples: ``findstr``, ``Select-String`` (PowerShell).
``optional-interactive``
    Interactive selection filters; useful but not required for automation.
    Examples: ``fzf``, ``peco``.
``text-processing``
    Classic POSIX text-processing utilities used as last-resort fallbacks.
    Examples: ``grep``, ``awk``, ``sed``.

Preferred vs. fallback
-----------------------
Backends with :attr:`SearchBackend.preferred` set to ``True`` are selected first
when multiple tools can satisfy a search intent.  Non-preferred backends are only
used when no preferred backend for the same category is available.  Searcher
always preserves the normalised output shape regardless of which backend runs.
"""

from __future__ import annotations

import enum
from dataclasses import dataclass, field
from typing import Optional


class BackendCategory(str, enum.Enum):
    """Broad category that determines how a backend is grouped and selected."""

    HIGH_PERFORMANCE = "high-performance"
    """Fast, purpose-built search engines for recursive code search."""

    SPECIALIZED = "specialized"
    """Tools optimised for a specific file type or format."""

    WINDOWS_COMPATIBLE = "windows-compatible"
    """Search tools that work on Windows without POSIX dependencies."""

    OPTIONAL_INTERACTIVE = "optional-interactive"
    """Interactive selection filters; not required for automation."""

    TEXT_PROCESSING = "text-processing"
    """Classic POSIX text-processing utilities used as last-resort fallbacks."""


class BackendCapability(str, enum.Enum):
    """Individual capability flags a backend may support."""

    RECURSIVE_SEARCH = "recursive-search"
    """Searches directories recursively without extra flags."""

    REGEX_SEARCH = "regex-search"
    """Supports full regular-expression patterns."""

    GIT_AWARE = "git-aware"
    """Respects .gitignore and similar ignore files by default."""

    BINARY_SEARCH = "binary-search"
    """Can search inside binary files."""

    MULTILINE_SEARCH = "multiline-search"
    """Supports patterns that span multiple lines."""

    STRUCTURED_QUERY = "structured-query"
    """Queries structured data formats (JSON, YAML, TOML, …)."""

    INTERACTIVE_FILTER = "interactive-filter"
    """Provides an interactive fuzzy-selection UI."""

    FILE_SEARCH = "file-search"
    """Finds files by name / path pattern (not content)."""

    STREAM_PROCESSING = "stream-processing"
    """Processes text streams line-by-line (awk / sed style)."""


@dataclass(frozen=True)
class SearchBackend:
    """Normalised descriptor for a single Searcher backend.

    Attributes
    ----------
    name:
        Canonical command name used to invoke the tool (e.g. ``"rg"``).
    label:
        Human-readable label for display and logging.
    category:
        Broad category that governs selection and fallback priority.
    preferred:
        ``True`` when this backend is the first choice for its category;
        ``False`` when it should only be used if no preferred backend is found.
    capabilities:
        Frozenset of capabilities this backend exposes to Searcher consumers.
    """

    name: str
    label: str
    category: BackendCategory
    preferred: bool
    capabilities: frozenset[BackendCapability] = field(default_factory=frozenset)

    def has_capability(self, cap: BackendCapability) -> bool:
        """Return ``True`` if this backend supports *cap*."""
        return cap in self.capabilities


# ---------------------------------------------------------------------------
# Catalog
# ---------------------------------------------------------------------------

#: The complete Searcher backend catalog.
#:
#: Entries are ordered by priority within each category: preferred backends
#: appear before optional fallbacks.  Callers SHOULD iterate in order when
#: selecting a backend for a given capability.
CATALOG: list[SearchBackend] = [
    # ── High-performance ────────────────────────────────────────────────────
    SearchBackend(
        name="rg",
        label="ripgrep",
        category=BackendCategory.HIGH_PERFORMANCE,
        preferred=True,
        capabilities=frozenset({
            BackendCapability.RECURSIVE_SEARCH,
            BackendCapability.REGEX_SEARCH,
            BackendCapability.GIT_AWARE,
            BackendCapability.BINARY_SEARCH,
            BackendCapability.MULTILINE_SEARCH,
        }),
    ),
    SearchBackend(
        name="ag",
        label="The Silver Searcher",
        category=BackendCategory.HIGH_PERFORMANCE,
        preferred=True,
        capabilities=frozenset({
            BackendCapability.RECURSIVE_SEARCH,
            BackendCapability.REGEX_SEARCH,
            BackendCapability.GIT_AWARE,
        }),
    ),
    SearchBackend(
        name="ugrep",
        label="ugrep",
        category=BackendCategory.HIGH_PERFORMANCE,
        preferred=False,
        capabilities=frozenset({
            BackendCapability.RECURSIVE_SEARCH,
            BackendCapability.REGEX_SEARCH,
            BackendCapability.BINARY_SEARCH,
            BackendCapability.STRUCTURED_QUERY,
        }),
    ),
    # ── Specialized ─────────────────────────────────────────────────────────
    SearchBackend(
        name="fd",
        label="fd",
        category=BackendCategory.SPECIALIZED,
        preferred=True,
        capabilities=frozenset({
            BackendCapability.RECURSIVE_SEARCH,
            BackendCapability.FILE_SEARCH,
            BackendCapability.GIT_AWARE,
        }),
    ),
    SearchBackend(
        name="jq",
        label="jq",
        category=BackendCategory.SPECIALIZED,
        preferred=True,
        capabilities=frozenset({BackendCapability.STRUCTURED_QUERY}),
    ),
    SearchBackend(
        name="yq",
        label="yq",
        category=BackendCategory.SPECIALIZED,
        preferred=True,
        capabilities=frozenset({BackendCapability.STRUCTURED_QUERY}),
    ),
    # ── Windows-compatible ──────────────────────────────────────────────────
    SearchBackend(
        name="findstr",
        label="findstr",
        category=BackendCategory.WINDOWS_COMPATIBLE,
        preferred=True,
        capabilities=frozenset({
            BackendCapability.RECURSIVE_SEARCH,
            BackendCapability.REGEX_SEARCH,
        }),
    ),
    SearchBackend(
        name="Select-String",
        label="PowerShell Select-String",
        category=BackendCategory.WINDOWS_COMPATIBLE,
        preferred=True,
        capabilities=frozenset({
            BackendCapability.REGEX_SEARCH,
            BackendCapability.MULTILINE_SEARCH,
        }),
    ),
    # ── Optional interactive ─────────────────────────────────────────────────
    SearchBackend(
        name="fzf",
        label="fzf",
        category=BackendCategory.OPTIONAL_INTERACTIVE,
        preferred=True,
        capabilities=frozenset({BackendCapability.INTERACTIVE_FILTER}),
    ),
    SearchBackend(
        name="peco",
        label="peco",
        category=BackendCategory.OPTIONAL_INTERACTIVE,
        preferred=False,
        capabilities=frozenset({BackendCapability.INTERACTIVE_FILTER}),
    ),
    # ── Text processing (last-resort fallbacks) ──────────────────────────────
    SearchBackend(
        name="grep",
        label="GNU grep",
        category=BackendCategory.TEXT_PROCESSING,
        preferred=False,
        capabilities=frozenset({
            BackendCapability.RECURSIVE_SEARCH,
            BackendCapability.REGEX_SEARCH,
            BackendCapability.BINARY_SEARCH,
        }),
    ),
    SearchBackend(
        name="awk",
        label="awk",
        category=BackendCategory.TEXT_PROCESSING,
        preferred=False,
        capabilities=frozenset({BackendCapability.STREAM_PROCESSING}),
    ),
    SearchBackend(
        name="sed",
        label="sed",
        category=BackendCategory.TEXT_PROCESSING,
        preferred=False,
        capabilities=frozenset({BackendCapability.STREAM_PROCESSING}),
    ),
]


def backends_with_capability(cap: BackendCapability) -> list[SearchBackend]:
    """Return catalog backends that support *cap*, preferred backends first.

    Parameters
    ----------
    cap:
        The :class:`BackendCapability` to filter on.

    Returns
    -------
    list[SearchBackend]
        Matching backends sorted so ``preferred=True`` entries precede
        ``preferred=False`` entries.  The relative order within each tier
        matches the catalog definition order.
    """
    matching = [b for b in CATALOG if b.has_capability(cap)]
    return sorted(matching, key=lambda b: not b.preferred)


def select_backend(
    cap: BackendCapability,
    available: list[str],
) -> Optional[SearchBackend]:
    """Select the best available backend for *cap* from *available* tool names.

    Iterates :func:`backends_with_capability` (preferred-first order) and
    returns the first entry whose :attr:`SearchBackend.name` appears in
    *available*.  Returns ``None`` when no capable backend is installed on
    the host.

    Parameters
    ----------
    cap:
        The capability that the chosen backend must support.
    available:
        Names of backends present on the host (e.g. ``["rg", "grep"]``).

    Returns
    -------
    SearchBackend or None
        The highest-priority available backend, or ``None`` if no capable
        backend is installed.

    Notes
    -----
    Because :func:`backends_with_capability` sorts preferred before
    non-preferred, this function automatically degrades to a fallback backend
    when a preferred tool is absent.  Callers do not need to inspect the
    ``preferred`` flag — they always receive the best available option.
    """
    available_set = set(available)
    for backend in backends_with_capability(cap):
        if backend.name in available_set:
            return backend
    return None


# ---------------------------------------------------------------------------
# Search intent
# ---------------------------------------------------------------------------


class SearchIntent(str, enum.Enum):
    """Why a search was issued — used to assign probe family and default OSI layer.

    +--------------------------------+-------+-----------------------------------+
    | Intent                         | Layer | Probe family label                |
    +================================+=======+===================================+
    | ``CONFIG_LOOKUP``              | 7     | ``config-lookup``                 |
    +--------------------------------+-------+-----------------------------------+
    | ``ERROR_STRING_HUNT``          | 7     | ``error-string-hunt``             |
    +--------------------------------+-------+-----------------------------------+
    | ``ENTRY_POINT_TRACING``        | 7     | ``entry-point-tracing``           |
    +--------------------------------+-------+-----------------------------------+
    | ``DEPENDENCY_TRACING``         | 7     | ``dependency-tracing``            |
    +--------------------------------+-------+-----------------------------------+
    | ``SCHEMA_OR_PAYLOAD_SEARCH``   | 6     | ``schema-or-payload-search``      |
    +--------------------------------+-------+-----------------------------------+
    | ``SECRET_OR_CONFIG_SURFACE``   | 7     | ``secret-or-config-surface``      |
    +--------------------------------+-------+-----------------------------------+
    """

    CONFIG_LOOKUP = "config-lookup"
    """Locate configuration values, keys, or files for a target component."""

    ERROR_STRING_HUNT = "error-string-hunt"
    """Hunt for error strings, stack traces, or exception patterns."""

    ENTRY_POINT_TRACING = "entry-point-tracing"
    """Trace entry points such as ``main``, CLI handlers, or route registrations."""

    DEPENDENCY_TRACING = "dependency-tracing"
    """Trace imports, ``require``, ``use``, or manifest dependency declarations."""

    SCHEMA_OR_PAYLOAD_SEARCH = "schema-or-payload-search"
    """Search data schemas, serialisation formats, or protocol payloads."""

    SECRET_OR_CONFIG_SURFACE_DETECTION = "secret-or-config-surface"
    """Surface exposed secrets, credentials, or sensitive config values."""

    def default_layer(self) -> Optional[int]:
        """Return the default OSI layer for findings produced by this intent.

        Returns ``None`` when the intent does not map to a single well-known layer.
        """
        if self == SearchIntent.SCHEMA_OR_PAYLOAD_SEARCH:
            return 6  # Presentation
        return 7  # Application


# ---------------------------------------------------------------------------
# Result kind
# ---------------------------------------------------------------------------


class ResultKind(str, enum.Enum):
    """The type of artifact that matched a search query."""

    FILE = "file"
    """A generic file path match (name or path search, no content examined)."""

    CONFIG = "config"
    """A configuration file or embedded config value."""

    LOG = "log"
    """A log file or log-formatted text stream."""

    SOURCE_CODE = "source-code"
    """Application source code."""

    STRUCTURED_TEXT = "structured-text"
    """Structured-text format: JSON, YAML, TOML, XML, CSV, …"""

    GENERATED_ARTIFACT = "generated-artifact"
    """Machine-generated artifact: build output, lock file, schema dump, …"""


# ---------------------------------------------------------------------------
# Raw search hit
# ---------------------------------------------------------------------------


@dataclass
class RawSearchHit:
    """Unprocessed output from a single search backend match, ready for normalisation.

    Parameters
    ----------
    file_path:
        Path to the file that contained the match.
    matched_text:
        The matched text or excerpt returned by the backend.
    backend:
        Name of the backend that produced this hit (e.g. ``"rg"``).
    intent:
        Why the search was issued.
    result_kind:
        Type of artifact that matched.
    query:
        The query string or pattern that was searched.
    line_number:
        Line number of the match, if the backend reports it.
    """

    file_path: str
    matched_text: str
    backend: str
    intent: SearchIntent
    result_kind: ResultKind
    query: str
    line_number: Optional[int] = None


# ---------------------------------------------------------------------------
# Normalisation
# ---------------------------------------------------------------------------


def normalize(
    hit: RawSearchHit,
    timestamp: str,
    status: "DiagnosticStatus",  # type: ignore[name-defined]  # noqa: F821
) -> "EvidenceRecord":  # type: ignore[name-defined]  # noqa: F821
    """Normalise a raw search hit into a shared :class:`~trio_reason.evidence.EvidenceRecord`.

    Parameters
    ----------
    hit:
        The raw match from a search backend.
    timestamp:
        RFC 3339 timestamp of when the search ran.
    status:
        Caller-assigned diagnostic status (e.g. :attr:`DiagnosticStatus.PASS`
        when a config was found, :attr:`DiagnosticStatus.FAIL` when a secret
        is exposed).

    Returns
    -------
    EvidenceRecord
        ``source_tool`` is always ``"searcher"``, ``probe_family`` is taken
        from :meth:`SearchIntent.value`, ``layer`` from
        :meth:`SearchIntent.default_layer`, and ``kind`` is always
        :attr:`EvidenceKind.STATIC` — Searcher operates on repository and
        filesystem artifacts, never on live runtime state.
    """
    from trio_reason.evidence import EvidenceKind, EvidenceRecord  # local import avoids cycles

    loc_suffix = f":{hit.line_number}" if hit.line_number is not None else ""
    summary = (
        f"[{hit.intent.value}] query {hit.query!r} matched in {hit.file_path}{loc_suffix}"
    )

    raw_refs: list[str] = [hit.matched_text]
    if hit.line_number is not None:
        raw_refs.append(f"{hit.file_path}:{hit.line_number}")

    metadata: dict[str, str] = {
        "backend": hit.backend,
        "result_kind": hit.result_kind.value,
        "query": hit.query,
    }
    if hit.line_number is not None:
        metadata["line_number"] = str(hit.line_number)

    return EvidenceRecord(
        source_tool="searcher",
        timestamp=timestamp,
        target=hit.file_path,
        probe_family=hit.intent.value,
        status=status,
        summary=summary,
        kind=EvidenceKind.STATIC,
        layer=hit.intent.default_layer(),
        raw_refs=raw_refs,
        confidence=1.0,
        interpretation=None,
        metadata=metadata,
    )
