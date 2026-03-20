"""Searcher backend catalog for Diagnostic Trio.

Searcher knows which search tools are available on the host, what each tool can
do, and which are preferred versus optional fallbacks.  This catalog is the
authoritative source of truth for capability selection and graceful-degradation
logic (see US-013 for fallback behaviour).

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
