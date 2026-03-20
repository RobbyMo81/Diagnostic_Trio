"""Tests for trio_reason.workspace — shared workspace and state contract."""

from pathlib import Path

import pytest

from trio_reason.workspace import (
    ARTIFACTS_DIR,
    CACHE_DIR,
    JOURNAL_DIR,
    STATE_DIR,
    SharedState,
    WorkspaceLayout,
)

ROOT = Path("/tmp/trio-test-workspace")


# ---------------------------------------------------------------------------
# WorkspaceLayout
# ---------------------------------------------------------------------------


def test_from_root_sets_root() -> None:
    layout = WorkspaceLayout.from_root(ROOT)
    assert layout.root == ROOT


def test_from_root_sub_dirs() -> None:
    layout = WorkspaceLayout.from_root(ROOT)
    assert layout.artifacts == ROOT / "artifacts"
    assert layout.cache == ROOT / "cache"
    assert layout.journal == ROOT / "journal"
    assert layout.state == ROOT / "state"


def test_from_root_accepts_str() -> None:
    layout = WorkspaceLayout.from_root("/tmp/trio-test-workspace")
    assert layout.root == Path("/tmp/trio-test-workspace")


def test_artifact_path_helper() -> None:
    layout = WorkspaceLayout.from_root(ROOT)
    assert layout.artifact_path("discover-findings.json") == ROOT / "artifacts" / "discover-findings.json"


def test_cache_path_helper() -> None:
    layout = WorkspaceLayout.from_root(ROOT)
    assert layout.cache_path("ripgrep-index") == ROOT / "cache" / "ripgrep-index"


def test_journal_path_helper() -> None:
    layout = WorkspaceLayout.from_root(ROOT)
    assert layout.journal_path("2026-03-19.jsonl") == ROOT / "journal" / "2026-03-19.jsonl"


def test_state_path_helper() -> None:
    layout = WorkspaceLayout.from_root(ROOT)
    assert layout.state_path("shared.json") == ROOT / "state" / "shared.json"


def test_constants_match_layout_dir_names() -> None:
    layout = WorkspaceLayout.from_root(ROOT)
    assert layout.artifacts.name == ARTIFACTS_DIR
    assert layout.cache.name == CACHE_DIR
    assert layout.journal.name == JOURNAL_DIR
    assert layout.state.name == STATE_DIR


# ---------------------------------------------------------------------------
# SharedState defaults
# ---------------------------------------------------------------------------


def _make_state(target: str = "example.host") -> SharedState:
    return SharedState(target=target, workspace=WorkspaceLayout.from_root(ROOT))


def test_shared_state_target() -> None:
    state = _make_state("10.0.0.1")
    assert state.target == "10.0.0.1"


def test_shared_state_workspace_is_layout() -> None:
    state = _make_state()
    assert isinstance(state.workspace, WorkspaceLayout)


def test_shared_state_discover_scope_defaults_empty() -> None:
    state = _make_state()
    assert state.discover_scope == []


def test_shared_state_search_roots_defaults_empty() -> None:
    state = _make_state()
    assert state.search_roots == []


def test_shared_state_search_query_defaults_none() -> None:
    state = _make_state()
    assert state.search_query is None


def test_shared_state_trace_scope_defaults_empty() -> None:
    state = _make_state()
    assert state.trace_scope == []


def test_shared_state_extra_defaults_empty() -> None:
    state = _make_state()
    assert state.extra == {}


# ---------------------------------------------------------------------------
# SharedState populated
# ---------------------------------------------------------------------------


def test_shared_state_discover_scope_populated() -> None:
    state = _make_state()
    state.discover_scope = ["config-parse", "dependency-trace"]
    assert len(state.discover_scope) == 2
    assert "config-parse" in state.discover_scope


def test_shared_state_trace_scope_populated() -> None:
    state = _make_state()
    state.trace_scope = ["processes", "listeners"]
    assert "processes" in state.trace_scope
    assert "listeners" in state.trace_scope


def test_shared_state_search_query_set() -> None:
    state = _make_state()
    state.search_query = "DATABASE_URL"
    assert state.search_query == "DATABASE_URL"


def test_shared_state_search_roots_populated() -> None:
    state = _make_state()
    state.search_roots = [Path("/etc"), Path("/var/log")]
    assert len(state.search_roots) == 2


def test_shared_state_extra_populated() -> None:
    state = _make_state()
    state.extra = {"port_range": "1-1024", "exclude": "*.pyc"}
    assert state.extra["port_range"] == "1-1024"


# ---------------------------------------------------------------------------
# Quartet independence — workspace does not import anything from Quartet
# ---------------------------------------------------------------------------


def test_workspace_module_has_no_quartet_imports() -> None:
    import importlib
    import sys

    # Ensure the module is loaded
    import trio_reason.workspace  # noqa: F401

    # No module whose name starts with 'quartet' should be present
    quartet_modules = [name for name in sys.modules if name.startswith("quartet")]
    assert quartet_modules == [], f"Unexpected Quartet imports: {quartet_modules}"
