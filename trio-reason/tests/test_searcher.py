"""Tests for trio_reason.searcher backend catalog (US-006)."""

from __future__ import annotations

import pytest

from trio_reason.searcher import (
    CATALOG,
    BackendCapability,
    BackendCategory,
    SearchBackend,
    backends_with_capability,
)


class TestBackendCategory:
    def test_high_performance_value(self) -> None:
        assert BackendCategory.HIGH_PERFORMANCE.value == "high-performance"

    def test_specialized_value(self) -> None:
        assert BackendCategory.SPECIALIZED.value == "specialized"

    def test_windows_compatible_value(self) -> None:
        assert BackendCategory.WINDOWS_COMPATIBLE.value == "windows-compatible"

    def test_optional_interactive_value(self) -> None:
        assert BackendCategory.OPTIONAL_INTERACTIVE.value == "optional-interactive"

    def test_text_processing_value(self) -> None:
        assert BackendCategory.TEXT_PROCESSING.value == "text-processing"

    def test_all_five_categories_defined(self) -> None:
        assert len(BackendCategory) == 5


class TestBackendCapability:
    def test_recursive_search_value(self) -> None:
        assert BackendCapability.RECURSIVE_SEARCH.value == "recursive-search"

    def test_regex_search_value(self) -> None:
        assert BackendCapability.REGEX_SEARCH.value == "regex-search"

    def test_git_aware_value(self) -> None:
        assert BackendCapability.GIT_AWARE.value == "git-aware"

    def test_binary_search_value(self) -> None:
        assert BackendCapability.BINARY_SEARCH.value == "binary-search"

    def test_multiline_search_value(self) -> None:
        assert BackendCapability.MULTILINE_SEARCH.value == "multiline-search"

    def test_structured_query_value(self) -> None:
        assert BackendCapability.STRUCTURED_QUERY.value == "structured-query"

    def test_interactive_filter_value(self) -> None:
        assert BackendCapability.INTERACTIVE_FILTER.value == "interactive-filter"

    def test_file_search_value(self) -> None:
        assert BackendCapability.FILE_SEARCH.value == "file-search"

    def test_stream_processing_value(self) -> None:
        assert BackendCapability.STREAM_PROCESSING.value == "stream-processing"


class TestSearchBackend:
    def test_has_capability_true(self) -> None:
        rg = next(b for b in CATALOG if b.name == "rg")
        assert rg.has_capability(BackendCapability.GIT_AWARE)

    def test_has_capability_false(self) -> None:
        grep = next(b for b in CATALOG if b.name == "grep")
        assert not grep.has_capability(BackendCapability.GIT_AWARE)

    def test_frozen_dataclass_is_immutable(self) -> None:
        rg = next(b for b in CATALOG if b.name == "rg")
        with pytest.raises((AttributeError, TypeError)):
            rg.preferred = False  # type: ignore[misc]


class TestCatalogCompleteness:
    def test_catalog_is_non_empty(self) -> None:
        assert len(CATALOG) > 0

    def test_catalog_contains_rg(self) -> None:
        assert any(b.name == "rg" for b in CATALOG)

    def test_catalog_contains_ag(self) -> None:
        assert any(b.name == "ag" for b in CATALOG)

    def test_catalog_contains_ugrep(self) -> None:
        assert any(b.name == "ugrep" for b in CATALOG)

    def test_catalog_contains_fd(self) -> None:
        assert any(b.name == "fd" for b in CATALOG)

    def test_catalog_contains_jq(self) -> None:
        assert any(b.name == "jq" for b in CATALOG)

    def test_catalog_contains_yq(self) -> None:
        assert any(b.name == "yq" for b in CATALOG)

    def test_catalog_contains_findstr(self) -> None:
        assert any(b.name == "findstr" for b in CATALOG)

    def test_catalog_contains_select_string(self) -> None:
        assert any(b.name == "Select-String" for b in CATALOG)

    def test_catalog_contains_fzf(self) -> None:
        assert any(b.name == "fzf" for b in CATALOG)

    def test_catalog_contains_peco(self) -> None:
        assert any(b.name == "peco" for b in CATALOG)

    def test_catalog_contains_grep(self) -> None:
        assert any(b.name == "grep" for b in CATALOG)

    def test_catalog_contains_awk(self) -> None:
        assert any(b.name == "awk" for b in CATALOG)

    def test_catalog_contains_sed(self) -> None:
        assert any(b.name == "sed" for b in CATALOG)

    def test_all_five_categories_represented(self) -> None:
        categories = {b.category for b in CATALOG}
        assert categories == set(BackendCategory)


class TestPreferredVsFallback:
    def test_rg_is_preferred(self) -> None:
        rg = next(b for b in CATALOG if b.name == "rg")
        assert rg.preferred is True

    def test_ag_is_preferred(self) -> None:
        ag = next(b for b in CATALOG if b.name == "ag")
        assert ag.preferred is True

    def test_ugrep_is_not_preferred(self) -> None:
        ugrep = next(b for b in CATALOG if b.name == "ugrep")
        assert ugrep.preferred is False

    def test_grep_is_not_preferred(self) -> None:
        grep = next(b for b in CATALOG if b.name == "grep")
        assert grep.preferred is False

    def test_fzf_is_preferred(self) -> None:
        fzf = next(b for b in CATALOG if b.name == "fzf")
        assert fzf.preferred is True

    def test_peco_is_not_preferred(self) -> None:
        peco = next(b for b in CATALOG if b.name == "peco")
        assert peco.preferred is False


class TestCategoryMembership:
    def test_rg_is_high_performance(self) -> None:
        rg = next(b for b in CATALOG if b.name == "rg")
        assert rg.category == BackendCategory.HIGH_PERFORMANCE

    def test_fd_is_specialized(self) -> None:
        fd = next(b for b in CATALOG if b.name == "fd")
        assert fd.category == BackendCategory.SPECIALIZED

    def test_findstr_is_windows_compatible(self) -> None:
        findstr = next(b for b in CATALOG if b.name == "findstr")
        assert findstr.category == BackendCategory.WINDOWS_COMPATIBLE

    def test_fzf_is_optional_interactive(self) -> None:
        fzf = next(b for b in CATALOG if b.name == "fzf")
        assert fzf.category == BackendCategory.OPTIONAL_INTERACTIVE

    def test_grep_is_text_processing(self) -> None:
        grep = next(b for b in CATALOG if b.name == "grep")
        assert grep.category == BackendCategory.TEXT_PROCESSING


class TestBackendsWithCapability:
    def test_recursive_search_returns_rg_first(self) -> None:
        results = backends_with_capability(BackendCapability.RECURSIVE_SEARCH)
        assert len(results) > 0
        assert results[0].name == "rg"

    def test_structured_query_includes_jq_and_yq(self) -> None:
        names = {b.name for b in backends_with_capability(BackendCapability.STRUCTURED_QUERY)}
        assert "jq" in names
        assert "yq" in names

    def test_interactive_filter_returns_fzf_before_peco(self) -> None:
        results = backends_with_capability(BackendCapability.INTERACTIVE_FILTER)
        names = [b.name for b in results]
        assert names.index("fzf") < names.index("peco")

    def test_preferred_before_non_preferred(self) -> None:
        results = backends_with_capability(BackendCapability.RECURSIVE_SEARCH)
        preferred_done = False
        for b in results:
            if not b.preferred:
                preferred_done = True
            if preferred_done:
                assert not b.preferred, "non-preferred backend followed by preferred"

    def test_git_aware_backends_are_all_preferred(self) -> None:
        results = backends_with_capability(BackendCapability.GIT_AWARE)
        assert all(b.preferred for b in results)

    def test_empty_result_for_unknown_capability_combo(self) -> None:
        # stream-processing backends do not have interactive-filter
        stream_backends = {b.name for b in backends_with_capability(BackendCapability.STREAM_PROCESSING)}
        interactive_backends = {b.name for b in backends_with_capability(BackendCapability.INTERACTIVE_FILTER)}
        assert stream_backends.isdisjoint(interactive_backends)
