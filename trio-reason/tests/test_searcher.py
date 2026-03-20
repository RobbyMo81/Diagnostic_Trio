"""Tests for trio_reason.searcher backend catalog and normalisation (US-006, US-007)."""

from __future__ import annotations

import pytest

from trio_reason.evidence import DiagnosticStatus, EvidenceKind
from trio_reason.searcher import (
    CATALOG,
    BackendCapability,
    BackendCategory,
    RawSearchHit,
    ResultKind,
    SearchBackend,
    SearchIntent,
    backends_with_capability,
    normalize,
    select_backend,
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


# ---------------------------------------------------------------------------
# SearchIntent
# ---------------------------------------------------------------------------


class TestSearchIntent:
    def test_config_lookup_value(self) -> None:
        assert SearchIntent.CONFIG_LOOKUP.value == "config-lookup"

    def test_error_string_hunt_value(self) -> None:
        assert SearchIntent.ERROR_STRING_HUNT.value == "error-string-hunt"

    def test_entry_point_tracing_value(self) -> None:
        assert SearchIntent.ENTRY_POINT_TRACING.value == "entry-point-tracing"

    def test_dependency_tracing_value(self) -> None:
        assert SearchIntent.DEPENDENCY_TRACING.value == "dependency-tracing"

    def test_schema_or_payload_search_value(self) -> None:
        assert SearchIntent.SCHEMA_OR_PAYLOAD_SEARCH.value == "schema-or-payload-search"

    def test_secret_or_config_surface_value(self) -> None:
        assert SearchIntent.SECRET_OR_CONFIG_SURFACE_DETECTION.value == "secret-or-config-surface"

    def test_all_six_intents_defined(self) -> None:
        assert len(SearchIntent) == 6

    def test_config_lookup_layer_7(self) -> None:
        assert SearchIntent.CONFIG_LOOKUP.default_layer() == 7

    def test_schema_or_payload_layer_6(self) -> None:
        assert SearchIntent.SCHEMA_OR_PAYLOAD_SEARCH.default_layer() == 6

    def test_dependency_tracing_layer_7(self) -> None:
        assert SearchIntent.DEPENDENCY_TRACING.default_layer() == 7

    def test_error_string_hunt_layer_7(self) -> None:
        assert SearchIntent.ERROR_STRING_HUNT.default_layer() == 7

    def test_entry_point_tracing_layer_7(self) -> None:
        assert SearchIntent.ENTRY_POINT_TRACING.default_layer() == 7

    def test_secret_surface_layer_7(self) -> None:
        assert SearchIntent.SECRET_OR_CONFIG_SURFACE_DETECTION.default_layer() == 7


# ---------------------------------------------------------------------------
# ResultKind
# ---------------------------------------------------------------------------


class TestResultKind:
    def test_file_value(self) -> None:
        assert ResultKind.FILE.value == "file"

    def test_config_value(self) -> None:
        assert ResultKind.CONFIG.value == "config"

    def test_log_value(self) -> None:
        assert ResultKind.LOG.value == "log"

    def test_source_code_value(self) -> None:
        assert ResultKind.SOURCE_CODE.value == "source-code"

    def test_structured_text_value(self) -> None:
        assert ResultKind.STRUCTURED_TEXT.value == "structured-text"

    def test_generated_artifact_value(self) -> None:
        assert ResultKind.GENERATED_ARTIFACT.value == "generated-artifact"

    def test_all_six_kinds_defined(self) -> None:
        assert len(ResultKind) == 6


# ---------------------------------------------------------------------------
# normalize
# ---------------------------------------------------------------------------


def _make_hit(
    intent: SearchIntent = SearchIntent.CONFIG_LOOKUP,
    result_kind: ResultKind = ResultKind.CONFIG,
    line_number: int | None = None,
) -> RawSearchHit:
    return RawSearchHit(
        file_path="/repo/src/main.rs",
        matched_text="DATABASE_URL=postgres://localhost/app",
        backend="rg",
        intent=intent,
        result_kind=result_kind,
        query="DATABASE_URL",
        line_number=line_number,
    )


class TestNormalize:
    def test_source_tool_is_searcher(self) -> None:
        rec = normalize(_make_hit(), "2026-03-19T00:00:00Z", DiagnosticStatus.PASS)
        assert rec.source_tool == "searcher"

    def test_probe_family_from_intent(self) -> None:
        rec = normalize(
            _make_hit(intent=SearchIntent.ERROR_STRING_HUNT, result_kind=ResultKind.LOG),
            "2026-03-19T00:00:00Z",
            DiagnosticStatus.PASS,
        )
        assert rec.probe_family == "error-string-hunt"

    def test_target_is_file_path(self) -> None:
        rec = normalize(_make_hit(), "2026-03-19T00:00:00Z", DiagnosticStatus.PASS)
        assert rec.target == "/repo/src/main.rs"

    def test_layer_7_for_config_lookup(self) -> None:
        rec = normalize(_make_hit(), "2026-03-19T00:00:00Z", DiagnosticStatus.PASS)
        assert rec.layer == 7

    def test_layer_6_for_schema_search(self) -> None:
        rec = normalize(
            _make_hit(
                intent=SearchIntent.SCHEMA_OR_PAYLOAD_SEARCH,
                result_kind=ResultKind.STRUCTURED_TEXT,
            ),
            "2026-03-19T00:00:00Z",
            DiagnosticStatus.PASS,
        )
        assert rec.layer == 6

    def test_kind_is_static(self) -> None:
        rec = normalize(_make_hit(), "2026-03-19T00:00:00Z", DiagnosticStatus.PASS)
        assert rec.kind == EvidenceKind.STATIC

    def test_status_is_propagated(self) -> None:
        rec = normalize(
            _make_hit(
                intent=SearchIntent.SECRET_OR_CONFIG_SURFACE_DETECTION,
                result_kind=ResultKind.CONFIG,
            ),
            "2026-03-19T00:00:00Z",
            DiagnosticStatus.FAIL,
        )
        assert rec.status == DiagnosticStatus.FAIL

    def test_raw_refs_contains_matched_text(self) -> None:
        rec = normalize(_make_hit(), "2026-03-19T00:00:00Z", DiagnosticStatus.PASS)
        assert "DATABASE_URL=postgres://localhost/app" in rec.raw_refs

    def test_metadata_contains_backend(self) -> None:
        rec = normalize(_make_hit(), "2026-03-19T00:00:00Z", DiagnosticStatus.PASS)
        assert rec.metadata.get("backend") == "rg"

    def test_metadata_contains_result_kind(self) -> None:
        rec = normalize(_make_hit(), "2026-03-19T00:00:00Z", DiagnosticStatus.PASS)
        assert rec.metadata.get("result_kind") == "config"

    def test_metadata_contains_query(self) -> None:
        rec = normalize(_make_hit(), "2026-03-19T00:00:00Z", DiagnosticStatus.PASS)
        assert rec.metadata.get("query") == "DATABASE_URL"

    def test_line_number_in_metadata_when_present(self) -> None:
        rec = normalize(
            _make_hit(intent=SearchIntent.ERROR_STRING_HUNT, result_kind=ResultKind.LOG, line_number=42),
            "2026-03-19T00:00:00Z",
            DiagnosticStatus.FAIL,
        )
        assert rec.metadata.get("line_number") == "42"

    def test_no_line_number_key_when_absent(self) -> None:
        rec = normalize(_make_hit(), "2026-03-19T00:00:00Z", DiagnosticStatus.PASS)
        assert "line_number" not in rec.metadata

    def test_summary_contains_intent_and_query(self) -> None:
        rec = normalize(
            _make_hit(intent=SearchIntent.ENTRY_POINT_TRACING, result_kind=ResultKind.SOURCE_CODE),
            "2026-03-19T00:00:00Z",
            DiagnosticStatus.PASS,
        )
        assert "entry-point-tracing" in rec.summary
        assert "DATABASE_URL" in rec.summary

    def test_all_intents_normalize_without_error(self) -> None:
        for intent in SearchIntent:
            rec = normalize(
                _make_hit(intent=intent, result_kind=ResultKind.FILE),
                "2026-03-19T00:00:00Z",
                DiagnosticStatus.PASS,
            )
            assert rec.source_tool == "searcher"

    def test_all_result_kinds_normalize_without_error(self) -> None:
        for kind in ResultKind:
            rec = normalize(
                _make_hit(intent=SearchIntent.CONFIG_LOOKUP, result_kind=kind),
                "2026-03-19T00:00:00Z",
                DiagnosticStatus.PASS,
            )
            assert rec.metadata.get("result_kind") == kind.value


# ---------------------------------------------------------------------------
# select_backend
# ---------------------------------------------------------------------------


class TestSelectBackend:
    def test_returns_rg_when_available(self) -> None:
        backend = select_backend(BackendCapability.RECURSIVE_SEARCH, ["rg", "grep"])
        assert backend is not None
        assert backend.name == "rg"

    def test_returns_preferred_first(self) -> None:
        # rg and ag are both preferred; rg comes first in catalog
        backend = select_backend(BackendCapability.RECURSIVE_SEARCH, ["ag", "rg", "grep"])
        assert backend is not None
        assert backend.name == "rg"

    def test_falls_back_when_preferred_missing(self) -> None:
        # rg and ag are missing; grep is the fallback
        backend = select_backend(BackendCapability.RECURSIVE_SEARCH, ["grep"])
        assert backend is not None
        assert backend.name == "grep"

    def test_falls_back_to_peco_when_fzf_missing(self) -> None:
        backend = select_backend(BackendCapability.INTERACTIVE_FILTER, ["peco"])
        assert backend is not None
        assert backend.name == "peco"

    def test_returns_none_when_no_tool_available(self) -> None:
        backend = select_backend(BackendCapability.RECURSIVE_SEARCH, [])
        assert backend is None

    def test_returns_none_when_no_capable_tool_available(self) -> None:
        # grep has no interactive-filter capability
        backend = select_backend(BackendCapability.INTERACTIVE_FILTER, ["grep"])
        assert backend is None

    def test_fallback_backend_is_not_preferred(self) -> None:
        backend = select_backend(BackendCapability.RECURSIVE_SEARCH, ["grep"])
        assert backend is not None
        assert backend.preferred is False

    def test_preferred_backend_is_preferred(self) -> None:
        backend = select_backend(BackendCapability.RECURSIVE_SEARCH, ["rg"])
        assert backend is not None
        assert backend.preferred is True

    def test_backend_name_preserved_in_normalize(self) -> None:
        backend = select_backend(BackendCapability.RECURSIVE_SEARCH, ["grep"])
        assert backend is not None
        hit = RawSearchHit(
            file_path="/repo/Cargo.toml",
            matched_text="tokio",
            backend=backend.name,
            intent=SearchIntent.DEPENDENCY_TRACING,
            result_kind=ResultKind.GENERATED_ARTIFACT,
            query="tokio",
        )
        rec = normalize(hit, "2026-03-20T00:00:00Z", DiagnosticStatus.PASS)
        assert rec.metadata.get("backend") == "grep"

    def test_structured_query_prefers_jq_or_yq_over_ugrep(self) -> None:
        backend = select_backend(BackendCapability.STRUCTURED_QUERY, ["ugrep", "jq", "yq"])
        assert backend is not None
        assert backend.preferred is True
        assert backend.name in {"jq", "yq"}

    def test_output_shape_preserved_for_fallback(self) -> None:
        # Normalized output from a fallback backend must have the same shape as
        # output from a preferred backend.
        preferred_backend = select_backend(BackendCapability.RECURSIVE_SEARCH, ["rg"])
        fallback_backend = select_backend(BackendCapability.RECURSIVE_SEARCH, ["grep"])
        assert preferred_backend is not None
        assert fallback_backend is not None

        def make_rec(backend_name: str) -> object:
            hit = RawSearchHit(
                file_path="/repo/src/main.rs",
                matched_text="pattern",
                backend=backend_name,
                intent=SearchIntent.CONFIG_LOOKUP,
                result_kind=ResultKind.SOURCE_CODE,
                query="pattern",
            )
            return normalize(hit, "2026-03-20T00:00:00Z", DiagnosticStatus.PASS)

        preferred_rec = make_rec(preferred_backend.name)
        fallback_rec = make_rec(fallback_backend.name)

        # Both records must have identical field names (same shape)
        assert vars(preferred_rec).keys() == vars(fallback_rec).keys()
