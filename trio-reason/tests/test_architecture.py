"""Tests for trio_reason.architecture."""

from __future__ import annotations

import pytest

from trio_reason.architecture import (
    ALL_CAPABILITIES,
    ALL_EXTENSION_POINTS,
    ALL_FLOWS,
    DESIGN_PRINCIPLES,
    CapabilityRole,
    DesignPrinciple,
    ExtensionPoint,
    OperatingFlow,
)


class TestOperatingFlow:
    def test_all_flows_count(self) -> None:
        assert len(ALL_FLOWS) == 3

    def test_flow_values_unique(self) -> None:
        values = [f.value for f in ALL_FLOWS]
        assert len(values) == len(set(values))

    def test_initial_setup_value(self) -> None:
        assert OperatingFlow.InitialSetup.value == "initial-setup"

    def test_layered_diagnosis_value(self) -> None:
        assert OperatingFlow.LayeredDiagnosis.value == "layered-diagnosis"

    def test_maintenance_drift_value(self) -> None:
        assert OperatingFlow.MaintenanceDrift.value == "maintenance-drift"

    def test_flow_labels_non_empty(self) -> None:
        for flow in ALL_FLOWS:
            assert flow.label()

    def test_initial_setup_label(self) -> None:
        assert OperatingFlow.InitialSetup.label() == "Initial Setup"

    def test_initial_setup_has_six_steps(self) -> None:
        assert len(OperatingFlow.InitialSetup.steps()) == 6

    def test_layered_diagnosis_has_six_steps(self) -> None:
        assert len(OperatingFlow.LayeredDiagnosis.steps()) == 6

    def test_maintenance_drift_has_six_steps(self) -> None:
        assert len(OperatingFlow.MaintenanceDrift.steps()) == 6

    def test_all_flow_steps_non_empty(self) -> None:
        for flow in ALL_FLOWS:
            for step in flow.steps():
                assert step

    def test_steps_returns_list(self) -> None:
        assert isinstance(OperatingFlow.InitialSetup.steps(), list)


class TestCapabilityRole:
    def test_all_capabilities_count(self) -> None:
        assert len(ALL_CAPABILITIES) == 3

    def test_capability_values_unique(self) -> None:
        values = [c.value for c in ALL_CAPABILITIES]
        assert len(values) == len(set(values))

    def test_discover_value(self) -> None:
        assert CapabilityRole.Discover.value == "discover"

    def test_searcher_value(self) -> None:
        assert CapabilityRole.Searcher.value == "searcher"

    def test_trace_value(self) -> None:
        assert CapabilityRole.Trace.value == "trace"

    def test_capability_labels_non_empty(self) -> None:
        for cap in ALL_CAPABILITIES:
            assert cap.label()

    def test_discover_and_searcher_emit_static(self) -> None:
        assert CapabilityRole.Discover.evidence_kind() == "Static"
        assert CapabilityRole.Searcher.evidence_kind() == "Static"

    def test_trace_emits_runtime(self) -> None:
        assert CapabilityRole.Trace.evidence_kind() == "Runtime"

    def test_source_domains_non_empty(self) -> None:
        for cap in ALL_CAPABILITIES:
            assert cap.source_domain()

    def test_descriptions_non_empty(self) -> None:
        for cap in ALL_CAPABILITIES:
            assert cap.description()

    def test_trace_source_domain_mentions_runtime(self) -> None:
        assert "runtime" in CapabilityRole.Trace.source_domain().lower()

    def test_discover_source_domain_mentions_filesystem(self) -> None:
        assert "filesystem" in CapabilityRole.Discover.source_domain().lower()


class TestExtensionPoint:
    def test_all_extension_points_count(self) -> None:
        assert len(ALL_EXTENSION_POINTS) == 4

    def test_extension_point_values_unique(self) -> None:
        values = [e.value for e in ALL_EXTENSION_POINTS]
        assert len(values) == len(set(values))

    def test_new_probe_family_value(self) -> None:
        assert ExtensionPoint.NewProbeFamily.value == "new-probe-family"

    def test_new_search_backend_value(self) -> None:
        assert ExtensionPoint.NewSearchBackend.value == "new-search-backend"

    def test_new_trace_target_value(self) -> None:
        assert ExtensionPoint.NewTraceTarget.value == "new-trace-target"

    def test_mcp_exposure_value(self) -> None:
        assert ExtensionPoint.McpExposure.value == "mcp-exposure"

    def test_no_extension_point_requires_schema_change(self) -> None:
        for ep in ALL_EXTENSION_POINTS:
            assert ep.schema_change_required() is False

    def test_labels_non_empty(self) -> None:
        for ep in ALL_EXTENSION_POINTS:
            assert ep.label()

    def test_descriptions_non_empty(self) -> None:
        for ep in ALL_EXTENSION_POINTS:
            assert ep.description()

    def test_new_probe_family_label_mentions_discover(self) -> None:
        assert "Discover" in ExtensionPoint.NewProbeFamily.label()

    def test_mcp_exposure_label_mentions_mcp(self) -> None:
        assert "MCP" in ExtensionPoint.McpExposure.label()


class TestDesignPrinciples:
    def test_design_principles_count(self) -> None:
        assert len(DESIGN_PRINCIPLES) == 5

    def test_all_names_non_empty(self) -> None:
        for p in DESIGN_PRINCIPLES:
            assert p.name

    def test_all_descriptions_non_empty(self) -> None:
        for p in DESIGN_PRINCIPLES:
            assert p.description

    def test_names_unique(self) -> None:
        names = [p.name for p in DESIGN_PRINCIPLES]
        assert len(names) == len(set(names))

    def test_schema_stability_principle_present(self) -> None:
        names = [p.name for p in DESIGN_PRINCIPLES]
        assert any("Schema stability" in n for n in names)

    def test_no_quartet_dependency_principle_present(self) -> None:
        names = [p.name for p in DESIGN_PRINCIPLES]
        assert any("Quartet" in n for n in names)

    def test_design_principle_is_frozen(self) -> None:
        p = DESIGN_PRINCIPLES[0]
        with pytest.raises((AttributeError, TypeError)):
            p.name = "mutated"  # type: ignore[misc]
