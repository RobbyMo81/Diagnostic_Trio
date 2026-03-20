"""Tests for trio_reason.discover — Discover evidence classification."""

import pytest

from trio_reason.discover import DiscoverProbeFamily, DiscoverScope, classify
from trio_reason.evidence import DiagnosticStatus, EvidenceKind

TS = "2026-03-19T22:00:00Z"


class TestDiscoverProbeFamilyValues:
    def test_config_parse_value(self) -> None:
        assert DiscoverProbeFamily.CONFIG_PARSE.value == "config-parse"

    def test_dependency_trace_value(self) -> None:
        assert DiscoverProbeFamily.DEPENDENCY_TRACE.value == "dependency-trace"

    def test_host_interface_value(self) -> None:
        assert DiscoverProbeFamily.HOST_INTERFACE.value == "host-interface"

    def test_routing_config_value(self) -> None:
        assert DiscoverProbeFamily.ROUTING_CONFIG.value == "routing-config"

    def test_port_config_value(self) -> None:
        assert DiscoverProbeFamily.PORT_CONFIG.value == "port-config"

    def test_tls_config_value(self) -> None:
        assert DiscoverProbeFamily.TLS_CONFIG.value == "tls-config"

    def test_service_config_value(self) -> None:
        assert DiscoverProbeFamily.SERVICE_CONFIG.value == "service-config"


class TestDiscoverProbeFamilyDefaultLayer:
    def test_host_interface_maps_to_l2(self) -> None:
        assert DiscoverProbeFamily.HOST_INTERFACE.default_layer() == 2

    def test_routing_config_maps_to_l3(self) -> None:
        assert DiscoverProbeFamily.ROUTING_CONFIG.default_layer() == 3

    def test_port_config_maps_to_l4(self) -> None:
        assert DiscoverProbeFamily.PORT_CONFIG.default_layer() == 4

    def test_tls_config_maps_to_l6(self) -> None:
        assert DiscoverProbeFamily.TLS_CONFIG.default_layer() == 6

    def test_config_parse_maps_to_l7(self) -> None:
        assert DiscoverProbeFamily.CONFIG_PARSE.default_layer() == 7

    def test_dependency_trace_maps_to_l7(self) -> None:
        assert DiscoverProbeFamily.DEPENDENCY_TRACE.default_layer() == 7

    def test_service_config_maps_to_l7(self) -> None:
        assert DiscoverProbeFamily.SERVICE_CONFIG.default_layer() == 7


class TestDiscoverScope:
    def test_repository_value(self) -> None:
        assert DiscoverScope.REPOSITORY.value == "repository"

    def test_host_value(self) -> None:
        assert DiscoverScope.HOST.value == "host"


class TestClassifyRequiredFields:
    def test_source_tool_is_discover(self) -> None:
        rec = classify(
            DiscoverScope.REPOSITORY,
            TS,
            "Cargo.toml",
            DiscoverProbeFamily.DEPENDENCY_TRACE,
            DiagnosticStatus.PASS,
            "Lock file present and consistent.",
        )
        assert rec.source_tool == "discover"

    def test_kind_is_static(self) -> None:
        rec = classify(
            DiscoverScope.HOST,
            TS,
            "/etc/resolv.conf",
            DiscoverProbeFamily.CONFIG_PARSE,
            DiagnosticStatus.PASS,
            "Resolver config present.",
        )
        assert rec.kind == EvidenceKind.STATIC

    def test_assigns_layer_from_probe_family(self) -> None:
        rec = classify(
            DiscoverScope.HOST,
            TS,
            "/etc/network/interfaces",
            DiscoverProbeFamily.HOST_INTERFACE,
            DiagnosticStatus.PASS,
            "Interface config found.",
        )
        assert rec.layer == 2  # Data Link

    def test_probe_family_name_stored(self) -> None:
        rec = classify(
            DiscoverScope.REPOSITORY,
            TS,
            "pyproject.toml",
            DiscoverProbeFamily.DEPENDENCY_TRACE,
            DiagnosticStatus.PASS,
            "Dependencies pinned.",
        )
        assert rec.probe_family == "dependency-trace"


class TestClassifyScope:
    def test_repository_scope_in_metadata(self) -> None:
        rec = classify(
            DiscoverScope.REPOSITORY,
            TS,
            "pyproject.toml",
            DiscoverProbeFamily.DEPENDENCY_TRACE,
            DiagnosticStatus.PASS,
            "Dependencies pinned.",
        )
        assert rec.metadata.get("discover_scope") == "repository"

    def test_host_scope_in_metadata(self) -> None:
        rec = classify(
            DiscoverScope.HOST,
            TS,
            "/etc/hosts",
            DiscoverProbeFamily.CONFIG_PARSE,
            DiagnosticStatus.PASS,
            "Hosts file readable.",
        )
        assert rec.metadata.get("discover_scope") == "host"


class TestClassifyStatuses:
    def test_status_fail(self) -> None:
        rec = classify(
            DiscoverScope.REPOSITORY,
            TS,
            "requirements.txt",
            DiscoverProbeFamily.DEPENDENCY_TRACE,
            DiagnosticStatus.FAIL,
            "Pinned version has known CVE.",
        )
        assert rec.status == DiagnosticStatus.FAIL

    def test_status_blocked(self) -> None:
        rec = classify(
            DiscoverScope.HOST,
            TS,
            "/etc/shadow",
            DiscoverProbeFamily.CONFIG_PARSE,
            DiagnosticStatus.BLOCKED,
            "Permission denied reading shadow file.",
        )
        assert rec.status == DiagnosticStatus.BLOCKED

    def test_status_partial(self) -> None:
        rec = classify(
            DiscoverScope.REPOSITORY,
            TS,
            "src/",
            DiscoverProbeFamily.SERVICE_CONFIG,
            DiagnosticStatus.PARTIAL,
            "Some service configs missing.",
        )
        assert rec.status == DiagnosticStatus.PARTIAL

    def test_status_not_tested(self) -> None:
        rec = classify(
            DiscoverScope.HOST,
            TS,
            "/proc/net/route",
            DiscoverProbeFamily.ROUTING_CONFIG,
            DiagnosticStatus.NOT_TESTED,
            "Route table probe skipped.",
        )
        assert rec.status == DiagnosticStatus.NOT_TESTED

    def test_status_pass(self) -> None:
        rec = classify(
            DiscoverScope.HOST,
            TS,
            "/etc/hosts",
            DiscoverProbeFamily.CONFIG_PARSE,
            DiagnosticStatus.PASS,
            "Hosts file readable.",
        )
        assert rec.status == DiagnosticStatus.PASS


class TestClassifyLayerSpotChecks:
    def test_tls_config_is_presentation_layer(self) -> None:
        rec = classify(
            DiscoverScope.REPOSITORY,
            TS,
            "certs/server.pem",
            DiscoverProbeFamily.TLS_CONFIG,
            DiagnosticStatus.PASS,
            "Certificate valid.",
        )
        assert rec.layer == 6  # Presentation

    def test_routing_is_network_layer(self) -> None:
        rec = classify(
            DiscoverScope.HOST,
            TS,
            "/etc/iproute2/rt_tables",
            DiscoverProbeFamily.ROUTING_CONFIG,
            DiagnosticStatus.PASS,
            "Routing tables found.",
        )
        assert rec.layer == 3  # Network

    def test_port_config_is_transport_layer(self) -> None:
        rec = classify(
            DiscoverScope.HOST,
            TS,
            "/etc/services",
            DiscoverProbeFamily.PORT_CONFIG,
            DiagnosticStatus.PASS,
            "Service port definitions readable.",
        )
        assert rec.layer == 4  # Transport
