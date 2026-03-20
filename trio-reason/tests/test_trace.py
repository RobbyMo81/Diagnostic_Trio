"""Tests for trio_reason.trace — Trace runtime evidence capture."""

from trio_reason.trace import TraceTarget, capture
from trio_reason.evidence import DiagnosticStatus, EvidenceKind

TS = "2026-03-19T23:00:00Z"


class TestTraceTargetValues:
    def test_processes_value(self) -> None:
        assert TraceTarget.PROCESSES.value == "processes"

    def test_listeners_and_ports_value(self) -> None:
        assert TraceTarget.LISTENERS_AND_PORTS.value == "listeners-and-ports"

    def test_routes_and_interfaces_value(self) -> None:
        assert TraceTarget.ROUTES_AND_INTERFACES.value == "routes-and-interfaces"

    def test_sessions_value(self) -> None:
        assert TraceTarget.SESSIONS.value == "sessions"

    def test_logs_value(self) -> None:
        assert TraceTarget.LOGS.value == "logs"

    def test_payload_or_protocol_value(self) -> None:
        assert TraceTarget.PAYLOAD_OR_PROTOCOL.value == "payload-or-protocol"

    def test_runtime_dependencies_value(self) -> None:
        assert TraceTarget.RUNTIME_DEPENDENCIES.value == "runtime-dependencies"

    def test_bind_or_transport_anomaly_value(self) -> None:
        assert TraceTarget.BIND_OR_TRANSPORT_ANOMALY.value == "bind-or-transport-anomaly"


class TestTraceTargetDefaultLayer:
    def test_processes_maps_to_l7(self) -> None:
        assert TraceTarget.PROCESSES.default_layer() == 7

    def test_listeners_and_ports_maps_to_l4(self) -> None:
        assert TraceTarget.LISTENERS_AND_PORTS.default_layer() == 4

    def test_routes_and_interfaces_maps_to_l3(self) -> None:
        assert TraceTarget.ROUTES_AND_INTERFACES.default_layer() == 3

    def test_sessions_maps_to_l5(self) -> None:
        assert TraceTarget.SESSIONS.default_layer() == 5

    def test_logs_maps_to_l7(self) -> None:
        assert TraceTarget.LOGS.default_layer() == 7

    def test_payload_or_protocol_maps_to_l6(self) -> None:
        assert TraceTarget.PAYLOAD_OR_PROTOCOL.default_layer() == 6

    def test_runtime_dependencies_maps_to_l7(self) -> None:
        assert TraceTarget.RUNTIME_DEPENDENCIES.default_layer() == 7

    def test_bind_or_transport_anomaly_maps_to_l4(self) -> None:
        assert TraceTarget.BIND_OR_TRANSPORT_ANOMALY.default_layer() == 4


class TestCaptureRequiredFields:
    def test_source_tool_is_trace(self) -> None:
        rec = capture(TS, "nginx", TraceTarget.PROCESSES, DiagnosticStatus.PASS, "Running.")
        assert rec.source_tool == "trace"

    def test_kind_is_runtime(self) -> None:
        rec = capture(TS, "nginx", TraceTarget.PROCESSES, DiagnosticStatus.PASS, "Running.")
        assert rec.kind == EvidenceKind.RUNTIME

    def test_assigns_layer_from_target(self) -> None:
        rec = capture(TS, ":443", TraceTarget.LISTENERS_AND_PORTS, DiagnosticStatus.PASS, "Listening.")
        assert rec.layer == 4  # Transport

    def test_probe_family_set_from_target(self) -> None:
        rec = capture(TS, "eth0", TraceTarget.ROUTES_AND_INTERFACES, DiagnosticStatus.PASS, "Route OK.")
        assert rec.probe_family == "routes-and-interfaces"

    def test_trace_target_in_metadata(self) -> None:
        rec = capture(TS, "eth0", TraceTarget.ROUTES_AND_INTERFACES, DiagnosticStatus.PASS, "Route OK.")
        assert rec.metadata.get("trace_target") == "routes-and-interfaces"


class TestCaptureLayerSpotChecks:
    def test_sessions_is_session_layer(self) -> None:
        rec = capture(TS, "ssh", TraceTarget.SESSIONS, DiagnosticStatus.PASS, "Session active.")
        assert rec.layer == 5  # Session

    def test_payload_is_presentation_layer(self) -> None:
        rec = capture(TS, "http", TraceTarget.PAYLOAD_OR_PROTOCOL, DiagnosticStatus.FAIL, "Bad framing.")
        assert rec.layer == 6  # Presentation

    def test_runtime_deps_is_application_layer(self) -> None:
        rec = capture(TS, "dns", TraceTarget.RUNTIME_DEPENDENCIES, DiagnosticStatus.PASS, "Resolver reachable.")
        assert rec.layer == 7  # Application

    def test_bind_anomaly_is_transport_layer(self) -> None:
        rec = capture(TS, ":8080", TraceTarget.BIND_OR_TRANSPORT_ANOMALY, DiagnosticStatus.FAIL, "Port in use.")
        assert rec.layer == 4  # Transport


class TestCaptureStatuses:
    def test_status_fail(self) -> None:
        rec = capture(TS, ":8080", TraceTarget.BIND_OR_TRANSPORT_ANOMALY, DiagnosticStatus.FAIL, "Port in use.")
        assert rec.status == DiagnosticStatus.FAIL

    def test_status_blocked(self) -> None:
        rec = capture(TS, "/var/log/secure", TraceTarget.LOGS, DiagnosticStatus.BLOCKED, "Permission denied.")
        assert rec.status == DiagnosticStatus.BLOCKED

    def test_status_partial(self) -> None:
        rec = capture(TS, "dns", TraceTarget.RUNTIME_DEPENDENCIES, DiagnosticStatus.PARTIAL, "Some resolvers unreachable.")
        assert rec.status == DiagnosticStatus.PARTIAL

    def test_status_not_tested(self) -> None:
        rec = capture(TS, "lo", TraceTarget.ROUTES_AND_INTERFACES, DiagnosticStatus.NOT_TESTED, "Loopback skipped.")
        assert rec.status == DiagnosticStatus.NOT_TESTED

    def test_status_pass(self) -> None:
        rec = capture(TS, "nginx", TraceTarget.PROCESSES, DiagnosticStatus.PASS, "Running.")
        assert rec.status == DiagnosticStatus.PASS


class TestCaptureMetadataIsolation:
    def test_metadata_does_not_bleed_between_calls(self) -> None:
        rec1 = capture(TS, "nginx", TraceTarget.PROCESSES, DiagnosticStatus.PASS, "Running.")
        rec2 = capture(TS, ":443", TraceTarget.LISTENERS_AND_PORTS, DiagnosticStatus.PASS, "Listening.")
        assert rec1.metadata.get("trace_target") == "processes"
        assert rec2.metadata.get("trace_target") == "listeners-and-ports"
