"""Tests for trio_reason.safety — runtime safety gating."""

from __future__ import annotations

import pytest

from trio_reason.safety import SafetyLevel, SafetyPolicy, SafetyViolation, check_gate


class TestSafetyLevel:
    def test_read_only_value(self) -> None:
        assert SafetyLevel.READ_ONLY.value == 0

    def test_authorized_value(self) -> None:
        assert SafetyLevel.AUTHORIZED.value == 1

    def test_read_only_less_than_authorized(self) -> None:
        assert SafetyLevel.READ_ONLY < SafetyLevel.AUTHORIZED

    def test_read_only_label(self) -> None:
        assert SafetyLevel.READ_ONLY.label() == "read-only"

    def test_authorized_label(self) -> None:
        assert SafetyLevel.AUTHORIZED.label() == "authorized"


class TestSafetyPolicy:
    def test_read_only_policy_level(self) -> None:
        assert SafetyPolicy.read_only().level == SafetyLevel.READ_ONLY

    def test_authorized_policy_level(self) -> None:
        assert SafetyPolicy.authorized().level == SafetyLevel.AUTHORIZED

    def test_default_policy_is_read_only(self) -> None:
        assert SafetyPolicy().level == SafetyLevel.READ_ONLY


class TestCheckGate:
    # --- passing cases ---

    def test_gate_passes_when_granted_equals_required(self) -> None:
        check_gate("op", SafetyLevel.READ_ONLY, SafetyPolicy.read_only())

    def test_gate_passes_when_granted_exceeds_required(self) -> None:
        check_gate("op", SafetyLevel.READ_ONLY, SafetyPolicy.authorized())

    def test_gate_passes_authorized_when_authorized_granted(self) -> None:
        check_gate("op", SafetyLevel.AUTHORIZED, SafetyPolicy.authorized())

    def test_gate_returns_none_on_pass(self) -> None:
        # check_gate returns None implicitly on success; verify no exception raised
        check_gate("op", SafetyLevel.READ_ONLY, SafetyPolicy.read_only())

    # --- blocking cases ---

    def test_gate_raises_when_authorized_required_but_read_only_granted(self) -> None:
        with pytest.raises(SafetyViolation):
            check_gate("sessions", SafetyLevel.AUTHORIZED, SafetyPolicy.read_only())

    def test_violation_carries_operation(self) -> None:
        with pytest.raises(SafetyViolation) as exc_info:
            check_gate("payload-or-protocol", SafetyLevel.AUTHORIZED, SafetyPolicy.read_only())
        assert exc_info.value.operation == "payload-or-protocol"

    def test_violation_carries_required_level(self) -> None:
        with pytest.raises(SafetyViolation) as exc_info:
            check_gate("sessions", SafetyLevel.AUTHORIZED, SafetyPolicy.read_only())
        assert exc_info.value.required == SafetyLevel.AUTHORIZED

    def test_violation_carries_granted_level(self) -> None:
        with pytest.raises(SafetyViolation) as exc_info:
            check_gate("sessions", SafetyLevel.AUTHORIZED, SafetyPolicy.read_only())
        assert exc_info.value.granted == SafetyLevel.READ_ONLY

    def test_violation_message_contains_operation(self) -> None:
        with pytest.raises(SafetyViolation) as exc_info:
            check_gate("sessions", SafetyLevel.AUTHORIZED, SafetyPolicy.read_only())
        assert "sessions" in str(exc_info.value)

    def test_violation_message_contains_required_label(self) -> None:
        with pytest.raises(SafetyViolation) as exc_info:
            check_gate("sessions", SafetyLevel.AUTHORIZED, SafetyPolicy.read_only())
        assert "authorized" in str(exc_info.value)

    def test_violation_message_contains_granted_label(self) -> None:
        with pytest.raises(SafetyViolation) as exc_info:
            check_gate("sessions", SafetyLevel.AUTHORIZED, SafetyPolicy.read_only())
        assert "read-only" in str(exc_info.value)


class TestTraceTargetSafetyLevel:
    def test_sessions_requires_authorized(self) -> None:
        from trio_reason.trace import TraceTarget

        assert TraceTarget.SESSIONS.required_safety_level() == SafetyLevel.AUTHORIZED

    def test_payload_or_protocol_requires_authorized(self) -> None:
        from trio_reason.trace import TraceTarget

        assert TraceTarget.PAYLOAD_OR_PROTOCOL.required_safety_level() == SafetyLevel.AUTHORIZED

    def test_processes_is_read_only(self) -> None:
        from trio_reason.trace import TraceTarget

        assert TraceTarget.PROCESSES.required_safety_level() == SafetyLevel.READ_ONLY

    def test_listeners_and_ports_is_read_only(self) -> None:
        from trio_reason.trace import TraceTarget

        assert TraceTarget.LISTENERS_AND_PORTS.required_safety_level() == SafetyLevel.READ_ONLY

    def test_routes_and_interfaces_is_read_only(self) -> None:
        from trio_reason.trace import TraceTarget

        assert TraceTarget.ROUTES_AND_INTERFACES.required_safety_level() == SafetyLevel.READ_ONLY

    def test_logs_is_read_only(self) -> None:
        from trio_reason.trace import TraceTarget

        assert TraceTarget.LOGS.required_safety_level() == SafetyLevel.READ_ONLY

    def test_runtime_dependencies_is_read_only(self) -> None:
        from trio_reason.trace import TraceTarget

        assert TraceTarget.RUNTIME_DEPENDENCIES.required_safety_level() == SafetyLevel.READ_ONLY

    def test_bind_or_transport_anomaly_is_read_only(self) -> None:
        from trio_reason.trace import TraceTarget

        assert TraceTarget.BIND_OR_TRANSPORT_ANOMALY.required_safety_level() == SafetyLevel.READ_ONLY


class TestDiscoverScopeSafetyLevel:
    def test_repository_is_read_only(self) -> None:
        from trio_reason.discover import DiscoverScope

        assert DiscoverScope.REPOSITORY.required_safety_level() == SafetyLevel.READ_ONLY

    def test_host_requires_authorized(self) -> None:
        from trio_reason.discover import DiscoverScope

        assert DiscoverScope.HOST.required_safety_level() == SafetyLevel.AUTHORIZED
