"""Tests for trio_reason.boundary."""

from __future__ import annotations

import json

import pytest

from trio_reason.boundary import (
    ALL_PYTHON_ROLES,
    ALL_RUST_ROLES,
    BridgeMessage,
    BridgeMessageKind,
    PythonRole,
    RustRole,
    decode_message,
    encode_message,
)


class TestRustRole:
    def test_cli_value(self) -> None:
        assert RustRole.CLI.value == "cli"

    def test_host_interaction_value(self) -> None:
        assert RustRole.HOST_INTERACTION.value == "host-interaction"

    def test_orchestration_value(self) -> None:
        assert RustRole.ORCHESTRATION.value == "orchestration"

    def test_normalization_value(self) -> None:
        assert RustRole.NORMALIZATION.value == "normalization"

    def test_mcp_exposure_value(self) -> None:
        assert RustRole.MCP_EXPOSURE.value == "mcp-exposure"

    def test_all_rust_roles_count(self) -> None:
        assert len(ALL_RUST_ROLES) == 5

    def test_all_rust_roles_values_unique(self) -> None:
        values = [r.value for r in ALL_RUST_ROLES]
        assert len(values) == len(set(values))

    def test_all_rust_roles_contains_all_members(self) -> None:
        for role in RustRole:
            assert role in ALL_RUST_ROLES


class TestPythonRole:
    def test_reasoning_value(self) -> None:
        assert PythonRole.REASONING.value == "reasoning"

    def test_interpretation_value(self) -> None:
        assert PythonRole.INTERPRETATION.value == "interpretation"

    def test_synthesis_value(self) -> None:
        assert PythonRole.SYNTHESIS.value == "synthesis"

    def test_narrative_generation_value(self) -> None:
        assert PythonRole.NARRATIVE_GENERATION.value == "narrative-generation"

    def test_all_python_roles_count(self) -> None:
        assert len(ALL_PYTHON_ROLES) == 4

    def test_all_python_roles_values_unique(self) -> None:
        values = [r.value for r in ALL_PYTHON_ROLES]
        assert len(values) == len(set(values))

    def test_all_python_roles_contains_all_members(self) -> None:
        for role in PythonRole:
            assert role in ALL_PYTHON_ROLES


class TestBridgeMessageKind:
    def test_evidence_for_reasoning_value(self) -> None:
        assert BridgeMessageKind.EVIDENCE_FOR_REASONING.value == "evidence-for-reasoning"

    def test_reasoning_response_value(self) -> None:
        assert BridgeMessageKind.REASONING_RESPONSE.value == "reasoning-response"

    def test_shutdown_value(self) -> None:
        assert BridgeMessageKind.SHUTDOWN.value == "shutdown"


class TestBridgeMessage:
    def test_construction_defaults(self) -> None:
        msg = BridgeMessage(kind=BridgeMessageKind.SHUTDOWN, payload="{}")
        assert msg.kind == BridgeMessageKind.SHUTDOWN
        assert msg.payload == "{}"
        assert msg.metadata == {}

    def test_construction_with_metadata(self) -> None:
        msg = BridgeMessage(
            kind=BridgeMessageKind.EVIDENCE_FOR_REASONING,
            payload="[]",
            metadata={"run_id": "abc123"},
        )
        assert msg.metadata["run_id"] == "abc123"

    def test_metadata_is_independent(self) -> None:
        msg1 = BridgeMessage(kind=BridgeMessageKind.SHUTDOWN, payload="{}")
        msg2 = BridgeMessage(kind=BridgeMessageKind.SHUTDOWN, payload="{}")
        msg1.metadata["x"] = "1"
        assert "x" not in msg2.metadata


class TestEncodeMessage:
    def test_shutdown_contains_kind(self) -> None:
        msg = BridgeMessage(kind=BridgeMessageKind.SHUTDOWN, payload="{}")
        line = encode_message(msg)
        assert '"kind":"shutdown"' in line

    def test_shutdown_contains_payload(self) -> None:
        msg = BridgeMessage(kind=BridgeMessageKind.SHUTDOWN, payload="{}")
        line = encode_message(msg)
        assert '"payload":"{}"' in line

    def test_produces_single_line(self) -> None:
        msg = BridgeMessage(kind=BridgeMessageKind.SHUTDOWN, payload="{}")
        line = encode_message(msg)
        assert "\n" not in line

    def test_output_is_valid_json(self) -> None:
        msg = BridgeMessage(kind=BridgeMessageKind.EVIDENCE_FOR_REASONING, payload="[]")
        line = encode_message(msg)
        parsed = json.loads(line)
        assert parsed["kind"] == "evidence-for-reasoning"

    def test_metadata_included(self) -> None:
        msg = BridgeMessage(
            kind=BridgeMessageKind.REASONING_RESPONSE,
            payload="{}",
            metadata={"session": "s1"},
        )
        line = encode_message(msg)
        parsed = json.loads(line)
        assert parsed["metadata"]["session"] == "s1"

    def test_payload_with_special_characters(self) -> None:
        msg = BridgeMessage(
            kind=BridgeMessageKind.EVIDENCE_FOR_REASONING, payload='{"note":"a\\nb"}'
        )
        line = encode_message(msg)
        # must be valid JSON and a single line
        assert "\n" not in line
        json.loads(line)  # must not raise


class TestDecodeMessage:
    def test_decode_shutdown(self) -> None:
        line = json.dumps({"kind": "shutdown", "payload": "{}", "metadata": {}})
        msg = decode_message(line)
        assert msg is not None
        assert msg.kind == BridgeMessageKind.SHUTDOWN
        assert msg.payload == "{}"

    def test_decode_evidence_for_reasoning(self) -> None:
        line = json.dumps(
            {
                "kind": "evidence-for-reasoning",
                "payload": "[]",
                "metadata": {"run_id": "r42"},
            }
        )
        msg = decode_message(line)
        assert msg is not None
        assert msg.kind == BridgeMessageKind.EVIDENCE_FOR_REASONING
        assert msg.metadata.get("run_id") == "r42"

    def test_decode_reasoning_response(self) -> None:
        line = json.dumps({"kind": "reasoning-response", "payload": "{}", "metadata": {}})
        msg = decode_message(line)
        assert msg is not None
        assert msg.kind == BridgeMessageKind.REASONING_RESPONSE

    def test_decode_missing_kind_returns_none(self) -> None:
        line = json.dumps({"payload": "{}", "metadata": {}})
        assert decode_message(line) is None

    def test_decode_unknown_kind_returns_none(self) -> None:
        line = json.dumps({"kind": "unknown-kind", "payload": "{}", "metadata": {}})
        assert decode_message(line) is None

    def test_decode_invalid_json_returns_none(self) -> None:
        assert decode_message("not json at all") is None

    def test_decode_missing_payload_returns_none(self) -> None:
        line = json.dumps({"kind": "shutdown", "metadata": {}})
        assert decode_message(line) is None

    def test_decode_metadata_defaults_to_empty(self) -> None:
        line = json.dumps({"kind": "shutdown", "payload": "{}"})
        msg = decode_message(line)
        assert msg is not None
        assert msg.metadata == {}

    def test_round_trip_encode_decode(self) -> None:
        original = BridgeMessage(
            kind=BridgeMessageKind.EVIDENCE_FOR_REASONING,
            payload='{"records":[]}',
            metadata={"run_id": "xyz"},
        )
        line = encode_message(original)
        decoded = decode_message(line)
        assert decoded is not None
        assert decoded.kind == original.kind
        assert decoded.payload == original.payload
        assert decoded.metadata == original.metadata
