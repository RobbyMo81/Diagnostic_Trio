"""Tests for the shared evidence schema."""

import pytest
from trio_reason.evidence import DiagnosticStatus, EvidenceKind, EvidenceRecord


def _minimal_record(**overrides: object) -> EvidenceRecord:
    defaults: dict[str, object] = dict(
        source_tool="discover",
        timestamp="2026-03-19T22:00:00Z",
        target="/etc/hosts",
        probe_family="config-parse",
        status=DiagnosticStatus.PASS,
        summary="Host file parsed successfully.",
        kind=EvidenceKind.STATIC,
    )
    defaults.update(overrides)
    return EvidenceRecord(**defaults)  # type: ignore[arg-type]


class TestDiagnosticStatus:
    def test_all_statuses_exist(self) -> None:
        expected = {"blocked", "pass", "fail", "partial", "not-tested"}
        actual = {s.value for s in DiagnosticStatus}
        assert actual == expected

    def test_string_value_is_lowercase(self) -> None:
        for status in DiagnosticStatus:
            assert status.value == status.value.lower()


class TestEvidenceKind:
    def test_kinds(self) -> None:
        assert EvidenceKind.STATIC.value == "static"
        assert EvidenceKind.RUNTIME.value == "runtime"


class TestEvidenceRecord:
    def test_minimal_record_defaults(self) -> None:
        rec = _minimal_record()
        assert rec.source_tool == "discover"
        assert rec.status == DiagnosticStatus.PASS
        assert rec.kind == EvidenceKind.STATIC
        assert rec.layer is None
        assert rec.raw_refs == []
        assert rec.confidence == 1.0
        assert rec.interpretation is None
        assert rec.metadata == {}

    def test_runtime_kind(self) -> None:
        rec = _minimal_record(
            source_tool="trace",
            target="eth0",
            probe_family="interface-probe",
            status=DiagnosticStatus.FAIL,
            summary="Interface has no carrier.",
            kind=EvidenceKind.RUNTIME,
            layer=1,
        )
        assert rec.kind == EvidenceKind.RUNTIME
        assert rec.layer == 1

    def test_valid_layers(self) -> None:
        for layer in range(1, 8):
            rec = _minimal_record(layer=layer)
            assert rec.layer == layer

    def test_invalid_layer_zero_raises(self) -> None:
        with pytest.raises(ValueError, match="layer"):
            _minimal_record(layer=0)

    def test_invalid_layer_eight_raises(self) -> None:
        with pytest.raises(ValueError, match="layer"):
            _minimal_record(layer=8)

    def test_confidence_out_of_range_raises(self) -> None:
        with pytest.raises(ValueError, match="confidence"):
            _minimal_record(confidence=1.1)

    def test_raw_refs_and_metadata(self) -> None:
        rec = _minimal_record(
            raw_refs=["line 42: foo=bar"],
            metadata={"probe_version": "1.0"},
        )
        assert rec.raw_refs == ["line 42: foo=bar"]
        assert rec.metadata["probe_version"] == "1.0"

    def test_all_diagnostic_statuses_usable(self) -> None:
        for status in DiagnosticStatus:
            rec = _minimal_record(status=status)
            assert rec.status == status

    def test_blocked_status(self) -> None:
        rec = _minimal_record(status=DiagnosticStatus.BLOCKED)
        assert rec.status.value == "blocked"

    def test_not_tested_status(self) -> None:
        rec = _minimal_record(status=DiagnosticStatus.NOT_TESTED)
        assert rec.status.value == "not-tested"

    def test_partial_status(self) -> None:
        rec = _minimal_record(status=DiagnosticStatus.PARTIAL)
        assert rec.status.value == "partial"

    def test_interpretation_field(self) -> None:
        rec = _minimal_record(interpretation="This indicates a DNS misconfiguration.")
        assert rec.interpretation == "This indicates a DNS misconfiguration."
