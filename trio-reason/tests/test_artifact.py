"""Tests for trio_reason.artifact — artifact write-back behaviour."""

from __future__ import annotations

import json
import os
import tempfile
from pathlib import Path

from trio_reason.artifact import ArtifactKind, append_record, format_record
from trio_reason.evidence import DiagnosticStatus, EvidenceKind, EvidenceRecord

TS = "2026-03-20T00:00:00Z"


def _record(**kwargs: object) -> EvidenceRecord:
    defaults: dict[str, object] = {
        "source_tool": "discover",
        "timestamp": TS,
        "target": "/etc/hosts",
        "probe_family": "config-parse",
        "status": DiagnosticStatus.PASS,
        "summary": "Host file parsed OK.",
        "kind": EvidenceKind.STATIC,
    }
    defaults.update(kwargs)
    return EvidenceRecord(**defaults)  # type: ignore[arg-type]


# ---------------------------------------------------------------------------
# ArtifactKind values
# ---------------------------------------------------------------------------


class TestArtifactKindValues:
    def test_discover_findings_value(self) -> None:
        assert ArtifactKind.DISCOVER_FINDINGS.value == "discover-findings"

    def test_searcher_findings_value(self) -> None:
        assert ArtifactKind.SEARCHER_FINDINGS.value == "searcher-findings"

    def test_trace_findings_value(self) -> None:
        assert ArtifactKind.TRACE_FINDINGS.value == "trace-findings"

    def test_three_artifact_kinds(self) -> None:
        assert len(ArtifactKind) == 3


# ---------------------------------------------------------------------------
# ArtifactKind.filename
# ---------------------------------------------------------------------------


class TestArtifactKindFilename:
    def test_discover_filename(self) -> None:
        assert ArtifactKind.DISCOVER_FINDINGS.filename == "discover-findings.jsonl"

    def test_searcher_filename(self) -> None:
        assert ArtifactKind.SEARCHER_FINDINGS.filename == "searcher-findings.jsonl"

    def test_trace_filename(self) -> None:
        assert ArtifactKind.TRACE_FINDINGS.filename == "trace-findings.jsonl"

    def test_all_filenames_have_jsonl_extension(self) -> None:
        for kind in ArtifactKind:
            assert kind.filename.endswith(".jsonl")

    def test_filename_includes_kind_value(self) -> None:
        for kind in ArtifactKind:
            assert kind.value in kind.filename


# ---------------------------------------------------------------------------
# format_record
# ---------------------------------------------------------------------------


class TestFormatRecord:
    def test_returns_valid_json(self) -> None:
        line = format_record(_record())
        obj = json.loads(line)
        assert isinstance(obj, dict)

    def test_source_tool_field(self) -> None:
        obj = json.loads(format_record(_record()))
        assert obj["source_tool"] == "discover"

    def test_timestamp_field(self) -> None:
        obj = json.loads(format_record(_record()))
        assert obj["timestamp"] == TS

    def test_target_field(self) -> None:
        obj = json.loads(format_record(_record()))
        assert obj["target"] == "/etc/hosts"

    def test_probe_family_field(self) -> None:
        obj = json.loads(format_record(_record()))
        assert obj["probe_family"] == "config-parse"

    def test_layer_null_when_absent(self) -> None:
        obj = json.loads(format_record(_record()))
        assert obj["layer"] is None

    def test_layer_present_when_set(self) -> None:
        obj = json.loads(format_record(_record(layer=7)))
        assert obj["layer"] == 7

    def test_status_uses_value(self) -> None:
        obj = json.loads(format_record(_record()))
        assert obj["status"] == "pass"

    def test_summary_field(self) -> None:
        obj = json.loads(format_record(_record()))
        assert obj["summary"] == "Host file parsed OK."

    def test_kind_uses_value(self) -> None:
        obj = json.loads(format_record(_record()))
        assert obj["kind"] == "static"

    def test_raw_refs_empty_list(self) -> None:
        obj = json.loads(format_record(_record()))
        assert obj["raw_refs"] == []

    def test_raw_refs_present_when_set(self) -> None:
        r = _record()
        r.raw_refs = ["line 42", "line 99"]
        obj = json.loads(format_record(r))
        assert obj["raw_refs"] == ["line 42", "line 99"]

    def test_confidence_field(self) -> None:
        obj = json.loads(format_record(_record()))
        assert obj["confidence"] == 1.0

    def test_interpretation_null_when_absent(self) -> None:
        obj = json.loads(format_record(_record()))
        assert obj["interpretation"] is None

    def test_interpretation_present_when_set(self) -> None:
        r = _record()
        r.interpretation = "Looks healthy."
        obj = json.loads(format_record(r))
        assert obj["interpretation"] == "Looks healthy."

    def test_metadata_empty_object(self) -> None:
        obj = json.loads(format_record(_record()))
        assert obj["metadata"] == {}

    def test_metadata_preserved(self) -> None:
        r = _record()
        r.metadata["scope"] = "repository"
        obj = json.loads(format_record(r))
        assert obj["metadata"]["scope"] == "repository"

    def test_no_embedded_newline(self) -> None:
        line = format_record(_record())
        assert "\n" not in line

    def test_all_statuses_serialise(self) -> None:
        for status in DiagnosticStatus:
            r = _record(status=status)
            obj = json.loads(format_record(r))
            assert obj["status"] == status.value

    def test_runtime_kind_serialises(self) -> None:
        r = _record(kind=EvidenceKind.RUNTIME)
        obj = json.loads(format_record(r))
        assert obj["kind"] == "runtime"

    def test_metadata_isolation_between_records(self) -> None:
        r1 = _record()
        r2 = _record()
        r1.metadata["x"] = "1"
        obj2 = json.loads(format_record(r2))
        assert obj2["metadata"] == {}

    def test_all_three_source_tools_serialise(self) -> None:
        for tool in ("discover", "searcher", "trace"):
            r = _record(source_tool=tool)
            obj = json.loads(format_record(r))
            assert obj["source_tool"] == tool


# ---------------------------------------------------------------------------
# append_record (file I/O)
# ---------------------------------------------------------------------------


class TestAppendRecord:
    def test_creates_file(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            path = Path(tmpdir) / "artifact.jsonl"
            assert not path.exists()
            append_record(path, _record())
            assert path.exists()

    def test_written_line_is_valid_json(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            path = Path(tmpdir) / "artifact.jsonl"
            append_record(path, _record())
            lines = path.read_text().splitlines()
            assert len(lines) == 1
            obj = json.loads(lines[0])
            assert obj["source_tool"] == "discover"

    def test_line_ends_with_newline(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            path = Path(tmpdir) / "artifact.jsonl"
            append_record(path, _record())
            content = path.read_text()
            assert content.endswith("\n")

    def test_second_append_adds_line(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            path = Path(tmpdir) / "artifact.jsonl"
            r1 = _record(target="host-a")
            r2 = _record(target="host-b")
            append_record(path, r1)
            append_record(path, r2)
            lines = path.read_text().splitlines()
            assert len(lines) == 2
            assert json.loads(lines[0])["target"] == "host-a"
            assert json.loads(lines[1])["target"] == "host-b"

    def test_does_not_overwrite_existing_content(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            path = Path(tmpdir) / "artifact.jsonl"
            path.write_text("prior-line\n", encoding="utf-8")
            append_record(path, _record())
            lines = path.read_text().splitlines()
            assert lines[0] == "prior-line"
            assert len(lines) == 2

    def test_accepts_str_path(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            path_str = os.path.join(tmpdir, "artifact.jsonl")
            append_record(path_str, _record())
            assert os.path.exists(path_str)

    def test_provenance_fields_all_present(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            path = Path(tmpdir) / "artifact.jsonl"
            r = _record(layer=4)
            r.raw_refs = ["excerpt"]
            r.interpretation = "Looks fine."
            r.metadata["key"] = "val"
            append_record(path, r)
            obj = json.loads(path.read_text().splitlines()[0])
            assert "source_tool" in obj
            assert "timestamp" in obj
            assert "target" in obj
            assert "probe_family" in obj
            assert "layer" in obj
            assert "status" in obj
            assert "summary" in obj
            assert "kind" in obj
            assert "raw_refs" in obj
            assert "confidence" in obj
            assert "interpretation" in obj
            assert "metadata" in obj
