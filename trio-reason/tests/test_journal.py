"""Tests for trio_reason.journal — shared journal workflow."""

from __future__ import annotations

import json
import os
import tempfile
from pathlib import Path

from trio_reason.journal import JournalEntry, JournalEventKind, append, format_line

TS = "2026-03-19T22:00:00Z"


def _entry(event_kind: JournalEventKind = JournalEventKind.TOOL_STARTED) -> JournalEntry:
    return JournalEntry(
        id="entry-001",
        timestamp=TS,
        tool="discover",
        event_kind=event_kind,
        summary="Test event.",
    )


# ---------------------------------------------------------------------------
# JournalEventKind values
# ---------------------------------------------------------------------------


class TestJournalEventKindValues:
    def test_tool_started_value(self) -> None:
        assert JournalEventKind.TOOL_STARTED.value == "tool-started"

    def test_finding_recorded_value(self) -> None:
        assert JournalEventKind.FINDING_RECORDED.value == "finding-recorded"

    def test_probe_completed_value(self) -> None:
        assert JournalEventKind.PROBE_COMPLETED.value == "probe-completed"

    def test_safety_gated_value(self) -> None:
        assert JournalEventKind.SAFETY_GATED.value == "safety-gated"

    def test_workspace_updated_value(self) -> None:
        assert JournalEventKind.WORKSPACE_UPDATED.value == "workspace-updated"

    def test_five_event_kinds(self) -> None:
        assert len(JournalEventKind) == 5


# ---------------------------------------------------------------------------
# JournalEntry construction
# ---------------------------------------------------------------------------


class TestJournalEntryConstruction:
    def test_required_fields_set(self) -> None:
        e = _entry()
        assert e.id == "entry-001"
        assert e.timestamp == TS
        assert e.tool == "discover"
        assert e.event_kind == JournalEventKind.TOOL_STARTED
        assert e.summary == "Test event."

    def test_evidence_ref_defaults_to_none(self) -> None:
        e = _entry()
        assert e.evidence_ref is None

    def test_metadata_defaults_to_empty(self) -> None:
        e = _entry()
        assert e.metadata == {}

    def test_evidence_ref_can_be_set(self) -> None:
        e = _entry()
        e.evidence_ref = "rec-99"
        assert e.evidence_ref == "rec-99"

    def test_metadata_can_be_populated(self) -> None:
        e = _entry()
        e.metadata["probe"] = "config-parse"
        assert e.metadata["probe"] == "config-parse"

    def test_metadata_isolation_between_instances(self) -> None:
        e1 = _entry()
        e2 = _entry()
        e1.metadata["x"] = "1"
        assert "x" not in e2.metadata


# ---------------------------------------------------------------------------
# format_line
# ---------------------------------------------------------------------------


class TestFormatLine:
    def test_returns_valid_json(self) -> None:
        line = format_line(_entry())
        obj = json.loads(line)
        assert isinstance(obj, dict)

    def test_id_field(self) -> None:
        obj = json.loads(format_line(_entry()))
        assert obj["id"] == "entry-001"

    def test_timestamp_field(self) -> None:
        obj = json.loads(format_line(_entry()))
        assert obj["timestamp"] == TS

    def test_tool_field(self) -> None:
        obj = json.loads(format_line(_entry()))
        assert obj["tool"] == "discover"

    def test_event_field_uses_value(self) -> None:
        obj = json.loads(format_line(_entry(JournalEventKind.FINDING_RECORDED)))
        assert obj["event"] == "finding-recorded"

    def test_summary_field(self) -> None:
        obj = json.loads(format_line(_entry()))
        assert obj["summary"] == "Test event."

    def test_evidence_ref_null_when_absent(self) -> None:
        obj = json.loads(format_line(_entry()))
        assert obj["evidence_ref"] is None

    def test_evidence_ref_present_when_set(self) -> None:
        e = _entry(JournalEventKind.FINDING_RECORDED)
        e.evidence_ref = "rec-42"
        obj = json.loads(format_line(e))
        assert obj["evidence_ref"] == "rec-42"

    def test_metadata_empty_object_when_absent(self) -> None:
        obj = json.loads(format_line(_entry()))
        assert obj["metadata"] == {}

    def test_metadata_preserved(self) -> None:
        e = _entry(JournalEventKind.PROBE_COMPLETED)
        e.metadata["layer"] = "7"
        e.metadata["probe"] = "config-parse"
        obj = json.loads(format_line(e))
        assert obj["metadata"]["layer"] == "7"
        assert obj["metadata"]["probe"] == "config-parse"

    def test_no_embedded_newline(self) -> None:
        line = format_line(_entry())
        assert "\n" not in line

    def test_all_five_event_kinds_serialise(self) -> None:
        for kind in JournalEventKind:
            line = format_line(_entry(kind))
            obj = json.loads(line)
            assert obj["event"] == kind.value

    def test_all_trio_tools_serialise(self) -> None:
        for tool in ("discover", "searcher", "trace"):
            e = JournalEntry(
                id="x",
                timestamp=TS,
                tool=tool,
                event_kind=JournalEventKind.TOOL_STARTED,
                summary="started",
            )
            obj = json.loads(format_line(e))
            assert obj["tool"] == tool


# ---------------------------------------------------------------------------
# append (file I/O)
# ---------------------------------------------------------------------------


class TestAppend:
    def test_creates_file(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            path = Path(tmpdir) / "journal.jsonl"
            assert not path.exists()
            append(path, _entry())
            assert path.exists()

    def test_written_line_is_valid_json(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            path = Path(tmpdir) / "journal.jsonl"
            append(path, _entry())
            lines = path.read_text().splitlines()
            assert len(lines) == 1
            obj = json.loads(lines[0])
            assert obj["id"] == "entry-001"

    def test_line_ends_with_newline(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            path = Path(tmpdir) / "journal.jsonl"
            append(path, _entry())
            content = path.read_text()
            assert content.endswith("\n")

    def test_second_append_adds_line(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            path = Path(tmpdir) / "journal.jsonl"
            e1 = JournalEntry(
                id="e1", timestamp=TS, tool="discover",
                event_kind=JournalEventKind.TOOL_STARTED, summary="first",
            )
            e2 = JournalEntry(
                id="e2", timestamp=TS, tool="searcher",
                event_kind=JournalEventKind.FINDING_RECORDED, summary="second",
            )
            append(path, e1)
            append(path, e2)
            lines = path.read_text().splitlines()
            assert len(lines) == 2
            assert json.loads(lines[0])["id"] == "e1"
            assert json.loads(lines[1])["id"] == "e2"

    def test_does_not_overwrite_existing_content(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            path = Path(tmpdir) / "journal.jsonl"
            path.write_text("existing-line\n", encoding="utf-8")
            append(path, _entry())
            lines = path.read_text().splitlines()
            assert lines[0] == "existing-line"
            assert len(lines) == 2

    def test_accepts_str_path(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            path_str = os.path.join(tmpdir, "journal.jsonl")
            append(path_str, _entry())
            assert os.path.exists(path_str)

    def test_evidence_ref_persisted(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            path = Path(tmpdir) / "journal.jsonl"
            e = _entry(JournalEventKind.FINDING_RECORDED)
            e.evidence_ref = "rec-77"
            append(path, e)
            obj = json.loads(path.read_text().splitlines()[0])
            assert obj["evidence_ref"] == "rec-77"
