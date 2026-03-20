"""Tests for trio_reason.layer — OSI layer model and status propagation."""

import pytest

from trio_reason.evidence import DiagnosticStatus
from trio_reason.layer import (
    ALL_LAYERS,
    OsiLayer,
    effective_status,
    status_blocks_upper,
)


class TestOsiLayer:
    def test_numeric_values_are_correct(self) -> None:
        assert OsiLayer.PHYSICAL.value == 1
        assert OsiLayer.DATA_LINK.value == 2
        assert OsiLayer.NETWORK.value == 3
        assert OsiLayer.TRANSPORT.value == 4
        assert OsiLayer.SESSION.value == 5
        assert OsiLayer.PRESENTATION.value == 6
        assert OsiLayer.APPLICATION.value == 7

    def test_layer_names(self) -> None:
        assert OsiLayer.PHYSICAL.layer_name == "Physical"
        assert OsiLayer.DATA_LINK.layer_name == "Data Link"
        assert OsiLayer.NETWORK.layer_name == "Network"
        assert OsiLayer.TRANSPORT.layer_name == "Transport"
        assert OsiLayer.SESSION.layer_name == "Session"
        assert OsiLayer.PRESENTATION.layer_name == "Presentation"
        assert OsiLayer.APPLICATION.layer_name == "Application"

    def test_ordering_is_ascending(self) -> None:
        assert OsiLayer.PHYSICAL < OsiLayer.DATA_LINK
        assert OsiLayer.DATA_LINK < OsiLayer.NETWORK
        assert OsiLayer.NETWORK < OsiLayer.TRANSPORT
        assert OsiLayer.TRANSPORT < OsiLayer.SESSION
        assert OsiLayer.SESSION < OsiLayer.PRESENTATION
        assert OsiLayer.PRESENTATION < OsiLayer.APPLICATION

    def test_from_number_round_trips(self) -> None:
        for n in range(1, 8):
            layer = OsiLayer.from_number(n)
            assert layer.value == n

    def test_from_number_rejects_out_of_range(self) -> None:
        with pytest.raises(ValueError):
            OsiLayer.from_number(0)
        with pytest.raises(ValueError):
            OsiLayer.from_number(8)
        with pytest.raises(ValueError):
            OsiLayer.from_number(-1)

    def test_is_below(self) -> None:
        assert OsiLayer.PHYSICAL.is_below(OsiLayer.APPLICATION)
        assert OsiLayer.NETWORK.is_below(OsiLayer.TRANSPORT)
        assert not OsiLayer.APPLICATION.is_below(OsiLayer.PHYSICAL)
        assert not OsiLayer.TRANSPORT.is_below(OsiLayer.TRANSPORT)

    def test_layers_below_inclusive_physical(self) -> None:
        result = OsiLayer.PHYSICAL.layers_below_inclusive()
        assert result == [OsiLayer.PHYSICAL]

    def test_layers_below_inclusive_transport(self) -> None:
        result = OsiLayer.TRANSPORT.layers_below_inclusive()
        assert result == [
            OsiLayer.PHYSICAL,
            OsiLayer.DATA_LINK,
            OsiLayer.NETWORK,
            OsiLayer.TRANSPORT,
        ]

    def test_layers_below_inclusive_application(self) -> None:
        result = OsiLayer.APPLICATION.layers_below_inclusive()
        assert result == list(OsiLayer)

    def test_all_layers_has_seven_entries(self) -> None:
        assert len(ALL_LAYERS) == 7

    def test_all_layers_ordered_ascending(self) -> None:
        values = [l.value for l in ALL_LAYERS]
        assert values == sorted(values)
        assert values[0] == 1
        assert values[-1] == 7


class TestStatusBlocksUpper:
    def test_fail_blocks(self) -> None:
        assert status_blocks_upper(DiagnosticStatus.FAIL)

    def test_not_tested_blocks(self) -> None:
        assert status_blocks_upper(DiagnosticStatus.NOT_TESTED)

    def test_blocked_blocks(self) -> None:
        assert status_blocks_upper(DiagnosticStatus.BLOCKED)

    def test_partial_blocks(self) -> None:
        assert status_blocks_upper(DiagnosticStatus.PARTIAL)

    def test_pass_does_not_block(self) -> None:
        assert not status_blocks_upper(DiagnosticStatus.PASS)


class TestEffectiveStatus:
    def test_no_findings_passes_through_own_status(self) -> None:
        result = effective_status(OsiLayer.APPLICATION, DiagnosticStatus.PASS, [])
        assert result == DiagnosticStatus.PASS

    def test_fail_on_lower_layer_blocks_upper(self) -> None:
        findings = [(OsiLayer.PHYSICAL, DiagnosticStatus.FAIL)]
        result = effective_status(OsiLayer.APPLICATION, DiagnosticStatus.PASS, findings)
        assert result == DiagnosticStatus.BLOCKED

    def test_not_tested_on_lower_layer_blocks_upper(self) -> None:
        findings = [(OsiLayer.NETWORK, DiagnosticStatus.NOT_TESTED)]
        result = effective_status(OsiLayer.TRANSPORT, DiagnosticStatus.PASS, findings)
        assert result == DiagnosticStatus.BLOCKED

    def test_blocked_on_lower_layer_blocks_upper(self) -> None:
        findings = [(OsiLayer.DATA_LINK, DiagnosticStatus.BLOCKED)]
        result = effective_status(OsiLayer.APPLICATION, DiagnosticStatus.PASS, findings)
        assert result == DiagnosticStatus.BLOCKED

    def test_partial_on_lower_layer_blocks_upper(self) -> None:
        findings = [(OsiLayer.TRANSPORT, DiagnosticStatus.PARTIAL)]
        result = effective_status(OsiLayer.APPLICATION, DiagnosticStatus.PASS, findings)
        assert result == DiagnosticStatus.BLOCKED

    def test_pass_on_lower_layers_allows_upper(self) -> None:
        findings = [
            (OsiLayer.PHYSICAL, DiagnosticStatus.PASS),
            (OsiLayer.DATA_LINK, DiagnosticStatus.PASS),
            (OsiLayer.NETWORK, DiagnosticStatus.PASS),
        ]
        result = effective_status(OsiLayer.TRANSPORT, DiagnosticStatus.PASS, findings)
        assert result == DiagnosticStatus.PASS

    def test_same_layer_finding_is_ignored(self) -> None:
        # A Fail finding at the same layer must NOT block the layer itself.
        findings = [(OsiLayer.APPLICATION, DiagnosticStatus.FAIL)]
        result = effective_status(OsiLayer.APPLICATION, DiagnosticStatus.PASS, findings)
        assert result == DiagnosticStatus.PASS

    def test_own_fail_status_passes_through_when_no_lower_block(self) -> None:
        result = effective_status(OsiLayer.NETWORK, DiagnosticStatus.FAIL, [])
        assert result == DiagnosticStatus.FAIL

    def test_mixed_findings_any_lower_block_is_enough(self) -> None:
        findings = [
            (OsiLayer.PHYSICAL, DiagnosticStatus.PASS),
            (OsiLayer.DATA_LINK, DiagnosticStatus.FAIL),  # this should block
        ]
        result = effective_status(OsiLayer.APPLICATION, DiagnosticStatus.PASS, findings)
        assert result == DiagnosticStatus.BLOCKED

    def test_higher_layer_finding_does_not_block_lower_query(self) -> None:
        # A fail on APPLICATION must not block a TRANSPORT query.
        findings = [(OsiLayer.APPLICATION, DiagnosticStatus.FAIL)]
        result = effective_status(OsiLayer.TRANSPORT, DiagnosticStatus.PASS, findings)
        assert result == DiagnosticStatus.PASS
