"""Tests for core models."""
from arcanum.core.models import Mode, Status, Severity, StashType


def test_mode_enum():
    assert Mode.autopilot.value == "autopilot"
    assert Mode.copilot.value == "copilot"
    assert Mode.manual.value == "manual"


def test_severity_enum():
    assert Severity.critical.value == "critical"
    assert Severity.high.value == "high"
    assert Severity.medium.value == "medium"
    assert Severity.low.value == "low"
    assert Severity.info.value == "info"


def test_stash_type_enum():
    assert StashType.credential.value == "credential"
    assert StashType.host.value == "host"
    assert StashType.payload.value == "payload"


def test_status_enum():
    assert Status.created.value == "created"
    assert Status.running.value == "running"
    assert Status.complete.value == "complete"
