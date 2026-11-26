import re

from cloudtrail_analyzer import engine
from cloudtrail_analyzer.rules import registry
from cloudtrail_analyzer.rules.metadata import (
    RULE_METADATA,
    VALID_SEVERITIES,
    rule_fields,
)

TECHNIQUE_ID = re.compile(r"^T\d{4}(\.\d{3})?$")


def test_registry_ids_are_unique():
    ids = [rule.rule_id for rule in registry.RULES]

    assert len(ids) == len(set(ids))


def test_every_registered_rule_has_metadata_and_vice_versa():
    assert {r.rule_id for r in registry.RULES} == set(RULE_METADATA)


def test_metadata_is_well_formed():
    for rule_id, meta in RULE_METADATA.items():
        assert meta["severity"] in VALID_SEVERITIES, rule_id
        assert meta["rule_name"], rule_id
        assert meta["mitre_attack"], rule_id

        for technique in meta["mitre_attack"]:
            assert TECHNIQUE_ID.match(technique["id"]), rule_id
            assert technique["name"] and technique["tactic"], rule_id


def test_rule_fields_returns_a_copy():
    first = rule_fields("SEC-001")
    first["mitre_attack"][0]["id"] = "CHANGED"

    assert rule_fields("SEC-001")["mitre_attack"][0]["id"] == "T1562.008"


def test_findings_carry_metadata_from_registry():
    event = {
        "eventSource": "cloudtrail.amazonaws.com",
        "eventName": "StopLogging",
        "eventID": "e1",
        "eventTime": "2026-01-01T00:00:00Z",
    }

    findings = engine.run_detection([event])

    assert len(findings) == 1
    assert findings[0]["rule_id"] == "SEC-001"
    assert findings[0]["severity"] == "HIGH"
    assert findings[0]["mitre_attack"][0]["id"] == "T1562.008"


def test_new_rule_runs_without_engine_changes(monkeypatch):
    def detect_test_event(event):
        if event.get("eventName") == "Boom":
            return {"rule_id": "TEST-001", "severity": "LOW"}
        return None

    def detect_test_batch(events):
        return [{"rule_id": "TEST-002", "count": len(events)}]

    monkeypatch.setattr(
        registry,
        "RULES",
        registry.RULES
        + [
            registry.Rule("TEST-001", registry.EVENT, detect_test_event),
            registry.Rule("TEST-002", registry.BATCH, detect_test_batch),
        ],
    )

    findings = engine.run_detection([{"eventName": "Boom"}])

    assert [f["rule_id"] for f in findings] == ["TEST-001", "TEST-002"]
    assert findings[1]["count"] == 1


def test_unknown_scope_is_rejected():
    try:
        registry.Rule("X-1", "weird", lambda e: None)
    except ValueError:
        return

    raise AssertionError("expected ValueError")
