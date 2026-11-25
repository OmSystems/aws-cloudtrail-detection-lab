from cloudtrail_analyzer.engine import run_detection
from cloudtrail_analyzer.loader import load_events


def test_engine_detects_findings_across_all_datasets():
    dataset_paths = [
        "datasets/s3-public/public-bucket-acl.json",
        "datasets/security-service-deletion/security-events.json",
        "datasets/login-failures/console-login-burst.json",
        "datasets/ami-public/public-ami-sharing.json",
    ]

    all_events = []

    for path in dataset_paths:
        all_events.extend(load_events(path))

    findings = run_detection(all_events)

    assert len(findings) == 6

    rule_ids = {finding["rule_id"] for finding in findings}

    assert rule_ids == {
        "S3-001",
        "SEC-001",
        "AUTH-001",
        "EC2-001",
    }


def test_engine_returns_empty_list_for_no_events():
    assert run_detection([]) == []


def test_engine_detects_multiple_security_events():
    events = load_events(
        "datasets/security-service-deletion/security-events.json"
    )

    findings = run_detection(events)

    assert len(findings) == 3

    assert all(
        finding["rule_id"] == "SEC-001"
        for finding in findings
    )
