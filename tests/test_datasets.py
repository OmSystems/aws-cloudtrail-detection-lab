from cloudtrail_analyzer.__main__ import DATASET_PATHS, PROJECT_ROOT
from cloudtrail_analyzer.engine import run_detection
from cloudtrail_analyzer.loader import load_events


def load_all_events():
    events = []

    for dataset_path in DATASET_PATHS:
        events.extend(load_events(PROJECT_ROOT / dataset_path))

    return events


def test_committed_datasets_produce_expected_findings():
    findings = run_detection(load_all_events())

    rule_ids = sorted(finding["rule_id"] for finding in findings)

    assert rule_ids == [
        "AUTH-001",
        "EC2-001",
        "S3-001",
        "SEC-001",
        "SEC-001",
        "SEC-001",
    ]


def test_every_single_event_finding_identifies_actor_and_event():
    findings = run_detection(load_all_events())

    for finding in findings:
        if finding["rule_id"] == "AUTH-001":
            assert finding["event_ids"]
            continue

        assert finding["event_id"]
        assert finding["event_time"]
        assert finding["actor"]


def test_negative_fixtures_do_not_produce_findings():
    findings = run_detection(load_all_events())

    actors = {finding.get("actor") for finding in findings}

    # example-intern's calls were denied; the private AMI share is not public.
    assert not any("example-intern" in (actor or "") for actor in actors)
    assert len([f for f in findings if f["rule_id"] == "EC2-001"]) == 1
