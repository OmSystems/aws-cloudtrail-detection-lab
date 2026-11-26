"""Run the detection engine against real CloudTrail records.

The records come from the public Invictus dataset (see datasets/real-world/README.md),
so these tests catch schema assumptions that hand-written fixtures cannot.
"""
from cloudtrail_analyzer.__main__ import PROJECT_ROOT
from cloudtrail_analyzer.engine import run_detection
from cloudtrail_analyzer.loader import load_events

REAL_LOG = PROJECT_ROOT / "datasets" / "real-world" / "invictus-stratus-subset.json"


def real_events():
    return load_events(REAL_LOG)


def test_real_log_loads():
    assert len(real_events()) > 0


def test_successful_delete_trail_is_detected():
    findings = run_detection(real_events())

    sec = [f for f in findings if f["rule_id"] == "SEC-001"]

    assert len(sec) == 2
    assert {f["event_name"] for f in sec} == {"DeleteTrail"}

    for finding in sec:
        assert finding["event_id"]
        assert finding["actor"].endswith("user/bert-jan")


def test_failed_stop_and_delete_calls_do_not_alert():
    events = real_events()
    failed = [
        e for e in events
        if e["eventName"] in ("StopLogging", "DeleteTrail") and e.get("errorCode")
    ]
    failed_ids = {e["eventID"] for e in failed}

    findings = run_detection(events)

    assert failed_ids
    assert not failed_ids & {f.get("event_id") for f in findings}


def test_private_ami_share_to_account_does_not_alert():
    findings = run_detection(real_events())

    assert not [f for f in findings if f["rule_id"] == "EC2-001"]


def test_successful_console_logins_do_not_alert():
    findings = run_detection(real_events())

    assert not [f for f in findings if f["rule_id"] == "AUTH-001"]
