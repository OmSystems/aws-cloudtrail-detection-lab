from cloudtrail_analyzer.rules.console_login_failures import (
    detect_console_login_failures,
)


def create_event(timestamp, source_ip="203.0.113.10",
                 result="Failure", event_source="signin.amazonaws.com",
                 event_name="ConsoleLogin"):
    return {
        "eventSource": event_source,
        "eventName": event_name,
        "eventTime": timestamp,
        "sourceIPAddress": source_ip,
        "responseElements": {
            "ConsoleLogin": result
        }
    }


def test_detects_five_failures_within_ten_minutes():
    events = [
        create_event("2026-11-25T08:00:00Z"),
        create_event("2026-11-25T08:02:00Z"),
        create_event("2026-11-25T08:04:00Z"),
        create_event("2026-11-25T08:06:00Z"),
        create_event("2026-11-25T08:08:00Z"),
    ]

    findings = detect_console_login_failures(events)

    assert len(findings) == 1
    assert findings[0]["rule_id"] == "AUTH-001"
    assert findings[0]["severity"] == "HIGH"
    assert findings[0]["failed_attempts"] == 5


def test_ignores_four_failed_attempts():
    events = [
        create_event("2026-11-25T08:00:00Z"),
        create_event("2026-11-25T08:02:00Z"),
        create_event("2026-11-25T08:04:00Z"),
        create_event("2026-11-25T08:06:00Z"),
    ]

    assert detect_console_login_failures(events) == []


def test_groups_failures_by_source_ip():
    events = [
        create_event("2026-11-25T08:00:00Z", "203.0.113.10"),
        create_event("2026-11-25T08:01:00Z", "203.0.113.20"),
        create_event("2026-11-25T08:02:00Z", "203.0.113.10"),
        create_event("2026-11-25T08:03:00Z", "203.0.113.20"),
        create_event("2026-11-25T08:04:00Z", "203.0.113.10"),
        create_event("2026-11-25T08:05:00Z", "203.0.113.20"),
    ]

    assert detect_console_login_failures(events) == []


def test_ignores_failures_outside_ten_minute_window():
    events = [
        create_event("2026-11-25T08:00:00Z"),
        create_event("2026-11-25T08:03:00Z"),
        create_event("2026-11-25T08:06:00Z"),
        create_event("2026-11-25T08:09:00Z"),
        create_event("2026-11-25T08:12:00Z"),
    ]

    assert detect_console_login_failures(events) == []


def test_ignores_successful_logins():
    events = [
        create_event(
            f"2026-11-25T08:0{i}:00Z",
            result="Success"
        )
        for i in range(5)
    ]

    assert detect_console_login_failures(events) == []


def test_ignores_unrelated_events():
    events = [
        create_event(
            f"2026-11-25T08:0{i}:00Z",
            event_source="s3.amazonaws.com"
        )
        for i in range(5)
    ]

    assert detect_console_login_failures(events) == []


def test_ignores_invalid_timestamps():
    events = [
        create_event("invalid-timestamp")
        for _ in range(5)
    ]

    assert detect_console_login_failures(events) == []


def test_ignores_events_without_source_ip():
    events = [
        create_event(f"2026-11-25T08:0{i}:00Z", source_ip=None)
        for i in range(5)
    ]

    assert detect_console_login_failures(events) == []


def test_ignores_non_string_timestamps():
    events = [
        create_event(12345)
        for _ in range(5)
    ]

    assert detect_console_login_failures(events) == []


def test_finding_includes_window_times_event_ids_and_users():
    events = []

    for minute in range(5):
        events.append({
            "eventSource": "signin.amazonaws.com",
            "eventName": "ConsoleLogin",
            "eventTime": f"2026-11-25T08:0{minute}:00Z",
            "eventID": f"event-{minute}",
            "sourceIPAddress": "203.0.113.10",
            "userIdentity": {"userName": "example-admin"},
            "responseElements": {"ConsoleLogin": "Failure"},
        })

    findings = detect_console_login_failures(events)

    assert len(findings) == 1
    assert findings[0]["first_event_time"] == "2026-11-25T08:00:00Z"
    assert findings[0]["last_event_time"] == "2026-11-25T08:04:00Z"
    assert findings[0]["event_ids"] == [f"event-{i}" for i in range(5)]
    assert findings[0]["targeted_users"] == ["example-admin"]
