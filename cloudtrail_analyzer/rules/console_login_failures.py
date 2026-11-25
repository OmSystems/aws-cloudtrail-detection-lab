from collections import defaultdict
from datetime import datetime, timedelta, timezone

from cloudtrail_analyzer.rules.common import get_actor


FAILURE_THRESHOLD = 5
TIME_WINDOW_MINUTES = 10


def detect_console_login_failures(events):
    """
    Detect repeated failed AWS Console login attempts
    from the same source IP within a rolling time window.
    """

    failures_by_ip = defaultdict(list)

    for event in events:

        if event.get("eventSource") != "signin.amazonaws.com":
            continue

        if event.get("eventName") != "ConsoleLogin":
            continue

        response_elements = event.get("responseElements", {})

        if not isinstance(response_elements, dict):
            continue

        if response_elements.get("ConsoleLogin") != "Failure":
            continue

        source_ip = event.get("sourceIPAddress")
        event_time = event.get("eventTime")

        if not source_ip or not isinstance(event_time, str):
            continue

        try:
            timestamp = datetime.fromisoformat(
                event_time.replace("Z", "+00:00")
            )
        except (ValueError, TypeError):
            continue

        if timestamp.tzinfo is None:
            continue

        failures_by_ip[source_ip].append((timestamp, event))

    findings = []

    for source_ip, failures in failures_by_ip.items():

        failures.sort(key=lambda failure: failure[0])

        for current_time, _ in failures:

            window_start = current_time - timedelta(
                minutes=TIME_WINDOW_MINUTES
            )

            matching = [
                (timestamp, event)
                for timestamp, event in failures
                if window_start <= timestamp <= current_time
            ]

            if len(matching) >= FAILURE_THRESHOLD:

                targeted_users = sorted({
                    actor
                    for _, event in matching
                    if (actor := get_actor(event))
                })

                finding = {
                    "rule_id": "AUTH-001",
                    "rule_name": "Console Login Failure Burst",
                    "severity": "HIGH",
                    "source_ip": source_ip,
                    "failed_attempts": len(matching),
                    "time_window_minutes": TIME_WINDOW_MINUTES,
                    "first_event_time": matching[0][1].get("eventTime"),
                    "last_event_time": matching[-1][1].get("eventTime"),
                    "event_ids": [
                        event["eventID"]
                        for _, event in matching
                        if event.get("eventID")
                    ],
                    "description": (
                        "Multiple failed AWS Console login attempts "
                        "detected from the same source IP."
                    )
                }

                if targeted_users:
                    finding["targeted_users"] = targeted_users

                findings.append(finding)

                break

    return findings
