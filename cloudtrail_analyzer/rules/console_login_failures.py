from collections import defaultdict
from datetime import datetime, timedelta, timezone


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

        failures_by_ip[source_ip].append(timestamp)

    findings = []

    for source_ip, timestamps in failures_by_ip.items():

        timestamps.sort()

        for index, current_time in enumerate(timestamps):

            window_start = current_time - timedelta(
                minutes=TIME_WINDOW_MINUTES
            )

            matching_attempts = [
                timestamp
                for timestamp in timestamps
                if window_start <= timestamp <= current_time
            ]

            if len(matching_attempts) >= FAILURE_THRESHOLD:

                findings.append({
                    "rule_id": "AUTH-001",
                    "rule_name": "Console Login Failure Burst",
                    "severity": "HIGH",
                    "source_ip": source_ip,
                    "failed_attempts": len(matching_attempts),
                    "time_window_minutes": TIME_WINDOW_MINUTES,
                    "description": (
                        "Multiple failed AWS Console login attempts "
                        "detected from the same source IP."
                    )
                })

                break

    return findings