SECURITY_EVENTS = {
    "cloudtrail.amazonaws.com": {
        "StopLogging": "CloudTrail logging stopped.",
        "DeleteTrail": "CloudTrail trail deleted."
    },
    "guardduty.amazonaws.com": {
        "DeleteDetector": "GuardDuty detector deleted."
    }
}


def detect_security_service_deletion(event):
    """
    Detect events that stop or delete security monitoring services.
    """

    event_source = event.get("eventSource")
    event_name = event.get("eventName")

    service_events = SECURITY_EVENTS.get(event_source, {})

    if event_name not in service_events:
        return None

    return {
        "rule_id": "SEC-001",
        "rule_name": "Security Service Deletion or Shutdown",
        "severity": "HIGH",
        "event_source": event_source,
        "event_name": event_name,
        "description": service_events[event_name]
    }
