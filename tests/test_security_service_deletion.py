from cloudtrail_analyzer.rules.security_service_deletion import (
    detect_security_service_deletion,
)


def test_detects_cloudtrail_stop_logging():
    event = {
        "eventSource": "cloudtrail.amazonaws.com",
        "eventName": "StopLogging",
    }

    result = detect_security_service_deletion(event)

    assert result is not None
    assert result["rule_id"] == "SEC-001"
    assert result["severity"] == "HIGH"
    assert result["event_name"] == "StopLogging"


def test_detects_cloudtrail_delete_trail():
    event = {
        "eventSource": "cloudtrail.amazonaws.com",
        "eventName": "DeleteTrail",
    }

    result = detect_security_service_deletion(event)

    assert result is not None
    assert result["rule_id"] == "SEC-001"
    assert result["event_name"] == "DeleteTrail"


def test_detects_guardduty_delete_detector():
    event = {
        "eventSource": "guardduty.amazonaws.com",
        "eventName": "DeleteDetector",
    }

    result = detect_security_service_deletion(event)

    assert result is not None
    assert result["rule_id"] == "SEC-001"
    assert result["event_name"] == "DeleteDetector"


def test_ignores_unrelated_event():
    event = {
        "eventSource": "s3.amazonaws.com",
        "eventName": "PutBucketAcl",
    }

    assert detect_security_service_deletion(event) is None


def test_ignores_wrong_event_for_service():
    event = {
        "eventSource": "guardduty.amazonaws.com",
        "eventName": "StopLogging",
    }

    assert detect_security_service_deletion(event) is None


def test_ignores_unknown_cloudtrail_event():
    event = {
        "eventSource": "cloudtrail.amazonaws.com",
        "eventName": "LookupEvents",
    }

    assert detect_security_service_deletion(event) is None


def test_ignores_event_with_missing_fields():
    event = {}

    assert detect_security_service_deletion(event) is None