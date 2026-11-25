"""Helpers shared by the detection rules."""


def is_failed_call(event):
    """Return True if AWS rejected the API call (errorCode is present).

    A denied call, for example AccessDenied on PutBucketAcl, did not change
    anything, so single-event rules must not alert on it.
    """
    return bool(event.get("errorCode"))


def get_actor(event):
    """Return the best available identifier of who made the call."""
    identity = event.get("userIdentity")

    if not isinstance(identity, dict):
        return None

    return (
        identity.get("arn")
        or identity.get("userName")
        or identity.get("principalId")
    )


def event_context(event):
    """Return the fields an analyst needs to find the original event.

    Fields missing from the event are left out instead of set to None.
    """
    context = {
        "event_time": event.get("eventTime"),
        "event_id": event.get("eventID"),
        "aws_region": event.get("awsRegion"),
        "source_ip": event.get("sourceIPAddress"),
        "actor": get_actor(event),
    }

    return {key: value for key, value in context.items() if value}
