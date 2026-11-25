from cloudtrail_analyzer.rules.common import event_context, is_failed_call


def _adds_public_group(add_permission):
    """Return True if launchPermission.add.items contains group "all".

    CloudTrail records the change as
    {"add": {"items": [{"group": "all"}, {"userId": "111122223333"}]}}.
    """

    if not isinstance(add_permission, dict):
        return False

    items = add_permission.get("items")

    if not isinstance(items, list):
        return False

    return any(
        isinstance(item, dict) and item.get("group") == "all"
        for item in items
    )


def detect_public_ami_sharing(event):
    """
    Detect EC2 AMIs made publicly accessible
    through launch permission changes.
    """

    if event.get("eventSource") != "ec2.amazonaws.com":
        return None

    if event.get("eventName") != "ModifyImageAttribute":
        return None

    if is_failed_call(event):
        return None

    request_parameters = event.get("requestParameters", {})

    if not isinstance(request_parameters, dict):
        return None

    launch_permission = request_parameters.get("launchPermission", {})

    if not isinstance(launch_permission, dict):
        return None

    if not _adds_public_group(launch_permission.get("add")):
        return None

    return {
        "rule_id": "EC2-001",
        "rule_name": "Public AMI Sharing",
        "severity": "HIGH",
        "event_name": event.get("eventName"),
        "image_id": request_parameters.get("imageId"),
        "description": (
            "EC2 AMI launch permissions were modified to allow public access."
        ),
        **event_context(event),
    }
