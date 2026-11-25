def detect_public_ami_sharing(event):
    """
    Detect EC2 AMIs made publicly accessible
    through launch permission changes.
    """

    if event.get("eventSource") != "ec2.amazonaws.com":
        return None

    if event.get("eventName") != "ModifyImageAttribute":
        return None

    request_parameters = event.get("requestParameters", {})

    if not isinstance(request_parameters, dict):
        return None

    launch_permission = request_parameters.get(
        "launchPermission", {}
    )

    if not isinstance(launch_permission, dict):
        return None

    add_permission = launch_permission.get("add", {})

    if not isinstance(add_permission, dict):
        return None

    if add_permission.get("group") != "all":
        return None

    return {
        "rule_id": "EC2-001",
        "rule_name": "Public AMI Sharing",
        "severity": "HIGH",
        "event_name": event.get("eventName"),
        "image_id": request_parameters.get("imageId"),
        "description": "EC2 AMI launch permissions were modified to allow public access."
    }
