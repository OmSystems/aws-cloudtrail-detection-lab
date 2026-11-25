from cloudtrail_analyzer.rules.public_ami_sharing import (
    detect_public_ami_sharing,
)


def create_event(
    group=None,
    user_id=None,
    event_source="ec2.amazonaws.com",
    event_name="ModifyImageAttribute",
):
    items = []

    if group is not None:
        items.append({"group": group})

    if user_id is not None:
        items.append({"userId": user_id})

    add_permission = {"items": items}

    return {
        "eventSource": event_source,
        "eventName": event_name,
        "requestParameters": {
            "imageId": "ami-0123456789abcdef0",
            "launchPermission": {
                "add": add_permission
            }
        }
    }


def test_detects_public_ami_sharing():
    event = create_event(group="all")

    result = detect_public_ami_sharing(event)

    assert result is not None
    assert result["rule_id"] == "EC2-001"
    assert result["severity"] == "HIGH"
    assert result["image_id"] == "ami-0123456789abcdef0"


def test_ignores_private_account_sharing():
    event = create_event(user_id="123456789012")

    assert detect_public_ami_sharing(event) is None


def test_ignores_unrelated_event_source():
    event = create_event(
        group="all",
        event_source="s3.amazonaws.com",
    )

    assert detect_public_ami_sharing(event) is None


def test_ignores_wrong_event_name():
    event = create_event(
        group="all",
        event_name="DescribeImages",
    )

    assert detect_public_ami_sharing(event) is None


def test_ignores_removal_of_public_permission():
    event = {
        "eventSource": "ec2.amazonaws.com",
        "eventName": "ModifyImageAttribute",
        "requestParameters": {
            "imageId": "ami-0123456789abcdef0",
            "launchPermission": {
                "remove": {
                    "items": [{"group": "all"}]
                }
            }
        }
    }

    assert detect_public_ami_sharing(event) is None


def test_ignores_missing_launch_permission():
    event = {
        "eventSource": "ec2.amazonaws.com",
        "eventName": "ModifyImageAttribute",
        "requestParameters": {
            "imageId": "ami-0123456789abcdef0"
        }
    }

    assert detect_public_ami_sharing(event) is None


def test_ignores_malformed_request_parameters():
    event = {
        "eventSource": "ec2.amazonaws.com",
        "eventName": "ModifyImageAttribute",
        "requestParameters": None,
    }

    assert detect_public_ami_sharing(event) is None


def test_detects_public_group_among_multiple_items():
    event = create_event(group="all", user_id="111122223333")

    assert detect_public_ami_sharing(event) is not None


def test_ignores_old_flat_group_shape_not_used_by_cloudtrail():
    event = {
        "eventSource": "ec2.amazonaws.com",
        "eventName": "ModifyImageAttribute",
        "requestParameters": {
            "imageId": "ami-0123456789abcdef0",
            "launchPermission": {"add": {"group": "all"}},
        },
    }

    assert detect_public_ami_sharing(event) is None


def test_ignores_denied_request():
    event = create_event(group="all")
    event["errorCode"] = "Client.UnauthorizedOperation"

    assert detect_public_ami_sharing(event) is None


def test_finding_includes_investigation_fields():
    event = create_event(group="all")
    event.update({
        "eventTime": "2026-11-25T09:00:00Z",
        "eventID": "11111111-2222-3333-4444-555555555555",
        "awsRegion": "eu-central-1",
        "sourceIPAddress": "198.51.100.7",
        "userIdentity": {
            "arn": "arn:aws:iam::123456789012:user/example-admin"
        },
    })

    result = detect_public_ami_sharing(event)

    assert result["event_time"] == "2026-11-25T09:00:00Z"
    assert result["event_id"] == "11111111-2222-3333-4444-555555555555"
    assert result["aws_region"] == "eu-central-1"
    assert result["source_ip"] == "198.51.100.7"
    assert result["actor"] == "arn:aws:iam::123456789012:user/example-admin"
