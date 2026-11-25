from cloudtrail_analyzer.rules.public_ami_sharing import (
    detect_public_ami_sharing,
)


def create_event(
    group=None,
    user_id=None,
    event_source="ec2.amazonaws.com",
    event_name="ModifyImageAttribute",
):
    add_permission = {}

    if group is not None:
        add_permission["group"] = group

    if user_id is not None:
        add_permission["userId"] = user_id

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
                    "group": "all"
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
