from cloudtrail_analyzer.rules.s3_public_access import detect_public_s3_acl


def create_event(grants, event_source="s3.amazonaws.com", event_name="PutBucketAcl"):
    return {
        "eventSource": event_source,
        "eventName": event_name,
        "requestParameters": {
            "bucketName": "test-bucket",
            "AccessControlPolicy": {
                "AccessControlList": {
                    "Grant": grants
                }
            }
        }
    }


def test_detects_single_public_read_grant():
    event = create_event({
        "Grantee": {
            "xsi:type": "Group",
            "URI": "http://acs.amazonaws.com/groups/global/AllUsers"
        },
        "Permission": "READ"
    })

    result = detect_public_s3_acl(event)

    assert result is not None
    assert result["rule_id"] == "S3-001"
    assert result["severity"] == "HIGH"
    assert result["bucket_name"] == "test-bucket"


def test_detects_public_grant_among_multiple_grants():
    event = create_event([
        {
            "Grantee": {
                "xsi:type": "CanonicalUser",
                "ID": "example-user-id"
            },
            "Permission": "READ"
        },
        {
            "Grantee": {
                "xsi:type": "Group",
                "URI": "http://acs.amazonaws.com/groups/global/AuthenticatedUsers"
            },
            "Permission": "READ"
        },
        {
            "Grantee": {
                "xsi:type": "Group",
                "URI": "http://acs.amazonaws.com/groups/global/AllUsers"
            },
            "Permission": "READ"
        }
    ])

    result = detect_public_s3_acl(event)

    assert result is not None
    assert result["rule_id"] == "S3-001"


def test_ignores_private_acl_grant():
    event = create_event({
        "Grantee": {
            "xsi:type": "CanonicalUser",
            "ID": "example-user-id"
        },
        "Permission": "READ"
    })

    assert detect_public_s3_acl(event) is None


def test_ignores_authenticated_users_grant():
    event = create_event({
        "Grantee": {
            "xsi:type": "Group",
            "URI": "http://acs.amazonaws.com/groups/global/AuthenticatedUsers"
        },
        "Permission": "READ"
    })

    assert detect_public_s3_acl(event) is None


def test_ignores_non_s3_event():
    event = create_event(
        {
            "Grantee": {
                "xsi:type": "Group",
                "URI": "http://acs.amazonaws.com/groups/global/AllUsers"
            },
            "Permission": "READ"
        },
        event_source="ec2.amazonaws.com"
    )

    assert detect_public_s3_acl(event) is None


def test_ignores_wrong_event_name():
    event = create_event(
        {
            "Grantee": {
                "xsi:type": "Group",
                "URI": "http://acs.amazonaws.com/groups/global/AllUsers"
            },
            "Permission": "READ"
        },
        event_name="GetBucketAcl"
    )

    assert detect_public_s3_acl(event) is None


def test_skips_malformed_grant_entries():
    event = create_event([
        "invalid-entry",
        None,
        {
            "Grantee": {
                "xsi:type": "Group",
                "URI": "http://acs.amazonaws.com/groups/global/AllUsers"
            },
            "Permission": "READ"
        }
    ])

    result = detect_public_s3_acl(event)

    assert result is not None
    assert result["rule_id"] == "S3-001"