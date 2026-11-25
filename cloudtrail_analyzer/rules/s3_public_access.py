from cloudtrail_analyzer.rules.common import event_context, is_failed_call


def detect_public_s3_acl(event):
    """
    Detect public-read grants in S3 bucket ACL events.
    """

    if event.get("eventSource") != "s3.amazonaws.com":
        return None

    if event.get("eventName") != "PutBucketAcl":
        return None

    if is_failed_call(event):
        return None

    request_parameters = event.get("requestParameters", {})

    access_control_policy = request_parameters.get(
        "AccessControlPolicy", {}
    )

    access_control_list = access_control_policy.get(
        "AccessControlList", {}
    )

    grants = access_control_list.get("Grant", [])

    if isinstance(grants, dict):
        grants = [grants]

    for grant in grants:

        if not isinstance(grant, dict):
            continue

        grantee = grant.get("Grantee", {})

        if not isinstance(grantee, dict):
            continue

        permission = grant.get("Permission")
        grantee_uri = grantee.get("URI")

        if (
            grantee_uri == "http://acs.amazonaws.com/groups/global/AllUsers"
            and permission == "READ"
        ):
            return {
                "rule_id": "S3-001",
                "rule_name": "Public S3 Bucket ACL",
                "severity": "HIGH",
                "event_name": event.get("eventName"),
                "bucket_name": request_parameters.get("bucketName"),
                "description": "S3 bucket ACL grants public read access.",
                **event_context(event),
            }

    return None