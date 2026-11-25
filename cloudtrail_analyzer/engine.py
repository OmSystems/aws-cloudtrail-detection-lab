from cloudtrail_analyzer.rules.s3_public_access import (
    detect_public_s3_acl,
)

from cloudtrail_analyzer.rules.security_service_deletion import (
    detect_security_service_deletion,
)

from cloudtrail_analyzer.rules.console_login_failures import (
    detect_console_login_failures,
)

from cloudtrail_analyzer.rules.public_ami_sharing import (
    detect_public_ami_sharing,
)


def run_detection(events):
    """
    Run all CloudTrail detection rules and combine findings.
    """

    findings = []

    for event in events:

        s3_finding = detect_public_s3_acl(event)

        if s3_finding is not None:
            findings.append(s3_finding)

        security_finding = detect_security_service_deletion(event)

        if security_finding is not None:
            findings.append(security_finding)

        ami_finding = detect_public_ami_sharing(event)

        if ami_finding is not None:
            findings.append(ami_finding)

    login_findings = detect_console_login_failures(events)

    findings.extend(login_findings)

    return findings
