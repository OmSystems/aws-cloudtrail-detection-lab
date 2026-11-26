# CloudTrail Security Findings

## Summary

- Total findings: 6
- HIGH: 5
- MEDIUM: 1
- LOW: 0

## Findings

### HIGH — S3-001: Public S3 Bucket ACL

- **Event:** PutBucketAcl
- **Bucket:** company-data
- **Time:** 2026-11-24T10:00:00Z
- **Actor:** arn:aws:iam::123456789012:user/example-admin
- **Source IP:** 198.51.100.7
- **Region:** eu-central-1
- **Event ID:** 00000000-0000-0000-0000-00005eed0001
- **MITRE ATT&CK:** T1530 (Data from Cloud Storage)
- **Description:** S3 bucket ACL grants public read access.

### HIGH — SEC-001: Security Service Deletion or Shutdown

- **Event:** StopLogging
- **Time:** 2026-11-25T08:00:00Z
- **Actor:** arn:aws:iam::123456789012:user/example-admin
- **Source IP:** 203.0.113.10
- **Region:** eu-central-1
- **Event ID:** 00000000-0000-0000-0000-00005eed0004
- **MITRE ATT&CK:** T1562.008 (Impair Defenses: Disable or Modify Cloud Logs)
- **Description:** CloudTrail logging stopped.

### HIGH — SEC-001: Security Service Deletion or Shutdown

- **Event:** DeleteTrail
- **Time:** 2026-11-25T08:05:00Z
- **Actor:** arn:aws:iam::123456789012:user/example-admin
- **Source IP:** 203.0.113.10
- **Region:** eu-central-1
- **Event ID:** 00000000-0000-0000-0000-00005eed0005
- **MITRE ATT&CK:** T1562.008 (Impair Defenses: Disable or Modify Cloud Logs)
- **Description:** CloudTrail trail deleted.

### HIGH — SEC-001: Security Service Deletion or Shutdown

- **Event:** DeleteDetector
- **Time:** 2026-11-25T08:10:00Z
- **Actor:** arn:aws:iam::123456789012:user/example-admin
- **Source IP:** 203.0.113.10
- **Region:** eu-central-1
- **Event ID:** 00000000-0000-0000-0000-00005eed0006
- **MITRE ATT&CK:** T1562.008 (Impair Defenses: Disable or Modify Cloud Logs)
- **Description:** GuardDuty detector deleted.

### HIGH — EC2-001: Public AMI Sharing

- **Event:** ModifyImageAttribute
- **AMI:** ami-0123456789abcdef0
- **Time:** 2026-11-25T09:00:00Z
- **Actor:** arn:aws:iam::123456789012:user/example-admin
- **Source IP:** 198.51.100.7
- **Region:** eu-central-1
- **Event ID:** 00000000-0000-0000-0000-00005eed000e
- **MITRE ATT&CK:** T1537 (Transfer Data to Cloud Account)
- **Description:** EC2 AMI launch permissions were modified to allow public access.

### MEDIUM — AUTH-001: Console Login Failure Burst

- **First failure:** 2026-11-25T08:00:00Z
- **Last failure:** 2026-11-25T08:08:00Z
- **Source IP:** 203.0.113.10
- **MITRE ATT&CK:** T1110 (Brute Force)
- **Failed attempts:** 5
- **Targeted users:** example-admin
- **Event IDs:** 00000000-0000-0000-0000-00005eed0007, 00000000-0000-0000-0000-00005eed0008, 00000000-0000-0000-0000-00005eed0009, 00000000-0000-0000-0000-00005eed000a, 00000000-0000-0000-0000-00005eed000b
- **Description:** Multiple failed AWS Console login attempts detected from the same source IP.
