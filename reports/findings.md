# CloudTrail Security Findings

## Summary

- Total findings: 6
- HIGH: 6
- MEDIUM: 0
- LOW: 0

## Findings

### HIGH — S3-001: Public S3 Bucket ACL

- **Event:** PutBucketAcl
- **Bucket:** company-data
- **Description:** S3 bucket ACL grants public read access.

### HIGH — SEC-001: Security Service Deletion or Shutdown

- **Event:** StopLogging
- **Description:** CloudTrail logging stopped.

### HIGH — SEC-001: Security Service Deletion or Shutdown

- **Event:** DeleteTrail
- **Description:** CloudTrail trail deleted.

### HIGH — SEC-001: Security Service Deletion or Shutdown

- **Event:** DeleteDetector
- **Description:** GuardDuty detector deleted.

### HIGH — EC2-001: Public AMI Sharing

- **Event:** ModifyImageAttribute
- **AMI:** ami-0123456789abcdef0
- **Description:** EC2 AMI launch permissions were modified to allow public access.

### HIGH — AUTH-001: Console Login Failure Burst

- **Source IP:** 203.0.113.10
- **Description:** Multiple failed AWS Console login attempts detected from the same source IP.
