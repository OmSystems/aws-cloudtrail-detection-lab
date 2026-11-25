# AWS CloudTrail Detection Lab

A hands-on cloud security lab combining Terraform security configuration analysis with Python-based AWS CloudTrail event detection.

The project demonstrates two complementary security activities:

- **Infrastructure security:** Compare secure and intentionally vulnerable Amazon S3 configurations using Terraform and Checkov.
- **Detection engineering:** Analyze CloudTrail JSON events and identify security-relevant activities using Python detection rules.

No AWS infrastructure is deployed. CloudTrail datasets are synthetic test fixtures.

## Project Objectives

- Identify common AWS S3 security misconfigurations through Infrastructure as Code (IaC) scanning.
- Implement Python detection rules for security-relevant CloudTrail events.
- Build a reusable event loader, detection engine, and reporting module.
- Validate detection logic using automated positive and negative tests.
- Produce reproducible JSON and Markdown security reports.

## Architecture

```text
                    AWS CloudTrail JSON
                     (Synthetic Fixtures)
                             |
                             v
                    CloudTrail Loader
                    loader.py
                             |
                             v
                     Detection Engine
                      engine.py
                             |
             +---------------+---------------+
             |               |               |
             v               v               v
          S3 ACL       Security Service    Public AMI
          Detection       Detection        Detection
             |               |               |
             +---------------+---------------+
                             |
                             v
                  Console Login Detection
                             |
                             v
                       Findings
                             |
                  +----------+----------+
                  |                     |
                  v                     v
              JSON Report         Markdown Report
             findings.json        findings.md
```

The Terraform security analysis is performed separately:

```text
       Secure Terraform          Vulnerable Terraform
              |                          |
              v                          v
           Checkov                     Checkov
              |                          |
              v                          v
      Secure Scan Report       Vulnerable Scan Report
              |                          |
              +------------+-------------+
                           |
                           v
                  Comparison Report
```

## Threat Model

The detection rules focus on security-relevant AWS activities that could indicate exposure, unauthorized changes, or attempts to weaken security monitoring.

| Threat | Potential Security Impact | Detection |
|---|---|---|
| Public S3 bucket ACL | Unauthorized object access | S3-001 |
| CloudTrail or GuardDuty shutdown | Reduced security visibility | SEC-001 |
| Repeated failed console logins | Possible credential-guessing activity | AUTH-001 |
| Public AMI sharing | Exposure of machine images | EC2-001 |

These detections identify suspicious or security-relevant events. They do not independently establish malicious intent.

## Infrastructure Security

The project contains two Terraform configurations.

**Secure configuration — `terraform/secure/`**

- S3 Block Public Access settings enabled.
- Bucket versioning enabled.
- Default server-side encryption using SSE-S3 (AES256).
- Bucket policy denying non-HTTPS requests.

**Intentionally vulnerable configuration — `terraform/vulnerable/`**

- Public-read bucket policy using wildcard Principal (`*`).
- No S3 Block Public Access configuration.
- Bucket versioning not enabled.
- No explicit default encryption configuration.
- No equivalent HTTPS-only bucket policy.

Both configurations were statically analyzed using Checkov 3.4.3.

### Checkov Results

| Metric | Secure | Vulnerable |
|---|---:|---:|
| Passed checks | 12 | 6 |
| Failed checks | 5 | 8 |
| Skipped checks | 0 | 0 |
| Parsing errors | 0 | 0 |
| Resources scanned | 5 | 2 |

The vulnerable configuration introduces additional findings related to public bucket access, missing public access blocking, and disabled versioning.

The secure configuration still has five findings. These include missing cross-region replication, event notifications, lifecycle configuration, access logging, and KMS encryption.

The secure bucket uses SSE-S3 encryption. Checkov's CKV_AWS_145 check expects AWS KMS encryption, so this finding does not mean that the bucket has no encryption.

Detailed results are available in:

- `reports/comparison.md`
- `reports/secure-checkov.json`
- `reports/vulnerable-checkov.json`

The resource counts differ between configurations. Therefore, raw pass/fail totals are not a normalized security score.

## CloudTrail Detection Rules

The Python analyzer currently implements four detection rules.

| Rule ID | Detection | Event Conditions | Severity |
|---|---|---|---|
| S3-001 | Public S3 Bucket ACL | `PutBucketAcl` with an `AllUsers` READ grant | HIGH |
| SEC-001 | Security Service Deletion or Shutdown | `StopLogging`, `DeleteTrail`, or `DeleteDetector` | HIGH |
| AUTH-001 | Console Login Failure Burst | At least 5 failed console logins from one source IP within 10 minutes | HIGH |
| EC2-001 | Public AMI Sharing | `ModifyImageAttribute` adding the `all` launch-permission group | HIGH |

### Detection Scope

- **S3-001:** Detects public-read ACL grants. It does not establish effective public access because other controls, such as S3 Block Public Access, may prevent access.
- **SEC-001:** Detects selected events that stop or delete security monitoring services. Authorized administrative activity can also trigger this rule.
- **AUTH-001:** Groups failed console login attempts by source IP and checks a rolling 10-minute window.
- **EC2-001:** Detects requests to add public AMI launch permissions. It does not independently verify the AMI's effective permissions after the change.

## Project Structure

```text
aws-cloudtrail-detection-lab/
|
|-- cloudtrail_analyzer/
|   |-- __init__.py
|   |-- __main__.py
|   |-- loader.py
|   |-- engine.py
|   |-- reporting.py
|   |
|   |-- rules/
|       |-- __init__.py
|       |-- s3_public_access.py
|       |-- security_service_deletion.py
|       |-- console_login_failures.py
|       |-- public_ami_sharing.py
|
|-- datasets/
|   |-- s3-public/
|   |-- security-service-deletion/
|   |-- login-failures/
|   |-- ami-public/
|
|-- terraform/
|   |-- secure/
|   |-- vulnerable/
|
|-- reports/
|   |-- comparison.md
|   |-- secure-checkov.json
|   |-- vulnerable-checkov.json
|   |-- findings.json
|   |-- findings.md
|
|-- tests/
|
|-- README.md
```

## Setup and Execution

### Prerequisites

- Python 3
- pytest
- Terraform
- Checkov

Terraform and Checkov are required for infrastructure scanning. Python and pytest are required for the detection analyzer and its tests.

### Run the Detection Analyzer

From the repository root:

```bash
python3 -m cloudtrail_analyzer
```

The analyzer reads the synthetic CloudTrail fixtures, executes the detection rules, and generates:

```text
reports/findings.json
reports/findings.md
```

### Run Automated Tests

```bash
python3 -m pytest -v
```

The test suite validates event loading, individual detection rules, detection engine integration, report generation, and CLI execution.

### Validate Terraform Configurations

Initialize and validate the secure configuration:

```bash
terraform -chdir=terraform/secure init
terraform -chdir=terraform/secure validate
```

Initialize and validate the vulnerable configuration:

```bash
terraform -chdir=terraform/vulnerable init
terraform -chdir=terraform/vulnerable validate
```

Run Checkov:

```bash
checkov -d terraform/secure --framework terraform
checkov -d terraform/vulnerable --framework terraform
```

**Safety:** The vulnerable configuration is intentionally insecure. Do not deploy it to an AWS account or run `terraform apply` against it.

## Validation Results

The current project execution produces:

| Metric | Result |
|---|---:|
| Synthetic CloudTrail events analyzed | 10 |
| Security findings generated | 6 |
| Automated tests passing | 49 |
| Detection rules | 4 |
| Terraform configurations scanned | 2 |

All six generated findings are classified as HIGH by the current rules.

These results demonstrate that the implemented detection logic identifies the expected conditions in the supplied fixtures. They are not evidence of actual attacks or production detection performance.

## Datasets and References

The `datasets/` directory contains synthetic CloudTrail JSON fixtures representing selected AWS event structures.

The fixtures cover:

- S3 public ACL changes.
- CloudTrail and GuardDuty security-service deletion or shutdown.
- Repeated failed AWS Console login attempts.
- Public EC2 AMI launch-permission changes.

The fixtures are intended for repeatable local testing. They are not collected from a live AWS environment or representative of real production telemetry.

## Limitations

- No AWS infrastructure was deployed.
- No live AWS account or CloudTrail event stream is connected.
- Detection tests use synthetic fixtures rather than production logs.
- The detection rules cover selected event patterns, not the full range of AWS security threats.
- Findings require contextual investigation before being treated as security incidents.
- Detection thresholds and severities are currently hard-coded.
- No alert delivery, persistent storage, dashboard, or incident-response integration is implemented.
- Checkov results represent static Terraform analysis, not runtime security validation.

## Project Status

The initial implementation includes:

- Secure and vulnerable S3 Terraform configurations.
- Checkov security scan reports and comparison.
- Python CloudTrail JSON loader.
- Four detection rules.
- Central detection engine.
- JSON and Markdown reporting.
- Automated unit and integration tests.

The next phase is documentation review, repository cleanup, and final validation.
