# AWS CloudTrail Detection Lab

![CI](https://github.com/OmSystems/aws-cloudtrail-detection-lab/actions/workflows/ci.yml/badge.svg)

A hands-on cloud security lab combining Terraform security configuration analysis with Python-based AWS CloudTrail event detection.

The project demonstrates two complementary security activities:

- **Infrastructure security:** Compare secure and intentionally vulnerable Amazon S3 configurations using Terraform and Checkov.
- **Detection engineering:** Analyze CloudTrail JSON events and identify security-relevant activities using Python detection rules.

No AWS infrastructure is deployed. Most CloudTrail datasets are hand-written test fixtures that follow the real CloudTrail record structure. One additional subset is unmodified real CloudTrail records from a public attack-simulation dataset (see [Real-World Validation](#real-world-validation)).

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

| Rule ID | Detection | Event Conditions | Severity | MITRE ATT&CK |
|---|---|---|---|---|
| S3-001 | Public S3 Bucket ACL | `PutBucketAcl` with an `AllUsers` READ grant | HIGH | T1530 Data from Cloud Storage |
| SEC-001 | Security Service Deletion or Shutdown | `StopLogging`, `DeleteTrail`, or `DeleteDetector` | HIGH | T1562.008 Disable or Modify Cloud Logs |
| AUTH-001 | Console Login Failure Burst | At least 5 failed console logins from one source IP within 10 minutes | MEDIUM | T1110 Brute Force |
| EC2-001 | Public AMI Sharing | `ModifyImageAttribute` with `launchPermission.add.items[].group = "all"` | HIGH | T1537 Transfer Data to Cloud Account |

Severity and ATT&CK mappings live in one place, `cloudtrail_analyzer/rules/metadata.py`, and every finding carries them. They are assigned by the author, and the reasoning for each severity is in that file. AUTH-001 is MEDIUM because failed logins alone do not show that a credential worked. T1562.008 and T1537 match published vendor detections for the same behaviour; T1530 and T1110 are the author's judgement.

### Adding a Rule

1. Write the detection function in `cloudtrail_analyzer/rules/`. Event rules take one event and return a finding or `None`; batch rules take all events and return a list.
2. Add the rule's name, severity and ATT&CK techniques to `rules/metadata.py` and use `**rule_fields("ID")` in the finding.
3. Append one `Rule(...)` entry to `rules/registry.py`.

`engine.py` does not change. `tests/test_registry.py` checks that every registered rule has well-formed metadata.

### Finding Fields

Every finding carries what an analyst needs to locate the original event: `event_time`, `event_id`, `actor` (IAM ARN, user name or principal ID), `source_ip` and `aws_region` when present in the record. AUTH-001 reports `first_event_time`, `last_event_time`, `event_ids` and `targeted_users` for the failures in the window.

Single-event rules (S3-001, SEC-001, EC2-001) ignore events that carry an `errorCode`, because a denied call changed nothing.

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
|       |-- common.py
|       |-- metadata.py
|       |-- registry.py
|
|-- datasets/
|   |-- s3-public/
|   |-- security-service-deletion/
|   |-- login-failures/
|   |-- ami-public/
|   |-- real-world/
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
|-- .github/workflows/ci.yml
|
|-- requirements.txt
|-- LICENSE
|-- README.md
```

## Setup and Execution

### Prerequisites

- Python 3.10+ (CI runs 3.10 and 3.12)
- pytest (`pip install -r requirements.txt`)
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

### Analyze Your Own CloudTrail Logs

Pass files or directories to analyze real exports instead of the bundled fixtures:

```bash
python3 -m cloudtrail_analyzer path/to/logs/
python3 -m cloudtrail_analyzer export.jsonl.gz --output-dir out/
```

The loader accepts CloudTrail log files (`{"Records": [...]}`), newline-delimited JSON (one event per line), a single bare event, and any of these gzip-compressed (`.json`, `.jsonl`, `.ndjson`, `.gz`). Directories are searched recursively, and unreadable files are skipped with a message instead of stopping the run.

The output lists how many events each rule can match in the input, so you can tell whether a dataset can exercise a rule at all, then the findings. Reports are written only if you pass `--output-dir`; this mode never overwrites `reports/`.

### Run Automated Tests

```bash
python3 -m pytest -v
```

The test suite validates event loading, individual detection rules, the rule registry, detection engine integration, report generation, CLI execution, and detection against real CloudTrail records.

GitHub Actions runs the suite on every push and also fails if `reports/findings.*` are out of date. Terraform and Checkov are not run in CI.

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
| Hand-written CloudTrail events analyzed | 13 |
| Security findings generated | 6 (5 HIGH, 1 MEDIUM) |
| Automated tests passing | 91 |
| Detection rules | 4 |
| Terraform configurations scanned | 2 |

All six generated findings are classified as HIGH by the current rules.

These results demonstrate that the implemented detection logic identifies the expected conditions in the supplied fixtures, including three events that must not alert (a private AMI share and two calls denied with `AccessDenied`/`UnauthorizedOperation`). They are not evidence of actual attacks or production detection performance.

## Real-World Validation

The analyzer was run on a public dataset of real CloudTrail logs from [invictus-ir/aws_dataset](https://github.com/invictus-ir/aws_dataset) (MIT License), generated by running Stratus Red Team attack techniques in the dataset authors' own AWS account. All 55 files (2,900 events) loaded and ran without errors. A 14-event subset covering this lab's event types is committed in `datasets/real-world/` and tested in `tests/test_real_world_logs.py`.

| Real event | Expected | Result |
|---|---|---|
| `DeleteTrail`, succeeded (2) | SEC-001 alert | 2 SEC-001 findings |
| `StopLogging` and `DeleteTrail`, failed with `TrailNotFoundException` (4) | No alert | No alert |
| `ModifyImageAttribute` adding one account ID, not the public group (1) | No EC2-001 alert | No alert |
| `ConsoleLogin` success (2) | No AUTH-001 alert | No alert |

What this does and does not show: the rules handle real record structure for these event types without schema errors, and the error-code and public-only logic behaves correctly on real data. It does not show real-world detection quality. This one dataset has a single simulated attacker and contains no failed logins or `PutBucketAcl` events, so SEC-001 is the only rule exercised with a positive match. S3-001, AUTH-001 and EC2-001 are still validated positively only by hand-written fixtures.

## Datasets and References

The `datasets/` directory contains hand-written CloudTrail JSON fixtures, plus the real-log subset in `datasets/real-world/` (see its README for source and license). Field names and nesting follow the documented CloudTrail record format (for example `launchPermission.add.items[]` for AMI changes), but the events were written by the author, not exported from AWS.

The fixtures cover:

- S3 public ACL changes.
- CloudTrail and GuardDuty security-service deletion or shutdown.
- Repeated failed AWS Console login attempts.
- Public EC2 AMI launch-permission changes.

The fixtures are intended for repeatable local testing. They are not collected from a live AWS environment or representative of real production telemetry. Account IDs and IP addresses use AWS and RFC 5737 documentation values.

## Limitations

- No AWS infrastructure was deployed.
- No live AWS account or CloudTrail event stream is connected.
- Real-log validation covers one public dataset and only one rule with a positive match (see Real-World Validation). Schema mismatches with other real events are still possible.
- The loader handles CloudTrail log files, newline-delimited JSON, bare events and gzip. It does not handle SIEM wrapper formats that nest the CloudTrail event inside another field.
- EC2-001 alerts only on public sharing. A share to one specific account, which is also a known exfiltration pattern, does not alert (confirmed on the real data).
- The detection rules cover selected event patterns, not the full range of AWS security threats.
- Findings require contextual investigation before being treated as security incidents.
- Detection thresholds are hard-coded, and each rule has one fixed severity regardless of context (for example, which bucket or user is involved).
- S3-001 only matches an `AllUsers` + `READ` grant. It does not cover other permissions, the `AuthenticatedUsers` group, canned ACL headers or public bucket policies.
- SEC-001 covers only `StopLogging`, `DeleteTrail` and `DeleteDetector`.
- AUTH-001 groups by source IP only and does not detect attempts spread across many IPs.
- No alert delivery, persistent storage, dashboard, or incident-response integration is implemented.
- Checkov results represent static Terraform analysis, not runtime security validation.

## Project Status

Status: complete as a local, fixture-based lab. The implementation includes:

- Secure and vulnerable S3 Terraform configurations.
- Checkov security scan reports and comparison.
- Python CloudTrail JSON loader.
- Four detection rules, registered through a rule registry with per-rule severity and MITRE ATT&CK metadata.
- Central detection engine.
- JSON and Markdown reporting.
- Automated unit and integration tests, including tests on real CloudTrail records.
- GitHub Actions CI.
- Findings that identify the actor, time and original event ID.

### Future Work

- Validate S3-001, AUTH-001 and EC2-001 against real logs that contain those events.
- Cover more S3 exposure paths (other ACL permissions, bucket policies, Block Public Access removal).
- Make thresholds and severities configurable.
