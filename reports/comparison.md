# Terraform Security Scan Comparison

## 1. Scan Environment

- **Scanner:** Checkov
- **Checkov version:** 3.4.3
- **Terraform version:** Terraform v1.17.2 on linux_amd64
- **Scan type:** Static analysis
- **Framework:** Terraform

## 2. Scan Summary

| Metric | Secure Configuration | Vulnerable Configuration |
|---|---:|---:|
| Passed checks | 12 | 6 |
| Failed checks | 5 | 8 |
| Skipped checks | 0 | 0 |
| Parsing errors | 0 | 0 |
| Resources scanned | 5 | 2 |

## 3. Security Findings

### 3.1 Secure Configuration

The secure Terraform configuration passed 12 checks and failed 5 checks.

The remaining findings were:

| Check ID | Finding |
|---|---|
| CKV_AWS_144 | S3 bucket does not have cross-region replication enabled |
| CKV2_AWS_62 | S3 bucket does not have event notifications enabled |
| CKV_AWS_145 | S3 bucket does not use AWS KMS encryption by default |
| CKV2_AWS_61 | S3 bucket does not have a lifecycle configuration |
| CKV_AWS_18 | S3 bucket does not have access logging enabled |

The secure configuration includes public access blocking, bucket versioning, server-side encryption using AES256, and a bucket policy that denies non-HTTPS requests.

### 3.2 Vulnerable Configuration

The vulnerable Terraform configuration passed 6 checks and failed 8 checks.

The findings were:

| Check ID | Finding |
|---|---|
| CKV_AWS_70 | S3 bucket policy allows an action with any Principal |
| CKV2_AWS_6 | S3 bucket does not have a Public Access Block |
| CKV_AWS_21 | S3 bucket does not have versioning enabled |
| CKV_AWS_144 | S3 bucket does not have cross-region replication enabled |
| CKV_AWS_145 | S3 bucket does not use AWS KMS encryption by default |
| CKV2_AWS_62 | S3 bucket does not have event notifications enabled |
| CKV_AWS_18 | S3 bucket does not have access logging enabled |
| CKV2_AWS_61 | S3 bucket does not have a lifecycle configuration |

The vulnerable configuration contains a bucket policy that allows public read access to objects through the wildcard Principal (`*`).

## 4. Key Security Differences

| Security Control | Secure Configuration | Vulnerable Configuration |
|---|---|---|
| Public object access | Not allowed by the intended configuration | Allowed by bucket policy |
| S3 Public Access Block | Configured | Not configured |
| Bucket versioning | Enabled | Not enabled |
| Default encryption | SSE-S3 (AES256) | No explicit default encryption configured |
| HTTPS enforcement | Denies non-HTTPS requests | No equivalent policy configured |

**Encryption note:** The secure configuration uses SSE-S3 encryption with AES256. Checkov still reports CKV_AWS_145 because this particular check expects AWS KMS encryption. SSE-S3 and SSE-KMS are different encryption options.

## 5. Interpretation

The scan identifies additional security weaknesses in the vulnerable configuration, particularly public object access, missing public access blocking, and disabled versioning.

The secure configuration addresses these three controls.

The five findings shared by both configurations relate to cross-region replication, event notifications, KMS encryption, lifecycle configuration, and access logging. These controls are outside the current implementation scope and are documented rather than added solely to eliminate every Checkov finding.

The resource counts differ between the configurations, so the raw pass/fail totals should not be treated as a normalized security score.

## 6. Limitations

- Checkov performs static analysis of Terraform configuration.
- No AWS infrastructure was deployed.
- No `terraform apply` operation was performed.
- No runtime security testing was conducted.
- The scan results demonstrate configuration-level findings, not verified exploitation or real-world data exposure.
- The project does not use a live production AWS environment.